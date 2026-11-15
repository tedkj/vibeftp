// VibeFTP, native: vibeftp-core behind a Slint UI on the software renderer. One process, no
// browser engine.
#![windows_subsystem = "windows"]

use slint::winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent};
use slint::{ComponentHandle, Timer, TimerMode};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use vibeftp_app::backend::CoreBackend;
use vibeftp_app::controller::{App, SlintSpawn};
use vibeftp_app::{AppWindow, host};
use vibeftp_core::{Core, Host};

/// The real release-list fetcher (WinHTTP), the exe's alone: it is in no test build, not the
/// lib's, not the integration tests', not this exe's own unit tests', so no test can go online
/// (review RAB-2; tests/pe.rs checks this line).
#[cfg(not(test))]
mod net;

/// The pointer in window coordinates (logical px), read from the OS: during a drag from
/// Explorer the window gets no pointer moves, and a drop says nothing about where it landed.
fn cursor_in(window: &slint::Window) -> Option<(f32, f32)> {
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::WindowsAndMessaging::GetCursorPos;
    let mut p = POINT { x: 0, y: 0 };
    if unsafe { GetCursorPos(&mut p) } == 0 {
        return None;
    }
    let origin = window.with_winit_window(|w| w.inner_position().ok()).flatten()?;
    let s = window.scale_factor();
    Some(((p.x - origin.x) as f32 / s, (p.y - origin.y) as f32 / s))
}

fn hit(ui: &AppWindow) -> (i32, i32) {
    match cursor_in(ui.window()) {
        Some((x, y)) => {
            let side = ui.invoke_hit_side(x, y);
            (side, ui.invoke_hit_row(side, x, y))
        }
        None => (-1, -1),
    }
}

/// `dev-hooks` builds only: VIBEFTP_DEV_HOME=<folder> runs on a profile of its own (sites, pins,
/// prefs, edit copies, updates, the local pane's home) and its own keychain namespace
/// ("VibeFTP-dev"), so a live check never touches the real profile or saved passwords.
#[cfg(feature = "dev-hooks")]
fn dev_home() -> Option<vibeftp_core::Paths> {
    let home = PathBuf::from(std::env::var_os("VIBEFTP_DEV_HOME")?);
    let paths = host::dev_paths(&home);
    if let Some(h) = &paths.home {
        let _ = std::fs::create_dir_all(h);
    }
    vibeftp_core::store::use_keychain_service("VibeFTP-dev");
    Some(paths)
}

#[cfg(not(feature = "dev-hooks"))]
fn dev_home() -> Option<vibeftp_core::Paths> {
    None
}

fn main() -> Result<(), slint::PlatformError> {
    // DLL hardening, first of all (VibeLink LINK-1): every DLL loaded from here on comes from
    // System32, never from the exe's own folder (the per-user install folder, which the user's
    // own programs can write). The static imports are covered by the link flag
    // /DEPENDENTLOADFLAG:0x800 (build.rs).
    // SAFETY: a process-wide setting with a valid flag; nothing has been loaded by name yet.
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    // No Windows "No Disk" box: a file call on an empty card reader or drive gets its error back
    // instead of a modal box (review fix-popup, RX1). tests/pe.rs checks this block comes next.
    // SAFETY: a process-wide setting with a valid flag, the bits already set kept.
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_FAILCRITICALERRORS, SetErrorMode};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    }
    // The command line is `VibeFTP.exe` (the installer, its finish page, the Start menu and an
    // update's restart pass nothing), or files dropped on the exe or its shortcut (the window,
    // and a toast that they were left alone: launch.rs; files dragged into the window upload as
    // before). Anything else, an option above all, ends the process before any window or file
    // (exit code 2). args_os: an argument that is not Unicode must not panic (panic = abort ends
    // the app).
    let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let left_alone = match vibeftp_app::launch::start(&raw) {
        vibeftp_app::launch::Start::Window => None,
        vibeftp_app::launch::Start::Dropped(note) => Some(note),
        vibeftp_app::launch::Start::Refused => std::process::exit(2),
    };
    vibeftp_app::updater::restore_temp();
    // The tree walks recurse once per folder level on a worker thread; tokio's default 2 MiB
    // stack overflows a few hundred levels down. Windows only reserves thread stacks, so 64 MiB
    // costs address space, not memory.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_stack_size(64 << 20)
        .build()
        .expect("tokio runtime");

    let slint_host = Arc::new(host::SlintHost::default());
    let host: Arc<dyn Host> = slint_host.clone();
    vibeftp_core::logger::install(host.clone());
    let paths = dev_home().unwrap_or_else(host::paths);
    // The probe hands back the value it was asked about, and `main` goes on with that one only: the
    // old binding is gone (`dev_probe`, review RRF-2).
    #[cfg(feature = "dev-hooks")]
    let paths = dev_probe(paths);
    let prefs = vibeftp_app::prefs::Store::new(paths.config.join("prefs.json"));
    let updates = vibeftp_app::updater::Policy::release(paths.local_data.join("update"));
    let update_failed = vibeftp_app::updater::take_failure(&paths.local_data);
    let core = Core::new(host, paths);
    {
        let core = core.clone();
        std::thread::spawn(move || vibeftp_core::ops::sweep_old_copies(&core));
    }

    let ui = AppWindow::new()?;
    let mut backend = CoreBackend::new(core.clone(), rt.handle().clone()).with_prefs(prefs.clone());
    if let Ok(u) = vibeftp_app::updater::Updater::new(updates) {
        backend = backend.with_updater(u); // (it fails only if no HTTP client can be built)
    }
    let backend = Rc::new(backend);
    // The one place that names the real release-list fetcher (tests/pe.rs checks it): every test
    // hands the controller a fake, so no test goes online. This exe's unit-test build has no
    // `net` and never runs `main`: it gets a stand-in that fetches nothing.
    #[cfg(not(test))]
    let fetch = Arc::new(net::fetch_release_list);
    #[cfg(test)]
    let fetch = Arc::new(|_: &str| vibeftp_app::check::Fetched::Failed("a test build has no fetcher".into()));
    let app = App::new(&ui, backend, Rc::new(SlintSpawn), vibeftp_app::controller::Check::system(fetch));
    {
        let app = app.clone();
        host::on_events(move |e| app.on_event(e));
    }
    app.set_event_drain(move || slint_host.drain());

    // Files dragged in from Explorer: highlight the target while they hover, upload on drop.
    let dropped: Rc<RefCell<Vec<PathBuf>>> = Rc::default();
    let hover = Rc::new(Timer::default());
    {
        let (app, weak, dropped, hover) = (app.clone(), ui.as_weak(), dropped.clone(), hover.clone());
        ui.window().on_winit_window_event(move |_, event| {
            match event {
                WindowEvent::HoveredFile(_) if !hover.running() => {
                    let (app, weak) = (app.clone(), weak.clone());
                    hover.start(TimerMode::Repeated, Duration::from_millis(50), move || {
                        if let Some(ui) = weak.upgrade() {
                            let (side, row) = hit(&ui);
                            app.os_hover(Some((side, row)));
                        }
                    });
                }
                WindowEvent::HoveredFileCancelled => {
                    hover.stop();
                    app.os_hover(None);
                }
                WindowEvent::DroppedFile(path) => {
                    // One event per file: collect them, act once the batch is in.
                    let first = dropped.borrow().is_empty();
                    dropped.borrow_mut().push(path.clone());
                    if first {
                        let (app, weak, dropped, hover) = (app.clone(), weak.clone(), dropped.clone(), hover.clone());
                        Timer::single_shot(Duration::from_millis(0), move || {
                            hover.stop();
                            let files = std::mem::take(&mut *dropped.borrow_mut());
                            if let Some(ui) = weak.upgrade() {
                                let (side, row) = hit(&ui);
                                app.os_drop(files, side, row);
                            }
                        });
                    }
                }
                _ => {}
            }
            EventResult::Propagate
        });
    }

    app.boot();
    if let Some(why) = update_failed {
        app.error(format!("The update did not install: {why}"));
    }
    if let Some(note) = left_alone {
        app.toast(note, vibeftp_app::ToastKind::Info);
    }
    #[cfg(feature = "dev-hooks")]
    if let Ok(id) = std::env::var("VIBEFTP_DEV_CONNECT") {
        app.dev_connect(id, std::env::var("VIBEFTP_DEV_PASSWORD").ok());
    }
    #[cfg(feature = "dev-hooks")]
    if std::env::var("VIBEFTP_DEV_LOG").is_ok() {
        ui.set_log_open(true); // live check of the log panel's follow
    }
    let ran = ui.run();
    prefs.flush(); // a change from the last moments, still on its way to disk
    // So are the folders of the last moments (the 600 ms debounce dies with the event loop,
    // X15CON-16): written now, bounded, on the engine's runtime.
    if let Some((id, remote, local)) = app.take_pending_touch() {
        let core = core.clone();
        let _ = rt.block_on(async move { tokio::time::timeout(Duration::from_secs(2), vibeftp_core::ops::site_touch(&core, id, remote, local)).await });
    }
    // Transfers are cut short; edit copies whose bytes are on the server go, unsent ones stay.
    // Nothing is told here, the window is gone (a known limit, HARDENING RVA4-1); unsent edits
    // were named by the quit question (RVA5-2, RVA6-1).
    vibeftp_core::ops::on_exit(&core);
    // Dropping the runtime would wait for every blocking task: a read stalled on a dead server
    // runs into its 60 s timeout in a process with no window. The cancelled ones end at once.
    rt.shutdown_timeout(Duration::from_secs(2));
    ran
}

/// Live checks only (review RRE-5, RRF-2): with VIBEFTP_DEV_PROBE set, `main` writes the
/// app's data folders, one a line on stdout, and ends (exit 0) right after the dev home, before
/// any of them is used and before any window. Else it hands back the value it was given,
/// unchanged, and `main` goes on with it (`let paths = dev_probe(paths);`), so the folders the
/// probe names are the ones `main` uses. tests/pe.rs asks this before it starts the exe for real
/// (`run_exe`): every folder must be inside the scratch dev home it gave, so an override that is
/// gone, compiled out or too late fails there, by what the exe does.
#[cfg(feature = "dev-hooks")]
fn dev_probe(paths: vibeftp_core::Paths) -> vibeftp_core::Paths {
    use std::io::Write;
    if std::env::var_os("VIBEFTP_DEV_PROBE").is_some() {
        let mut out = std::io::stdout().lock();
        for f in [&paths.config, &paths.local_data].into_iter().chain(&paths.home) {
            let _ = writeln!(out, "{}", f.display());
        }
        let _ = out.flush();
        std::process::exit(0);
    }
    paths
}
