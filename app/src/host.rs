//! The engine's `Host` for the native app: events go to the UI thread in batches, files go to
//! the Windows shell, and the folders are named by the app id (`com.tedkj.vibeftp`).

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vibeftp_core::error::{AppError, Result};
use vibeftp_core::{Event, Host, Paths};

/// The UI thread's handler for engine events.
type Sink = Box<dyn Fn(Event)>;

thread_local! {
    /// The UI thread's receiver for engine events (set once by the controller).
    static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Install the UI thread's event handler. Call on the UI thread.
pub fn on_events(handler: impl Fn(Event) + 'static) {
    SINK.with(|s| *s.borrow_mut() = Some(Box::new(handler)));
}

#[derive(Default)]
pub struct SlintHost {
    queue: Arc<Mutex<Vec<Event>>>,
    scheduled: Arc<AtomicBool>,
}

impl SlintHost {
    /// Deliver what is queued right now, synchronously, on the UI thread. The scheduled flush
    /// then finds the queue empty.
    pub fn drain(&self) {
        let events = std::mem::take(&mut *self.queue.lock().unwrap());
        SINK.with(|s| {
            if let Some(h) = s.borrow().as_ref() {
                for e in events {
                    h(e);
                }
            }
        });
    }
}

impl Host for SlintHost {
    fn emit(&self, event: Event) {
        {
            let mut q = self.queue.lock().unwrap();
            // Bounded updates: of a transfer's progress only the newest report is worth drawing.
            if let Event::Progress(p) = &event
                && let Some(old) = q.iter_mut().find(|e| matches!(e, Event::Progress(o) if o.id == p.id))
            {
                *old = event;
                return;
            }
            q.push(event);
        }
        // One wake-up per batch, however many events arrive before the UI thread gets to them.
        if !self.scheduled.swap(true, Ordering::AcqRel) {
            let (queue, scheduled) = (self.queue.clone(), self.scheduled.clone());
            let woken = slint::invoke_from_event_loop(move || {
                scheduled.store(false, Ordering::Release);
                let events = std::mem::take(&mut *queue.lock().unwrap());
                SINK.with(|s| {
                    if let Some(h) = s.borrow().as_ref() {
                        for e in events {
                            h(e);
                        }
                    }
                });
            });
            if woken.is_err() {
                // No event loop (yet, or any more): the next event tries again instead of
                // finding the flag stuck and never waking anyone.
                self.scheduled.store(false, Ordering::Release);
            }
        }
    }

    fn open_path(&self, path: &str, with: Option<&str>) -> Result<()> {
        off_worker(|| shell_open(path, with))
    }

    fn reveal(&self, path: &str) -> Result<()> {
        use std::os::windows::process::CommandExt;
        // explorer parses its own command line: the path goes in quotes after /select,
        explorer_command()
            .map_err(AppError::Msg)?
            .raw_arg(format!("/select,\"{}\"", path.replace('"', "")))
            .spawn()
            .map(|_| ())
            .map_err(|e| AppError::Msg(format!("Could not open Explorer: {e}")))
    }
}

/// The engine calls `open_path` from async code (an edit open), on one of the runtime's two
/// workers, and ShellExecuteEx can wait as long as a "Pick an app" dialog stays open. Handed
/// over as blocking work there, so the worker's other tasks move to another thread meanwhile.
/// Elsewhere (the blocking pool, the UI thread, a current-thread runtime) it just runs.
fn off_worker<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A path as Windows takes it: its UTF-16 units kept exactly (a lone surrogate included), NUL-ended.
pub fn wide_path(p: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// A web page in the default browser (About's links). https only: nothing else is ever handed
/// to the shell from here.
pub fn open_url(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        return Err(vibeftp_core::error::AppError::Msg(format!("Not a web address: {url}")));
    }
    shell_open(url, None)
}

/// Text the window cannot let the user select (toasts, confirms, the log) onto the clipboard.
pub fn copy_text(text: &str) -> Result<()> {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
    let w = wide(&clipboard_text(text));
    let fail = |what: &str| AppError::Msg(format!("Could not copy ({what}): {}", std::io::Error::last_os_error()));
    unsafe {
        // Another program (a clipboard manager) may hold it for a moment: a few short tries.
        let mut open = OpenClipboard(std::ptr::null_mut()) != 0;
        for _ in 0..4 {
            if open {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
            open = OpenClipboard(std::ptr::null_mut()) != 0;
        }
        if !open {
            return Err(fail("the clipboard is busy"));
        }
        let put = (|| {
            if EmptyClipboard() == 0 {
                return Err(fail("empty"));
            }
            let h = GlobalAlloc(GMEM_MOVEABLE, w.len() * 2);
            if h.is_null() {
                return Err(fail("memory"));
            }
            let p = GlobalLock(h) as *mut u16;
            if p.is_null() {
                let e = fail("memory"); // before GlobalFree, which may overwrite the last error
                GlobalFree(h);
                return Err(e);
            }
            std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
            GlobalUnlock(h);
            // The clipboard owns the memory once this succeeds; only a failure leaves it ours.
            if SetClipboardData(CF_UNICODETEXT as u32, h).is_null() {
                let e = fail("set");
                GlobalFree(h);
                return Err(e);
            }
            Ok(())
        })();
        CloseClipboard();
        put
    }
}

/// Windows text on the clipboard ends its lines with CRLF (Notepad and others expect it).
fn clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// ShellExecuteEx with the shell's own error dialogs suppressed: a missing file or a missing
/// association comes back as an error here, it never parks a modal box on the UI.
fn shell_open(path: &str, with: Option<&str>) -> Result<()> {
    use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let (file, params) = match with {
        Some(program) => {
            let program = program_path(program).ok_or_else(|| AppError::Msg(format!("Could not open {path}: System32 is not known")))?;
            (wide(&program), Some(wide(&format!("\"{}\"", path.replace('"', "")))))
        }
        None => (wide(path), None),
    };
    unsafe {
        // The shell wants an STA; harmless when the thread already has one.
        CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ref().map(|p| p.as_ptr()).unwrap_or(std::ptr::null());
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            return Err(AppError::Msg(format!("Could not open {path}: {}", std::io::Error::last_os_error())));
        }
    }
    Ok(())
}

/// A bare program name ("notepad.exe") as the System32 file: the shell would look in the
/// current directory first, and a planted notepad.exe there must not be what opens a script.
/// None when System32 is not known: never the bare name.
fn program_path(program: &str) -> Option<String> {
    if program.contains(['\\', '/']) {
        return Some(program.to_string());
    }
    windows_dir(true).map(|dir| dir.join(program).to_string_lossy().into_owned())
}

/// Explorer by its full path (`<Windows>\explorer.exe`), started in System32. Every program the
/// app starts goes by its full path: a bare "explorer.exe" is looked for in this exe's own folder
/// (and the current one) first, Rust's std as CreateProcess, so on a stick or in the per-user
/// install folder anyone's file of that name would run. Started in System32, the child neither
/// searches nor holds the exe's folder.
pub fn explorer_command() -> std::result::Result<std::process::Command, String> {
    let win = windows_dir(false).ok_or("Could not open Explorer: the Windows folder is not known")?;
    let sys = windows_dir(true).ok_or("Could not open Explorer: System32 is not known")?;
    let mut c = std::process::Command::new(win.join("explorer.exe"));
    c.current_dir(sys);
    Ok(c)
}

/// Windows' own folder (`GetSystemWindowsDirectoryW`) or System32 (`GetSystemDirectoryW`), as
/// Windows names them: never from the environment, never relative.
pub fn windows_dir(system: bool) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW};
    let mut buf = [0u16; 1024];
    // SAFETY: a buffer and its length in units.
    let n = unsafe { if system { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } else { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } } as usize;
    (n > 0 && n < buf.len()).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..n]))).filter(|p| p.is_absolute())
}

fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        let ok = SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) == 0;
        let out = if ok && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            Some(PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(p, len))))
        } else {
            None
        };
        CoTaskMemFree(p as *const _);
        out
    }
}

/// The user's own folders an install may be in, as the installer has them (vibeftp.nsi
/// `OwnFolder`: $LOCALAPPDATA and $PROFILE): local app data and the profile.
pub fn own_folders() -> Vec<PathBuf> {
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, FOLDERID_Profile};
    [&FOLDERID_LocalAppData, &FOLDERID_Profile].into_iter().filter_map(known_folder).collect()
}

/// The folders named by the app id, the family's convention, so every update keeps sites.json,
/// known_hosts.json and edit copies. Do not rename.
pub fn paths() -> Paths {
    use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_RoamingAppData};
    const ID: &str = "com.tedkj.vibeftp";
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from).unwrap_or_default();
    Paths {
        config: known_folder(&FOLDERID_RoamingAppData).unwrap_or_else(|| env("APPDATA")).join(ID),
        local_data: known_folder(&FOLDERID_LocalAppData).unwrap_or_else(|| env("LOCALAPPDATA")).join(ID),
        home: known_folder(&FOLDERID_Profile),
    }
}

/// A development profile under `home` (VIBEFTP_DEV_HOME, `dev-hooks` builds only): config
/// (sites, pins, prefs), local data (edit copies, updates) and the local pane's home all inside
/// it, so a live check never reads or writes the user's real profile.
pub fn dev_paths(home: &std::path::Path) -> Paths {
    Paths { config: home.join("config"), local_data: home.join("data"), home: Some(home.join("home")) }
}

/// A rectangle in physical pixels, edges as Win32's RECT has them (right and bottom exclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Px {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Where a window's visible frame goes so it fits the monitor's work area (X15A11Y-3): a side
/// longer than the area's shrinks to it, then the frame moves inside the area (left and top edges
/// first). None when it already fits. The window's minimum size still wins: Windows keeps it
/// (WM_GETMINMAXINFO), so a window whose minimum is bigger than the area ends up at its minimum.
pub fn fit_frame(frame: Px, work: Px) -> Option<Px> {
    let w = (frame.right - frame.left).min(work.right - work.left);
    let h = (frame.bottom - frame.top).min(work.bottom - work.top);
    let left = frame.left.min(work.right - w).max(work.left);
    let top = frame.top.min(work.bottom - h).max(work.top);
    let fitted = Px { left, top, right: left + w, bottom: top + h };
    (fitted != frame).then_some(fitted)
}

/// What the fit does with a window in this state (X15RFTP-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FitWhat {
    /// Not on screen yet, or minimized (a shortcut set to "Run: Minimized"): nothing to fit now,
    /// so the next window event tries again, the one after the user restores it at the latest.
    Later,
    /// Maximized (a shortcut set to "Run: Maximized"): its restore rectangle, the size it comes
    /// back at when the user restores it.
    RestoreRect,
    /// A normal window: its frame.
    Frame,
}

pub fn fit_what(visible: bool, minimized: bool, maximized: bool) -> FitWhat {
    if !visible || minimized {
        FitWhat::Later
    } else if maximized {
        FitWhat::RestoreRect
    } else {
        FitWhat::Frame
    }
}

/// A maximized window's restore rectangle fitted to the work area of its monitor (`fit_frame`).
/// `normal` is GetWindowPlacement's, in workspace coordinates (screen coordinates less `origin`,
/// the primary monitor's work-area top left); `work` is in screen coordinates; the result is in
/// workspace coordinates again. None when it already fits.
pub fn fit_restore(normal: Px, work: Px, origin: (i32, i32)) -> Option<Px> {
    let shift = |r: Px, dx: i32, dy: i32| Px { left: r.left + dx, top: r.top + dy, right: r.right + dx, bottom: r.bottom + dy };
    fit_frame(shift(normal, origin.0, origin.1), work).map(|f| shift(f, -origin.0, -origin.1))
}

/// Fit a window that has just opened into its monitor's work area (X15A11Y-3; `fit_frame`):
/// the window opens at its preferred size, sized for a big screen at 100 %, which on a 1080p
/// laptop at 150 % runs past the taskbar and puts the toasts and the status line out of sight.
/// All in physical pixels (the process is per-monitor DPI aware, so no scaling): the work area of
/// the monitor the window is on, and its visible frame (DWM's, without the invisible resize
/// borders, which go back on around it). A maximized window gets its restore rectangle fitted
/// instead (that one has no DWM frame yet, so its invisible borders count as part of it: it
/// comes back a few pixels inside the area). None while the window is not on screen yet or is
/// minimized (try again later, `fit_what`); else whether it changed.
pub fn fit_to_work_area(hwnd: isize) -> Option<bool> {
    use windows_sys::Win32::Foundation::{POINT, RECT};
    use windows_sys::Win32::Graphics::Dwm::{DWMWA_EXTENDED_FRAME_BOUNDS, DwmGetWindowAttribute};
    use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, MonitorFromRect, MonitorFromWindow};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowPlacement, GetWindowRect, IsIconic, IsWindowVisible, IsZoomed, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPlacement, SetWindowPos, WINDOWPLACEMENT,
    };
    let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
    let px = |r: RECT| Px { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
    let work_of = |m| {
        // SAFETY: a MONITORINFO of its own size for a monitor handle Windows just gave.
        let mut mi: MONITORINFO = unsafe { std::mem::zeroed() };
        mi.cbSize = size_of::<MONITORINFO>() as u32;
        (unsafe { GetMonitorInfoW(m, &mut mi) } != 0).then(|| px(mi.rcWork))
    };
    // SAFETY: plain Win32 calls on the app's own window handle, each with a struct of its own
    // size; a call that fails leaves the window as it is.
    unsafe {
        match fit_what(IsWindowVisible(hwnd) != 0, IsIconic(hwnd) != 0, IsZoomed(hwnd) != 0) {
            FitWhat::Later => return None,
            FitWhat::Frame => {}
            FitWhat::RestoreRect => {
                let mut wp: WINDOWPLACEMENT = std::mem::zeroed();
                wp.length = size_of::<WINDOWPLACEMENT>() as u32;
                if GetWindowPlacement(hwnd, &mut wp) == 0 {
                    return Some(false);
                }
                let Some(primary) = work_of(MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY)) else { return Some(false) };
                let n = wp.rcNormalPosition;
                let on_screen = RECT { left: n.left + primary.left, top: n.top + primary.top, right: n.right + primary.left, bottom: n.bottom + primary.top };
                let Some(work) = work_of(MonitorFromRect(&on_screen, MONITOR_DEFAULTTONEAREST)) else { return Some(false) };
                let Some(to) = fit_restore(px(n), work, (primary.left, primary.top)) else { return Some(false) };
                wp.rcNormalPosition = RECT { left: to.left, top: to.top, right: to.right, bottom: to.bottom };
                return Some(SetWindowPlacement(hwnd, &wp) != 0);
            }
        }
        let mut outer: RECT = std::mem::zeroed();
        if GetWindowRect(hwnd, &mut outer) == 0 {
            return Some(false);
        }
        let mut seen = outer;
        if DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS as u32, (&mut seen as *mut RECT).cast(), size_of::<RECT>() as u32) != 0 {
            seen = outer;
        }
        let Some(work) = work_of(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)) else { return Some(false) };
        let Some(to) = fit_frame(px(seen), work) else { return Some(false) };
        let (l, t, r, b) = (seen.left - outer.left, seen.top - outer.top, outer.right - seen.right, outer.bottom - seen.bottom);
        Some(SetWindowPos(hwnd, std::ptr::null_mut(), to.left - l, to.top - t, to.right - to.left + l + r, to.bottom - to.top + t + b, SWP_NOZORDER | SWP_NOACTIVATE) != 0)
    }
}
