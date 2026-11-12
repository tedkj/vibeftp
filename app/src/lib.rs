//! VibeFTP's native UI on vibeftp-core. Also the VibeWare kitchen sink, shared by the `kitchen`
//! binary (for looking at it) and the UI tests (for driving it headless).

pub mod backend;
pub mod check;
pub mod controller;
pub mod format;
#[cfg(windows)]
pub mod host;
pub mod launch;
pub mod model;
pub mod pane;
pub mod paths;
pub mod prefs;
pub mod text;
pub mod trust;
pub mod updater;

use slint::{ComponentHandle, Model, ModelRc, VecModel};
use std::rc::Rc;

slint::include_modules!();

/// This build's version (Cargo's), as About and the install check say it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn row(name: &str, size: &str, modified: &str, is_dir: bool) -> Row {
    Row { name: name.into(), size: size.into(), modified: modified.into(), is_dir }
}

pub fn sample_rows() -> Vec<Row> {
    vec![
        row("assets", "", "2026-10-12 09:41", true),
        row("releases", "", "2026-10-16 22:05", true),
        row("index.html", "14 KB", "2026-10-16 13:54", false),
        row("report-final.pdf", "2.1 MB", "2026-10-15 18:20", false),
        row("VibeFTP_0.1.0_x64-setup.exe", "4.0 MB", "2026-10-17 23:11", false),
        row("notes.txt", "812 B", "2026-10-17 08:02", false),
        row("backup-2026-10-16.tar.zst", "1.4 GB", "2026-10-16 03:00", false),
    ]
}

/// The kitchen sink window with its demo lists and callbacks wired.
pub fn kitchen() -> Result<KitchenSink, slint::PlatformError> {
    let ui = KitchenSink::new()?;
    let a = Rc::new(VecModel::from(sample_rows()));
    let b: Rc<VecModel<Row>> = Rc::new(VecModel::default());
    ui.set_list_a(ModelRc::from(a.clone()));
    ui.set_list_b(ModelRc::from(b.clone()));
    ui.set_cursor_a(3);
    ui.set_selected_a(ModelRc::new(VecModel::from(vec![3])));

    let weak = ui.as_weak();
    ui.on_action(move |what| {
        if let Some(ui) = weak.upgrade() {
            ui.set_last_action(what);
        }
    });

    let weak = ui.as_weak();
    ui.on_moved_to_b(move |i| {
        let Some(ui) = weak.upgrade() else { return };
        let i = i as usize;
        if i >= a.row_count() {
            return;
        }
        let moved = a.remove(i);
        b.push(moved.clone());
        let last = a.row_count() as i32 - 1;
        ui.set_cursor_a(ui.get_cursor_a().min(last).max(0));
        ui.set_selected_a(ModelRc::new(VecModel::from(Vec::<i32>::new())));
        ui.set_last_action(format!("moved {}", moved.name).into());
    });

    let weak = ui.as_weak();
    ui.on_activated_a(move |i| {
        let Some(ui) = weak.upgrade() else { return };
        let name = ui.get_list_a().row_data(i as usize).map(|r| r.name).unwrap_or_default();
        ui.set_last_action(format!("open {name}").into());
    });

    Ok(ui)
}
