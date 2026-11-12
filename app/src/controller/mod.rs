//! The UI brain. It lives on the UI thread: async work runs as local futures on Slint's event loop
//! (`Spawn`), engine calls go through `Backend` (tokio underneath), and every result re-checks the sequence and session it was started under before it touches the screen.
//!
//! This file: state, connection, navigation, selection, keyboard, menus, drags, events, wiring.
//! The rest by area: `transfers` (queue, pump, conflicts), `edit` (edit-and-watch), `fileops`
//! (new folder, rename, move, delete, permissions), `sites` (sites, bookmarks, site manager),
//! `dialogs` (prompt, confirm, password), `sync` (synchronized browsing), `about` (About's
//! install check).

pub mod about;
pub mod dialogs;
pub mod edit;
pub mod fileops;
pub mod sites;
pub mod sync;
pub mod transfers;

use crate::backend::Backend;
use crate::format::{bytes, octal, rwx, shown, shown_lines};
use crate::model::{FileModel, QueueModel};
use crate::pane::{Change, Pane, Side, SortKey};
use crate::paths::{join_path, normalize_remote, parent_path};
use crate::{AppWindow, CheckRow, Icons, LinkState, LogRow, MenuEntry, PaneInfo, Theme, ToastItem, ToastKind};
pub use about::{Check, Fetcher};
use dialogs::Answer;
use slint::platform::Key;
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;
use transfers::TRef;
use vibeftp_core::error::AppError;
use vibeftp_core::types::{Action, Conflict, EditChanged, Entry, LogLine, Protocol, Site};
use vibeftp_core::Event;

/// Runs the controller's async work on the UI thread.
pub trait Spawn {
    fn spawn(&self, f: Pin<Box<dyn Future<Output = ()>>>);
}

pub struct SlintSpawn;

impl Spawn for SlintSpawn {
    fn spawn(&self, f: Pin<Box<dyn Future<Output = ()>>>) {
        let _ = slint::spawn_local(f);
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum MenuAction {
    Transfer,
    Open,
    Reveal,
    Rename,
    Perms,
    Delete,
    Mkdir,
    Refresh,
    None,
}

/// An internal drag in progress (pointer based: rows to the other pane or onto a folder).
struct Drag {
    from: usize,
    entries: Vec<Entry>,
}

/// The warning on the first-connection prompt of a server pinned in a kept copy of a damaged
/// known_hosts.json (review FR2-2), or of any server while a kept copy no key can be read out
/// of is recent (FR3-1). That prompt asks for an explicit choice (Ted, 2026-10-20).
pub fn trusted_before(p: &vibeftp_core::types::PinnedBefore, cert: bool, fingerprint: &str) -> String {
    let what = if cert { "certificate" } else { "key" };
    let when = crate::format::when(p.at);
    if !p.named {
        return format!("This server may have been trusted before, with a {what} that can't be read now: VibeFTP's saved keys were damaged on {when}.");
    }
    match &p.pin {
        Some(pin) if same_pin(pin, fingerprint) => {
            format!("This server was trusted before, with this same {what}. VibeFTP's saved keys were damaged on {when} (kept in {}).", p.file)
        }
        Some(pin) => format!("This server was trusted before, with a different {what}:\n{pin}\nVibeFTP's saved keys were damaged on {when} (kept in {}).", p.file),
        None => format!("This server was trusted before, with a {what} that can't be read now. VibeFTP's saved keys were damaged on {when} (kept in {}).", p.file),
    }
}

/// A pin is `"<key algorithm> SHA256:..."` or a bare `"SHA256:..."`; so is a fingerprint.
fn same_pin(pin: &str, fingerprint: &str) -> bool {
    pin.split_whitespace().last() == fingerprint.split_whitespace().last()
}

/// The trust prompt's choices for a server trusted before: its group's name and the option
/// that does not connect (the other is "Trust this key" / "Trust this certificate").
pub const TRUST_CHOICE: &str = "Trust choice";
pub const DONT_CONNECT: &str = "Don't connect, I'll check with the owner";

#[derive(Default)]
pub(crate) struct State {
    sites: Vec<Site>,
    /// Entries of sites.json this build cannot read (kept as they are; the site manager says so).
    sites_unreadable: usize,
    site: Option<Site>,
    pub(crate) session: Option<String>,
    connecting: bool,
    /// Bumped by every connect attempt; a result for an older attempt is discarded.
    connect_seq: u64,
    last_error: Option<String>,
    roots: Vec<String>,
    show_filter: [bool; 2],
    scroll_seq: [i32; 2],
    toasts: Vec<(i32, String, ToastKind, String)>,
    /// Toast id -> what its action button does.
    toast_actions: HashMap<i32, String>,
    /// Toasts that stay until dismissed (notices): no timer, never pushed out by a burst.
    sticky: HashSet<i32>,
    toast_seq: i32,
    modal: Option<tokio::sync::oneshot::Sender<Answer>>,
    menu: Vec<MenuAction>,
    menu_side: usize,
    drag: Option<Drag>,
    /// Where a drag (internal or from Explorer) would land: the pane and maybe a folder row.
    drop: Option<(usize, Option<String>)>,
    /// A plain press on a row of a multi-selection collapses it only on release, so the whole
    /// selection can still be dragged.
    pending_collapse: Option<(usize, String)>,
    /// The pane that last had the keyboard (it gets it back after a dialog).
    focused: usize,
    status: String,
    /// The line in `status` was a warning or an error (the status bar draws it red).
    status_warn: bool,
    connections: usize,
    busy: usize,
    note: String,
    parallel: usize,
    touch_timer: Option<Timer>,
    local_path_pref: String,
    /// Boot's remembered folder lost to a navigation still loading: should that one fail too
    /// and leave the local pane with no folder, it goes home in boot's place.
    home_if_nowhere: bool,

    // Transfers.
    conflicts: Vec<Conflict>,
    conflict_shown: Option<String>,
    conflict_seq: u64,
    /// "Apply to all" answers, each scoped to the transfers that were queued when it was given.
    policy_by_id: HashMap<String, Action>,
    tx_seq: u64,
    batch_seq: u64,
    /// Bytes moved across all transfers, counted per progress event.
    bytes_moved: u64,
    last_sampled: u64,
    samples: Vec<u64>,
    busy_glyph: bool,
    /// One coalesced toast for transfer failures while it is on screen: (count, first, toast id).
    failures: (usize, String, i32),
    refresh_timers: [Option<Timer>; 2],
    /// A post-transfer refresh is running for the pane; `refresh_again` holds one follow-up.
    refreshing: [bool; 2],
    refresh_again: [Option<String>; 2],

    // Edit-and-watch.
    editing: Vec<EditChanged>,
    /// Edit copies (`session|local`) whose "Stop watching" is under way.
    stopping: HashSet<String>,

    // Dialogs and panels.
    perms: Option<fileops::Perms>,
    form: sites::Form,
    sync_root: Option<(String, String)>,
    logs: Vec<LogLine>,
    log_buffer: Vec<LogLine>,
    log_filter: String,
    /// A leave was already confirmed (update and restart, quit): the close guard must not ask again.
    leaving: bool,
    /// The site last picked to connect (its id): the bar's picker keeps showing it after a
    /// disconnect, so Connect dials it again.
    picked: Option<String>,
    /// A drag cancelled with Escape (or by a dialog): the rest of that press moves nothing.
    drag_dead: bool,
    prefs: crate::prefs::Prefs,
    /// The newer version the bar offers, and whether its install is under way.
    update: Option<crate::updater::Offer>,
    updating: bool,
    /// A verified download not started yet (the user was busy), with its version.
    ready: Option<(String, crate::updater::Ready)>,
    update_timer: Option<Timer>,
    modal_seq: i32,
    /// About's install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<std::sync::mpsc::Receiver<(u64, crate::check::Rows)>>,
}

pub struct App {
    ui: Weak<AppWindow>,
    backend: Rc<dyn Backend>,
    spawner: Rc<dyn Spawn>,
    panes: [Rc<RefCell<Pane>>; 2],
    models: [Rc<FileModel>; 2],
    pub(crate) st: RefCell<State>,
    pub(crate) queue: Rc<RefCell<Vec<TRef>>>,
    by_id: RefCell<HashMap<String, TRef>>,
    /// Every row before this index is finished: the pump starts its scan here.
    q_head: Cell<usize>,
    queue_model: Rc<QueueModel>,
    log_model: Rc<VecModel<LogRow>>,
    /// Delivers the engine events queued right now (set by main; the tests have none).
    drain: RefCell<Option<Box<dyn Fn()>>>,
    timers: RefCell<Vec<Timer>>,
    /// About's install check: its services, its three rows, the timer that polls a running one.
    check: Check,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
}

pub(crate) fn idx(side: Side) -> usize {
    match side {
        Side::Local => 0,
        Side::Remote => 1,
    }
}

fn side_of(i: i32) -> Side {
    if i == 1 { Side::Remote } else { Side::Local }
}

fn key_is(text: &str, k: Key) -> bool {
    let c: char = k.into();
    text.chars().eq(std::iter::once(c))
}

/// A local listing's entries, and its count of hidden items (none when it failed).
fn split_hidden(r: vibeftp_core::error::Result<(Vec<Entry>, usize)>) -> (vibeftp_core::error::Result<Vec<Entry>>, usize) {
    match r {
        Ok((e, h)) => (Ok(e), h),
        Err(e) => (Err(e), 0),
    }
}

fn starts_with_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Up to three "name: reason" lines under an optional heading, then a count of the rest.
pub fn summarise(lines: &[String], head: &str) -> String {
    let mut shown = lines.iter().take(3).cloned().collect::<Vec<_>>().join("\n");
    if lines.len() > 3 {
        shown.push_str(&format!("\n…and {} more", lines.len() - 3));
    }
    if head.is_empty() { shown } else { format!("{head}:\n{shown}") }
}

/// The quit question's sentence on copies with unsent edits (`names` not empty): the names
/// capped as `summarise` caps a list (three, then how many more), and where they stay.
fn unsent_sentence(names: &[String], folder: &str) -> String {
    let shown = &names[..names.len().min(3)];
    let who = match (shown, names.len() - shown.len()) {
        ([one], 0) => one.clone(),
        ([rest @ .., last], 0) => format!("{} and {last}", rest.join(", ")),
        (shown, more) => format!("{} and {more} more", shown.join(", ")),
    };
    if names.len() == 1 {
        format!("{who} has edits the server never got; it stays on this computer, under {folder}.")
    } else {
        format!("{who} have edits the server never got; they stay on this computer, under {folder}.")
    }
}

fn proto_name(p: &Protocol) -> &'static str {
    match p {
        Protocol::Sftp => "sftp",
        Protocol::Ftps => "ftps",
        Protocol::Ftp => "ftp",
    }
}

fn warns(l: &LogLine) -> bool {
    l.level == "warn" || l.level == "error"
}

fn log_time(ts: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ts as i64)
        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

fn log_row(l: &LogLine) -> LogRow {
    let kind = if warns(l) {
        1
    } else if l.line.starts_with("> ") {
        2
    } else if l.line.starts_with("< ") {
        3
    } else {
        0
    };
    LogRow { time: log_time(l.ts).into(), line: shown(&l.line).as_ref().into(), kind }
}

impl App {
    /// `check`: About's install check's services (`Check::system` in `main`, fakes in the tests).
    pub fn new(ui: &AppWindow, backend: Rc<dyn Backend>, spawner: Rc<dyn Spawn>, check: Check) -> Rc<App> {
        let panes = [Rc::new(RefCell::new(Pane::new(Side::Local))), Rc::new(RefCell::new(Pane::new(Side::Remote)))];
        let models = [FileModel::new(panes[0].clone()), FileModel::new(panes[1].clone())];
        ui.set_local_items(ModelRc::from(models[0].clone()));
        ui.set_remote_items(ModelRc::from(models[1].clone()));
        let queue: Rc<RefCell<Vec<TRef>>> = Rc::default();
        let queue_model = QueueModel::new(queue.clone());
        ui.set_queue_rows(ModelRc::from(queue_model.clone()));
        let log_model = Rc::new(VecModel::default());
        ui.set_log_rows(ModelRc::from(log_model.clone()));
        let st = State { parallel: 1, ..Default::default() };
        let app = Rc::new(App {
            ui: ui.as_weak(),
            backend,
            spawner,
            panes,
            models,
            st: RefCell::new(st),
            queue,
            by_id: RefCell::default(),
            q_head: Cell::new(0),
            queue_model,
            log_model,
            drain: RefCell::new(None),
            timers: RefCell::default(),
            check,
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
        });
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&crate::check::Rows::idle());
        ui.set_about_line(app.about_line().into());
        app.wire(ui);
        app.start_timers();
        app.push_all();
        app
    }

    /// Main passes the host's synchronous event delivery (see `stop_editing`).
    pub fn set_event_drain(&self, f: impl Fn() + 'static) {
        *self.drain.borrow_mut() = Some(Box::new(f));
    }

    pub(crate) fn drain_events(&self) {
        if let Some(f) = self.drain.borrow().as_ref() {
            f();
        }
    }

    fn start_timers(self: &Rc<Self>) {
        let me = Rc::downgrade(self);
        let samples = Timer::default();
        samples.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            if let Some(a) = me.upgrade() {
                a.sample();
            }
        });
        let me = Rc::downgrade(self);
        let logs = Timer::default();
        logs.start(TimerMode::Repeated, Duration::from_millis(120), move || {
            if let Some(a) = me.upgrade() {
                a.flush_logs();
            }
        });
        self.timers.borrow_mut().extend([samples, logs]);
    }

    fn go<F: Future<Output = ()> + 'static>(self: &Rc<Self>, f: impl FnOnce(Rc<App>) -> F) {
        self.spawner.spawn(Box::pin(f(self.clone())));
    }

    fn pane(&self, side: Side) -> &Rc<RefCell<Pane>> {
        &self.panes[idx(side)]
    }

    fn apply(&self, side: Side, change: Change) {
        // A reset rebuilds the rows: the one holding a drag's pointer grab is gone, and its
        // release can never end that drag. A reset of the target pane leaves the grab alone.
        if matches!(change, Change::Reset) && self.st.borrow().drag.as_ref().is_some_and(|d| d.from == idx(side)) {
            self.drop_stale_drag();
        }
        self.models[idx(side)].apply(change);
    }

    pub fn connected(&self) -> bool {
        self.st.borrow().session.is_some()
    }

    // ---------- pushing state to the window ----------

    fn push_all(&self) {
        self.push_pane(Side::Local);
        self.push_pane(Side::Remote);
        self.push_link();
        self.push_sites();
        self.push_toasts();
        self.push_transfers();
        self.push_bookmarks();
        self.push_edits();
        self.push_sync();
    }

    fn pane_info(&self, side: Side) -> PaneInfo {
        let p = self.pane(side).borrow();
        let st = self.st.borrow();
        let i = idx(side);
        let remote = side == Side::Remote;
        let connected = st.session.is_some();
        let n = p.selected_count();
        let single = if n == 1 { p.selected_entries().into_iter().next() } else { None };
        let (dirs, files) = p.counts();
        let (key, asc) = p.sort();
        let title = if remote {
            st.site.as_ref().map(|s| if s.name.is_empty() { s.host.clone() } else { s.name.clone() }).unwrap_or_else(|| "Remote".into())
        } else {
            "Local".into()
        };
        let root_index = if remote {
            -1
        } else {
            let up = p.path.replace('/', "\\").to_uppercase();
            st.roots.iter().position(|r| up.starts_with(&r.to_uppercase())).map(|i| i as i32).unwrap_or(-1)
        };
        let (drop_hover, drop_path) = match &st.drop {
            Some((s, folder)) if *s == i => (true, folder.clone().unwrap_or_default()),
            _ => (false, String::new()),
        };
        PaneInfo {
            title: title.into(),
            path: shown(&p.path).as_ref().into(),
            offline: remote && !connected,
            loading: p.loading,
            filter_text: p.filter().into(),
            show_filter: st.show_filter[i],
            sort_key: match key {
                SortKey::Name => 0,
                SortKey::Size => 1,
                SortKey::Modified => 2,
            },
            sort_asc: asc,
            can_transfer: n > 0 && connected,
            counts: match p.hidden {
                0 => format!("{dirs} folders, {files} files"),
                1 => format!("{dirs} folders, {files} files · 1 item with a name Windows apps can't show is hidden"),
                n => format!("{dirs} folders, {files} files · {n} items with names Windows apps can't show are hidden"),
            }
            .into(),
            selection: if n > 0 { format!("{n} selected · {}", bytes(p.selected_bytes())).into() } else { SharedString::new() },
            perms: match single.and_then(|e| e.mode) {
                Some(m) if remote => format!("{} {}", rwx(m), octal(m)).into(),
                _ => SharedString::new(),
            },
            cursor_index: p.cursor_index().map(|i| i as i32).unwrap_or(-1),
            scroll_seq: st.scroll_seq[i],
            drop_hover,
            drop_path: drop_path.into(),
            root_index,
        }
    }

    fn push_pane(&self, side: Side) {
        let info = self.pane_info(side);
        if let Some(ui) = self.ui.upgrade() {
            match side {
                Side::Local => ui.set_local(info),
                Side::Remote => ui.set_remote(info),
            }
        }
    }

    pub(crate) fn push_link(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let st = self.st.borrow();
        let connected = st.session.is_some();
        let link = if st.connecting {
            LinkState::Connecting
        } else if !connected {
            if st.last_error.is_some() { LinkState::Error } else { LinkState::Idle }
        } else if st.busy_glyph {
            LinkState::Busy
        } else {
            LinkState::Connected
        };
        let title = if st.connecting { "Connecting…".to_string() } else { st.site.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "Not connected".into()) };
        let sub = match &st.site {
            None if st.connecting => "Opening connection".to_string(),
            // Not connected: an error says why; else the site Connect dials (the one picked
            // last, if it is still saved), else how to pick one.
            None => st.last_error.clone().unwrap_or_else(|| {
                let picked = st.picked.as_deref().and_then(|id| st.sites.iter().find(|s| !id.is_empty() && s.id == id));
                match picked {
                    Some(s) => format!("Connect dials {}", if s.name.is_empty() { &s.host } else { &s.name }),
                    None => "Press Connect to pick a site".into(),
                }
            }),
            Some(s) => {
                let user = if s.username.is_empty() { String::new() } else { format!("{}@", s.username) };
                let host = if s.host.contains(':') { format!("[{}]", s.host) } else { s.host.clone() };
                let proto = proto_name(&s.protocol);
                let port = if s.port != s.protocol.default_port() { format!(":{}", s.port) } else { String::new() };
                let link = if !st.note.is_empty() && st.note != "Reconnected" {
                    st.note.clone()
                } else {
                    let c = st.connections.max(1);
                    format!("{c} connection{}{}", if c == 1 { "" } else { "s" }, if st.busy > 0 { format!(", {} busy", st.busy) } else { String::new() })
                };
                format!("{proto}://{user}{host}{port}  ·  {link}")
            }
        };
        ui.set_link(link);
        ui.set_link_title(shown(&title).as_ref().into());
        ui.set_link_detail(shown(&sub).as_ref().into());
        ui.set_connected(connected);
        ui.set_connecting(st.connecting);
        let status = if !st.status.is_empty() { st.status.clone() } else if connected { "Connected".into() } else { "Not connected".into() };
        ui.set_status_left(status.into());
        ui.set_status_warn(!st.status.is_empty() && st.status_warn);
        ui.set_status_right(if connected { format!("{} conn{}", st.connections.max(1), if st.busy > 0 { format!(" · {} busy", st.busy) } else { String::new() }).into() } else { SharedString::new() });
    }

    fn push_sites(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let st = self.st.borrow();
        let names: Vec<SharedString> = st.sites.iter().map(|s| SharedString::from(shown(&s.name).as_ref())).collect();
        ui.set_site_names(ModelRc::new(VecModel::from(names)));
        let protocols: Vec<SharedString> = st.sites.iter().map(|s| SharedString::from(proto_name(&s.protocol))).collect();
        ui.set_site_details(ModelRc::new(VecModel::from(protocols)));
        // The picker shows the connected (or dialled) site, else the one last picked, by id: an
        // index would point at the next site once one above it is deleted.
        let id = st.site.as_ref().map(|s| s.id.as_str()).or(st.picked.as_deref());
        let i = id.and_then(|id| st.sites.iter().position(|x| !id.is_empty() && x.id == id));
        ui.set_site_index(i.map_or(-1, |i| i as i32));
        let roots: Vec<SharedString> = st.roots.iter().map(|r| SharedString::from(&r[..2.min(r.len())])).collect();
        ui.set_roots(ModelRc::new(VecModel::from(roots)));
    }

    fn push_toasts(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let st = self.st.borrow();
        let items: Vec<ToastItem> = st
            .toasts
            .iter()
            .map(|(id, text, kind, action)| ToastItem { id: *id, text: shown_lines(text).into(), kind: *kind, action: action.as_str().into() })
            .collect();
        ui.set_toasts(ModelRc::new(VecModel::from(items)));
    }

    // ---------- toasts ----------

    pub fn toast(self: &Rc<Self>, text: impl Into<String>, kind: ToastKind) -> i32 {
        self.toast_with(text, kind, None)
    }

    /// A toast with an action button: `action` is (label, a path to show in Explorer).
    pub fn toast_with(self: &Rc<Self>, text: impl Into<String>, kind: ToastKind, action: Option<(String, String)>) -> i32 {
        self.toast_kept(text, kind, action, false)
    }

    /// A notice: an error toast that stays until the user dismisses it (review FR-1, FR-4).
    pub fn notice(self: &Rc<Self>, text: impl Into<String>, show: Option<String>) -> i32 {
        self.toast_kept(text, ToastKind::Error, show.map(|p| ("Show".to_string(), p)), true)
    }

    fn toast_kept(self: &Rc<Self>, text: impl Into<String>, kind: ToastKind, action: Option<(String, String)>, sticky: bool) -> i32 {
        let text: String = text.into();
        if sticky {
            // The same notice once: a file reported again (each reload, each connect) is
            // already on screen until dismissed.
            let st = self.st.borrow();
            if let Some(t) = st.toasts.iter().find(|t| st.sticky.contains(&t.0) && t.1 == text) {
                return t.0;
            }
        }
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            let label = action.as_ref().map(|a| a.0.clone()).unwrap_or_default();
            if let Some((_, target)) = action {
                st.toast_actions.insert(id, target);
            }
            st.toasts.push((id, text, kind, label));
            if sticky {
                st.sticky.insert(id);
            }
            // The newest few only: a burst must not stack a column over the remote pane. A
            // notice stays (it is dismissed by hand).
            let mut over = st.toasts.len().saturating_sub(5);
            let State { toasts, sticky: kept, .. } = &mut *st;
            toasts.retain(|t| {
                let drop = over > 0 && !kept.contains(&t.0);
                if drop {
                    over -= 1;
                }
                !drop
            });
            id
        };
        self.push_toasts();
        if sticky {
            return id;
        }
        let me = Rc::downgrade(self);
        let ms = if kind == ToastKind::Error { 8000 } else { 3000 };
        Timer::single_shot(Duration::from_millis(ms), move || {
            if let Some(a) = me.upgrade() {
                a.dismiss_toast(id);
            }
        });
        id
    }

    pub fn error(self: &Rc<Self>, e: impl std::fmt::Display) {
        self.toast(e.to_string(), ToastKind::Error);
    }

    fn info(self: &Rc<Self>, text: impl Into<String>) {
        self.toast(text, ToastKind::Info);
    }

    pub fn dismiss_toast(&self, id: i32) {
        {
            let mut st = self.st.borrow_mut();
            st.toasts.retain(|t| t.0 != id);
            st.toast_actions.remove(&id);
            st.sticky.remove(&id);
        }
        self.push_toasts();
    }

    fn toast_action(self: &Rc<Self>, id: i32) {
        let target = self.st.borrow().toast_actions.get(&id).cloned();
        self.dismiss_toast(id);
        if let Some(path) = target {
            let b = self.backend.clone();
            self.go(|a| async move {
                if let Err(e) = b.local_reveal(path).await {
                    a.error(e);
                }
            });
        }
    }

    /// Change a remembered preference; only the fields that really changed are written.
    fn remember(&self, f: impl FnOnce(&mut crate::prefs::Prefs)) {
        let (p, fields) = {
            let mut st = self.st.borrow_mut();
            let before = st.prefs.clone();
            f(&mut st.prefs);
            (st.prefs.clone(), before.diff(&st.prefs))
        };
        if fields != 0 {
            self.backend.save_prefs(p, fields);
        }
    }

    // ---------- updates ----------

    /// Look for a newer version. `manual` (the menu): say what came of it either way.
    pub async fn check_update(self: Rc<Self>, manual: bool) {
        match self.backend.update_check().await {
            Ok(Some(offer)) => {
                if let Some(ui) = self.ui.upgrade() {
                    ui.set_update_version(offer.version.as_str().into());
                }
                self.st.borrow_mut().update = Some(offer);
            }
            Ok(None) => {
                if manual {
                    self.toast("You're on the latest version".to_string(), ToastKind::Ok);
                }
            }
            Err(e) => {
                if manual {
                    self.info(format!("Could not check for updates: {e}"));
                }
            }
        }
    }

    /// The bar's "Update to ...": ask as a quit would, look again (the offer may have moved on),
    /// download and verify, ask again if work began meanwhile, start the installer and quit.
    /// Any failure keeps this app running.
    pub async fn install_update(self: Rc<Self>) {
        if self.st.borrow().updating || !self.confirm_leave("Update and restart").await {
            return;
        }
        let asked = self.work();
        self.st.borrow_mut().updating = true;
        self.push_updating();
        match self.backend.update_check().await {
            Ok(None) => {
                {
                    let mut st = self.st.borrow_mut();
                    st.update = None;
                    st.ready = None;
                }
                if let Some(ui) = self.ui.upgrade() {
                    ui.set_update_version(SharedString::new());
                }
                self.info("That update is no longer available".to_string());
            }
            Err(e) => self.error(format!("Update failed: {e}")),
            Ok(Some(offer)) => {
                if let Some(ui) = self.ui.upgrade() {
                    ui.set_update_version(offer.version.as_str().into());
                }
                // A download kept from an earlier click, if it is still the version on offer.
                let version = offer.version.clone();
                let kept = self.st.borrow_mut().ready.take().filter(|(v, _)| *v == version).map(|(_, r)| r);
                let ready = match kept {
                    Some(r) => Ok(r),
                    None => self.backend.update_download(offer).await,
                };
                match ready {
                    Err(e) => self.error(format!("Update failed: {e}")),
                    Ok(ready) => {
                        // The download can take a while, and the window stays usable. A dialog
                        // the user is in now must not be replaced by a question, and work begun
                        // since the first answer is asked about, not cut short. Either way the
                        // download is kept for the next click.
                        let in_dialog = self.ui.upgrade().is_some_and(|u| u.get_dialog_open());
                        let more = !self.work().is_subset(&asked);
                        if in_dialog || (more && !self.confirm_leave("Update and restart").await) {
                            self.st.borrow_mut().ready = Some((version, ready));
                            self.info("The update is downloaded and checked. Click Update again to install it.".to_string());
                        } else {
                            // The installer's restart must not stop at the close guard.
                            self.st.borrow_mut().leaving = true;
                            match self.backend.update_start(ready) {
                                Ok(()) => {
                                    let _ = slint::quit_event_loop();
                                    return;
                                }
                                Err(e) => {
                                    self.st.borrow_mut().leaving = false;
                                    self.error(format!("Update failed: {e}"));
                                }
                            }
                        }
                    }
                }
            }
        }
        self.st.borrow_mut().updating = false;
        self.push_updating();
    }

    fn push_updating(&self) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_updating(self.st.borrow().updating);
        }
    }

    // ---------- engine events ----------

    pub fn on_event(self: &Rc<Self>, event: Event) {
        match event {
            Event::Log(l) => self.st.borrow_mut().log_buffer.push(l),
            Event::SessionState(s) => {
                let mine = self.st.borrow().session.as_deref() == Some(s.session.as_str());
                if mine {
                    {
                        let mut st = self.st.borrow_mut();
                        st.connections = s.connections;
                        st.busy = s.busy;
                        st.note = s.note.clone();
                    }
                    if s.note == "Reconnected" {
                        self.toast("Reconnected", ToastKind::Ok);
                    }
                    self.push_link();
                }
            }
            Event::Progress(p) => self.on_progress(p),
            Event::Conflict(c) => self.on_conflict(c),
            Event::Skipped(s) => self.on_skipped(s),
            Event::EditChanged(e) => self.on_edit_changed(e),
            Event::Notice { text, path } => {
                // Told here: no other window tells about this kept copy again (FR2-6).
                if let Some(name) = path.as_deref().and_then(sites::kept_name) {
                    self.mark_told(name);
                }
                self.notice(text, path);
            }
        }
    }

    fn flush_logs(&self) {
        let fresh = std::mem::take(&mut self.st.borrow_mut().log_buffer);
        if fresh.is_empty() {
            return;
        }
        let trimmed = {
            let mut st = self.st.borrow_mut();
            if let Some(last) = fresh.last() {
                st.status = shown(last.line.lines().next().unwrap_or("")).into_owned();
                st.status_warn = warns(last);
            }
            st.logs.extend(fresh.iter().cloned());
            if st.logs.len() > 2000 {
                let n = st.logs.len() - 1500;
                st.logs.drain(..n);
                true
            } else {
                false
            }
        };
        if trimmed {
            self.rebuild_log_view();
        } else {
            let f = self.st.borrow().log_filter.to_lowercase();
            for l in fresh.iter().filter(|l| f.is_empty() || l.line.to_lowercase().contains(&f)) {
                self.log_model.push(log_row(l));
            }
            self.log_changed();
        }
        self.push_link();
    }

    fn rebuild_log_view(&self) {
        let st = self.st.borrow();
        let f = st.log_filter.to_lowercase();
        let rows: Vec<LogRow> = st.logs.iter().filter(|l| f.is_empty() || l.line.to_lowercase().contains(&f)).map(log_row).collect();
        drop(st);
        self.log_model.set_vec(rows);
        self.log_changed();
    }

    fn log_changed(&self) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_log_seq(ui.get_log_seq().wrapping_add(1));
        }
    }

    // ---------- boot ----------

    pub fn boot(self: &Rc<Self>) {
        let prefs = self.backend.prefs();
        if let Some(ui) = self.ui.upgrade() {
            ui.global::<Theme>().set_dark(prefs.dark());
            ui.set_bar_thick(prefs.thick());
            ui.set_log_open(prefs.log);
            ui.set_update_at_start(prefs.update_at_start);
        }
        {
            let mut st = self.st.borrow_mut();
            st.local_path_pref = prefs.local_path.clone();
            st.prefs = prefs;
        }
        if self.backend.prefs_broken() {
            self.error("prefs.json could not be read: the window's settings are back to their defaults, and the old file will be kept as prefs.json.broken.");
        }
        // A quiet look for a newer version once the window has settled (so startup stays quick),
        // unless the user turned that off in the menu (asked when the timer fires, so turning it
        // off in the first seconds counts too). The menu's "Check for updates" always asks.
        let me = Rc::downgrade(self);
        let timer = Timer::default();
        timer.start(TimerMode::SingleShot, Duration::from_secs(4), move || {
            // The borrow ends inside `filter`, before the look starts.
            if let Some(a) = me.upgrade().filter(|a| a.st.borrow().prefs.update_at_start) {
                a.go(|a| a.check_update(false));
            }
        });
        self.st.borrow_mut().update_timer = Some(timer);
        self.go(|a| async move {
            match a.backend.local_roots().await {
                Ok(r) => a.st.borrow_mut().roots = r,
                Err(e) => a.error(e),
            }
            #[cfg(feature = "dev-hooks")]
            if let Ok(p) = std::env::var("VIBEFTP_DEV_LOCAL") {
                a.st.borrow_mut().local_path_pref = p;
            }
            let last = a.st.borrow().local_path_pref.clone();
            // Home only when the remembered folder failed: a superseded listing (`None`) means
            // the user already went somewhere else, which must stay on screen. Unless that
            // failed as well and the pane has no folder at all: then home after all, decided by
            // whichever of the two listings settles last.
            let back = if last.is_empty() { Some(false) } else { a.navigate(Side::Local, last, true, None).await };
            let home = match back {
                Some(ok) => !ok,
                None => {
                    let (nowhere, loading) = {
                        let p = a.pane(Side::Local).borrow();
                        (p.path.is_empty(), p.loading)
                    };
                    a.st.borrow_mut().home_if_nowhere = nowhere && loading;
                    nowhere && !loading
                }
            };
            if home {
                a.go_home().await;
            }
            a.reload_sites().await;
            a.push_pane(Side::Local);
        });
    }

    // ---------- connection ----------

    /// Ask before a reconnect, disconnect or quit would kill work in progress.
    pub async fn confirm_leave(self: &Rc<Self>, verb: &str) -> bool {
        // A file still downloading for editing is a queue row, so it counts as a transfer. A save
        // the watcher has not announced yet only exists while its file is open for editing.
        // Edits the server never got stay on this computer: they count as work even with nothing
        // open and nothing running (a failed save, then stop editing: RVA6-1).
        let (n, e) = (self.pending_count(), self.st.borrow().editing.len());
        let unsent = self.backend.unsent_edits();
        if n == 0 && e == 0 && unsent.is_empty() {
            return true;
        }
        let mut parts = Vec::new();
        if n > 0 {
            parts.push(format!("{n} transfer{} running", if n == 1 { "" } else { "s" }));
        }
        if e > 0 {
            parts.push(format!("{e} file{} open for editing", if e == 1 { "" } else { "s" }));
        }
        let mut said = Vec::new();
        if !parts.is_empty() {
            said.push(format!("{}.", parts.join(" and ")));
        }
        // Say which, and where (after a quit nothing else can), before they are left there.
        if !unsent.is_empty() {
            said.push(unsent_sentence(&unsent, &self.backend.edit_folder()));
        }
        said.push(format!("{verb} anyway?"));
        self.confirm(&format!("{verb}?"), &said.join(" "), verb, true).await
    }

    /// While a connect is in flight the glyph click cancels it.
    pub fn abort_connect(self: &Rc<Self>) {
        {
            let mut st = self.st.borrow_mut();
            if !st.connecting {
                return;
            }
            st.connect_seq += 1;
            st.connecting = false;
        }
        self.push_link();
        self.info("Connection attempt cancelled");
    }

    /// Ask for a password or key passphrase. "Save" puts it in the keychain; a failed save is
    /// reported and the connect goes on with what was typed.
    async fn ask_secret(self: &Rc<Self>, site: Site, label: &str) -> Option<(Site, String)> {
        let title = if site.name.is_empty() { site.host.clone() } else { site.name.clone() };
        let (pw, save) = self.ask_password(&title, label).await?;
        let site = if save { self.save_secret(site, &pw).await } else { site };
        Some((site, pw))
    }

    pub async fn connect(self: Rc<Self>, mut site: Site, mut password: Option<String>) {
        if self.st.borrow().connecting {
            self.abort_connect(); // picking another site mid-dial starts over
        }
        if self.connected() && !self.confirm_leave("Switch site").await {
            self.push_sites(); // the picker goes back to the site still connected
            return;
        }
        let seq = {
            let mut st = self.st.borrow_mut();
            st.picked = Some(site.id.clone());
            st.connect_seq += 1;
            st.connecting = true;
            st.connect_seq
        };
        self.push_link();
        let current = |a: &App| a.st.borrow().connect_seq == seq;
        let mut failure: Option<AppError> = None;
        'attempt: {
            if self.connected() {
                self.clone().disconnect().await;
            }
            // Cancelled (or another site picked) during the old session's hang-up: no prompt,
            // no keychain write, no dial for this attempt.
            if !current(&self) {
                break 'attempt;
            }
            // A key's passphrase is asked for only once the backend finds the key encrypted:
            // most keys have none (C1-F10-8).
            let key_site = site.protocol == Protocol::Sftp && !site.key_path.is_empty();
            if !site.has_password && !key_site && !site.username.is_empty() && password.is_none() {
                let Some((s, pw)) = self.ask_secret(site.clone(), "Password").await else { break 'attempt };
                if !current(&self) {
                    break 'attempt;
                }
                site = s;
                password = Some(pw);
            }
            self.st.borrow_mut().last_error = None;
            let r = match self.backend.connect(site.clone(), password.clone()).await {
                Ok(r) => r,
                Err(e) => {
                    if current(&self) {
                        failure = Some(e);
                    }
                    break 'attempt;
                }
            };
            if !current(&self) {
                // Cancelled (or superseded) while dialing: hand the session straight back.
                let b = self.backend.clone();
                let s = r.session.clone();
                self.go(|_| async move {
                    let _ = b.disconnect(s).await;
                });
                break 'attempt;
            }
            {
                let mut st = self.st.borrow_mut();
                st.session = Some(r.session.clone());
                st.site = Some(st.sites.iter().find(|s| s.id == site.id).cloned().unwrap_or_else(|| site.clone()));
                st.parallel = r.parallel.max(1);
                st.connections = 1;
                st.busy = 0;
                st.note.clear();
                st.status.clear();
                st.connecting = false; // from here on "cancel" means disconnect, not abort
            }
            self.pane(Side::Remote).borrow_mut().path = r.cwd.clone();
            self.push_all();
            // The panes are live from here: a folder the user opens while the first listing is
            // on its way wins over the remembered one.
            let (rseq, lseq) = (self.pane(Side::Remote).borrow().seq, self.pane(Side::Local).borrow().seq);
            self.refresh(Side::Remote).await;
            let mine = |a: &App| a.st.borrow().session.as_deref() == Some(r.session.as_str());
            if !mine(&self) {
                break 'attempt; // disconnected or switched meanwhile
            }
            if site.remote_path.is_empty() && !site.last_remote.is_empty() && site.last_remote != r.cwd && self.pane(Side::Remote).borrow().seq == rseq {
                self.navigate(Side::Remote, site.last_remote.clone(), true, None).await;
            }
            if !mine(&self) {
                break 'attempt;
            }
            let local = if site.local_path.is_empty() { site.last_local.clone() } else { site.local_path.clone() };
            if !local.is_empty() && self.pane(Side::Local).borrow().seq == lseq {
                self.navigate(Side::Local, local, true, Some(r.session.clone())).await;
            }
            if mine(&self) {
                self.toast(format!("Connected to {}", site.name), ToastKind::Ok);
            }
        }
        if current(&self) {
            self.st.borrow_mut().connecting = false;
        }
        if let Some(e) = failure {
            self.st.borrow_mut().last_error = Some(e.to_string());
            self.push_link();
            self.handle_connect_error(e, site, password).await;
        }
        self.push_link();
    }

    /// Host key and certificate prompts show the fingerprint and pin exactly that one; a missing
    /// saved password or a locked key asks for it. Then the connect runs again.
    async fn handle_connect_error(self: &Rc<Self>, e: AppError, site: Site, password: Option<String>) {
        let again = |a: Rc<App>, site: Site, password: Option<String>| Box::pin(a.connect(site, password));
        let trust_host = |fp: String| self.backend.trust_host_key(site.host.clone(), site.port, fp);
        let trust_cert = |fp: String| self.backend.trust_certificate(site.host.clone(), site.port, fp);
        // A server whose key (certificate) is in a kept copy of a damaged known_hosts.json, and
        // not trusted again since, was trusted before: its prompt says so, with the pin it had,
        // not only a notice the user may have dismissed (review FR-4, FR2-2), and asks for an
        // explicit choice, none made at first. Other servers get the usual prompt.
        let before = |cert: bool| {
            let (host, port) = (site.host.clone(), site.port);
            async move {
                self.tell_kept().await;
                self.backend.pinned_before(host, port, cert).await.ok().flatten()
            }
        };
        let title = format!("First connection to {}", site.host);
        let choose = |body: String, fingerprint: String, p: vibeftp_core::types::PinnedBefore, cert: bool| {
            let title = title.clone();
            async move {
                let trust = if cert { "Trust this certificate" } else { "Trust this key" };
                let warning = trusted_before(&p, cert, &fingerprint);
                let choice = dialogs::Choice { warning: &warning, label: TRUST_CHOICE, options: &[trust, DONT_CONNECT] };
                self.choose(&title, &body, "Confirm", choice).await == Some(0)
            }
        };
        match &e {
            AppError::HostKeyUnknown { fingerprint, .. } => {
                let ok = match before(false).await {
                    Some(p) => choose(format!("The server identifies itself with the key\n{fingerprint}"), fingerprint.clone(), p, false).await,
                    None => {
                        self.confirm(
                            &title,
                            &format!("The server identifies itself with the key\n{fingerprint}\n\nTrust it and remember it for this host?"),
                            "Trust and connect",
                            false,
                        )
                        .await
                    }
                };
                if ok {
                    match trust_host(fingerprint.clone()).await {
                        Ok(()) => again(self.clone(), site, password).await,
                        Err(e) => self.error(e),
                    }
                }
            }
            AppError::HostKeyChanged { expected, actual, .. } => {
                let ok = self
                    .confirm(
                        &format!("Host key for {} CHANGED", site.host),
                        &format!("Was: {expected}\nNow: {actual}\n\nThis happens after a server reinstall, but it is also what an attacker in the middle looks like. Trust the new key?"),
                        "Trust new key",
                        true,
                    )
                    .await;
                if ok {
                    match trust_host(actual.clone()).await {
                        Ok(()) => again(self.clone(), site, password).await,
                        Err(e) => self.error(e),
                    }
                }
            }
            AppError::HostKeyTypeChanged { old_type, new_type, fingerprint, .. } => {
                let ok = self
                    .confirm(
                        &format!("New host key type for {}", site.host),
                        &format!("The server no longer offers the {old_type} key you trusted and now presents a {new_type} key:\n{fingerprint}\n\nThis is usual after a server upgrade. If you did not expect it, check the fingerprint with the server's admin. Trust the new key?"),
                        "Trust new key",
                        false,
                    )
                    .await;
                if ok {
                    match trust_host(fingerprint.clone()).await {
                        Ok(()) => again(self.clone(), site, password).await,
                        Err(e) => self.error(e),
                    }
                }
            }
            // FTPS: a certificate no public authority vouches for (self-signed, private CA, other name).
            AppError::CertUnknown { fingerprint, reason, .. } => {
                let why = if reason.is_empty() { String::new() } else { format!(" ({reason})") };
                let head = format!("No public authority vouches for this server's certificate{why}. Its fingerprint:\n{fingerprint}");
                let ok = match before(true).await {
                    Some(p) => choose(head, fingerprint.clone(), p, true).await,
                    None => {
                        self.confirm(&title, &format!("{head}\n\nTrust this certificate and remember it for this host?"), "Trust and connect", false)
                            .await
                    }
                };
                if ok {
                    match trust_cert(fingerprint.clone()).await {
                        Ok(()) => again(self.clone(), site, password).await,
                        Err(e) => self.error(e),
                    }
                }
            }
            AppError::CertChanged { expected, actual, .. } => {
                let ok = self
                    .confirm(
                        &format!("Certificate for {} CHANGED", site.host),
                        &format!("Was: {expected}\nNow: {actual}\n\nThis happens when the server gets a new certificate, but it is also what an attacker in the middle looks like. Trust the new certificate?"),
                        "Trust new certificate",
                        true,
                    )
                    .await;
                if ok {
                    match trust_cert(actual.clone()).await {
                        Ok(()) => again(self.clone(), site, password).await,
                        Err(e) => self.error(e),
                    }
                }
            }
            // The site says a password is saved, but the keychain has none or cannot be read.
            AppError::SecretUnavailable(why) => {
                let what = if site.protocol == Protocol::Sftp && !site.key_path.is_empty() { "Key passphrase" } else { "Password" };
                if let Some((s, pw)) = self.ask_secret(site.clone(), &format!("{what} (the saved one is unavailable: {why})")).await {
                    again(self.clone(), s, Some(pw)).await;
                }
            }
            // An encrypted key without a passphrase, or with one that does not open it.
            _ if site.protocol == Protocol::Sftp
                && !site.key_path.is_empty()
                && (e.to_string().starts_with("The key is encrypted") || matches!(e, AppError::WrongPassphrase)) =>
            {
                let locked = e.to_string().starts_with("The key is encrypted");
                let label = if locked { "Key passphrase" } else { "Key passphrase (the one given did not open the key)" };
                if let Some((s, pw)) = self.ask_secret(site.clone(), label).await
                    && !pw.is_empty()
                {
                    again(self.clone(), s, Some(pw)).await;
                }
            }
            _ => self.error(e),
        }
    }

    pub async fn disconnect(self: Rc<Self>) {
        let s = {
            let mut st = self.st.borrow_mut();
            st.site = None;
            st.last_error = None;
            st.connections = 0;
            st.busy = 0;
            st.note.clear();
            st.status.clear();
            st.show_filter[1] = false;
            st.editing.clear();
            st.conflicts.clear();
            st.policy_by_id.clear();
            st.sync_root = None;
            // A follow-up or debounced refresh the old session's transfers left would list the
            // next session's folder (S1b). Local ones stay: those files did change.
            st.refresh_again[1] = None;
            st.refresh_timers[1] = None;
            st.session.take()
        };
        let change = {
            let mut p = self.pane(Side::Remote).borrow_mut();
            p.seq += 1; // any listing still in flight for the old session is dropped
            p.loading = false;
            p.arrive(String::new(), Vec::new())
        };
        self.apply(Side::Remote, change);
        // Repaint only the rows cancelled here (after the borrow: Slint reads them right away).
        let cancelled: Vec<usize> = {
            let q = self.queue.borrow();
            let n = q.len();
            let mut rows = Vec::new();
            for (i, t) in q.iter().enumerate() {
                let mut t = t.borrow_mut();
                if Some(&t.session) == s.as_ref() && t.status == transfers::Status::Queued {
                    t.status = transfers::Status::Cancelled;
                    rows.push(n - 1 - i);
                }
            }
            rows
        };
        for row in cancelled {
            self.queue_model.row_changed(row);
        }
        self.perms_close(); // its paths belong to the session that ends here
        self.push_conflict();
        self.push_all();
        let Some(s) = s else { return };
        // Edit copies holding saves the server never got stay on disk: say where.
        let kept = self.backend.disconnect(s).await.unwrap_or_default();
        if let Some(first) = kept.first() {
            let lines: Vec<String> = kept.iter().map(|k| format!("{}: {}", k.name, k.local)).collect();
            self.toast_with(
                summarise(&lines, "Not uploaded, your edited copies are kept here"),
                ToastKind::Error,
                Some(("Show".into(), first.local.clone())),
            );
        }
    }

    /// The bar's Connect button: cancel a dial, disconnect, or connect the picked site.
    pub fn connect_clicked(self: &Rc<Self>) {
        let (connecting, connected) = {
            let st = self.st.borrow();
            (st.connecting, st.session.is_some())
        };
        if connecting {
            self.abort_connect();
        } else if connected {
            self.go(|a| async move {
                if a.confirm_leave("Disconnect").await {
                    a.disconnect().await;
                }
            });
        } else {
            let pick = self.ui.upgrade().map(|u| u.get_site_index()).unwrap_or(-1);
            if pick >= 0 { self.site_picked(pick) } else { self.open_site_manager() }
        }
    }

    /// Measurement builds only (feature `dev-hooks`): connect a saved site at startup
    /// (VIBEFTP_DEV_CONNECT=<site id>, with VIBEFTP_DEV_PASSWORD), so a live check needs no clicks.
    #[cfg(feature = "dev-hooks")]
    pub fn dev_connect(self: &Rc<Self>, id: String, password: Option<String>) {
        self.go(|a| async move {
            // The site list arrives with boot; give it a moment.
            for _ in 0..50 {
                if !a.st.borrow().sites.is_empty() {
                    break;
                }
                let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                Timer::single_shot(Duration::from_millis(100), move || {
                    let _ = tx.send(());
                });
                let _ = rx.await;
            }
            let site = a.st.borrow().sites.iter().find(|s| s.id == id).cloned();
            match site {
                Some(s) => a.clone().connect(s, password).await,
                None => a.error(format!("VIBEFTP_DEV_CONNECT: no site {id}")),
            }
            // A connect opens the site's own local folder: a requested one goes on top of that.
            if let Ok(p) = std::env::var("VIBEFTP_DEV_LOCAL") {
                a.navigate(Side::Local, p, false, None).await;
            }
        });
    }

    pub fn site_picked(self: &Rc<Self>, i: i32) {
        let site = self.st.borrow().sites.get(i.max(0) as usize).cloned();
        if let Some(s) = site.filter(|_| i >= 0) {
            self.go(|a| a.connect(s, None));
        }
    }

    /// The window's close button: ask first when work would be cut short or edits the server
    /// never got would be left behind (RVA6-1).
    pub fn close_requested(self: &Rc<Self>) -> CloseRequestResponse {
        let busy = self.pending_count() > 0 || !self.st.borrow().editing.is_empty() || !self.backend.unsent_edits().is_empty();
        if self.st.borrow().leaving || !busy {
            return CloseRequestResponse::HideWindow;
        }
        self.go(|a| async move {
            if a.confirm_leave("Quit").await {
                a.st.borrow_mut().leaving = true;
                let _ = slint::quit_event_loop();
            }
        });
        CloseRequestResponse::KeepWindowShown
    }

    // ---------- navigation ----------

    /// `Some(true)` navigated, `Some(false)` failed, `None` superseded by a newer navigation.
    /// `owner`: the session this navigation belongs to (a connect opening the site's local
    /// folder); it is dropped if that session is gone when the listing lands.
    pub async fn navigate(self: &Rc<Self>, side: Side, path: String, quiet: bool, owner: Option<String>) -> Option<bool> {
        let remote = side == Side::Remote;
        if remote && !self.connected() {
            return Some(false);
        }
        let mut path = path;
        if !remote && starts_with_drive(&path) {
            path = path.replace('/', "\\").trim_end_matches('\\').to_string();
            if path.len() == 2 {
                path.push('\\');
            }
        }
        if remote && !path.starts_with('~') {
            // Relative input is relative to the folder on screen, not to the connection's cwd.
            // A leading `~` is left for servers that expand it (FTP home shorthand).
            if !path.starts_with('/') {
                let here = self.pane(side).borrow().path.clone();
                path = join_path(if here.is_empty() { "/" } else { &here }, &path, true);
            }
            path = normalize_remote(&path);
        }
        let session = self.st.borrow().session.clone();
        let seq = {
            let mut p = self.pane(side).borrow_mut();
            p.seq += 1;
            p.loading = true;
            p.seq
        };
        self.push_pane(side);
        let (res, hidden) = if remote {
            (self.backend.remote_list(session.clone().unwrap_or_default(), path.clone()).await, 0)
        } else {
            split_hidden(self.backend.local_list(path.clone()).await)
        };
        let stale = |a: &App| {
            a.pane(side).borrow().seq != seq
                || (remote && a.st.borrow().session != session)
                || (owner.is_some() && a.st.borrow().session != owner)
        };
        if stale(self) {
            // A newer navigation owns `loading`; one dropped for its session alone does not.
            let mine = {
                let mut p = self.pane(side).borrow_mut();
                let mine = p.seq == seq;
                if mine {
                    p.loading = false;
                }
                mine
            };
            if mine {
                self.push_pane(side);
                // Dropped for its session (a disconnect), not overtaken: boot's fallback still
                // applies if the pane is left with no folder.
                if !remote && std::mem::take(&mut self.st.borrow_mut().home_if_nowhere) && self.pane(side).borrow().path.is_empty() {
                    Box::pin(self.go_home()).await;
                }
            }
            return None;
        }
        self.pane(side).borrow_mut().loading = false;
        match res {
            Ok(entries) => {
                if remote {
                    self.browsed();
                }
                // `~` is expanded by the server: show (and walk up from, and sync against) the
                // folder it named, taken from the rows. An empty home keeps the `~`.
                if remote && path.starts_with('~')
                    && let Some(first) = entries.first()
                {
                    path = parent_path(&first.path, true).unwrap_or(path);
                }
                let prev = self.pane(side).borrow().path.clone();
                self.pane(side).borrow_mut().hidden = hidden;
                let change = self.pane(side).borrow_mut().arrive(path.clone(), entries);
                self.apply(side, change);
                if !remote {
                    self.st.borrow_mut().local_path_pref = path.clone();
                    self.remember(|p| p.local_path = path.clone());
                }
                self.push_pane(side);
                self.touch_site();
                if !quiet && self.st.borrow().sync_root.is_some() && prev != path {
                    Box::pin(self.mirror(side, path)).await;
                }
                Some(true)
            }
            Err(e) => {
                if remote {
                    self.browsed();
                }
                self.push_pane(side);
                if !quiet {
                    self.error(e);
                }
                // The navigation that beat boot's remembered folder failed: see boot.
                if !remote && std::mem::take(&mut self.st.borrow_mut().home_if_nowhere) && self.pane(side).borrow().path.is_empty() {
                    Box::pin(self.go_home()).await;
                }
                Some(false)
            }
        }
    }

    async fn go_home(self: &Rc<Self>) {
        match self.backend.local_home().await {
            Ok(home) => {
                self.navigate(Side::Local, home, false, None).await;
            }
            Err(e) => self.error(e),
        }
    }

    pub async fn refresh(self: &Rc<Self>, side: Side) {
        let remote = side == Side::Remote;
        if remote && !self.connected() {
            return;
        }
        // S42: every refresh takes a generation, and only the newest one's answer lands (letting
        // whichever answers last win would rely on one session's listings coming back in
        // order). Navigation still wins over both through `seq`.
        let (path, seq, generation) = {
            let mut p = self.pane(side).borrow_mut();
            p.loading = true;
            p.refresh_gen += 1;
            (p.path.clone(), p.seq, p.refresh_gen) // observe seq, don't bump: a navigation in flight must win
        };
        let session = self.st.borrow().session.clone();
        self.push_pane(side);
        let (res, hidden) = if remote {
            (self.backend.remote_list(session.clone().unwrap_or_default(), path.clone()).await, 0)
        } else {
            split_hidden(self.backend.local_list(path.clone()).await)
        };
        let stale = {
            let p = self.pane(side).borrow();
            p.path != path || p.seq != seq || p.refresh_gen != generation || (remote && self.st.borrow().session != session)
        };
        if stale {
            return;
        }
        self.pane(side).borrow_mut().loading = false;
        match res {
            Ok(entries) => {
                if remote {
                    self.browsed();
                }
                // Filter what is selected *now*, not what was selected before the await.
                self.pane(side).borrow_mut().hidden = hidden;
                let change = self.pane(side).borrow_mut().refreshed(entries);
                self.apply(side, change);
                let name = self.pane(side).borrow_mut().select_after.take();
                if let Some(name) = name {
                    self.select_by_name(side, &name);
                }
            }
            Err(e) => {
                self.pane(side).borrow_mut().select_after = None;
                if remote {
                    self.browsed();
                }
                self.error(e);
            }
        }
        self.push_pane(side);
    }

    /// A listing came back (or failed for good): any redial it triggered is over, so a
    /// "Reconnecting…" note must not stay up.
    fn browsed(&self) {
        let changed = {
            let mut st = self.st.borrow_mut();
            let n = st.note == "Reconnecting…";
            if n {
                st.note.clear();
            }
            n
        };
        if changed {
            self.push_link();
        }
    }

    /// Remember the folders on screen for this site (debounced, also kept in memory so a later
    /// save does not roll them back).
    fn touch_site(self: &Rc<Self>) {
        let (id, r, l) = {
            let mut st = self.st.borrow_mut();
            let Some(site) = st.site.as_ref() else { return };
            if site.id.is_empty() || st.session.is_none() {
                return;
            }
            let id = site.id.clone();
            let r = self.panes[1].borrow().path.clone();
            let l = self.panes[0].borrow().path.clone();
            if let Some(s) = st.site.as_mut() {
                s.last_remote = r.clone();
                s.last_local = l.clone();
            }
            if let Some(s) = st.sites.iter_mut().find(|s| s.id == id) {
                s.last_remote = r.clone();
                s.last_local = l.clone();
            }
            (id, r, l)
        };
        let me = Rc::downgrade(self);
        let timer = Timer::default();
        timer.start(TimerMode::SingleShot, Duration::from_millis(600), move || {
            if let Some(a) = me.upgrade() {
                let b = a.backend.clone();
                let (id, r, l) = (id.clone(), r.clone(), l.clone());
                a.go(|_| async move {
                    let _ = b.site_touch(id, r, l).await;
                });
            }
        });
        self.st.borrow_mut().touch_timer = Some(timer);
    }

    pub fn up(self: &Rc<Self>, side: Side) {
        let parent = {
            let p = self.pane(side).borrow();
            parent_path(&p.path, p.remote())
        };
        if let Some(p) = parent {
            self.go(|a| async move {
                a.navigate(side, p, false, None).await;
            });
        }
    }

    /// Double-click / Enter: folders open, local files open in their app, remote files open for
    /// editing.
    pub fn open(self: &Rc<Self>, side: Side, entry: Entry) {
        let (remote, here) = {
            let p = self.pane(side).borrow();
            (p.remote(), p.path.clone())
        };
        if entry.is_dir {
            // Remote folders by the path the user walked: SFTP rows carry the real path behind
            // a symlinked folder, which would leave the synced tree and make Up jump elsewhere.
            let target = if remote && !here.is_empty() { join_path(&here, &entry.name, true) } else { entry.path.clone() };
            self.go(|a| async move {
                a.navigate(side, target, false, None).await;
            });
            return;
        }
        if !remote {
            self.go(|a| async move {
                match a.backend.local_open(entry.path.clone()).await {
                    Ok(true) => {}
                    Ok(false) => a.info(format!("{} can run code, so it was shown in Explorer instead of opened", entry.name)),
                    Err(e) => a.error(e),
                }
            });
            return;
        }
        self.go(|a| a.edit_remote(entry));
    }

    // ---------- selection, sort, filter ----------

    pub fn row_pressed(self: &Rc<Self>, side: Side, row: usize, ctrl: bool, shift: bool) {
        self.drop_stale_drag();
        let i = idx(side);
        self.st.borrow_mut().focused = i;
        let change = {
            let mut p = self.pane(side).borrow_mut();
            let path = p.view_entry(row).map(|e| e.path.clone());
            if !ctrl && !shift && p.selected_count() > 1 && path.as_deref().is_some_and(|x| p.is_selected(x)) {
                self.st.borrow_mut().pending_collapse = path.map(|x| (i, x));
                Change::None
            } else {
                self.st.borrow_mut().pending_collapse = None;
                p.select(row, ctrl, shift)
            }
        };
        self.apply(side, change);
        self.push_pane(side);
    }

    pub fn row_clicked(self: &Rc<Self>, side: Side, row: usize) {
        let pending = self.st.borrow_mut().pending_collapse.take();
        if let Some((i, path)) = pending
            && i == idx(side) && self.pane(side).borrow().view_index_of(&path) == Some(row)
        {
            let change = self.pane(side).borrow_mut().select(row, false, false);
            self.apply(side, change);
            self.push_pane(side);
        }
    }

    pub fn blank_pressed(self: &Rc<Self>, side: Side) {
        self.drop_stale_drag();
        // The offline remote pane is only its "Not connected" overlay: a press there selects nothing and must not take the keyboard's pane.
        if side == Side::Remote && !self.connected() {
            return;
        }
        self.st.borrow_mut().focused = idx(side);
        let change = self.pane(side).borrow_mut().clear_selection();
        self.apply(side, change);
        self.push_pane(side);
    }

    pub fn sort(self: &Rc<Self>, side: Side, key: i32) {
        let key = match key {
            1 => SortKey::Size,
            2 => SortKey::Modified,
            _ => SortKey::Name,
        };
        let change = self.pane(side).borrow_mut().sort_by(key);
        self.apply(side, change);
        self.push_pane(side);
    }

    pub fn open_filter(self: &Rc<Self>, side: Side) {
        self.st.borrow_mut().show_filter[idx(side)] = true;
        self.push_pane(side);
    }

    pub fn set_filter(self: &Rc<Self>, side: Side, text: &str) {
        let change = self.pane(side).borrow_mut().set_filter(text);
        self.apply(side, change);
        self.push_pane(side);
    }

    pub fn close_filter(self: &Rc<Self>, side: Side) {
        self.st.borrow_mut().show_filter[idx(side)] = false;
        self.set_filter(side, "");
    }

    pub fn pick_root(self: &Rc<Self>, i: usize) {
        let root = self.st.borrow().roots.get(i).cloned();
        if let Some(r) = root {
            self.go(|a| async move {
                if a.navigate(Side::Local, r, false, None).await != Some(true) {
                    a.push_pane(Side::Local); // put the picker back on the drive on screen
                }
            });
        }
    }

    fn scroll_to_cursor(&self, side: Side) {
        self.st.borrow_mut().scroll_seq[idx(side)] += 1;
    }

    fn select_change(self: &Rc<Self>, side: Side, change: Change) {
        self.apply(side, change);
        self.scroll_to_cursor(side);
        self.push_pane(side);
    }

    // ---------- keyboard (the list's keys) ----------

    #[allow(clippy::too_many_arguments)]
    pub fn list_key(self: &Rc<Self>, side: Side, text: &str, ctrl: bool, shift: bool, alt: bool, repeat: bool, page: i64) -> bool {
        if side == Side::Remote && !self.connected() {
            return false;
        }
        // Behind a dialog the list takes no keys, whatever has the focus (a popup closing hands
        // it back to the item focused before the popup opened).
        if self.ui.upgrade().is_some_and(|u| u.get_dialog_open()) {
            return false;
        }
        self.st.borrow_mut().focused = idx(side);
        // Held keys must not queue the same transfer thirty times a second.
        if repeat && [Key::Return, Key::F5, Key::F7, Key::F2, Key::Delete].iter().any(|k| key_is(text, *k)) {
            return true;
        }
        let selected = self.pane(side).borrow().selected_entries();
        if key_is(text, Key::DownArrow) {
            let c = self.pane(side).borrow_mut().move_cursor(1, shift);
            self.select_change(side, c);
        } else if key_is(text, Key::UpArrow) {
            let c = self.pane(side).borrow_mut().move_cursor(-1, shift);
            self.select_change(side, c);
        } else if key_is(text, Key::PageDown) {
            let c = self.pane(side).borrow_mut().move_cursor(page.max(1), shift);
            self.select_change(side, c);
        } else if key_is(text, Key::PageUp) {
            let c = self.pane(side).borrow_mut().move_cursor(-page.max(1), shift);
            self.select_change(side, c);
        } else if key_is(text, Key::Home) {
            let c = self.pane(side).borrow_mut().move_cursor(-1_000_000_000, shift);
            self.select_change(side, c);
        } else if key_is(text, Key::End) {
            let c = self.pane(side).borrow_mut().move_cursor(1_000_000_000, shift);
            self.select_change(side, c);
        } else if key_is(text, Key::Return) {
            if selected.len() == 1 {
                self.open(side, selected[0].clone());
            } else if selected.len() > 1 {
                self.transfer_selected(side);
            }
        } else if key_is(text, Key::Backspace) {
            self.up(side);
        } else if key_is(text, Key::Delete) {
            self.go(move |a| a.remove(side));
        } else if key_is(text, Key::F2) {
            if selected.len() == 1 {
                self.go(move |a| a.rename(side));
            }
        } else if key_is(text, Key::F5) {
            self.transfer_selected(side);
        } else if key_is(text, Key::F7) {
            self.go(move |a| a.mkdir(side));
        } else if key_is(text, Key::Escape) {
            // One thing at a time: drag, then filter, then selection.
            if self.st.borrow().drag.is_some() {
                self.cancel_drag();
            } else if !self.pane(side).borrow().filter().is_empty() || self.st.borrow().show_filter[idx(side)] {
                self.close_filter(side);
            } else {
                self.blank_pressed(side);
            }
        } else if ctrl && text.eq_ignore_ascii_case("a") {
            let c = self.pane(side).borrow_mut().select_all();
            self.apply(side, c);
            self.push_pane(side);
        } else if ctrl && text.eq_ignore_ascii_case("f") {
            self.open_filter(side);
        } else if ctrl && text.eq_ignore_ascii_case("r") {
            self.go(|a| async move { a.refresh(side).await });
        } else if !ctrl && !alt && text.chars().count() == 1 && !text.chars().next().is_some_and(|c| c.is_control() || ('\u{F700}'..='\u{F8FF}').contains(&c)) {
            let c = self.pane(side).borrow_mut().jump_to(text.chars().next().unwrap());
            self.select_change(side, c);
        } else {
            return false;
        }
        true
    }

    fn transfer_selected(self: &Rc<Self>, side: Side) {
        let entries = self.pane(side).borrow().selected_entries();
        if entries.is_empty() {
            return;
        }
        self.transfer_entries(side, entries, None);
    }

    // ---------- context menu ----------

    pub fn row_context(self: &Rc<Self>, side: Side, row: usize, x: f32, y: f32) {
        self.drop_stale_drag();
        self.st.borrow_mut().focused = idx(side);
        let selected = self.pane(side).borrow().view_entry(row).map(|e| self.pane(side).borrow().is_selected(&e.path)).unwrap_or(false);
        if !selected {
            let c = self.pane(side).borrow_mut().select(row, false, false);
            self.apply(side, c);
            self.push_pane(side);
        }
        self.show_menu(side, x, y);
    }

    pub fn blank_context(self: &Rc<Self>, side: Side, x: f32, y: f32) {
        if side == Side::Remote && !self.connected() {
            self.drop_stale_drag();
            return; // no menu over "Not connected": nothing in it could act
        }
        self.blank_pressed(side);
        self.show_menu(side, x, y);
    }

    fn show_menu(self: &Rc<Self>, side: Side, x: f32, y: f32) {
        let Some(ui) = self.ui.upgrade() else { return };
        let icons = ui.global::<Icons>();
        let remote = side == Side::Remote;
        let connected = self.connected();
        let (has, single) = {
            let p = self.pane(side).borrow();
            let sel = p.selected_entries();
            (!sel.is_empty(), if sel.len() == 1 { sel.into_iter().next() } else { None })
        };
        let mut rows: Vec<(MenuEntry, MenuAction)> = Vec::new();
        let item = |label: &str, icon: SharedString, shortcut: &str, danger: bool| MenuEntry {
            label: label.into(),
            icon,
            shortcut: shortcut.into(),
            danger,
            separator: false,
            disabled: false,
        };
        if has {
            if connected {
                rows.push((
                    item(if remote { "Download" } else { "Upload" }, if remote { icons.get_download() } else { icons.get_upload() }, "F5", false),
                    MenuAction::Transfer,
                ));
            }
            if let Some(e) = &single {
                let (label, icon) = if e.is_dir {
                    ("Open", icons.get_folder_open())
                } else if remote {
                    ("Edit", icons.get_edit())
                } else {
                    ("Open with default app", icons.get_external())
                };
                rows.push((item(label, icon, "Enter", false), MenuAction::Open));
                if !remote && !e.is_dir {
                    rows.push((item("Show in Explorer", icons.get_folder_open(), "", false), MenuAction::Reveal));
                }
                rows.push((item("Rename", icons.get_pencil(), "F2", false), MenuAction::Rename));
            }
            if remote {
                rows.push((item("Permissions…", icons.get_lock(), "", false), MenuAction::Perms));
            }
            rows.push((item("Delete", icons.get_trash(), "Del", true), MenuAction::Delete));
            rows.push((MenuEntry { separator: true, ..Default::default() }, MenuAction::None));
        }
        rows.push((item("New folder", icons.get_folder_plus(), "F7", false), MenuAction::Mkdir));
        rows.push((item("Refresh", icons.get_refresh(), "Ctrl+R", false), MenuAction::Refresh));

        let height = rows.iter().map(|(e, _)| if e.separator { 9.0 } else { 26.0 }).sum::<f32>() + 8.0;
        let size = ui.window().size().to_logical(ui.window().scale_factor());
        ui.set_menu_x(x.min(size.width - 226.0).max(0.0));
        ui.set_menu_y(y.min(size.height - height - 4.0).max(0.0));
        let (entries, actions): (Vec<MenuEntry>, Vec<MenuAction>) = rows.into_iter().unzip();
        {
            let mut st = self.st.borrow_mut();
            st.menu = actions;
            st.menu_side = idx(side);
        }
        ui.set_menu_entries(ModelRc::new(VecModel::from(entries)));
        ui.invoke_show_menu();
    }

    pub fn menu_activated(self: &Rc<Self>, i: usize) {
        let (action, side) = {
            let st = self.st.borrow();
            (st.menu.get(i).copied().unwrap_or(MenuAction::None), side_of(st.menu_side as i32))
        };
        let single = {
            let sel = self.pane(side).borrow().selected_entries();
            if sel.len() == 1 { sel.into_iter().next() } else { None }
        };
        match action {
            MenuAction::Transfer => self.transfer_selected(side),
            MenuAction::Open => {
                if let Some(e) = single {
                    self.open(side, e);
                }
            }
            MenuAction::Reveal => {
                if let Some(e) = single {
                    let b = self.backend.clone();
                    self.go(|a| async move {
                        if let Err(err) = b.local_reveal(e.path).await {
                            a.error(err);
                        }
                    });
                }
            }
            MenuAction::Rename => self.go(move |a| a.rename(side)),
            MenuAction::Perms => self.open_perms(),
            MenuAction::Delete => self.go(move |a| a.remove(side)),
            MenuAction::Mkdir => self.go(move |a| a.mkdir(side)),
            MenuAction::Refresh => self.go(|a| async move { a.refresh(side).await }),
            MenuAction::None => {}
        }
    }

    // ---------- drags ----------

    /// Pointer drags between the panes or onto a folder row. `over`: 0 local, 1 remote, -1
    /// outside; `row`: the view row under the pointer there, or -1.
    pub fn drag(self: &Rc<Self>, from: usize, over: i32, row: i32, end: bool) {
        if self.st.borrow().drag_dead {
            if end {
                self.st.borrow_mut().drag_dead = false; // the button is up: the next press may drag
            }
            return;
        }
        if self.ui.upgrade().is_some_and(|u| u.get_dialog_open()) {
            if self.st.borrow().drag.is_some() {
                self.cancel_drag();
            }
            return;
        }
        if self.st.borrow().drag.is_none() {
            if end {
                return;
            }
            let side = side_of(from as i32);
            let entries = self.pane(side).borrow().selected_entries();
            if entries.is_empty() {
                return;
            }
            let mut st = self.st.borrow_mut();
            st.pending_collapse = None; // a drag started: the press was not a click
            st.drag = Some(Drag { from, entries });
        }
        let target_side = if over == 0 { Some(Side::Local) } else if over == 1 { Some(Side::Remote) } else { None };
        // The folder under the pointer, but never one of the rows being dragged onto itself.
        let folder = target_side.and_then(|s| {
            let p = self.pane(s).borrow();
            let e = p.view_entry(row.max(0) as usize).filter(|_| row >= 0)?.clone();
            let st = self.st.borrow();
            let own = st.drag.as_ref().is_some_and(|d| d.from == idx(s) && d.entries.iter().any(|x| x.path == e.path));
            (e.is_dir && !own).then_some(e)
        });
        let (from_side, label, one_file) = {
            let st = self.st.borrow();
            let d = st.drag.as_ref().unwrap();
            let name = if d.entries.len() == 1 { d.entries[0].name.clone() } else { format!("{} items", d.entries.len()) };
            (d.from, name, d.entries.len() == 1 && !d.entries[0].is_dir)
        };
        let cross = over >= 0 && over as usize != from_side;
        if end {
            let drag = self.st.borrow_mut().drag.take();
            self.st.borrow_mut().drop = None;
            if let Some(ui) = self.ui.upgrade() {
                ui.set_dragging(false);
            }
            self.push_pane(Side::Local);
            self.push_pane(Side::Remote);
            let Some(drag) = drag else { return };
            let from = side_of(drag.from as i32);
            if cross {
                self.transfer_entries(from, drag.entries, folder.map(|f| f.path));
            } else if over >= 0
                && let Some(f) = folder
            {
                self.go(move |a| a.move_into(from, drag.entries, f));
            }
            return;
        }
        let hint = if cross {
            format!("  → {}", folder.as_ref().map(|f| f.name.clone()).unwrap_or_else(|| if over == 1 { "server".into() } else { "local".into() }))
        } else if let Some(f) = &folder {
            format!("  move → {}", f.name)
        } else {
            String::new()
        };
        let drop = if cross || folder.is_some() { Some((over as usize, folder.map(|f| f.path))) } else { None };
        self.st.borrow_mut().drop = drop;
        if let Some(ui) = self.ui.upgrade() {
            ui.set_dragging(true);
            ui.set_drag_label(crate::format::shown(&format!("{label}{hint}")).as_ref().into());
            ui.set_drag_one_file(one_file);
        }
        self.push_pane(Side::Local);
        self.push_pane(Side::Remote);
    }

    /// Drop the drag in progress; the press it came from moves nothing more (`drag_dead`).
    pub fn cancel_drag(self: &Rc<Self>) {
        {
            let mut st = self.st.borrow_mut();
            st.drag_dead = st.drag.is_some();
            st.drag = None;
            st.drop = None;
        }
        if let Some(ui) = self.ui.upgrade() {
            ui.set_dragging(false);
        }
        self.push_pane(Side::Local);
        self.push_pane(Side::Remote);
    }

    /// A press proves the button went up, so a drag still recorded lost its release (its row
    /// was rebuilt under the pointer, or the OS took the capture) and must not be continued by
    /// this gesture. Unlike `cancel_drag` this does
    /// not swallow the gesture that is starting.
    fn drop_stale_drag(&self) {
        let stale = {
            let mut st = self.st.borrow_mut();
            st.drag_dead = false;
            let stale = st.drag.take().is_some();
            if stale {
                st.drop = None;
            }
            stale
        };
        if stale {
            if let Some(ui) = self.ui.upgrade() {
                ui.set_dragging(false);
            }
            self.push_pane(Side::Local);
            self.push_pane(Side::Remote);
        }
    }

    /// Files from Explorer hover over the window at this side/row (`None` once they leave).
    pub fn os_hover(self: &Rc<Self>, at: Option<(i32, i32)>) {
        let drop = at.and_then(|(side, row)| {
            // Through dialogs the remote pane is not reachable, and only it takes OS drops.
            if side != 1 || !self.connected() || self.ui.upgrade().is_some_and(|u| u.get_dialog_open()) {
                return None;
            }
            let p = self.pane(Side::Remote).borrow();
            let folder = p.view_entry(row.max(0) as usize).filter(|e| row >= 0 && e.is_dir).map(|e| e.path.clone());
            Some((1usize, folder))
        });
        if self.st.borrow().drop != drop {
            self.st.borrow_mut().drop = drop;
            self.push_pane(Side::Remote);
        }
    }

    /// Files dropped from Explorer at this side/row: an upload into the remote folder (or the
    /// folder row) under the pointer.
    pub fn os_drop(self: &Rc<Self>, paths: Vec<std::path::PathBuf>, side: i32, row: i32) {
        self.os_hover(Some((side, row)));
        let target = self.st.borrow_mut().drop.take();
        self.push_pane(Side::Remote);
        if let Some((_, folder)) = target {
            // A path that is not valid Unicode has no lossless String: a lossy one would upload
            // another file (or none) under that name (VibeRename RR-7).
            let (good, bad): (Vec<_>, Vec<_>) = paths.iter().partition(|p| p.to_str().is_some());
            if !bad.is_empty() {
                let names: Vec<String> = bad.iter().map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned()).collect();
                self.error(summarise(&names, "Not uploaded: the name is not valid Unicode"));
            }
            let paths = good.iter().filter_map(|p| p.to_str().map(str::to_string)).collect();
            self.upload_paths(paths, folder);
        }
    }

    // ---------- panels and toggles ----------

    fn toggle_log(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let open = !ui.get_log_open();
        ui.set_log_open(open);
        self.remember(|p| p.log = open);
    }

    /// The Copy buttons (text the window cannot let the user select). True once the clipboard
    /// has it, so the button may say "Copied"; a failure says why in a toast.
    pub fn copy_text(self: &Rc<Self>, text: &str) -> bool {
        match self.backend.copy_text(text.to_string()) {
            Ok(()) => true,
            Err(e) => {
                self.error(e);
                false
            }
        }
    }

    /// The log's Copy all: the lines on screen (the filter applies), "time line" each.
    fn copy_log(self: &Rc<Self>) -> bool {
        let lines: Vec<String> = self.log_model.iter().map(|r| format!("{} {}", r.time, r.line)).collect();
        !lines.is_empty() && self.copy_text(&lines.join("\n"))
    }

    fn log_filter(&self, f: &str) {
        self.st.borrow_mut().log_filter = f.to_string();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_log_filter(f.into());
        }
        self.rebuild_log_view();
    }

    // ---------- window wiring ----------

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        let a = self.clone();
        ui.on_pane_navigate(move |s, p| {
            let p = p.trim().to_string();
            // The field shows the path as `shown` makes it: unchanged, it is the folder on screen.
            let here = a.pane(side_of(s)).borrow().path.clone();
            if p.is_empty() || p == here || p == shown(&here) {
                return;
            }
            a.go(|a| async move {
                a.navigate(side_of(s), p, false, None).await;
            });
        });
        let a = self.clone();
        ui.on_pane_up(move |s| a.up(side_of(s)));
        let a = self.clone();
        ui.on_pane_refresh(move |s| a.go(|a| async move { a.refresh(side_of(s)).await }));
        let a = self.clone();
        ui.on_pane_mkdir(move |s| a.go(move |a| a.mkdir(side_of(s))));
        let a = self.clone();
        ui.on_pane_open_filter(move |s| a.open_filter(side_of(s)));
        let a = self.clone();
        ui.on_pane_filter(move |s, t| a.set_filter(side_of(s), &t));
        let a = self.clone();
        ui.on_pane_filter_closed(move |s| a.close_filter(side_of(s)));
        let a = self.clone();
        ui.on_pane_transfer(move |s| a.transfer_selected(side_of(s)));
        let a = self.clone();
        ui.on_pane_sort(move |s, k| a.sort(side_of(s), k));
        let a = self.clone();
        ui.on_pane_root(move |_, i| a.pick_root(i.max(0) as usize));
        let a = self.clone();
        ui.on_row_pressed(move |s, r, c, sh| a.row_pressed(side_of(s), r.max(0) as usize, c, sh));
        let a = self.clone();
        ui.on_row_clicked(move |s, r| a.row_clicked(side_of(s), r.max(0) as usize));
        let a = self.clone();
        ui.on_row_opened(move |s, r| {
            let e = a.pane(side_of(s)).borrow().view_entry(r.max(0) as usize).cloned();
            if let Some(e) = e {
                a.open(side_of(s), e);
            }
        });
        let a = self.clone();
        ui.on_row_context(move |s, r, x, y| a.row_context(side_of(s), r.max(0) as usize, x, y));
        let a = self.clone();
        ui.on_blank_pressed(move |s| a.blank_pressed(side_of(s)));
        let a = self.clone();
        ui.on_blank_context(move |s, x, y| a.blank_context(side_of(s), x, y));
        let a = self.clone();
        ui.on_list_key(move |s, t, c, sh, alt, rep, page| a.list_key(side_of(s), &t, c, sh, alt, rep, page as i64));
        let a = self.clone();
        ui.on_drag(move |from, over, row, end| a.drag(from.max(0) as usize, over, row, end));
        let a = self.clone();
        ui.on_site_picked(move |i| a.site_picked(i));
        let a = self.clone();
        ui.on_connect_clicked(move || a.connect_clicked());
        let a = self.clone();
        ui.on_open_sites(move || a.open_site_manager());
        let a = self.clone();
        ui.on_theme_toggled(move || {
            let Some(ui) = a.ui.upgrade() else { return };
            let t = ui.global::<Theme>();
            let dark = !t.get_dark();
            t.set_dark(dark);
            a.remember(|p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
        });
        let a = self.clone();
        ui.on_menu_activated(move |i| a.menu_activated(i.max(0) as usize));
        let a = self.clone();
        ui.on_toast_dismissed(move |id| a.dismiss_toast(id));
        let a = self.clone();
        ui.on_toast_action(move |id| a.toast_action(id));
        let a = self.clone();
        ui.on_copy_text(move |t| a.copy_text(&t));
        let a = self.clone();
        ui.on_log_copy_all(move || a.copy_log());

        // Dialogs.
        let a = self.clone();
        ui.on_modal_accepted(move |v, save| a.modal_answer(Answer::Ok(v.to_string(), save)));
        let a = self.clone();
        ui.on_modal_cancelled(move || a.modal_answer(Answer::Cancel));
        let a = self.clone();
        ui.on_conflict_answer(move |action, all| {
            let action = match action {
                0 => Action::Overwrite,
                1 => Action::Resume,
                2 => Action::Skip,
                _ => Action::Cancel,
            };
            a.answer_conflict(action, all);
        });
        let a = self.clone();
        ui.on_perms_toggle(move |i| a.perms_toggle(i.clamp(0, 8) as usize));
        let a = self.clone();
        ui.on_perms_text_edited(move |t| a.perms_text(&t));
        let a = self.clone();
        ui.on_perms_apply(move || a.perms_apply());
        let a = self.clone();
        ui.on_perms_cancelled(move || a.perms_close());

        // Site manager.
        let a = self.clone();
        ui.on_sm_pick(move |i| a.go(move |a| a.sm_pick_asked(i.max(0) as usize)));
        let a = self.clone();
        ui.on_sm_new(move || a.go(|a| a.sm_new_asked()));
        let a = self.clone();
        ui.on_sm_edited(move || a.sm_edited());
        let a = self.clone();
        ui.on_sm_protocol_picked(move |i| a.sm_protocol(i));
        let a = self.clone();
        ui.on_sm_forget_password(move || a.sm_forget());
        let a = self.clone();
        ui.on_sm_browse_key(move || a.sm_browse_key());
        let a = self.clone();
        ui.on_sm_browse_local(move || a.sm_browse_local());
        let a = self.clone();
        ui.on_sm_save(move || a.go(|a| a.sm_save()));
        let a = self.clone();
        ui.on_sm_delete(move || a.go(|a| a.sm_delete()));
        let a = self.clone();
        ui.on_sm_connect(move || a.go(|a| a.sm_connect()));
        let a = self.clone();
        ui.on_sm_close(move || a.go(|a| a.sm_close_asked()));
        let a = self.clone();
        ui.on_dialogs_closed(move || a.refocus());

        // Top bar.
        let a = self.clone();
        ui.on_go_bookmark(move |i| a.go(move |a| a.go_bookmark(i.max(0) as usize)));
        let a = self.clone();
        ui.on_remove_bookmark(move |i| a.go(move |a| a.remove_bookmark(i.max(0) as usize)));
        let a = self.clone();
        ui.on_add_bookmark(move || a.go(|a| a.add_bookmark()));
        let a = self.clone();
        ui.on_stop_editing(move |i| a.stop_editing(i.max(0) as usize));
        let a = self.clone();
        ui.on_toggle_sync(move || a.toggle_sync());
        let a = self.clone();
        ui.on_toggle_log(move || a.toggle_log());
        let a = self.clone();
        ui.on_toggle_bar(move || {
            let Some(ui) = a.ui.upgrade() else { return };
            let thick = !ui.get_bar_thick();
            ui.set_bar_thick(thick);
            a.remember(|p| p.bar = Some(if thick { "thick" } else { "thin" }.into()));
        });
        let a = self.clone();
        ui.on_toggle_update_at_start(move || {
            let Some(ui) = a.ui.upgrade() else { return };
            let on = !ui.get_update_at_start();
            ui.set_update_at_start(on);
            a.remember(|p| p.update_at_start = on);
        });
        let a = self.clone();
        ui.on_check_updates(move || a.go(|a| a.check_update(true)));
        let w = ui.as_weak();
        ui.on_about(move || {
            if let Some(ui) = w.upgrade() {
                ui.set_about_open(true);
            }
        });
        let w = ui.as_weak();
        ui.on_about_closed(move || {
            if let Some(ui) = w.upgrade() {
                ui.set_about_open(false);
            }
        });
        let a = self.clone();
        ui.on_check_install(move || a.check_install());
        let a = self.clone();
        ui.on_open_site(move || {
            a.go(|a| async move {
                if let Err(e) = a.backend.open_url(crate::check::SITE.to_string()).await {
                    a.error(e);
                }
            });
        });
        let a = self.clone();
        ui.on_install_update(move || a.go(|a| a.install_update()));

        // Queue and log.
        let w = ui.as_weak();
        ui.on_queue_toggle(move || {
            if let Some(ui) = w.upgrade() {
                ui.set_queue_open(!ui.get_queue_open());
            }
        });
        let a = self.clone();
        ui.on_queue_cancel(move |id| a.cancel_by_id(&id));
        let a = self.clone();
        ui.on_queue_cancel_all(move || a.cancel_all());
        let a = self.clone();
        ui.on_queue_clear(move || a.clear_finished());
        let a = self.clone();
        ui.on_log_filter_edited(move |f| a.log_filter(&f));
        let w = ui.as_weak();
        ui.on_log_follow_toggled(move |v| {
            if let Some(ui) = w.upgrade() {
                ui.set_log_follow(v);
            }
        });
        let a = self.clone();
        ui.on_log_clear(move || {
            a.st.borrow_mut().logs.clear();
            a.log_model.set_vec(Vec::new());
        });

        // Closing the window asks first when work would be cut short.
        let a = self.clone();
        ui.window().on_close_requested(move || a.close_requested());
    }
}
