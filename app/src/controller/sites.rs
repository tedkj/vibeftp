//! Sites, the site manager and bookmarks.

use super::App;
use crate::format::shown;
use crate::pane::Side;
use crate::paths::base_name;
use crate::{BookmarkRow, SiteRow, ToastKind};
use slint::winit_030::WinitWindowAccessor;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::rc::Rc;
use vibeftp_core::error::AppError;
use vibeftp_core::types::{Bookmark, Kept, Protocol, Site};

const PARALLEL: [u8; 7] = [0, 1, 2, 3, 4, 6, 8];

pub fn blank_site() -> Site {
    Site {
        id: String::new(),
        name: String::new(),
        protocol: Protocol::Sftp,
        host: String::new(),
        port: 22,
        username: String::new(),
        key_path: String::new(),
        remote_path: String::new(),
        local_path: String::new(),
        insecure_tls: false,
        has_password: false,
        secret_for: String::new(),
        parallel: 0,
        bookmarks: Vec::new(),
        last_remote: String::new(),
        last_local: String::new(),
        ftp_mode: "passive".into(),
        extra: Default::default(),
    }
}

/// The kept copy's file name, when `path` is one (`sites.json.broken`, `known_hosts.json.broken-2`).
pub(crate) fn kept_name(path: &str) -> Option<String> {
    let name = std::path::Path::new(path).file_name()?.to_string_lossy().into_owned();
    name.contains(".json.broken").then_some(name)
}

/// What the site manager says about the entries of sites.json this build cannot read.
pub fn unreadable_note(n: usize) -> String {
    match n {
        0 => String::new(),
        1 => "1 site this version can't read is kept as it is".into(),
        n => format!("{n} sites this version can't read are kept as they are"),
    }
}

fn protocol_index(p: &Protocol) -> i32 {
    match p {
        Protocol::Sftp => 0,
        Protocol::Ftps => 1,
        Protocol::Ftp => 2,
    }
}

fn protocol_of(i: i32) -> Protocol {
    match i {
        1 => Protocol::Ftps,
        2 => Protocol::Ftp,
        _ => Protocol::Sftp,
    }
}

/// The site manager's form, as the controller keeps it.
#[derive(Default)]
pub struct Form {
    /// The saved site this form edits (`None` for a new one).
    pub base: Option<Site>,
    pub clear_password: bool,
    pub busy: bool,
}

impl App {
    // ---------- sites ----------

    pub async fn reload_sites(self: &Rc<Self>) {
        match self.backend.sites_list().await {
            Ok(l) => {
                let mut st = self.st.borrow_mut();
                st.sites = l.sites;
                st.sites_unreadable = l.unreadable;
                let cur = st.site.as_ref().and_then(|c| st.sites.iter().find(|x| x.id == c.id).cloned());
                if let Some(c) = cur {
                    st.site = Some(c);
                }
            }
            // A file VibeFTP cannot read at all: a notice that stays, with the file to show (FR2-1).
            Err(AppError::Unreadable { text, path }) => {
                self.notice(text, Some(path));
            }
            Err(e) => self.error(format!("Could not read saved sites: {e}")),
        }
        self.push_sites();
        // The bar's "Connect dials …" line names a saved site: renamed or deleted, it follows.
        self.push_link();
        self.push_bookmarks();
        // An open site manager lists the same sites: its rows must stay the ones `sm_pick` indexes.
        if self.ui.upgrade().is_some_and(|u| u.get_sm_open()) {
            self.push_sm_sites();
        }
        self.tell_kept().await;
    }

    /// Tell about the kept copies of damaged files this profile has not been told about yet
    /// (another window set them aside, or this one before a restart): the same notice, once
    /// per copy per profile, not once per window, nor never (review FR2-6).
    pub(crate) async fn tell_kept(self: &Rc<Self>) {
        let Ok(copies) = self.backend.set_aside_copies().await else { return };
        let mut told: Vec<String> = {
            // Another window may have told some since this one started: the file's list counts.
            let mut all = self.backend.prefs().told;
            all.extend(self.st.borrow().prefs.told.iter().cloned());
            // A copy that is gone is forgotten: a later one may take its name.
            all.retain(|n| copies.iter().any(|c| &c.name == n));
            all
        };
        let fresh: Vec<Kept> = copies.into_iter().filter(|c| !told.contains(&c.name)).collect();
        told.extend(fresh.iter().map(|c| c.name.clone()));
        told.sort();
        told.dedup();
        self.remember(|p| p.told = told);
        for c in fresh {
            self.notice(c.text, Some(c.path));
        }
    }

    /// This window told about the kept copy `name` (its own set-aside's notice).
    pub(crate) fn mark_told(&self, name: String) {
        self.remember(|p| {
            if !p.told.contains(&name) {
                p.told.push(name);
                p.told.sort();
            }
        });
    }

    pub async fn save_site(self: &Rc<Self>, site: Site, password: Option<String>) -> Result<Site, String> {
        let saved = self.backend.site_save(site, password).await.map_err(|e| e.to_string())?;
        self.reload_sites().await;
        Ok(saved)
    }

    async fn delete_site(self: &Rc<Self>, id: &str) -> Result<(), String> {
        self.backend.site_delete(id.to_string()).await.map_err(|e| e.to_string())?;
        {
            let mut st = self.st.borrow_mut();
            if let Some(s) = st.site.as_mut().filter(|s| s.id == id) {
                // Keep the live session, but nothing may save this site back to disk.
                s.id.clear();
                s.has_password = false;
            }
        }
        self.reload_sites().await;
        Ok(())
    }

    // ---------- bookmarks ----------

    pub(crate) fn push_bookmarks(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let rows: Vec<BookmarkRow> = self
            .st
            .borrow()
            .site
            .as_ref()
            .map(|s| s.bookmarks.iter().map(|b| BookmarkRow { name: shown(&b.name).as_ref().into(), remote: shown(&b.remote).as_ref().into() }).collect())
            .unwrap_or_default();
        ui.set_bookmarks(ModelRc::new(VecModel::from(rows)));
    }

    /// Save the current site with changed bookmarks. S41: the answer is applied only when the
    /// same site is still connected under the same session (a switch while the save was out
    /// must not make the old site current again).
    async fn save_bookmarks(self: &Rc<Self>, site: Site, what: &str) {
        let (session, id) = (self.st.borrow().session.clone(), site.id.clone());
        match self.save_site(site, None).await {
            Ok(saved) => {
                let same = {
                    let st = self.st.borrow();
                    st.session == session && st.site.as_ref().is_some_and(|s| s.id == id)
                };
                if same {
                    self.st.borrow_mut().site = Some(saved);
                    self.push_bookmarks();
                }
            }
            Err(e) => self.error(format!("Could not {what}: {e}")),
        }
    }

    pub async fn add_bookmark(self: Rc<Self>) {
        let site = self.st.borrow().site.clone();
        let Some(site) = site.filter(|s| !s.id.is_empty()) else { return };
        if !self.connected() {
            return;
        }
        let (remote, local) = (self.pane(Side::Remote).borrow().path.clone(), self.pane(Side::Local).borrow().path.clone());
        let suggest = { let b = base_name(&remote); if b.is_empty() { "root".to_string() } else { b } };
        let Some(name) = self.prompt("New bookmark", &suggest, "Name", "Add").await else { return };
        if site.bookmarks.iter().any(|x| x.name == name && x.remote == remote) {
            self.info("That bookmark already exists");
            return;
        }
        let mut site = self.st.borrow().site.clone().filter(|s| s.id == site.id).unwrap_or(site);
        site.bookmarks.push(Bookmark { name, remote, local, extra: Default::default() });
        self.save_bookmarks(site, "save the bookmark").await;
    }

    pub async fn remove_bookmark(self: Rc<Self>, i: usize) {
        let Some(mut site) = self.st.borrow().site.clone().filter(|s| !s.id.is_empty()) else { return };
        if i >= site.bookmarks.len() {
            return;
        }
        site.bookmarks.remove(i);
        self.save_bookmarks(site, "remove the bookmark").await;
    }

    pub async fn go_bookmark(self: Rc<Self>, i: usize) {
        let Some(b) = self.st.borrow().site.as_ref().and_then(|s| s.bookmarks.get(i).cloned()) else { return };
        // Both hops at once, each guarded by its own pane sequence and session: a slow local
        // listing must not let the remote hop land on whatever site is current by then.
        let connected = self.connected();
        let local = async {
            if b.local.is_empty() { None } else { self.navigate(Side::Local, b.local.clone(), true, None).await }
        };
        let remote = async {
            if b.remote.is_empty() || !connected { None } else { self.navigate(Side::Remote, b.remote.clone(), true, None).await }
        };
        let (l, r) = futures::future::join(local, remote).await;
        // Quiet hops say nothing on failure themselves; a superseded one (None) is fine.
        if l == Some(false) {
            self.info(format!("Could not open the bookmarked folder on this computer: {}", b.local));
        }
        if r == Some(false) {
            self.info(format!("Could not open the bookmarked folder on the server: {}", b.remote));
        }
    }

    // ---------- the site manager ----------

    pub fn open_site_manager(self: &Rc<Self>) {
        let s = {
            let st = self.st.borrow();
            st.site.as_ref().filter(|s| !s.id.is_empty()).and_then(|c| st.sites.iter().find(|x| x.id == c.id).cloned()).or_else(|| st.sites.first().cloned())
        };
        self.sm_load(s);
        if let Some(ui) = self.ui.upgrade() {
            ui.set_sm_open(true);
        }
    }

    pub fn sm_close(&self) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_sm_open(false);
            // A typed password has no business in the window once the form is gone.
            ui.set_sm_pass(Default::default());
        }
    }

    pub fn sm_load(&self, s: Option<Site>) {
        let Some(ui) = self.ui.upgrade() else { return };
        let site = s.clone().unwrap_or_else(blank_site);
        // A save or delete still out keeps the form busy across a pick: only its answer ends it.
        let busy = {
            let mut st = self.st.borrow_mut();
            let busy = st.form.busy;
            st.form = Form { base: s.clone(), clear_password: false, busy };
            busy
        };
        self.push_sm_sites();
        ui.set_sm_heading(if s.is_none() { "New site".into() } else { shown(&site.name).as_ref().into() });
        ui.set_sm_name(site.name.as_str().into());
        ui.set_sm_protocol(protocol_index(&site.protocol));
        ui.set_sm_host(site.host.as_str().into());
        ui.set_sm_port(site.port.to_string().into());
        ui.set_sm_user(site.username.as_str().into());
        ui.set_sm_pass(Default::default());
        ui.set_sm_has_password(site.has_password);
        ui.set_sm_clear_password(false);
        ui.set_sm_key(site.key_path.as_str().into());
        ui.set_sm_mode(if site.ftp_mode == "active" { 1 } else { 0 });
        ui.set_sm_parallel(PARALLEL.iter().position(|&p| p == site.parallel).unwrap_or(0) as i32);
        ui.set_sm_rpath(site.remote_path.as_str().into());
        ui.set_sm_lpath(site.local_path.as_str().into());
        ui.set_sm_busy(busy);
        self.sm_edited();
    }

    /// The manager's list of sites, and which row the form shows.
    fn push_sm_sites(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let st = self.st.borrow();
        let rows: Vec<SiteRow> = st
            .sites
            .iter()
            .map(|s| {
                let proto = match s.protocol {
                    Protocol::Sftp => "sftp",
                    Protocol::Ftps => "ftps",
                    Protocol::Ftp => "ftp",
                };
                SiteRow { name: shown(&s.name).as_ref().into(), detail: shown(&format!("{proto}://{}", s.host)).as_ref().into() }
            })
            .collect();
        let current = st.form.base.as_ref().and_then(|x| st.sites.iter().position(|y| y.id == x.id)).map(|i| i as i32).unwrap_or(-1);
        let note = unreadable_note(st.sites_unreadable);
        drop(st);
        ui.set_sm_sites(ModelRc::new(VecModel::from(rows)));
        ui.set_sm_current(current);
        ui.set_sm_note(note.into());
    }

    /// The form as a site: trimmed, a default name, a valid port. The fields the form does not
    /// show (bookmarks, has_password, the last folders) come from the site as it is now, not as
    /// it was when the form loaded: a bookmark or keychain save since then must not be undone.
    fn sm_prepared(&self) -> Site {
        let ui = self.ui.upgrade().expect("window");
        let mut s = {
            let st = self.st.borrow();
            let base = st.form.base.as_ref();
            base.and_then(|b| st.sites.iter().find(|x| x.id == b.id).cloned()).or_else(|| base.cloned()).unwrap_or_else(blank_site)
        };
        s.name = ui.get_sm_name().to_string();
        s.protocol = protocol_of(ui.get_sm_protocol());
        s.host = ui.get_sm_host().trim().to_string();
        s.username = ui.get_sm_user().trim().to_string();
        if s.name.trim().is_empty() {
            s.name = if s.username.is_empty() { s.host.clone() } else { format!("{}@{}", s.username, s.host) };
        }
        s.port = match ui.get_sm_port().trim().parse::<u32>() {
            Ok(p) if (1..=65535).contains(&p) => p as u16,
            _ => s.protocol.default_port(),
        };
        s.key_path = ui.get_sm_key().to_string();
        // Older sites store no mode (""): it means passive, and stays "" until really changed,
        // or every such site would show unsaved changes the moment it opens.
        let picked = if ui.get_sm_mode() == 1 { "active" } else { "passive" };
        let stored = if s.ftp_mode == "active" { "active" } else { "passive" };
        if picked != stored {
            s.ftp_mode = picked.into();
        }
        s.parallel = PARALLEL.get(ui.get_sm_parallel().max(0) as usize).copied().unwrap_or(0);
        s.remote_path = ui.get_sm_rpath().to_string();
        s.local_path = ui.get_sm_lpath().to_string();
        s
    }

    fn sm_password_arg(&self) -> Option<String> {
        let pw = self.ui.upgrade().map(|u| u.get_sm_pass().to_string()).unwrap_or_default();
        if self.st.borrow().form.clear_password {
            return Some(String::new());
        }
        if !pw.is_empty() {
            Some(pw)
        } else if self.sm_secret_switched() {
            Some(String::new())
        } else {
            None
        }
    }

    /// The form now needs another kind of secret than the one saved (an SFTP key's passphrase
    /// on a site switched to FTP or to a password login, or the reverse): the save forgets the
    /// saved one unless a new one is typed, and the form already shows it as not saved (SNA5).
    fn sm_secret_switched(&self) -> bool {
        let stored = {
            let st = self.st.borrow();
            let Some(base) = st.form.base.as_ref() else { return false };
            st.sites.iter().find(|x| x.id == base.id).unwrap_or(base).stored_secret().to_string()
        };
        stored != self.sm_prepared().wants_secret()
    }

    /// Recompute "dirty" and the port check after any edit.
    pub fn sm_edited(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        if !ui.get_sm_pass().is_empty() && self.st.borrow().form.clear_password {
            // Typing a password takes back a "Forget".
            self.st.borrow_mut().form.clear_password = false;
            ui.set_sm_clear_password(false);
        }
        let typed = ui.get_sm_port().trim().to_string();
        ui.set_sm_invalid_port(!typed.is_empty() && !matches!(typed.parse::<u32>(), Ok(p) if (1..=65535).contains(&p)));
        let now = {
            let mut s = self.sm_prepared();
            s.last_remote.clear();
            s.last_local.clear();
            serde_json::to_value(&s).ok()
        };
        let base = {
            let st = self.st.borrow();
            let mut b = st.form.base.as_ref().and_then(|x| st.sites.iter().find(|y| y.id == x.id).cloned()).unwrap_or_else(blank_site);
            b.last_remote.clear();
            b.last_local.clear();
            serde_json::to_value(&b).ok()
        };
        let dirty = now != base || !ui.get_sm_pass().is_empty() || self.st.borrow().form.clear_password;
        ui.set_sm_dirty(dirty);
        let saved = {
            let st = self.st.borrow();
            st.form.base.as_ref().is_some_and(|b| st.sites.iter().find(|y| y.id == b.id).unwrap_or(b).has_password)
        };
        ui.set_sm_has_password(saved && !self.sm_secret_switched());
    }

    pub fn sm_protocol(&self, i: i32) {
        let Some(ui) = self.ui.upgrade() else { return };
        let old = protocol_of(ui.get_sm_protocol());
        let new = protocol_of(i);
        let port = ui.get_sm_port().trim().parse::<u16>().ok();
        ui.set_sm_protocol(i);
        if port.is_none() || port == Some(old.default_port()) {
            ui.set_sm_port(new.default_port().to_string().into());
        }
        self.sm_edited();
    }

    pub fn sm_forget(&self) {
        self.st.borrow_mut().form.clear_password = true;
        if let Some(ui) = self.ui.upgrade() {
            ui.set_sm_clear_password(true);
            ui.set_sm_pass(Default::default());
        }
        self.sm_edited();
    }

    /// Whether the form may be left (Close, Escape, another site, New site): at once when it
    /// holds nothing unsaved, otherwise only when the user says to discard it. A half-typed site,
    /// its password included, is never dropped without asking (copy-ux M4). A save still out
    /// counts as saved: its edits land whatever the form shows next.
    async fn sm_may_leave(self: &Rc<Self>) -> bool {
        let dirty = self.ui.upgrade().is_some_and(|u| u.get_sm_open() && u.get_sm_dirty()) && !self.st.borrow().form.busy;
        !dirty || self.confirm("Unsaved changes", "Discard your changes to this site?", "Discard", true).await
    }

    pub async fn sm_close_asked(self: Rc<Self>) {
        if self.sm_may_leave().await {
            self.sm_close();
        }
    }

    /// Another site picked in the list. The site is taken before the question, so a list that
    /// reloads under it loads the one clicked (if it is still there), not whatever row `i` holds.
    pub async fn sm_pick_asked(self: Rc<Self>, i: usize) {
        let Some(id) = self.st.borrow().sites.get(i).map(|s| s.id.clone()) else { return };
        if !self.sm_may_leave().await || !self.ui.upgrade().is_some_and(|u| u.get_sm_open()) {
            return;
        }
        let s = self.st.borrow().sites.iter().find(|s| s.id == id).cloned();
        if s.is_some() {
            self.sm_load(s);
        }
    }

    pub async fn sm_new_asked(self: Rc<Self>) {
        if self.sm_may_leave().await && self.ui.upgrade().is_some_and(|u| u.get_sm_open()) {
            self.sm_new();
        }
    }

    async fn sm_save_inner(self: &Rc<Self>) -> Option<Site> {
        let ui = self.ui.upgrade()?;
        if self.st.borrow().form.busy {
            return None;
        }
        let s = self.sm_prepared();
        if s.host.is_empty() {
            self.error("Host is required");
            return None;
        }
        let typed = ui.get_sm_port().trim().to_string();
        if !typed.is_empty() && s.port.to_string() != typed {
            self.error(format!("\"{typed}\" is not a port (1-65535)"));
            return None;
        }
        let pw = self.sm_password_arg();
        let form_of = |a: &App| a.st.borrow().form.base.as_ref().map(|b| b.id.clone());
        let was = form_of(self);
        self.st.borrow_mut().form.busy = true;
        ui.set_sm_busy(true);
        let r = self.save_site(s, pw).await;
        self.st.borrow_mut().form.busy = false;
        ui.set_sm_busy(false);
        match r {
            Ok(saved) => {
                // A site picked while the save was out stays on screen, with whatever was typed
                // into it; the list (reloaded by the save) already shows the saved one.
                if form_of(self) == was {
                    self.sm_load(Some(saved.clone()));
                }
                Some(saved)
            }
            Err(e) => {
                self.error(e);
                None
            }
        }
    }

    pub async fn sm_save(self: Rc<Self>) {
        self.sm_save_inner().await;
    }

    pub async fn sm_connect(self: Rc<Self>) {
        // A typed password goes straight through, so no re-prompt on first connect.
        let typed = self.ui.upgrade().map(|u| u.get_sm_pass().to_string()).unwrap_or_default();
        let Some(saved) = self.sm_save_inner().await else { return };
        self.sm_close();
        self.connect(saved, if typed.is_empty() { None } else { Some(typed) }).await;
    }

    pub async fn sm_delete(self: Rc<Self>) {
        let Some(base) = self.st.borrow().form.base.clone() else { return };
        if self.st.borrow().form.busy {
            return;
        }
        if !self.confirm("Delete site", &format!("Delete \"{}\"?", base.name), "Delete", true).await {
            return;
        }
        self.st.borrow_mut().form.busy = true;
        let ui = self.ui.upgrade();
        if let Some(ui) = &ui {
            ui.set_sm_busy(true);
        }
        let r = self.delete_site(&base.id).await;
        self.st.borrow_mut().form.busy = false;
        if let Some(ui) = &ui {
            ui.set_sm_busy(false);
        }
        match r {
            Ok(()) => {
                let first = self.st.borrow().sites.first().cloned();
                self.sm_load(first);
            }
            Err(e) => self.error(e),
        }
    }

    pub fn sm_new(&self) {
        self.sm_load(None);
    }

    /// A native picker owned by the main window, so it stays in front of it rather than
    /// dropping behind it while the window waits for the answer.
    fn picker(&self, title: &str) -> rfd::FileDialog {
        let owned = self.ui.upgrade().and_then(|ui| ui.window().with_winit_window(|w| rfd::FileDialog::new().set_parent(w)));
        owned.unwrap_or_default().set_title(title)
    }

    pub fn sm_browse_key(self: &Rc<Self>) {
        if let Some(f) = self.picker("Choose private key").pick_file().and_then(|f| self.unicode_path(f)) {
            if let Some(ui) = self.ui.upgrade() {
                ui.set_sm_key(f.as_str().into());
            }
            self.sm_edited();
        }
    }

    pub fn sm_browse_local(self: &Rc<Self>) {
        if let Some(d) = self.picker("Choose local folder").pick_folder().and_then(|d| self.unicode_path(d)) {
            if let Some(ui) = self.ui.upgrade() {
                ui.set_sm_lpath(d.as_str().into());
            }
            self.sm_edited();
        }
    }

    /// A picked path as text, or a toast: a path that is not valid Unicode has no lossless
    /// String, and a lossy one would name another file or folder (VibeRename RR-7).
    fn unicode_path(self: &Rc<Self>, p: std::path::PathBuf) -> Option<String> {
        let s = p.to_str().map(str::to_string);
        if s.is_none() {
            self.error(format!("{} is not valid Unicode, so VibeFTP cannot use it", crate::format::shown(&p.to_string_lossy())));
        }
        s
    }

    /// "Save in keychain" from a password prompt. A failed save is reported and the connect
    /// goes on with what was typed.
    pub(crate) async fn save_secret(self: &Rc<Self>, mut site: Site, password: &str) -> Site {
        if site.id.is_empty() || password.is_empty() {
            return site;
        }
        match self.save_site(site.clone(), Some(password.to_string())).await {
            Ok(_) => site.has_password = true,
            Err(e) => {
                self.toast(format!("Could not save it in the keychain: {e}"), ToastKind::Error);
            }
        }
        site
    }
}
