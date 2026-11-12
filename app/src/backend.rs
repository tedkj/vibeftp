//! What the controller asks of the engine. The app uses `CoreBackend` (vibeftp-core on tokio);
//! the controller tests use a scripted fake whose calls stay pending until the test answers them.
//! Futures resolve on the UI thread (they are awaited from `slint::spawn_local`), so they need
//! not be `Send`; the engine work itself runs on tokio's threads.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use vibeftp_core::error::{AppError, Result};
use vibeftp_core::identity::LocalId;
use vibeftp_core::ops;
use vibeftp_core::protocol::Looks;
use vibeftp_core::types::{Action, ConnectResult, EditChanged, Entry, Kept, PinnedBefore, Policy, Site, SiteList};
use vibeftp_core::Core;
use crate::prefs::{Prefs, Store};
use crate::updater::{Offer, Ready, Updater};

pub type Fut<T> = Pin<Box<dyn Future<Output = Result<T>>>>;

pub trait Backend {
    fn local_home(&self) -> Fut<String>;
    fn local_roots(&self) -> Fut<Vec<String>>;
    /// The entries, and how many items are hidden because their names are not valid Unicode.
    fn local_list(&self, path: String) -> Fut<(Vec<Entry>, usize)>;
    fn local_open(&self, path: String) -> Fut<bool>;
    /// The sites, and how many entries of sites.json this build cannot read (review FR2-1).
    fn sites_list(&self) -> Fut<SiteList>;
    fn site_touch(&self, id: String, last_remote: String, last_local: String) -> Fut<()>;
    fn connect(&self, site: Site, password: Option<String>) -> Fut<ConnectResult>;
    fn disconnect(&self, session: String) -> Fut<Vec<EditChanged>>;
    fn remote_list(&self, session: String, path: String) -> Fut<Vec<Entry>>;
    fn trust_host_key(&self, host: String, port: u16, fingerprint: String) -> Fut<()>;
    fn trust_certificate(&self, host: String, port: u16, fingerprint: String) -> Fut<()>;
    /// This server's pin (`cert`: its certificate's) in a kept copy of a damaged known_hosts.json,
    /// when it is not pinned now (review FR2-2).
    fn pinned_before(&self, host: String, port: u16, cert: bool) -> Fut<Option<PinnedBefore>>;
    /// Every kept copy of a damaged sites.json or known_hosts.json, with its notice (FR2-6).
    fn set_aside_copies(&self) -> Fut<Vec<Kept>>;

    // ---- sites ----
    fn site_save(&self, site: Site, password: Option<String>) -> Fut<Site>;
    fn site_delete(&self, id: String) -> Fut<()>;

    // ---- file operations ----
    fn remote_mkdir(&self, session: String, path: String) -> Fut<()>;
    /// `seen`: the row the user confirmed; another object at the path now is left alone (SOL-FTP-2).
    /// `looks`: one per action, shared by its rows (each folder is read once for all, R-SOL-2).
    fn remote_delete(&self, session: String, path: String, is_dir: bool, seen: Entry, looks: Looks) -> Fut<()>;
    /// `replace`: the row of the target the user agreed to replace (`None`: replace nothing).
    /// `looks` as for `remote_delete`.
    fn remote_rename(&self, session: String, from: String, to: String, replace: Option<Entry>, looks: Looks) -> Fut<()>;
    fn remote_chmod(&self, session: String, paths: Vec<String>, mode: u32) -> Fut<()>;
    fn local_mkdir(&self, path: String) -> Fut<()>;
    /// What a local path is now: taken when a delete or replace question is shown, checked
    /// again by the delete or rename (review SOL-FTP-2).
    fn local_identity(&self, path: String) -> Fut<LocalId>;
    fn local_delete(&self, path: String, is_dir: bool, seen: LocalId) -> Fut<()>;
    /// `replace`: the identity of the target the user agreed to replace (`None`: replace nothing).
    fn local_rename(&self, from: String, to: String, replace: Option<LocalId>) -> Fut<()>;
    fn local_same_file(&self, a: String, b: String) -> Fut<bool>;
    fn local_reveal(&self, path: String) -> Fut<()>;

    // ---- transfers and edit copies ----
    #[allow(clippy::too_many_arguments)]
    fn transfer(&self, session: String, id: String, download: bool, src: String, dst: String, is_dir: bool, policy: Policy) -> Fut<()>;
    /// Synchronous on purpose: a cancel lands before anything else runs.
    fn cancel_transfer(&self, id: String);
    fn resolve_conflict(&self, id: String, action: Action, all: bool);
    fn edit_open(&self, session: String, path: String, id: String, discard: bool) -> Fut<String>;
    fn edit_stop(&self, session: String, local: String) -> bool;
    /// Whether an edit copy is still on disk (the engine deletes one once the server has it).
    fn edit_copy_exists(&self, local: String) -> bool;
    /// The names of the edit copies holding edits the server never got (they stay on this
    /// computer when the session ends or the app quits). Read only.
    fn unsent_edits(&self) -> Vec<String>;
    /// The folder edit copies live under, as the user would type it. Read only.
    fn edit_folder(&self) -> String;

    // ---- the window's own ----
    /// What the window remembered last time (read once at boot).
    fn prefs(&self) -> Prefs;
    /// prefs found the file garbled (it is kept aside by the first save).
    fn prefs_broken(&self) -> bool;
    /// Remember these (`fields`: the ones that changed); written off the UI thread.
    fn save_prefs(&self, prefs: Prefs, fields: u8);
    fn open_url(&self, url: String) -> Fut<()>;
    /// Put text on the clipboard (the Copy buttons). Synchronous: it is quick, and the button
    /// says "Copied" only once it worked.
    fn copy_text(&self, text: String) -> Result<()>;
    /// A newer version on offer (SLINT-PORT-PLAN 4c), if any.
    fn update_check(&self) -> Fut<Option<Offer>>;
    /// Download and verify it; nothing runs yet.
    fn update_download(&self, offer: Offer) -> Fut<Ready>;
    /// Start a verified installer (silent, restarting VibeFTP). The caller quits once it has.
    fn update_start(&self, ready: Ready) -> Result<()>;
}

pub struct CoreBackend {
    core: Arc<Core>,
    rt: tokio::runtime::Handle,
    prefs: Option<Store>,
    updater: Option<Arc<Updater>>,
}

impl CoreBackend {
    pub fn new(core: Arc<Core>, rt: tokio::runtime::Handle) -> Self {
        CoreBackend { core, rt, prefs: None, updater: None }
    }

    /// Updates come through this updater (without one, there are none).
    pub fn with_updater(mut self, updater: Updater) -> Self {
        self.updater = Some(Arc::new(updater));
        self
    }

    fn updates<T: Send + 'static>(&self, f: impl FnOnce(Arc<Updater>) -> Pin<Box<dyn Future<Output = std::result::Result<T, String>> + Send>> + Send + 'static) -> Fut<T> {
        let Some(u) = self.updater.clone() else {
            return Box::pin(async { Err(AppError::Msg("Updates are not available in this build".into())) });
        };
        let task = self.rt.spawn(f(u));
        Box::pin(async move { task.await.map_err(|e| AppError::Msg(e.to_string()))?.map_err(AppError::Msg) })
    }

    /// Remember the window's preferences in this store (without one, nothing is remembered).
    pub fn with_prefs(mut self, store: Store) -> Self {
        self.prefs = Some(store);
        self
    }

    fn run<T: Send + 'static>(&self, f: impl FnOnce(Arc<Core>) -> Pin<Box<dyn Future<Output = Result<T>> + Send>> + Send + 'static) -> Fut<T> {
        let task = self.rt.spawn(f(self.core.clone()));
        Box::pin(async move { task.await.map_err(|e| AppError::Msg(e.to_string()))? })
    }

    /// Disk or shell work that blocks: on tokio's blocking pool, never the UI thread.
    fn blocking<T: Send + 'static>(&self, f: impl FnOnce(&Core) -> Result<T> + Send + 'static) -> Fut<T> {
        let core = self.core.clone();
        let task = self.rt.spawn_blocking(move || f(&core));
        Box::pin(async move { task.await.map_err(|e| AppError::Msg(e.to_string()))? })
    }
}

impl Backend for CoreBackend {
    fn local_home(&self) -> Fut<String> {
        self.blocking(ops::local_home)
    }
    fn local_roots(&self) -> Fut<Vec<String>> {
        self.blocking(|_| Ok(ops::local_roots()))
    }
    fn local_list(&self, path: String) -> Fut<(Vec<Entry>, usize)> {
        self.run(move |_| Box::pin(ops::local_list_counted(path)))
    }
    fn local_open(&self, path: String) -> Fut<bool> {
        self.blocking(move |c| ops::local_open(c, path))
    }
    fn sites_list(&self) -> Fut<SiteList> {
        self.run(|c| Box::pin(async move { ops::sites_read(&c).await }))
    }
    fn site_touch(&self, id: String, last_remote: String, last_local: String) -> Fut<()> {
        self.run(move |c| Box::pin(async move { ops::site_touch(&c, id, last_remote, last_local).await }))
    }
    fn connect(&self, site: Site, password: Option<String>) -> Fut<ConnectResult> {
        self.run(move |c| Box::pin(async move { ops::connect(&c, site, password).await }))
    }
    fn disconnect(&self, session: String) -> Fut<Vec<EditChanged>> {
        self.run(move |c| Box::pin(async move { ops::disconnect(&c, session).await }))
    }
    fn remote_list(&self, session: String, path: String) -> Fut<Vec<Entry>> {
        self.run(move |c| Box::pin(async move { ops::remote_list(&c, session, path).await }))
    }
    fn trust_host_key(&self, host: String, port: u16, fingerprint: String) -> Fut<()> {
        self.blocking(move |c| ops::trust_host_key(c, host, port, fingerprint))
    }
    fn trust_certificate(&self, host: String, port: u16, fingerprint: String) -> Fut<()> {
        self.blocking(move |c| ops::trust_certificate(c, host, port, fingerprint))
    }
    fn pinned_before(&self, host: String, port: u16, cert: bool) -> Fut<Option<PinnedBefore>> {
        self.blocking(move |c| ops::pinned_before(c, host, port, cert))
    }
    fn set_aside_copies(&self) -> Fut<Vec<Kept>> {
        self.blocking(ops::set_aside_copies)
    }
    fn site_save(&self, site: Site, password: Option<String>) -> Fut<Site> {
        self.run(move |c| Box::pin(async move { ops::site_save(&c, site, password).await }))
    }
    fn site_delete(&self, id: String) -> Fut<()> {
        self.run(move |c| Box::pin(async move { ops::site_delete(&c, id).await }))
    }
    fn remote_mkdir(&self, session: String, path: String) -> Fut<()> {
        self.run(move |c| Box::pin(async move { ops::remote_mkdir(&c, session, path).await }))
    }
    fn remote_delete(&self, session: String, path: String, is_dir: bool, seen: Entry, looks: Looks) -> Fut<()> {
        self.run(move |c| Box::pin(async move { ops::remote_delete(&c, session, path, is_dir, seen, looks).await }))
    }
    fn remote_rename(&self, session: String, from: String, to: String, replace: Option<Entry>, looks: Looks) -> Fut<()> {
        self.run(move |c| Box::pin(async move { ops::remote_rename(&c, session, from, to, replace, looks).await }))
    }
    fn remote_chmod(&self, session: String, paths: Vec<String>, mode: u32) -> Fut<()> {
        self.run(move |c| Box::pin(async move { ops::remote_chmod(&c, session, paths, mode).await }))
    }
    fn local_mkdir(&self, path: String) -> Fut<()> {
        self.run(move |_| Box::pin(ops::local_mkdir(path)))
    }
    fn local_identity(&self, path: String) -> Fut<LocalId> {
        self.run(move |_| Box::pin(ops::local_identity(path)))
    }
    fn local_delete(&self, path: String, is_dir: bool, seen: LocalId) -> Fut<()> {
        self.run(move |_| Box::pin(ops::local_delete(path, is_dir, seen)))
    }
    fn local_rename(&self, from: String, to: String, replace: Option<LocalId>) -> Fut<()> {
        self.run(move |_| Box::pin(ops::local_rename(from, to, replace)))
    }
    fn local_same_file(&self, a: String, b: String) -> Fut<bool> {
        self.run(move |_| Box::pin(async move { Ok(ops::local_same_file(a, b).await) }))
    }
    fn local_reveal(&self, path: String) -> Fut<()> {
        self.blocking(move |c| ops::local_reveal(c, path))
    }
    fn transfer(&self, session: String, id: String, download: bool, src: String, dst: String, is_dir: bool, policy: Policy) -> Fut<()> {
        let direction = if download { "download" } else { "upload" }.to_string();
        self.run(move |c| Box::pin(async move { ops::transfer(&c, session, id, direction, src, dst, is_dir, policy).await }))
    }
    fn cancel_transfer(&self, id: String) {
        ops::cancel_transfer(&self.core, id)
    }
    fn resolve_conflict(&self, id: String, action: Action, all: bool) {
        ops::resolve_conflict(&self.core, id, action, all)
    }
    fn edit_open(&self, session: String, path: String, id: String, discard: bool) -> Fut<String> {
        self.run(move |c| Box::pin(async move { ops::edit_open(&c, session, path, id, discard).await }))
    }
    fn edit_stop(&self, session: String, local: String) -> bool {
        ops::edit_stop(&self.core, session, local)
    }
    fn edit_copy_exists(&self, local: String) -> bool {
        copy_on_disk(&local)
    }
    fn unsent_edits(&self) -> Vec<String> {
        ops::unsent_copies(&self.core)
    }
    fn edit_folder(&self) -> String {
        ops::edit_root(&self.core).display().to_string()
    }
    fn prefs(&self) -> Prefs {
        self.prefs.as_ref().map(|p| p.load()).unwrap_or_default()
    }
    fn prefs_broken(&self) -> bool {
        self.prefs.as_ref().is_some_and(|p| p.broken())
    }
    fn save_prefs(&self, prefs: Prefs, fields: u8) {
        if let Some(p) = &self.prefs {
            p.save(prefs, fields, &self.rt);
        }
    }
    fn open_url(&self, url: String) -> Fut<()> {
        self.blocking(move |_| crate::host::open_url(&url))
    }
    fn copy_text(&self, text: String) -> Result<()> {
        crate::host::copy_text(&text)
    }
    fn update_check(&self) -> Fut<Option<Offer>> {
        self.updates(|u| Box::pin(async move { u.check().await }))
    }
    fn update_download(&self, offer: Offer) -> Fut<Ready> {
        self.updates(move |u| Box::pin(async move { u.download(&offer).await.map(|v| Ready(Some(v))) }))
    }
    fn update_start(&self, ready: Ready) -> Result<()> {
        ready.start().map_err(AppError::Msg)
    }
}

/// Only a confirmed absence says the engine dropped the copy. Any other stat error (a scanner or
/// the editor holding the file for a moment) counts as present: the save is re-sent, and the
/// worst case is one upload too many rather than a newer save left unsent.
fn copy_on_disk(local: &str) -> bool {
    !matches!(std::fs::symlink_metadata(local), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}
