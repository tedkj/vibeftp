use crate::error::{AppError, Result};
use crate::identity::LocalId;
use crate::protocol::{deleted_before, safe_name, verbatim, Ctx, Looks, Remote, Tally};
use crate::session::Session;
use crate::store::Store;
use crate::types::{
    millis, split_remote, Action, Conflict, ConnectResult, Decision, EditChanged, Entry, Policy,
    Kept, PinnedBefore, Progress, Protocol, Site, SiteList, Skipped,
};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::host::{Event, Host, Paths};
use tokio::sync::oneshot;

/// The engine's state. One per process; every operation in this module takes it.
pub struct Core {
    host: Arc<dyn Host>,
    paths: Paths,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// transfer id -> (session id, cancel flag)
    transfers: Mutex<HashMap<String, (String, Arc<AtomicBool>)>>,
    /// Parked conflict prompts; shared with the transfers' prompt closures.
    conflicts: Arc<Mutex<HashMap<String, oneshot::Sender<Decision>>>>,
    /// Watchers of edit copies, by `session|local`.
    edits: Mutex<HashMap<String, Watch>>,
    /// Edit copies on disk, by local path, with the signature of the bytes the server has
    /// (after the download or the last save that went up in full).
    copies: Mutex<HashMap<String, EditCopy>>,
    /// Edit copies being downloaded right now (one open per file at a time).
    opening: Mutex<std::collections::HashSet<String>>,
    /// Local sources of uploads in progress: an edit copy must not be re-downloaded over
    /// a save that is still on its way up.
    uploading: Mutex<std::collections::HashSet<String>>,
    /// `session|remote` destinations of uploads in progress: an edit download of one of them
    /// (or of a file inside one) would copy a half-written file.
    writing: Mutex<Vec<String>>,
    /// The session folders whose live marker this engine holds, with the open marker. One engine
    /// per process, living as long as it: held until the process ends (RVA5-1).
    live: Mutex<Vec<(PathBuf, std::fs::File)>>,
}

/// (length, modified ms) of a local file.
type Sig = (u64, u64);

fn sig_of(p: &Path) -> Option<Sig> {
    std::fs::metadata(p).ok().map(|m| (m.len(), m.modified().map(millis).unwrap_or(0)))
}

struct EditCopy {
    session: String,
    remote: String,
    sig: Option<Sig>,
    /// The server's file as last seen (`server_look`): read before the edit download, and again
    /// after each save that went up. A save finding another file there asks first (FEA2).
    server: Server,
}

/// The server's file as an edit copy last saw it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Server {
    /// (size, modified), or None: no file there (absent, or a folder).
    Seen(Option<(u64, u64)>),
    /// The look failed (the server would not say): nothing to compare a save with, and the next
    /// good reading takes its place (RVA6).
    Unknown,
}

/// The server's file at `path` as (size, modified), or None (absent or a folder). Every reading
/// of an edit copy's server file is taken this one way, so an unchanged file always reads the
/// same (whatever precision the server's dates have). A failed look is an error, never "absent".
async fn server_now(remote: &Remote, path: &str) -> Result<Option<(u64, u64)>> {
    Ok(remote.stat(path).await?.filter(|e| !e.is_dir).map(|e| (e.size, e.modified)))
}

/// `server_now` on the lease's link. A dead link (`lease` does not probe one that died less
/// than a minute ago) is dialled again and looked on once more, so a dropped link never reads
/// as a changed file; a look that still fails is `Unknown` (RVA6). The redial's own error is
/// the caller's.
async fn server_look(sess: &Arc<Session>, lease: &mut crate::session::Lease, path: &str) -> Result<Server> {
    match server_now(&lease.remote, path).await {
        Ok(now) => return Ok(Server::Seen(now)),
        Err(e) if !e.is_connection_error() => return Ok(Server::Unknown),
        Err(e) => log::warn!(target: "vibeftp", "Looking at {path} hit a dead link ({e}); looking again"),
    }
    redial(sess, lease).await?;
    Ok(server_now(&lease.remote, path).await.map_or(Server::Unknown, Server::Seen))
}

/// A new link in place of the lease's dead one. A server that will not take another login now
/// (its per-user cap may still count the dead link) is used over the browse link instead.
async fn redial(sess: &Arc<Session>, lease: &mut crate::session::Lease) -> Result<()> {
    match sess.redial(lease.idx, &lease.remote).await {
        Ok(r) => lease.remote = r,
        Err(e) if lease.idx != 0 && e.is_refusal() && !e.is_auth_failure() => {
            log::warn!(target: "vibeftp", "Reconnect refused ({e}); sharing the browse connection");
            *lease = sess.share().ok_or(e)?;
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// A running watcher of one edit copy.
struct Watch {
    handle: tokio::task::JoinHandle<()>,
    state: Arc<Mutex<WatchState>>,
    local: PathBuf,
}

struct WatchState {
    /// What the watcher last announced, or found when it started.
    last: Option<Sig>,
    stopped: bool,
}

impl Watch {
    /// Stop watching. True when the copy holds bytes newer than the last save announced
    /// (written but not yet seen twice): nothing has queued them.
    fn halt(&self) -> bool {
        let last = {
            let mut st = self.state.lock().unwrap();
            st.stopped = true;
            st.last
        };
        self.handle.abort();
        sig_of(&self.local).is_some_and(|now| Some(now) != last)
    }
}

impl Core {
    pub fn new(host: Arc<dyn Host>, paths: Paths) -> Arc<Core> {
        Arc::new(Core {
            host,
            paths,
            sessions: Default::default(),
            transfers: Default::default(),
            conflicts: Default::default(),
            edits: Default::default(),
            copies: Default::default(),
            opening: Default::default(),
            uploading: Default::default(),
            writing: Default::default(),
            live: Default::default(),
        })
    }

    fn session(&self, id: &str) -> Result<Arc<Session>> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(AppError::NotConnected)
    }
}

/// Ids no other window can make: the time, this process's id and a counter shared by every
/// engine in it. Two windows saving a new site in the same millisecond once made the same id,
/// and a site's id names its keychain entry, which is now written before the site is saved.
fn new_id(prefix: &str, _state: &Core) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{prefix}-{t}-{}-{n}", std::process::id())
}

// ---------- sites ----------

/// Site file edits are load-modify-save: serialize them (across processes too: the store's
/// lock), and keep the disk work off the main thread.
async fn with_store<T: Send + 'static>(
    state: &Core,
    f: impl FnOnce(&Store) -> Result<T> + Send + 'static,
) -> Result<T> {
    let (dir, host) = (state.paths.config.clone(), state.host.clone());
    tokio::task::spawn_blocking(move || {
        let store = store(&dir, &host)?;
        store.transact(|| f(&store))
    })
    .await
    .map_err(|e| AppError::Msg(e.to_string()))?
}

/// The store, reporting a file it sets aside to the user (`Event::Notice`).
fn store(dir: &Path, host: &Arc<dyn Host>) -> Result<Store> {
    Ok(Store::new(dir)?.reporting(host.clone()))
}

/// Keychain work, off the main thread and outside `store.lock`: on a keychain that asks to be
/// unlocked, the question must not hold every window's site changes (review FR-5).
async fn keychain(state: &Core, f: impl FnOnce(&Store) -> Result<()> + Send + 'static) -> Result<()> {
    let dir = state.paths.config.clone();
    blocking(move || f(&Store::new(&dir)?)).await
}

/// The saved sites, and how many entries of sites.json this build cannot read (they are kept
/// as they are, review FR2-1).
pub async fn sites_read(state: &Core) -> Result<SiteList> {
    let dir = state.paths.config.clone();
    tokio::task::spawn_blocking(move || Store::new(&dir)?.load_sites())
        .await
        .map_err(|e| AppError::Msg(e.to_string()))?
}


/// Save a site. `password`: None = leave keychain untouched,
/// Some("") = remove stored password (on a key-based SFTP site: the key has no passphrase,
/// so connect stops asking), Some(pw) = store it. None on a change that makes the secret mean
/// something else (an SFTP key's passphrase on a site that now logs in with a password, or the
/// reverse) forgets it: a key's passphrase must never go to a server as a password (SNA5).
pub async fn site_save(
    state: &Core,
    mut site: Site,
    mut password: Option<String>,
) -> Result<Site> {
    let is_new = site.id.is_empty();
    if is_new {
        site.id = new_id("site", state);
    }
    if site.port == 0 {
        site.port = site.protocol.default_port();
    }
    // 1. Under the lock: can the change land at all (a newer build's file, a site deleted
    // meanwhile, a damaged file kept aside now), and which id is free. A save that cannot land
    // has not touched the keychain.
    let probe = site.id.clone();
    let (id, stored) = with_store(state, move |store| {
        let c = store.sites_for_change()?;
        if !is_new {
            return match c.sites.iter().find(|s| s.id == probe) {
                Some(s) => Ok((probe, Some(s.stored_secret().to_string()))),
                None => Err(c.missing(&probe)),
            };
        }
        // An id already in the file (an older build's, made in the same millisecond, or an
        // entry this build cannot read) is never shared: it names the other site's password.
        Ok((
            if c.id_taken(&probe) {
                (2..).map(|n| format!("{probe}-{n}")).find(|id| !c.id_taken(id)).expect("a free id")
            } else {
                probe
            },
            None,
        ))
    })
    .await?;
    site.id = id;
    // The secret kept as it is only while it still means what it was saved as (SNA5).
    if password.is_none() && stored.is_some_and(|s| s != site.wants_secret()) {
        password = Some(String::new());
    }
    // 2. The keychain, outside the lock (review FR-5).
    let (mut wrote, mut forgot) = (false, false);
    if let Some(pw) = password {
        let id = site.id.clone();
        if pw.is_empty() {
            keychain(state, move |s| s.delete_password(&id)).await?;
            forgot = true;
            site.has_password = site.protocol == Protocol::Sftp && !site.key_path.is_empty();
            site.secret_for.clear();
        } else {
            keychain(state, move |s| s.set_password(&id, &pw)).await?;
            site.has_password = true;
            site.secret_for = site.wants_secret().into();
            wrote = true;
        }
    }
    // 3. Under the lock again, on the newest file.
    let saving = site.clone();
    let saved = with_store(state, move |store| {
        let mut c = store.sites_for_change()?;
        match (c.sites.iter().position(|s| s.id == saving.id), is_new) {
            (Some(i), false) => c.sites[i] = saving.clone(),
            (None, true) if !c.id_taken(&saving.id) => c.sites.push(saving.clone()),
            // Saving a site deleted meanwhile would resurrect it (without its password).
            (None, false) => return Err(c.missing(&saving.id)),
            _ => return Err(AppError::Msg("Another window saved a site with the same id at this moment; save again".into())),
        }
        if forgot {
            c.password_gone(&saving.id); // a duplicate this build cannot read (FR3-3)
        }
        store.save_sites(&c)?;
        Ok(saving)
    })
    .await;
    // A password written for a site that did not land would be an orphan nobody is told about.
    // Removed only where the id is this save's alone: a new site, or one deleted meanwhile
    // (whose own password went before it did); an existing site keeps the password it now has.
    if let Err(e) = &saved {
        let gone = !is_new && !with_store(state, {
            let id = site.id.clone();
            move |s| Ok(s.sites_if_sound()?.is_none_or(|c| c.id_taken(&id)))
        })
        .await
        .unwrap_or(true);
        if wrote && (is_new || gone) {
            let id = site.id.clone();
            if let Err(k) = keychain(state, move |s| s.delete_password(&id)).await {
                log::warn!(target: "vibeftp", "A password saved for a site that was not saved ({e}) stays in the keychain ({k})");
            }
        }
    }
    saved
}

/// Remember the last visited folders for a site (cheap, called on navigation).
pub async fn site_touch(state: &Core, id: String, last_remote: String, last_local: String) -> Result<()> {
    with_store(state, move |store| {
        // Automatic: a damaged file is left for a change the user makes to set aside.
        let Some(mut c) = store.sites_if_sound()? else { return Ok(()) };
        if let Some(s) = c.sites.iter_mut().find(|s| s.id == id) {
            if !last_remote.is_empty() {
                s.last_remote = last_remote;
            }
            if !last_local.is_empty() {
                s.last_local = last_local;
            }
            store.save_sites(&c)?;
        }
        Ok(())
    })
    .await
}

/// The site stays until its password is gone: an orphan in the keychain that nobody is told
/// about is worse than an error the user can retry. A delete never writes a list it did not
/// read: on a damaged file, the file is kept aside and the user is told the site is not in the
/// new list (review FR-2). The keychain is outside the lock (FR-5). A site that is not in the
/// list any more (another window deleted it, a sync tool replaced the file) still has its
/// password removed, or nothing would ever name it again (FR2-4). One that is there only as an
/// entry this build cannot read is still a site, and keeps its password (FR2-1). A readable
/// site with such a duplicate (same id): the readable one owns the password, both go, and the
/// duplicate stays in the file with `has_password` false (FR3-3).
pub async fn site_delete(state: &Core, id: String) -> Result<()> {
    let probe = id.clone();
    let there = with_store(state, move |store| {
        let c = store.sites_for_change()?;
        let there = c.sites.iter().any(|s| s.id == probe);
        if c.set_aside.is_some() || (!there && c.id_taken(&probe)) {
            return Err(c.missing(&probe));
        }
        Ok(there)
    })
    .await?;
    let key = id.clone();
    keychain(state, move |s| s.delete_password(&key)).await?;
    if !there {
        return Ok(());
    }
    with_store(state, move |store| {
        let mut c = store.sites_for_change()?;
        if c.set_aside.is_some() {
            return Err(c.missing(&id));
        }
        let before = c.sites.len();
        c.sites.retain(|s| s.id != id);
        // A duplicate this build cannot read keeps its place, without the password (FR3-3).
        let twin = c.password_gone(&id);
        if c.sites.len() == before && !twin {
            return Ok(());
        }
        store.save_sites(&c)
    })
    .await
}

// ---------- sessions ----------

pub async fn connect(
    state: &Core,
    site: Site,
    password: Option<String>,
) -> Result<ConnectResult> {
    let (password, known) = {
        let (dir, host) = (state.paths.config.clone(), state.host.clone());
        let site = site.clone();
        tokio::task::spawn_blocking(move || -> Result<(String, Option<String>)> {
            let store = store(&dir, &host)?;
            // A key without a passphrase has nothing in the keychain (C1-F10-8).
            let key_site = site.protocol == Protocol::Sftp && !site.key_path.is_empty();
            let password = match password {
                Some(p) => p,
                // A secret saved as something else is never sent as this site's secret: a key's
                // passphrase never goes to a server as a password (SNA5). Not even read.
                None if site.stored_secret() != site.wants_secret() => {
                    if site.has_password && !key_site {
                        return Err(AppError::SecretUnavailable("it was saved as the SFTP key's passphrase".into()));
                    }
                    String::new()
                }
                // A password the site says is saved but the keychain cannot give must not go
                // out as an empty one (a failed login with no hint at the keychain).
                None => match store.get_password(&site.id) {
                    Ok(Some(p)) => p,
                    Ok(None) if site.has_password && !key_site => {
                        return Err(AppError::SecretUnavailable(format!(
                            "the keychain has no password for {}",
                            site.name
                        )));
                    }
                    Err(e) if site.has_password => {
                        return Err(AppError::SecretUnavailable(format!("the keychain could not be read ({e})")));
                    }
                    _ => String::new(),
                },
            };
            let known = match site.protocol {
                Protocol::Sftp => store.known_host(&site.host, site.port)?,
                Protocol::Ftps => store.known_cert(&site.host, site.port)?,
                Protocol::Ftp => None,
            };
            Ok((password, known))
        })
        .await
        .map_err(|e| AppError::Msg(e.to_string()))??
    };
    let id = new_id("sess", state);
    // An unknown or changed SSH host key (FTPS certificate) comes back as an error carrying
    // the fingerprint; the UI confirms it and calls `trust_host_key` (`trust_certificate`),
    // then retries.
    let (session, cwd, fingerprint) =
        Session::open(state.host.clone(), id.clone(), site.clone(), password, known.clone()).await?;
    // Pins from before the key algorithm was stored get it on their first matching connect,
    // so later connects ask for that key type first (C1-F06-1).
    if let (Protocol::Sftp, Some(pin), Some(entry)) = (&site.protocol, known, fingerprint)
        && crate::protocol::sftp::pin_needs_upgrade(&pin, &entry)
    {
        let (dir, events, host, port) = (state.paths.config.clone(), state.host.clone(), site.host.clone(), site.port);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = store(&dir, &events).and_then(|s| s.upgrade_host(&host, port, &pin, &entry)) {
                log::warn!(target: "vibeftp", "Could not record the host key type for {host}: {e}");
            }
        });
    }
    let parallel = session.site.transfer_slots();
    state.sessions.lock().unwrap().insert(id.clone(), session);
    Ok(ConnectResult {
        session: id,
        cwd,
        parallel,
    })
}

/// Returns the edit copies of this session that hold saves the server never got, and the files
/// saved beside a copy (one still held included): they stay on disk (named in the log too);
/// everything else of the session's edit copies is deleted, a held one later.
pub async fn disconnect(state: &Core, session: String) -> Result<Vec<EditChanged>> {
    let s = state.sessions.lock().unwrap().remove(&session);
    // Cancel this session's transfers and release any parked conflict prompts.
    {
        let transfers = state.transfers.lock().unwrap();
        let mut ids = Vec::new();
        for (id, (sess, flag)) in transfers.iter() {
            if *sess == session {
                flag.store(true, Ordering::Relaxed);
                ids.push(id.clone());
            }
        }
        let mut conflicts = state.conflicts.lock().unwrap();
        conflicts.retain(|k, _| !ids.iter().any(|id| k.starts_with(&format!("{id}-c"))));
    }
    // Stop file watchers that belong to this session (guards dropped before any await), then
    // let go of the copies whose bytes the server has.
    let kept = {
        let prefix = format!("{session}|");
        let mut edits = state.edits.lock().unwrap();
        edits.retain(|k, w| {
            if k.starts_with(&prefix) {
                w.halt();
                false
            } else {
                true
            }
        });
        drop(edits);
        sweep_copies(state, Some(&session))
    };
    if let Some(s) = s {
        s.close().await;
    }
    Ok(kept)
}

/// Delete edit copies (of one session, or all) whose bytes are on the server; return the rest.
fn sweep_copies(state: &Core, session: Option<&str>) -> Vec<EditChanged> {
    let mut copies = state.copies.lock().unwrap();
    let mut kept = Vec::new();
    copies.retain(|local, c| {
        if session.is_some_and(|s| s != c.session) {
            return true;
        }
        let p = Path::new(local);
        match sig_of(p) {
            Some(now) if Some(now) != c.sig => {
                log::warn!(target: "vibeftp", "Edit copy {local} has changes the server never got; it stays there");
                // Kept for good: the week-old sweep must not take what the toast says is kept.
                if let (Some(dir), Some(file)) = (p.parent(), p.file_name()) {
                    write_note(dir, KEEP_MARKER, &file.to_string_lossy());
                }
                kept.push(EditChanged {
                    session: c.session.clone(),
                    remote: c.remote.clone(),
                    local: local.clone(),
                    name: split_remote(&c.remote).1,
                });
                false
            }
            _ => {
                // Still held (Busy): the copy stays listed and is tried again, at exit if the
                // session is over; a file the user saved beside it is named now, while the
                // session's end can still say so (RVA4-1).
                let (stays, others) = match remove_copy(state, p) {
                    Removal::Done => (false, Vec::new()),
                    Removal::Busy(others) => (true, others),
                    Removal::Shared(others) => (false, others),
                };
                for o in others {
                    log::warn!(target: "vibeftp", "{} was saved next to the edit copy {local}; the server never got it, and it stays there", o.display());
                    kept.push(EditChanged {
                        session: c.session.clone(),
                        remote: c.remote.clone(),
                        local: o.to_string_lossy().to_string(),
                        name: o.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                    });
                }
                stays
            }
        }
    });
    kept
}

/// The names of the edit copies holding edits the server never got: the ones the session's end
/// and the exit keep (the comparison `sweep_copies` keeps a copy by). Read only, for the
/// question asked before a quit (RVA5-2).
pub fn unsent_copies(state: &Core) -> Vec<String> {
    let copies = state.copies.lock().unwrap();
    let mut names: Vec<String> = copies
        .iter()
        .filter(|(local, c)| sig_of(Path::new(local)).is_some_and(|now| Some(now) != c.sig))
        .map(|(_, c)| split_remote(&c.remote).1)
        .collect();
    names.sort();
    names
}

/// What `remove_copy` did.
enum Removal {
    /// The copy, its part file and its folder are gone.
    Done,
    /// The copy could not go (an editor still holds it): it goes with the next sweep. Nothing
    /// is removed; these are the files beside it that are not the editor's, the user's (RVA3-2),
    /// named by the sweep (RVA4-1).
    Busy(Vec<PathBuf>),
    /// Something else is in the copy's folder, such as a file the user saved there with Save
    /// As: nothing is removed, and these are the other things.
    Shared(Vec<PathBuf>),
}

/// The part file an edit download writes before it is swapped in over the copy.
fn part_of(local: &Path) -> PathBuf {
    let own = local.file_name().is_some_and(|n| n == ".vibeftp-part");
    local.with_file_name(if own { ".vibeftp-part~" } else { ".vibeftp-part" })
}

/// Whether `name` is the lock or backup file an editor makes beside `file`, the one it has
/// open: `<file>~` (Emacs and others), Vim's `.<file>.sw?` (`<file>.sw?` when `file` already
/// starts with a dot: `.htaccess.swp`, RVA3-3), LibreOffice's `.~lock.<file>#`, Word's `~$` and
/// the tail of `<file>` (it drops up to two leading characters). Those are the editor's, not
/// files the user saved (RVA2). Only a name built from that file counts: one that merely looks
/// like it (`notes~`) is the user's (RVA2-1). Case-blind, as Windows names are.
fn editor_file_of(name: &str, file: &str) -> bool {
    let (n, f) = (name.to_lowercase(), file.to_lowercase());
    let swap = |r: Option<&str>| r.and_then(|r| r.strip_prefix(".sw")).is_some_and(|r| r.chars().count() == 1);
    let vim = swap(n.strip_prefix('.').and_then(|r| r.strip_prefix(f.as_str()))) || (f.starts_with('.') && swap(n.strip_prefix(f.as_str())));
    let word = n.strip_prefix("~$").is_some_and(|t| !t.is_empty() && f.ends_with(t) && f.chars().count() - t.chars().count() <= 2);
    n == format!("{f}~") || vim || n == format!(".~lock.{f}#") || word
}

/// The file in each copy's folder that names the copy, written when the copy is made, so the
/// sweeps never have to guess which file is the copy (RVA3-1). It starts with U+FFFD, which no
/// copy's name can hold (`safe_name` refuses it), so it never takes a server file's place.
/// Hidden, so the editor's Save As does not show it.
const COPY_MARKER: &str = "\u{FFFD}vibeftp-copy";

/// Beside the marker, in the folder of a copy that a session's end or the exit kept for edits
/// the server never got ("kept here", says the toast): the week-old sweep keeps such a folder for
/// good (review 52-A4, outside its range). Same rules as the marker: U+FFFD first, so no copy can
/// have its name; hidden; never counted or named; a failed write is only logged.
const KEEP_MARKER: &str = "\u{FFFD}vibeftp-keep";

/// In each session folder: a hidden file this process makes with the folder and holds open,
/// sharing nothing, until the process ends (not the session: copies a session that ended keeps
/// listed for the exit are covered too). The start-up sweep of another window cannot open it,
/// so it never sweeps a live session's folder (RVA5-1); after a crash nobody holds it, and the
/// folder is swept as before. Same rules as the markers: U+FFFD first, so no copy can have its
/// name; hidden; never counted or named (it is in the session folder, not a copy's); a failed
/// make is only logged, and that session's folder is then swept as before.
const LIVE_MARKER: &str = "\u{FFFD}vibeftp-live";

/// Make and hold the live marker of a session folder (`Core::live`), unless it is held already.
fn hold_session(state: &Core, dir: &Path) {
    let mut live = state.live.lock().unwrap();
    if live.iter().any(|(d, _)| d == dir) {
        return;
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        open.share_mode(0).attributes(FILE_ATTRIBUTE_HIDDEN);
    }
    match open.open(dir.join(LIVE_MARKER)) {
        Ok(f) => live.push((dir.to_path_buf(), f)),
        Err(e) => log::warn!(target: "vibeftp", "Could not mark the edit folder {} as in use: {e}", dir.display()),
    }
}

/// Open a session folder's live marker the way its hold does, sharing nothing: refused while a
/// process holds it.
fn open_live(dir: &Path) -> std::io::Result<std::fs::File> {
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        open.share_mode(0);
    }
    open.open(dir.join(LIVE_MARKER))
}

/// Remove a session folder that holds nothing but its live marker (or nothing): the hold
/// (`held`: the engine's; the sweep holds none) is closed first and the marker removed, or the
/// folder could never go. Anything else in it keeps the folder and the hold.
fn remove_session_dir(dir: &Path, held: Option<&Mutex<Vec<(PathBuf, std::fs::File)>>>) -> bool {
    let mut live = held.map(|h| h.lock().unwrap());
    let bare = std::fs::read_dir(dir).is_ok_and(|mut items| items.all(|e| e.is_ok_and(|e| e.file_name() == LIVE_MARKER)));
    if !bare {
        return false;
    }
    if let Some(live) = live.as_mut() {
        live.retain(|(d, _)| d != dir);
    }
    let _ = std::fs::remove_file(dir.join(LIVE_MARKER));
    std::fs::remove_dir(dir).is_ok()
}

/// Write the copy's name into its folder's marker. Best effort: a folder without one is swept
/// as an older version's (`sweep_old_session`), which keeps more, never less, while the copy is
/// in it: it goes only with the copy alone (and part files), where a marked folder also lets the
/// copy's editor files go (RVA4-2: no file of the user's under a plain name goes in either).
fn write_marker(dir: &Path, name: &str) {
    write_note(dir, COPY_MARKER, name);
}

/// Write `name` into the hidden file `file` in `dir`, unless it already holds it. Best effort.
fn write_note(dir: &Path, file: &str, name: &str) {
    let marker = dir.join(file);
    if std::fs::read_to_string(&marker).is_ok_and(|n| n == name) {
        return;
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create(true).truncate(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        open.attributes(FILE_ATTRIBUTE_HIDDEN);
    }
    if let Err(e) = open.open(&marker).and_then(|mut f| std::io::Write::write_all(&mut f, name.as_bytes())) {
        log::warn!(target: "vibeftp", "Could not write a note on the edit copy in {}: {e}", dir.display());
    }
}

/// Whether a file is an Office-style temporary file: a name that starts with `~` (Word's
/// `~WRL0001.tmp` and `~$` files) and the hidden or temporary attribute (RVA3-2). The attribute
/// alone never makes a file the editor's: a hidden file under a plain name is the user's, kept
/// and named (RVA4-2). A file both hidden and system (`Thumbs.db`, `desktop.ini`) is the
/// system's, whatever its name: not named, and it goes with the copy (RVA5-4).
fn editor_temp(e: &std::fs::DirEntry) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
        const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
        let Ok(a) = e.metadata().map(|m| m.file_attributes()) else { return false };
        let tilde = e.file_name().to_string_lossy().starts_with('~');
        (tilde && a & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY) != 0)
            || a & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

/// Whether `name` looks like any editor's lock or backup file, whatever file it is of: the
/// patterns `editor_file_of` knows. Only for folders with no marker, where the copy is unknown.
fn editor_pattern(name: &str) -> bool {
    let n = name.to_lowercase();
    let mut head = n.chars();
    let vim = n.starts_with('.') && head.next_back().is_some() && head.as_str().len() > 3 && head.as_str().ends_with(".sw");
    n.ends_with('~') || vim || (n.starts_with(".~lock.") && n.ends_with('#')) || n.starts_with("~$")
}

/// Whether a program has `local` open (Word and Excel hold the file they show). Not knowing
/// is "no": the removal then finds out for itself.
#[cfg(windows)]
fn held(local: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(local)
        .is_err_and(|e| e.raw_os_error() == Some(ERROR_SHARING_VIOLATION))
}
#[cfg(not(windows))]
fn held(_local: &Path) -> bool {
    false
}

/// Remove an edit copy and its half-downloaded part, by name, then its per-file folder, and
/// the session and host folders if that left them empty. A folder is only ever removed empty:
/// when anything else is in it (the editor's Save As opens there), all of it stays and is
/// named (FEA4). A copy its editor still holds is Busy whatever is beside it: nothing is
/// removed, it stays listed and is tried again later (RVA3-2), and the files beside it that are
/// not the editor's are named as the user's (RVA4-1, as RVA2-4 wanted). The editor's own lock
/// and backup files of the copy (by name, RVA2, RVA2-1; or a hidden or temporary `~` file,
/// RVA3-2, RVA4-2; or a hidden system file, RVA5-4) are not counted, and go with it, and so do
/// the folder's marker (RVA3-1) and any keep marker.
fn remove_copy(state: &Core, local: &Path) -> Removal {
    let Some(dir) = local.parent() else { return Removal::Busy(Vec::new()) };
    let part = part_of(local);
    let same = |a: &Path, b: &Path| match (a.file_name(), b.file_name()) {
        (Some(a), Some(b)) => a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),
        _ => false,
    };
    let copy = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (marker, keep) = (dir.join(COPY_MARKER), dir.join(KEEP_MARKER));
    let editor_own = |e: &std::fs::DirEntry| editor_file_of(&e.file_name().to_string_lossy(), &copy) || editor_temp(e);
    let (editor, others): (Vec<PathBuf>, Vec<PathBuf>) = match std::fs::read_dir(dir) {
        Ok(items) => {
            let (editor, others): (Vec<std::fs::DirEntry>, Vec<std::fs::DirEntry>) =
                items.flatten().filter(|e| !same(&e.path(), local) && !same(&e.path(), &part) && e.path() != marker && e.path() != keep).partition(editor_own);
            (editor.iter().map(|e| e.path()).collect(), others.iter().map(|e| e.path()).collect())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Removal::Done,
        Err(_) => return Removal::Busy(Vec::new()),
    };
    // Held: the files of the user's beside it are named now (RVA4-1); the copy itself waits
    // until it is let go (RVA3-2).
    if held(local) {
        return Removal::Busy(others);
    }
    if !others.is_empty() {
        return Removal::Shared(others);
    }
    for f in [local, part.as_path()] {
        match std::fs::remove_file(f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Removal::Busy(Vec::new()),
            _ => {}
        }
    }
    // One the editor still holds stays, and its folder with it (the week-old sweep takes both).
    for f in editor.iter().chain([&marker, &keep]) {
        let _ = std::fs::remove_file(f);
    }
    // Only if still empty: a file saved there this instant stays, with its folder. The session
    // folder goes with its live marker, once nothing else is in it.
    if std::fs::remove_dir(dir).is_ok()
        && let Some(session_dir) = dir.parent()
        && remove_session_dir(session_dir, Some(&state.live))
    {
        let _ = session_dir.parent().map(std::fs::remove_dir);
    }
    Removal::Done
}

/// Delete one edit copy once nothing needs it: not being opened or uploaded, and the server
/// has its bytes. Otherwise it stays until a save of it goes up, the session ends or the app exits.
fn discard_copy(state: &Core, session: &str, local: &str) {
    if state.opening.lock().unwrap().contains(&format!("{session}|{local}"))
        || state.uploading.lock().unwrap().contains(local)
        || state.edits.lock().unwrap().contains_key(&format!("{session}|{local}"))
    {
        return;
    }
    let mut copies = state.copies.lock().unwrap();
    let Some(c) = copies.get(local) else { return };
    let p = Path::new(local);
    if sig_of(p).is_some_and(|now| Some(now) != c.sig) {
        return;
    }
    // Left in the list when anything stays: the session's end names what stayed.
    if matches!(remove_copy(state, p), Removal::Done) {
        copies.remove(local);
    }
}

/// At exit: cancel every transfer, stop every watcher and delete the edit copies whose bytes
/// the server has. What stays is told to nobody here: the window is already gone, and the log
/// lines die with it (a known limit, RVA4-1). Unsent edits of a file open for editing are named
/// by the question before the quit (`unsent_copies`, RVA5-2); files saved beside a copy are not.
pub fn on_exit(state: &Core) {
    // A quit the user confirmed cuts the transfers short. An FTP file runs as one blocking task
    // that only stops at its cancel flag, and the runtime's shutdown would wait for it to finish.
    for (_, flag) in state.transfers.lock().unwrap().values() {
        flag.store(true, Ordering::Relaxed);
    }
    // Parked on a conflict prompt: a dropped sender wakes it with Cancel.
    state.conflicts.lock().unwrap().clear();
    for (_, w) in state.edits.lock().unwrap().drain() {
        w.halt();
    }
    sweep_copies(state, None);
}

/// Edit copies left behind by a crash: session folders untouched for a week go. Also the
/// folder older versions kept them in, under %TEMP%: nothing is saved there any more, so its
/// week-old folders go whole, in whichever layout those versions wrote (RVA9).
pub fn sweep_old_copies(state: &Core) {
    sweep_old_in(&[edit_root(state)], false);
    sweep_old_in(&[std::env::temp_dir().join("VibeFTP")], true);
}

/// The sweep, on its roots. It walks real folders only: a root, host or session folder that is
/// a link, a junction or any other reparse point is passed over, never entered and never
/// removed, so a link planted there cannot point the sweep at folders elsewhere (SP3). `whole`:
/// a week-old session folder goes with everything in it (the old versions' root); otherwise
/// copy by copy (`sweep_old_session`).
fn sweep_old_in(roots: &[PathBuf], whole: bool) {
    let week = Duration::from_secs(7 * 24 * 3600);
    for root in roots {
        if !std::fs::symlink_metadata(root).is_ok_and(|m| plain_dir(&m)) {
            continue;
        }
        let Ok(hosts) = std::fs::read_dir(root) else { continue };
        for host in hosts.flatten() {
            // A DirEntry's metadata is the entry's own (FindNextFile's), not a link's target.
            if !host.metadata().is_ok_and(|m| plain_dir(&m)) {
                continue;
            }
            let Ok(sessions) = std::fs::read_dir(host.path()) else { continue };
            for s in sessions.flatten() {
                let Ok(m) = s.metadata() else { continue };
                let old = m.modified().is_ok_and(|t| t.elapsed().is_ok_and(|age| age > week));
                if old && plain_dir(&m) {
                    if whole {
                        let _ = std::fs::remove_dir_all(s.path());
                    } else {
                        sweep_old_session(&s.path());
                    }
                }
            }
            let _ = std::fs::remove_dir(host.path());
        }
    }
}

/// A week-old session folder. Each copy's folder goes when it holds no more than the copy, the
/// app's part file, the marker and the editor's own lock and backup files of the copy
/// (`editor_file_of`, RVA2; or a hidden or temporary `~` file or a hidden system file,
/// `editor_temp`, RVA4-2, RVA5-4). The copy
/// is the file the marker names (RVA3-1): anything else (a file saved next to the copy, a
/// look-alike such as `notes~`, the user's `index.php` beside a copy `index.php~`) keeps the
/// folder whole, and the session folder with it. A folder with the keep marker (a copy kept for
/// unsent edits, `KEEP_MARKER`) stays for good while the copy it names is in it; without that
/// copy it is a plain marked folder, the keep marker going with the marker (RVA5-3). A folder
/// with no marker (made by a version
/// before it) goes only when it holds exactly one file besides part files, and that file is not
/// named like any editor's file; any other stays. The copy and part files go first, the editor's
/// files and the marker only once those did. Folders are only ever removed empty (FEA4). A live
/// session's folder (a process holds its `LIVE_MARKER`) is left whole; a marker nobody holds (a
/// crash) goes with the folder (RVA5-1).
fn sweep_old_session(dir: &Path) {
    let live = match open_live(dir) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return,
    };
    let Ok(items) = std::fs::read_dir(dir) else { return };
    for it in items.flatten() {
        if !it.metadata().is_ok_and(|m| plain_dir(&m)) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(it.path()) else { continue };
        let files: Vec<std::fs::DirEntry> = files.flatten().collect();
        if !files.iter().all(|e| e.metadata().is_ok_and(|m| m.is_file())) {
            continue;
        }
        let name = |e: &std::fs::DirEntry| e.file_name().to_string_lossy().into_owned();
        // The keep marker holds while the copy it names is still there (unreadable: it holds).
        // Once the user moved or deleted that copy, the folder is a plain marked one (RVA5-3).
        let keeps = |k: &std::fs::DirEntry| match std::fs::read_to_string(k.path()) {
            Ok(kept) => files.iter().any(|e| name(e).to_lowercase() == kept.to_lowercase()),
            Err(_) => true,
        };
        if files.iter().any(|e| e.file_name() == KEEP_MARKER && keeps(e)) {
            continue;
        }
        let part = |e: &std::fs::DirEntry| e.file_name() == ".vibeftp-part" || e.file_name() == ".vibeftp-part~";
        let is_marker = |e: &std::fs::DirEntry| e.file_name() == COPY_MARKER || e.file_name() == KEEP_MARKER;
        let own: Vec<&std::fs::DirEntry> = match files.iter().find(|e| e.file_name() == COPY_MARKER) {
            Some(m) => {
                // Unreadable: the copy is not known, so nothing goes.
                let Ok(copy) = std::fs::read_to_string(m.path()) else { continue };
                let copy = copy.to_lowercase();
                let is_copy = |e: &std::fs::DirEntry| name(e).to_lowercase() == copy;
                let editor = |e: &std::fs::DirEntry| editor_file_of(&name(e), &copy) || editor_temp(e);
                if !files.iter().all(|e| is_marker(e) || part(e) || is_copy(e) || editor(e)) {
                    continue;
                }
                files.iter().filter(|e| part(e) || is_copy(e)).collect()
            }
            None => {
                let counted: Vec<&std::fs::DirEntry> = files.iter().filter(|e| !part(e)).collect();
                if counted.len() > 1 || counted.first().is_some_and(|e| editor_pattern(&name(e))) {
                    continue;
                }
                files.iter().collect()
            }
        };
        if own.iter().all(|e| std::fs::remove_file(e.path()).is_ok()) {
            let rest = files.iter().filter(|e| !is_marker(e) && !own.iter().any(|o| std::ptr::eq(*o, *e)));
            for e in rest.chain(files.iter().filter(|e| is_marker(e))) {
                let _ = std::fs::remove_file(e.path());
            }
            let _ = std::fs::remove_dir(it.path());
        }
    }
    drop(live);
    remove_session_dir(dir, None);
}

/// A folder that is not a link, a junction or any other reparse point.
fn plain_dir(m: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
    }
    m.is_dir() && !m.file_type().is_symlink()
}

/// Pin exactly the fingerprint the user was shown (not whatever the next handshake presents),
/// with its key algorithm when this run saw it.
pub fn trust_host_key(state: &Core, host: String, port: u16, fingerprint: String) -> Result<()> {
    let entry = crate::protocol::sftp::pin_entry(&fingerprint);
    store(&state.paths.config, &state.host)?.remember_host(&host, port, &entry)
}

/// Pin the FTPS certificate the user was shown (`SHA256:…` of the server's certificate) for
/// this host and port; it is then accepted although no public authority vouches for it.
pub fn trust_certificate(state: &Core, host: String, port: u16, fingerprint: String) -> Result<()> {
    if !fingerprint.starts_with("SHA256:") || fingerprint.contains(char::is_whitespace) {
        return Err(AppError::Msg("Not a certificate fingerprint".into()));
    }
    store(&state.paths.config, &state.host)?.remember_cert(&host, port, &fingerprint)
}

/// Whether this host's key (`cert`: its FTPS certificate) was pinned in a kept copy of a damaged
/// known_hosts.json and is not pinned now: then its first-connection prompt says it was
/// trusted before (review FR-4, FR2-2). Other hosts get the usual prompt.
pub fn pinned_before(state: &Core, host: String, port: u16, cert: bool) -> Result<Option<PinnedBefore>> {
    let key = if cert { format!("ftps:{host}:{port}") } else { format!("{host}:{port}") };
    Ok(Store::new(&state.paths.config)?.pinned_before(&key))
}

/// Every kept copy of a damaged sites.json or known_hosts.json, with its notice: each window
/// tells about the ones it has not told about yet (review FR2-6).
pub fn set_aside_copies(state: &Core) -> Result<Vec<Kept>> {
    Store::new(&state.paths.config)?.kept_copies()
}

// ---------- remote fs ----------

pub async fn remote_list(
    state: &Core,
    session: String,
    path: String,
) -> Result<Vec<Entry>> {
    let s = state.session(&session)?;
    let mut entries = s.browse(|r, _| {
        let p = path.clone();
        async move { r.list(&p).await }
    }).await?;
    sort_entries(&mut entries);
    Ok(entries)
}

pub async fn remote_mkdir(state: &Core, session: String, path: String) -> Result<()> {
    let s = state.session(&session)?;
    s.browse(|r, retry| {
        let p = path.clone();
        async move {
            // The first MKD may have gone through with only its reply lost.
            if retry && r.stat(&p).await?.is_some_and(|e| e.is_dir) {
                return Ok(());
            }
            r.mkdir(&p).await
        }
    })
    .await
}

/// `seen`: the row the user confirmed. What is at `path` must still be it (servers have no
/// stable ids: the same kind, and a file's size and date), or nothing is deleted (review
/// SOL-FTP-2). `looks`: shared by the rows of one delete, so each folder is read once for all
/// of them (review R-SOL-2).
pub async fn remote_delete(
    state: &Core,
    session: String,
    path: String,
    is_dir: bool,
    seen: Entry,
    looks: Looks,
) -> Result<()> {
    let s = state.session(&session)?;
    delete_on(&s, path, is_dir, seen, looks, crate::protocol::WALK_BOUNDS).await
}

/// `remote_delete` on `s`, a folder's walk held to `bounds`. One count for the whole delete,
/// across `browse`'s retry (RF1-2): whatever error it ends in says what went before it, once
/// (RL5-1): a walk's refusal or bound, a connection error once no retry is left, a redial the
/// server refuses, the retry's own look failing or finding the folder changed. "Nothing was
/// deleted" only when nothing was.
pub(crate) async fn delete_on(
    s: &Session,
    path: String,
    is_dir: bool,
    seen: Entry,
    looks: Looks,
    bounds: crate::protocol::WalkBounds,
) -> Result<()> {
    let tally = Arc::new(Tally::default());
    let r = s
        .browse(|r, retry| {
            let (p, seen, looks, tally) = (path.clone(), seen.clone(), looks.clone(), tally.clone());
            async move {
                // The first DELE/RMD may have gone through with only its reply lost.
                if retry && r.stat(&p).await?.is_none() {
                    return Ok(());
                }
                if let Some(why) = r.changed_since(&p, &seen, &looks).await? {
                    // Items gone already (a retry): the count is added below, as to every error.
                    return Err(AppError::Msg(if tally.removed() == 0 { format!("{why}; nothing was deleted") } else { why }));
                }
                if is_dir {
                    // A link where a folder was named goes as the link itself (review R2-4).
                    r.remove_dir_all_in(&p, &looks, bounds, &tally).await
                } else {
                    r.remove_file(&p).await
                }
            }
        })
        .await;
    // Any error, however it came (`browse`'s own redial included), unless it says the count already.
    match r {
        Err(e) if tally.removed() > 0 && !matches!(e, AppError::Tallied(_)) => Err(deleted_before(e, tally.removed(), &path)),
        r => r,
    }
}

/// `replace`: the row of the target the user agreed to replace (`None`: a plain rename, which
/// never replaces anything); another object there now is not replaced (review SOL-FTP-2).
/// `looks`: shared by the moves of one action, so the target folder is read once for all of
/// them (review R-SOL-2).
pub async fn remote_rename(
    state: &Core,
    session: String,
    from: String,
    to: String,
    replace: Option<Entry>,
    looks: Looks,
) -> Result<()> {
    let s = state.session(&session)?;
    // Where a replace put the old target while it renamed: a retry after a dropped link finds
    // it there and finishes or undoes the move rather than starting over blind.
    let aside: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let r = s
        .browse(|r, retry| {
            let (f, t, aside, replace, looks) = (from.clone(), to.clone(), aside.clone(), replace.clone(), looks.clone());
            async move {
                if retry
                    && let Some(done) = rename_landed(&r, &f, &t, &aside).await?
                {
                    return done;
                }
                rename_once(&r, &f, &t, replace.as_ref(), &looks, &aside).await
            }
        })
        .await;
    let left = aside.lock().unwrap().take();
    match (r, left) {
        (Err(e), Some(a)) => Err(AppError::Msg(format!(
            "{e}. The old {} may now be called {}",
            split_remote(&to).1,
            split_remote(&a).1
        ))),
        (r, _) => r,
    }
}

/// A case-only rename (`readme` -> `README`) on a case-folding server finds the source itself
/// when it looks for the target: such a rename is told by listing the folder. The source's
/// folder may be reached by another path (SFTP lists a symlinked folder by its real path):
/// the target folder's listing holding the source says it is the same one. `None`: not case-only.
async fn case_only_listing(r: &Remote, f: &str, t: &str) -> Result<Option<Vec<Entry>>> {
    let (dir_t, name_t) = split_remote(t);
    let (dir_f, name_f) = split_remote(f);
    // A move keeps the name exactly: not case-only, and no listing to pay for.
    if name_f == name_t || !crate::protocol::same_name(&name_f, &name_t) {
        return Ok(None);
    }
    let l = r.list(&dir_t).await?;
    Ok((dir_f == dir_t || l.iter().any(|e| e.path == f)).then_some(l))
}

/// One attempt at a rename (with the move-aside dance when replacing on a server that will not
/// rename onto an existing file). A connection error is returned as it is, so `browse` redials
/// and `rename_landed` sorts out what the lost attempt did.
async fn rename_once(r: &Remote, f: &str, t: &str, replace: Option<&Entry>, looks: &Looks, aside: &Mutex<Option<String>>) -> Result<()> {
    let (_, name_t) = split_remote(t);
    let (_, name_f) = split_remote(f);
    let overwrite = replace.is_some();
    // Unix servers replace on RNTO: the target must still be the one the user agreed to lose.
    if let Some(seen) = replace
        && let Some(why) = r.changed_since(t, seen, looks).await?
    {
        return Err(AppError::Msg(format!("The {name_t} you chose to replace: {why}; nothing was renamed")));
    }
    // Unix FTP servers replace the target on RNTO; check first unless told otherwise.
    if !overwrite && f != t {
        // Only an entry spelled exactly like the target, other than the source, blocks a
        // case-only rename. Otherwise any-case: on a case-folding FTP server that answers only
        // through its listing, `readme.txt` is the very file `README.TXT` would replace.
        let existing = match case_only_listing(r, f, t).await? {
            Some(l) => l.into_iter().find(|e| e.name == name_t && e.name != name_f),
            None => r.stat_any_case(t).await?,
        };
        if let Some(existing) = existing {
            if existing.is_dir {
                return Err(AppError::Msg(format!("A folder named {} is in the way", existing.name)));
            }
            if existing.name != name_t {
                return Err(AppError::Msg(format!(
                    "{} already exists (the server takes names that differ only by case as one)",
                    existing.name
                )));
            }
            return Err(AppError::Msg(format!("{} already exists", existing.name)));
        }
    }
    let e = match r.rename(f, t).await {
        Ok(()) => return Ok(()),
        Err(e) if overwrite && !e.is_connection_error() => e,
        Err(e) => return Err(e),
    };
    // SFTP and Windows FTP servers refuse to rename onto an existing file.
    // Move the target aside first, so a rename that still fails costs nothing.
    // A case-only rename on a case-folding server finds the source itself: only
    // a distinct entry spelled exactly like the target is something to move aside
    // (README -> Readme next to an existing Readme on a case-sensitive server).
    let found = match case_only_listing(r, f, t).await {
        Ok(Some(l)) => Ok(l.into_iter().find(|x| x.name == name_t && x.name != name_f)),
        Ok(None) => r.stat(t).await,
        Err(e2) => Err(e2),
    };
    match found {
        Ok(Some(old)) if !old.is_dir => {}
        Ok(_) => return Err(e),
        Err(e2) if e2.is_connection_error() => return Err(e2),
        Err(_) => return Err(e),
    }
    // The aside name must be free: a replacing server would rename over it.
    let Some(a) = free_name(r, t).await? else {
        return Err(AppError::Msg(format!(
            "{e}. Ten old copies of {name_t} (.vibeftp-old) are in the way; remove them first"
        )));
    };
    // Recorded before the move: its reply may be the thing that gets lost.
    *aside.lock().unwrap() = Some(a.clone());
    if let Err(e2) = r.rename(t, &a).await {
        if !e2.is_connection_error() {
            *aside.lock().unwrap() = None; // nothing moved
        }
        return Err(e2);
    }
    match r.rename(f, t).await {
        // The rename went through; a leftover copy is still news the user needs.
        Ok(()) => finish_aside(r, &a, &name_t, aside).await,
        Err(e2) if e2.is_connection_error() => Err(e2),
        Err(e2) => match r.rename(&a, t).await {
            Ok(()) => {
                *aside.lock().unwrap() = None;
                Err(e2)
            }
            Err(e4) if e4.is_connection_error() => Err(e4),
            Err(_) => {
                *aside.lock().unwrap() = None;
                Err(AppError::Msg(format!(
                    "{e2}. The old {name_t} could not be put back; it is now called {}",
                    split_remote(&a).1
                )))
            }
        },
    }
}

/// The rename is done: remove the old target from where it was put aside.
async fn finish_aside(r: &Remote, a: &str, name_t: &str, aside: &Mutex<Option<String>>) -> Result<()> {
    match r.remove_file(a).await {
        Ok(()) => {
            *aside.lock().unwrap() = None;
            Ok(())
        }
        Err(e3) if e3.is_connection_error() => Err(e3),
        Err(e3) => {
            *aside.lock().unwrap() = None;
            Err(AppError::Msg(format!(
                "Renamed, but the old {name_t} could not be removed ({e3}); it is still called {}",
                split_remote(a).1
            )))
        }
    }
}

/// On the retry after a dropped link: did the lost attempt already do the job? `Some(result)`
/// when it did (with the cleanup of an aside copy, if one was left), `None` to run the rename
/// again, after putting an aside target back.
async fn rename_landed(r: &Remote, f: &str, t: &str, aside: &Mutex<Option<String>>) -> Result<Option<Result<()>>> {
    let (_, name_t) = split_remote(t);
    let (_, name_f) = split_remote(f);
    let a = aside.lock().unwrap().clone();
    let landed = match case_only_listing(r, f, t).await? {
        // One entry on a case-folding server: done once it is spelled like the target.
        Some(l) => l.iter().any(|e| e.name == name_t) && !l.iter().any(|e| e.name == name_f),
        None => r.stat(f).await?.is_none() && r.stat(t).await?.is_some(),
    };
    if landed {
        return Ok(Some(match a {
            Some(a) if r.stat(&a).await?.is_some() => finish_aside(r, &a, &name_t, aside).await,
            _ => {
                *aside.lock().unwrap() = None;
                Ok(())
            }
        }));
    }
    if let Some(a) = a {
        // The old target sits aside and the rename did not happen: put it back first.
        if r.stat(t).await?.is_none() && r.stat(&a).await?.is_some() {
            r.rename(&a, t).await?;
        }
        *aside.lock().unwrap() = None;
    }
    Ok(None)
}

/// The first of `<path>.vibeftp-old`, `.1`, `.2`... that nothing is called; `None` when all
/// ten are taken. A server that cannot say is an error: a rename onto a name in use would
/// destroy that file on Unix FTP (and a dropped link must reach `browse`'s retry).
async fn free_name(r: &Remote, path: &str) -> Result<Option<String>> {
    for i in 0..10 {
        let cand = if i == 0 { format!("{path}.vibeftp-old") } else { format!("{path}.vibeftp-old.{i}") };
        if r.stat(&cand).await?.is_none() {
            return Ok(Some(cand));
        }
    }
    Ok(None)
}

pub async fn remote_chmod(
    state: &Core,
    session: String,
    paths: Vec<String>,
    mode: u32,
) -> Result<()> {
    let s = state.session(&session)?;
    for path in paths {
        s.browse(|r, _| {
            let p = path.clone();
            async move { r.chmod(&p, mode).await }
        })
        .await?;
    }
    Ok(())
}

// ---------- local fs ----------

pub fn local_home(state: &Core) -> Result<String> {
    let home = state.paths.home.as_ref().ok_or_else(|| AppError::Msg("This account has no home folder".into()))?;
    Ok(home.to_string_lossy().to_string())
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLogicalDrives() -> u32;
}

/// Drive letters from the kernel's bitmask: no probing, so a dead mapped drive
/// cannot stall startup.
pub fn local_roots() -> Vec<String> {
    #[cfg(windows)]
    {
        let mask = unsafe { GetLogicalDrives() };
        (0..26u32)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| format!("{}:\\", (b'A' + i as u8) as char))
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec!["/".to_string()]
    }
}

/// Disk I/O never runs on the main thread: a slow share or a big delete would freeze the window.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Msg(e.to_string()))?
}

pub async fn local_list(path: String) -> Result<Vec<Entry>> {
    local_list_counted(path).await.map(|(entries, _)| entries)
}

/// The listing, and how many items it leaves out because their names are not valid Unicode
/// (no action may land on them; the pane says how many there are, review FR-10).
pub async fn local_list_counted(path: String) -> Result<(Vec<Entry>, usize)> {
    blocking(move || local_list_sync(&path)).await
}

fn local_list_sync(path: &str) -> Result<(Vec<Entry>, usize)> {
    // Read through the verbatim path (`work.` is not `work`), hand back the ordinary one.
    let shown = PathBuf::from(path);
    let mut out = Vec::new();
    let mut not_unicode = 0;
    for e in std::fs::read_dir(verbatim(path))? {
        let e = match e {
            Ok(e) => e,
            Err(_) => continue,
        };
        // A name that is not valid Unicode (a lone surrogate) has no String path: a lossy one
        // would name another file (`a\u{FFFD}`) or none. Such entries are left out, and said so.
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            not_unicode += 1;
            continue;
        };
        // The directory entry already carries type and size; only links need a second look.
        let own = e.metadata();
        let is_link = own.as_ref().map(|m| m.file_type().is_symlink()).unwrap_or(false);
        let meta = match &own {
            Ok(m) if m.file_type().is_symlink() => std::fs::metadata(e.path()).or_else(|_| e.metadata()),
            _ => own,
        };
        let (is_dir, size, modified) = match meta {
            Ok(m) => (
                // A link whose target is gone still says whether it was made for a folder.
                m.is_dir() || link_to_dir(&m),
                if m.is_dir() { 0 } else { m.len() },
                m.modified().map(millis).unwrap_or(0),
            ),
            Err(_) => (false, 0, 0),
        };
        out.push(Entry {
            path: shown.join(&name).to_string_lossy().to_string(),
            name,
            is_dir,
            is_link,
            size,
            modified,
            mode: None,
        });
    }
    if not_unicode > 0 {
        log::warn!(target: "vibeftp", "{path}: {not_unicode} item(s) with names that are not valid Unicode are not shown; VibeFTP cannot act on them safely");
    }
    sort_entries(&mut out);
    Ok((out, not_unicode))
}

#[cfg(windows)]
fn link_to_dir(m: &std::fs::Metadata) -> bool {
    std::os::windows::fs::FileTypeExt::is_symlink_dir(&m.file_type())
}
#[cfg(not(windows))]
fn link_to_dir(_m: &std::fs::Metadata) -> bool {
    false
}

/// A name the user typed for a new local file or folder. Through the `\\?\` path a trailing
/// dot or space (or a device name) would be stored as typed, an entry Explorer can neither
/// open nor delete, and the "already exists" check would miss its trimmed namesake.
fn new_local_name(path: &str) -> Result<()> {
    let name = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(AppError::Msg(format!(
            "{name:?} ends in a dot or a space, which Windows programs cannot handle; use {:?}",
            name.trim_end_matches(['.', ' '])
        )));
    }
    if !crate::protocol::safe_name(&name) {
        return Err(AppError::Msg(format!("{name:?} is not a valid file or folder name on Windows")));
    }
    Ok(())
}

pub async fn local_mkdir(path: String) -> Result<()> {
    new_local_name(&path)?;
    blocking(move || Ok(std::fs::create_dir(verbatim(&path))?)).await
}

/// What `path` is now (a link itself, not its target): taken when a delete or replace question
/// is shown, checked again right before the item goes (review SOL-FTP-2).
pub async fn local_identity(path: String) -> Result<LocalId> {
    blocking(move || Ok(crate::identity::of(&verbatim(&path))?)).await
}

/// `seen`: the item the user confirmed. Another one at the name now (or none) is left alone,
/// and a folder replaced meanwhile is never descended into.
pub async fn local_delete(path: String, is_dir: bool, seen: LocalId) -> Result<()> {
    blocking(move || {
        let path = verbatim(&path);
        let r = if seen.is_dir != is_dir {
            Ok(Some(crate::identity::CHANGED)) // already another kind when the question came
        } else if is_dir && !seen.reparse {
            crate::identity::remove_tree(&path, &seen)
        } else {
            // A file, or a link (a junction too): the link goes, never what it points at.
            crate::identity::remove_one(&path, &seen)
        };
        match r {
            Ok(None) => Ok(()),
            Ok(Some(why)) => Err(AppError::Msg(format!("{why}; nothing was deleted"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(AppError::Msg("it is no longer there; nothing was deleted".into()))
            }
            Err(e) => Err(e.into()),
        }
    })
    .await
}

/// Rename never replaces an existing file unless the user agreed to replace it (Windows'
/// rename would, silently). Renaming a file onto itself with different casing is fine.
/// `replace`: the target the user agreed to replace (`None`: a plain rename); another file
/// there now (or none) is not replaced (review SOL-FTP-2).
pub async fn local_rename(from: String, to: String, replace: Option<LocalId>) -> Result<()> {
    // A move keeps the name it has, whatever it is; only a new name is checked.
    if Path::new(&from).file_name() != Path::new(&to).file_name() {
        new_local_name(&to)?;
    }
    blocking(move || {
        let (from_v, to_v) = (verbatim(&from), verbatim(&to));
        let name = Path::new(&to).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if std::fs::symlink_metadata(&to_v).is_ok() {
            let same_file = match (std::fs::canonicalize(&from_v), std::fs::canonicalize(&to_v)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            };
            let target_is_dir = std::fs::metadata(&to_v).map(|m| m.is_dir()).unwrap_or(false);
            if !same_file && (replace.is_none() || target_is_dir) {
                return Err(AppError::Msg(format!("{} already exists", Path::new(&to).display())));
            }
            if let Some(seen) = replace.as_ref().filter(|_| !same_file)
                && !seen.same(&crate::identity::of(&to_v)?)
            {
                return Err(AppError::Msg(format!("The {name} you chose to replace: {}; nothing was renamed", crate::identity::CHANGED)));
            }
        } else if replace.is_some() {
            return Err(AppError::Msg(format!("The {name} you chose to replace is no longer there; nothing was renamed")));
        }
        Ok(std::fs::rename(from_v, to_v)?)
    })
    .await
}

/// Whether two local paths are one file (through a junction or link, say): both resolve to
/// the same final path. Anything unreadable counts as different.
pub async fn local_same_file(a: String, b: String) -> bool {
    blocking(move || {
        Ok(match (std::fs::canonicalize(verbatim(&a)), std::fs::canonicalize(verbatim(&b))) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        })
    })
    .await
    .unwrap_or(false)
}

/// File types Windows would *run* (or install, mount, apply) rather than open for viewing/editing,
/// and pages a browser would show (a phish, or an NTLM leak through a link). Two layers: this
/// list, and whatever Windows itself rates dangerous (`AssocIsDangerous`, review SNA2).
fn runs_code(path: &str) -> bool {
    const RISKY: &[&str] = &[
        "exe", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "msi",
        "msp", "msc", "scr", "pif", "lnk", "url", "reg", "cpl", "inf", "jar", "application", "appref-ms",
        "chm", "py", "pyw", "msix", "appx", "appinstaller", "scf", "settingcontent-ms", "library-ms",
        "search-ms", "xll", "diagcab", "iso", "vhdx", "rdp", "vhd", "img", "theme", "themepack",
        "deskthemepack", "msstyles", "diagcfg", "diagpkg", "psc1", "ppkg", "msu", "xbap", "xaml", "vsto",
        "mam", "mde", "accde", "wcx", "hlp", "ws", "wsc", "sct", "ps1xml", "mst", "website", "gadget",
        // SNA2: run at once by their handlers (the Python launcher, Java Web Start, Windows Sandbox),
        // a search location that can point at another host, pages and web archives a browser
        // shows, and the rest of the family of types already listed.
        "pyz", "pyzw", "pyc", "pyo", "jnlp", "wsb", "searchconnector-ms", "htm", "html", "xhtml", "xht",
        "shtml", "svg", "svgz", "mht", "mhtml", "msixbundle", "appxbundle", "cer", "crt", "der", "p7b",
        "ins", "isp", "shb", "shs", "vb", "vbp", "ade", "adp", "mdb", "mda", "mdz",
    ];
    let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str()) else { return false };
    let ext = ext.to_ascii_lowercase();
    RISKY.contains(&ext.as_str()) || windows_rates_dangerous(&ext)
}

/// Windows' own answer for a file type: its built-in list of dangerous types, plus any type
/// registered as always unsafe (`FTA_AlwaysUnsafe`) and the policy's own (SNA2).
#[cfg(windows)]
fn windows_rates_dangerous(ext: &str) -> bool {
    let wide: Vec<u16> = format!(".{ext}").encode_utf16().chain(Some(0)).collect();
    // SAFETY: a NUL-ended UTF-16 string that lives across the call.
    unsafe { windows_sys::Win32::UI::Shell::AssocIsDangerous(wide.as_ptr()) != 0 }
}
#[cfg(not(windows))]
fn windows_rates_dangerous(_ext: &str) -> bool {
    false
}

/// The shell resolves `foo.` and `foo ` to `foo`: opening such a name would open another file.
fn shell_safe(path: &str) -> Result<()> {
    for c in Path::new(path).components() {
        if let Component::Normal(n) = c {
            let n = n.to_string_lossy();
            if n.ends_with('.') || n.ends_with(' ') {
                return Err(AppError::Msg(format!(
                    "{n:?} ends in a dot or a space, which Windows would take for {:?}; rename it first",
                    n.trim_end_matches(['.', ' '])
                )));
            }
        }
    }
    Ok(())
}

/// Open with the default app. Executable types are revealed in Explorer instead.
/// Returns true when opened, false when only revealed.
pub fn local_open(state: &Core, path: String) -> Result<bool> {
    shell_safe(&path)?;
    if runs_code(&path) {
        state.host.reveal(&path)?;
        return Ok(false);
    }
    state.host.open_path(&path, None)?;
    Ok(true)
}

pub fn local_reveal(state: &Core, path: String) -> Result<()> {
    shell_safe(&path)?;
    state.host.reveal(&path)
}

// ---------- transfers ----------

fn make_ctx(
    state: &Core,
    session: &str,
    id: &str,
    direction: &'static str,
    policy: Policy,
) -> Ctx {
    let cancel = {
        let mut transfers = state.transfers.lock().unwrap();
        let flag = transfers
            .get(id)
            .map(|(_, f)| f.clone())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        transfers.insert(id.to_string(), (session.to_string(), flag.clone()));
        flag
    };

    // (last emit, current file, last done for that file, bytes moved overall)
    let track = Mutex::new((Instant::now() - Duration::from_secs(1), String::new(), 0u64, 0u64));
    let emit_host = state.host.clone();
    let emit_id = id.to_string();
    let report = Arc::new(move |file: &str, done: u64, total: Option<u64>| {
        let finished = total.map(|t| done >= t).unwrap_or(false);
        let mut t = track.lock().unwrap();
        // Every file starts with a report at its offset (or at its full size when
        // skipped), so only growth within a file counts as bytes moved.
        if t.1 != file {
            t.1 = file.to_string();
            t.2 = done;
        } else if done > t.2 {
            t.3 += done - t.2;
            t.2 = done;
        }
        if !finished && t.0.elapsed() < Duration::from_millis(80) {
            return;
        }
        t.0 = Instant::now();
        emit_host.emit(Event::Progress(Progress {
            id: emit_id.clone(),
            file: file.to_string(),
            transferred: done,
            total,
            moved: t.3,
        }));
    });

    // Conflict prompts: emit an event, park on a oneshot until the UI answers.
    let (ask_host, ask_conflicts) = (state.host.clone(), state.conflicts.clone());
    let ask_cancel = cancel.clone();
    let ask: crate::protocol::AskFn = Arc::new(move |c: Conflict| {
        let (host, parked) = (ask_host.clone(), ask_conflicts.clone());
        let cancel = ask_cancel.clone();
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            {
                let mut conflicts = parked.lock().unwrap();
                // A cancel that landed before this prompt was registered must still win.
                if cancel.load(Ordering::Relaxed) {
                    return Decision { action: Action::Cancel, all: false };
                }
                conflicts.insert(c.id.clone(), tx);
            }
            host.emit(Event::Conflict(c));
            rx.await.unwrap_or(Decision {
                action: Action::Cancel,
                all: false,
            })
        })
    });

    Ctx {
        id: id.to_string(),
        direction,
        cancel,
        report,
        policy: Arc::new(Mutex::new(policy)),
        ask,
        conflict_seq: Arc::new(AtomicU32::new(0)),
        done: Arc::new(Mutex::new(std::collections::HashSet::new())),
        inflight: Arc::new(Mutex::new(None)),
        skipped: Arc::new(Mutex::new(Vec::new())),
        source: Arc::new(Mutex::new(None)),
        answers: Arc::new(Mutex::new(HashMap::new())),
        created: Arc::new(Mutex::new(std::collections::HashSet::new())),
        walked: Arc::new(Tally::default()),
        host_url: state.session(session).ok().and_then(|s| crate::protocol::host_url(&s.site)).unwrap_or_default(),
        part: Default::default(),
    }
}

/// Run one transfer. Emits `transfer-progress` and `transfer-conflict` events.
/// `direction` is "download" (src = remote, dst = local) or "upload" (src = local, dst = remote).
// One argument per field of the app's transfer request (backend.rs hands them through as is).
#[allow(clippy::too_many_arguments)]
pub async fn transfer(
    state: &Core,
    session: String,
    id: String,
    direction: String,
    src: String,
    dst: String,
    is_dir: bool,
    policy: Policy,
) -> Result<()> {
    let dir: &'static str = if direction == "download" { "download" } else { "upload" };
    let precheck = (|| {
        let sess = state.session(&session)?;
        if dir == "download" {
            let p = Path::new(&dst);
            if p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(AppError::Msg("Refusing a destination path that contains '..'".into()));
            }
            let leaf = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !safe_name(leaf) {
                return Err(AppError::Msg(format!("{leaf:?} is not a name this computer can store")));
            }
        }
        Ok(sess)
    })();
    let sess = match precheck {
        Ok(s) => s,
        Err(e) => {
            // Drop a pre-set cancel flag that would otherwise sit there forever.
            state.transfers.lock().unwrap().remove(&id);
            return Err(e);
        }
    };
    let mut ctx = make_ctx(state, &session, &id, dir, policy);

    // The local side goes through its verbatim path, so a name ending in a dot or a space
    // is that file and not its trimmed sibling.
    let run = |remote: Arc<Remote>, ctx: Ctx, src: String, dst: String| async move {
        if dir == "download" {
            remote.download(&src, &verbatim(&dst), is_dir, None, &ctx).await
        } else {
            let local = verbatim(&src);
            let local_is_dir = tokio::fs::metadata(&local)
                .await
                .map(|m| m.is_dir())
                .unwrap_or(is_dir);
            remote.upload(&local, &dst, local_is_dir, None, &ctx).await
        }
    };

    // A save of an edit copy is an upload of it, in its session, to the file it was opened from;
    // sent anywhere else it is a plain upload, and the copy still holds what that file never got.
    let edit_of = |c: &EditCopy| dir == "upload" && c.session == session && c.remote == dst;
    // A save: what the copy holds as it starts, recorded as what the server has once it lands
    // (a change made during the upload then still counts as unsent).
    let edit_sig = if state.copies.lock().unwrap().get(&src).is_some_and(edit_of) { sig_of(Path::new(&src)) } else { None };
    // And the server's file as last seen: one that changed since (someone else saved it) is
    // asked about like any other overwrite, never replaced unasked (FEA2).
    let edit_was = state.copies.lock().unwrap().get(&src).filter(|c| edit_of(c)).map(|c| c.server);
    let mut edit_now = Server::Unknown;
    // An edit save's question has no Resume: my copy's tail behind their head would be neither
    // version, and it would count as sent. A Resume answer for one is taken as Overwrite (RVA4).
    if edit_was.is_some() {
        let ask = ctx.ask.clone();
        ctx.ask = Arc::new(move |c: Conflict| {
            let asked = ask(c);
            Box::pin(async move {
                let mut d = asked.await;
                if matches!(d.action, Action::Resume) {
                    d.action = Action::Overwrite;
                }
                d
            })
        });
    }
    let writing_key = format!("{session}|{dst}");
    if dir == "upload" {
        state.uploading.lock().unwrap().insert(src.clone());
        state.writing.lock().unwrap().push(writing_key.clone());
    }
    let result = async {
        // The lease is the only standing reference to the link besides its slot: the
        // pool's "nobody else is on it" check counts on exactly those two.
        let mut lease = sess.lease().await?;
        // Nothing to compare with (the last look failed): the save goes up as before FEA2, and
        // the look after it is the next reading (RVA6).
        if let Some(Server::Seen(was)) = edit_was {
            match server_look(&sess, &mut lease, &dst).await? {
                Server::Seen(now) if now != was => {
                    log::warn!(target: "vibeftp", "{dst} changed on the server since it was opened for editing; asking before the save replaces it");
                    *ctx.policy.lock().unwrap() = Policy::Ask;
                }
                Server::Seen(_) => {}
                Server::Unknown => {
                    log::warn!(target: "vibeftp", "{dst}: the server would not say whether it changed since it was opened for editing; the save goes up")
                }
            }
        }
        let mut idle_retries = 0;
        let sent_now = || ctx.inflight.lock().unwrap().as_ref().map(|i| (i.1, i.2)).unwrap_or((0, false));
        loop {
            let before = (ctx.done.lock().unwrap().len(), sent_now().0);
            match run(lease.remote.clone(), ctx.clone(), src.clone(), dst.clone()).await {
                Err(e) if e.is_connection_error() && !ctx.cancelled() => {
                    // Keep going while files complete or the in-flight file grows between
                    // drops; give up after a few attempts that made no progress at all. A
                    // download started over from zero is no progress, however far it got (RVA1).
                    let ((sent, restarted), done) = (sent_now(), ctx.done.lock().unwrap().len());
                    let progressed = done > before.0 || (sent > before.1 && !(dir == "download" && restarted));
                    if progressed {
                        idle_retries = 0;
                    } else {
                        idle_retries += 1;
                    }
                    if idle_retries > 2 {
                        return Err(e);
                    }
                    log::warn!(target: "vibeftp", "Transfer {} hit a dead link ({}), retrying", id, e);
                    // The ctx remembers what finished and what was mid-flight, so the
                    // rerun skips the former and resumes the latter under the same policy.
                    redial(&sess, &mut lease).await?;
                }
                other => {
                    // An FTP cancel mid-file closes its link without a goodbye: the next user
                    // redials it rather than finding it dead (and taking the other links for
                    // dead too). A cancel at a prompt or while waiting leaves the link alone.
                    if lease.remote.is_dead() {
                        lease.mark_stale();
                    }
                    // A failed look keeps comparing: `Unknown` takes the next good reading.
                    if other.is_ok() && edit_was.is_some() {
                        edit_now = server_look(&sess, &mut lease, &dst).await.unwrap_or(Server::Unknown);
                    }
                    return other;
                }
            }
        }
    }
    .await;

    if dir == "upload" {
        state.uploading.lock().unwrap().remove(&src);
        let mut w = state.writing.lock().unwrap();
        if let Some(i) = w.iter().position(|k| *k == writing_key) {
            w.remove(i);
        }
    }
    // Skipped at the question (or left out): the server kept its file, so the copy still holds
    // saves it never got, and is kept as such.
    let kept_theirs = *ctx.policy.lock().unwrap() == Policy::Skip
        || ctx.answers.lock().unwrap().get(&dst) == Some(&Policy::Skip)
        || !ctx.skipped.lock().unwrap().is_empty();
    if let (Some(sig), Ok(()), false) = (edit_sig, &result, kept_theirs) {
        if let Some(c) = state.copies.lock().unwrap().get_mut(&src) {
            c.sig = Some(sig);
            c.server = edit_now;
        }
        // Watching stopped while this save was queued: the copy has done its job.
        discard_copy(state, &session, &src);
    }
    state.transfers.lock().unwrap().remove(&id);
    // What was left out, with why, also when the transfer ended in an error (the user needs
    // to know what an aborted tree had already given up on); a cancel says enough itself.
    let skipped = ctx.skipped.lock().unwrap().clone();
    if !skipped.is_empty() && !matches!(result, Err(AppError::Cancelled)) {
        let (names, reasons) = skipped.into_iter().unzip();
        state.host.emit(Event::Skipped(Skipped { id: id.clone(), names, reasons }));
    }
    result
}

pub fn cancel_transfer(state: &Core, id: String) {
    {
        let mut transfers = state.transfers.lock().unwrap();
        match transfers.get(&id) {
            Some((_, flag)) => flag.store(true, Ordering::Relaxed),
            // Not registered yet: leave a pre-set flag for make_ctx to pick up.
            // Ids embed a millisecond timestamp, so stale pre-sets can be aged out here.
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                transfers.retain(|k, (sess, _)| {
                    if !sess.is_empty() {
                        return true;
                    }
                    let born: u64 = k.split('-').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    now.saturating_sub(born) < 60_000
                });
                transfers.insert(id.clone(), (String::new(), Arc::new(AtomicBool::new(true))));
            }
        }
    }
    // A transfer parked on a conflict prompt wakes up with Cancel when its sender is dropped.
    let prefix = format!("{id}-c");
    state
        .conflicts
        .lock()
        .unwrap()
        .retain(|k, _| !k.starts_with(&prefix));
}

pub fn resolve_conflict(state: &Core, id: String, action: Action, all: bool) {
    if let Some(tx) = state.conflicts.lock().unwrap().remove(&id) {
        let _ = tx.send(Decision { action, all });
    }
}

// ---------- edit in external app ----------

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Where edit copies live: the app's own per-user folder (owner-only on a stock profile, and
/// removed with the app's data), not the shared temp folder. Public for the quit question,
/// which says where kept copies stay (RVA6-2); reading it changes nothing.
pub fn edit_root(state: &Core) -> PathBuf {
    state.paths.local_data.join("edit")
}

/// Download a remote file to a private folder, open it with the default app and
/// watch it. Every save emits `edit-changed`; the UI queues the upload.
/// `id`: the transfer id the download runs under (`cancel_transfer` stops it).
/// `discard`: replace a copy holding changes that never reached the server (the user agreed);
/// without it such a copy is refused with `UnsentEdits`.
pub async fn edit_open(
    state: &Core,
    session: String,
    path: String,
    id: String,
    discard: bool,
) -> Result<String> {
    let sess = state.session(&session)?;
    let (_, name) = split_remote(&path);
    if !safe_name(&name) {
        return Err(AppError::Msg(format!("{name:?} is not a name this computer can store")));
    }
    // One folder per session and remote file: the same path on another account, port or
    // connection, or README.txt next to Readme.txt (one and the same file to Windows), must
    // never land in a copy some editor still has open.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    let dir = edit_root(state)
        .join(sanitize(&sess.site.host))
        .join(sanitize(&session))
        .join(format!("{:016x}", h.finish()));
    tokio::fs::create_dir_all(&dir).await?;
    // Held until the process ends: no other window's sweep takes this live session (RVA5-1).
    if let Some(session_dir) = dir.parent() {
        hold_session(state, session_dir);
    }
    let local = dir.join(&name);
    if local.parent() != Some(dir.as_path()) {
        return Err(AppError::Msg("Refusing to write outside the edit folder".into()));
    }
    // The copy's name, written down for the sweeps (RVA3-1).
    write_marker(&dir, &name);
    let key = format!("{session}|{}", local.to_string_lossy());
    // The queue writing this file (or a folder above it) right now: the copy would be the
    // half-written file, and its first save would replace the finished upload.
    {
        let mine = format!("{session}|");
        let w = state.writing.lock().unwrap();
        let busy = w.iter().filter_map(|k| k.strip_prefix(&mine)).any(|dst| {
            path == dst || path.starts_with(&format!("{}/", dst.trim_end_matches('/')))
        });
        if busy {
            return Err(AppError::Msg(format!("{name} is being uploaded right now; open it when that finishes")));
        }
    }
    // A save of this copy that is still queued or uploading reads the file when it starts:
    // downloading the server's version over it would send the old text up as the save.
    {
        let local_s = local.to_string_lossy().to_string();
        let up = state.uploading.lock().unwrap();
        if up.iter().any(|s| *s == local_s || local_s.starts_with(&format!("{s}\\")) || local_s.starts_with(&format!("{s}/"))) {
            return Err(AppError::Msg(format!("{name} is still being uploaded; open it again when that finishes")));
        }
    }
    // A second open of the same file while the first is still downloading would race its
    // watcher (a half-written copy would go up as a "save"): one at a time.
    if !state.opening.lock().unwrap().insert(key.clone()) {
        return Err(AppError::Msg(format!("{name} is already being opened")));
    }
    let r = edit_open_run(state, &sess, &session, &path, &local, &name, &key, &id, discard).await;
    state.opening.lock().unwrap().remove(&key);
    r
}

#[allow(clippy::too_many_arguments)]
async fn edit_open_run(
    state: &Core,
    sess: &Arc<Session>,
    session: &str,
    path: &str,
    local: &Path,
    name: &str,
    key: &str,
    id: &str,
    discard: bool,
) -> Result<String> {
    let local_str = local.to_string_lossy().to_string();
    // Reopening a file already being edited: silence its watcher first, or the
    // re-download looks like a save and a half-written copy goes up. Its key stays in the
    // map: a "Stop watching" meanwhile removes it, and then nothing is put back.
    let had_watcher = state.edits.lock().unwrap().get(key).map(|w| w.halt());
    let rewatch = || {
        let mut edits = state.edits.lock().unwrap();
        if edits.contains_key(key) && state.sessions.lock().unwrap().contains_key(session) {
            let w = spawn_watcher(state.host.clone(), session.to_string(), path.to_string(), local.to_path_buf(), name.to_string());
            if let Some(old) = edits.insert(key.to_string(), w) {
                old.handle.abort();
            }
        }
    };

    if had_watcher == Some(true) {
        // A save the watcher had seen but not announced yet: announce it now (the editing row
        // is still there, so it is queued), and show the editor its copy again instead of
        // replacing it with the server's older text.
        state.host.emit(Event::EditChanged(EditChanged {
            session: session.to_string(),
            remote: path.to_string(),
            local: local_str.clone(),
            name: name.to_string(),
        }));
        // The mark goes on before the new watcher takes its baseline: writing the stream moves
        // the file's modified time, which a watcher started first would take for a save (APA1).
        mark_copy(&local_str, &sess.site);
        rewatch();
        open_in_editor(state, &local_str)?;
        return Ok(local_str);
    }
    // Bytes the server never got (a failed or cancelled save, edits after watching stopped)
    // are only replaced when the user said so.
    let unsent = local.exists() && state.copies.lock().unwrap().get(&local_str).is_none_or(|c| c.sig != sig_of(local));
    if unsent && !discard {
        if had_watcher.is_some() {
            rewatch();
        }
        return Err(AppError::UnsentEdits(name.to_string()));
    }

    // Into a part file, swapped in only once complete: a download that fails half-way must
    // not cut the copy the editor has (its next save would upload the cut copy).
    let part = part_of(local);
    let ctx = make_ctx(state, session, id, "download", Policy::Overwrite);
    let r = edit_download(sess, path, &part, &ctx).await;
    state.transfers.lock().unwrap().remove(id);
    let r = r.and_then(|server| crate::protocol::swap_in(&part, local, name).map(|()| server));
    let server = match r {
        Ok(server) => server,
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            // The editor may still be open on the previous copy, untouched: put its watcher back,
            // unless the session went away meanwhile (its watchers were just torn down on purpose).
            if had_watcher.is_some() && local.exists() {
                rewatch();
            }
            return Err(e);
        }
    };
    // Marked before the copy's signature and the watcher's baseline are taken (APA1).
    mark_copy(&local_str, &sess.site);
    state.copies.lock().unwrap().insert(
        local_str.clone(),
        EditCopy { session: session.to_string(), remote: path.to_string(), sig: sig_of(local), server },
    );

    // The copy is complete: watch it before handing it to an editor, so a refused or
    // cancelled "open with" cannot leave a row that says "watching" with nothing behind it.
    let watch = spawn_watcher(state.host.clone(), session.to_string(), path.to_string(), local.to_path_buf(), name.to_string());
    let gone = {
        let mut edits = state.edits.lock().unwrap();
        if let Some(old) = edits.insert(key.to_string(), watch) {
            old.handle.abort();
        }
        let gone = state.sessions.lock().unwrap().get(session).is_none();
        if gone {
            // Disconnected while we were downloading: don't leave a watcher behind.
            if let Some(w) = edits.remove(key) {
                w.handle.abort();
            }
        }
        gone
    };
    if gone {
        state.opening.lock().unwrap().remove(key);
        discard_copy(state, session, &local_str);
        return Err(AppError::NotConnected);
    }

    if let Err(e) = open_in_editor(state, &local_str) {
        if had_watcher.is_none() {
            // No editor ever had this copy: a watcher without a row would upload unseen.
            if let Some(w) = state.edits.lock().unwrap().remove(key) {
                w.handle.abort();
            }
            state.opening.lock().unwrap().remove(key);
            discard_copy(state, session, &local_str);
        }
        return Err(e);
    }
    Ok(local_str)
}

/// The edit download, on a transfer link like any download (the browse link stays free, and
/// `cancel_transfer` reaches it), with one reconnect. Returns the server's file as read before
/// the download (`server_look`): a change in between then reads as a change at the first save.
async fn edit_download(sess: &Arc<Session>, path: &str, part: &Path, ctx: &Ctx) -> Result<Server> {
    let mut lease = sess.lease().await?;
    let server = server_look(sess, &mut lease, path).await?;
    let mut retried = false;
    loop {
        let _ = tokio::fs::remove_file(part).await;
        match lease.remote.download_file(path, part, 0, None, true, Default::default(), ctx).await {
            Err(e) if e.is_connection_error() && !ctx.cancelled() && !retried => {
                retried = true;
                lease.remote = sess.redial(lease.idx, &lease.remote).await?;
            }
            Err(AppError::Cancelled) => {
                if lease.remote.is_dead() {
                    lease.mark_stale(); // the FTP cancel closed the link
                }
                return Err(AppError::Cancelled);
            }
            other => return other.map(|()| server),
        }
    }
}

/// Every copy handed to an app carries the Mark of the Web, written again before the hand-off
/// (an editor's save may have replaced the file without it), so SmartScreen and Office Protected
/// View treat it as from the internet (SNA2). Writing the stream moves the file's modified time,
/// so it is written before the copy's signature and its watcher's baseline are taken, never after:
/// a watcher started first saw the mark as a save and uploaded every opened file back (APA1).
fn mark_copy(local: &str, site: &Site) {
    crate::protocol::mark_downloaded(Path::new(local), crate::protocol::host_url(site).as_deref().unwrap_or(""));
}

/// Hand a marked copy (`mark_copy`) to its app.
fn open_in_editor(state: &Core, local: &str) -> Result<()> {
    if runs_code(local) {
        // ShellExecute would *run* a .js/.bat/.ps1; editing them is a core FTP job,
        // so hand them to a text editor explicitly.
        state
            .host
            .open_path(local, Some("notepad.exe"))
            .or_else(|_| state.host.reveal(local))
    } else {
        state.host.open_path(local, None)
    }
}

/// Poll a local copy and announce saves (two identical polls after a change).
fn spawn_watcher(
    watch_host: Arc<dyn Host>,
    watch_session: String,
    watch_remote: String,
    watch_local: PathBuf,
    watch_name: String,
) -> Watch {
    let state = Arc::new(Mutex::new(WatchState { last: sig_of(&watch_local), stopped: false }));
    let shared = state.clone();
    let local = watch_local.clone();
    let handle = tokio::spawn(async move {
        let sig = |m: &std::fs::Metadata| (m.len(), m.modified().map(millis).unwrap_or(0));
        let mut pending: Option<Sig> = None;
        loop {
            tokio::time::sleep(Duration::from_millis(700)).await;
            let now = match tokio::fs::metadata(&watch_local).await {
                Ok(m) => sig(&m),
                Err(_) => continue,
            };
            let mut st = shared.lock().unwrap();
            if st.stopped {
                return;
            }
            if Some(now) == st.last {
                pending = None;
                continue;
            }
            // Wait until the file stops changing (editors write in bursts).
            if pending == Some(now) {
                // Recorded and announced under the lock, so a Stop sees either neither or both.
                st.last = Some(now);
                pending = None;
                watch_host.emit(Event::EditChanged(EditChanged {
                    session: watch_session.clone(),
                    remote: watch_remote.clone(),
                    local: watch_local.to_string_lossy().to_string(),
                    name: watch_name.clone(),
                }));
            } else {
                pending = Some(now);
            }
        }
    });
    Watch { handle, state, local }
}

/// Stop watching an edit copy. Returns true when it holds bytes newer than the last save the
/// watcher announced (every announced save was queued by the UI, also one whose event arrives
/// while this call runs): the caller queues them, or has a running save of the copy sent
/// again. Otherwise the copy is deleted once the server has its bytes (now, or when a queued
/// save of it lands).
pub fn edit_stop(state: &Core, session: String, local: String) -> bool {
    let key = format!("{session}|{local}");
    let Some(w) = state.edits.lock().unwrap().remove(&key) else {
        return false;
    };
    let unsent = w.halt();
    if !unsent {
        discard_copy(state, &session, &local);
    }
    unsent
}

fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}
