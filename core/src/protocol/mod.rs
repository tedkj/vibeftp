pub mod ftp;
pub mod sftp;

use crate::error::{AppError, Result};
use crate::types::{join_remote, millis, split_remote, Action, Conflict, Decision, Entry, Policy, Site};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub type AskFn =
    Arc<dyn Fn(Conflict) -> Pin<Box<dyn Future<Output = Decision> + Send>> + Send + Sync>;

/// The progress sink: (path, bytes done, total when known).
pub type ReportFn = Arc<dyn Fn(&str, u64, Option<u64>) + Send + Sync>;

/// Per-transfer context: cancellation, progress sink, overwrite policy and
/// the callback that asks the user when the policy is `Ask`.
#[derive(Clone)]
pub struct Ctx {
    pub id: String,
    pub direction: &'static str,
    pub cancel: Arc<AtomicBool>,
    pub report: ReportFn,
    pub policy: Arc<Mutex<Policy>>,
    pub ask: AskFn,
    pub conflict_seq: Arc<AtomicU32>,
    /// Destinations fully transferred so far (skipped on a retry after a reconnect).
    pub done: Arc<Mutex<HashSet<String>>>,
    /// Destination being written when a retry started: (key, bytes sent so far, restart).
    /// `restart` is set when the attempt replaced an existing destination from zero: on an
    /// upload, a server that keeps the old file until completion makes resuming unsafe, so
    /// such a file is sent again from the start; on a download, the attempt started over what
    /// an earlier one had landed, so its bytes are no progress (review RVA1).
    pub inflight: Arc<Mutex<Option<(String, u64, bool)>>>,
    /// (path, reason) of what could not be transferred and was left out (reported at the end).
    pub skipped: Arc<Mutex<Vec<(String, String)>>>,
    /// (size, mtime) of the source the in-flight file was read from: the local file of an
    /// upload, the server's file of a download (0 = unknown). A retry after a reconnect must
    /// not continue a different file.
    pub source: Arc<Mutex<Option<(u64, u64)>>>,
    /// Single-file answers to conflict prompts, by destination key: a rerun after a dropped
    /// link (an FTP server may close the idle control link while the dialog is open) applies
    /// them instead of asking again.
    pub answers: Arc<Mutex<HashMap<String, Policy>>>,
    /// Remote folders this transfer made and then trusted as empty: a rerun after a drop
    /// finds them existing and must still know they were its own.
    pub created: Arc<Mutex<HashSet<String>>>,
    /// What this transfer's folder walk has listed so far: a rerun after a dropped link goes on
    /// counting from it, so the whole transfer is held to `WALK_BOUNDS` (RF1-1).
    pub walked: Arc<Tally>,
    /// The server's address the Mark of the Web of every file this transfer downloads names
    /// (`host_url`; empty: none, the mark then says only where it came from by zone).
    pub host_url: String,
    /// The part file of an overwrite whose link died, kept for the rerun to continue
    /// (`Remote::download_over`). It goes with the transfer: the last clone of this context
    /// dropped drops it, and so removes it (review RVA1, RVA7).
    pub part: Arc<Mutex<Option<PartFile>>>,
}

impl Ctx {

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn check(&self) -> Result<()> {
        if self.cancelled() {
            Err(AppError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn skip(&self, name: &str, why: &str) {
        let name = display_path(name);
        log::warn!(target: "vibeftp", "Skipping {name}: {why}");
        let mut s = self.skipped.lock().unwrap();
        if !s.iter().any(|(x, _)| *x == name) {
            s.push((name, why.to_string()));
        }
    }

    /// A file skipped by an earlier attempt that a rerun has now delivered is no longer left out.
    fn unskip(&self, names: &[&str]) {
        let names: Vec<String> = names.iter().map(|n| display_path(n)).collect();
        self.skipped.lock().unwrap().retain(|(x, _)| !names.contains(x));
    }

    /// A child that failed and is left out must not stay "in flight": a rerun would take it
    /// for an interrupted transfer to continue.
    fn forget_inflight(&self, key: &str) {
        let mut i = self.inflight.lock().unwrap();
        if i.as_ref().is_some_and(|(k, _, _)| k == key) {
            *i = None;
            drop(i);
            *self.source.lock().unwrap() = None;
        }
    }

    /// (bytes sent, must restart) for `key` if it was the file in flight when a retry started.
    pub fn sent_to(&self, key: &str) -> Option<(u64, bool)> {
        self.inflight
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(k, _, _)| k == key)
            .map(|(_, n, r)| (*n, *r))
    }

    /// A download starts writing `key` at `offset`: from here on a rerun continues it. Started
    /// from zero over bytes an earlier attempt had landed in it, it is a restart (review RVA1).
    pub(crate) fn begin(&self, key: String, offset: u64) {
        let mut i = self.inflight.lock().unwrap();
        let restart = offset == 0 && i.as_ref().is_some_and(|(k, n, _)| *k == key && *n > 0);
        *i = Some((key, offset, restart));
    }

    /// The part file kept for `path` by an attempt whose link died. One kept for another file
    /// stays where it is: it goes with the transfer, or is continued when its own file comes
    /// (review RVA2-2).
    fn take_part(&self, path: &Path) -> Option<PartFile> {
        let mut kept = self.part.lock().unwrap();
        if kept.as_ref().is_some_and(|p| p.path == path) { kept.take() } else { None }
    }

    /// Note that the in-flight destination replaced an existing file from zero.
    pub fn mark_restart(&self) {
        if let Some(i) = self.inflight.lock().unwrap().as_mut() {
            i.2 = true;
        }
    }

    /// Record progress on the in-flight destination (cheap: one lock per chunk).
    pub fn progress(&self, done: u64) {
        if let Some(i) = self.inflight.lock().unwrap().as_mut() {
            i.1 = done;
        }
    }

    /// The policy for `key`: the transfer's, or the answer already given for this file.
    fn effective(&self, key: &str) -> Policy {
        let policy = *self.policy.lock().unwrap();
        match (policy, self.answers.lock().unwrap().get(key)) {
            (Policy::Ask, Some(p)) => *p,
            _ => policy,
        }
    }

    /// Ask the user about `remote` and remember the answer (for this file, or for all).
    async fn ask_user(&self, key: &str, remote: &str, src: (u64, u64), dst: (u64, u64)) -> Result<Policy> {
        let n = self.conflict_seq.fetch_add(1, Ordering::Relaxed);
        let d = (self.ask)(Conflict {
            id: format!("{}-c{}", self.id, n),
            transfer: self.id.clone(),
            direction: self.direction.to_string(),
            name: split_remote(remote).1,
            path: remote.to_string(),
            src_size: src.0,
            dst_size: dst.0,
            src_modified: src.1,
            dst_modified: dst.1,
        })
        .await;
        let policy = match d.action {
            Action::Overwrite => Policy::Overwrite,
            Action::Resume => Policy::Resume,
            Action::Skip => Policy::Skip,
            Action::Cancel => {
                self.cancel.store(true, Ordering::Relaxed);
                return Err(AppError::Cancelled);
            }
        };
        if d.all {
            *self.policy.lock().unwrap() = policy;
        } else {
            self.answers.lock().unwrap().insert(key.to_string(), policy);
        }
        Ok(policy)
    }

    /// Decide what to do about an existing destination (`key`: its done/inflight key,
    /// `remote`: the server path the prompt names).
    /// Returns `None` to skip, or `Some(offset)` to transfer from that offset.
    async fn resolve(
        &self,
        key: &str,
        remote: &str,
        src: (u64, u64),
        dst: (u64, u64),
        force_resume: bool,
        exact: bool,
    ) -> Result<Option<u64>> {
        let forced = (force_resume && exact).then_some(Policy::Resume);
        self.decide(key, remote, src, dst, forced, exact).await
    }

    /// `resolve` under `forced` instead of the policy in force: `Some(Ask)` asks again about a
    /// file whose answer no longer fits it (its source changed since).
    async fn decide(
        &self,
        key: &str,
        remote: &str,
        src: (u64, u64),
        dst: (u64, u64),
        forced: Option<Policy>,
        exact: bool,
    ) -> Result<Option<u64>> {
        let mut policy = forced.unwrap_or_else(|| self.effective(key));
        // A destination with neither a size nor a date (a row this session's own write left in
        // the listing cache, a listing without facts) says nothing a resume could continue or
        // call complete: the user is asked (review R2-5).
        if policy == Policy::Ask || (policy == Policy::Resume && dst == (0, 0)) {
            policy = self.ask_user(key, remote, src, dst).await?;
        }
        Ok(match policy {
            Policy::Overwrite => Some(0),
            Policy::Skip => None,
            // A name that only matches by case is a different file on a case-sensitive
            // server: never splice onto it, send the whole thing.
            Policy::Resume | Policy::Ask if !exact => Some(0),
            // Resume: continue a shorter destination, treat an equal/larger one as done.
            // A source of size 0 (empty, or a server that did not say) is sent whole.
            Policy::Resume | Policy::Ask => {
                if src.0 == 0 {
                    Some(0)
                } else if dst.0 < src.0 {
                    Some(dst.0)
                } else {
                    None
                }
            }
        })
    }
}

pub const CHUNK: usize = 256 * 1024;

/// What one folder listing from a server may hold (IN-VibeFTP-1, -2). Past any bound the
/// listing fails with a reason; it is never shown as complete. `line`: one LIST/MLSD line, or one
/// SFTP name; `bytes`: the FTP data stream, or the SFTP names and long names together.
#[derive(Clone, Copy, Debug)]
pub struct ListBounds {
    pub entries: usize,
    pub bytes: usize,
    pub line: usize,
    pub deadline: std::time::Duration,
}

/// 250,000 rows (Pure-FTPd's default cut is 10,000; a camera dump folder can hold 100,000),
/// 64 MiB, 16 KiB a row (a name is at most 255 UTF-16 units), five minutes.
pub const LIST_BOUNDS: ListBounds =
    ListBounds { entries: 250_000, bytes: 64 << 20, line: 16 * 1024, deadline: std::time::Duration::from_secs(300) };

/// `64 MB`, `16 KB`, `300 bytes`.
fn size_words(n: usize) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{} MB", n >> 20)
    } else if n >= 1 << 10 && n.is_multiple_of(1 << 10) {
        format!("{} KB", n >> 10)
    } else {
        format!("{n} bytes")
    }
}

/// Why a listing past its bounds is not shown.
pub(crate) fn listing_refused(dir: &str, why: &str) -> AppError {
    AppError::Msg(format!("{dir}: the server's listing {why}, so VibeFTP does not show it"))
}

impl ListBounds {
    pub(crate) fn too_many(&self, dir: &str) -> AppError {
        listing_refused(dir, &format!("has more than {} items", self.entries))
    }
    pub(crate) fn too_big(&self, dir: &str) -> AppError {
        listing_refused(dir, &format!("is larger than {}", size_words(self.bytes)))
    }
    pub(crate) fn too_long(&self, dir: &str) -> AppError {
        listing_refused(dir, &format!("has a line longer than {}", size_words(self.line)))
    }
    pub(crate) fn too_slow(&self, dir: &str) -> AppError {
        listing_refused(dir, &format!("took longer than {} s to arrive", self.deadline.as_secs()))
    }
}

/// What one recursive walk over a server's folders may cover in all: a folder download or a
/// recursive delete (RINF-1). `LIST_BOUNDS` holds one listing; a walk keeps one listing open per
/// level below it and remembers rows as it goes, so nesting multiplied the bound. Past any of
/// these the walk stops with a sentence that says what was done and what was not; it is never
/// reported as complete.
#[derive(Clone, Copy, Debug)]
pub struct WalkBounds {
    /// Folders below the one the walk starts in.
    pub depth: usize,
    /// Rows listed, all folders of the walk together.
    pub entries: usize,
    /// What those rows take to hold (each row with its name and path).
    pub bytes: usize,
}

/// 256 folders deep (a local path runs out long before: 32,767 UTF-16 units), a million items,
/// 512 MB of rows. The count is the action's (`Tally`), not one attempt's: a download's reruns
/// after a dropped link and a delete's retry go on from where the last attempt stopped.
pub const WALK_BOUNDS: WalkBounds = WalkBounds { depth: 256, entries: 1_000_000, bytes: 512 << 20 };

/// Which walk a `Walk` counts, for its sentence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WalkOf {
    Download,
    Delete,
}

/// What the walks of one action (a transfer, a delete) have counted so far, all its attempts
/// together (RF1-1, RF1-2): a rerun or a retry starts a new `Walk` on the same `Tally`.
#[derive(Debug, Default)]
pub struct Tally {
    entries: AtomicUsize,
    bytes: AtomicUsize,
    /// Items a delete removed so far inside the folder it was asked to delete.
    removed: AtomicUsize,
}

impl Tally {
    /// Items a delete removed so far, all its attempts together.
    pub fn removed(&self) -> usize {
        self.removed.load(Ordering::SeqCst)
    }
}

/// `e`, and how many items (`n` > 0) a delete removed inside `path` before it.
pub(crate) fn deleted_before(e: impl std::fmt::Display, n: usize, path: &str) -> AppError {
    AppError::Tallied(format!(
        "{e} ({n} item{} inside {path} {} deleted before that; the rest is still on the server)",
        if n == 1 { "" } else { "s" },
        if n == 1 { "was" } else { "were" }
    ))
}

/// One attempt's walk, counted on its action's `Tally` against its `WalkBounds`.
pub(crate) struct Walk<'a> {
    bounds: WalkBounds,
    of: WalkOf,
    /// The folder the walk started at, as its sentences name it.
    root: String,
    tally: &'a Tally,
    /// A bound stopped the walk: every level passes its error up unchanged, none skips it.
    stopped: AtomicBool,
}

impl<'a> Walk<'a> {
    fn new(bounds: WalkBounds, of: WalkOf, root: &str, tally: &'a Tally) -> Walk<'a> {
        Walk { bounds, of, root: root.to_string(), tally, stopped: AtomicBool::new(false) }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    fn removed_one(&self) {
        self.tally.removed.fetch_add(1, Ordering::SeqCst);
    }

    /// The walk is over: why, and what was and was not done. A delete's sentence says its
    /// count itself (`Tallied`).
    fn stop(&self, why: String) -> AppError {
        self.stopped.store(true, Ordering::SeqCst);
        let root = &self.root;
        match self.of {
            WalkOf::Download => AppError::Msg(format!(
                "{root}: the folder on the server {why}, so VibeFTP stopped the download; the files that arrived are kept, the rest was not downloaded"
            )),
            WalkOf::Delete => AppError::Tallied(match self.tally.removed() {
                0 => format!("{root}: the folder on the server {why}, so VibeFTP stopped deleting it; nothing was deleted"),
                n => format!(
                    "{root}: the folder on the server {why}, so VibeFTP stopped deleting it; {n} item{} inside it {} deleted, {root} and the rest of it are still on the server",
                    if n == 1 { "" } else { "s" },
                    if n == 1 { "was" } else { "were" }
                ),
            }),
        }
    }

    /// A folder `depth` levels below the start is about to be listed.
    fn enter(&self, depth: usize) -> Result<()> {
        if depth > self.bounds.depth {
            return Err(self.stop(format!("goes more than {} folders deep", self.bounds.depth)));
        }
        Ok(())
    }

    /// Count a folder's rows against the walk.
    fn take(&self, rows: &[Entry]) -> Result<()> {
        let size: usize = rows.iter().map(|e| std::mem::size_of::<Entry>() + e.name.len() + e.path.len()).sum();
        let entries = self.tally.entries.fetch_add(rows.len(), Ordering::SeqCst) + rows.len();
        let bytes = self.tally.bytes.fetch_add(size, Ordering::SeqCst) + size;
        if entries > self.bounds.entries {
            return Err(self.stop(format!("holds more than {} items", self.bounds.entries)));
        }
        if bytes > self.bounds.bytes {
            return Err(self.stop(format!("lists more than {} of names", size_words(self.bounds.bytes))));
        }
        Ok(())
    }
}

/// What a download's decision was made on, checked again where the write starts.
#[derive(Clone, Copy, Debug, Default)]
pub struct Seen {
    /// (size, modified) of the server's file a resume offset was chosen for (review SOL-FTP-3).
    pub source: Option<(u64, u64)>,
}

/// What an upload knows about its destination's name before the first write (review SOL-FTP-1,
/// R-SOL-1, R2-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fresh {
    /// It may be taken: written as it is (an overwrite, a resume, a replace the user agreed to).
    No,
    /// A listing showed it free, and the listing may be older than another client's upload of
    /// it: the first write makes sure (in every folder, also one this transfer made).
    Listed,
}

/// What the links of one session learn together: FTP's recent folder listings (review
/// R-SOL-1), and whether the SFTP server refuses exclusive creates (R-SOL-5).
#[derive(Clone, Default)]
pub struct Shared {
    recent: ftp::Recent,
    no_excl: Arc<AtomicBool>,
}

impl Shared {
    /// A dropped link came back: what the server was found to refuse is tried again (review R2-7).
    pub fn reconnected(&self) {
        self.no_excl.store(false, Ordering::Relaxed);
    }
}

/// Folder listings taken for one user action over many rows (a delete of a selection, a move
/// of several files): each folder is read once, before its first row is checked, not once per
/// row (review R-SOL-2).
#[derive(Clone, Default)]
pub struct Looks(Arc<Mutex<HashMap<String, Arc<Vec<Entry>>>>>);

impl Looks {
    fn get(&self, dir: &str) -> Option<Arc<Vec<Entry>>> {
        self.0.lock().unwrap().get(dir).cloned()
    }

    fn put(&self, dir: &str, list: Arc<Vec<Entry>>) {
        self.0.lock().unwrap().insert(dir.to_string(), list);
    }

    /// A folder a delete is done with (RINF-1): its listing is let go.
    fn forget(&self, dir: &str) {
        self.0.lock().unwrap().remove(dir);
    }

    /// Whether `other` is this very set (one action's rows share one).
    pub fn same(&self, other: &Looks) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Whether the server's file now (`size` as it says it, `modified` 0 when it would not say) is
/// the one `was` describes: the same size, and the same modified time where that was known.
/// A size it will not give proves nothing. Size and date are all FTP and SFTP have, so a
/// replacement that keeps both passes (HARDENING.md).
fn same_source(was: (u64, u64), size: Option<u64>, modified: u64) -> bool {
    size == Some(was.0) && (was.1 == 0 || modified == was.1)
}

/// `local` is still the file an overwrite was decided on (review SOL-FTP-2): looked at before
/// the download starts and again right before its part file takes the name.
async fn still_seen(local: &Path, seen: &crate::identity::LocalId) -> Result<()> {
    let name = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let changed = || AppError::Msg(format!("{name}: the file on this computer changed since it was compared; nothing was written"));
    match local_id(local).await {
        Ok(now) if seen.same(&now) => Ok(()),
        Ok(_) => Err(changed()),
        Err(AppError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Err(changed()),
        Err(e) => Err(e),
    }
}

/// The part file an overwrite of `local` is downloaded into, beside it (review FEA5). Named by
/// the file's name, case-blind, so a rerun of the same file finds it.
fn part_beside(local: &Path) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    local.file_name().map(|n| case_key(&n.to_string_lossy())).hash(&mut h);
    local.with_file_name(format!(".{:016x}.vibeftp-part", h.finish()))
}

/// Whether `name` is one `part_beside` makes: `.`, 16 lowercase hex digits, `.vibeftp-part`.
fn is_part_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 30
        && b[0] == b'.'
        && b[1..17].iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        && &b[17..] == b".vibeftp-part"
}

/// The part files alive in this process (case-folded paths): the folder sweep leaves them alone.
static LIVE_PARTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// An overwrite's part file (review FEA5). Dropping it removes the file at once, with no await,
/// so a failure, a cancel or a quit that drops the transfer's task all take it; only a part
/// that took the real name is let go without that (RVA7). While it lives it is held open,
/// letting others read and write it but not delete or rename it, so no `sweep_parts` removes it,
/// this process's or another VibeFTP's; the hold goes right before the rename (RVA2-3).
pub struct PartFile {
    path: PathBuf,
    hold: Option<std::fs::File>,
    live: bool,
    /// The server's file (size, modified) its bytes came from, noted when a dead link keeps it,
    /// so a rerun checks the server's file against it whatever ran in between (RVA3-4).
    source: Option<(u64, u64)>,
}

impl PartFile {
    /// A new, empty part at `path` (RVA3-5, RVA3-6): a leftover nobody holds is removed first
    /// (a link as the link itself), then the part is made with `create_new`, which never opens
    /// what is there and never follows a link. A name still taken is refused before anything is
    /// written. What holds it is not known: another VibeFTP window's part shares reading and
    /// writing, as a sync client or a scanner reading a leftover does, so the words say only
    /// that (RVA4-3), with where the part is and what the user can do (RVA5-5); anything else at
    /// that name that cannot be removed gets them too.
    fn new(path: PathBuf, name: &str) -> Result<PartFile> {
        remove_unheld(&path);
        let mut open = std::fs::OpenOptions::new();
        open.read(true).write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x1;
            const FILE_SHARE_WRITE: u32 = 0x2;
            open.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let hold = open.open(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => AppError::Msg(format!(
                "{name}: a part file for this download ({}, in the same folder) is already there and could not be cleared away; another program or another VibeFTP window may be using it. Nothing was written. Try again when that is done, or delete that file.",
                path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
            )),
            _ => AppError::from(e),
        })?;
        LIVE_PARTS.lock().unwrap().push(case_key(&path.to_string_lossy()));
        Ok(PartFile { path, hold: Some(hold), live: true, source: None })
    }

    /// Close the hold: the rename that lets the part take the real name needs it gone.
    fn release(&mut self) {
        self.hold = None;
    }

    /// The part took the real name: nothing is left to remove.
    fn landed(mut self) {
        self.live = false;
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        self.release();
        if self.live {
            let _ = std::fs::remove_file(&self.path);
        }
        let key = case_key(&self.path.to_string_lossy());
        let mut live = LIVE_PARTS.lock().unwrap();
        if let Some(i) = live.iter().position(|k| *k == key) {
            live.swap_remove(i);
        }
    }
}

/// Part files a quit, a crash or a power cut left in `dir` (of exactly `part_beside`'s naming,
/// plain files only, never anything else): removed when a download into that folder starts
/// (review RVA7). One of a transfer still running in this process is left alone, and so is one
/// another program holds open: another VibeFTP's part is held open for as long as it lives
/// (`PartFile`, RVA2-3), up to the instant before its rename.
async fn sweep_parts(dir: &Path) {
    let dir = dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        let Ok(items) = std::fs::read_dir(&dir) else { return };
        for it in items.flatten() {
            let name = it.file_name();
            if !is_part_name(&name.to_string_lossy()) || !it.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let path = it.path();
            if LIVE_PARTS.lock().unwrap().contains(&case_key(&path.to_string_lossy())) {
                continue;
            }
            remove_unheld(&path);
        }
    })
    .await;
}

/// Remove `path` unless something holds it open: opened for nobody else to share, deleted on
/// close, the link itself if it is one.
#[cfg(windows)]
fn remove_unheld(path: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let _ = std::fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path);
}
#[cfg(not(windows))]
fn remove_unheld(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// A whole download in its part file takes the real name (the edit copy's and an overwrite's
/// swap). On an error the part is still there for the caller to remove.
pub(crate) fn swap_in(part: &Path, local: &Path, name: &str) -> Result<()> {
    std::fs::rename(part, local).map_err(|e| match read_only(local) {
        true => AppError::Msg(format!("{name}: the file on this computer is read-only, so the fresh copy could not replace it (clear Read-only in its Properties)")),
        false => AppError::Msg(format!("{name}: the fresh copy could not replace the one on disk ({e}); is another program locking it?")),
    })
}

/// Whether `local` has the read-only attribute.
fn read_only(local: &Path) -> bool {
    std::fs::metadata(local).is_ok_and(|m| m.permissions().readonly())
}

/// `local` can be replaced: opened for writing (nothing truncated, nothing written) before any
/// byte is fetched, so a read-only file, or one a program holds without letting it be written,
/// fails at once instead of after the whole download (review RVA8).
async fn replaceable(local: &Path, name: &str) -> Result<()> {
    match tokio::fs::OpenOptions::new().write(true).open(local).await {
        Ok(_) => Ok(()),
        Err(_) if read_only(local) => Err(AppError::Msg(format!(
            "{name}: the file on this computer is read-only, so it cannot be replaced; nothing was downloaded (clear Read-only in its Properties to replace it)"
        ))),
        Err(e) => Err(AppError::Msg(format!(
            "{name}: the file on this computer cannot be replaced ({e}); is another program using it? Nothing was downloaded"
        ))),
    }
}

/// Server-supplied names become local path components, so they must be plain
/// file names: no separators, no drive prefixes, no `.`/`..`, no Windows device names.
pub fn safe_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.encode_utf16().count() > 255 {
        return false;
    }
    if name.contains('\u{FFFD}') {
        return false; // lossily decoded: the server would not recognise it back
    }
    if name.chars().any(|c| matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || (c as u32) < 32) {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    !is_device(name)
}

/// A name Win32 opens as a device wherever it stands (`nul`, `com1.txt`, `CONIN$`, `lpt¹.log`):
/// the whole reserved set, compared case-blind on the stem before the first dot, trailing spaces
/// dropped as Win32 drops them (`con .txt`). COM0/LPT0 and the superscript digits included
/// (IN-VibeFTP-6; the rule VibeVerify's checksum paths use).
pub fn is_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit())
        || ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str())
}

/// Mark a downloaded file as coming from the internet (the Mark of the Web, as browsers write
/// it), so SmartScreen gets a say if it is ever run and Office opens it in Protected View.
/// `host_url`: the server it came from (`host_url`), or empty. Best effort, Windows only.
#[cfg(windows)]
pub fn mark_downloaded(local: &Path, host_url: &str) {
    let ads = format!("{}:Zone.Identifier", local.to_string_lossy());
    let _ = std::fs::write(ads, zone_identifier(host_url));
}
#[cfg(not(windows))]
pub fn mark_downloaded(_local: &Path, _host_url: &str) {}

/// The Mark of the Web's text: Internet zone, and where the file came from when known.
pub fn zone_identifier(host_url: &str) -> String {
    let mut text = String::from("[ZoneTransfer]\r\nZoneId=3\r\n");
    // A line break would let the address add lines of its own (another ZoneId).
    if !host_url.is_empty() && !host_url.contains(['\r', '\n']) {
        text.push_str(&format!("HostUrl={host_url}\r\n"));
    }
    text
}

/// The server a site's downloads come from, as the Mark of the Web names it:
/// `sftp://host:22/`, never a user name or password. None when the host is not plain address
/// text (letters, digits, `.`, `-`, `_`, an IPv6 address): nothing then goes into the mark that
/// could change its meaning (SNA2).
pub fn host_url(site: &Site) -> Option<String> {
    let scheme = match site.protocol {
        crate::types::Protocol::Ftp => "ftp",
        crate::types::Protocol::Ftps => "ftps",
        crate::types::Protocol::Sftp => "sftp",
    };
    let host = site.host.trim();
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if bare.is_empty() || !bare.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')) {
        return None;
    }
    let host = if bare.contains(':') { format!("[{bare}]") } else { bare.to_string() };
    Some(format!("{scheme}://{host}:{}/", site.port))
}

/// Case-insensitive key the way file systems fold case: one character at a time, so no
/// final-sigma rule (`ΟΔΟΣ` and `οδοσ` are one NTFS file, `οδος` another) and no `ß` -> `ss`.
pub fn case_key(name: &str) -> String {
    name.chars().flat_map(char::to_lowercase).collect()
}

/// Key under which a server may take two names for one file: case folded as above and
/// Unicode-normalised (macOS stores `café` decomposed, Windows sends it composed).
pub fn name_key(name: &str) -> String {
    case_key(&nfc(name))
}

/// True when a server that folds case or Unicode forms would see one file in `a` and `b`.
pub fn same_name(a: &str, b: &str) -> bool {
    a == b || name_key(a) == name_key(b)
}

/// The ASCII (punycode) form of an internationalised host name, `None` when it is ASCII
/// already. std hands the UTF-8 bytes to the resolver as they are, which finds nothing.
#[cfg(windows)]
pub fn ascii_host(host: &str) -> Result<Option<String>> {
    if host.is_ascii() {
        return Ok(None);
    }
    #[link(name = "normaliz")]
    unsafe extern "system" {
        fn IdnToAscii(flags: u32, src: *const u16, src_len: i32, dst: *mut u16, dst_len: i32) -> i32;
    }
    let src: Vec<u16> = host.encode_utf16().collect();
    let mut dst = vec![0u16; 256]; // a DNS name is at most 255 characters
    let n = unsafe { IdnToAscii(0, src.as_ptr(), src.len() as i32, dst.as_mut_ptr(), dst.len() as i32) };
    if n <= 0 {
        return Err(AppError::Msg(format!("{host} is not a valid host name")));
    }
    dst.truncate(n as usize);
    Ok(Some(String::from_utf16_lossy(&dst)))
}
#[cfg(not(windows))]
pub fn ascii_host(_host: &str) -> Result<Option<String>> {
    Ok(None)
}

/// NFC form of a name (Windows' own normaliser; elsewhere names are compared as given).
#[cfg(windows)]
fn nfc(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    if s.is_ascii() {
        return Cow::Borrowed(s);
    }
    #[link(name = "normaliz")]
    unsafe extern "system" {
        fn NormalizeString(form: i32, src: *const u16, src_len: i32, dst: *mut u16, dst_len: i32) -> i32;
    }
    const NORMALIZATION_C: i32 = 1;
    let src: Vec<u16> = s.encode_utf16().collect();
    // NFC never grows a string past three times its length.
    let mut dst = vec![0u16; src.len() * 3 + 8];
    let n = unsafe { NormalizeString(NORMALIZATION_C, src.as_ptr(), src.len() as i32, dst.as_mut_ptr(), dst.len() as i32) };
    if n <= 0 {
        return Cow::Borrowed(s); // not valid Unicode: compare it as given
    }
    dst.truncate(n as usize);
    Cow::Owned(String::from_utf16_lossy(&dst))
}
#[cfg(not(windows))]
fn nfc(s: &str) -> std::borrow::Cow<'_, str> {
    std::borrow::Cow::Borrowed(s)
}

/// A remote folder's listing, looked up by exact name and by `name_key`.
#[derive(Default)]
pub struct Listing {
    exact: HashMap<String, Entry>,
    folded: HashMap<String, String>,
}

impl Listing {
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    pub fn new(entries: Vec<Entry>) -> Self {
        let mut l = Listing::default();
        for e in entries {
            l.folded.entry(name_key(&e.name)).or_insert_with(|| e.name.clone());
            l.exact.insert(e.name.clone(), e);
        }
        l
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.exact.get(name)
    }

    /// An entry spelled differently that a case- or normalisation-folding server takes for `name`.
    pub fn similar(&self, name: &str) -> Option<&Entry> {
        self.folded.get(&name_key(name)).and_then(|n| self.exact.get(n))
    }
}

/// `NAME~N.EXT`: what Windows generates as a file's 8.3 short name. On a Windows-hosted
/// server such a name may open another file that the listing shows under its long name.
fn looks_short(name: &str) -> bool {
    let (stem, ext) = name.split_once('.').unwrap_or((name, ""));
    let Some((head, n)) = stem.rsplit_once('~') else { return false };
    !head.is_empty()
        && head.chars().count() <= 6
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && stem.len() <= 8
        && ext.len() <= 3
        && !ext.contains('.')
}

/// A local path in Win32's verbatim form (`\\?\C:\...`, `\\?\UNC\srv\share\...`), so a name
/// ending in a dot or a space is the file of that name and not its trimmed sibling (Win32
/// strips them from ordinary paths). `.` and `..` are resolved here as Win32 would have;
/// relative, drive-relative and already verbatim paths pass unchanged.
#[cfg(windows)]
pub fn verbatim(p: &str) -> PathBuf {
    use std::path::{Component, Prefix};
    let mut comps = Path::new(p).components().peekable();
    let base = match comps.next() {
        Some(Component::Prefix(pre)) => match pre.kind() {
            Prefix::Disk(d) => format!(r"\\?\{}:\", d as char),
            Prefix::UNC(srv, share) => {
                format!(r"\\?\UNC\{}\{}\", srv.to_string_lossy(), share.to_string_lossy())
            }
            _ => return PathBuf::from(p),
        },
        _ => return PathBuf::from(p),
    };
    match comps.peek() {
        Some(Component::RootDir) => {
            comps.next();
        }
        None if base.starts_with(r"\\?\UNC\") => {}
        _ => return PathBuf::from(p), // C:foo: relative to that drive's current folder
    }
    let mut parts = Vec::new();
    for c in comps {
        match c {
            Component::Normal(n) => parts.push(n),
            Component::ParentDir => {
                parts.pop();
            }
            _ => {}
        }
    }
    let mut out = PathBuf::from(base);
    for n in parts {
        out.push(n);
    }
    out
}
#[cfg(not(windows))]
pub fn verbatim(p: &str) -> PathBuf {
    PathBuf::from(p)
}

/// The ordinary form of a path `verbatim` produced, for anything the user reads.
pub fn display_path(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    match p.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
        _ => p.to_string(),
    }
}

/// The real name of an existing local file or folder when `local` reached it through
/// another one: NTFS also resolves the 8.3 short name (`REPORT~1.TXT` opens
/// `report final.txt`), even through a verbatim path. Links are taken as they are.
#[cfg(windows)]
async fn aliased(local: &Path) -> Option<String> {
    let own = tokio::fs::symlink_metadata(local).await.ok()?;
    if own.file_type().is_symlink() {
        return None;
    }
    let want = local.file_name()?.to_string_lossy().to_string();
    let real = tokio::fs::canonicalize(local).await.ok()?;
    let got = real.file_name()?.to_string_lossy().to_string();
    (case_key(&got) != case_key(&want)).then_some(got)
}
#[cfg(not(windows))]
async fn aliased(_local: &Path) -> Option<String> {
    None
}

/// The identity of the local file a download would write into (off the async threads).
async fn local_id(local: &Path) -> Result<crate::identity::LocalId> {
    let p = local.to_path_buf();
    tokio::task::spawn_blocking(move || crate::identity::of_target(&p))
        .await
        .map_err(|e| AppError::Msg(e.to_string()))?
        .map_err(AppError::from)
}

pub enum Remote {
    Ftp(ftp::FtpConn),
    Sftp(sftp::SftpConn),
}

impl Remote {
    /// Returns (connection, start directory, the server's identity: the SSH host key pin
    /// entry on SFTP, the certificate fingerprint on FTPS). `known_fingerprint` is the pin to
    /// check it against.
    pub async fn connect(
        site: &Site,
        password: &str,
        known_fingerprint: Option<String>,
    ) -> Result<(Self, String, Option<String>)> {
        // Resolvers and TLS take host names in their ASCII (punycode) form.
        let ascii;
        let site = match ascii_host(&site.host)? {
            Some(host) => {
                ascii = Site { host, ..site.clone() };
                &ascii
            }
            None => site,
        };
        match site.protocol {
            crate::types::Protocol::Sftp => {
                let (conn, cwd, fp) =
                    sftp::SftpConn::connect(site, password, known_fingerprint).await?;
                Ok((Remote::Sftp(conn), cwd, Some(fp)))
            }
            _ => {
                let (conn, cwd, fp) = ftp::FtpConn::connect(site, password, known_fingerprint).await?;
                Ok((Remote::Ftp(conn), cwd, fp))
            }
        }
    }

    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        match self {
            Remote::Ftp(c) => c.list(path).await,
            Remote::Sftp(c) => c.list(path).await,
        }
    }

    /// `list` for callers that take a missing name as absent: a listing the server cut
    /// short is an error, not a partial answer.
    pub async fn list_complete(&self, path: &str) -> Result<Vec<Entry>> {
        match self {
            Remote::Ftp(c) => c.list_complete(path).await,
            Remote::Sftp(c) => c.list(path).await,
        }
    }

    pub async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        match self {
            Remote::Ftp(c) => c.stat(path).await,
            Remote::Sftp(c) => c.stat(path).await,
        }
    }

    /// `stat` for a destination about to be written, plus whether the answer is unknown: the
    /// server would not say whether it exists (a drop box that refuses SIZE and listing), which
    /// is never taken for "absent" (review R2-1). `any_case`: an FTP listing fallback may answer
    /// with a name that differs only by case (the same file on a case-folding server); callers
    /// compare `name` to tell.
    async fn stat_checked(&self, remote: &str, any_case: bool) -> Result<(Option<Entry>, bool)> {
        let r = match self {
            Remote::Ftp(c) if any_case => c.stat_any_case(remote).await,
            _ => self.stat(remote).await,
        };
        match r {
            Ok(e) => Ok((e, false)),
            Err(e) if e.is_connection_error() => Err(e),
            Err(e) => {
                log::warn!(target: "vibeftp", "Cannot tell whether {remote} exists ({e})");
                Ok((None, true))
            }
        }
    }

    /// `stat` that, on a case-folding FTP server answering only through its listing, also
    /// reports a name that differs only by case (the same file there).
    pub async fn stat_any_case(&self, path: &str) -> Result<Option<Entry>> {
        match self {
            Remote::Ftp(c) => c.stat_any_case(path).await,
            Remote::Sftp(c) => c.stat(path).await,
        }
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.mkdir(path).await,
            Remote::Sftp(c) => c.mkdir(path).await,
        }
    }

    pub async fn remove_file(&self, path: &str) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.remove_file(path).await,
            Remote::Sftp(c) => c.remove_file(path).await,
        }
    }

    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.remove_dir(path).await,
            Remote::Sftp(c) => c.remove_dir(path).await,
        }
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.rename(from, to).await,
            Remote::Sftp(c) => c.rename(from, to).await,
        }
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.chmod(path, mode).await,
            Remote::Sftp(c) => c.chmod(path, mode).await,
        }
    }

    /// `expected`: the size a listing showed, the length check's fallback when the server
    /// will not say. `fresh`: the destination was absent, so it is created exclusively and an
    /// `AlreadyExists` error means something else took the name meanwhile. `seen`: the server
    /// file a resume offset was chosen for (another one there is `SourceChanged`).
    #[allow(clippy::too_many_arguments)]
    pub async fn download_file(
        &self,
        remote: &str,
        local: &Path,
        offset: u64,
        expected: Option<u64>,
        fresh: bool,
        seen: Seen,
        ctx: &Ctx,
    ) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.download_file(remote, local, offset, expected, fresh, seen, ctx).await,
            Remote::Sftp(c) => c.download_file(remote, local, offset, expected, fresh, seen, ctx).await,
        }
    }

    /// An overwrite of `local`, the file `id` describes (another one there is refused): it is
    /// downloaded into a part file beside it, which takes the name only once the length check
    /// passed and `local` is still that file (review FEA5). `from`: `Some(0)` starts the part
    /// afresh; more continues the part an attempt whose link died left (the caller made the
    /// resume's checks); `None`: that part is whole already. A dead link keeps the part for the
    /// rerun (in `ctx.part`); any other failure, a cancel or a dropped task removes it, and the
    /// old file is untouched (RVA1, RVA7).
    #[allow(clippy::too_many_arguments)]
    async fn download_over(
        &self,
        remote: &str,
        local: &Path,
        id: &crate::identity::LocalId,
        from: Option<u64>,
        expected: Option<u64>,
        seen: Seen,
        ctx: &Ctx,
    ) -> Result<()> {
        let name = split_remote(remote).1;
        still_seen(local, id).await?;
        replaceable(local, &name).await?;
        let path = part_beside(local);
        // This transfer's own kept part, or a new one (RVA3-5).
        let mut part = match ctx.take_part(&path) {
            Some(p) => p,
            None => PartFile::new(path, &name)?,
        };
        let r = match from {
            Some(offset) => self.download_file(remote, &part.path, offset, expected, false, seen, ctx).await,
            None => Ok(()),
        };
        let r = match r {
            Ok(()) => still_seen(local, id).await,
            Err(e) => Err(e),
        };
        // The hold goes right before the rename it would block (RVA2-3).
        match r.and_then(|()| {
            part.release();
            swap_in(&part.path, local, &name)
        }) {
            Ok(()) => {
                part.landed();
                Ok(())
            }
            Err(e) if e.is_connection_error() && !ctx.cancelled() => {
                // Kept only as the file in flight, the one a rerun continues: a part another
                // file kept stays when this one died before it started writing (RVA2-2).
                if ctx.sent_to(&part.path.to_string_lossy()).is_some() {
                    part.source = *ctx.source.lock().unwrap();
                    *ctx.part.lock().unwrap() = Some(part);
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// `fresh`: only a listing says the name is free, so the first write must not replace a
    /// file that took it since (`NameTaken`): SFTP creates exclusively, FTP looks right before
    /// STOR.
    pub async fn upload_file(&self, local: &Path, remote: &str, offset: u64, fresh: Fresh, ctx: &Ctx) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.upload_file(local, remote, offset, fresh, ctx).await,
            Remote::Sftp(c) => c.upload_file(local, remote, offset, fresh, ctx).await,
        }
    }

    /// Let this link learn with the other links of its session (`Shared`). Called before the
    /// link is used.
    pub fn share(&mut self, with: &Shared) {
        match self {
            Remote::Ftp(c) => c.share_listings(&with.recent),
            Remote::Sftp(c) => c.share(&with.no_excl),
        }
    }

    /// The entry at `path` as its folder's listing shows it, so it compares one to one with a
    /// row the user saw: on FTP MLST where the listing is MLSD, else the listing itself (LIST
    /// dates are minutes in the server's zone, MDTM's seconds in UTC), read once per folder for
    /// all the rows of `looks`; stat on SFTP.
    pub async fn listed(&self, path: &str, looks: &Looks) -> Result<Option<Entry>> {
        match self {
            Remote::Ftp(c) => c.listed(path, looks).await,
            Remote::Sftp(c) => c.listed(path).await,
        }
    }

    /// Why what is at `path` now is not the row `seen` the user confirmed, or `None` when it
    /// still is (servers have no stable file ids). The kind first: a folder, a file, a link
    /// (a folder that became a link, or a link that became a folder, is another item; review
    /// R2-4). A folder: the same kind is all, since its date moves whenever its contents change.
    /// A file: the same size (0 is a size like any other; review R2-3) and the same modified
    /// time where both sides know it (0 is "not given"; review R-SOL-7). A server that will not
    /// say is a reason too (review SOL-FTP-2).
    pub async fn changed_since(&self, path: &str, seen: &Entry, looks: &Looks) -> Result<Option<String>> {
        let now = match self.listed(path, looks).await {
            Ok(now) => now,
            Err(e) if e.is_connection_error() => return Err(e),
            Err(e) => return Ok(Some(format!("the server would not say whether it changed since you confirmed ({e})"))),
        };
        let changed = || Some("it changed on the server since you confirmed".to_string());
        Ok(match now {
            None => Some("it is no longer on the server".to_string()),
            Some(n) if n.is_dir != seen.is_dir || n.is_link != seen.is_link => changed(),
            Some(n) if n.is_dir => None,
            Some(n) if n.size != seen.size || (n.modified != 0 && seen.modified != 0 && n.modified != seen.modified) => changed(),
            Some(_) => None,
        })
    }

    /// Cheap liveness probe used after idle periods.
    pub async fn ping(&self) -> Result<()> {
        match self {
            Remote::Ftp(c) => c.noop().await,
            Remote::Sftp(c) => c.ping().await,
        }
    }

    pub async fn disconnect(&self) {
        match self {
            Remote::Ftp(c) => c.disconnect().await,
            Remote::Sftp(c) => c.disconnect().await,
        }
    }

    /// An FTP cancel tore the link down mid-transfer (an SFTP cancel never does).
    pub fn is_dead(&self) -> bool {
        match self {
            Remote::Ftp(c) => c.is_dead(),
            Remote::Sftp(_) => false,
        }
    }

    /// Recursively delete a remote directory. A refusal names the item that blocked it. `looks`:
    /// the action's listings (the delete check's own are reused). The walk is held to
    /// `WALK_BOUNDS` (RINF-1), counted on `tally`: the delete's, kept across its retry (RF1-2).
    /// Only a bound's sentence says the count; `ops::delete_on` adds it to every other error,
    /// once the delete is over (RL5-1). A connection error stays as it is, for the retry.
    pub async fn remove_dir_all(&self, path: &str, looks: &Looks, tally: &Tally) -> Result<()> {
        self.remove_dir_all_in(path, looks, WALK_BOUNDS, tally).await
    }

    pub(crate) async fn remove_dir_all_in(&self, path: &str, looks: &Looks, bounds: WalkBounds, tally: &Tally) -> Result<()> {
        self.remove_tree(path, looks, &Walk::new(bounds, WalkOf::Delete, path, tally), 0).await
    }

    /// One folder of `remove_dir_all`, `depth` levels below where the walk started.
    async fn remove_tree(&self, path: &str, looks: &Looks, walk: &Walk<'_>, depth: usize) -> Result<()> {
        // Connection errors stay as they are: the caller reconnects and tries again.
        let named = |p: &str, e: AppError| {
            if e.is_connection_error() { e } else { AppError::Msg(format!("{p}: {e}")) }
        };
        // What is at `path` now, the way its folder lists it: only a folder is descended into. A
        // link (also one that took a folder's place) goes as the one entry it is, never its
        // target's contents (review R2-4); so does a file; gone is done.
        match self.listed(path, looks).await.map_err(|e| named(path, e))? {
            None => return Ok(()),
            Some(e) if e.is_link || !e.is_dir => {
                self.remove_file(path).await.map_err(|err| named(path, err))?;
                walk.removed_one();
                return Ok(());
            }
            Some(_) => {}
        }
        walk.enter(depth)?;
        // A listing the server cut short is an error here: a delete never takes it for all there is.
        let entries = Arc::new(self.list_complete(path).await.map_err(|e| named(path, e))?);
        walk.take(&entries)?;
        // The children are checked against this listing (no second look on a LIST server), and it
        // is let go once they are done, whatever happened (RINF-1).
        looks.put(path, entries.clone());
        let children = async {
            for e in entries.iter() {
                if e.name.contains('\u{FFFD}') {
                    return Err(AppError::Msg(format!(
                        "{} has a name this client cannot send back to the server (encoding); delete it another way",
                        e.path
                    )));
                }
                if e.is_dir && !e.is_link {
                    Box::pin(self.remove_tree(&e.path, looks, walk, depth + 1)).await?;
                } else {
                    // Plain files and links (even links to directories) are unlinked, never descended.
                    self.remove_file(&e.path).await.map_err(|err| named(&e.path, err))?;
                    walk.removed_one();
                }
            }
            Ok::<(), AppError>(())
        }
        .await;
        looks.forget(path);
        drop(entries);
        children?;
        match self.remove_dir(path).await {
            Ok(()) => {
                if depth > 0 {
                    walk.removed_one();
                }
                Ok(())
            }
            // Everything listed is gone and the folder still will not go: it holds what the
            // listing leaves out (pipes, sockets and devices on SFTP, hidden names on some FTP servers).
            Err(e) if !e.is_connection_error() && self.list_complete(path).await.is_ok_and(|l| l.is_empty()) => Err(AppError::Msg(
                format!("{path}: {e} (it may hold items the server does not list: hidden or special files)"),
            )),
            Err(e) => Err(named(path, e)),
        }
    }

    /// Download a file or a whole directory tree, resolving conflicts via `ctx`.
    /// `src` is the remote entry when already known (saves a stat). A tree is held to
    /// `WALK_BOUNDS` (RINF-1), counted on `ctx.walked`: the transfer's, kept across its reruns
    /// (RF1-1).
    pub async fn download(
        &self,
        remote: &str,
        local: &Path,
        is_dir: bool,
        src: Option<&Entry>,
        ctx: &Ctx,
    ) -> Result<()> {
        self.download_in(remote, local, is_dir, src, ctx, WALK_BOUNDS).await
    }

    pub(crate) async fn download_in(
        &self,
        remote: &str,
        local: &Path,
        is_dir: bool,
        src: Option<&Entry>,
        ctx: &Ctx,
        bounds: WalkBounds,
    ) -> Result<()> {
        let walk = Walk::new(bounds, WalkOf::Download, remote, &ctx.walked);
        self.download_at(remote, local, is_dir, src, ctx, &walk, 0).await
    }

    /// `download` of one item `depth` levels below where the walk started.
    #[allow(clippy::too_many_arguments)]
    async fn download_at(
        &self,
        remote: &str,
        local: &Path,
        is_dir: bool,
        src: Option<&Entry>,
        ctx: &Ctx,
        walk: &Walk<'_>,
        depth: usize,
    ) -> Result<()> {
        ctx.check()?;
        if !is_dir {
            let key = local.to_string_lossy().to_string();
            let name = split_remote(remote).1;
            if ctx.done.lock().unwrap().contains(&key) {
                return Ok(());
            }
            if depth == 0
                && let Some(dir) = local.parent()
            {
                sweep_parts(dir).await;
            }
            // The listing's size backs the length check up where the server will not say.
            let expected = src.filter(|e| !e.is_link).map(|e| e.size);
            let mut exclusive = true;
            // What the server says now about a file a resume found replaced: asked about again.
            let mut changed: Option<(u64, u64)> = None;
            // ...and that resume was an overwrite continuing its part: started over, unasked.
            let mut part_changed = false;
            // An overwrite downloads into this part file beside the file (review FEA5).
            let part = part_beside(local);
            let part_key = part.to_string_lossy().to_string();
            loop {
                // The part of an overwrite whose link died, kept in `ctx.part`: continued from
                // what landed in it, checked as a resume in place is (review RVA1). Another file
                // of the tree may have taken the in-flight record since (it ran `begin` and
                // failed): this part is the file in flight again, its length the bytes landed,
                // its server file the one they came from, so a restart from zero is still seen
                // as one (RVA3-4).
                let kept = ctx.part.lock().unwrap().as_ref().filter(|p| p.path == part).map(|p| p.source);
                let landed = tokio::fs::metadata(&part).await.ok().filter(|m| m.is_file()).map(|m| m.len());
                let over = match (kept, landed) {
                    (Some(source), Some(len)) => {
                        if ctx.sent_to(&part_key).is_none() {
                            *ctx.inflight.lock().unwrap() = Some((part_key.clone(), len, false));
                            *ctx.source.lock().unwrap() = source;
                        }
                        true
                    }
                    _ => false,
                };
                let resuming = over || ctx.sent_to(&key).is_some();
                let mut offset = 0;
                // Every byte is in the part already: it only has to take the name.
                let mut whole = false;
                let mut fresh = false;
                let mut seen = Seen::default();
                // The local file an overwrite from zero replaces (review SOL-FTP-2).
                let mut replaces = None;
                match tokio::fs::metadata(local).await {
                    Ok(m) => {
                        if let Some(long) = aliased(local).await {
                            ctx.skip(remote, &format!("on this computer that name is the short (8.3) name of {long}"));
                            return Ok(());
                        }
                        if m.is_dir() {
                            ctx.skip(remote, "a local folder with that name is in the way");
                            return Ok(());
                        }
                        // The file an overwrite would replace is the one compared (and asked about) here.
                        replaces = Some(local_id(local).await?);
                        let facts = |m: &std::fs::Metadata| (m.len(), m.modified().map(millis).unwrap_or(0));
                        // A resumed overwrite continues its part, not the file it replaces.
                        let dst = match over {
                            true => tokio::fs::metadata(&part).await.map(|p| facts(&p)).unwrap_or_default(),
                            false => facts(&m),
                        };
                        let reask = changed.take();
                        let restart_part = std::mem::take(&mut part_changed);
                        // A listing shows a link's own length, not its target's; SIZE follows links.
                        // A decision that may end in a real resume (a local part shorter than the
                        // server's file) takes the server's own facts: the read checks them again,
                        // and a listing's date may be minutes in the server's zone. A complete or
                        // empty local file needs no look (review R-SOL-4).
                        let cached = match src {
                            Some(e)
                                if !e.is_link
                                    && !resuming
                                    && !(matches!(ctx.effective(&key), Policy::Ask | Policy::Resume) && 0 < dst.0 && dst.0 < e.size) =>
                            {
                                Some((e.size, e.modified))
                            }
                            _ => None,
                        };
                        let src = match (reask, cached) {
                            (Some(now), _) => now,
                            (None, Some(row)) => row,
                            (None, None) => match self.stat(remote).await? {
                                Some(e) if !e.is_dir => (e.size, e.modified),
                                Some(_) => {
                                    ctx.skip(remote, "it is a folder on the server, not a file");
                                    return Ok(());
                                }
                                None => return Err(AppError::Msg(format!("{name}: no such file on the server"))),
                            },
                        };
                        // The server's file was replaced while the link was down: its tail
                        // behind the old file's head would be a splice, so start over. An
                        // overwrite's part is started over unasked: the user chose to replace
                        // the file whatever the server has (found at the read instead: below).
                        let replaced = resuming
                            && match *ctx.source.lock().unwrap() {
                                Some((size, modified)) => (size > 0 && src.0 != size) || (modified != 0 && src.1 != 0 && modified != src.1),
                                None => false,
                            };
                        if replaced {
                            // Still in flight: the attempt that starts it over is a restart, no
                            // progress, and a rerun after another drop looks again (RVA1).
                            log::warn!(target: "vibeftp", "{remote}: the file on the server changed since the first attempt; downloading it again");
                        } else {
                            if resuming && src.0 > 0 && dst.0 > src.0 {
                                // The server's copy shrank while the link was down: what landed
                                // cannot be a prefix of it, so "already complete" would be a lie.
                                *ctx.inflight.lock().unwrap() = None;
                                return Err(AppError::Msg(format!(
                                    "{name}: the file on the server shrank during the download ({} bytes now, {} already received)",
                                    src.0, dst.0
                                )));
                            }
                            // Asked again when the file a resume was chosen for was replaced since;
                            // an overwrite's part found replaced at the read starts over (RVA2-5).
                            let forced = match (reask, resuming) {
                                (Some(_), _) if restart_part => Some(Policy::Overwrite),
                                (Some(_), _) => Some(Policy::Ask),
                                (None, true) => Some(Policy::Resume),
                                (None, false) => None,
                            };
                            match ctx.decide(&key, remote, src, dst, forced, true).await? {
                                None if over => whole = true,
                                None => {
                                    if resuming {
                                        mark_downloaded(local, &ctx.host_url); // every byte landed before the link died
                                    }
                                    *ctx.inflight.lock().unwrap() = None;
                                    (ctx.report)(remote, src.0, Some(src.0));
                                    ctx.done.lock().unwrap().insert(key);
                                    ctx.unskip(&[remote]);
                                    return Ok(());
                                }
                                Some(o) => offset = o,
                            }
                            if offset > 0 {
                                // Without a date, size alone cannot tell the file the local part
                                // came from apart from another of the same size: no resume.
                                if !resuming && src.1 == 0 {
                                    return Err(AppError::Msg(format!(
                                        "{name}: the server does not say when its file was changed, so it cannot be told from another file of that size; not resumed (choose Overwrite to download it whole)"
                                    )));
                                }
                                seen.source = Some(src);
                            }
                        }
                    }
                    Err(_) => fresh = exclusive,
                }
                ctx.check()?;
                // Both download_file implementations mark the file before the first byte.
                let got = match replaces.filter(|_| over || offset == 0) {
                    Some(id) => {
                        let from = (!whole).then_some(offset);
                        self.download_over(remote, local, &id, from, expected, seen, ctx).await
                    }
                    None => self.download_file(remote, local, offset, expected, fresh, seen, ctx).await,
                };
                match got {
                    // The name was taken since the look above (a parallel download of the same
                    // file under its long or short name): look again, once.
                    Err(AppError::Io(e)) if fresh && e.kind() == std::io::ErrorKind::AlreadyExists => {
                        exclusive = false;
                        continue;
                    }
                    // The server's file is not the one the resume was chosen for: its tail behind
                    // the local head would be a splice. Ask again with what is there now; an
                    // overwrite's part (dropped with the error) starts over unasked (RVA2-5).
                    Err(AppError::SourceChanged { size: Some(size), modified, .. }) => {
                        let next = if over { "downloading it again" } else { "asking again" };
                        log::warn!(target: "vibeftp", "{remote}: the file on the server changed since it was compared; {next}");
                        changed = Some((size, modified));
                        part_changed = over;
                        continue;
                    }
                    r => r?,
                }
                break;
            }
            *ctx.inflight.lock().unwrap() = None;
            ctx.done.lock().unwrap().insert(key);
            ctx.unskip(&[remote]);
            return Ok(());
        }
        // A folder finished by an earlier attempt is not listed again on a rerun.
        let dir_key = format!("dir:{}", local.to_string_lossy());
        if ctx.done.lock().unwrap().contains(&dir_key) {
            return Ok(());
        }
        // Too deep: stopped before anything of it is made here.
        walk.enter(depth)?;
        tokio::fs::create_dir_all(local).await?;
        if let Some(long) = aliased(local).await {
            ctx.skip(remote, &format!("on this computer that name is the short (8.3) name of the folder {long}"));
            return Ok(());
        }
        sweep_parts(local).await;
        let entries = self.list_complete(remote).await?;
        walk.take(&entries)?;
        // Windows folds case: two remote names differing only by case would overwrite each other.
        let mut seen: HashSet<String> = HashSet::new();
        for e in entries {
            if !safe_name(&e.name) {
                ctx.skip(&e.path, "not a name this computer can store");
                continue;
            }
            if !seen.insert(case_key(&e.name)) {
                ctx.skip(&e.path, "differs only by case from a file already written");
                continue;
            }
            if e.is_link && e.is_dir {
                ctx.skip(&e.path, "link to a folder");
                continue;
            }
            let target = local.join(&e.name);
            match Box::pin(self.download_at(&e.path, &target, e.is_dir, Some(&e), ctx, walk, depth + 1)).await {
                Ok(()) => {}
                // A walk bound ends the whole tree, never just this child (RINF-1).
                Err(err)
                    if walk.stopped()
                        || err.is_connection_error()
                        || err.is_storage_error()
                        || matches!(err, AppError::Cancelled) =>
                {
                    return Err(err)
                }
                // One unreadable child (permissions, a link the server won't send, a
                // vanished file) must not abort the whole tree.
                Err(err) => {
                    ctx.forget_inflight(&target.to_string_lossy());
                    ctx.forget_inflight(&part_beside(&target).to_string_lossy());
                    ctx.skip(&e.path, &err.to_string());
                }
            }
        }
        ctx.done.lock().unwrap().insert(dir_key);
        Ok(())
    }

    /// Upload a file or a whole directory tree, resolving conflicts via `ctx`.
    /// `existing` is the listing of the remote parent when already known.
    pub async fn upload(
        &self,
        local: &Path,
        remote: &str,
        is_dir: bool,
        existing: Option<&Listing>,
        ctx: &Ctx,
    ) -> Result<()> {
        ctx.check()?;
        if !is_dir {
            let name = split_remote(remote).1;
            let key = remote.to_string();
            if ctx.done.lock().unwrap().contains(&key) {
                return Ok(());
            }
            // The user may answer a conflict for a file that exists; Skip and Resume promise
            // to spare what is there, so they need to know and cannot work blind.
            let sent = ctx.sent_to(&key);
            let resuming = sent.is_some();
            // A retry of an attempt that replaced an existing file from zero cannot
            // trust the server's reported size (it may still hold the old file): resend.
            let restart = matches!(sent, Some((_, true)));
            // Only the cached listing says the name is free, and it may be older than another
            // client's upload of it: unless Overwrite, the first write makes sure (SOL-FTP-1).
            let mut fresh = Fresh::No;
            // The server would not say whether the name is taken: never "free" (review R2-1).
            let mut unknown = false;
            // (size, modified, exact-name match). A name that matches only by case or Unicode
            // form is a different file on a case-sensitive server, the same file on IIS,
            // FileZilla Server or a Mac: prompt, never resume.
            let mut hit: Option<(Entry, bool)> = match existing {
                // After a reconnect the cached listing is stale for the in-flight file, and a
                // link's row carries the link's own length, not its target's.
                Some(map) if !resuming => match map.get(&name) {
                    Some(e) if !e.is_link => Some((e.clone(), true)),
                    Some(_) => {
                        let (e, u) = self.stat_checked(remote, false).await?;
                        unknown = u;
                        e.map(|e| (e, true))
                    }
                    // Spelled differently in the listing: ask the server about the exact name.
                    // Absent means it keeps them apart; when it will not say, assume the worst.
                    None => match map.similar(&name) {
                        Some(e) => match self.stat_checked(remote, true).await? {
                            (Some(now), _) => Some((now, false)),
                            (None, true) => Some((e.clone(), false)),
                            (None, false) => None,
                        },
                        None if looks_short(&name) => {
                            let (e, u) = self.stat_checked(remote, false).await?;
                            if e.is_some() {
                                ctx.skip(remote, "the server takes this name for another file (an 8.3 short name)");
                                return Ok(());
                            }
                            unknown = u;
                            None
                        }
                        None => {
                            if ctx.effective(&key) != Policy::Overwrite {
                                fresh = Fresh::Listed;
                            }
                            None
                        }
                    },
                },
                _ => {
                    let (e, u) = self.stat_checked(remote, true).await?;
                    unknown = u;
                    e.map(|e| {
                        let exact = e.name == name;
                        (e, exact)
                    })
                }
            };
            // Replaced with the user's consent although the server would not say what is there.
            let mut blind = false;
            loop {
                if matches!(&hit, Some((e, _)) if e.is_dir) {
                    ctx.skip(remote, "a folder with that name is in the way on the server");
                    return Ok(());
                }
                // Taken, maybe: the server would not say. Skip leaves it alone with the reason,
                // Ask and Resume ask, and only an Overwrite (the policy or the answer) sends.
                if unknown && !blind {
                    let m = tokio::fs::metadata(local).await?;
                    let src = (m.len(), m.modified().map(millis).unwrap_or(0));
                    let policy = match ctx.effective(&key) {
                        p @ (Policy::Skip | Policy::Overwrite) => p,
                        Policy::Ask | Policy::Resume => ctx.ask_user(&key, remote, src, (0, 0)).await?,
                    };
                    if policy != Policy::Overwrite {
                        ctx.skip(remote, "the server would not say whether a file of that name is there now, so it was left alone");
                        return Ok(());
                    }
                    blind = true;
                }
                let dst: Option<(u64, u64, bool)> = hit.as_ref().map(|(e, exact)| (e.size, e.modified, *exact));
                let mut offset = 0;
                let existed = dst.is_some() || blind;
                if restart {
                    offset = 0;
                } else if let Some((size, modified, exact)) = dst {
                    let m = tokio::fs::metadata(local).await?;
                    let src = (m.len(), m.modified().map(millis).unwrap_or(0));
                    // The server reports more than we ever sent: it kept an older copy. A source
                    // that changed since the first attempt cannot be continued either.
                    let stale_remote = matches!(sent, Some((n, _)) if size > n);
                    let source_changed = resuming && ctx.source.lock().unwrap().map(|s| s != src).unwrap_or(false);
                    if source_changed {
                        log::warn!(target: "vibeftp", "{remote}: the local file changed since the last attempt; sending it again");
                    }
                    if stale_remote || source_changed {
                        offset = 0;
                    } else {
                        match ctx.resolve(&key, remote, src, (size, modified), resuming, exact).await? {
                            None => {
                                if !exact {
                                    // Not the same name: the file itself never went up.
                                    ctx.skip(remote, "a file whose name differs only by case or accents is on the server");
                                }
                                (ctx.report)(remote, src.0, Some(src.0));
                                ctx.done.lock().unwrap().insert(key);
                                return Ok(());
                            }
                            Some(o) => offset = o,
                        }
                    }
                }
                ctx.check()?;
                let outcome = self.upload_file(local, remote, offset, if existed { Fresh::No } else { fresh }, ctx).await;
                match outcome {
                    // The name was taken after the listing: decide about that file as about any
                    // existing one (Skip spares it, Ask asks).
                    Err(AppError::NameTaken { now: Some(e), .. }) => {
                        fresh = Fresh::No;
                        let exact = e.name == name;
                        hit = Some((e, exact));
                        continue;
                    }
                    // Taken, maybe: the server would not say (see the top of the loop).
                    Err(AppError::NameTaken { now: None, .. }) => {
                        fresh = Fresh::No;
                        unknown = true;
                        continue;
                    }
                    _ => {}
                }
                if offset == 0 && existed {
                    ctx.mark_restart(); // an overwrite from zero: never resume this one
                }
                outcome?;
                *ctx.inflight.lock().unwrap() = None;
                ctx.done.lock().unwrap().insert(key);
                ctx.unskip(&[remote, &local.to_string_lossy()]);
                return Ok(());
            }
        }
        // A folder finished by an earlier attempt is not listed again on a rerun.
        let dir_key = format!("dir:{remote}");
        if ctx.done.lock().unwrap().contains(&dir_key) {
            return Ok(());
        }
        // Read the local folder first: one that cannot be read must not leave an empty
        // namesake on the server.
        let mut rd = match tokio::fs::read_dir(local).await {
            Ok(rd) => rd,
            Err(e) if existing.is_some() => {
                // A child folder we cannot read is skipped; the top level still errors.
                ctx.skip(&local.to_string_lossy(), &e.to_string());
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        // Always list: some storage gateways answer MKD with success on an existing
        // folder, and an unlisted folder would mean silent overwrites. A failed
        // listing is only "empty" when the folder was not there before we made it.
        let (before, blind) = match existing {
            Some(map) => (map.get(&split_remote(remote).1).map(|e| e.is_dir), false),
            None => {
                let (e, blind) = self.stat_checked(remote, false).await?;
                (e.map(|e| e.is_dir), blind)
            }
        };
        if before == Some(false) {
            let why = "a file with that name is in the way on the server";
            if existing.is_some() {
                ctx.skip(remote, why);
                return Ok(());
            }
            return Err(AppError::Msg(format!("{}: {why}", split_remote(remote).1)));
        }
        let mut refused = None;
        let created = before.is_none()
            && match self.mkdir(remote).await {
                Ok(()) => true,
                // A timed-out MKD leaves its late reply for the next command to misread.
                Err(e) if e.is_connection_error() => return Err(e),
                Err(e) => {
                    refused = Some(e);
                    false
                }
            };
        // A folder that cannot be listed is only "empty" when we know we made it (a fresh stat
        // said absent, not "could not tell"; a cached parent listing may predate someone
        // else's MKD on a gateway that answers MKD OK for an existing folder), or when an
        // earlier attempt of this transfer made it. Its children are still looked at, each at
        // its first write, like those of any other folder (review R2-2).
        let ours = ctx.created.lock().unwrap().contains(remote);
        let map: Option<Listing> = match (self.list_complete(remote).await, refused) {
            (Ok(list), _) => Some(Listing::new(list)),
            (Err(e), _) if e.is_connection_error() => return Err(e),
            (Err(_), _) if ours => Some(Listing::default()),
            // Absent and MKD refused: every child would fail for "no such folder"; say why instead.
            (Err(_), Some(m)) if existing.is_some() && !m.is_storage_error() => {
                ctx.skip(remote, &format!("could not create the folder: {m}"));
                return Ok(());
            }
            (Err(_), Some(m)) => return Err(m),
            (Err(_), None) if created && !blind && existing.is_none() => {
                ctx.created.lock().unwrap().insert(remote.to_string());
                Some(Listing::default())
            }
            // Not listable: no snapshot at all, so every child asks the server itself and
            // honours the policy in force by then (a Skip-all answered later still counts):
            // where the server will not say, Ask and Resume ask and Overwrite sends. Under Skip
            // every child would be left out for that same reason, so the folder is.
            (Err(_), None) if *ctx.policy.lock().unwrap() != Policy::Skip => None,
            (Err(e), None) => return Err(e),
        };
        while let Some(entry) = rd.next_entry().await? {
            // A name that is not valid Unicode cannot go to the server as it is: a lossy name
            // could land on another file's (VibeRename RR-7).
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                ctx.skip(&entry.path().to_string_lossy(), "its name is not valid Unicode");
                continue;
            };
            let child_remote = join_remote(remote, &name);
            // Don't follow links/junctions to folders (cycles); files behind links are fine.
            let child_path = entry.path();
            let child_is_dir = match tokio::fs::symlink_metadata(&child_path).await {
                Ok(m) if m.file_type().is_symlink() => match tokio::fs::metadata(&child_path).await {
                    Ok(t) if t.is_dir() => {
                        ctx.skip(&child_path.to_string_lossy(), "link to a folder");
                        continue;
                    }
                    Ok(t) => t.is_dir(),
                    Err(e) => {
                        ctx.skip(&child_path.to_string_lossy(), &e.to_string());
                        continue;
                    }
                },
                Ok(m) => m.is_dir(),
                Err(e) => {
                    ctx.skip(&child_path.to_string_lossy(), &e.to_string());
                    continue;
                }
            };
            match Box::pin(self.upload(&child_path, &child_remote, child_is_dir, map.as_ref(), ctx)).await {
                Ok(()) => {}
                Err(err)
                    if err.is_connection_error()
                        || err.is_storage_error()
                        || matches!(err, AppError::Cancelled) =>
                {
                    return Err(err)
                }
                // A locked or unreadable local file must not abort the whole tree.
                Err(err) => {
                    ctx.forget_inflight(&child_remote);
                    ctx.skip(&child_path.to_string_lossy(), &err.to_string());
                }
            }
        }
        ctx.done.lock().unwrap().insert(dir_key);
        Ok(())
    }
}
