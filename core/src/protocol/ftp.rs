use super::{Ctx, Fresh, ListBounds, Looks, Seen, CHUNK, LIST_BOUNDS};
use crate::error::{AppError, Result};
use crate::types::{join_remote, millis, split_remote, Entry, Protocol, Site};
use std::collections::HashMap;
use std::time::Instant;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use suppaftp::list::{File as FtpFile, ListParser, PosixPexQuery};
use suppaftp::types::{FileType, Response};
use suppaftp::{
    DataStream, FtpError, ImplFtpStream, Mode, RustlsConnector, RustlsFtpStream, Status, TlsStream, TransferStream,
};

const IO_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The overall deadline of one operation on the control link once it holds the link: its
/// command replies and, for a listing, the listing too (whose own deadline is shorter). A
/// transfer counts its command phases only, not the data. A reply that trickles in a byte a
/// minute keeps every read inside `IO_TIMEOUT`, so without this it held the link, and
/// disconnect behind it, for ever (IN-VibeFTP-4).
const OP_DEADLINE: Duration = Duration::from_secs(600);
/// Dial to logged in: TLS, USER/PASS, FEAT, the start folder. (Three seconds in this crate's
/// unit tests, whose servers are on loopback, so the trickling greeting's test is quick.)
const LOGIN_DEADLINE: Duration = Duration::from_secs(if cfg!(test) { 3 } else { 60 });
/// How long a folder's listing stands in for a look at one of its names (review R-SOL-1).
const RECENT: Duration = Duration::from_secs(2);

/// Recent complete listings by folder: when taken, and the rows.
pub type Recent = Arc<Mutex<HashMap<String, (Instant, Arc<Vec<Entry>>)>>>;

/// The key a folder's listing is kept under.
fn folder_key(path: &str) -> String {
    if path.len() > 1 { path.trim_end_matches('/').to_string() } else { path.to_string() }
}

/// The listing of `dir` taken less than `RECENT` ago, if any.
fn recent_listing(i: &Inner, dir: &str) -> Option<Arc<Vec<Entry>>> {
    let r = i.recent.lock().unwrap();
    r.get(&folder_key(dir)).filter(|(at, _)| at.elapsed() < RECENT).map(|(_, l)| l.clone())
}

/// Keep a complete listing of `dir` (and drop the ones that are too old to be used).
fn remember_listing(i: &Inner, dir: &str, rows: &[Entry]) {
    let mut r = i.recent.lock().unwrap();
    r.retain(|_, (at, _)| at.elapsed() < RECENT);
    r.insert(folder_key(dir), (Instant::now(), Arc::new(rows.to_vec())));
}

/// A write through this session changed `dir`: `name` is there now (`Some`), or what the
/// listing says is unknown (`None`: forget it).
fn wrote_to(i: &Inner, dir: &str, name: Option<Entry>) {
    let mut r = i.recent.lock().unwrap();
    let key = folder_key(dir);
    match name {
        Some(e) => {
            if let Some((_, rows)) = r.get_mut(&key) {
                let rows = Arc::make_mut(rows);
                rows.retain(|x| x.name != e.name);
                rows.push(e);
            }
        }
        None => {
            r.remove(&key);
        }
    }
}

struct Inner {
    ftp: RustlsFtpStream,
    /// None = untested, Some(true) = server speaks MLSD.
    mlsd: Option<bool>,
    /// None = untested, Some(true) = server accepts `LIST -a` (dotfiles).
    list_all: Option<bool>,
    /// FEAT lists MLST: one path can be asked about without listing its folder.
    mlst: bool,
    /// SIZE: `Some(false)` when FEAT leaves it out or the server answered it 500/502/504,
    /// `None` when FEAT did not say.
    size: Option<bool>,
    /// Complete folder listings of the last `RECENT` seconds, shared by the links of a session
    /// (`share_listings`): what an upload onto a free-looking name checks against on a server
    /// without SIZE (review R-SOL-1).
    recent: Recent,
    /// Pure-FTPd cuts listings at `max_ls_files` (10,000 by default) and still answers 226.
    pure_ftpd: bool,
    /// Set after a cancelled transfer: the control channel is torn down and the
    /// session pool will redial on the next use.
    dead: Arc<AtomicBool>,
    /// What one listing may hold (`LIST_BOUNDS`; the tests make it small).
    bounds: ListBounds,
    /// `OP_DEADLINE` (the tests make it short) and the watch that keeps it.
    op_deadline: Duration,
    watch: Watch,
}

/// A deadline over the control link (IN-VibeFTP-4). Armed while an operation waits for its
/// replies, with the socket that operation reads; when the deadline passes, that socket is shut
/// down, so the blocked read fails at once, the link is let go, and it is marked dead (the pool
/// redials). One sleeping thread per link, gone with the link.
///
/// The socket is named by its raw handle at each arm, never kept: a handle copy made at connect
/// (`try_clone`) was found not connected by the time a later reply trickled (WSAENOTCONN under
/// parallel tests), and the cut did nothing. The raw handle is only used while armed, every arm
/// is made by the code that holds the socket (the operation under the link's lock, the login
/// with `keep`), and it disarms before letting go; a cut and a disarm take the same lock.
struct Watch {
    shared: Arc<WatchShared>,
}

struct WatchShared {
    state: Mutex<WatchState>,
    wake: Condvar,
}

#[derive(Default)]
struct WatchState {
    until: Option<(Instant, RawSock)>,
    fired: bool,
    stop: bool,
}

#[cfg(windows)]
type RawSock = std::os::windows::io::RawSocket;
#[cfg(not(windows))]
type RawSock = std::os::fd::RawFd;

fn raw_of(s: &TcpStream) -> RawSock {
    #[cfg(windows)]
    {
        std::os::windows::io::AsRawSocket::as_raw_socket(s)
    }
    #[cfg(not(windows))]
    {
        std::os::fd::AsRawFd::as_raw_fd(s)
    }
}

/// Shut a socket down by its raw handle, leaving it open (its owner closes it).
fn cut(raw: RawSock) -> std::io::Result<()> {
    // SAFETY: the handle is a live socket for as long as the watch is armed with it (above);
    // ManuallyDrop keeps this borrowed view from closing it.
    #[cfg(windows)]
    let s = std::mem::ManuallyDrop::new(unsafe { <TcpStream as std::os::windows::io::FromRawSocket>::from_raw_socket(raw) });
    #[cfg(not(windows))]
    let s = std::mem::ManuallyDrop::new(unsafe { <TcpStream as std::os::fd::FromRawFd>::from_raw_fd(raw) });
    s.shutdown(Shutdown::Both)
}

impl WatchShared {
    fn state(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Watch {
    fn start(dead: Arc<AtomicBool>) -> Watch {
        let shared = Arc::new(WatchShared { state: Mutex::new(WatchState::default()), wake: Condvar::new() });
        let s = shared.clone();
        let spawned = std::thread::Builder::new().name("vibeftp-ftp-watch".into()).spawn(move || {
            let mut st = s.state();
            while !st.stop {
                match st.until {
                    None => st = s.wake.wait(st).unwrap_or_else(|e| e.into_inner()),
                    Some((t, raw)) => {
                        let now = Instant::now();
                        if now < t {
                            st = s.wake.wait_timeout(st, t - now).unwrap_or_else(|e| e.into_inner()).0;
                            continue;
                        }
                        st.until = None;
                        st.fired = true;
                        dead.store(true, Ordering::SeqCst);
                        let r = cut(raw);
                        log::warn!(target: "vibeftp", "The FTP server did not finish its answer in time; connection dropped ({r:?})");
                    }
                }
            }
        });
        if let Err(e) = spawned {
            log::warn!(target: "vibeftp", "FTP reply deadline not kept on this link: {e}");
        }
        Watch { shared }
    }

    /// Arm: the deadline `d` from now over the socket `sock` reads. The caller holds `sock`
    /// until it disarms.
    fn arm(&self, d: Duration, sock: &TcpStream) {
        self.shared.state().until = Some((Instant::now() + d, raw_of(sock)));
        self.shared.wake.notify_all();
    }

    fn disarm(&self) {
        self.shared.state().until = None;
        self.shared.wake.notify_all();
    }

    fn fired(&self) -> bool {
        self.shared.state().fired
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.shared.state().stop = true;
        self.shared.wake.notify_all();
    }
}

/// `Watch::arm` over the link's control socket, for `i.op_deadline`.
fn arm(i: &Inner) {
    i.watch.arm(i.op_deadline, &i.ftp.get_ref());
}

/// What an operation the watch cut short answers.
fn too_slow(what: &str, d: Duration) -> AppError {
    AppError::Io(std::io::Error::new(
        ErrorKind::TimedOut,
        format!("The server took longer than {} s to {what}; the connection was closed", d.as_secs()),
    ))
}

pub struct FtpConn {
    inner: Arc<Mutex<Inner>>,
    /// `Inner::dead`, readable while another transfer holds the link.
    dead: Arc<AtomicBool>,
}

impl FtpConn {
    /// `pin`: the FTPS certificate fingerprint the user trusted for this site (`SHA256:…`).
    /// Returns the connection, the start folder and, on FTPS, the fingerprint of the
    /// certificate the server presented.
    pub async fn connect(site: &Site, password: &str, pin: Option<String>) -> Result<(Self, String, Option<String>)> {
        let site = site.clone();
        let password = password.to_string();
        let (inner, cwd, seen) = tokio::task::spawn_blocking(move || match open(&site, &password, false, &pin) {
            // The rare FTPS server that speaks TLS 1.3 only: one more try with it allowed.
            Err(e) if site.protocol == Protocol::Ftps && tls_version_refused(&e) => {
                log::info!(target: "vibeftp", "The server requires TLS 1.3; reconnecting with it");
                open(&site, &password, true, &pin)
            }
            r => r,
        })
        .await
        .map_err(|e| AppError::Msg(e.to_string()))??;
        Ok((
            FtpConn {
                dead: inner.dead.clone(),
                inner: Arc::new(Mutex::new(inner)),
            },
            cwd,
            seen,
        ))
    }

    async fn with<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Inner) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        self.run(true, f).await
    }

    /// Run `f` on the link once it is free. `whole`: the reply deadline covers all of `f`; a
    /// transfer (`false`) arms it around its own command phases, never its data.
    async fn run<F, R>(&self, whole: bool, f: F) -> Result<R>
    where
        F: FnOnce(&mut Inner) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| AppError::Poisoned)?;
            if guard.dead.load(Ordering::SeqCst) {
                return Err(AppError::NotConnected);
            }
            let d = guard.op_deadline;
            if whole {
                arm(&guard);
            }
            let r = f(&mut guard);
            guard.watch.disarm();
            match r {
                Err(_) if guard.watch.fired() => Err(too_slow("answer", d)),
                r => r,
            }
        })
        .await
        .map_err(|e| AppError::Msg(e.to_string()))?
    }

    /// `with` for a file transfer. A transfer sharing this link waits here while another file
    /// runs on it: its cancel must end that wait at once, not when that file is done
    /// (C2-F02-4). Once it has the link, the closure's own checks handle a cancel; the waiting
    /// thread left behind finds the flag set and lets go without touching the link.
    async fn with_ctx<F, R>(&self, ctx: &Ctx, f: F) -> Result<R>
    where
        F: FnOnce(&mut Inner) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        use std::sync::atomic::fence;
        let started = Arc::new(AtomicBool::new(false));
        let (flag, c) = (started.clone(), ctx.clone());
        let job = self.run(false, move |i| {
            flag.store(true, Ordering::SeqCst);
            fence(Ordering::SeqCst); // pairs with the fence below: one side sees the other
            c.check()?;
            f(i)
        });
        tokio::pin!(job);
        loop {
            tokio::select! {
                r = &mut job => return r,
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if ctx.cancelled() {
                        fence(Ordering::SeqCst);
                        if !started.load(Ordering::SeqCst) {
                            return Err(AppError::Cancelled);
                        }
                    }
                }
            }
        }
    }

    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let path = path.to_string();
        self.with(move |i| list_in(i, &path, false)).await
    }

    /// `list` for callers that treat a missing name as absent: a listing the server cut
    /// short is an error here, not a partial answer.
    pub async fn list_complete(&self, path: &str) -> Result<Vec<Entry>> {
        let path = path.to_string();
        self.with(move |i| list_in(i, &path, true)).await
    }

    /// Existence check that sees dotfiles too: MLST where the server has it, else SIZE for
    /// files, CWD for folders, and the parent listing when the server will not answer SIZE.
    pub async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        self.stat_impl(path, false).await
    }

    /// `stat`, but when only the parent listing can answer, a name that differs only by
    /// case is returned too (its `name` tells): on a case-folding server that is the very
    /// file a write would replace.
    pub async fn stat_any_case(&self, path: &str) -> Result<Option<Entry>> {
        self.stat_impl(path, true).await
    }

    async fn stat_impl(&self, path: &str, any_case: bool) -> Result<Option<Entry>> {
        let full = path.to_string();
        self.with(move |i| stat_in(i, &full, any_case)).await
    }

    /// Keep recent listings with `recent`, the session's (see `Inner::recent`).
    pub fn share_listings(&self, recent: &Recent) {
        if let Ok(mut i) = self.inner.lock() {
            i.recent = recent.clone();
        }
    }

    /// The entry at `path` as its folder's listing shows it (see `Remote::listed`).
    pub async fn listed(&self, path: &str, looks: &Looks) -> Result<Option<Entry>> {
        let (dir, name) = split_remote(path);
        let full = path.to_string();
        let (key, have) = (dir.clone(), looks.get(&dir));
        let (found, taken) = self
            .with(move |i| {
                // MLSD rows carry MLST's facts; a LIST row only matches another LIST row. A link
                // that has not listed yet lists by MLSD where FEAT has MLST.
                if (i.mlsd == Some(true) || (i.mlsd.is_none() && i.mlst))
                    && let Some(known) = mlst_in(i, &full, &name)?
                {
                    return Ok((known, None));
                }
                let rows = match have {
                    Some(rows) => rows,
                    None => Arc::new(list_in(i, &dir, true)?),
                };
                Ok((rows.iter().find(|e| e.name == name).cloned(), Some(rows)))
            })
            .await?;
        if let Some(rows) = taken {
            looks.put(&key, rows);
        }
        Ok(found)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let path = path.to_string();
        self.with(move |i| {
            i.ftp.mkdir(&path)?;
            let (dir, name) = split_remote(&path);
            wrote_to(i, &dir, Some(Entry { name, path: path.clone(), is_dir: true, is_link: false, size: 0, modified: 0, mode: None }));
            Ok(())
        })
        .await
    }

    pub async fn remove_file(&self, path: &str) -> Result<()> {
        let path = path.to_string();
        self.with(move |i| {
            guard_twin(i, &path)?;
            let r = i.ftp.rm(&path);
            wrote_to(i, &split_remote(&path).0, None);
            Ok(r?)
        })
        .await
    }

    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        let path = path.to_string();
        self.with(move |i| {
            guard_twin(i, &path)?;
            let r = i.ftp.rmdir(&path);
            wrote_to(i, &split_remote(&path).0, None);
            Ok(r?)
        })
        .await
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let (from, to) = (from.to_string(), to.to_string());
        self.with(move |i| {
            guard_twin(i, &from)?;
            let r = i.ftp.rename(&from, &to);
            wrote_to(i, &split_remote(&from).0, None);
            wrote_to(i, &split_remote(&to).0, None);
            Ok(r?)
        })
        .await
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        let path = path.to_string();
        self.with(move |i| {
            guard_twin(i, &path)?;
            i.ftp.site(format!("CHMOD {:o} {}", mode & 0o7777, path))?;
            Ok(())
        })
        .await
    }

    pub async fn noop(&self) -> Result<()> {
        self.with(|i| Ok(i.ftp.noop()?)).await
    }

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
        let (dir, name) = split_remote(remote);
        let full = remote.to_string();
        let local = local.to_path_buf();
        let (waiting, ctx) = (ctx, ctx.clone());
        self.with_ctx(waiting, move |i| {
            ctx.check()?;
            // The command phases have a deadline, the data does not (a slow link is no fault).
            arm(i);
            i.ftp.cwd(&dir)?;
            // MLST gives size and date in one round trip (the date tells a retry whether the file
            // was replaced meanwhile); SIZE otherwise. With neither, the listing's size stands in:
            // a short transfer must not pass as complete.
            let (reported, modified) = match mlst_in(i, &full, &name)? {
                Some(Some(e)) if !e.is_dir => (Some(e.size), e.modified),
                // A resume is checked on the date too: MDTM where MLST would not say.
                _ if offset > 0 && seen.source.is_some() => (size_of(i, &name)?, mdtm_of(i, &name)?),
                // So is the first read, so a rerun after a dead link tells a replaced file by its
                // date too (review RVA2-6). Only where SIZE answered, as `stat` asks MDTM: its
                // reading is what the rerun compares with.
                _ => match size_of(i, &name)? {
                    Some(size) => (Some(size), mdtm_of(i, &name)?),
                    None => (None, 0),
                },
            };
            // The offset was chosen for the file the decision saw: continuing another one here
            // would put its tail behind that file's head (review SOL-FTP-3).
            if let Some(was) = seen.source.filter(|_| offset > 0)
                && !super::same_source(was, reported, modified)
            {
                return Err(AppError::SourceChanged { name: name.clone(), size: reported, modified });
            }
            let total = reported.or(expected.filter(|&e| e > 0));
            let mut offset = offset;
            if offset > 0 {
                i.ftp.resume_transfer(offset as usize)?;
            }
            let mut stream = match i.ftp.retr_as_stream(&name) {
                Ok(s) => s,
                // REST refused (small embedded servers): the local file is ours, fetch it whole.
                Err(FtpError::UnexpectedResponse(r)) if offset > 0 && r.status != Status::NotAvailable => {
                    log::warn!(target: "vibeftp", "{name}: the server will not resume ({}); downloading it whole", reply_text(&r));
                    offset = 0;
                    i.ftp.retr_as_stream(&name)?
                }
                Err(e) => return Err(e.into()),
            };
            arm_data_timeouts(&stream);
            // Only now touch the local file: a failed CWD/RETR must leave nothing behind
            // (a stub would look like a conflict on the retry), and the old copy stays
            // intact until data actually flows. REST was consumed by RETR either way.
            // An existing file is never written from zero here, only an overwrite's part file
            // (`Remote::download_over`).
            let mut opts = std::fs::OpenOptions::new();
            if fresh && offset == 0 {
                opts.write(true).create_new(true);
            } else {
                opts.write(true).create(true).append(offset > 0).truncate(offset == 0);
            }
            let opened = opts.open(&local).map_err(AppError::from);
            let mut out = match opened {
                Ok(f) => f,
                Err(e) => {
                    drop(stream); // closes the data socket and reads the transfer reply
                    return Err(e);
                }
            };
            if offset > 0 {
                // The offset came from a listing taken before the conflict prompt (or the
                // outage): appending behind a file that changed meanwhile would splice.
                let len = out.metadata().map(|m| m.len()).unwrap_or(offset);
                if len != offset {
                    drop(stream);
                    return Err(AppError::Msg(format!(
                        "{name}: the local file changed while waiting ({len} bytes now, resume expected {offset})"
                    )));
                }
            }
            // From here on the destination is being written: a retry must resume, not re-ask.
            super::mark_downloaded(&local, &ctx.host_url);
            ctx.begin(local.to_string_lossy().to_string(), offset);
            *ctx.source.lock().unwrap() = Some((reported.unwrap_or(0), modified));
            (ctx.report)(&full, offset, total);
            let mut buf = vec![0u8; CHUNK];
            let mut done: u64 = offset;
            i.watch.disarm();
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    // TLS peers that close without close_notify: let the 226/426 reply decide.
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => 0,
                    // A broken or stalled data link. The server words the failed send its own way
                    // (426, sftpgo 550, ...), none of which says the file is unreadable: keep the
                    // I/O error so the transfer redials and resumes. The reply is only logged.
                    Err(e) => {
                        arm(i);
                        if let Err(r) = stream.finish() {
                            log::warn!(target: "vibeftp", "{name}: download interrupted ({e}); server said: {r}");
                        }
                        return Err(e.into());
                    }
                };
                if n == 0 {
                    break;
                }
                // Before the write: a read that returns after a cancel (another session may
                // own this file by then) must not touch the destination.
                if ctx.cancelled() {
                    kill_transfer(i, stream);
                    return Err(AppError::Cancelled);
                }
                // A server that announced the size stops there: more would fill the disk with
                // what was never asked for (IN-VibeFTP-3).
                if let Some(t) = total.filter(|&t| done + n as u64 > t) {
                    drop_link(i, stream, "the server sent more than it announced");
                    return Err(oversized(&name, t));
                }
                out.write_all(&buf[..n])?;
                done += n as u64;
                ctx.progress(done);
                (ctx.report)(&full, done, total);
            }
            arm(i);
            stream.finish()?;
            out.flush()?;
            if let Some(t) = total
                && done != t
            {
                return Err(AppError::Msg(format!(
                    "{name}: size mismatch (received {done} bytes, server said {t})"
                )));
            }
            (ctx.report)(&full, done, Some(done));
            Ok(())
        })
        .await
    }

    pub async fn upload_file(&self, local: &Path, remote: &str, offset: u64, fresh: Fresh, ctx: &Ctx) -> Result<()> {
        let (dir, name) = split_remote(remote);
        let local = local.to_path_buf();
        let key = remote.to_string();
        let full = remote.to_string();
        let (waiting, ctx) = (ctx, ctx.clone());
        self.with_ctx(waiting, move |i| {
            ctx.check()?;
            let mut file = std::fs::File::open(&local)?;
            let meta = file.metadata().ok();
            let total = meta.as_ref().map(|m| m.len());
            *ctx.source.lock().unwrap() = meta.as_ref().map(|m| (m.len(), m.modified().map(millis).unwrap_or(0)));
            // A rerun after a dropped link, continuing the file this transfer was writing.
            let retry = ctx.sent_to(&key).is_some();
            let mut offset = offset;
            if offset > 0 {
                file.seek(SeekFrom::Start(offset))?;
            }
            // The command phases have a deadline, the data does not (a slow link is no fault).
            arm(i);
            i.ftp.cwd(&dir)?;
            // The offset was read before the conflict prompt, or from a listing (where a link
            // shows its own length): APPE continues at the server's real end, so that end must
            // be where we think it is.
            if offset > 0 {
                // MLST also tells "gone" (APPE would recreate the file as just our tail).
                let now = match mlst_in(i, &full, &name)? {
                    Some(Some(e)) => Some(e.size),
                    Some(None) => Some(0),
                    None => size_of(i, &name)?,
                };
                if let Some(now) = now.filter(|&s| s != offset) {
                    return Err(AppError::Msg(format!(
                        "{name}: the file on the server changed while waiting ({now} bytes now, resume expected {offset}); nothing was sent"
                    )));
                }
            }
            let mut restarted = false;
            let (mut stream, rest_stor) = if offset > 0 {
                match resume_upload(&mut i.ftp, &name, offset) {
                    Ok(s) => s,
                    Err(e) if e.is_connection_error() => return Err(e),
                    // Our own partial from before the drop: starting over is always safe.
                    Err(e) if retry => {
                        log::warn!(target: "vibeftp", "{name}: the server will not resume ({e}); sending it again from the start");
                        offset = 0;
                        restarted = true;
                        file.seek(SeekFrom::Start(0))?;
                        (i.ftp.put_with_stream(&name)?, false)
                    }
                    Err(e) => {
                        return Err(AppError::Msg(format!(
                            "{name}: the server does not allow resuming here ({e}); choose Overwrite to send the whole file"
                        )))
                    }
                }
            } else {
                if fresh != Fresh::No {
                    // FTP has no exclusive create: STOR replaces whatever holds the name now, so
                    // look right before it, on this link (review SOL-FTP-1, R-SOL-1).
                    look_free(i, &dir, &full, &name)?;
                }
                (i.ftp.put_with_stream(&name)?, false)
            };
            arm_data_timeouts(&stream);
            // The session's recent listing of the folder has this name from now on: another
            // upload of it must not take it for free (review R-SOL-1). Its size and date are not
            // known yet (0, 0): a decision about it asks rather than resume (review R2-5).
            wrote_to(i, &dir, Some(Entry { name: name.clone(), path: full.clone(), is_dir: false, is_link: false, size: 0, modified: 0, mode: None }));
            *ctx.inflight.lock().unwrap() = Some((key, offset, false));
            if restarted {
                ctx.mark_restart(); // a later retry goes straight to a full send
            }
            (ctx.report)(&full, offset, total);
            let mut buf = vec![0u8; CHUNK];
            let mut done: u64 = offset;
            i.watch.disarm();
            loop {
                let n = match file.read(&mut buf) {
                    Ok(n) => n,
                    // The file opened but cannot be read on (a byte-range lock, a bad sector, a
                    // dropped share). A clean close would make the server keep the short copy as
                    // a finished upload: reset the data connection so it sees an aborted one.
                    Err(e) => {
                        abort_data(stream);
                        return Err(AppError::Msg(format!(
                            "{name}: reading the local file failed after {done} bytes ({e}); the upload was aborted and the copy on the server is incomplete"
                        )));
                    }
                };
                if n == 0 {
                    break;
                }
                if ctx.cancelled() {
                    kill_transfer(i, stream);
                    return Err(AppError::Cancelled);
                }
                if let Err(e) = stream.write_all(&buf[..n]) {
                    // Servers stop a full disk or quota by resetting the data connection: their
                    // reply says so, and only without one is the control link suspect.
                    arm(i);
                    return Err(match stream.finish() {
                        Err(FtpError::UnexpectedResponse(r)) if is_storage_reply(&r) => refused_upload(r, &name),
                        _ => e.into(),
                    });
                }
                done += n as u64;
                ctx.progress(done);
                (ctx.report)(&full, done, total);
            }
            arm(i);
            match stream.finish() {
                Ok(()) => {}
                Err(FtpError::UnexpectedResponse(r)) => return Err(refused_upload(r, &name)),
                Err(e) => return Err(e.into()),
            }
            // A source truncated mid-upload reads EOF early; never report that as complete.
            if let Some(t) = total {
                if done != t {
                    return Err(AppError::Msg(format!(
                        "{name}: size mismatch (sent {done} bytes, the file has {t})"
                    )));
                }
                // A server that takes REST but ignores it on STOR wrote our tail from byte 0.
                if rest_stor
                    && let Some(s) = size_of(i, &name)?.filter(|&s| s != t)
                {
                    return Err(AppError::Msg(format!(
                        "{name}: the server did not continue the file at byte {offset} ({s} bytes there now, {t} expected); send it again with Overwrite"
                    )));
                }
            }
            // Pure-FTPd turns edge spaces into `_` (` notes.txt` lands as `_notes.txt`) and Win32
            // drops trailing dots and spaces: make sure the file is where it was meant to go.
            if (name.trim() != name || name.ends_with('.'))
                && let Ok(entries) = list_in(i, &dir, true)
                && !entries.iter().any(|e| e.name == name)
            {
                return Err(AppError::Msg(format!(
                    "{name:?}: the server stored it under another name (it changes edge spaces or dots); rename the local file and send it again"
                )));
            }
            (ctx.report)(&full, done, Some(done));
            Ok(())
        })
        .await
    }

    pub async fn disconnect(&self) {
        let _ = self.with(|i| Ok(i.ftp.quit()?)).await;
    }

    /// A cancel tore this link down (`kill_transfer`). Other cancels (at a prompt, or while
    /// waiting for the link) leave it healthy.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
}

/// Dial, secure, log in. FTPS stays on TLS 1.2 unless `tls13`: FTPS servers tie each data
/// connection to the control session and expect its ticket to be reused, but rustls uses a
/// TLS 1.3 ticket only once and an upload never reads the replacement ones, so from the third
/// upload vsftpd, ProFTPD and FileZilla Server refuse the data connection (522), after
/// truncating the file. TLS 1.2 sessions can be resumed any number of times.
fn open(site: &Site, password: &str, tls13: bool, pin: &Option<String>) -> Result<(Inner, String, Option<String>)> {
    let verifier = Arc::new(PinnedCert::new(pin.clone()));
    match open_with(site, password, tls13, &verifier) {
        Ok((inner, cwd)) => Ok((inner, cwd, verifier.seen.lock().unwrap().clone())),
        // rustls checks the certificate lazily, so its refusal surfaces as whatever I/O came
        // next; the verifier knows what it turned down.
        Err(e) => Err(match verifier.refused.lock().unwrap().take() {
            Some((actual, reason)) => match pin {
                Some(expected) => AppError::CertChanged {
                    host: site.host.clone(),
                    expected: expected.clone(),
                    actual,
                },
                None => AppError::CertUnknown {
                    host: site.host.clone(),
                    fingerprint: actual,
                    reason,
                },
            },
            None => e,
        }),
    }
}

fn open_with(site: &Site, password: &str, tls13: bool, verifier: &Arc<PinnedCert>) -> Result<(Inner, String)> {
    // Try every resolved address, IPv4 first: dual-stack hosts often
    // resolve to an IPv6 address the local network cannot reach.
    let mut addrs: Vec<SocketAddr> = format!("{}:{}", site.host, site.port)
        .to_socket_addrs()?
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    if addrs.is_empty() {
        return Err(AppError::Msg(format!("Could not resolve {}", site.host)));
    }
    let mut last_err: Option<std::io::Error> = None;
    let mut picked: Option<(TcpStream, SocketAddr)> = None;
    for a in &addrs {
        log::info!(target: "vibeftp", "Connecting to {} ({})", site.host, a);
        match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            Ok(t) => {
                picked = Some((t, *a));
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let (tcp, addr) = match picked {
        Some(p) => p,
        None => return Err(last_err.map(AppError::Io).unwrap_or(AppError::NotConnected)),
    };
    // The login has an overall deadline too (IN-VibeFTP-4): a greeting or a reply that trickles
    // in never holds the connect for ever.
    // `keep` holds the socket open until the watch is disarmed, whatever `login` drops.
    let dead = Arc::new(AtomicBool::new(false));
    let watch = Watch::start(dead.clone());
    let keep = tcp.try_clone()?;
    let started = Instant::now();
    watch.arm(LOGIN_DEADLINE, &keep);
    let shared = watch.shared.clone();
    let r = login(site, password, tls13, verifier, tcp, addr, dead, watch);
    let fired = {
        let mut st = shared.state();
        st.until = None;
        st.fired
    };
    drop(keep);
    match r {
        Err(_) if fired => Err(too_slow("log in", LOGIN_DEADLINE)),
        // A login that got through past its deadline is refused too (review RB2): the watch
        // marked that link dead, or ran too late (or its cut missed) to stop the wait.
        Ok(_) if fired || started.elapsed() >= LOGIN_DEADLINE => Err(too_slow("log in", LOGIN_DEADLINE)),
        r => r,
    }
}

#[allow(clippy::too_many_arguments)]
fn login(
    site: &Site,
    password: &str,
    tls13: bool,
    verifier: &Arc<PinnedCert>,
    tcp: TcpStream,
    addr: SocketAddr,
    dead: Arc<AtomicBool>,
    watch: Watch,
) -> Result<(Inner, String)> {
    // Short timeout for the banner (an implicit-TLS port never sends one); raised after login.
    tcp.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    // An SSH server greets first too: say so instead of "invalid syntax".
    let mut greeting = [0u8; 4];
    match tcp.peek(&mut greeting) {
        Ok(4) if &greeting == b"SSH-" => {
            return Err(AppError::Msg(format!(
                "Port {} answers with SSH, not FTP: choose SFTP for this site",
                site.port
            )));
        }
        Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            return Err(AppError::Msg(format!(
                "No FTP greeting from port {} within {} s (implicit FTPS? This app speaks explicit FTPS, usually on port 21)",
                site.port,
                CONNECT_TIMEOUT.as_secs()
            )));
        }
        _ => {}
    }
    let ftp = RustlsFtpStream::connect_with_stream(tcp)?
        // PASV connects get a deadline too (Windows otherwise waits ~21 s per blocked port).
        .passive_stream_builder(|addr| {
            TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(FtpError::ConnectionError)
        });
    let pure_ftpd = ftp.get_welcome_msg().is_some_and(|w| w.contains("Pure-FTPd"));
    let mut ftp = if site.protocol == Protocol::Ftps {
        let tls = RustlsConnector::from(tls_config(verifier.clone(), tls13));
        ftp.into_secure(tls, &site.host)?
    } else {
        ftp
    };
    if site.ftp_mode == "active" {
        // Server connects back to us; needs an open inbound firewall.
        ftp = ftp.active_mode(CONNECT_TIMEOUT);
        log::info!(target: "vibeftp", "FTP active mode");
    } else {
        if addr.is_ipv6() {
            ftp.set_mode(Mode::ExtendedPassive);
        }
        ftp.set_passive_nat_workaround(true);
    }
    let (user, pass) = if site.username.is_empty() {
        ("anonymous", "anonymous@vibeftp")
    } else {
        (site.username.as_str(), password)
    };
    ftp.login(user, pass)?;
    let _ = ftp.get_ref().set_read_timeout(Some(IO_TIMEOUT));
    ftp.transfer_type(FileType::Binary)?;
    // Best effort: ask for UTF-8 names (RFC 2640). Servers that don't know it just refuse.
    let _ = ftp.opts("UTF8", Some("ON"));
    let (mlst, size) = match ftp.feat() {
        Ok(f) => (f.keys().any(|k| k.eq_ignore_ascii_case("MLST")), Some(f.keys().any(|k| k.eq_ignore_ascii_case("SIZE")))),
        Err(e) => {
            let e = AppError::Ftp(e);
            if e.is_connection_error() {
                return Err(e);
            }
            (false, None)
        }
    };
    if !site.remote_path.is_empty()
        && let Err(e) = ftp.cwd(&site.remote_path)
    {
        let e = AppError::Ftp(e);
        if e.is_connection_error() {
            return Err(e);
        }
        return Err(AppError::Msg(format!(
            "Remote folder {} is not on the server ({e}); change it in the site settings",
            site.remote_path
        )));
    }
    let cwd = unquote_pwd(ftp.pwd()?);
    Ok((
        Inner {
            ftp,
            mlsd: None,
            list_all: None,
            mlst,
            size,
            recent: Recent::default(),
            pure_ftpd,
            dead,
            bounds: LIST_BOUNDS,
            op_deadline: OP_DEADLINE,
            watch,
        },
        cwd,
    ))
}

/// The server turned down a TLS 1.2-only handshake with a protocol_version alert.
fn tls_version_refused(e: &AppError) -> bool {
    let AppError::Ftp(FtpError::ConnectionError(io)) = e else { return false };
    matches!(
        io.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion))
    )
}

/// MLST of one path (RFC 3659). `Some(Some(entry))`: it exists; `Some(None)`: the server says
/// there is no such file; `None`: no answer to trust (no MLST, a refusal, a link: SIZE follows
/// links, MLST may not), so the caller asks the other ways.
fn mlst_in(i: &mut Inner, full: &str, name: &str) -> Result<Option<Option<Entry>>> {
    if !i.mlst {
        return Ok(None);
    }
    let line = match i.ftp.mlst(Some(full)) {
        Ok(l) => l,
        Err(e) if is_unsupported(&e) => {
            i.mlst = false;
            return Ok(None);
        }
        // Only a plain "not there" counts as absent: a 550 can also be a denied lookup in a
        // drop box, where a Skip that trusted it would overwrite.
        Err(FtpError::UnexpectedResponse(r)) if r.status == Status::FileUnavailable => {
            return Ok(says_absent(&reply_text(&r), full).then_some(None));
        }
        Err(e) => {
            let e = AppError::Ftp(e);
            return if e.is_connection_error() { Err(e) } else { Ok(None) };
        }
    };
    let entry = |is_dir: bool, size: u64, modified: u64, mode: Option<u32>| Entry {
        name: name.to_string(),
        path: full.to_string(),
        is_dir,
        is_link: false,
        size,
        modified,
        mode,
    };
    match mlsd_line(&line) {
        None => Ok(Some(Some(entry(true, 0, 0, None)))), // type=cdir: the folder itself
        Some((_, true)) => Ok(None),
        Some((l, false)) => Ok(ListParser::parse_mlst(&l).ok().map(|f| {
            let dir = f.is_directory();
            Some(entry(dir, if dir { 0 } else { f.size() as u64 }, millis(f.modified()), mlsd_mode(&l)))
        })),
    }
}

/// The words of an MLST 550 that say there is no such file; any other 550 proves nothing.
/// "cannot be listed" is ProFTPD's (mod_facts `facts_mlst`, review R3-1): it sends it when
/// `facts_mlinfo_get` fails, which is an lstat of the path that failed (ENOENT; or EACCES on a
/// folder on the way, ELOOP, ENAMETOOLONG, ENOTDIR, which make STOR's open of the same path fail
/// the same way), a link whose target does not stat, or a link that cannot be read. Such a link
/// is there, but STOR is refused on it (`xfer_pre_stor` counts it as existing: "Overwrite
/// permission denied" or "Not a regular file"), or writes through it with `TransferOptions
/// AllowSymlinkUpload`, and MLSD hides it too, so the listing would say "free" all the same
/// (review R4-3). Its `<Limit>` refusal is another text ("path: Permission denied"),
/// a hidden path an empty 250 list. Pure-FTPd says "Can't check for file existence" for every
/// stat failure, a denied one too, so it is not here: Pure-FTPd goes on to SIZE and the listing.
const ABSENT: [&str; 6] = ["not exist", "no such", "not found", "cannot find", "can't find", "cannot be listed"];

/// Whether a 550 to MLST of `full` says there is no such file, read on the server's own words
/// only (review R3-2). ProFTPD and Serv-U echo the path in the reply (`550 /box/Not Found.html:
/// Permission denied`). The rule is that a phrase inside the path never counts: such a reply proves
/// nothing and the name goes on to SIZE and the listing. The verbatim echo of `full` is also cut
/// out (any case), so a phrase that straddles its edge proves nothing either; `full` starts with
/// `/` and cannot sit inside the server's own words. The bare name is not cut (review R4-1): `a`
/// or `list` would cut the server's words. So a server that echoes only the bare name can still
/// finish a phrase with it (name `no`, `550 no such entry: Permission denied`); no known server
/// does (cleanup review C-4).
fn says_absent(reply: &str, full: &str) -> bool {
    let sent = full.to_lowercase();
    let own = if sent.is_empty() { reply.to_lowercase() } else { reply.to_lowercase().replace(&sent, "\n") };
    ABSENT.iter().any(|p| own.contains(p) && !sent.contains(p))
}

/// Continue an upload at `offset`: APPE, or REST+STOR (`true`) where APPE is refused.
/// ProFTPD refuses both on an existing file unless AllowStoreRestart is on.
fn resume_upload<T: TlsStream>(
    ftp: &mut ImplFtpStream<T>,
    name: &str,
    offset: u64,
) -> Result<(TransferStream<T>, bool)> {
    match ftp.append_with_stream(name) {
        Ok(s) => Ok((s, false)),
        Err(FtpError::UnexpectedResponse(r)) if r.status != Status::NotAvailable => {
            log::warn!(target: "vibeftp", "{name}: APPE refused ({}); trying REST and STOR", reply_text(&r));
            ftp.resume_transfer(offset as usize)?;
            Ok((ftp.put_with_stream(name)?, true))
        }
        Err(e) => Err(e.into()),
    }
}

/// End an upload's data connection with a reset instead of a clean close, so the server
/// records a failed transfer rather than a finished short file. The control link stays in
/// use: dropping the stream reads the server's reply (426/451).
fn abort_data<T: TlsStream>(mut stream: TransferStream<T>) {
    let sock = stream.get_ref().get_ref();
    reset_on_close(sock);
    // Dropping TLS sends close_notify, a clean end: swap in a plain handle on the same socket
    // and let the TLS layer go without it.
    if let Ok(dup) = sock.try_clone() {
        let tls = std::mem::replace(stream.get_mut(), DataStream::Tcp(dup));
        let _ = tls.into_tcp_stream();
    }
    drop(stream);
}

/// SO_LINGER 0: the last close of this socket sends RST instead of FIN.
#[cfg(windows)]
fn reset_on_close(sock: &TcpStream) {
    use std::os::windows::io::AsRawSocket;
    #[repr(C)]
    struct Linger {
        onoff: u16,
        linger: u16,
    }
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(s: usize, level: i32, name: i32, val: *const Linger, len: i32) -> i32;
    }
    const SOL_SOCKET: i32 = 0xffff;
    const SO_LINGER: i32 = 0x0080;
    let l = Linger { onoff: 1, linger: 0 };
    // SAFETY: a live socket handle and a LINGER struct of the size passed.
    unsafe { setsockopt(sock.as_raw_socket() as usize, SOL_SOCKET, SO_LINGER, &l, size_of_val(&l) as i32) };
}
#[cfg(not(windows))]
fn reset_on_close(_sock: &TcpStream) {} // elsewhere the close stays a clean one

/// 451/452/552 in answer to an upload's data: a full disk or quota. vsftpd says "451 Failure
/// writing to local file", ProFTPD 452/552, Pure-FTPd 451/552, sftpgo "451 Issue during transfer".
fn is_storage_reply(r: &Response) -> bool {
    matches!(r.status, Status::ActionAborted | Status::RequestedActionNotTaken | Status::ExceededStorage)
}

/// The server's verdict on an upload it did not finish. A storage reply becomes a storage
/// error, so a tree stops instead of truncating one existing file after another.
fn refused_upload(r: Response, name: &str) -> AppError {
    if is_storage_reply(&r) {
        AppError::Io(std::io::Error::new(
            ErrorKind::StorageFull,
            format!("{name}: the server stopped taking the upload ({}); out of space or over quota?", reply_text(&r)),
        ))
    } else {
        AppError::Ftp(FtpError::UnexpectedResponse(r))
    }
}

fn reply_text(r: &Response) -> String {
    String::from_utf8_lossy(&r.body).trim_end().to_string()
}

/// Windows-hosted servers hand paths to Win32, which drops trailing dots and spaces (`x.txt `
/// is `x.txt` there), and ProFTPD's SITE loses edge spaces. When that trimmed twin exists, the
/// command could act on it instead of the file the user picked.
fn guard_twin(i: &mut Inner, path: &str) -> Result<()> {
    let (dir, name) = split_remote(path);
    let bare = name.trim_start_matches(' ').trim_end_matches([' ', '.']);
    if bare == name || bare.is_empty() {
        return Ok(());
    }
    if list_in(i, &dir, true)?.iter().any(|e| e.name == bare) {
        return Err(AppError::Msg(format!(
            "{name:?}: the server may act on {bare:?} instead (it can drop edge spaces and trailing dots); handle it another way"
        )));
    }
    Ok(())
}

/// Right before STOR creates `name` in the working folder `dir`, which a listing showed free:
/// `Ok` only when the server shows it still is, `NameTaken` with what is there (or `now: None`
/// when the server will not say). "Free" is proven, never inferred (review R2-1, R2-2): by an
/// MLST the server answers "no such file" (`mlst_in`), or by a complete listing of the folder
/// (the session's own if it is under `RECENT` old) without the name. In order: MLST where the
/// server has it (one command either way); SIZE, where 213 is a file there (a 550 says nothing,
/// in whatever words: a drop box refuses SIZE for its files too); then the listing. The same in
/// every folder, also one this transfer made. Leaves the working folder at `dir`.
fn look_free(i: &mut Inner, dir: &str, full: &str, name: &str) -> Result<()> {
    let taken = |e: Entry| AppError::NameTaken { name: name.to_string(), now: Some(e) };
    match mlst_in(i, full, name)? {
        Some(Some(e)) => return Err(taken(e)),
        Some(None) => return Ok(()),
        None => {}
    }
    if i.size != Some(false) {
        match i.ftp.size(name) {
            Ok(size) => {
                let modified = mdtm_of(i, name)?;
                let e = Entry { name: name.to_string(), path: full.to_string(), is_dir: false, is_link: false, size: size as u64, modified, mode: None };
                return Err(taken(e));
            }
            Err(e) if is_unsupported(&e) => i.size = Some(false),
            Err(e) => {
                let e = AppError::Ftp(e);
                if e.is_connection_error() {
                    return Err(e);
                }
            }
        }
    }
    let rows = match recent_listing(i, dir) {
        Some(rows) => rows,
        None => {
            let rows = match list_in(i, dir, true) {
                Ok(rows) => rows,
                Err(e) if e.is_connection_error() => return Err(e),
                Err(_) => return Err(AppError::NameTaken { name: name.to_string(), now: None }),
            };
            i.ftp.cwd(dir)?; // the listing may have looked into links
            Arc::new(rows)
        }
    };
    // A name that differs only by case or Unicode form is asked about: on a server that folds
    // them it is the file STOR replaces.
    match rows.iter().find(|e| e.name == name).or_else(|| rows.iter().find(|e| super::same_name(&e.name, name))) {
        Some(e) => Err(taken(e.clone())),
        None => Ok(()),
    }
}

/// Existence check on the link (see `FtpConn::stat`, `stat_any_case`).
fn stat_in(i: &mut Inner, full: &str, any_case: bool) -> Result<Option<Entry>> {
    let (dir, name) = split_remote(full);
    let full = full.to_string();
    // One round trip and no data connection: a new file must not cost a listing of
    // its whole folder.
    if let Some(known) = mlst_in(i, &full, &name)? {
        return Ok(known);
    }
    i.ftp.cwd(&dir)?;
    match i.ftp.size(&name) {
        Ok(size) => {
            // MDTM is optional, but a dead link must not read as "unknown date".
            if let Err(e) = i.ftp.noop() {
                let e = AppError::Ftp(e);
                if e.is_connection_error() {
                    return Err(e);
                }
            }
            let modified = mdtm_of(i, &name)?;
            return Ok(Some(Entry {
                name,
                path: full,
                is_dir: false,
                is_link: false,
                size: size as u64,
                modified,
                mode: None,
            }));
        }
        Err(e) => {
            let e = AppError::Ftp(e);
            if e.is_connection_error() {
                return Err(e);
            }
        }
    }
    // Not a file, or SIZE refused: a folder?
    match i.ftp.cwd(&full) {
        Ok(()) => {
            return Ok(Some(Entry {
                name,
                path: full,
                is_dir: true,
                is_link: false,
                size: 0,
                modified: 0,
                mode: None,
            }))
        }
        Err(FtpError::UnexpectedResponse(_)) => {}
        Err(e) => return Err(e.into()),
    }
    // SIZE refused: unsupported, denied (a write-only file) or really not there. Only
    // the listing can tell those apart, so it always gets the last word; when it is
    // refused too (a drop box) the answer is an error, never "absent": a Skip that
    // trusted it would overwrite. Callers decide what a blind write may do.
    let entries = list_in(i, &dir, true)?;
    if let Some(e) = entries.iter().find(|e| e.name == name) {
        return Ok(Some(e.clone()));
    }
    if !any_case {
        return Ok(None);
    }
    let Some(e) = entries.iter().find(|e| super::same_name(&e.name, &name)) else {
        return Ok(None);
    };
    // The other spelling answers SIZE (or CWD) where ours did not: the server keeps the
    // two apart, so ours is absent. Only when neither answers is the variant our file.
    let answered = if e.is_dir { i.ftp.cwd(&e.path).map(|_| ()) } else { i.ftp.size(&e.path).map(|_| ()) };
    match answered {
        Ok(()) => Ok(None),
        Err(err) => {
            let err = AppError::Ftp(err);
            if err.is_connection_error() { Err(err) } else { Ok(Some(e.clone())) }
        }
    }
}

/// MDTM in Unix ms. A refusal is "unknown date" (0); a timeout leaves the reply in the socket
/// for the next command to misread, so it must surface.
fn mdtm_of(i: &mut Inner, name: &str) -> Result<u64> {
    match i.ftp.mdtm(name) {
        Ok(t) => Ok(t.and_utc().timestamp_millis().max(0) as u64),
        Err(e) => {
            let e = AppError::Ftp(e);
            if e.is_connection_error() { Err(e) } else { Ok(0) }
        }
    }
}

/// SIZE that distinguishes "server won't say" from "the link is gone".
fn size_of(i: &mut Inner, name: &str) -> Result<Option<u64>> {
    match i.ftp.size(name) {
        Ok(s) => Ok(Some(s as u64)),
        Err(e) => {
            let e = AppError::Ftp(e);
            if e.is_connection_error() {
                Err(e)
            } else {
                Ok(None)
            }
        }
    }
}

/// Read a listing through the data channel, tolerating servers that close the
/// TLS data socket without close_notify (rustls reports UnexpectedEof). Also returns the
/// completion reply when it says the server cut the listing short.
/// The listing is held to `i.bounds` as it arrives (IN-VibeFTP-1): rows, bytes, the length of a
/// line, and an overall deadline. Past any of them the link is dropped (the server is still
/// sending) and the listing fails; it is never returned as complete.
fn read_listing(i: &mut Inner, cmd: &str, dir: &str) -> Result<(Vec<String>, Option<String>)> {
    let bounds = i.bounds;
    let (_reply, mut stream) = i
        .ftp
        .custom_data_command(cmd, &[Status::AboutToSend, Status::AlreadyOpen])?;
    arm_data_timeouts(&stream);
    let deadline = Instant::now() + bounds.deadline;
    let mut lines = Lines::new(bounds);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        // Each read waits at most until the deadline, so a trickle is cut there, not later.
        let left = deadline.saturating_duration_since(Instant::now());
        let over = if left.is_zero() {
            Some(Over::Slow)
        } else {
            let wait = left.min(IO_TIMEOUT);
            let _ = stream.get_ref().get_ref().set_read_timeout(Some(wait));
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => lines.push(&chunk[..n]).err(),
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                // A read that waited out what was left of the deadline is the deadline, even when
                // the system's timer fired a hair early.
                Err(e) if Instant::now() >= deadline || (wait == left && matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)) => Some(Over::Slow),
                Err(e) => return Err(e.into()),
            }
        };
        if let Some(over) = over {
            drop_link(i, stream, "the listing went past its bounds");
            return Err(over.error(&bounds, dir));
        }
    }
    let lines = match lines.finish() {
        Ok(l) => l,
        Err(over) => {
            drop_link(i, stream, "the listing went past its bounds");
            return Err(over.error(&bounds, dir));
        }
    };
    let mut cut = None;
    if i.pure_ftpd {
        // Pure-FTPd stops at max_ls_files and still answers `226 Output truncated to N
        // matches`, but finish() drops the reply text. So close the data socket, let a NOOP's
        // reply read take the pending 226 (its text is kept), and let finish() read the NOOP's.
        let _ = stream.get_ref().get_ref().shutdown(Shutdown::Both);
        let done = i
            .ftp
            .custom_command("NOOP", &[Status::ClosingDataConnection, Status::RequestedFileActionOk]);
        match stream.finish() {
            Ok(()) | Err(FtpError::UnexpectedResponse(_)) => {}
            Err(e) => return Err(e.into()),
        }
        let done = done?;
        let text = reply_text(&done);
        if text.to_ascii_lowercase().contains("truncated") {
            cut = text.lines().last().map(|l| l.trim().to_string());
        }
    } else {
        stream.finish()?;
    }
    Ok((lines, cut))
}

/// Which bound a listing went past.
#[derive(Debug, PartialEq)]
enum Over {
    Many,
    Big,
    Long,
    Slow,
}

impl Over {
    fn error(&self, b: &ListBounds, dir: &str) -> AppError {
        match self {
            Over::Many => b.too_many(dir),
            Over::Big => b.too_big(dir),
            Over::Long => b.too_long(dir),
            Over::Slow => b.too_slow(dir),
        }
    }
}

/// A listing's bytes as lines, split as they arrive and held to the bounds: what the old
/// `from_utf8_lossy(all).lines()` gave (CRs at a line's end dropped, empty lines skipped), with
/// never more than one line and the rows kept in memory.
struct Lines {
    bounds: ListBounds,
    total: usize,
    line: Vec<u8>,
    out: Vec<String>,
}

impl Lines {
    fn new(bounds: ListBounds) -> Lines {
        Lines { bounds, total: 0, line: Vec::new(), out: Vec::new() }
    }

    fn push(&mut self, bytes: &[u8]) -> std::result::Result<(), Over> {
        self.total += bytes.len();
        if self.total > self.bounds.bytes {
            return Err(Over::Big);
        }
        for part in bytes.split_inclusive(|&b| b == b'\n') {
            let (body, ends) = match part.strip_suffix(b"\n") {
                Some(body) => (body, true),
                None => (part, false),
            };
            if self.line.len() + body.len() > self.bounds.line {
                return Err(Over::Long);
            }
            self.line.extend_from_slice(body);
            if ends {
                self.end_line()?;
            }
        }
        Ok(())
    }

    fn end_line(&mut self) -> std::result::Result<(), Over> {
        let text = String::from_utf8_lossy(&self.line);
        let row = text.trim_end_matches('\r');
        if !row.is_empty() {
            if self.out.len() >= self.bounds.entries {
                return Err(Over::Many);
            }
            self.out.push(row.to_string());
        }
        self.line.clear();
        Ok(())
    }

    fn finish(mut self) -> std::result::Result<Vec<String>, Over> {
        if !self.line.is_empty() {
            self.end_line()?;
        }
        Ok(self.out)
    }
}

/// A stalled data connection must not hang the control connection's mutex forever.
fn arm_data_timeouts<T: suppaftp::TlsStream>(stream: &suppaftp::TransferStream<T>) {
    let sock = stream.get_ref().get_ref();
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
}

/// Cancel a running transfer. ABOR reply sequences differ between servers and
/// desync the control channel, so instead tear the whole connection down; the
/// session pool redials transparently on the next operation.
fn kill_transfer<T: suppaftp::TlsStream>(i: &mut Inner, stream: suppaftp::TransferStream<T>) {
    let _ = i.ftp.get_ref().shutdown(std::net::Shutdown::Both);
    let _ = stream.get_ref().get_ref().shutdown(std::net::Shutdown::Both);
    // Both sockets are down, so the stream's Drop (close + reply read) fails fast.
    drop(stream);
    i.dead.store(true, Ordering::SeqCst);
    log::info!(target: "vibeftp", "FTP transfer cancelled, connection dropped");
}

/// As `kill_transfer`, for a server that is still sending what VibeFTP will not take (a
/// listing past its bounds, a file past its size): the link is dropped and redialled later.
fn drop_link<T: suppaftp::TlsStream>(i: &mut Inner, stream: suppaftp::TransferStream<T>, why: &str) {
    let _ = i.ftp.get_ref().shutdown(std::net::Shutdown::Both);
    let _ = stream.get_ref().get_ref().shutdown(std::net::Shutdown::Both);
    drop(stream);
    i.dead.store(true, Ordering::SeqCst);
    log::warn!(target: "vibeftp", "FTP connection dropped: {why}");
}

/// A download that went past the size its server announced (IN-VibeFTP-3).
pub(super) fn oversized(name: &str, size: u64) -> AppError {
    AppError::Msg(format!("{name}: the server sent more than the {size} bytes it announced; the download was stopped"))
}

fn is_unsupported(e: &FtpError) -> bool {
    matches!(
        e,
        FtpError::UnexpectedResponse(r)
            if matches!(
                r.status,
                Status::BadCommand | Status::NotImplemented | Status::NotImplementedParameter
            )
    )
}

/// `strict`: a listing the server cut short is an error (for callers that read a missing
/// name as "absent"); otherwise it is returned as far as it goes, with a warning.
fn list_in(i: &mut Inner, path: &str, strict: bool) -> Result<Vec<Entry>> {
    i.ftp.cwd(path)?;
    let dir = match i.ftp.pwd() {
        Ok(p) => unquote_pwd(p),
        Err(e) => {
            let e = AppError::Ftp(e);
            if e.is_connection_error() {
                return Err(e); // a late reply would pair with the next command
            }
            path.to_string()
        }
    };

    // (line, parsed, from_mlsd, link type the parser cannot express)
    let mut rows: Vec<(String, FtpFile, bool, bool)> = Vec::new();
    let mut unparsed = 0;

    let mut cut = None;
    let mlsd_lines = match i.mlsd {
        Some(false) => None,
        _ => match read_listing(i, "MLSD", &dir) {
            Ok((lines, c)) => {
                i.mlsd = Some(true);
                cut = c;
                Some(lines)
            }
            // Only a "don't know that command" reply downgrades us for good.
            Err(AppError::Ftp(e)) if is_unsupported(&e) => {
                i.mlsd = Some(false);
                None
            }
            Err(e) => return Err(e),
        },
    };

    match mlsd_lines {
        Some(lines) => {
            for l in lines {
                let Some((l, link)) = mlsd_line(&l) else { continue };
                match ListParser::parse_mlsd(&l) {
                    Ok(f) => rows.push((l, f, true, link)),
                    Err(_) => unparsed += 1,
                }
            }
        }
        None => {
            // `LIST -a` shows dotfiles on vsftpd and friends; fall back to plain LIST once.
            let (lines, c) = match i.list_all {
                Some(false) => read_listing(i, "LIST", &dir)?,
                Some(true) => read_listing(i, "LIST -a", &dir)?,
                None => match read_listing(i, "LIST -a", &dir) {
                    Ok(l) => {
                        i.list_all = Some(true);
                        l
                    }
                    // Only "-a not understood" (500/501/502/504, or a 550 from a server that read
                    // "-a" as a path) means plain LIST: after a failed data connection it would
                    // hide dotfiles for the rest of the session, and Skip would overwrite them.
                    Err(AppError::Ftp(FtpError::UnexpectedResponse(r)))
                        if matches!(
                            r.status,
                            Status::BadCommand
                                | Status::BadArguments
                                | Status::NotImplemented
                                | Status::NotImplementedParameter
                                | Status::FileUnavailable
                        ) =>
                    {
                        let l = read_listing(i, "LIST", &dir)?;
                        i.list_all = Some(false);
                        l
                    }
                    Err(e) => return Err(e),
                },
            };
            cut = c;
            for l in lines {
                // `ls`-based servers (busybox, BSD ftpd) start with a "total N" line.
                if l.strip_prefix("total ").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
                    continue;
                }
                // POSIX or DOS rows only: suppaftp's last-resort MLST parser would turn any
                // other line into a file named after the whole line.
                match ListParser::parse_posix(&acl_free(&l)).or_else(|_| ListParser::parse_dos(&dos_two_digit_year(&l))) {
                    Ok(f) => rows.push((l, f, false, false)),
                    Err(_) => unparsed += 1,
                }
            }
        }
    }
    if unparsed > 0 {
        log::warn!(target: "vibeftp", "{} listing line(s) in {} could not be parsed", unparsed, dir);
    }
    if let Some(reply) = cut {
        if strict {
            return Err(AppError::Msg(format!(
                "{dir}: the server cut the listing short ({reply}), so it cannot tell what is there"
            )));
        }
        log::warn!(target: "vibeftp", "{dir}: the server cut the listing short ({reply}); the rest is not shown");
    }

    let mut out = Vec::new();
    for (line, f, from_mlsd, link) in rows {
        let dos = line.starts_with(|c: char| c.is_ascii_digit());
        let name = if from_mlsd {
            f.name().to_string()
        } else if dos {
            dos_name(&line, f.name())
        } else {
            posix_name(&line, f.name())
        };
        if name == "." || name == ".." {
            continue;
        }
        // A link to a folder must open like one (cPanel's `www`); the listing only says
        // "link", so ask the server once per link, as SFTP does.
        let mut is_dir = f.is_directory();
        if (link || f.is_symlink()) && !is_dir {
            match i.ftp.cwd(join_remote(&dir, &name)) {
                Ok(()) => is_dir = true,
                Err(FtpError::UnexpectedResponse(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // Permission bits are only real when the server actually sent them. suppaftp keeps
        // just rwx, so the special bits come straight from the fact / permission column.
        let mode = if from_mlsd {
            mlsd_mode(&line)
        } else if dos {
            None // DOS-style listing: no mode information
        } else {
            Some(posix_mode(&line).unwrap_or_else(|| mode_of(&f)))
        };
        out.push(Entry {
            path: join_remote(&dir, &name),
            name,
            is_dir,
            is_link: link || f.is_symlink(),
            size: f.size() as u64,
            modified: millis(f.modified()),
            mode,
        });
    }
    if strict {
        remember_listing(i, path, &out);
    }
    Ok(out)
}

/// The name as it stands in a POSIX `LIST` row. The parser trims the run of spaces between
/// the date and the name, so ` report.txt` came back as `report.txt` (and collided with
/// its sibling). Servers put exactly one space there: the rest belongs to the name.
/// Symlink rows (`a -> b`) are left to the parser.
fn posix_name(line: &str, parsed: &str) -> String {
    if parsed.is_empty() || !line.ends_with(parsed) {
        return parsed.to_string();
    }
    let before = &line[..line.len() - parsed.len()];
    let spaces = before.len() - before.trim_end_matches(' ').len();
    if spaces > 1 {
        format!("{}{}", " ".repeat(spaces - 1), parsed)
    } else {
        parsed.to_string()
    }
}

/// `drwxr-xr-x+` (ACL), `@` (extended attributes) or `.` (SELinux) after the mode column:
/// suppaftp's POSIX parser wants exactly ten mode characters.
fn acl_free(line: &str) -> std::borrow::Cow<'_, str> {
    let b = line.as_bytes();
    if b.len() > 11 && matches!(b[10], b'+' | b'@' | b'.') && b[11] == b' ' && b[..10].is_ascii() {
        format!("{}{}", &line[..10], &line[11..]).into()
    } else {
        line.into()
    }
}

/// IIS with four-digit years (`01-15-2024  10:30AM ...`): suppaftp's DOS parser wants two.
fn dos_two_digit_year(line: &str) -> std::borrow::Cow<'_, str> {
    let b = line.as_bytes();
    let four = b.len() > 11
        && b[..10].iter().enumerate().all(|(i, c)| if i == 2 || i == 5 { *c == b'-' } else { c.is_ascii_digit() })
        && b[10] == b' ';
    if four {
        format!("{}{}", &line[..6], &line[8..]).into()
    } else {
        line.into()
    }
}

/// The name as it stands in an IIS MS-DOS `LIST` row: the parser trims the spaces before it,
/// so ` report.txt` came back as `report.txt` (and collided with its sibling). IIS puts the
/// name at a fixed column: after the date, two spaces, a 7-character time and a 22-character
/// size or `<DIR>` field.
fn dos_name(line: &str, parsed: &str) -> String {
    let col = line.find(' ').unwrap_or(0) + 31;
    match line.get(col..) {
        Some(rest) if line.as_bytes()[col - 1] == b' ' && rest.len() > parsed.len() && rest.trim_start_matches(' ') == parsed => {
            rest.to_string()
        }
        _ => parsed.to_string(),
    }
}

/// suppaftp keeps the text between the first and last quote of the PWD reply; inside
/// it a quote is doubled (RFC 959), so `"/has""quote"` is the folder `/has"quote`.
fn unquote_pwd(p: String) -> String {
    p.replace("\"\"", "\"")
}

/// Pre-digest an MLSD line: drop `.`/`..` by their type fact (not by searching the whole
/// line, which includes the name) and turn OS-specific link types (`OS.unix=slink:/t`,
/// `OS.unix=symlink`) into plain files flagged as links; suppaftp refuses those outright.
fn mlsd_line(line: &str) -> Option<(String, bool)> {
    // No facts at all (RFC 3659 7.2): a space and the name, which may itself contain "; ".
    if line.starts_with(' ') {
        return Some((line.to_string(), false));
    }
    let Some(split) = line.find("; ") else {
        return Some((line.to_string(), false));
    };
    let (facts, name) = (&line[..split], &line[split + 2..]);
    let mut out: Vec<String> = Vec::new();
    let mut link = false;
    for fact in facts.split(';') {
        let lower = fact.to_ascii_lowercase();
        // ProFTPD and Pure-FTPd print the mode as `0%o`: `00` for mode 0, `07`, `01777`.
        // suppaftp accepts exactly three or four digits, so re-emit it as four. A mode that
        // carries the file type says "link" too (`0120777`; review R2-4).
        if let Some(m) = lower.strip_prefix("unix.mode=")
            && (1..=7).contains(&m.len()) && m.bytes().all(|b| (b'0'..=b'7').contains(&b))
            && let Ok(v) = u32::from_str_radix(m, 8)
        {
            link |= v & 0o170000 == 0o120000;
            out.push(format!("UNIX.mode={:04o}", v & 0o7777));
            continue;
        }
        if let Some(t) = lower.strip_prefix("type=") {
            if t == "cdir" || t == "pdir" {
                return None;
            }
            if t.starts_with("os.unix=slink") || t.starts_with("os.unix=symlink") {
                link = true;
                out.push("type=file".to_string());
                continue;
            }
        }
        // A leap second (`...60`) on a date before 1970 overflows inside suppaftp's time
        // parser, and a panic aborts the release build: take the second before it.
        if let Some(v) = lower.strip_prefix("modify=")
            && v.len() >= 14 && v.as_bytes()[..14].iter().all(u8::is_ascii_digit) && &v[12..14] == "60"
        {
            out.push(format!("{}59{}", &fact[..19], &fact[21..]));
            continue;
        }
        out.push(fact.to_string());
    }
    Some((format!("{}; {name}", out.join(";")), link))
}

/// The full `UNIX.mode=` fact (setuid/setgid/sticky included), when the server sent one.
fn mlsd_mode(line: &str) -> Option<u32> {
    if line.starts_with(' ') {
        return None; // factless line: the name may contain "; "
    }
    let facts = line.find("; ").map(|i| &line[..i]).unwrap_or("");
    facts.split(';').find_map(|f| {
        let (k, v) = f.split_once('=')?;
        if !k.eq_ignore_ascii_case("unix.mode") {
            return None;
        }
        u32::from_str_radix(v, 8).ok().map(|m| m & 0o7777)
    })
}

/// Permission bits from a `-rwsr-sr-t` column, special bits included.
fn posix_mode(line: &str) -> Option<u32> {
    let perm: Vec<char> = line.chars().take(10).collect();
    if perm.len() < 10 || !matches!(perm[0], '-' | 'd' | 'l' | 'b' | 'c' | 'p' | 's') {
        return None;
    }
    let mut m = 0u32;
    for (i, c) in perm[1..].iter().enumerate() {
        let shift = 6 - (i / 3) * 3;
        let bit = [4u32, 2, 1][i % 3];
        let special = match i {
            2 => 0o4000,
            5 => 0o2000,
            8 => 0o1000,
            _ => 0,
        };
        match c {
            'r' | 'w' | 'x' => m |= bit << shift,
            's' | 't' => m |= (1 << shift) | special,
            'S' | 'T' => m |= special,
            '-' => {}
            _ => return None,
        }
    }
    Some(m)
}

fn mode_of(f: &FtpFile) -> u32 {
    let mut m = 0;
    for (who, shift) in [
        (PosixPexQuery::Owner, 6),
        (PosixPexQuery::Group, 3),
        (PosixPexQuery::Others, 0),
    ] {
        if f.can_read(who) {
            m |= 0o4 << shift;
        }
        if f.can_write(who) {
            m |= 0o2 << shift;
        }
        if f.can_execute(who) {
            m |= 0o1 << shift;
        }
    }
    m
}

/// One shared rustls config per connection: the data channel reuses it, which
/// gives TLS session resumption (many FTPS servers refuse data connections without it).
/// TLS 1.2 only unless `tls13` (see `open` for why).
fn tls_config(verifier: Arc<PinnedCert>, tls13: bool) -> Arc<ClientConfig> {
    let versions: &[&rustls::SupportedProtocolVersion] = if tls13 {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS12]
    };
    let cfg = ClientConfig::builder_with_provider(verifier.provider())
        .with_protocol_versions(versions)
        .expect("rustls protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// FTPS certificate check. A certificate a public authority issued for this host name passes
/// as on the web; any other (self-signed, private CA, another name, expired) must be the one
/// the user pinned for the site, by SHA-256 of the server's own certificate, the way an SSH
/// host key is pinned. Unpinned, the handshake stops before the password is sent.
/// Resumed data-channel handshakes skip this; their session came from a checked one.
#[derive(Debug)]
struct PinnedCert {
    webpki: Arc<WebPkiServerVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    pin: Option<String>,
    /// Fingerprint of the certificate presented (pool dials pin it).
    seen: Mutex<Option<String>>,
    /// (fingerprint, why) of a certificate turned down.
    refused: Mutex<Option<(String, String)>>,
}

impl PinnedCert {
    fn new(pin: Option<String>) -> Self {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("webpki verifier");
        PinnedCert {
            webpki,
            provider,
            pin,
            seen: Mutex::new(None),
            refused: Mutex::new(None),
        }
    }

    fn provider(&self) -> Arc<rustls::crypto::CryptoProvider> {
        self.provider.clone()
    }
}

/// `SHA256:<base64>` of a DER certificate, the format SSH fingerprints are shown in.
fn cert_fingerprint(der: &[u8]) -> String {
    let digest = russh::keys::HashAlg::Sha256.digest(der);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    russh::keys::ssh_key::Fingerprint::Sha256(bytes).to_string()
}

/// An FTPS fingerprint as people compare it (X15CRY-2): the certificate's SHA-256 in uppercase
/// hex, a colon between bytes, as `openssl x509 -fingerprint -sha256` and FileZilla print it.
/// Pins stay in `cert_fingerprint`'s form; this is for showing them only. Anything that isn't
/// such a fingerprint is given back as it is.
pub fn cert_fingerprint_hex(fp: &str) -> String {
    match fp.parse::<russh::keys::ssh_key::Fingerprint>() {
        Ok(russh::keys::ssh_key::Fingerprint::Sha256(b)) => b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":"),
        _ => fp.to_string(),
    }
}

/// Plain words for why a certificate is not publicly trusted.
fn cert_reason(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::UnknownIssuer => "not issued by a public authority".into(),
            C::Expired | C::ExpiredContext { .. } => "expired".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "not valid yet".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => "issued for another host name".into(),
            C::Other(o) if o.to_string().contains("CaUsedAsEndEntity") => "self-signed".into(),
            other => format!("{other:?}"),
        },
        other => other.to_string(),
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity.as_ref());
        *self.seen.lock().unwrap() = Some(fp.clone());
        match self.webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Ok(v) => Ok(v),
            Err(_) if self.pin.as_deref() == Some(fp.as_str()) => Ok(ServerCertVerified::assertion()),
            Err(e) => {
                log::warn!(target: "vibeftp", "Certificate {fp} not trusted: {e}");
                *self.refused.lock().unwrap() = Some((fp, cert_reason(&e)));
                Err(e)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}
