use super::{Ctx, Fresh, ListBounds, Seen, CHUNK, LIST_BOUNDS};
use std::sync::atomic::{AtomicBool, Ordering};
use crate::error::{AppError, Result};
use crate::types::{join_remote, millis, split_remote, Entry, Site};
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{load_secret_key, Algorithm, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::Disconnect;
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use std::io::SeekFrom;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

struct Handler {
    /// The pinned fingerprint (`SHA256:…`), without its algorithm.
    expected: Option<String>,
    /// (algorithm, fingerprint) of the key the server presented.
    seen: Arc<Mutex<Option<(String, String)>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    /// Only a key we already trust gets through. An unknown key is recorded and
    /// refused so the UI can show the fingerprint before any credentials are sent.
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let (algo, fp) = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                (key.algorithm(), key.fingerprint(HashAlg::Sha256).to_string())
            }
            PublicKeyOrCertificate::Certificate(c) => (
                c.public_key().algorithm(),
                c.public_key().fingerprint(HashAlg::Sha256).to_string(),
            ),
        };
        let algo = algo.as_str().to_string();
        remember_algorithm(&fp, &algo);
        let ok = self.expected.as_deref() == Some(fp.as_str());
        *self.seen.lock().unwrap() = Some((algo, fp));
        Ok(ok)
    }
}

/// A known_hosts pin is `"<algorithm> SHA256:…"`; entries written before the algorithm
/// was stored are a bare `"SHA256:…"`. Returns (algorithm, fingerprint).
fn split_pin(pin: &str) -> (Option<&str>, &str) {
    match pin.split_once(' ') {
        Some((algo, fp)) => (Some(algo), fp),
        None => (None, pin),
    }
}

/// Fingerprints seen in handshakes this run, with their key algorithm. The host-key
/// prompt only hands back the fingerprint; the hash covers the whole key blob, so the
/// algorithm recorded for it here is exact.
static SEEN_ALGOS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

fn remember_algorithm(fp: &str, algo: &str) {
    let mut seen = SEEN_ALGOS.lock().unwrap();
    if !seen.iter().any(|(f, _)| f == fp) {
        if seen.len() >= 64 {
            seen.remove(0);
        }
        seen.push((fp.to_string(), algo.to_string()));
    }
}

/// The known_hosts entry for a fingerprint the user chose to trust: with its algorithm
/// when this run saw that key, else the bare fingerprint (the next connect adds it).
pub fn pin_entry(fingerprint: &str) -> String {
    let fp = split_pin(fingerprint).1;
    match SEEN_ALGOS.lock().unwrap().iter().find(|(f, _)| f == fp) {
        Some((_, algo)) => format!("{algo} {fp}"),
        None => fp.to_string(),
    }
}

/// Whether a pin lacks the algorithm that `entry` (from a matching connect) carries.
pub fn pin_needs_upgrade(pin: &str, entry: &str) -> bool {
    let (algo, fp) = split_pin(pin);
    let (new_algo, new_fp) = split_pin(entry);
    algo.is_none() && new_algo.is_some() && fp == new_fp
}

/// Ask for the pinned key's type first, as OpenSSH does: the server negotiates the
/// client's first choice it has, so a server that gains a key type (an RSA-only box gets
/// Ed25519) would otherwise present the new key and look like a changed one.
fn preferred_for(algo: Option<&str>) -> russh::Preferred {
    let mut p = russh::Preferred::default();
    let Some(want) = algo.and_then(|a| Algorithm::new(a).ok()) else {
        return p;
    };
    // An RSA key is offered under three signature names; keep all three together.
    let same = |k: &Algorithm| match want {
        Algorithm::Rsa { .. } => matches!(k, Algorithm::Rsa { .. }),
        _ => *k == want,
    };
    let mut keys: Vec<Algorithm> = p.key.iter().filter(|k| same(k)).cloned().collect();
    keys.extend(p.key.iter().filter(|k| !same(k)).cloned());
    p.key = keys.into();
    p
}

/// Why a handshake that saw a host key (`seen`: its algorithm and fingerprint) was refused, given
/// the pin (`pinned_algo`, `expected`); None when the key is not why. A key of another type than
/// the pinned one is a changed key (X15CRY-1): `preferred_for` asked for the pinned type first, so
/// a server that still has that key presents it, and only a server without it (an upgrade that
/// dropped the type, or an attacker in the middle, who picks the type) presents another.
fn key_refusal(host: &str, pinned_algo: Option<String>, expected: Option<String>, seen: Option<(String, String)>) -> Option<AppError> {
    let (new_type, actual) = seen?;
    Some(match expected {
        Some(exp) if pinned_algo.as_ref().is_some_and(|a| *a != new_type) => AppError::HostKeyTypeChanged {
            host: host.to_string(),
            old: format!("{} {exp}", pinned_algo.unwrap_or_default()),
            new_type,
            fingerprint: actual,
        },
        Some(exp) if exp != actual => AppError::HostKeyChanged { host: host.to_string(), expected: exp, actual },
        Some(_) => return None,
        None => AppError::HostKeyUnknown { host: host.to_string(), fingerprint: actual },
    })
}

/// A dial or handshake that ran out of time: a transport failure (so not a refusal that
/// lowers the pool's cap), with the text the user sees.
fn timed_out(what: &str) -> AppError {
    AppError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, what.to_string()))
}

/// Load the site's private key. Each format says "locked" or "wrong passphrase" in its own
/// words (OpenSSH and PEM "The key is encrypted", PuTTY "PPK parsing error: private key is
/// encrypted", encrypted PKCS#8 a DER tag error; wrong: "cryptographic error", "Padding
/// error", "incorrect MAC", "PKCS#5 decryption failed"), so an encrypted key file turns any
/// load failure into one of two fixed errors the UI asks the passphrase on.
pub fn load_key(path: &str, passphrase: Option<&str>) -> Result<russh::keys::PrivateKey> {
    use russh::keys::Error as K;
    match load_secret_key(path, passphrase) {
        Ok(k) => Ok(k),
        Err(e @ K::IO(_)) => Err(e.into()),
        Err(K::KeyIsEncrypted) if passphrase.is_none() => Err(AppError::Key(K::KeyIsEncrypted)),
        Err(e) => {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            if !key_is_encrypted(&text) {
                // A passphrase saved for a key that has none: PKCS#8 tries to decrypt with it.
                return match passphrase {
                    Some(_) => load_secret_key(path, None).map_err(|_| e.into()),
                    None => Err(e.into()),
                };
            }
            log::info!(target: "vibeftp", "Key {path} not unlocked: {e}");
            Err(match passphrase {
                None => AppError::Key(K::KeyIsEncrypted),
                Some(_) => AppError::WrongPassphrase,
            })
        }
    }
}

/// Whether a private key file is passphrase-protected, from its text alone.
fn key_is_encrypted(text: &str) -> bool {
    // PKCS#8 "BEGIN ENCRYPTED PRIVATE KEY", legacy PEM "Proc-Type: 4,ENCRYPTED".
    if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") || text.contains("Proc-Type: 4,ENCRYPTED") {
        return true;
    }
    // PuTTY: "Encryption: aes256-cbc" (or "none").
    if let Some(line) = text.lines().find(|l| l.starts_with("Encryption:")) {
        return line["Encryption:".len()..].trim() != "none";
    }
    // OpenSSH: the cipher name is readable without the passphrase.
    russh::keys::PrivateKey::from_openssh(text).is_ok_and(|k| k.is_encrypted())
}

pub struct SftpConn {
    handle: Handle<Handler>,
    sftp: SftpSession,
    /// The server refused an exclusive create for a name that was not there: new names are
    /// looked at, then created, for the rest of the session (review R-SOL-5).
    no_excl: Arc<AtomicBool>,
}

/// `stat` on the session (see `SftpConn::stat`).
async fn stat_on(sftp: &SftpSession, path: &str) -> Result<Option<Entry>> {
    match sftp.metadata(path).await {
        Ok(m) => Ok(Some(Entry {
            name: split_remote(path).1,
            path: path.to_string(),
            is_dir: m.is_dir(),
            is_link: false,
            size: m.len(),
            modified: m.modified().map(millis).unwrap_or(0),
            mode: m.permissions.map(|p| p & 0o7777),
        })),
        Err(e) if is_missing(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A folder's entries (see `SftpConn::list`), read within `bounds`. The deadline covers all of
/// it: the folder's name, the READDIR loop and the look behind every link (RINF-2).
async fn list_on(sftp: &SftpSession, path: &str, bounds: &ListBounds) -> Result<Vec<Entry>> {
    log::info!(target: "vibeftp", "SFTP ls {path}");
    let deadline = tokio::time::Instant::now() + bounds.deadline;
    let dir = match tokio::time::timeout_at(deadline, sftp.canonicalize(path)).await {
        Err(_) => return Err(bounds.too_slow(path)),
        Ok(r) => r.unwrap_or(path.to_string()),
    };
    let mut out = Vec::new();
    for (name, mut meta) in read_folder(sftp.raw(), &dir, bounds, deadline).await? {
        let full = join_remote(&dir, &name);
        if is_special(&meta) {
            continue;
        }
        let is_link = meta.is_symlink();
        if is_link {
            // Show what the link points at, but remember that it is a link.
            let target = match tokio::time::timeout_at(deadline, sftp.metadata(&full)).await {
                Err(_) => return Err(bounds.too_slow(&dir)),
                Ok(r) => r,
            };
            if let Ok(m) = target {
                // A link to a FIFO or device opens the device itself.
                if is_special(&m) {
                    continue;
                }
                meta = m;
            }
        }
        out.push(Entry {
            name,
            path: full,
            is_dir: meta.is_dir(),
            is_link,
            size: meta.len(),
            modified: meta.modified().map(millis).unwrap_or(0),
            mode: meta.permissions.map(|p| p & 0o7777),
        });
    }
    Ok(out)
}

/// OPENDIR, then READDIR until EOF, held to `bounds` (IN-VibeFTP-2): entries kept, bytes of
/// names and long names, the length of each, and an overall deadline. `.` and `..` are dropped
/// as they come (russh-sftp's `read_dir` reads until EOF without a limit, re-collects every batch
/// and recurses once per dot it skips). Past a bound the listing fails; the handle is closed
/// either way. `deadline`: the listing's, which `list_on` started.
async fn read_folder(raw: &RawSftpSession, dir: &str, bounds: &ListBounds, deadline: tokio::time::Instant) -> Result<Vec<(String, FileAttributes)>> {
    let handle = match tokio::time::timeout_at(deadline, raw.opendir(dir)).await {
        Err(_) => return Err(bounds.too_slow(dir)),
        Ok(r) => r?.handle,
    };
    let mut out = Vec::new();
    let mut bytes = 0usize;
    let read: Result<()> = 'read: loop {
        let batch = match tokio::time::timeout_at(deadline, raw.readdir(handle.as_str())).await {
            Err(_) => break Err(bounds.too_slow(dir)),
            Ok(Err(russh_sftp::client::error::Error::Status(s))) if s.status_code == StatusCode::Eof => break Ok(()),
            Ok(Err(e)) => break Err(e.into()),
            Ok(Ok(batch)) => batch,
        };
        for f in batch.files {
            bytes += f.filename.len() + f.longname.len();
            if bytes > bounds.bytes {
                break 'read Err(bounds.too_big(dir));
            }
            if f.filename.len() > bounds.line || f.longname.len() > bounds.line {
                break 'read Err(bounds.too_long(dir));
            }
            if f.filename == "." || f.filename == ".." {
                continue;
            }
            if out.len() >= bounds.entries {
                break 'read Err(bounds.too_many(dir));
            }
            out.push((f.filename, f.attrs));
        }
    };
    // Not waited for long: a server that stopped answering must not hold the listing's error.
    let _ = tokio::time::timeout(Duration::from_secs(5), raw.close(handle)).await;
    read.map(|()| out)
}

/// The entry at `path` as `list` shows it: the item itself first (lstat), so a link is a link
/// (review R2-4), with what it points at as its kind, size and date, or its own attributes when
/// the target cannot be read (a dangling link).
async fn listed_on(sftp: &SftpSession, path: &str) -> Result<Option<Entry>> {
    let own = match sftp.symlink_metadata(path).await {
        Ok(m) => m,
        Err(e) if is_missing(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let is_link = own.is_symlink();
    let m = match is_link {
        true => sftp.metadata(path).await.unwrap_or(own),
        false => own,
    };
    Ok(Some(Entry {
        name: split_remote(path).1,
        path: path.to_string(),
        is_dir: m.is_dir(),
        is_link,
        size: m.len(),
        modified: m.modified().map(millis).unwrap_or(0),
        mode: m.permissions.map(|p| p & 0o7777),
    }))
}

/// Open `remote` for an upload's first write. A resume continues a file that is there: if it
/// went away meanwhile, fail rather than create one holding only our tail. A name only a
/// listing showed free (`fresh`) is created exclusively, so a file that took it since is never
/// truncated (review SOL-FTP-1). A server that refuses the exclusive create for a name that is
/// not there (`OpUnsupported`, or a bare `Failure`) gets the FTP way: a look, then a plain create;
/// only when that plain create works was it the exclusive create that was refused, and the rest
/// of the session (until a reconnect) goes that way (`no_excl`, review R-SOL-5, R2-7). A plain
/// create that fails too (a full disk, a quota) is that error, and nothing is remembered.
async fn open_upload(sftp: &SftpSession, remote: &str, offset: u64, fresh: bool, no_excl: &AtomicBool) -> Result<russh_sftp::client::fs::File> {
    let name = || split_remote(remote).1;
    let plain = OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE;
    // What a look says about a name an exclusive create did not get (or was not tried on).
    let looked = |r: Result<Option<Entry>>| match r {
        Ok(Some(now)) => Err(AppError::NameTaken { name: name(), now: Some(now) }),
        Ok(None) => Ok(()),
        Err(e) if e.is_connection_error() => Err(e),
        Err(_) => Err(AppError::NameTaken { name: name(), now: None }),
    };
    if offset > 0 {
        return match sftp.open_with_flags(remote, OpenFlags::WRITE).await {
            Ok(f) => Ok(f),
            Err(e) if is_missing(&e) => Err(AppError::Msg(format!("{}: the file on the server is gone since it was looked at; nothing was sent", name()))),
            Err(e) => Err(e.into()),
        };
    }
    if !fresh {
        return Ok(sftp.open_with_flags(remote, plain).await?);
    }
    if no_excl.load(Ordering::Relaxed) {
        looked(stat_on(sftp, remote).await)?;
        return Ok(sftp.open_with_flags(remote, plain).await?);
    }
    match sftp.open_with_flags(remote, OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE).await {
        Ok(f) => Ok(f),
        // SFTP v3 says only "failure" for a name that exists: ask the server what is there.
        Err(e) if refused(&e) => {
            looked(stat_on(sftp, remote).await)?;
            let unsupported = matches!(&e, russh_sftp::client::error::Error::Status(s)
                if matches!(s.status_code, StatusCode::OpUnsupported | StatusCode::Failure));
            if !unsupported {
                return Err(e.into());
            }
            let f = sftp.open_with_flags(remote, plain).await?;
            if !no_excl.swap(true, Ordering::Relaxed) {
                log::warn!(target: "vibeftp", "The server refuses exclusive creates ({e}); new files are looked for first, then created, for the rest of this session");
            }
            Ok(f)
        }
        Err(e) => Err(e.into()),
    }
}

/// FIFOs, sockets, devices: opening one can wedge sftp-server. Only when the server
/// actually said so; missing type bits mean a plain file.
fn is_special(meta: &russh_sftp::protocol::FileAttributes) -> bool {
    matches!(
        meta.permissions.map(|p| p & 0o170000),
        Some(0o010000 | 0o020000 | 0o060000 | 0o140000)
    )
}

fn is_missing(e: &russh_sftp::client::error::Error) -> bool {
    matches!(e, russh_sftp::client::error::Error::Status(s) if s.status_code == StatusCode::NoSuchFile)
}

/// The server answered the request with a refusal (the session itself is fine).
fn refused(e: &russh_sftp::client::error::Error) -> bool {
    matches!(e, russh_sftp::client::error::Error::Status(s)
        if !matches!(s.status_code, StatusCode::ConnectionLost | StatusCode::NoConnection))
}

/// russh-sftp wraps its own errors in `io::Error` (kind Other) on the File
/// read/write path. Unwrap them so a dropped session is classified as such.
fn sftp_io(e: std::io::Error) -> AppError {
    let kind = e.kind();
    match e.into_inner() {
        Some(b) => match b.downcast::<russh_sftp::client::error::Error>() {
            Ok(inner) => AppError::Sftp(*inner),
            Err(b) => {
                // A refused WRITE/READ arrives as its bare message: keep "disk full"
                // recognisable, or a tree upload would truncate every remaining file.
                let msg = b.to_string();
                let lower = msg.to_ascii_lowercase();
                let kind = if lower.contains("quota") {
                    std::io::ErrorKind::QuotaExceeded
                } else if crate::error::mentions_storage(&msg) {
                    std::io::ErrorKind::StorageFull
                } else {
                    kind
                };
                AppError::Io(std::io::Error::new(kind, msg))
            }
        },
        None => AppError::Io(std::io::Error::from(kind)),
    }
}

/// SFTP v3 has status codes 0..=8. ProFTPD and Apache MINA also send newer ones to v3
/// clients (11 "file already exists" for a rename or mkdir onto an existing name, 18
/// "directory not empty"), which russh-sftp 3.0 cannot decode: it ends the whole session,
/// and the app redials and reruns the same request into the same wall. So the server's
/// packets pass through a pump that turns such a code into its v3 equivalent and keeps the
/// server's message. Remove once russh-sftp decodes unknown codes itself.
fn clamp_status<S>(stream: S) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(stream);
    // A duplex, not a simplex: when the session drops its end the pump's write fails and it stops.
    let (session_end, mut pump_end) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        let mut buf = Vec::new();
        while let Ok(len) = rd.read_u32().await {
            // russh-sftp's own packet limit: it would end the session on this frame too.
            if len > 256 * 1024 {
                log::warn!(target: "vibeftp", "SFTP packet of {len} bytes from the server; closing");
                break;
            }
            buf.resize(len as usize, 0);
            if rd.read_exact(&mut buf).await.is_err() {
                break;
            }
            // SSH_FXP_STATUS (101): request id, then the code.
            if buf.len() >= 9 && buf[0] == 101 {
                let code = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
                if code > 8 {
                    // NO_SUCH_PATH -> NO_SUCH_FILE, WRITE_PROTECT -> PERMISSION_DENIED, rest FAILURE.
                    let v3: u32 = match code {
                        10 => 2,
                        12 => 3,
                        _ => 4,
                    };
                    buf[5..9].copy_from_slice(&v3.to_be_bytes());
                }
            }
            if pump_end.write_all(&len.to_be_bytes()).await.is_err() || pump_end.write_all(&buf).await.is_err() {
                break;
            }
        }
        // Dropping `pump_end` gives the session its end of stream.
    });
    tokio::io::join(session_end, wr)
}

/// A WRITE or CLOSE the server refused after it let us open the file: OpenSSH reports a
/// full disk or an exceeded quota as a bare "Failure", so every such refusal must count as
/// storage exhaustion (skipping past it would truncate every remaining file of a tree).
fn write_refused(e: std::io::Error) -> AppError {
    let e = sftp_io(e);
    if e.is_connection_error() || e.is_storage_error() {
        return e;
    }
    match e {
        AppError::Io(io) => AppError::Io(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            format!("the server refused the write ({io}); out of space or over quota?"),
        )),
        other => other,
    }
}

impl SftpConn {
    /// `expected` is the known_hosts pin (`"<algorithm> SHA256:…"` or a bare fingerprint).
    /// With `None` the connection is refused with `HostKeyUnknown` carrying the fingerprint
    /// seen, before auth. Returns the connection, the canonical start directory and the
    /// pin entry of the key seen (`"<algorithm> SHA256:…"`).
    pub async fn connect(
        site: &Site,
        password: &str,
        expected: Option<String>,
    ) -> Result<(Self, String, String)> {
        let (pinned_algo, expected) = match expected.as_deref().map(split_pin) {
            Some((algo, fp)) => (algo.map(str::to_string), Some(fp.to_string())),
            None => (None, None),
        };
        let seen = Arc::new(Mutex::new(None));
        let handler = Handler {
            expected: expected.clone(),
            seen: seen.clone(),
        };
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(20)),
            keepalive_max: 3,
            nodelay: true,
            // russh only refills the receive window once it drops below half, so a 2 MiB
            // window lets about 1 MiB arrive per round trip and caps the 64 queued reads below.
            window_size: 4 * 1024 * 1024,
            preferred: preferred_for(pinned_algo.as_deref()),
            ..Default::default()
        });

        log::info!(target: "vibeftp", "SSH connecting to {}:{}", site.host, site.port);
        // Dial the socket ourselves: russh spawns its session task before the key exchange
        // is done and dropping the connect future does not stop it (a stalled handshake
        // would spin on its keepalive timer forever), so a timeout cuts the socket instead.
        // IPv4 first, like FTP: dual-stack hosts often resolve to an unreachable v6 address.
        let (host, port) = (site.host.clone(), site.port);
        // One 15 s budget for resolving and dialing, however many addresses the name has.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let dial = tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
            let mut addrs: Vec<std::net::SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
            if addrs.is_empty() {
                return Err(AppError::Msg(format!("Could not resolve {host}")));
            }
            addrs.sort_by_key(|a| a.is_ipv6());
            let mut last: Option<std::io::Error> = None;
            for a in &addrs {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                match std::net::TcpStream::connect_timeout(a, left) {
                    Ok(t) => {
                        // An FTP server greets with a reply code; the SSH handshake would wait
                        // for "SSH-" and end in "timed out" with no hint at the protocol.
                        let _ = t.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut b = [0u8; 4];
                        if let Ok(4) = t.peek(&mut b)
                            && b[..3].iter().all(u8::is_ascii_digit) && (b[3] == b' ' || b[3] == b'-')
                        {
                            return Err(AppError::Msg(format!(
                                "Port {port} answers like an FTP server, not SSH: choose FTP or FTPS for this site"
                            )));
                        }
                        let _ = t.set_read_timeout(None);
                        return Ok(t);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(match last {
                Some(e) => AppError::Io(e),
                None => timed_out("Connection timed out"),
            })
        });
        // DNS has no timeout of its own: a socket the blocking thread produces late is dropped.
        let std_tcp = match tokio::time::timeout(Duration::from_secs(16), dial).await {
            Err(_) => return Err(timed_out("Connection timed out")),
            Ok(joined) => joined.map_err(|e| AppError::Msg(e.to_string()))??,
        };
        std_tcp.set_nonblocking(true)?;
        let _ = std_tcp.set_nodelay(true);
        // A second handle on the same socket: shutting it down ends the session task.
        let cutter = std_tcp.try_clone()?;
        let tcp = tokio::net::TcpStream::from_std(std_tcp)?;
        let connect = client::connect_stream(config, tcp, handler);
        let mut handle = match tokio::time::timeout(Duration::from_secs(15), connect).await {
            Err(_) => {
                let _ = cutter.shutdown(std::net::Shutdown::Both);
                return Err(timed_out("Connection timed out"));
            }
            Ok(Err(e)) => {
                let seen = seen.lock().unwrap().clone();
                return Err(key_refusal(&site.host, pinned_algo, expected, seen).unwrap_or_else(|| e.into()));
            }
            Ok(Ok(h)) => h,
        };
        let fingerprint = match seen.lock().unwrap().clone() {
            Some((algo, fp)) => format!("{algo} {fp}"),
            None => String::new(),
        };
        log::info!(target: "vibeftp", "SSH host key {}", fingerprint);

        let rest = async {
            let mut ok = if !site.key_path.is_empty() {
                let passphrase = if password.is_empty() {
                    None
                } else {
                    Some(password)
                };
                let key = load_key(&site.key_path, passphrase)?;
                let hash = handle.best_supported_rsa_hash().await?.flatten();
                log::info!(target: "vibeftp", "SSH auth: public key {}", site.key_path);
                handle
                    .authenticate_publickey(
                        site.username.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await?
                    .success()
            } else {
                log::info!(target: "vibeftp", "SSH auth: password for {}", site.username);
                handle
                    .authenticate_password(site.username.clone(), password)
                    .await?
                    .success()
            };
            if !ok && site.key_path.is_empty() {
                // PAM-style servers only offer keyboard-interactive; answer every prompt with the password.
                log::info!(target: "vibeftp", "SSH auth: keyboard-interactive for {}", site.username);
                ok = keyboard_interactive(&mut handle, &site.username, password).await?;
            }
            if !ok {
                return Err(AppError::AuthFailed);
            }

            let channel = handle.channel_open_session().await?;
            channel.request_subsystem(true, "sftp").await?;
            // Throughput is bytes in flight per round trip: 64 requests both ways (OpenSSH
            // sftp's depth), 2 MiB against servers that answer 32 KiB per READ; writes stay
            // 32 KiB, the size every server accepts.
            // The request timeout counts from queueing, and OpenSSH answers 255 KiB per READ
            // (16 MiB queued), so it must be long: 300 s still drains that at ~56 KB/s. A
            // dead link is caught sooner by the 20 s x 3 keepalive, which ends the session.
            let cfg = russh_sftp::client::Config {
                request_timeout_secs: 300,
                max_concurrent_reads: 64,
                max_concurrent_writes: 64,
                ..Default::default()
            };
            let sftp = SftpSession::new_with_config(clamp_status(channel.into_stream()), cfg).await?;
            log::info!(target: "vibeftp", "SFTP subsystem ready");

            let start = if site.remote_path.is_empty() {
                "."
            } else {
                site.remote_path.as_str()
            };
            // A configured start folder that is gone is said so at connect (some servers
            // resolve a missing path without complaint).
            let missing = || {
                AppError::Msg(format!(
                    "Remote folder {start} is not on the server; change it in the site settings"
                ))
            };
            let cwd = match sftp.canonicalize(start).await {
                Ok(c) => c,
                Err(e) if !site.remote_path.is_empty() && is_missing(&e) => return Err(missing()),
                Err(e) => return Err(e.into()),
            };
            if !site.remote_path.is_empty() {
                match sftp.metadata(&cwd).await {
                    Err(e) if is_missing(&e) => return Err(missing()),
                    Ok(m) if m.permissions.is_some() && !m.is_dir() => return Err(missing()),
                    _ => {}
                }
            }
            Ok::<_, AppError>((handle, sftp, cwd))
        };
        let (handle, sftp, cwd) = match tokio::time::timeout(Duration::from_secs(20), rest).await {
            Err(_) => {
                let _ = cutter.shutdown(std::net::Shutdown::Both);
                return Err(timed_out("Server stopped responding during login"));
            }
            Ok(r) => r?,
        };

        Ok((SftpConn { handle, sftp, no_excl: Arc::new(AtomicBool::new(false)) }, cwd, fingerprint))
    }

    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        list_on(&self.sftp, path, &LIST_BOUNDS).await
    }

    pub async fn stat(&self, path: &str) -> Result<Option<Entry>> {
        stat_on(&self.sftp, path).await
    }

    /// Learn with the other links of the session whether the server refuses exclusive creates.
    pub fn share(&mut self, no_excl: &Arc<AtomicBool>) {
        if self.no_excl.load(Ordering::Relaxed) {
            no_excl.store(true, Ordering::Relaxed);
        }
        self.no_excl = no_excl.clone();
    }

    /// The entry at `path` as `list` shows it (see `Remote::listed`).
    pub async fn listed(&self, path: &str) -> Result<Option<Entry>> {
        listed_on(&self.sftp, path).await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        log::info!(target: "vibeftp", "SFTP mkdir {path}");
        Ok(self.sftp.create_dir(path).await?)
    }

    pub async fn remove_file(&self, path: &str) -> Result<()> {
        log::info!(target: "vibeftp", "SFTP rm {path}");
        Ok(self.sftp.remove_file(path).await?)
    }

    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        log::info!(target: "vibeftp", "SFTP rmdir {path}");
        Ok(self.sftp.remove_dir(path).await?)
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        log::info!(target: "vibeftp", "SFTP mv {from} -> {to}");
        Ok(self.sftp.rename(from, to).await?)
    }

    pub async fn chmod(&self, path: &str, mode: u32) -> Result<()> {
        log::info!(target: "vibeftp", "SFTP chmod {:o} {path}", mode & 0o7777);
        let m = self.sftp.metadata(path).await?;
        let kept = m.permissions.unwrap_or(0) & !0o7777;
        // Only send the permission bits; some servers reject attribute bundles.
        let mut attrs = russh_sftp::protocol::FileAttributes::empty();
        attrs.permissions = Some(kept | (mode & 0o7777));
        Ok(self.sftp.set_metadata(path, attrs).await?)
    }

    pub async fn ping(&self) -> Result<()> {
        self.sftp.canonicalize(".").await?;
        Ok(())
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
        Self::download_on(&self.sftp, remote, local, offset, expected, fresh, seen, ctx).await
    }

    /// `download_file` on the session (the tests' in-memory server has no SSH around it).
    #[allow(clippy::too_many_arguments)]
    async fn download_on(
        sftp: &SftpSession,
        remote: &str,
        local: &Path,
        offset: u64,
        expected: Option<u64>,
        fresh: bool,
        seen: Seen,
        ctx: &Ctx,
    ) -> Result<()> {
        ctx.check()?;
        log::info!(target: "vibeftp", "SFTP get {remote} (offset {offset})");
        // Remote first: a missing remote file must not touch the local copy.
        let mut src = sftp.open(remote).await?;
        let meta = src.metadata().await.ok();
        // OPEN succeeds on a folder (sftpgo, OpenSSH) and only the first READ fails: a stale
        // row must not leave an empty, marked local file behind.
        if meta.as_ref().is_some_and(|m| m.is_dir()) {
            drop(src);
            let name = split_remote(remote).1;
            return Err(AppError::Msg(format!("{name}: it is a folder on the server, not a file")));
        }
        // `len()` reads 0 for a missing size attribute: keep "unknown" distinct from empty.
        let reported = meta.as_ref().and_then(|m| m.size);
        let modified = meta.as_ref().and_then(|m| m.modified().ok()).map(millis).unwrap_or(0);
        // The offset was chosen for the file the decision saw; the handle's own attributes say
        // which file this read gets. Another one's tail behind its head would be a splice
        // (review SOL-FTP-3).
        if let Some(was) = seen.source.filter(|_| offset > 0)
            && !super::same_source(was, reported, modified)
        {
            drop(src);
            return Err(AppError::SourceChanged { name: split_remote(remote).1, size: reported, modified });
        }
        let total = reported.or(expected);
        let mut dst = if offset > 0 {
            src.seek(SeekFrom::Start(offset)).await.map_err(sftp_io)?;
            let f = tokio::fs::OpenOptions::new().append(true).open(local).await?;
            // The offset came from a listing taken before the conflict prompt (or the
            // outage): appending behind a file that changed meanwhile would splice.
            let len = f.metadata().await.map(|m| m.len()).unwrap_or(offset);
            if len != offset {
                let _ = src.shutdown().await;
                let name = split_remote(remote).1;
                return Err(AppError::Msg(format!(
                    "{name}: the local file changed while waiting ({len} bytes now, resume expected {offset})"
                )));
            }
            f
        } else if fresh {
            tokio::fs::OpenOptions::new().write(true).create_new(true).open(local).await?
        } else {
            // Also an overwrite's part file (`Remote::download_over`, which holds it open).
            tokio::fs::File::create(local).await?
        };
        // Marked before any byte lands: a retry that finds the file complete never writes again.
        super::mark_downloaded(local, &ctx.host_url);
        ctx.begin(local.to_string_lossy().to_string(), offset);
        *ctx.source.lock().unwrap() = Some((reported.unwrap_or(0), modified));
        (ctx.report)(remote, offset, total);
        let mut buf = vec![0u8; CHUNK];
        let mut done: u64 = offset;
        let outcome: Result<()> = async {
            loop {
                let n = src.read(&mut buf).await.map_err(sftp_io)?;
                if n == 0 {
                    break;
                }
                // Before the write: a read that returns after a cancel (another session may
                // own this file by then) must not touch the destination.
                if ctx.cancelled() {
                    return Err(AppError::Cancelled);
                }
                // A server that announced the size stops there: more would fill the disk with
                // what was never asked for (IN-VibeFTP-3). A declared 0 is no length (below).
                if let Some(t) = total.filter(|&t| t > 0 && done + n as u64 > t) {
                    return Err(super::ftp::oversized(&split_remote(remote).1, t));
                }
                dst.write_all(&buf[..n]).await?;
                done += n as u64;
                ctx.progress(done);
                (ctx.report)(remote, done, total);
            }
            Ok(())
        }
        .await;
        // tokio's File completes writes in the background: the last write's error
        // (full disk) only shows up here, so it must not be dropped.
        let flushed = dst.flush().await;
        if let Err(e) = outcome {
            // Close without waiting: the reply queues behind up to 64 reads already asked
            // for (16 MiB against OpenSSH), which would hold a cancel for that long.
            drop(src);
            return Err(e);
        }
        flushed?;
        src.shutdown().await.map_err(sftp_io)?;
        // EOF is a successful read: a source that shrank mid-transfer must not pass as complete.
        // A declared 0 is not a length: /proc-style files report 0 and still have content.
        if let Some(t) = total.filter(|&t| t > 0)
            && done != t
        {
            let name = split_remote(remote).1;
            return Err(AppError::Msg(format!(
                "{name}: size mismatch (received {done} bytes, server said {t})"
            )));
        }
        (ctx.report)(remote, done, Some(done));
        Ok(())
    }

    pub async fn upload_file(&self, local: &Path, remote: &str, offset: u64, fresh: Fresh, ctx: &Ctx) -> Result<()> {
        ctx.check()?;
        log::info!(target: "vibeftp", "SFTP put {remote} (offset {offset})");
        let mut src = tokio::fs::File::open(local).await?;
        let meta = src.metadata().await.ok();
        let total = meta.as_ref().map(|m| m.len());
        *ctx.source.lock().unwrap() = meta.as_ref().map(|m| (m.len(), m.modified().map(millis).unwrap_or(0)));
        let mut dst = open_upload(&self.sftp, remote, offset, fresh != Fresh::No, &self.no_excl).await?;
        // The offset was read before the conflict prompt: writing at it into a file that grew
        // or shrank meanwhile would leave a stale tail or a hole.
        if offset > 0
            && let Some(now) = dst.metadata().await?.size.filter(|&s| s != offset)
        {
            drop(dst);
            let name = split_remote(remote).1;
            return Err(AppError::Msg(format!(
                "{name}: the file on the server changed while waiting ({now} bytes now, resume expected {offset}); nothing was sent"
            )));
        }
        *ctx.inflight.lock().unwrap() = Some((remote.to_string(), offset, false));
        if offset > 0 {
            src.seek(SeekFrom::Start(offset)).await?;
            dst.seek(SeekFrom::Start(offset)).await.map_err(sftp_io)?;
        }
        (ctx.report)(remote, offset, total);
        let mut buf = vec![0u8; CHUNK];
        let mut done: u64 = offset;
        loop {
            // The open succeeded, but a byte-range lock, a bad sector or a dropped share only
            // fails here, after the server copy was truncated: say so instead of a bare OS
            // error that reads (in a tree, as "left out") like the file was never touched.
            let n = match src.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    let _ = dst.shutdown().await;
                    let name = split_remote(remote).1;
                    return Err(AppError::Msg(format!(
                        "{name}: reading the local file failed after {done} bytes ({e}); the upload was aborted and the copy on the server is incomplete"
                    )));
                }
            };
            if n == 0 {
                break;
            }
            if ctx.cancelled() {
                // Wait for the queued writes: a new upload of this file (maybe on another
                // link) must not have them land after its own truncate.
                let _ = dst.shutdown().await;
                return Err(AppError::Cancelled);
            }
            dst.write_all(&buf[..n]).await.map_err(write_refused)?;
            done += n as u64;
            ctx.progress(done);
            (ctx.report)(remote, done, total);
        }
        dst.shutdown().await.map_err(write_refused)?;
        if let Some(t) = total
            && done != t
        {
            let name = split_remote(remote).1;
            return Err(AppError::Msg(format!(
                "{name}: size mismatch (sent {done} bytes, the file has {t})"
            )));
        }
        (ctx.report)(remote, done, Some(done));
        Ok(())
    }

    pub async fn disconnect(&self) {
        // The SFTP close only queues a packet and should return at once; the cap is a belt
        // and braces so the SSH goodbye below is always sent and the server frees the slot.
        let _ = tokio::time::timeout(Duration::from_secs(2), self.sftp.close()).await;
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "bye", "en")
            .await;
    }
}

async fn keyboard_interactive(handle: &mut Handle<Handler>, user: &str, password: &str) -> Result<bool> {
    let mut r = handle
        .authenticate_keyboard_interactive_start(user.to_string(), None::<String>)
        .await?;
    for _ in 0..5 {
        match r {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let responses = prompts.iter().map(|_| password.to_string()).collect();
                r = handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await?;
            }
        }
    }
    Ok(false)
}
