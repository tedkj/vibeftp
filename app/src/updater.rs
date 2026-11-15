//! Updates. The manifest (latest.json: the version, notes, date, and per platform the installer's
//! URL and its signature) is unsigned, so nothing in it is believed on its own: the installer's
//! minisign signature covers the bytes *and* a trusted comment naming the version and the file,
//! and the updater insists that both match what it was offered and that the version is newer
//! than the running one. That closes downgrades to an older, genuinely signed release and swapped files even if the manifest is not ours.
//!
//! The download is verified in memory, written under the user's own local app data (not %TEMP%),
//! reopened so nobody else can write it, checked again byte for byte, and started from there,
//! but only once Windows says it is validly signed (Authenticode) by the publisher, by the install
//! check's rule (X15SIG-2). Only VibeFTP's own installer names are taken (X15SIG-5).
//! HTTPS only, to GitHub's release hosts only (redirects included), with size caps and timeouts.
//! Any failure before the installer starts leaves the running app as it was. A copy outside the
//! user's own folders, which the installer would refuse after the app quit, is refused before
//! anything is downloaded (X15RFTP-3).

use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use reqwest::Url;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

/// VibeFTP's release key (`vibeftp-release pubkey`).
pub const PUBLIC_KEY: &str = "RWRtiPHhr0TNUFN/XkthdjPMyH1O9YUG07Ge9MyAFamDUBzJ2agHr7EA";
pub const MANIFEST_URL: &str = "https://github.com/tedkj/vibeftp/releases/latest/download/latest.json";
const PLATFORM: &str = "windows-x86_64";
/// How VibeFTP's installers are named (`VibeFTP_<version>_x64-setup.exe`, release.ps1).
const INSTALLER_PREFIX: &str = "VibeFTP_";

#[derive(Clone, Debug)]
pub struct Policy {
    pub manifest_url: String,
    pub public_key: String,
    /// The hosts the manifest, the installer and every redirect may be on.
    pub hosts: Vec<String>,
    pub https_only: bool,
    pub max_manifest: u64,
    pub max_installer: u64,
    pub connect_timeout: Duration,
    /// Longest wait for the next bytes: a server that stops sending is given up on.
    pub stall_timeout: Duration,
    /// The whole manifest fetch: it is small, so a connection that trickles it (each read just
    /// inside the stall timeout) is given up on long before the installer's limit.
    pub manifest_timeout: Duration,
    pub total_timeout: Duration,
    /// Where verified installers are written.
    pub dir: PathBuf,
    /// The running version.
    pub current: String,
    /// Who must have signed the installer (Authenticode, X15SIG-2), by the install check's rule
    /// (`check::by_publisher`); "" takes any valid signature, never none.
    pub publisher: String,
    /// What Windows says of a file's signature: `trust::update_signature` (WinVerifyTrust, which
    /// may fetch the certificate chain, X15RFTP-7) in a release; a stand-in in tests, so no test
    /// needs a real signature.
    pub authenticode: fn(&std::path::Path) -> crate::check::Sig,
    /// The folder the running exe is in, and the user's own folders (local app data, the
    /// profile): the installer refuses to update a copy outside them, so the app refuses first,
    /// before it downloads or quits (X15RFTP-3, `own_folder`).
    pub install_dir: PathBuf,
    pub own_folders: Vec<PathBuf>,
}

impl Policy {
    pub fn release(dir: PathBuf) -> Policy {
        Policy {
            manifest_url: MANIFEST_URL.into(),
            public_key: PUBLIC_KEY.into(),
            hosts: ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"].map(String::from).to_vec(),
            https_only: true,
            max_manifest: 64 * 1024,
            max_installer: 128 * 1024 * 1024,
            connect_timeout: Duration::from_secs(15),
            stall_timeout: Duration::from_secs(30),
            manifest_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(15 * 60),
            dir,
            current: env!("CARGO_PKG_VERSION").into(),
            publisher: crate::check::PUBLISHER.into(),
            authenticode: crate::trust::update_signature,
            install_dir: std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)).unwrap_or_default(),
            own_folders: crate::host::own_folders(),
        }
    }

    fn allowed(&self, u: &Url) -> bool {
        let scheme = u.scheme() == "https" || (!self.https_only && u.scheme() == "http");
        let host = u.host_str().is_some_and(|h| self.hosts.iter().any(|x| x.eq_ignore_ascii_case(h)));
        let port = !self.https_only || u.port_or_known_default() == Some(443);
        scheme && host && port && u.username().is_empty() && u.password().is_none()
    }
}

/// A newer version on offer, with what the download must prove.
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub version: String,
    pub notes: String,
    url: String,
    file: String,
    signature: String,
}

/// A verified installer waiting to be started (`None` in the controller's tests).
pub struct Ready(pub(crate) Option<Verified>);

impl Ready {
    #[doc(hidden)]
    pub fn for_tests() -> Ready {
        Ready(None)
    }

    /// Start it: silent, then VibeFTP again.
    pub fn start(self) -> Result<(), String> {
        match self.0 {
            Some(v) => v.start(&["/S", "/RUN"]),
            None => Ok(()),
        }
    }
}

impl Offer {
    /// An offer with nothing behind it, for the controller's tests (a fake engine answers them).
    #[doc(hidden)]
    pub fn for_tests(version: &str) -> Offer {
        Offer { version: version.into(), notes: String::new(), url: String::new(), file: String::new(), signature: String::new() }
    }
}

/// A downloaded installer that checked out, held open so no one else can change it before it runs.
pub struct Verified {
    path: PathBuf,
    _guard: std::fs::File,
}

pub struct Updater {
    policy: Policy,
    client: reqwest::Client,
}

impl Updater {
    pub fn new(policy: Policy) -> Result<Updater, String> {
        // The app's TLS (as the FTPS code): aws-lc-rs, the system's roots.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let p = policy.clone();
        let redirects = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if p.allowed(attempt.url()) {
                attempt.follow()
            } else {
                let to = attempt.url().host_str().unwrap_or("?").to_string();
                attempt.error(format!("redirected to {to}, which is not where VibeFTP's releases live"))
            }
        });
        let client = reqwest::Client::builder()
            .redirect(redirects)
            .https_only(policy.https_only)
            .connect_timeout(policy.connect_timeout)
            .read_timeout(policy.stall_timeout)
            .timeout(policy.total_timeout)
            .user_agent(concat!("VibeFTP/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Updater { policy, client })
    }

    /// The newer version on offer, if any. No manifest at all (404) is no offer: GitHub's
    /// /releases/latest skips pre-releases, so until the first full release there is none.
    pub async fn check(&self) -> Result<Option<Offer>, String> {
        let Some(body) = self.get(&self.policy.manifest_url, self.policy.max_manifest, self.policy.manifest_timeout, true).await? else {
            return Ok(None);
        };
        let m: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "The update information is not readable".to_string())?;
        let version = m["version"].as_str().ok_or("The update information names no version")?;
        let version = version.strip_prefix('v').unwrap_or(version).to_string();
        if version.len() > 64 || !version.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c)) {
            return Err("The update information names no readable version".into());
        }
        if !newer(&version, &self.policy.current)? {
            return Ok(None);
        }
        let p = &m["platforms"][PLATFORM];
        let url = p["url"].as_str().ok_or("The update offers nothing for Windows")?.to_string();
        let u = Url::parse(&url).map_err(|_| "The update's address is not valid".to_string())?;
        if !self.policy.allowed(&u) {
            return Err(format!("The update is offered from {}, which is not where VibeFTP's releases live", u.host_str().unwrap_or("?")));
        }
        let file = u.path_segments().and_then(|mut s| s.next_back()).unwrap_or("").to_string();
        // VibeFTP's own installers only (X15SIG-5): the release key signs for the whole family.
        if !file.starts_with(INSTALLER_PREFIX) || !file.ends_with("-setup.exe") || !file.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return Err("The update's file name is not one VibeFTP would publish".into());
        }
        let signature = p["signature"]
            .as_str()
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s.trim()).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or("The update carries no readable signature")?;
        let offer = Offer { version, notes: m["notes"].as_str().unwrap_or("").to_string(), url, file, signature };
        // The signed promise must be genuine and match the offer before the bar shows anything
        // or a byte is downloaded (all checked again, with the payload, once the bytes are in).
        if !comment_signed(&self.policy.public_key, &offer.signature) {
            return Err("The update's signature does not check out".into());
        }
        self.promised(&offer)?;
        Ok(Some(offer))
    }

    /// Download, verify and write the installer. Nothing is written unless it checks out.
    pub async fn download(&self, offer: &Offer) -> Result<Verified, String> {
        // The installer would refuse this copy's folder after the app had quit, leaving the user
        // without it (X15RFTP-3): say so now, and the app keeps running.
        if !own_folder(&self.policy.install_dir, &self.policy.own_folders) {
            return Err(format!(
                "VibeFTP installs only inside your own user folder, and {} isn't in it, so it can't update itself there. Uninstall VibeFTP, then install it again into a folder of your own; nothing was installed",
                crate::text::clean_max(&self.policy.install_dir.to_string_lossy(), 200)
            ));
        }
        let bytes = self.fetch(&offer.url, self.policy.max_installer, self.policy.total_timeout).await?;
        let key = PublicKey::from_base64(&self.policy.public_key).map_err(|_| "The release key is not valid".to_string())?;
        let sig = Signature::decode(&offer.signature).map_err(|_| "The update's signature is not readable".to_string())?;
        key.verify(&bytes, &sig, false).map_err(|_| "The download's signature does not check out; nothing was installed".to_string())?;
        self.promised(offer)?;

        std::fs::create_dir_all(&self.policy.dir).map_err(|e| format!("Could not prepare the update folder: {e}"))?;
        // One installer at a time: earlier downloads go. One still running, or held by another
        // VibeFTP, is locked and stays (and so does what its installer is using in tmp).
        if let Ok(old) = std::fs::read_dir(&self.policy.dir) {
            for e in old.flatten() {
                let p = e.path();
                let _ = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
            }
        }
        let path = self.policy.dir.join(&offer.file);
        let saved = std::fs::File::create(&path).and_then(|mut f| f.write_all(&bytes).and_then(|_| f.sync_all()));
        // Reopened shared for reading only: until it runs, no one can write or replace it. What
        // is on disk must be what was verified.
        let reopened = open_read_only(&path).and_then(|g| {
            let mut again = Vec::with_capacity(bytes.len());
            (&g).read_to_end(&mut again)?;
            Ok((g, again == bytes))
        });
        match (saved, reopened) {
            // Saved, or not writable because another VibeFTP holds this very installer, verified
            // and waiting to run: the same bytes, so this one shares it (its hold, too, lets no
            // one write).
            // Windows must vouch for it as well (X15SIG-2): validly signed by the publisher, by
            // the install check's rule, read from the held file, so the installer that would start
            // is the one checked. A leaked release key alone can't push an update this way.
            (_, Ok((guard, true))) => match self.vouched(&path) {
                Ok(()) => Ok(Verified { path, _guard: guard }),
                Err(e) => {
                    drop(guard);
                    let _ = std::fs::remove_file(&path); // shared by another VibeFTP: it stays
                    Err(e)
                }
            },
            (Err(e), _) => Err(format!("Could not save the update: {e}")),
            (Ok(()), Err(e)) => Err(format!("Could not reopen the update: {e}")),
            (Ok(()), Ok((guard, false))) => {
                drop(guard);
                let _ = std::fs::remove_file(&path);
                Err("The saved update changed on disk; nothing was installed".into())
            }
        }
    }

    /// Whether Windows says the saved installer is validly signed by the publisher
    /// (`check::by_publisher`, the install check's own rule). Anything else is refused in words.
    fn vouched(&self, path: &std::path::Path) -> Result<(), String> {
        use crate::check::Sig;
        let who = if self.policy.publisher.is_empty() { "a publisher Windows trusts".to_string() } else { self.policy.publisher.clone() };
        match (self.policy.authenticode)(path) {
            Sig::Signed(s) if crate::check::by_publisher(&self.policy.publisher, &s) => Ok(()),
            Sig::Signed(s) => Err(format!("The update's signature isn't {who}'s (it names {}); nothing was installed", s.name)),
            Sig::NotSigned => Err(format!("The update isn't signed by {who}, so Windows can't vouch for it; nothing was installed")),
            Sig::Broken(why) | Sig::Unknown(why) => Err(format!("Windows couldn't confirm the update is signed by {who} ({why}); nothing was installed")),
            Sig::Missing => Err("The saved update is gone; nothing was installed".into()),
        }
    }

    /// The trusted comment's file name and version are the offer's, and the version is newer.
    fn promised(&self, offer: &Offer) -> Result<(), String> {
        let sig = Signature::decode(&offer.signature).map_err(|_| "The update's signature is not readable".to_string())?;
        let fields: Vec<(&str, &str)> = sig.trusted_comment().split('\t').filter_map(|f| f.split_once(':')).collect();
        let field = |k: &str| fields.iter().find(|(name, _)| *name == k).map(|(_, v)| *v);
        if field("file") != Some(offer.file.as_str()) {
            return Err("The update's signature is for a different file; nothing was installed".into());
        }
        if field("version") != Some(offer.version.as_str()) || !newer(&offer.version, &self.policy.current)? {
            return Err("The update's signature is for a different version; nothing was installed".into());
        }
        Ok(())
    }

    async fn fetch(&self, url: &str, cap: u64, timeout: Duration) -> Result<Vec<u8>, String> {
        // With `missing_ok` false a 404 is an error, so there is always a body here.
        Ok(self.get(url, cap, timeout, false).await?.unwrap_or_default())
    }

    /// `url`'s body, capped; `None` for a 404 when `missing_ok` (only from an allowed host).
    async fn get(&self, url: &str, cap: u64, timeout: Duration, missing_ok: bool) -> Result<Option<Vec<u8>>, String> {
        let u = Url::parse(url).map_err(|_| format!("Not a valid address: {url}"))?;
        if !self.policy.allowed(&u) {
            return Err(format!("{} is not where VibeFTP's releases live", u.host_str().unwrap_or("?")));
        }
        let mut r = self.client.get(u).timeout(timeout).send().await.map_err(|e| describe(&e))?;
        if !self.policy.allowed(r.url()) {
            return Err(format!("{} is not where VibeFTP's releases live", r.url().host_str().unwrap_or("?")));
        }
        if missing_ok && r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(format!("{} answered {}", r.url().host_str().unwrap_or("?"), r.status()));
        }
        let expected = r.content_length();
        if expected.is_some_and(|n| n > cap) {
            return Err("The download is larger than any VibeFTP release; stopped".into());
        }
        let mut buf = Vec::new();
        while let Some(chunk) = r.chunk().await.map_err(|e| describe(&e))? {
            if (buf.len() + chunk.len()) as u64 > cap {
                return Err("The download is larger than any VibeFTP release; stopped".into());
            }
            buf.extend_from_slice(&chunk);
        }
        if expected.is_some_and(|n| n != buf.len() as u64) {
            return Err("The download was cut short".into());
        }
        Ok(Some(buf))
    }
}

impl Verified {
    /// Start the installer (silent, then VibeFTP again). The caller quits right after.
    pub fn start(self, args: &[&str]) -> Result<(), String> {
        // NSIS unpacks itself and its plugins into %TEMP%, which other accounts can sometimes
        // write to: give it a folder of the user's own, next to the installer.
        // The restarted app inherits the installer's environment: it puts the user's own folders
        // back first thing (restore_temp).
        let tmp = self.path.parent().map(|d| d.join("tmp")).unwrap_or_default();
        let _ = std::fs::create_dir_all(&tmp);
        let mut c = std::process::Command::new(&self.path);
        c.args(args).env("TMP", &tmp).env("TEMP", &tmp);
        for (k, keep) in TEMP_VARS {
            c.env(keep, std::env::var_os(k).unwrap_or_default()); // empty: it was not set
        }
        c.spawn()
            .map(|_| ())
            .map_err(|e| format!("The installer did not start: {e}"))
    }
}

const TEMP_VARS: [(&str, &str); 2] = [("TMP", "VIBEFTP_RESTORE_TMP"), ("TEMP", "VIBEFTP_RESTORE_TEMP")];

/// After an update the app is started by the installer, with the installer's private TMP/TEMP:
/// put the user's own back. Call at the start of main (after the DLL block and the argument
/// check), before any other thread exists.
pub fn restore_temp() {
    for (k, keep) in TEMP_VARS {
        if let Some(v) = std::env::var_os(keep) {
            // SAFETY: single-threaded here (start of main), nothing reads the environment yet.
            unsafe {
                if v.is_empty() {
                    std::env::remove_var(k);
                } else {
                    std::env::set_var(k, v);
                }
                std::env::remove_var(keep);
            }
        }
    }
}

/// Why the last silent update did not install, if it failed (the installer leaves a note and
/// starts the unchanged version again). Read once: the note is removed.
pub fn take_failure(local_data: &std::path::Path) -> Option<String> {
    let p = local_data.join("update-failed.txt");
    let s = std::fs::read_to_string(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    let s = s.trim().chars().take(300).collect::<String>();
    Some(if s.is_empty() { "the installer stopped".into() } else { s })
}

#[cfg(windows)]
fn open_read_only(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)
}

#[cfg(not(windows))]
fn open_read_only(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "The update server stopped answering".into()
    } else if e.is_redirect() {
        // The policy's own words ("redirected to ..., which is not ...").
        let mut s = e.to_string();
        let mut src = std::error::Error::source(e);
        while let Some(x) = src {
            s = x.to_string();
            src = x.source();
        }
        s
    } else if e.is_body() || e.is_decode() {
        "The download was cut short".into()
    } else {
        format!("Could not reach the update server: {e}")
    }
}

/// Whether `dir` is strictly inside one of `own`, case-blind and with no `..` part: the
/// installer's folder rule (vibeftp.nsi `OwnFolder`), which refuses an update anywhere else.
pub fn own_folder(dir: &std::path::Path, own: &[PathBuf]) -> bool {
    let d = dir.to_string_lossy().to_lowercase();
    if d.split(['\\', '/']).any(|part| part == "..") {
        return false;
    }
    own.iter().any(|o| {
        let mut o = o.to_string_lossy().to_lowercase();
        if o.is_empty() {
            return false;
        }
        if !o.ends_with('\\') {
            o.push('\\');
        }
        d.len() > o.len() && d.starts_with(&o)
    })
}

/// `a` is a newer version than the running `b`, by semver precedence (build metadata ignored).
/// A pre-release is offered only to a pre-release: a stable install stays on stable releases.
/// Unreadable is an error.
pub fn newer(a: &str, b: &str) -> Result<bool, String> {
    use std::cmp::Ordering;
    fn parse(v: &str) -> Option<([u64; 3], Vec<&str>)> {
        let v = v.split('+').next()?;
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, p.split('.').collect::<Vec<_>>()),
            None => (v, Vec::new()),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() != 3 || pre.iter().any(|p| p.is_empty()) {
            return None;
        }
        let mut n = [0u64; 3];
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            n[i] = p.parse().ok()?;
        }
        Some((n, pre))
    }
    // Pre-release identifiers: numbers numerically and below words; a shorter list below a
    // longer one it starts.
    fn pre_cmp(x: &[&str], y: &[&str]) -> Ordering {
        for (p, q) in x.iter().zip(y) {
            let o = match (p.parse::<u64>(), q.parse::<u64>()) {
                (Ok(m), Ok(n)) => m.cmp(&n),
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => p.cmp(q),
            };
            if o != Ordering::Equal {
                return o;
            }
        }
        x.len().cmp(&y.len())
    }
    let (Some((na, pa)), Some((nb, pb))) = (parse(a), parse(b)) else {
        return Err(format!("Unreadable version: {a}"));
    };
    if !pa.is_empty() && pb.is_empty() {
        return Ok(false);
    }
    Ok(match na.cmp(&nb) {
        Ordering::Equal => match (pa.is_empty(), pb.is_empty()) {
            (true, false) => true,
            (false, false) => pre_cmp(&pa, &pb) == Ordering::Greater,
            _ => false,
        },
        o => o == Ordering::Greater,
    })
}

/// The trusted comment's own signature (Ed25519 over the signature and the comment), by this
/// key: what the bar is about to show was really signed. The payload is checked at download.
fn comment_signed(public_key: &str, sig_text: &str) -> bool {
    use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey};
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.decode(s.trim()).ok();
    let Some(pk) = b64(public_key).filter(|b| b.len() == 42 && &b[..2] == b"Ed") else { return false };
    let lines: Vec<&str> = sig_text.lines().collect();
    let (Some(sig), Some(comment), Some(global)) = (
        lines.get(1).and_then(|l| b64(l)).filter(|b| b.len() == 74),
        lines.get(2).and_then(|l| l.strip_prefix("trusted comment: ")),
        lines.get(3).and_then(|l| b64(l)).filter(|b| b.len() == 64),
    ) else {
        return false;
    };
    if sig[2..10] != pk[2..10] {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(pk[10..42].try_into().unwrap()) else { return false };
    let mut msg = sig[10..74].to_vec();
    msg.extend_from_slice(comment.as_bytes());
    key.verify(&msg, &EdSig::from_bytes(global[..].try_into().unwrap())).is_ok()
}
