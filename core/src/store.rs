//! Persistence: sites.json + known_hosts.json (SSH host keys, FTPS certificates) in the app config dir,
//! passwords in the OS keychain (Windows Credential Manager, macOS Keychain,
//! Secret Service on Linux).
//!
//! Damage safety (VibeWare family lessons, 2026-10-20; reviews FR-1..FR-7, FR2-1..FR2-9):
//! - A file that is there but cannot be read right now (another program holds it) is an error,
//!   and nothing is written over it.
//! - A *damaged* file (not JSON at all, cut short, or JSON that is not a list or an object) is
//!   never written over, and never read as an empty list. It is kept aside as `<name>.broken`
//!   (`.broken-2`, ... when an older copy is there: never replaced) and the user is told.
//!   sites.json goes aside on the first change (save or delete) and until then the site list
//!   says why it is empty; known_hosts.json goes aside on the first connect that needs it.
//!   A leading UTF-8 BOM (Notepad's "UTF-8 with BOM") is not damage (FR2-9).
//! - Per entry (FR2-1): a site or pin this build cannot read (a newer VibeFTP's protocol or pin
//!   form, a hand edit gone wrong) is not used, but never dropped and never rewritten: every save
//!   carries it through as it is, and does not make the file read-only. A readable site's fields
//!   this build does not know are kept too (`Site::extra`).
//! - Only a file that is sound JSON but not this build's shape at all (an object where the site
//!   list belongs, a list where the pins belong) is left as it is with every change refused
//!   (`AppError::Unreadable`, naming the file). There is no version marker to check yet.
//! - Every load-modify-save holds `store.lock` in the config folder, a lock across processes:
//!   two windows of this build never drop each other's sites or pins, each change lands on the
//!   newest file by site id or pin key. Nested on one thread it is taken once, never twice,
//!   however the folder is spelled (FR2-3).
//! - Writes go to this process's own temp file, synced, then renamed over the target.

use crate::error::{AppError, Result};
use crate::host::{Event, Host};
use crate::types::{millis, Kept, PinnedBefore, Site, SiteList};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

const SITES: &str = "sites.json";
const HOSTS: &str = "known_hosts.json";
const LOCK: &str = "store.lock";

static SERVICE: OnceLock<String> = OnceLock::new();

/// The keychain's service name for saved passwords ("VibeFTP"). A development build pointed at a
/// test profile sets its own before anything is saved, so it never touches the real entries.
pub fn use_keychain_service(name: &str) {
    let _ = SERVICE.set(name.to_string());
}

fn service() -> &'static str {
    SERVICE.get().map(String::as_str).unwrap_or("VibeFTP")
}

/// What an edit or delete of a site that is only there as an entry this build cannot read gets.
pub const UNREADABLE_SITE: &str = "That site was changed in a way this VibeFTP can't read (by a newer VibeFTP, or a hand edit); it is kept as it is";

const SITES_LOCKED: &str = "no site can be saved or deleted";
const PINS_LOCKED: &str = "no host key or certificate can be trusted or forgotten";

/// What a JSON file holds.
enum Read {
    Missing,
    /// Sound JSON: a list or an object.
    Value(Value),
    /// Damaged: not JSON (or not UTF-8, or cut short), or JSON that is not a list or an object.
    Damaged(String),
}

/// A file that is there but cannot be read right now is an error: nothing may be written over it.
fn read_json(path: &Path) -> Result<Read> {
    match fs::read(path) {
        Ok(b) => Ok(classify(&b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Read::Missing),
        Err(e) => Err(AppError::Msg(format!("{} cannot be read right now ({e}); nothing was changed", file_name(path)))),
    }
}

/// A JSON file's text as UTF-8: a leading UTF-8 BOM is read past (Notepad's "UTF-8 with BOM",
/// FR2-9), a UTF-16 one decoded (its "UTF-16 LE" / "UTF-16 BE", FR3-1; an odd last byte is
/// dropped, a lone surrogate becomes U+FFFD). Anything else is taken as it is.
fn utf8(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let utf16 = |b: &[u8], unit: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| unit([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units).into_bytes().into()
    };
    if let Some(b) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        b.into()
    } else if let Some(b) = bytes.strip_prefix(b"\xFF\xFE") {
        utf16(b, u16::from_le_bytes)
    } else if let Some(b) = bytes.strip_prefix(b"\xFE\xFF") {
        utf16(b, u16::from_be_bytes)
    } else {
        bytes.into()
    }
}

/// Damaged means "not JSON at all", never "not what this build expects" (review FR-3). A
/// BOM is read past, a UTF-16 file decoded (`utf8`): neither is damage.
fn classify(bytes: &[u8]) -> Read {
    match serde_json::from_slice::<Value>(&utf8(bytes)) {
        Ok(v) if v.is_array() || v.is_object() => Read::Value(v),
        Ok(_) => Read::Damaged("not a JSON list or object".into()),
        Err(e) => Read::Damaged(e.to_string()),
    }
}

/// A file this build cannot read at all (FR2-1): it stays as it is, every change is refused,
/// and the error names it.
fn unreadable(path: &Path, what: &str) -> AppError {
    AppError::Unreadable {
        text: format!(
            "{} is not in a form this VibeFTP can read. It is left as it is, and {what} until it is moved away (VibeFTP then starts a new one).",
            path.display()
        ),
        path: path.to_string_lossy().into_owned(),
    }
}

/// The sites of a list that this build can read, and the entries it cannot, as they are.
fn split_sites(v: Value, path: &Path) -> Result<(Vec<Site>, Vec<Value>)> {
    let Value::Array(items) = v else { return Err(unreadable(path, SITES_LOCKED)) };
    let (mut sites, mut kept) = (Vec::new(), Vec::new());
    for item in items {
        match Site::deserialize(&item) {
            Ok(s) => sites.push(s),
            Err(_) => kept.push(item),
        }
    }
    Ok((sites, kept))
}

/// The id an entry this build cannot read carries, if any.
fn entry_id(v: &Value) -> Option<&str> {
    v.get("id").and_then(Value::as_str)
}

/// The reentrancy guard's key for a folder: the folder itself, not its spelling (a Windows path
/// in another case is the same folder, and its `store.lock` the same lock; review FR2-3).
fn lock_key(dir: &Path) -> PathBuf {
    let p = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if cfg!(windows) { PathBuf::from(p.to_string_lossy().to_lowercase()) } else { p }
}

thread_local! {
    /// Config folders (`lock_key`) whose `store.lock` this thread holds (a nested `transact`
    /// must not wait on its own lock: on Windows that never returns, review FR-7).
    static HELD: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` holding `store.lock` in `dir` (a lock across processes, released when `f` returns).
/// Nested on the same thread it runs `f` under the lock already held. prefs.json, next to
/// sites.json, takes the same lock for its read-modify-write.
pub fn locked<T>(dir: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let key = lock_key(dir);
    if HELD.with(|h| h.borrow().contains(&key)) {
        return f();
    }
    let lock = fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(LOCK))?;
    lock.lock()?;
    struct Held(PathBuf);
    impl Drop for Held {
        fn drop(&mut self) {
            HELD.with(|h| {
                let mut h = h.borrow_mut();
                if let Some(i) = h.iter().rposition(|d| *d == self.0) {
                    h.remove(i);
                }
            });
        }
    }
    HELD.with(|h| h.borrow_mut().push(key.clone()));
    let _held = Held(key); // dropped before `lock`, which unlocks
    f()
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn absent(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// Where a damaged file is kept: `<name>.broken`, or `.broken-2`, `-3`, ... next to an older copy.
pub fn broken_path(path: &Path) -> PathBuf {
    let name = file_name(path);
    (1..)
        .map(|n| path.with_file_name(if n == 1 { format!("{name}.broken") } else { format!("{name}.broken-{n}") }))
        .find(|p| absent(p))
        .expect("a free name")
}

/// The kept copies of `name` in `dir` (`<name>.broken`, `.broken-2`, ...), newest first, with
/// when each was set aside. A folder that cannot be listed right now is an error, never "no
/// copies" (FR3-4).
fn kept_copies_of(dir: &Path, name: &str) -> Result<Vec<(SystemTime, PathBuf)>> {
    let stem = format!("{name}.broken");
    let ours = |n: &str| {
        n.strip_prefix(&stem).is_some_and(|rest| {
            rest.is_empty() || rest.strip_prefix('-').is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    let mut v: Vec<(SystemTime, PathBuf)> = fs::read_dir(dir)?
        .flatten()
        .filter(|e| ours(&e.file_name().to_string_lossy()))
        .map(|e| (e.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH), e.path()))
        .collect();
    v.sort_by_key(|k| std::cmp::Reverse(k.0));
    Ok(v)
}

/// What the notice about a kept copy of `name` says.
fn aside_text(name: &str, kept: &str) -> String {
    if name == SITES {
        format!("sites.json was damaged and is kept as {kept}. The site list starts over from here; the sites you had are in that file.")
    } else {
        format!(
            "known_hosts.json was damaged and is kept as {kept}. The host keys and certificates you trusted are not known any more: VibeFTP asks again on each server's next connect, so check each fingerprint with the server's owner."
        )
    }
}

/// What a kept copy of a damaged known_hosts.json says about one pin key.
#[derive(Debug, PartialEq)]
enum InCopy {
    /// It names the key: with the pin, when that can be read out of it.
    Named(Option<String>),
    /// It names other keys, not this one.
    Others,
    /// No key can be read out of it at all (zero-filled, cut short in its first key, an
    /// encoding it does not say): this server may have been in it (FR3-1).
    Nothing,
}

/// What a kept copy says about pin `key`. A copy that parses is read as JSON. Otherwise it is
/// searched as text (UTF-16 decoded, `utf8`) for the exact key, quotes included (review FR2-2):
/// followed by `:` it is the key, with the pin when a string follows; at the very end of the
/// text (cut right after it) it is the key too, pin unknown (FR3-1); followed by anything else
/// it is a value (a newer build's pin naming the host), not the key.
fn pin_in_copy(bytes: &[u8], key: &str) -> InCopy {
    if let Read::Value(v) = classify(bytes) {
        return match v.get(key) {
            Some(pin) => InCopy::Named(pin.as_str().map(String::from)),
            None => InCopy::Others,
        };
    }
    let bytes = utf8(bytes);
    let text = String::from_utf8_lossy(&bytes);
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(i) = text[from..].find(&needle) {
        from += i + needle.len();
        let rest = text[from..].trim_start_matches(|c: char| c.is_whitespace() || c == '\0');
        if let Some(value) = rest.strip_prefix(':') {
            let pin = value.trim_start().strip_prefix('"').and_then(|v| v.find('"').map(|end| v[..end].to_string()));
            return InCopy::Named(pin);
        }
        if rest.is_empty() {
            return InCopy::Named(None);
        }
    }
    if names_a_key(&text) { InCopy::Others } else { InCopy::Nothing }
}

/// Whether `text` holds any `"...":` pair (a pin key, read or not).
fn names_a_key(text: &str) -> bool {
    let mut rest = text;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { return false };
        let tail = &after[close + 1..];
        if close > 0 && tail.trim_start().starts_with(':') {
            return true;
        }
        rest = tail;
    }
    false
}

/// How long a kept pin copy that no key can be read out of puts its line on every
/// first-connection prompt (FR3-1).
const UNREAD_COPY_WARNS: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);

pub struct Store {
    dir: PathBuf,
    /// Where a file set aside is reported (a notice the user dismisses), besides the log.
    host: Option<Arc<dyn Host>>,
}

/// The sites a change starts from (inside `transact`).
pub struct ForChange {
    pub sites: Vec<Site>,
    /// The entries this build cannot read, as they are: `save_sites` writes them back unchanged.
    pub kept: Vec<Value>,
    /// sites.json was damaged and this call kept it aside as this file (named): the change
    /// starts a new list, so a site that was only in the damaged file is not in it.
    pub set_aside: Option<String>,
}

impl ForChange {
    /// Whether `id` is taken, by a site or by an entry this build cannot read (it names that
    /// entry's password).
    pub fn id_taken(&self, id: &str) -> bool {
        self.sites.iter().any(|s| s.id == id) || self.kept.iter().any(|v| entry_id(v) == Some(id))
    }

    /// Site `id`'s password is gone: an entry this build cannot read with the same id (a
    /// duplicate a sync tool's merge or a hand edit left) no longer claims one. The readable
    /// site owns the keychain entry; the duplicate is kept, with only `has_password` changed
    /// (review FR3-3).
    /// Whether that changed anything.
    pub fn password_gone(&mut self, id: &str) -> bool {
        let mut changed = false;
        for v in self.kept.iter_mut().filter(|v| entry_id(v) == Some(id)) {
            if let Some(has) = v.get_mut("has_password").filter(|h| **h == Value::Bool(true)) {
                *has = Value::Bool(false);
                changed = true;
            }
        }
        changed
    }

    /// What an edit or delete of site `id` that is not in `sites` says.
    pub fn missing(&self, id: &str) -> AppError {
        AppError::Msg(match &self.set_aside {
            Some(kept) => format!("Your sites file was damaged and kept as {kept}; this site is not in the new list"),
            None if self.kept.iter().any(|v| entry_id(v) == Some(id)) => UNREADABLE_SITE.into(),
            None => "That site no longer exists".into(),
        })
    }
}

impl Store {
    /// `dir`: the app config folder (`Paths::config`).
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Store { dir: dir.to_path_buf(), host: None })
    }

    /// Report files set aside to `host` too (`Event::Notice`), not only to the log.
    pub fn reporting(mut self, host: Arc<dyn Host>) -> Self {
        self.host = Some(host);
        self
    }

    /// Run a load-modify-save holding the lock across processes (released when it returns).
    /// Nested on one thread, the lock is taken once.
    pub fn transact<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        locked(&self.dir, f)
    }

    fn tell(&self, text: String, path: String) {
        if let Some(h) = &self.host {
            h.emit(Event::Notice { text, path: Some(path) });
        }
    }

    /// Move a damaged file aside (never over an older copy) and say so: in the log, and to the
    /// user as a notice that stays until dismissed (review FR-1, FR-2). The kept copy's
    /// modified time becomes the moment it was set aside.
    fn keep_aside(&self, name: &str) -> Result<PathBuf> {
        let p = self.dir.join(name);
        let to = broken_path(&p);
        fs::rename(&p, &to).map_err(|e| AppError::Msg(format!("{name} is damaged and could not be set aside ({e}); nothing was changed")))?;
        let _ = fs::OpenOptions::new().write(true).open(&to).and_then(|f| f.set_modified(SystemTime::now()));
        log::warn!(target: "vibeftp", "{name} was damaged and is kept as {}", to.display());
        self.tell(aside_text(name, &file_name(&to)), to.to_string_lossy().into_owned());
        Ok(to)
    }

    /// Every kept copy of a damaged sites.json or known_hosts.json in the config folder, with
    /// what its notice says: a window that did not set it aside tells about it too (FR2-6). A
    /// folder that cannot be listed right now is an error (FR3-4).
    pub fn kept_copies(&self) -> Result<Vec<Kept>> {
        let mut all = Vec::new();
        for name in [SITES, HOSTS] {
            for (_, p) in kept_copies_of(&self.dir, name)? {
                let kept = file_name(&p);
                all.push(Kept { text: aside_text(name, &kept), name: kept, path: p.to_string_lossy().into_owned() });
            }
        }
        Ok(all)
    }

    /// The saved sites (not inside `transact`), and how many entries this build cannot read. A
    /// damaged file is an error that says why the list is empty; it stays as it is until the
    /// first change keeps it aside. A file that is not a list is `AppError::Unreadable`.
    pub fn load_sites(&self) -> Result<SiteList> {
        let p = self.dir.join(SITES);
        if absent(&p) {
            // Looked again under the lock: another window's first save may have landed while
            // this one waited, and a stale temp file must never go over it (review FR-6).
            self.transact(|| {
                if absent(&p) {
                    self.recover_tmp();
                }
                Ok(())
            })?;
        }
        match read_json(&p)? {
            Read::Missing => Ok(SiteList::default()),
            Read::Value(v) => {
                let (sites, kept) = split_sites(v, &p)?;
                if !kept.is_empty() {
                    log::warn!(
                        target: "vibeftp",
                        "sites.json: {} of its {} entries are not in a form this VibeFTP can read; they are kept as they are",
                        kept.len(),
                        kept.len() + sites.len()
                    );
                }
                Ok(SiteList { sites, unreadable: kept.len() })
            }
            Read::Damaged(why) => Err(AppError::Msg(format!(
                "sites.json is damaged ({why}). It stays as it is for now; the next site you save or delete starts a new list, and the old file is kept as sites.json.broken"
            ))),
        }
    }

    /// The sites to change (inside `transact`): a damaged file is kept aside first and the
    /// change starts a new list, never written over the old one. Entries this build cannot
    /// read come along as they are; a file that is not a list is never changed.
    pub fn sites_for_change(&self) -> Result<ForChange> {
        let p = self.dir.join(SITES);
        Ok(match self.read_sites_locked()? {
            Read::Missing => ForChange { sites: vec![], kept: vec![], set_aside: None },
            Read::Value(v) => {
                let (sites, kept) = split_sites(v, &p)?;
                ForChange { sites, kept, set_aside: None }
            }
            Read::Damaged(_) => {
                let to = self.keep_aside(SITES)?;
                ForChange { sites: vec![], kept: vec![], set_aside: Some(file_name(&to)) }
            }
        })
    }

    /// The sites as they are (inside `transact`), `None` when there are none or the file is
    /// damaged or not a list: for the automatic updates (last folders), which never move a
    /// damaged file.
    pub fn sites_if_sound(&self) -> Result<Option<ForChange>> {
        Ok(match self.read_sites_locked()? {
            Read::Value(v @ Value::Array(_)) => {
                let (sites, kept) = split_sites(v, &self.dir.join(SITES))?;
                Some(ForChange { sites, kept, set_aside: None })
            }
            _ => None,
        })
    }

    /// Inside `transact`.
    fn read_sites_locked(&self) -> Result<Read> {
        let p = self.dir.join(SITES);
        if absent(&p) {
            self.recover_tmp();
        }
        read_json(&p)
    }

    /// A crash between the first temp write and its rename leaves the data in a temp file: the
    /// newest one that parses becomes sites.json (only while there is none).
    fn recover_tmp(&self) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let mut tmps: Vec<(SystemTime, PathBuf)> = rd
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("sites.json.") && n.ends_with(".tmp")
            })
            .map(|e| (e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH), e.path()))
            .collect();
        tmps.sort();
        for (_, tmp) in tmps.into_iter().rev() {
            if matches!(read_json(&tmp), Ok(Read::Value(Value::Array(_)))) && fs::rename(&tmp, self.dir.join(SITES)).is_ok() {
                return;
            }
        }
    }

    /// The sites, then the entries this build cannot read, unchanged (FR2-1). Written straight
    /// from the structs, so a site's fields keep their order in the file (`id`, `name` first;
    /// fields this build does not know last), not sorted by name (FR3-2).
    pub fn save_sites(&self, c: &ForChange) -> Result<()> {
        #[derive(serde::Serialize)]
        #[serde(untagged)]
        enum Item<'a> {
            Site(&'a Site),
            Kept(&'a Value),
        }
        let all: Vec<Item> = c.sites.iter().map(Item::Site).chain(c.kept.iter().map(Item::Kept)).collect();
        self.write_atomic(SITES, &serde_json::to_string_pretty(&all)?)
    }

    /// Write to this process's own sibling temp file and rename it over the target, so a crash
    /// mid-write never leaves a half-written JSON file behind, and another process writing at
    /// the same moment never writes into it.
    fn write_atomic(&self, name: &str, body: &str) -> Result<()> {
        use std::io::Write;
        let target = self.dir.join(name);
        let tmp = self.dir.join(format!("{name}.{}.tmp", std::process::id()));
        let written = (|| -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        // rename replaces on every platform we build for; a scanner holding the
        // file open is the only usual reason it fails, so retry briefly rather
        // than delete the target (which could lose the data if the retry failed).
        let mut last = None;
        for _ in 0..10 {
            match fs::rename(&tmp, &target) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
        let _ = fs::remove_file(&tmp);
        Err(last.expect("rename attempted").into())
    }

    /// The pins as the file holds them: a pin this build reads is a string, any other value is
    /// another build's and is left alone (FR2-1). A damaged pin file is never "no pins" behind
    /// the user's back: it is kept aside (a notice says so). A file that is not an object of
    /// pins reads as none, is left as it is, and the user is told.
    fn load_hosts(&self) -> Result<Map<String, Value>> {
        let p = self.dir.join(HOSTS);
        match read_json(&p)? {
            Read::Missing => Ok(Map::new()),
            Read::Value(Value::Object(m)) => Ok(m),
            Read::Value(_) => {
                if let AppError::Unreadable { text, path } = unreadable(&p, PINS_LOCKED) {
                    log::warn!(target: "vibeftp", "{text}");
                    self.tell(text, path);
                }
                Ok(Map::new())
            }
            Read::Damaged(_) => self.transact(|| {
                // Another process may have set it aside (or mended it) meanwhile.
                Ok(match read_json(&p)? {
                    Read::Damaged(_) => {
                        self.keep_aside(HOSTS)?;
                        Map::new()
                    }
                    Read::Value(Value::Object(m)) => m,
                    _ => Map::new(),
                })
            }),
        }
    }

    fn pin(&self, key: &str) -> Result<Option<String>> {
        Ok(self.load_hosts()?.get(key).and_then(Value::as_str).map(String::from))
    }

    /// Whether the host or certificate pinned as `key` was pinned in a kept copy of a damaged
    /// known_hosts.json, and is not pinned now: only then does a first-connection prompt say
    /// the server was trusted before (review FR2-2). Newest kept copy first. When no copy names
    /// it but one set aside in the last 30 days holds no readable key at all, any server may
    /// have been in that one: `named: false`, the prompt's general line (FR3-1).
    pub fn pinned_before(&self, key: &str) -> Option<PinnedBefore> {
        if let Ok(Read::Value(Value::Object(m))) = read_json(&self.dir.join(HOSTS))
            && m.contains_key(key)
        {
            return None; // trusted again since
        }
        let mut unread = None;
        for (at, p) in kept_copies_of(&self.dir, HOSTS).unwrap_or_default() {
            let Ok(bytes) = fs::read(&p) else { continue };
            let found = |pin, named| Some(PinnedBefore { file: file_name(&p), at: millis(at), pin, named });
            match pin_in_copy(&bytes, key) {
                InCopy::Named(pin) => return found(pin, true),
                InCopy::Others => {}
                InCopy::Nothing => {
                    let recent = SystemTime::now().duration_since(at).map_or(true, |age| age < UNREAD_COPY_WARNS);
                    if unread.is_none() && recent {
                        unread = found(None, false);
                    }
                }
            }
        }
        unread
    }

    /// One pin changed on the newest file, under the lock. `f` returns false to leave it as is.
    fn change_hosts(&self, f: impl FnOnce(&mut Map<String, Value>) -> Result<bool>) -> Result<()> {
        let p = self.dir.join(HOSTS);
        self.transact(|| {
            let mut hosts = match read_json(&p)? {
                Read::Missing => Map::new(),
                Read::Value(Value::Object(m)) => m,
                Read::Value(_) => return Err(unreadable(&p, PINS_LOCKED)),
                Read::Damaged(_) => {
                    self.keep_aside(HOSTS)?;
                    Map::new()
                }
            };
            if f(&mut hosts)? { self.write_atomic(HOSTS, &serde_json::to_string_pretty(&hosts)?) } else { Ok(()) }
        })
    }

    /// A pin that is another build's (not a string) is never replaced or removed.
    fn own(hosts: &Map<String, Value>, key: &str) -> Result<()> {
        match hosts.get(key) {
            Some(v) if !v.is_string() => Err(AppError::Msg(format!(
                "The saved entry for {key} in known_hosts.json is in a form this VibeFTP can't read (a newer VibeFTP wrote it); it is kept as it is"
            ))),
            _ => Ok(()),
        }
    }

    fn set_pin(&self, key: String, value: &str) -> Result<()> {
        self.change_hosts(|h| {
            Self::own(h, &key)?;
            h.insert(key, Value::String(value.to_string()));
            Ok(true)
        })
    }

    /// A pin is `"<key algorithm> SHA256:…"`, or a bare `"SHA256:…"` from older versions.
    pub fn known_host(&self, host: &str, port: u16) -> Result<Option<String>> {
        self.pin(&format!("{host}:{port}"))
    }

    pub fn remember_host(&self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        self.set_pin(format!("{host}:{port}"), fingerprint)
    }

    /// Replace a pin with the same key's fuller entry, only if it is still `old` (the user
    /// may have trusted another key meanwhile).
    pub fn upgrade_host(&self, host: &str, port: u16, old: &str, new: &str) -> Result<()> {
        self.change_hosts(|h| {
            Ok(match h.get_mut(&format!("{host}:{port}")) {
                Some(Value::String(v)) if v == old => {
                    *v = new.to_string();
                    true
                }
                _ => false,
            })
        })
    }

    /// FTPS certificate pins live in the same file under their own key, so an SSH pin for the
    /// same host and port is never compared with a certificate (values: `SHA256:…`).
    pub fn known_cert(&self, host: &str, port: u16) -> Result<Option<String>> {
        self.pin(&format!("ftps:{host}:{port}"))
    }

    pub fn remember_cert(&self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        self.set_pin(format!("ftps:{host}:{port}"), fingerprint)
    }

    /// `Ok(None)`: nothing stored. A keychain that cannot be read is an error, never "no
    /// password": an empty one would go to the server as a failed login.
    pub fn get_password(&self, site_id: &str) -> Result<Option<String>> {
        match keyring::Entry::new(service(), site_id).and_then(|e| e.get_password()) {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                log::warn!(target: "vibeftp", "Keychain read failed for {site_id}: {e}");
                Err(e.into())
            }
        }
    }

    pub fn set_password(&self, site_id: &str, password: &str) -> Result<()> {
        keyring::Entry::new(service(), site_id)?.set_password(password)?;
        Ok(())
    }

    /// Nothing stored counts as removed; a store that refuses to delete does not.
    pub fn delete_password(&self, site_id: &str) -> Result<()> {
        match keyring::Entry::new(service(), site_id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
