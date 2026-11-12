//! The few things the window remembers between runs: theme, top bar mode, protocol log open, the
//! last local folder, whether to look for updates at start. `prefs.json` next to sites.json; a
//! missing file, or a field that cannot be read, means that field's default.
//! Each field is written on its own: a second window changing the
//! theme does not undo this one's last folder.
//!
//! A file that is not JSON (or not an object) is never written over: the window says so once,
//! and the first write keeps it aside as `prefs.json.broken` (replacing an older copy). A file
//! that is there but cannot be read right now is never written at all (VibeBackup BA-3,
//! VibeTrace TA-4/TR-1). The read-merge-write holds `store.lock`, the lock sites.json and
//! known_hosts.json take in the same folder, so two windows never undo each other's field
//! (review FR-8).

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Which fields a change touched.
pub const THEME: u8 = 1;
pub const BAR: u8 = 2;
pub const LOG: u8 = 4;
pub const LOCAL_PATH: u8 = 8;
pub const TOLD: u8 = 16;
pub const UPDATE_AT_START: u8 = 32;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// "thin" for the compact bar; anything else is the thick one.
    pub bar: Option<String>,
    pub log: bool,
    pub local_path: String,
    /// The kept copies of damaged files (`sites.json.broken`, ...) some window of this profile
    /// has told the user about: each is told once, not by every window (review FR2-6).
    pub told: Vec<String>,
    /// Look for a newer version a few seconds after the window opens. On unless the user turned
    /// it off in the menu; a file from before the switch existed reads as on.
    pub update_at_start: bool,
}

impl Default for Prefs {
    fn default() -> Prefs {
        Prefs { theme: None, bar: None, log: false, local_path: String::new(), told: Vec::new(), update_at_start: true }
    }
}

/// Where a garbled prefs file is kept: `prefs.json.broken`.
pub fn broken_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".broken");
    path.with_file_name(name)
}

impl Prefs {
    /// Defaults when the file is missing, garbled or cannot be read right now.
    pub fn load(path: &Path) -> Prefs {
        Prefs::read(path).ok().flatten().unwrap_or_default()
    }

    /// `Some`: the file's prefs (defaults when it is missing; a field that cannot be read is that
    /// field's default). `None`: garbled, not a JSON object. An error when it is there but cannot
    /// be read right now. In neither of the last two may a write put anything over it.
    fn read(path: &Path) -> std::io::Result<Option<Prefs>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Prefs::parse(&bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(Prefs::default())),
            Err(e) => Err(e),
        }
    }

    fn parse(bytes: &[u8]) -> Option<Prefs> {
        // Notepad's "UTF-8 with BOM" is not garbled (review FR2-9).
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let v: serde_json::Value = serde_json::from_slice(bytes).ok().filter(serde_json::Value::is_object)?;
        let text = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
        Some(Prefs {
            theme: text("theme").filter(|t| t == "dark" || t == "light"),
            bar: text("bar"),
            log: v.get("log").and_then(|x| x.as_bool()).unwrap_or(false),
            local_path: text("local_path").unwrap_or_default(),
            told: v
                .get("told")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|n| n.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            update_at_start: v.get("update_at_start").and_then(|x| x.as_bool()).unwrap_or(true),
        })
    }

    /// The fields in which `other` differs from this.
    pub fn diff(&self, other: &Prefs) -> u8 {
        (if self.theme != other.theme { THEME } else { 0 })
            | (if self.bar != other.bar { BAR } else { 0 })
            | (if self.log != other.log { LOG } else { 0 })
            | (if self.local_path != other.local_path { LOCAL_PATH } else { 0 })
            | (if self.told != other.told { TOLD } else { 0 })
            | (if self.update_at_start != other.update_at_start { UPDATE_AT_START } else { 0 })
    }

    /// Take `fields` from `from` (this window's) over what the file holds now (in `dir`).
    fn take(&mut self, from: &Prefs, fields: u8, dir: &Path) {
        if fields & THEME != 0 {
            self.theme = from.theme.clone();
        }
        if fields & BAR != 0 {
            self.bar = from.bar.clone();
        }
        if fields & LOG != 0 {
            self.log = from.log;
        }
        if fields & LOCAL_PATH != 0 {
            self.local_path = from.local_path.clone();
        }
        if fields & UPDATE_AT_START != 0 {
            self.update_at_start = from.update_at_start;
        }
        if fields & TOLD != 0 {
            // Both lists: another window may have told about a copy this one does not know of
            // (review FR3-4). A copy that is gone is forgotten (a later one may take its name);
            // one that cannot be looked at right now is not gone.
            for n in &from.told {
                if !self.told.contains(n) {
                    self.told.push(n.clone());
                }
            }
            self.told.retain(|n| !matches!(std::fs::symlink_metadata(dir.join(n)), Err(e) if e.kind() == std::io::ErrorKind::NotFound));
            self.told.sort();
        }
    }

    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => system_dark(),
        }
    }

    pub fn thick(&self) -> bool {
        self.bar.as_deref() != Some("thin")
    }
}

/// Writes off the UI thread, newest wins: a burst of navigations costs one or two writes, and
/// an older write can never land after a newer one (the lock covers take-and-write). Only the
/// fields this window changed are written, over what the file holds now.
#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    pending: Arc<Mutex<Option<(Prefs, u8)>>>,
    write: Arc<Mutex<()>>,
    /// `load` found the file garbled (the window says so once).
    broken: Arc<AtomicBool>,
}

impl Store {
    pub fn new(path: PathBuf) -> Store {
        Store { path, pending: Default::default(), write: Default::default(), broken: Default::default() }
    }

    /// The prefs, defaults when the file is missing, garbled or cannot be read right now. Reads
    /// only: a garbled file is noted (`broken`) and kept aside by the first write.
    pub fn load(&self) -> Prefs {
        match Prefs::read(&self.path) {
            Ok(Some(p)) => p,
            Ok(None) => {
                self.broken.store(true, Ordering::Relaxed);
                Prefs::default()
            }
            Err(_) => Prefs::default(),
        }
    }

    /// `load` found the file garbled.
    pub fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    /// Remember `p`; `fields` are the ones that changed.
    pub fn save(&self, p: Prefs, fields: u8, rt: &tokio::runtime::Handle) {
        self.stage(p, fields);
        let me = self.clone();
        rt.spawn_blocking(move || me.flush());
    }

    fn stage(&self, p: Prefs, fields: u8) {
        let mut pending = self.pending.lock().unwrap();
        let before = pending.as_ref().map_or(0, |(_, f)| *f);
        *pending = Some((p, before | fields));
    }

    /// Write what is pending, if anything (also called at exit, so the last change is kept). A
    /// failed write stays pending for the next one.
    pub fn flush(&self) {
        let _w = self.write.lock().unwrap();
        let Some((p, fields)) = self.pending.lock().unwrap().take() else { return };
        let dir = self.path.parent().map(Path::to_path_buf).unwrap_or_default();
        let _ = std::fs::create_dir_all(&dir);
        // Across processes: another window's read-merge-write must not land between this one's
        // read and its rename (it would put back the field this one just changed).
        let written = vibeftp_core::store::locked(&dir, || {
            Ok(match Prefs::read(&self.path) {
                Ok(Some(mut now)) => {
                    now.take(&p, fields, &dir);
                    self.write_file(&now)
                }
                // Garbled: kept aside, never written over. This window's prefs (its defaults and
                // what it changed since) start the new file.
                Ok(None) => std::fs::rename(&self.path, broken_path(&self.path)).is_ok() && self.write_file(&p),
                // There but not readable now: nothing is written.
                Err(_) => false,
            })
        })
        .unwrap_or(false);
        if !written {
            // Unless something newer is already waiting, try this again with the next change.
            let mut pending = self.pending.lock().unwrap();
            match pending.as_mut() {
                Some((_, f)) => *f |= fields,
                None => *pending = Some((p, fields)),
            }
        }
    }

    fn write_file(&self, p: &Prefs) -> bool {
        let Ok(body) = serde_json::to_string_pretty(p) else { return false };
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Whole or not at all: a crash or a power cut mid-write leaves the old file. The temp
        // file is this process's own, so a second window writing at the same moment cannot write
        // into it. It is on the disk (`sync_all`) before it takes the name, so a power cut right
        // after cannot leave prefs.json on zeros (FS10), and it is removed on every error. std's
        // rename replaces with POSIX semantics on NTFS: a reader holding the file open does not
        // block it, where MoveFileExW is refused.
        let tmp = self.path.with_extension(format!("json.{}.tmp", std::process::id()));
        let written = std::fs::File::create(&tmp).and_then(|mut f| {
            use std::io::Write;
            f.write_all(body.as_bytes())?;
            f.sync_all()
        });
        let ok = written.is_ok() && std::fs::rename(&tmp, &self.path).is_ok();
        if !ok {
            let _ = std::fs::remove_file(&tmp);
        }
        ok
    }
}

/// Windows' app mode (Settings > Personalization > Colors), dark when it cannot be read.
#[cfg(windows)]
pub fn system_dark() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    let key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0".encode_utf16().collect();
    let value: Vec<u16> = "AppsUseLightTheme\0".encode_utf16().collect();
    let mut data: u32 = 1;
    let mut size = std::mem::size_of::<u32>() as u32;
    let r = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut data as *mut u32).cast(), &mut size)
    };
    r != 0 || data == 0
}

#[cfg(not(windows))]
pub fn system_dark() -> bool {
    true
}
