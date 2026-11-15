use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ftp,
    Ftps,
    Sftp,
}

impl Protocol {
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Ftp | Protocol::Ftps => 21,
            Protocol::Sftp => 22,
        }
    }
}

/// A saved site. The password never lives in this struct on disk;
/// it goes to the OS keychain keyed by the site id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub key_path: String,
    #[serde(default)]
    pub remote_path: String,
    #[serde(default)]
    pub local_path: String,
    /// No longer used: FTPS certificates are trusted by pinning (`trust_certificate`). Kept so
    /// sites.json files that still carry it load and save unchanged.
    #[serde(default)]
    pub insecure_tls: bool,
    /// Whether a password is stored in the keychain for this site.
    #[serde(default)]
    pub has_password: bool,
    /// What the keychain secret was saved as: `"passphrase"` (an SFTP key's, a local secret) or
    /// `"password"` (the server's login). Empty for a site saved before this field: read as what
    /// the site needs now (`stored_secret`). A secret is only ever used as what it was saved as
    /// (review SNA5).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_for: String,
    /// Max simultaneous connections for transfers. 0 = protocol default.
    #[serde(default)]
    pub parallel: u8,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    /// Last visited folders, restored on connect when the site has no fixed path.
    #[serde(default)]
    pub last_remote: String,
    #[serde(default)]
    pub last_local: String,
    /// FTP data connection mode: "passive" (default) or "active".
    #[serde(default)]
    pub ftp_mode: String,
    /// Fields this build does not know (a newer VibeFTP's): kept as they are through every save
    /// (review FR2-1).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Site {
    /// Pool dials must not fail just because the configured start folder went away.
    pub fn for_pool(&self) -> Site {
        let mut s = self.clone();
        s.remote_path.clear();
        s
    }

    /// What the site's secret is now: an SFTP key's passphrase, or a login password.
    pub fn wants_secret(&self) -> &'static str {
        if self.protocol == Protocol::Sftp && !self.key_path.is_empty() { "passphrase" } else { "password" }
    }

    /// What the secret in the keychain was saved as (a site from before `secret_for`: what the
    /// site needs now, the only thing an older build could have meant).
    pub fn stored_secret(&self) -> &str {
        if self.secret_for.is_empty() { self.wants_secret() } else { &self.secret_for }
    }

    /// Whether the secret saved for `before` (this site as it was saved) still means what it
    /// was saved as now that the site is this: the same kind of secret (SNA5), and never a
    /// password that only went inside SFTP or FTPS now going out over plain FTP (X15CRY-4).
    /// Not kept: a save forgets it unless a new one is typed.
    pub fn keeps_secret_of(&self, before: &Site) -> bool {
        let unencrypted = self.protocol == Protocol::Ftp && before.protocol != Protocol::Ftp;
        before.stored_secret() == self.wants_secret() && !unencrypted
    }
}

impl Site {
    /// Transfers that may run at once (connections minus the browse slot).
    pub fn transfer_slots(&self) -> usize {
        let m = self.max_connections();
        if m > 1 { m - 1 } else { 1 }
    }

    pub fn max_connections(&self) -> usize {
        if self.parallel > 0 {
            return (self.parallel as usize).min(8);
        }
        match self.protocol {
            // Slot 0 browses; the rest carry transfers.
            Protocol::Sftp => 4,
            Protocol::Ftp | Protocol::Ftps => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub name: String,
    pub remote: String,
    pub local: String,
    /// Fields this build does not know, kept as they are (review FR2-1).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The saved sites as this build reads them.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SiteList {
    pub sites: Vec<Site>,
    /// Entries of sites.json this build cannot read (a newer VibeFTP's, a hand edit gone
    /// wrong): not shown, never dropped, carried through every save unchanged (review FR2-1).
    pub unreadable: usize,
}

/// A damaged file VibeFTP kept aside (`sites.json.broken`, `known_hosts.json.broken-2`, ...)
/// and what the notice about it says (review FR2-6).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Kept {
    /// The kept copy's file name.
    pub name: String,
    pub path: String,
    pub text: String,
}

/// A host whose pin is in a kept copy of a damaged known_hosts.json (review FR2-2).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PinnedBefore {
    /// The kept copy's file name.
    pub file: String,
    /// When it was set aside (ms).
    pub at: u64,
    /// The pin it held, when it can be read out of it.
    pub pin: Option<String>,
    /// The kept copy names this server. `false`: no key at all can be read out of it (a
    /// zero-filled file, say), so this server may have been in it (review FR3-1).
    pub named: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    /// Symbolic link (is_dir/size describe the target when it could be followed).
    #[serde(default)]
    pub is_link: bool,
    pub size: u64,
    /// Unix milliseconds, 0 if unknown.
    pub modified: u64,
    /// POSIX permission bits (0o755 etc), when known.
    #[serde(default)]
    pub mode: Option<u32>,
}

pub fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub id: String,
    pub file: String,
    pub transferred: u64,
    pub total: Option<u64>,
    /// Bytes actually moved by this transfer so far (skips and resume offsets excluded).
    pub moved: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub id: String,
    pub names: Vec<String>,
    /// Why each of `names` was left out (same order).
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectResult {
    pub session: String,
    pub cwd: String,
    pub parallel: usize,
}

/// Sent to the UI when a transfer finds its destination already exists.
#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub id: String,
    pub transfer: String,
    pub direction: String,
    pub name: String,
    /// Remote path of the file in question: in a tree, `name` alone does not say which folder.
    pub path: String,
    pub src_size: u64,
    pub dst_size: u64,
    pub src_modified: u64,
    pub dst_modified: u64,
}

/// What to do with an existing destination.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Ask,
    Overwrite,
    Resume,
    Skip,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Overwrite,
    Resume,
    Skip,
    Cancel,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Decision {
    pub action: Action,
    pub all: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub ts: u64,
    pub level: String,
    pub line: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionState {
    pub session: String,
    pub connections: usize,
    pub busy: usize,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EditChanged {
    pub session: String,
    pub remote: String,
    pub local: String,
    pub name: String,
}

/// Join a remote (POSIX) path and a child name.
pub fn join_remote(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Split a remote path into (parent, name).
pub fn split_remote(path: &str) -> (String, String) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => ("/".to_string(), trimmed[1..].to_string()),
        Some(i) => (trimmed[..i].to_string(), trimmed[i + 1..].to_string()),
        None => (".".to_string(), trimmed.to_string()),
    }
}
