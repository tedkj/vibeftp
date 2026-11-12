//! What the engine needs from the program around it: somewhere to report to, a way to hand
//! files to the shell, and the folders it keeps its files in. The app (`app/src/host.rs`) posts
//! the events to its UI event loop.

use crate::error::Result;
use crate::types::{Conflict, EditChanged, LogLine, Progress, SessionState, Skipped};
use std::path::PathBuf;

/// What the engine reports while it works.
pub enum Event {
    /// Bytes moved on a transfer (at most every 80 ms per transfer, plus each file's end).
    Progress(Progress),
    /// A transfer is parked on a conflict prompt until `Core::resolve_conflict` answers it.
    Conflict(Conflict),
    /// Items a tree transfer left out, with why.
    Skipped(Skipped),
    /// Connections in a session's pool, with an optional note ("Reconnecting…").
    SessionState(SessionState),
    /// An edit copy was saved (it stopped changing): queue its upload.
    EditChanged(EditChanged),
    /// A protocol log line.
    Log(LogLine),
    /// Something the user must see and dismiss, not a toast that fades: a damaged sites.json or
    /// known_hosts.json was kept aside (`path`: the kept copy).
    Notice { text: String, path: Option<String> },
}

pub trait Host: Send + Sync + 'static {
    /// Called from any thread, often from inside a transfer: must not block.
    fn emit(&self, event: Event);
    /// Open a file with its default app, or with the program `with` when given.
    fn open_path(&self, path: &str, with: Option<&str>) -> Result<()>;
    /// Show a file selected in its folder (Explorer).
    fn reveal(&self, path: &str) -> Result<()>;
}

/// Folders the engine keeps its files in.
#[derive(Clone, Debug)]
pub struct Paths {
    /// sites.json and known_hosts.json (`%APPDATA%\com.tedkj.vibeftp`, named by the app id).
    pub config: PathBuf,
    /// Per-user local data; edit copies live under `edit` (`%LOCALAPPDATA%\com.tedkj.vibeftp`).
    pub local_data: PathBuf,
    /// The user's home folder, the local pane's default. `None` when the system has none.
    pub home: Option<PathBuf>,
}
