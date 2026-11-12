use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Msg(String),
    /// A delete's error that already says how many items it deleted (a walk bound's sentence,
    /// or an error given the count): `ops::delete_on` never adds the count to it again (RL5-1).
    #[error("{0}")]
    Tallied(String),
    /// sites.json or known_hosts.json is sound JSON but not in a shape this build can read at
    /// all: it is left as it is and no change is made to it (`path`: the file, for a Show
    /// button; review FR2-1).
    #[error("{text}")]
    Unreadable { text: String, path: String },
    #[error("Transfer cancelled")]
    Cancelled,
    #[error("Host key for {host} changed! Expected {expected}, got {actual}")]
    HostKeyChanged {
        host: String,
        expected: String,
        actual: String,
    },
    #[error("Unknown host key for {host}: {fingerprint}")]
    HostKeyUnknown { host: String, fingerprint: String },
    /// The server no longer offers the pinned key's type and presents another type instead
    /// (an upgrade dropping ssh-rsa, say): `fingerprint` is the new key's.
    #[error("Host key type for {host} changed from {old_type} to {new_type}: {fingerprint}")]
    HostKeyTypeChanged {
        host: String,
        old_type: String,
        new_type: String,
        fingerprint: String,
    },
    /// FTPS: a certificate no public authority vouches for and nobody pinned (self-signed,
    /// private CA, another host name). `reason` says which; the UI pins it via `trust_certificate`.
    #[error("Unknown certificate for {host}: {fingerprint} ({reason})")]
    CertUnknown {
        host: String,
        fingerprint: String,
        reason: String,
    },
    #[error("Certificate for {host} changed! Expected {expected}, got {actual}")]
    CertChanged {
        host: String,
        expected: String,
        actual: String,
    },
    /// The site says a password is saved, but the keychain has none (or cannot be read).
    #[error("Saved password unavailable: {0}")]
    SecretUnavailable(String),
    /// The edit copy holds bytes the server never got (a failed or cancelled save, or edits
    /// made after watching stopped); downloading would replace them.
    #[error("Unsent edits: {0} has changes that never reached the server")]
    UnsentEdits(String),
    /// An upload that the folder's listing showed as new found the name taken when its first
    /// write was about to start (`now`: what is there, `None` when the server would not say).
    /// The transfer decides about it as about any existing file (review SOL-FTP-1).
    #[error("{name}: another file took this name on the server after its folder was listed")]
    NameTaken { name: String, now: Option<crate::types::Entry> },
    /// A resumed download found the server's file is not the one its offset was chosen for
    /// (`size`, `modified`: what the server says now). Nothing was written (review SOL-FTP-3).
    #[error("{name}: the file on the server changed since it was compared; nothing was written")]
    SourceChanged { name: String, size: Option<u64>, modified: u64 },
    #[error("Authentication failed")]
    AuthFailed,
    /// An encrypted key file the passphrase given does not open (whatever its format).
    #[error("The passphrase does not open the key")]
    WrongPassphrase,
    #[error("Not connected")]
    NotConnected,
    /// A panic while the FTP link was in use: its state is unknown, so it must be redialled.
    #[error("FTP connection poisoned")]
    Poisoned,
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Ftp(#[from] suppaftp::FtpError),
    #[error("{0}")]
    Ssh(#[from] russh::Error),
    #[error("{0}")]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error("{0}")]
    Key(#[from] russh::keys::Error),
    #[error("Keychain: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}

impl AppError {
    /// True when the underlying connection is probably dead and a reconnect
    /// plus retry makes sense.
    pub fn is_connection_error(&self) -> bool {
        use std::io::ErrorKind as K;
        match self {
            AppError::NotConnected | AppError::Poisoned | AppError::Ssh(_) => true,
            AppError::Io(e) => matches!(
                e.kind(),
                K::ConnectionReset
                    | K::ConnectionAborted
                    | K::BrokenPipe
                    | K::UnexpectedEof
                    | K::TimedOut
                    | K::WouldBlock
                    | K::NotConnected
            ),
            // BadResponse also covers "could not parse SIZE" and a data socket closed
            // without close_notify: neither means the control link is dead.
            AppError::Ftp(suppaftp::FtpError::ConnectionError(e)) => matches!(
                e.kind(),
                K::ConnectionReset
                    | K::ConnectionAborted
                    | K::ConnectionRefused
                    | K::BrokenPipe
                    | K::UnexpectedEof
                    | K::TimedOut
                    | K::WouldBlock
                    | K::NotConnected
            ),
            AppError::Ftp(suppaftp::FtpError::UnexpectedResponse(r)) => {
                r.status == suppaftp::Status::NotAvailable
            }
            AppError::Sftp(russh_sftp::client::error::Error::Status(s)) => matches!(
                s.status_code,
                russh_sftp::protocol::StatusCode::ConnectionLost
                    | russh_sftp::protocol::StatusCode::NoConnection
            ),
            AppError::Sftp(_) => true,
            _ => false,
        }
    }
}

impl AppError {
    /// The server turned the login down (or its identity is in question): dialing again with
    /// the same credentials only adds failed logins, which lockout tools count.
    pub fn is_auth_failure(&self) -> bool {
        match self {
            AppError::AuthFailed
            | AppError::HostKeyChanged { .. }
            | AppError::HostKeyUnknown { .. }
            | AppError::HostKeyTypeChanged { .. }
            | AppError::WrongPassphrase
            | AppError::CertChanged { .. }
            | AppError::CertUnknown { .. }
            | AppError::Key(_) => true,
            // 530 is also how some servers say "too many connections" (ProFTPD's
            // MaxClientsPerUser): that one is worth a retry once the old link is gone.
            AppError::Ftp(suppaftp::FtpError::UnexpectedResponse(r)) => {
                r.status == suppaftp::Status::NotLoggedIn && !mentions_capacity(&String::from_utf8_lossy(&r.body))
            }
            _ => false,
        }
    }

    /// A server saying "no more connections now": worth sharing a link, not worth remembering
    /// forever. Transport failures (a blip, a timeout) are not refusals.
    pub fn is_refusal(&self) -> bool {
        use russh::Error as S;
        match self {
            AppError::Ftp(suppaftp::FtpError::UnexpectedResponse(_)) => true,
            // A socket closed, reset or silent before or during the key exchange, as on FTP.
            AppError::Ssh(
                S::IO(_)
                | S::HUP
                | S::Disconnect
                | S::ConnectionTimeout
                | S::KeepaliveTimeout
                | S::InactivityTimeout
                | S::Elapsed(_)
                | S::SendError
                | S::RecvError,
            ) => false,
            AppError::Ssh(_) => true,
            AppError::Ftp(_) | AppError::Io(_) => false,
            e => !e.is_connection_error(),
        }
    }
}

/// Server wording for a connection or session limit.
fn mentions_capacity(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    ["too many", "maximum", "max ", "limit", "clients", "connections", "sessions"].iter().any(|p| m.contains(p))
}

impl AppError {
    /// Disk or quota exhaustion: skipping past it would truncate every remaining file.
    pub fn is_storage_error(&self) -> bool {
        use std::io::ErrorKind as K;
        match self {
            AppError::Io(e) => matches!(e.kind(), K::StorageFull | K::QuotaExceeded | K::ReadOnlyFilesystem),
            AppError::Ftp(suppaftp::FtpError::UnexpectedResponse(r)) => matches!(
                r.status,
                suppaftp::Status::RequestedActionNotTaken | suppaftp::Status::ExceededStorage
            ),
            AppError::Sftp(russh_sftp::client::error::Error::Status(s)) => mentions_storage(&s.error_message),
            _ => false,
        }
    }
}

/// Server wording for a full disk or an exhausted quota (sftpgo: "denying write due to space
/// limit"). Only for status texts that carry no file name: a name could contain these words.
pub fn mentions_storage(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    ["quota", "no space", "disk full", "space limit"].iter().any(|p| m.contains(p))
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Msg(s)
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        AppError::Msg(s.to_string())
    }
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
