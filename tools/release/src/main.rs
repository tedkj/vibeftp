//! vibeftp-release: the VibeWare release key, and signing an installer with it.
//!
//!   vibeftp-release keygen [--out <folder>]
//!       makes a new key pair: <folder>\release.key (minisign secret key, scrypt-encrypted) and
//!       release.key.pub; the folder defaults to %USERPROFILE%\.vibeware. Never overwrites a key.
//!       Prints the public key line (RW...) and its key id.
//!
//!   vibeftp-release sign <installer> --version 0.2.0 --url https://github.com/.../VibeFTP_0.2.0_x64-setup.exe
//!       [--key <release.key>] [--notes "..."]
//!       writes <installer>.sig (base64 of the minisign text) and latest.json beside it
//!
//!   vibeftp-release pubkey [--key ...]      prints the public key line the app compiles in
//!
//!   vibeftp-release verify <installer> --pubkey RW...
//!       checks the installer, its .sig and latest.json as a client will (release.ps1's last step)
//!
//! The key defaults to %USERPROFILE%\.vibeware\release.key. Its password comes from
//! VIBEWARE_SIGN_PASSWORD, or is asked on the console when that is unset (twice for keygen).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use vibeftp_release::{KDF, KEY_FILE, PUB_FILE, SecretKey, check_release, keygen, publish, release_tag, verify};

const PASSWORD_VAR: &str = "VIBEWARE_SIGN_PASSWORD";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// %USERPROFILE%\.vibeware: outside every repository. No profile, no default (never a relative
/// folder that could land inside a work tree).
fn key_folder() -> Result<PathBuf, String> {
    match std::env::var_os("USERPROFILE") {
        Some(p) if !p.is_empty() => Ok(PathBuf::from(p).join(".vibeware")),
        _ => Err("USERPROFILE is not set; name the folder with --out or the key with --key".into()),
    }
}

fn password(confirm: bool) -> Result<String, String> {
    if let Some(p) = std::env::var_os(PASSWORD_VAR) {
        return p.into_string().map_err(|_| format!("{PASSWORD_VAR} is not valid text"));
    }
    let first = console::ask(if confirm { "Password for the new key: " } else { "Key password: " })?;
    if confirm && console::ask("The same password again: ")? != first {
        return Err("the two passwords differ".into());
    }
    Ok(first)
}

fn key(args: &[String]) -> Result<SecretKey, String> {
    let path = match arg(args, "--key") {
        Some(p) => PathBuf::from(p),
        None => key_folder()?.join(KEY_FILE),
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    SecretKey::decode(&text, &password(false)?)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let dir = match arg(&args, "--out") {
                Some(p) => PathBuf::from(p),
                None => key_folder()?,
            };
            // Refused before a password is asked for.
            for f in [KEY_FILE, PUB_FILE] {
                if dir.join(f).symlink_metadata().is_ok() {
                    return Err(format!("{} already exists; a key is never overwritten", dir.join(f).display()));
                }
            }
            let key = keygen(&dir, &password(true)?, KDF)?;
            println!("{}\n{}", dir.join(KEY_FILE).display(), dir.join(PUB_FILE).display());
            println!("public key: {}\nkey id: {}", key.public_key(), key.key_id());
            Ok(())
        }
        Some("pubkey") => {
            println!("{}", key(&args)?.public_key());
            Ok(())
        }
        Some("sign") => {
            let file = PathBuf::from(args.get(1).ok_or("sign <installer>")?);
            let version = arg(&args, "--version").ok_or("--version is required")?;
            let url = arg(&args, "--url").ok_or("--url is required")?;
            let notes = arg(&args, "--notes").unwrap_or_default();
            let name = file.file_name().and_then(|n| n.to_str()).ok_or("the installer needs a file name")?;
            // Refused before the key is even read.
            check_release(&version, name, &url)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let (sig, manifest) = publish(&key(&args)?, &file, &version, &url, &notes, now, &rfc3339(now))?;
            println!("{}\n{}", sig.display(), manifest.display());
            Ok(())
        }
        // The version's release tag (`release_tag`), for release.ps1: one rule everywhere.
        Some("tag") => {
            let version = args.get(1).ok_or("tag <version>")?;
            println!("{}", release_tag(version));
            Ok(())
        }
        Some("verify") => {
            let file = PathBuf::from(args.get(1).ok_or("verify <installer>")?);
            let pubkey = arg(&args, "--pubkey").ok_or("--pubkey is required (the key the app compiles in)")?;
            verify(&file, &pubkey)?;
            println!("verified: {} with {pubkey}", file.display());
            Ok(())
        }
        _ => Err("usage: vibeftp-release keygen [--out <folder>] | sign <installer> --version <v> --url <url> | tag <version> | verify <installer> --pubkey <key> | pubkey".into()),
    }
}

/// A password typed on the console without echo (no crate for it: two kernel32 calls).
mod console {
    use std::io::Write;

    #[cfg(windows)]
    mod echo {
        use std::ffi::c_void;

        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        const ENABLE_ECHO_INPUT: u32 = 0x4;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> *mut c_void;
            fn GetConsoleMode(h: *mut c_void, mode: *mut u32) -> i32;
            fn SetConsoleMode(h: *mut c_void, mode: u32) -> i32;
        }

        /// Echo off while it lives, when stdin is a console (piped input is read as it comes).
        pub struct Off(Option<(*mut c_void, u32)>);

        impl Off {
            pub fn new() -> Off {
                // SAFETY: plain kernel32 calls on this process's own stdin handle; `mode` is a
                // live local.
                unsafe {
                    let h = GetStdHandle(STD_INPUT_HANDLE);
                    let mut mode = 0u32;
                    if !h.is_null() && GetConsoleMode(h, &mut mode) != 0 && SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) != 0 {
                        return Off(Some((h, mode)));
                    }
                }
                Off(None)
            }
        }

        impl Drop for Off {
            fn drop(&mut self) {
                if let Some((h, mode)) = self.0 {
                    // SAFETY: the handle and mode GetConsoleMode gave us, restored as they were.
                    unsafe {
                        SetConsoleMode(h, mode);
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    mod echo {
        pub struct Off;

        impl Off {
            pub fn new() -> Off {
                Off
            }
        }
    }

    pub fn ask(prompt: &str) -> Result<String, String> {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let read = {
            let _off = echo::Off::new();
            std::io::stdin().read_line(&mut line)
        };
        eprintln!();
        read.map_err(|e| format!("reading the password: {e}"))?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}

/// UTC, seconds precision (no date crate needed for one timestamp).
fn rfc3339(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    // Civil from days (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("vibeftp-release: {e}");
        std::process::exit(1);
    }
}
