//! Forwards protocol-level log lines to the UI as `Event::Log`.
//! FTP control traffic comes from suppaftp's trace logs; SFTP ops are logged
//! by our own code under the `vibeftp` target.

use crate::host::{Event, Host};
use crate::types::LogLine;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static HOST: OnceLock<Arc<dyn Host>> = OnceLock::new();

struct Forwarder;

impl log::Log for Forwarder {
    fn enabled(&self, m: &log::Metadata) -> bool {
        let t = m.target();
        t.starts_with("vibeftp") || t.starts_with("suppaftp")
    }

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let raw = r.args().to_string();
        let line = if r.target().starts_with("suppaftp") {
            match shape_ftp(&raw) {
                Some(l) => l,
                None => return,
            }
        } else {
            raw
        };
        let Some(host) = HOST.get() else { return };
        let line = if line.len() > 4096 {
            let mut cut = 4096;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            format!("{}… ({} bytes)", &line[..cut], line.len())
        } else {
            line
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        host.emit(Event::Log(LogLine {
            ts,
            level: r.level().to_string().to_lowercase(),
            line,
        }));
    }

    fn flush(&self) {}
}

/// Keep only control-channel traffic, mask passwords, tidy the formatting.
fn shape_ftp(raw: &str) -> Option<String> {
    if let Some(cmd) = raw.strip_prefix("CC OUT: ") {
        let cmd = cmd.trim();
        if cmd.to_uppercase().starts_with("PASS ") {
            return Some("> PASS ****".into());
        }
        return Some(format!("> {cmd}"));
    }
    if let Some(resp) = raw.strip_prefix("CC IN: ") {
        let s = resp.trim();
        // The library logs reply lines as byte vectors (`[50, 50, 48, ...]`).
        let text = if s.starts_with('[') && s.ends_with(']') {
            let bytes: Vec<u8> = s[1..s.len() - 1]
                .split(',')
                .filter_map(|n| n.trim().parse::<u8>().ok())
                .collect();
            String::from_utf8_lossy(&bytes).to_string()
        } else {
            s.trim_matches('"').to_string()
        };
        let text = text
            .trim_end_matches(['\r', '\n'])
            .trim_end_matches("\\r\\n")
            .to_string();
        // The same reply line is traced twice (line read + response parse): drop the echo.
        let dup = LAST.with(|last| {
            let mut last = last.borrow_mut();
            if last.as_deref() == Some(text.as_str()) {
                *last = None;
                true
            } else {
                *last = Some(text.clone());
                false
            }
        });
        if dup {
            return None;
        }
        return Some(format!("< {text}"));
    }
    None
}

thread_local! {
    static LAST: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

pub fn install(host: Arc<dyn Host>) {
    let _ = HOST.set(host);
    if log::set_boxed_logger(Box::new(Forwarder)).is_ok() {
        log::set_max_level(log::LevelFilter::Trace);
    }
}
