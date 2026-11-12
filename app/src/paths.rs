//! Path helpers: joining, parents, names, relative segments, safe names.
//! Remote paths are POSIX; local ones are Windows paths (either separator accepted).

fn is_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn starts_with_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

pub fn join_path(dir: &str, name: &str, remote: bool) -> String {
    if remote {
        if dir.is_empty() || dir == "/" {
            return format!("/{name}");
        }
        return if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") };
    }
    let sep = if dir.contains('\\') || starts_with_drive(dir) { '\\' } else { '/' };
    if dir.ends_with(sep) { format!("{dir}{name}") } else { format!("{dir}{sep}{name}") }
}

/// Parent of a path, or `None` at a root (`/`, a drive, `\\server` or `\\server\share`).
pub fn parent_path(path: &str, remote: bool) -> Option<String> {
    if remote {
        let t = path.trim_end_matches('/');
        if t.is_empty() {
            return None;
        }
        return Some(match t.rfind('/') {
            Some(i) if i > 0 => t[..i].to_string(),
            _ => "/".to_string(),
        });
    }
    let norm = path.trim_end_matches(['\\', '/']);
    if norm.is_empty() || is_drive(norm) || is_unc_root(norm) {
        return None;
    }
    let i = norm.rfind(['\\', '/'])?;
    let p = &norm[..i];
    if is_drive(p) {
        return Some(format!("{p}\\"));
    }
    Some(if p.is_empty() { "/".to_string() } else { p.to_string() })
}

/// `\\server` or `\\server\share`, nothing below.
fn is_unc_root(norm: &str) -> bool {
    let Some(rest) = norm.strip_prefix("\\\\") else { return false };
    let parts: Vec<&str> = rest.split('\\').collect();
    !rest.is_empty() && parts.len() <= 2 && parts.iter().all(|p| !p.is_empty())
}

pub fn base_name(path: &str) -> String {
    let t = path.trim_end_matches(['\\', '/']);
    match t.rfind(['\\', '/']) {
        Some(i) => t[i + 1..].to_string(),
        None => t.to_string(),
    }
}

/// Segments of `path` below `root`, or `None` when it is not under it.
pub fn relative_segments(root: &str, path: &str, remote: bool) -> Option<Vec<String>> {
    let trim = |s: &str| -> String {
        if remote { s.trim_end_matches('/').to_string() } else { s.trim_end_matches(['\\', '/']).to_string() }
    };
    let (r, p) = (trim(root), trim(path));
    let eq = |a: &str, b: &str| if remote { a == b } else { a.to_lowercase() == b.to_lowercase() };
    if eq(&p, &r) {
        return Some(Vec::new());
    }
    if p.len() <= r.len() || !p.is_char_boundary(r.len()) || !eq(&p[..r.len()], &r) {
        return None;
    }
    let rest = &p[r.len()..];
    if !rest.starts_with('/') && (remote || !rest.starts_with('\\')) {
        return None;
    }
    let segs = if remote { rest.split('/').collect::<Vec<_>>() } else { rest.split(['\\', '/']).collect() };
    Some(segs.into_iter().filter(|s| !s.is_empty()).map(str::to_string).collect())
}

pub fn join_segments(root: &str, segs: &[String], remote: bool) -> String {
    segs.iter().fold(root.to_string(), |p, s| join_path(&p, s, remote))
}

/// Collapse `//`, resolve `.` and `..`, drop the trailing `/`.
pub fn normalize_remote(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// Case folded one character at a time, as the backend's case_key and NTFS do (no final sigma).
pub fn case_key(s: &str) -> String {
    s.replace('Σ', "σ").to_lowercase()
}

/// A server-supplied name must be a plain file name this computer can store.
pub fn is_safe_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.chars().count() > 255 {
        return false;
    }
    if name.chars().any(|c| "\\/:*?\"<>|".contains(c) || (c as u32) < 0x20) {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    // The engine's rule (every Win32 device name, IN-VibeFTP-6): the window refuses what the
    // engine would.
    !vibeftp_core::protocol::is_device(name)
}
