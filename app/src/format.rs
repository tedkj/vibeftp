//! Display formatting: sizes, times, speeds, permissions, and names made safe to show.

/// `812 B`, `14.2 KB`, `2.1 MB`, `140 GB`: one decimal below 10, whole numbers above.
pub fn bytes(n: u64) -> String {
    let n = n as f64;
    if n < 1023.5 {
        return format!("{} B", n.round() as u64);
    }
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    let mut v = n / 1024.0;
    let mut i = 0;
    // 1023.6 KB rounds to "1024 KB"; bump it to the next unit instead.
    while v >= 1023.5 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v < 10.0 { format!("{v:.1} {}", UNITS[i]) } else { format!("{} {}", v.round() as u64, UNITS[i]) }
}

/// Local time, `2026-10-16 13:54`; empty for an unknown time (0).
pub fn when(ms: u64) -> String {
    if ms == 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

pub fn speed(bytes_per_sec: u64) -> String {
    bytes(bytes_per_sec) + "/s"
}

/// Percent done, 0..=100; 0 when the total is unknown.
pub fn pct(done: u64, total: Option<u64>) -> u32 {
    match total {
        Some(t) if t > 0 => ((done as f64 / t as f64) * 100.0).round().min(100.0) as u32,
        _ => 0,
    }
}

/// `755`
pub fn octal(mode: u32) -> String {
    format!("{:03o}", mode & 0o777)
}

/// `rwxr-xr-x`
pub fn rwx(mode: u32) -> String {
    let bits = b"rwxrwxrwx";
    (0..9).map(|i| if mode & (1 << (8 - i)) != 0 { bits[i] as char } else { '-' }).collect()
}

/// Marks that change how the text around them reads without showing themselves: direction
/// overrides and isolates (`invoice\u{202E}fdp.exe` reads "invoiceexe.pdf"), zero-width
/// spaces, word joiners, the BOM, the line and paragraph separators (a fake line break), the
/// soft hyphen and the Unicode tag characters (U+E0000..U+E007F): the template's set
/// (`VibeTemplate\template\src\text.rs`, IN-VibeFTP-5). Zero-width (non-)joiners stay: emoji and
/// scripts need them.
pub(crate) fn invisible(c: char) -> bool {
    matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// Text from outside (file names, server replies and errors, log lines) as one line on screen:
/// a tab is a space, every other control character and invisible mark is shown as U+FFFD, so
/// nothing can fake a line, recolour the log or turn a name around (VibeTrace TA-10). Display
/// only: the real name stays what paths and transfers use.
pub fn shown(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(|c| c.is_control() || invisible(c)) {
        return s.into();
    }
    s.chars().map(|c| if c == '\t' { ' ' } else if c.is_control() || invisible(c) { '\u{FFFD}' } else { c }).collect::<String>().into()
}

/// As `shown`, keeping line breaks (toasts, dialog texts and lists the app itself breaks into
/// lines); a CR before a line break goes.
pub fn shown_lines(s: &str) -> String {
    s.replace("\r\n", "\n").split('\n').map(shown).collect::<Vec<_>>().join("\n")
}
