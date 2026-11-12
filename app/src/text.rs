//! Outside text as the install check words it (a signer's name, a file error, a list's app name):
//! the template's `clean_max` and `clean_wide`, so `check.rs` and `trust.rs` stay the family's
//! files. One set of invisible characters in the app: `format`'s (the template's), with every
//! control besides. Where the window shows names and server text as they are, `format::shown`
//! marks such characters instead; this drops them and cuts the text to a length.

/// Outside text as it may be shown: invisible characters gone, runs of whitespace (a newline
/// or tab included) one space, trimmed, at most `max` characters (an ellipsis marks a cut).
pub fn clean_max(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max * 4));
    let mut space = false;
    let mut n = 0usize;
    let mut cut = false;
    for c in s.chars() {
        if c.is_whitespace() || c == '\u{2028}' || c == '\u{2029}' {
            space = !out.is_empty();
            continue;
        }
        if c.is_control() || crate::format::invisible(c) {
            continue;
        }
        if space {
            if n + 1 >= max {
                cut = true;
                break;
            }
            out.push(' ');
            n += 1;
            space = false;
        }
        if n >= max {
            cut = true;
            break;
        }
        out.push(c);
        n += 1;
    }
    if cut {
        // Room for the ellipsis: drop the last character (never a byte: chars only).
        out.pop();
        out.push('…');
    }
    out
}

/// UTF-16 from Windows as shown text: a lone surrogate becomes U+FFFD, then cleaned.
pub fn clean_wide(w: &[u16], max: usize) -> String {
    clean_max(&String::from_utf16_lossy(w), max)
}
