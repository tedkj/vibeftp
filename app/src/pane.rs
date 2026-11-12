//! One file pane's state: the listing, the sorted/filtered view of it, selection, cursor, the
//! navigation sequence. The UI reads it through `FileModel`. Every change says which view rows it touched, so the list only
//! repaints those.

use std::collections::HashSet;
use vibeftp_core::types::Entry;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Local,
    Remote,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortKey {
    Name,
    Size,
    Modified,
}

/// What a change did to the visible rows.
#[derive(Debug, PartialEq)]
pub enum Change {
    None,
    /// The view was rebuilt (new listing, sort or filter): everything.
    Reset,
    /// Only these view rows changed (selection or cursor).
    Rows(Vec<usize>),
}

pub struct Pane {
    pub side: Side,
    pub path: String,
    entries: Vec<Entry>,
    /// Collation keys, parallel to `entries`.
    keys: Vec<Vec<u8>>,
    /// Indices into `entries`, sorted and filtered: what the list shows.
    view: Vec<usize>,
    selected: HashSet<String>,
    cursor: Option<String>,
    anchor: Option<String>,
    /// Bumped on every navigation; a listing that comes back for an older seq is dropped.
    pub seq: u64,
    /// Bumped by every refresh: only the newest refresh's answer lands (S42).
    pub refresh_gen: u64,
    /// A name to select once the newest refresh lands (New folder, Rename); a navigation drops it.
    pub select_after: Option<String>,
    pub loading: bool,
    /// Local items left out of `entries` because their names are not valid Unicode: no action
    /// may land on them, but the pane says they are there (review FR-10).
    pub hidden: usize,
    sort_key: SortKey,
    sort_asc: bool,
    filter: String,
}

impl Pane {
    pub fn new(side: Side) -> Self {
        Pane {
            side,
            path: String::new(),
            entries: Vec::new(),
            keys: Vec::new(),
            view: Vec::new(),
            selected: HashSet::new(),
            cursor: None,
            anchor: None,
            seq: 0,
            refresh_gen: 0,
            select_after: None,
            loading: false,
            hidden: 0,
            sort_key: SortKey::Name,
            sort_asc: true,
            filter: String::new(),
        }
    }

    pub fn remote(&self) -> bool {
        self.side == Side::Remote
    }

    // ---------- reading ----------

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    pub fn view_len(&self) -> usize {
        self.view.len()
    }
    pub fn view_entry(&self, i: usize) -> Option<&Entry> {
        self.view.get(i).map(|&e| &self.entries[e])
    }
    pub fn view_index_of(&self, path: &str) -> Option<usize> {
        self.view.iter().position(|&e| self.entries[e].path == path)
    }
    pub fn is_selected(&self, path: &str) -> bool {
        self.selected.contains(path)
    }
    pub fn selected_count(&self) -> usize {
        self.selected.len()
    }
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
    pub fn cursor_index(&self) -> Option<usize> {
        self.cursor.as_deref().and_then(|c| self.view_index_of(c))
    }
    pub fn sort(&self) -> (SortKey, bool) {
        (self.sort_key, self.sort_asc)
    }
    pub fn filter(&self) -> &str {
        &self.filter
    }
    /// The selected entries, in listing order.
    pub fn selected_entries(&self) -> Vec<Entry> {
        self.entries.iter().filter(|e| self.selected.contains(&e.path)).cloned().collect()
    }
    pub fn counts(&self) -> (usize, usize) {
        let dirs = self.entries.iter().filter(|e| e.is_dir).count();
        (dirs, self.entries.len() - dirs)
    }
    pub fn selected_bytes(&self) -> u64 {
        self.entries.iter().filter(|e| self.selected.contains(&e.path)).map(|e| e.size).sum()
    }

    // ---------- listing, sort, filter ----------

    /// A fresh listing. One row per path: a parser that collapses two names onto one path must
    /// neither show a duplicate nor let a selection act on a row the view does not show.
    pub fn set_entries(&mut self, entries: Vec<Entry>) -> Change {
        self.entries = one_per_path(entries);
        self.keys = self.entries.iter().map(|e| collation_key(&e.name)).collect();
        self.rebuild();
        Change::Reset
    }

    /// Navigation landed somewhere new: nothing selected, no cursor, no filter.
    pub fn arrive(&mut self, path: String, entries: Vec<Entry>) -> Change {
        self.path = path;
        self.select_after = None;
        self.selected.clear();
        self.cursor = None;
        self.anchor = None;
        self.filter.clear();
        self.set_entries(entries)
    }

    /// A refresh of the folder on screen: selection keeps what still exists.
    pub fn refreshed(&mut self, entries: Vec<Entry>) -> Change {
        let entries = one_per_path(entries);
        // Nothing changed (the routine refresh after a transfer elsewhere): the rows stay, and
        // with them a drag out of this pane, the scroll position and the hover.
        if entries == self.entries {
            return Change::None;
        }
        self.set_entries(entries);
        let have: HashSet<&str> = self.entries.iter().map(|e| e.path.as_str()).collect();
        self.selected.retain(|p| have.contains(p.as_str()));
        Change::Reset
    }

    pub fn sort_by(&mut self, key: SortKey) -> Change {
        if self.sort_key == key {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_key = key;
            self.sort_asc = key == SortKey::Name;
        }
        self.rebuild();
        Change::Reset
    }

    /// Filtering also drops selected rows it hides, so Delete or F5 never act on invisible items.
    pub fn set_filter(&mut self, filter: &str) -> Change {
        if self.filter == filter {
            return Change::None;
        }
        self.filter = filter.to_string();
        self.rebuild();
        let visible: HashSet<&str> = self.view.iter().map(|&i| self.entries[i].path.as_str()).collect();
        self.selected.retain(|p| visible.contains(p.as_str()));
        Change::Reset
    }

    fn rebuild(&mut self) {
        let f = self.filter.to_lowercase();
        // The name as listed, or as shown (a control or direction mark shows as U+FFFD, and the
        // user can only type what they see, review FR-11).
        let hit = |name: &str| name.to_lowercase().contains(&f) || crate::format::shown(name).to_lowercase().contains(&f);
        let mut view: Vec<usize> = (0..self.entries.len())
            .filter(|&i| f.is_empty() || hit(&self.entries[i].name))
            .collect();
        let (entries, keys, key, asc) = (&self.entries, &self.keys, self.sort_key, self.sort_asc);
        view.sort_by(|&a, &b| order(entries, keys, key, asc, a, b));
        self.view = view;
    }

    // ---------- selection ----------

    fn changed_rows(&self, before: &HashSet<String>, before_cursor: Option<&str>) -> Change {
        let rows: Vec<usize> = self
            .view
            .iter()
            .enumerate()
            .filter(|&(_, &e)| {
                let p = self.entries[e].path.as_str();
                before.contains(p) != self.selected.contains(p)
                    || (before_cursor == Some(p)) != (self.cursor.as_deref() == Some(p))
            })
            .map(|(i, _)| i)
            .collect();
        if rows.is_empty() { Change::None } else { Change::Rows(rows) }
    }

    /// Click semantics: plain = only this one; Ctrl toggles; Shift selects the range from the
    /// anchor (or cursor) to here.
    pub fn select(&mut self, view_index: usize, ctrl: bool, shift: bool) -> Change {
        let Some(path) = self.view_entry(view_index).map(|e| e.path.clone()) else { return Change::None };
        let (before, before_cursor) = (self.selected.clone(), self.cursor.clone());
        if shift {
            let from = self.anchor.as_deref().or(self.cursor.as_deref()).and_then(|p| self.view_index_of(p));
            if let Some(a) = from {
                let (lo, hi) = if a < view_index { (a, view_index) } else { (view_index, a) };
                self.selected = self.view[lo..=hi].iter().map(|&e| self.entries[e].path.clone()).collect();
                self.cursor = Some(path);
                return self.changed_rows(&before, before_cursor.as_deref());
            }
        }
        if ctrl {
            if !self.selected.remove(&path) {
                self.selected.insert(path.clone());
            }
        } else {
            self.selected = HashSet::from([path.clone()]);
        }
        self.cursor = Some(path.clone());
        self.anchor = Some(path);
        self.changed_rows(&before, before_cursor.as_deref())
    }

    /// Select the row with this path (after a mkdir or rename lands): selection, cursor, anchor.
    pub fn select_path(&mut self, path: Option<String>) -> Change {
        let (before, before_cursor) = (self.selected.clone(), self.cursor.clone());
        self.selected = path.iter().cloned().collect();
        self.cursor = path.clone();
        self.anchor = path;
        self.changed_rows(&before, before_cursor.as_deref())
    }

    pub fn select_all(&mut self) -> Change {
        let before = self.selected.clone();
        self.selected = self.view.iter().map(|&e| self.entries[e].path.clone()).collect();
        self.changed_rows(&before, self.cursor.clone().as_deref())
    }

    pub fn clear_selection(&mut self) -> Change {
        let before = std::mem::take(&mut self.selected);
        self.changed_rows(&before, self.cursor.clone().as_deref())
    }

    /// Arrow keys: move the cursor, selecting the row (extending from the anchor with Shift).
    pub fn move_cursor(&mut self, delta: i64, extend: bool) -> Change {
        let n = self.view.len() as i64;
        if n == 0 {
            return Change::None;
        }
        let i = self.cursor_index().map(|i| i as i64).unwrap_or(-1);
        let next = (i + delta).clamp(0, n - 1) as usize;
        self.select(next, false, extend)
    }

    /// Type-ahead: the first row whose name starts with this character.
    pub fn jump_to(&mut self, c: char) -> Change {
        let c: String = c.to_lowercase().collect();
        match self.view.iter().position(|&e| self.entries[e].name.to_lowercase().starts_with(&c)) {
            Some(i) => self.select(i, false, false),
            None => Change::None,
        }
    }
}

/// The list's order of rows `a` and `b`: folders first, then the sort key, then the name's
/// collation key. A total order (VibeRename RR-1: a `sort_by` with an inconsistent comparator
/// panics, and with `panic = "abort"` that kills the app): every step compares values computed
/// once per listing (byte strings, numbers), never asks Windows again mid-sort.
fn order(entries: &[Entry], keys: &[Vec<u8>], key: SortKey, asc: bool, a: usize, b: usize) -> std::cmp::Ordering {
    let (x, y) = (&entries[a], &entries[b]);
    if x.is_dir != y.is_dir {
        return if x.is_dir { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater };
    }
    let by_name = keys[a].cmp(&keys[b]);
    let dir = |o: std::cmp::Ordering| if asc { o } else { o.reverse() };
    match key {
        SortKey::Name => dir(by_name),
        SortKey::Size => dir(x.size.cmp(&y.size)).then(by_name),
        SortKey::Modified => dir(x.modified.cmp(&y.modified)).then(by_name),
    }
}

fn one_per_path(entries: Vec<Entry>) -> Vec<Entry> {
    let mut seen = HashSet::new();
    entries.into_iter().filter(|e| seen.insert(e.path.clone())).collect()
}

/// Windows' own collation (as Explorer and the browser's Intl.Collator with base sensitivity
/// order names: case, accents and width ignored), as a byte sort key computed once per listing.
#[cfg(windows)]
fn collation_key(name: &str) -> Vec<u8> {
    use windows_sys::Win32::Globalization::{
        LCMAP_SORTKEY, LCMapStringEx, NORM_IGNORECASE, NORM_IGNOREKANATYPE, NORM_IGNORENONSPACE, NORM_IGNOREWIDTH,
    };
    let wide: Vec<u16> = name.encode_utf16().collect();
    if wide.is_empty() {
        return Vec::new();
    }
    let flags = LCMAP_SORTKEY | NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH;
    unsafe {
        let n = LCMapStringEx(
            std::ptr::null(),
            flags,
            wide.as_ptr(),
            wide.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        if n <= 0 {
            return name.to_lowercase().into_bytes();
        }
        let mut key = vec![0u8; n as usize];
        let m = LCMapStringEx(
            std::ptr::null(),
            flags,
            wide.as_ptr(),
            wide.len() as i32,
            key.as_mut_ptr() as *mut u16,
            n,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        key.truncate(m.max(0) as usize);
        key
    }
}

#[cfg(not(windows))]
fn collation_key(name: &str) -> Vec<u8> {
    name.to_lowercase().into_bytes()
}
