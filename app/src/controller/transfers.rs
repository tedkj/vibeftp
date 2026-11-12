//! The transfer queue: rows, the pump (its path-key rules keep two
//! writes to one destination, or a write and a read of one path, from ever running at once),
//! progress, conflicts and their "apply to all" scope, cancel, and the refreshes that finished
//! transfers schedule.

use super::{App, idx, summarise};
use crate::format::{bytes, pct, shown, speed};
use crate::model::QueueModel;
use crate::pane::Side;
use crate::paths::{base_name, case_key, is_safe_name, join_path, parent_path};
use crate::{ConflictInfo, ToastKind};
use slint::{Timer, TimerMode};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};
use vibeftp_core::error::AppError;
use vibeftp_core::types::{Action, Conflict, Entry, Policy, Progress, Skipped};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Queued,
    Active,
    Done,
    Error,
    Cancelled,
    Skipped,
}

impl Status {
    pub fn live(self) -> bool {
        matches!(self, Status::Queued | Status::Active)
    }
    pub fn label(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Active => "active",
            Status::Done => "done",
            Status::Error => "error",
            Status::Cancelled => "cancelled",
            Status::Skipped => "skipped",
        }
    }
}

pub struct Transfer {
    pub id: String,
    pub session: String,
    pub download: bool,
    pub name: String,
    pub src: String,
    pub dst: String,
    pub is_dir: bool,
    pub policy: Policy,
    pub status: Status,
    pub file: String,
    pub transferred: u64,
    pub total: Option<u64>,
    pub error: Option<String>,
    pub started_at: Option<Instant>,
    pub ended_at: Option<Instant>,
    /// Bytes moved so far as reported by the backend.
    pub moved: Option<u64>,
    /// Set when a save arrived while this file was still uploading: run it again after.
    pub requeue: bool,
    /// The user asked for this one to stop; any failure after that is "cancelled", not an error.
    pub cancel_requested: bool,
    pub refresh: (Side, String),
    /// Rows queued by one action share a batch: "Cancel, apply to all" stops only that batch.
    pub batch: u64,
    /// An edit-and-watch save (src is the edit copy).
    pub edit: bool,
    /// Items a tree transfer left out, with why.
    pub left_out: Option<Vec<(String, String)>>,
}

pub type TRef = Rc<RefCell<Transfer>>;

/// A transfer as the UI describes it, before it gets an id, a session and a status.
pub struct NewTransfer {
    pub download: bool,
    pub name: String,
    pub src: String,
    pub dst: String,
    pub is_dir: bool,
    pub policy: Policy,
    pub refresh: (Side, String),
    pub edit: bool,
}

/// What a transfer writes or reads, in a form two of them can be compared by: case folded
/// (Windows always, many servers too), `.`/`..` segments and doubled separators collapsed.
pub fn path_key(download: bool, path: &str) -> String {
    let sep = if download { '\\' } else { '/' };
    let norm: String = case_key(path).chars().map(|c| if c == '\\' || c == '/' { sep } else { c }).collect();
    let mut parts: Vec<&str> = Vec::new();
    let mut prev_sep = false;
    for seg in norm.split(sep) {
        // Doubled separators: skip the empty segments after the first.
        if seg.is_empty() && !parts.is_empty() {
            prev_sep = true;
            continue;
        }
        let _ = prev_sep;
        if seg == "." {
            continue;
        }
        if seg == ".." {
            if parts.len() > 1 || parts.first().is_some_and(|p| !p.is_empty()) {
                parts.pop();
            }
            continue;
        }
        parts.push(seg);
    }
    format!("{}:{}", if download { "download" } else { "upload" }, parts.join(&sep.to_string()))
}

pub fn dst_key(t: &Transfer) -> String {
    path_key(t.download, &t.dst)
}

/// What a transfer reads, keyed as the opposite direction's destination: a download of a file
/// an upload is still reading (or the reverse) must wait; read/read may overlap.
pub fn src_key(t: &Transfer) -> String {
    path_key(!t.download, &t.src)
}

/// The same destination, or one inside the other.
pub fn overlaps(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let sep = if a.starts_with("download:") { '\\' } else { '/' };
    a.starts_with(&format!("{b}{sep}")) || b.starts_with(&format!("{a}{sep}"))
}

/// The queue's counters for the current session's transfers only.
pub struct Stats {
    pub active: Vec<TRef>,
    pub pending: usize,
    pub done: usize,
    pub failed: usize,
}

impl App {
    // ---------- reading ----------

    pub(crate) fn stats(&self) -> Stats {
        let session = self.st.borrow().session.clone();
        let mut s = Stats { active: Vec::new(), pending: 0, done: 0, failed: 0 };
        for tr in self.queue.borrow().iter() {
            let t = tr.borrow();
            if Some(&t.session) != session.as_ref() {
                continue;
            }
            match t.status {
                Status::Active => {
                    s.active.push(tr.clone());
                    s.pending += 1;
                }
                Status::Queued => s.pending += 1,
                Status::Error => s.failed += 1,
                Status::Done if t.left_out.is_some() => s.failed += 1,
                Status::Done => s.done += 1,
                _ => {}
            }
        }
        s
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.stats().pending
    }

    /// What a quit would cut short, by identity: queued or running transfers (any session),
    /// files open for editing, and copies with edits the server never got (by name, the second
    /// of a name counted apart: a save that fails meanwhile is new work, RVA6-4).
    pub(crate) fn work(&self) -> std::collections::HashSet<String> {
        let mut w: std::collections::HashSet<String> = self
            .queue
            .borrow()
            .iter()
            .filter(|t| matches!(t.borrow().status, Status::Queued | Status::Active))
            .map(|t| format!("t:{}", t.borrow().id))
            .collect();
        w.extend(self.st.borrow().editing.iter().map(|e| format!("e:{}|{}", e.session, e.local)));
        for name in self.backend.unsent_edits() {
            let n = (1..).find(|n| !w.contains(&format!("u:{n}:{name}"))).unwrap_or(1);
            w.insert(format!("u:{n}:{name}"));
        }
        w
    }

    /// Bytes per second, smoothed over the last three samples.
    fn speed_now(&self) -> u64 {
        let st = self.st.borrow();
        let s: Vec<u64> = st.samples.iter().rev().take(3).copied().collect();
        if s.is_empty() { 0 } else { s.iter().sum::<u64>() / s.len() as u64 }
    }

    /// 0..1 progress of the current files, -1 when unknown, below -1 when idle.
    fn overall_progress(&self, pending: usize) -> f32 {
        if pending == 0 {
            return -2.0;
        }
        let session = self.st.borrow().session.clone();
        let q = self.queue.borrow();
        let live: Vec<_> = q.iter().filter(|t| {
            let t = t.borrow();
            t.status.live() && Some(&t.session) == session.as_ref()
        }).collect();
        let known: Vec<_> = live.iter().filter(|t| t.borrow().total.is_some_and(|x| x > 0)).collect();
        if known.is_empty() {
            return if live.iter().any(|t| t.borrow().status == Status::Active) { -1.0 } else { -2.0 };
        }
        let total: u64 = known.iter().map(|t| t.borrow().total.unwrap_or(0)).sum();
        let done: u64 = known.iter().map(|t| { let t = t.borrow(); t.transferred.min(t.total.unwrap_or(0)) }).sum();
        if total == 0 { -2.0 } else { done as f32 / total as f32 }
    }

    // ---------- pushing to the window ----------

    pub(crate) fn push_transfers(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let stats = self.stats();
        let sp = self.speed_now();
        let (has_rows, finished) = {
            let q = self.queue.borrow();
            (!q.is_empty(), q.iter().filter(|t| !t.borrow().status.live()).count())
        };
        let parallel = self.st.borrow().parallel;
        let active = stats.active.len();
        ui.set_queue_visible(has_rows);
        ui.set_queue_can_cancel_all(stats.pending > 0);
        ui.set_queue_can_clear(finished > 0);
        let summary = if active > 0 {
            let mut s = format!("{active} running");
            if parallel > 1 {
                s.push_str(&format!(" of {parallel}"));
            }
            s.push_str(&format!(" · {}", speed(sp)));
            if stats.pending > active {
                s.push_str(&format!(" · {} waiting", stats.pending - active));
            }
            s
        } else if stats.pending > 0 {
            format!("{} queued", stats.pending)
        } else {
            "Idle".into()
        };
        ui.set_queue_summary(summary.into());
        let status = if active > 0 {
            format!("{active} transferring · {}", speed(sp))
        } else if stats.pending > 0 {
            format!("{} queued", stats.pending)
        } else if stats.failed > 0 {
            format!("{} failed", stats.failed)
        } else {
            String::new()
        };
        ui.set_status_transfers(status.into());
        ui.set_queued(stats.pending.to_string().into());
        ui.set_done(stats.done.to_string().into());
        ui.set_failed(if stats.failed > 0 { format!("/ {} failed", stats.failed).into() } else { Default::default() });
        ui.set_speed(if sp > 0 { speed(sp).into() } else { "—".into() });
        ui.set_progress(self.overall_progress(stats.pending));
        // The detail line: one file and its percentage, or how many run, or what waits.
        let editing = self.st.borrow().editing.len();
        let detail = if active == 1 {
            let t = stats.active[0].borrow();
            let p = if t.total.is_some_and(|x| x > 0) { format!(" {}%", pct(t.transferred, t.total)) } else { String::new() };
            format!("{} {}{p}", if t.download { "↓" } else { "↑" }, t.file)
        } else if active > 1 {
            format!("{active} transfers running")
        } else if stats.pending > 0 {
            format!("{} queued", stats.pending)
        } else if editing > 0 {
            format!("{editing} file{} open for editing", if editing == 1 { "" } else { "s" })
        } else {
            String::new()
        };
        ui.set_transfer_detail(detail.into());
        ui.set_sparkline(self.sparkline().into());
        let busy = active > 0;
        if self.st.borrow().busy_glyph != busy {
            self.st.borrow_mut().busy_glyph = busy;
            self.push_link();
        }
    }

    /// The last 60 one-second samples as a path in a 96 x 22 box.
    fn sparkline(&self) -> String {
        let st = self.st.borrow();
        let s = &st.samples;
        if s.len() < 2 {
            return String::new();
        }
        let max = s.iter().copied().max().unwrap_or(1).max(1) as f64;
        let (w, h) = (96.0, 22.0);
        s.iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = i as f64 / 59.0 * w;
                let y = h - (v as f64 / max) * (h - 2.0) - 1.0;
                format!("{} {x:.1} {y:.1}", if i == 0 { "M" } else { "L" })
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// One sample per second of the bytes moved across all transfers.
    pub(crate) fn sample(&self) {
        {
            let mut st = self.st.borrow_mut();
            let delta = st.bytes_moved.saturating_sub(st.last_sampled);
            st.last_sampled = st.bytes_moved;
            st.samples.push(delta);
            let n = st.samples.len();
            if n > 60 {
                st.samples.drain(..n - 60);
            }
        }
        self.push_transfers();
    }

    pub(crate) fn notify_row(&self, t: &TRef) {
        let idx = self.queue.borrow().iter().position(|x| Rc::ptr_eq(x, t));
        if let Some(i) = idx {
            let n = self.queue.borrow().len();
            self.queue_model.row_changed(n - 1 - i);
        }
    }

    // ---------- queueing ----------

    /// Queue entries of `from` into `target_dir` on the other side (its current folder by default).
    pub fn transfer_entries(self: &Rc<Self>, from: Side, entries: Vec<Entry>, target_dir: Option<String>) {
        if !self.connected() {
            self.info("Connect to a server first");
            return;
        }
        let to = if from == Side::Remote { Side::Local } else { Side::Remote };
        let dir = target_dir.unwrap_or_else(|| self.pane(to).borrow().path.clone());
        let mut items = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for e in entries {
            if from == Side::Remote && !is_safe_name(&e.name) {
                self.info(format!("Skipped \"{}\": not a name this computer can store", e.name));
                continue;
            }
            // Windows folds case: two remote names differing only by case would write one local file.
            let k = case_key(&e.name);
            if from == Side::Remote && seen.contains(&k) {
                self.info(format!("Skipped \"{}\": differs only by case from another item in this batch", e.name));
                continue;
            }
            seen.insert(k);
            items.push(NewTransfer {
                download: from == Side::Remote,
                name: e.name.clone(),
                src: e.path.clone(),
                dst: join_path(&dir, &e.name, to == Side::Remote),
                is_dir: e.is_dir,
                policy: Policy::Ask,
                refresh: (to, dir.clone()),
                edit: false,
            });
        }
        self.enqueue(items);
    }

    /// Upload OS paths (dropped from Explorer) into a remote folder.
    pub fn upload_paths(self: &Rc<Self>, paths: Vec<String>, target_dir: Option<String>) {
        if !self.connected() {
            return;
        }
        let dir = target_dir.unwrap_or_else(|| self.pane(Side::Remote).borrow().path.clone());
        let items = paths
            .into_iter()
            .map(|p| {
                let name = base_name(&p);
                NewTransfer {
                    download: false,
                    dst: join_path(&dir, &name, true),
                    name,
                    src: p,
                    is_dir: false, // the backend stats the path
                    policy: Policy::Ask,
                    refresh: (Side::Remote, dir.clone()),
                    edit: false,
                }
            })
            .collect();
        self.enqueue(items);
    }

    /// One queue update and one pump per batch.
    pub(crate) fn enqueue(self: &Rc<Self>, items: Vec<NewTransfer>) {
        if items.is_empty() {
            return;
        }
        self.add_rows(items, Status::Queued);
        self.pump();
    }

    /// Append rows (one batch). `Active` is for work the pump does not start itself (an edit
    /// download).
    pub(crate) fn add_rows(&self, items: Vec<NewTransfer>, status: Status) -> Vec<TRef> {
        let (session, batch, stamp) = {
            let mut st = self.st.borrow_mut();
            st.batch_seq += 1;
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
            (st.session.clone().unwrap_or_default(), st.batch_seq, stamp)
        };
        let mut rows = Vec::new();
        for t in items {
            let id = {
                let mut st = self.st.borrow_mut();
                st.tx_seq += 1;
                format!("tx-{stamp}-{}", st.tx_seq)
            };
            let row = Rc::new(RefCell::new(Transfer {
                id: id.clone(),
                session: session.clone(),
                download: t.download,
                file: t.name.clone(),
                name: t.name,
                src: t.src,
                dst: t.dst,
                is_dir: t.is_dir,
                policy: t.policy,
                status,
                transferred: 0,
                total: None,
                error: None,
                started_at: if status == Status::Active { Some(Instant::now()) } else { None },
                ended_at: None,
                moved: None,
                requeue: false,
                cancel_requested: false,
                refresh: t.refresh,
                batch,
                edit: t.edit,
                left_out: None,
            }));
            self.by_id.borrow_mut().insert(id, row.clone());
            self.queue.borrow_mut().push(row.clone());
            rows.push(row);
        }
        // Newest first: the batch is the top rows. A reset would rebuild every row and drop a
        // click half made on one of them.
        self.queue_model.row_added(0, rows.len());
        self.push_transfers();
        rows
    }

    /// Take out a row that did nothing (an edit download refused before it began).
    pub(crate) fn drop_row(&self, t: &TRef) {
        let i = self.queue.borrow().iter().position(|x| Rc::ptr_eq(x, t));
        let Some(i) = i else { return };
        let n = self.queue.borrow().len();
        self.queue.borrow_mut().remove(i);
        if i < self.q_head.get() {
            self.q_head.set(self.q_head.get() - 1);
        }
        self.by_id.borrow_mut().remove(&t.borrow().id);
        self.queue_model.row_removed(n - 1 - i);
        self.push_transfers();
    }

    pub(crate) fn pump(self: &Rc<Self>) {
        // Model rows of what the scan cancels, repainted once the queue is no longer borrowed.
        let mut dropped = Vec::new();
        loop {
            let next = {
                let q = self.queue.borrow();
                // Finished rows never come back, so the scan starts at the first live one.
                let mut head = self.q_head.get();
                while head < q.len() && !q[head].borrow().status.live() {
                    head += 1;
                }
                self.q_head.set(head);
                let (session, parallel) = {
                    let st = self.st.borrow();
                    (st.session.clone(), st.parallel.max(1))
                };
                // Two transfers must never write the same destination at once (README and
                // Readme land in one Windows file; a folder and a file inside it clash the same
                // way), nor write what another one is still reading. Every active row counts,
                // whichever session it belongs to: a cancelled transfer of the last site can still
                // be mid-write. A file downloading for editing is a reader too.
                let mut mine = 0;
                let (mut writes, mut reads) = (Vec::new(), Vec::new());
                for t in &q[head..] {
                    let t = t.borrow();
                    if t.status != Status::Active {
                        continue;
                    }
                    if Some(&t.session) == session.as_ref() {
                        mine += 1;
                    }
                    if !t.dst.is_empty() {
                        writes.push(dst_key(&t));
                    }
                    reads.push(src_key(&t));
                }
                if mine >= parallel {
                    None
                } else {
                    let mut found = None;
                    for (i, tr) in q.iter().enumerate().skip(head) {
                        let mut t = tr.borrow_mut();
                        if t.status != Status::Queued {
                            continue;
                        }
                        if Some(&t.session) != session.as_ref() {
                            t.status = Status::Cancelled;
                            dropped.push(q.len() - 1 - i);
                            continue;
                        }
                        let (k, s) = (dst_key(&t), src_key(&t));
                        if writes.iter().any(|x| overlaps(x, &k) || overlaps(x, &s)) || reads.iter().any(|x| overlaps(x, &k)) {
                            // A row that has to wait still owns what it will write and read: a
                            // later row must not overtake it on those paths.
                            writes.push(k);
                            reads.push(s);
                            continue;
                        }
                        found = Some(tr.clone());
                        break;
                    }
                    found
                }
            };
            let Some(t) = next else { break };
            {
                let mut tb = t.borrow_mut();
                tb.status = Status::Active;
                tb.started_at = Some(Instant::now());
            }
            self.notify_row(&t);
            self.go(|a| async move {
                a.run_one(t).await;
                a.pump();
                if a.pending_count() == 0 {
                    a.st.borrow_mut().policy_by_id.clear();
                }
            });
        }
        // Only the rows that changed: a reset here (every completion) would rebuild them all.
        for row in dropped {
            self.queue_model.row_changed(row);
        }
        self.push_transfers();
    }

    async fn run_one(self: &Rc<Self>, t: TRef) {
        let (session, id, download, src, dst, is_dir, policy) = {
            let t = t.borrow();
            (t.session.clone(), t.id.clone(), t.download, t.src.clone(), t.dst.clone(), t.is_dir, t.policy)
        };
        let r = self.backend.transfer(session.clone(), id.clone(), download, src, dst, is_dir, policy).await;
        let current = self.st.borrow().session.clone();
        let mut failure_toast = None;
        let mut left_out_toast = false;
        {
            let mut tb = t.borrow_mut();
            match r {
                Ok(()) => {
                    tb.status = Status::Done;
                    if let Some(total) = tb.total {
                        tb.transferred = total;
                    }
                    // Reported before the result: say what was left out.
                    left_out_toast = tb.left_out.is_some() && current.as_deref() == Some(tb.session.as_str());
                }
                Err(e) => {
                    let msg = e.to_string();
                    if matches!(e, AppError::Cancelled) || tb.cancel_requested || current.as_deref() != Some(tb.session.as_str()) {
                        tb.status = Status::Cancelled; // a deliberate stop is not an error
                    } else {
                        tb.status = Status::Error;
                        failure_toast = Some(format!("{}: {msg}", tb.name));
                        tb.error = Some(msg);
                    }
                }
            }
            tb.ended_at = Some(Instant::now());
        }
        self.st.borrow_mut().conflicts.retain(|c| c.transfer != id);
        self.push_conflict();
        self.notify_row(&t);
        if left_out_toast {
            self.toast_left_out(&t);
        }
        if let Some(text) = failure_toast {
            self.toast_failure(text);
        }
        let requeue = {
            let mut tb = t.borrow_mut();
            // The engine deletes an edit copy only once the server has its bytes: a copy gone
            // after this upload has nothing newer to send, and a re-send would fail on it.
            let r = tb.requeue
                && current.as_deref() == Some(tb.session.as_str())
                && !(tb.edit && !self.backend.edit_copy_exists(tb.src.clone()));
            if r {
                tb.requeue = false;
            }
            r
        };
        if requeue {
            let tb = t.borrow();
            let item = NewTransfer {
                download: tb.download,
                name: tb.name.clone(),
                src: tb.src.clone(),
                dst: tb.dst.clone(),
                is_dir: false,
                policy: Policy::Overwrite,
                refresh: tb.refresh.clone(),
                edit: tb.edit,
            };
            drop(tb);
            self.enqueue(vec![item]);
        }
        // S1b: a transfer of an earlier session never refreshes what the current one shows
        // (the same path on another server is another folder). Local folders do get refreshed:
        // the files there did change.
        let (side, dir, of_session) = {
            let tb = t.borrow();
            (tb.refresh.0, tb.refresh.1.clone(), tb.session.clone())
        };
        if side == Side::Local || current.as_deref() == Some(of_session.as_str()) {
            self.schedule_refresh(side, dir);
        }
        self.push_transfers();
    }

    // ---------- events ----------

    pub(crate) fn on_progress(&self, p: Progress) {
        let Some(t) = self.by_id.borrow().get(&p.id).cloned() else { return };
        {
            let mut tb = t.borrow_mut();
            // The backend counts real bytes per transfer; skips and resume offsets are excluded.
            let delta = p.moved.saturating_sub(tb.moved.unwrap_or(0));
            self.st.borrow_mut().bytes_moved += delta;
            tb.moved = Some(p.moved);
            tb.file = p.file;
            tb.transferred = p.transferred;
            tb.total = p.total;
        }
        self.notify_row(&t);
        self.push_transfers();
    }

    pub(crate) fn on_conflict(&self, c: Conflict) {
        let t = self.by_id.borrow().get(&c.transfer).cloned();
        let session = self.st.borrow().session.clone();
        let stale = match &t {
            None => true,
            Some(t) => {
                let t = t.borrow();
                t.status != Status::Active || Some(&t.session) != session.as_ref()
            }
        };
        if stale {
            // Stale prompt from a dead transfer or session: answer so Rust can move on.
            self.backend.resolve_conflict(c.id, Action::Cancel, false);
            return;
        }
        let standing = self.st.borrow().policy_by_id.get(&c.transfer).copied();
        if let Some(a) = standing {
            self.backend.resolve_conflict(c.id, a, true);
            return;
        }
        self.st.borrow_mut().conflicts.push(c);
        self.push_conflict();
    }

    pub(crate) fn push_conflict(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let (first, waiting, seq) = {
            let mut st = self.st.borrow_mut();
            let first = st.conflicts.first().cloned();
            let id = first.as_ref().map(|c| c.id.clone());
            if id != st.conflict_shown {
                st.conflict_shown = id;
                st.conflict_seq += 1;
            }
            (first, st.conflicts.len(), st.conflict_seq)
        };
        let Some(c) = first else {
            ui.set_conflict_open(false);
            return;
        };
        let download = c.direction == "download";
        // An edit save asks only when the server's file changed since it was opened (FEA2).
        let edit = self.by_id.borrow().get(&c.transfer).is_some_and(|t| t.borrow().edit);
        let date = |ms: u64| {
            let w = crate::format::when(ms);
            if w.is_empty() { "unknown date".to_string() } else { w }
        };
        // An edit save's card says what happened and names its buttons for that (RVA3); it is
        // always answered on its own (RVA5).
        let (title, question, src_label, dst_label, skip_text, overwrite_text) = if edit {
            (
                "Changed on the server".to_string(),
                format!("{} was changed on the server since you opened it. Replace it with your copy, or keep the server's?", shown(&c.name)),
                "YOUR COPY".to_string(),
                "ON THE SERVER".to_string(),
                "Keep the server's",
                "Replace with my copy",
            )
        } else {
            (
                format!("File already exists {}", if download { "on this computer" } else { "on the server" }),
                String::new(),
                format!("SOURCE ({})", if download { "server" } else { "local" }),
                format!("EXISTING ({})", if download { "local" } else { "server" }),
                "Skip",
                "Overwrite",
            )
        };
        ui.set_conflict_info(ConflictInfo {
            title: title.into(),
            name: shown(&c.name).as_ref().into(),
            path: if c.path.is_empty() { Default::default() } else { format!("{} {}", if download { "from" } else { "to" }, shown(&c.path)).into() },
            src_label: src_label.into(),
            src_size: bytes(c.src_size).into(),
            src_date: date(c.src_modified).into(),
            dst_label: dst_label.into(),
            dst_size: bytes(c.dst_size).into(),
            dst_date: date(c.dst_modified).into(),
            // Nothing there to continue (an empty file, or a server that would not say what is
            // there): no Resume (review R-SOL-6). Never for an edit save: my copy's tail behind
            // their head would be neither version (RVA4).
            can_resume: !edit && 0 < c.dst_size && c.dst_size < c.src_size,
            resume_hint: format!("Continue from {}", bytes(c.dst_size)).into(),
            waiting: if waiting > 1 { format!("{waiting} waiting").into() } else { Default::default() },
            question: question.into(),
            skip_text: skip_text.into(),
            overwrite_text: overwrite_text.into(),
            single: edit,
        });
        ui.set_conflict_seq(seq as i32);
        ui.set_conflict_open(true);
    }

    /// The prompt's answer. `all` makes it standing: Cancel stops the batches that asked (never
    /// edit saves or other actions' transfers); the others cover what is queued right now, still
    /// asks, and has no answer yet. An edit save's question is never answered by `all`, its own
    /// or another's: it is always asked on its own (RVA5).
    pub fn answer_conflict(self: &Rc<Self>, action: Action, all: bool) {
        let Some(c) = self.st.borrow().conflicts.first().cloned() else { return };
        let is_edit = |x: &Conflict| self.by_id.borrow().get(&x.transfer).is_some_and(|t| t.borrow().edit);
        let all = all && !is_edit(&c);
        self.backend.resolve_conflict(c.id.clone(), action, all);
        self.st.borrow_mut().conflicts.retain(|x| x.id != c.id);
        if !all {
            self.push_conflict();
            return;
        }
        // The questions still waiting that `all` answers: an edit save's stays in the line.
        let take_others = || {
            let waiting: Vec<Conflict> = std::mem::take(&mut self.st.borrow_mut().conflicts);
            let (edits, others): (Vec<Conflict>, Vec<Conflict>) = waiting.into_iter().partition(&is_edit);
            self.st.borrow_mut().conflicts = edits;
            others
        };
        if matches!(action, Action::Cancel) {
            let others = take_others();
            let mut batches = std::collections::HashSet::new();
            for x in std::iter::once(&c).chain(others.iter()) {
                if let Some(t) = self.by_id.borrow().get(&x.transfer) {
                    batches.insert(t.borrow().batch);
                }
            }
            for o in &others {
                self.backend.resolve_conflict(o.id.clone(), Action::Cancel, true);
            }
            self.cancel_where(|tb| tb.status.live() && batches.contains(&tb.batch) && !tb.edit);
            self.push_conflict();
            return;
        }
        {
            let rows: Vec<TRef> = self.queue.borrow().clone();
            let mut st = self.st.borrow_mut();
            for t in rows {
                let mut tb = t.borrow_mut();
                if tb.status.live() && tb.policy == Policy::Ask && !tb.edit && !st.policy_by_id.contains_key(&tb.id) {
                    st.policy_by_id.insert(tb.id.clone(), action);
                    if tb.status == Status::Queued {
                        tb.policy = match action {
                            Action::Overwrite => Policy::Overwrite,
                            Action::Resume => Policy::Resume,
                            Action::Skip => Policy::Skip,
                            Action::Cancel => Policy::Ask,
                        };
                    }
                }
            }
        }
        for o in take_others() {
            let a = self.st.borrow().policy_by_id.get(&o.transfer).copied().unwrap_or(action);
            self.backend.resolve_conflict(o.id, a, true);
        }
        self.push_conflict();
    }

    /// A tree transfer left items out: keep them (with why) on its row, not only in a toast.
    pub(crate) fn on_skipped(self: &Rc<Self>, s: Skipped) {
        let Some(t) = self.by_id.borrow().get(&s.id).cloned() else { return };
        if s.names.is_empty() {
            return;
        }
        t.borrow_mut().left_out = Some(s.names.iter().enumerate().map(|(i, n)| (n.clone(), s.reasons.get(i).cloned().unwrap_or_default())).collect());
        self.notify_row(&t);
        // The event may come before or after the transfer's own result.
        let finished = {
            let tb = t.borrow();
            tb.status == Status::Done && self.st.borrow().session.as_deref() == Some(tb.session.as_str())
        };
        if finished {
            self.toast_left_out(&t);
        }
        self.push_transfers();
    }

    fn toast_left_out(self: &Rc<Self>, t: &TRef) {
        let (name, lines) = {
            let tb = t.borrow();
            let lo = tb.left_out.clone().unwrap_or_default();
            (tb.name.clone(), lo.iter().map(|(n, why)| if why.is_empty() { base_name(n) } else { format!("{}: {why}", base_name(n)) }).collect::<Vec<_>>())
        };
        let n = lines.len();
        self.error(summarise(&lines, &format!("{name}: {n} item{} left out", if n == 1 { " was" } else { "s were" })));
    }

    /// Transfer failures share one toast while it is up: "N transfers failed", first reason kept.
    fn toast_failure(self: &Rc<Self>, text: String) {
        let (n, first, old) = {
            let mut st = self.st.borrow_mut();
            let up = st.failures.2 != 0 && st.toasts.iter().any(|t| t.0 == st.failures.2);
            if up {
                st.failures.0 += 1;
            } else {
                st.failures.0 = 1;
                st.failures.1 = text.clone();
            }
            (st.failures.0, st.failures.1.clone(), if up { Some(st.failures.2) } else { None })
        };
        if let Some(id) = old {
            self.dismiss_toast(id);
        }
        let id = self.toast(if n == 1 { text } else { format!("{n} transfers failed. First: {first}") }, ToastKind::Error);
        self.st.borrow_mut().failures.2 = id;
    }

    // ---------- stopping ----------

    pub fn cancel(&self, t: &TRef) {
        self.stop(t);
        self.notify_row(t);
        self.push_transfers();
    }

    /// Cancel every row `hit` picks, then repaint once: per-row counters made a long queue's
    /// Cancel all quadratic.
    fn cancel_where(&self, hit: impl Fn(&Transfer) -> bool) {
        let rows: Vec<TRef> = self.queue.borrow().clone();
        let n = rows.len();
        for (i, t) in rows.iter().enumerate() {
            if hit(&t.borrow()) {
                self.stop(t);
                self.queue_model.row_changed(n - 1 - i);
            }
        }
        self.push_transfers();
    }

    /// Cancel one row without repainting anything.
    fn stop(&self, t: &TRef) {
        let (active, id) = {
            let mut tb = t.borrow_mut();
            tb.requeue = false; // a cancelled upload must not come back on its own
            tb.cancel_requested = true;
            if tb.status == Status::Queued {
                tb.status = Status::Cancelled;
            }
            (tb.status == Status::Active, tb.id.clone())
        };
        if active {
            self.backend.cancel_transfer(id);
        }
    }

    pub fn cancel_by_id(self: &Rc<Self>, id: &str) {
        let t = self.by_id.borrow().get(id).cloned();
        if let Some(t) = t {
            self.cancel(&t);
            self.pump();
        }
    }

    pub fn cancel_all(self: &Rc<Self>) {
        self.cancel_where(|_| true);
        self.pump();
    }

    pub fn clear_finished(&self) {
        self.queue.borrow_mut().retain(|t| t.borrow().status.live());
        self.q_head.set(0);
        let map = self.queue.borrow().iter().map(|t| (t.borrow().id.clone(), t.clone())).collect();
        *self.by_id.borrow_mut() = map;
        self.queue_model.reset();
        self.push_transfers();
    }

    // ---------- refreshes after transfers ----------

    /// The folder on screen, by either the path the user took or the real path the server reports.
    fn showing(&self, side: Side, dir: &str) -> bool {
        let p = self.pane(side).borrow();
        if p.path == dir {
            return true;
        }
        p.entries().first().and_then(|e| parent_path(&e.path, p.remote())).is_some_and(|x| x == dir)
    }

    /// Coalesce the refreshes finished transfers trigger: debounced, never more than one in
    /// flight per pane (on FTP they queue on the browse link ahead of the user's navigation).
    /// Completions while one runs leave exactly one follow-up.
    pub(crate) fn schedule_refresh(self: &Rc<Self>, side: Side, dir: String) {
        if !self.showing(side, &dir) {
            return;
        }
        let i = idx(side);
        if self.st.borrow().refreshing[i] {
            self.st.borrow_mut().refresh_again[i] = Some(dir);
            return;
        }
        let me = Rc::downgrade(self);
        let timer = Timer::default();
        timer.start(TimerMode::SingleShot, Duration::from_millis(150), move || {
            let Some(a) = me.upgrade() else { return };
            if !a.showing(side, &dir) {
                return;
            }
            // Set here, not in the future: a completion that runs before its first poll must
            // see this refresh as running and leave a follow-up, not start a second listing.
            a.st.borrow_mut().refreshing[i] = true;
            a.go(|a| async move {
                a.refresh(side).await;
                a.st.borrow_mut().refreshing[i] = false;
                let again = a.st.borrow_mut().refresh_again[i].take();
                if let Some(d) = again {
                    a.schedule_refresh(side, d);
                }
            });
        });
        self.st.borrow_mut().refresh_timers[i] = Some(timer);
    }
}

/// Used by the queue model and the tests: a row as the queue panel shows it.
pub fn queue_row(t: &Transfer) -> crate::QueueRow {
    let state = match t.status {
        // A size of 0 counts as unknown: an empty file reads "done", not "0 B".
        Status::Active => format!("{}{}", bytes(t.transferred), t.total.filter(|&x| x > 0).map(|x| format!(" / {}", bytes(x))).unwrap_or_default()),
        Status::Done if t.left_out.is_some() => "incomplete".into(),
        Status::Done => t.total.filter(|&x| x > 0).map(bytes).unwrap_or_else(|| "done".into()),
        s => s.label().into(),
    };
    let progress = match t.status {
        Status::Done => 1.0,
        Status::Active | Status::Error => pct(t.transferred, t.total) as f32 / 100.0,
        _ => -1.0,
    };
    let left = t.left_out.as_ref();
    crate::QueueRow {
        id: t.id.as_str().into(),
        download: t.download,
        name: shown(&t.name).as_ref().into(),
        sub: if t.is_dir && t.status == Status::Active && t.file != t.name { shown(&t.file).as_ref().into() } else { Default::default() },
        error: if t.status == Status::Error { shown(t.error.as_deref().unwrap_or_default()).as_ref().into() } else { Default::default() },
        left_out: left.map(|l| format!("{} left out", l.len()).into()).unwrap_or_default(),
        left_out_detail: left
            .map(|l| {
                let lines: Vec<String> = l.iter().map(|(n, w)| if w.is_empty() { shown(n).into_owned() } else { format!("{}: {}", shown(n), shown(w)) }).collect();
                format!("Left out:\n{}", lines.join("\n")).into()
            })
            .unwrap_or_default(),
        progress,
        failed: t.status == Status::Error,
        active: t.status == Status::Active,
        state: state.into(),
        dim: (t.status == Status::Done && t.left_out.is_none()) || t.status == Status::Skipped,
        can_cancel: t.status.live(),
    }
}

impl QueueModel {
    pub fn row_changed(&self, row: usize) {
        self.notify.row_changed(row);
    }
    pub fn row_added(&self, row: usize, count: usize) {
        self.notify.row_added(row, count);
    }
    pub fn row_removed(&self, row: usize) {
        self.notify.row_removed(row, 1);
    }
    pub fn reset(&self) {
        self.notify.reset();
    }
}
