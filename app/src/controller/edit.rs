//! Edit-and-watch: a remote file opens in its app, every save goes up.

use super::App;
use super::transfers::{NewTransfer, Status, TRef, dst_key, overlaps, path_key};
use crate::pane::Side;
use crate::paths::parent_path;
use crate::ToastKind;
use std::rc::Rc;
use std::time::Instant;
use vibeftp_core::error::AppError;
use vibeftp_core::types::{EditChanged, Entry, Policy};

impl App {
    /// Double-click / Enter on a remote file: download it to a private copy, open it, watch it.
    pub(crate) async fn edit_remote(self: Rc<Self>, entry: Entry) {
        let Some(session) = self.st.borrow().session.clone() else { return };
        if entry.size > 25 * 1024 * 1024 {
            let ok = self.confirm("Large file", &format!("{} is big. Download and open it anyway?", entry.name), "Open", false).await;
            if !ok || self.st.borrow().session.as_deref() != Some(session.as_str()) {
                return;
            }
        }
        let row = self.st.borrow().editing.iter().find(|x| x.session == session && x.remote == entry.path).cloned();
        let opened_for = session.clone();
        let relaunch = move |a: Rc<App>, why: String, local: String| {
            let session = opened_for.clone();
            async move {
                match a.backend.local_open(local).await {
                    Ok(_) => a.info(why),
                    Err(e) => {
                        if a.st.borrow().session.as_deref() == Some(session.as_str()) {
                            a.error(e);
                        }
                    }
                }
            }
        };
        // The queue owns a remote path while an upload to it is queued or running. A save of this
        // file reads the edit copy when it starts, so a fresh download would send the server's
        // old text up as the save; any other upload would hand the editor a partial file that the
        // next save then writes over the finished one. Asked from the queue, not from the editing
        // row, so "Stop watching" cannot unmask it.
        let key = path_key(false, &entry.path);
        let writer_of = |a: &App| -> Option<TRef> {
            a.queue.borrow().iter().find(|t| {
                let t = t.borrow();
                !t.download && t.status.live() && overlaps(&dst_key(&t), &key)
            }).cloned()
        };
        let busy = |a: &Rc<App>| a.info(format!("{} is being uploaded; open it when that transfer finishes", entry.name));
        if let Some(w) = writer_of(&self) {
            match &row {
                Some(r) if w.borrow().src == r.local => {
                    relaunch(self.clone(), format!("{} is still uploading your last save; opened the copy you were editing", entry.name), r.local.clone()).await;
                }
                _ => busy(&self),
            }
            return;
        }
        // The last save of this file never reached the server (failed or cancelled): the copy
        // holds the only record of those edits, and a download would replace it.
        let last = self.queue.borrow().iter().rev().find(|t| {
            let t = t.borrow();
            t.edit && t.session == session && t.dst == entry.path
        }).cloned();
        let mut discard = false;
        if let Some(last) = last {
            let (status, src) = {
                let l = last.borrow();
                (l.status, l.src.clone())
            };
            if matches!(status, Status::Error | Status::Cancelled) {
                if let Some(r) = &row
                    && src == r.local
                {
                    let why = format!("Your last save of {} did not reach the server; opened the copy you were editing. Save it again to upload.", entry.name);
                    relaunch(self.clone(), why, r.local.clone()).await;
                    return;
                }
                if !self.unsent(&entry.name).await || self.st.borrow().session.as_deref() != Some(session.as_str()) {
                    return;
                }
                if writer_of(&self).is_some() {
                    busy(&self); // queued while the question was open
                    return;
                }
                discard = true;
            }
        }
        loop {
            let local = match self.edit_download(&session, &entry, discard).await {
                Ok(l) => l,
                Err(e) => {
                    if self.st.borrow().session.as_deref() != Some(session.as_str()) {
                        return;
                    }
                    if matches!(e, AppError::Cancelled) {
                        return;
                    }
                    // The backend knows the copy best (edits after Stop, a save cleared from the
                    // queue): it refuses to replace one the server never got, and asks to be told.
                    if !discard && matches!(e, AppError::UnsentEdits(_)) {
                        if !self.unsent(&entry.name).await || self.st.borrow().session.as_deref() != Some(session.as_str()) {
                            return;
                        }
                        if writer_of(&self).is_some() {
                            busy(&self);
                            return;
                        }
                        discard = true;
                        continue;
                    }
                    let msg = e.to_string();
                    let refusal = ["is being uploaded right now", "is still being uploaded", "is already being opened"].iter().any(|p| msg.contains(p));
                    self.toast(msg, if refusal { ToastKind::Info } else { ToastKind::Error });
                    return;
                }
            };
            if self.st.borrow().session.as_deref() != Some(session.as_str()) {
                return;
            }
            {
                let mut st = self.st.borrow_mut();
                if !st.editing.iter().any(|x| x.local == local) {
                    st.editing.push(EditChanged { session: session.clone(), remote: entry.path.clone(), local, name: entry.name.clone() });
                }
            }
            self.push_edits();
            self.toast(format!("Editing {}. Saves upload automatically.", entry.name), ToastKind::Ok);
            return;
        }
    }

    async fn unsent(self: &Rc<Self>, name: &str) -> bool {
        self.confirm("Unsent edits", &format!("Your edits to {name} did not reach the server. Download the server's version over them?"), "Download", true).await
    }

    /// The edit download as a queue row: it shows progress, counts as work a quit would cut
    /// short, holds uploads to the file back (the pump sees it reading the remote path), and its
    /// Cancel stops it (the backend runs it under the row's id).
    async fn edit_download(self: &Rc<Self>, session: &str, entry: &Entry, discard: bool) -> Result<String, AppError> {
        let t = self
            .add_rows(
                vec![NewTransfer {
                    download: true,
                    name: entry.name.clone(),
                    src: entry.path.clone(),
                    dst: String::new(), // a private copy no other transfer writes to
                    is_dir: false,
                    policy: Policy::Overwrite,
                    refresh: (Side::Remote, String::new()),
                    edit: false,
                }],
                Status::Active,
            )
            .remove(0);
        let id = t.borrow().id.clone();
        let r = self.backend.edit_open(session.to_string(), entry.path.clone(), id, discard).await;
        match &r {
            Ok(_) => {
                let mut tb = t.borrow_mut();
                tb.status = Status::Done;
                if let Some(total) = tb.total {
                    tb.transferred = total;
                }
            }
            Err(e) => {
                let gone = self.st.borrow().session.as_deref() != Some(session);
                let (cancelled, moved) = {
                    let tb = t.borrow();
                    (tb.cancel_requested, tb.moved.is_some())
                };
                if matches!(e, AppError::Cancelled) || cancelled || gone {
                    t.borrow_mut().status = Status::Cancelled;
                } else if !moved {
                    self.drop_row(&t); // refused before any byte moved: the caller says why, or asks
                } else {
                    let mut tb = t.borrow_mut();
                    tb.status = Status::Error;
                    tb.error = Some(e.to_string());
                }
            }
        }
        t.borrow_mut().ended_at = Some(Instant::now());
        self.notify_row(&t);
        self.pump(); // an upload to this path may have waited for the download
        r
    }

    /// Stop the watcher. A save already queued or uploading still goes up (it was made while
    /// watching), and so does one announced while the stop is under way. Bytes the watcher had
    /// not announced yet come back from edit_stop as `true` and are queued here.
    pub fn stop_editing(self: &Rc<Self>, i: usize) {
        let Some(e) = self.st.borrow().editing.get(i).cloned() else { return };
        self.st.borrow_mut().editing.retain(|x| !(x.session == e.session && x.local == e.local));
        self.push_edits();
        let key = format!("{}|{}", e.session, e.local);
        self.st.borrow_mut().stopping.insert(key.clone());
        let unsent = self.backend.edit_stop(e.session.clone(), e.local.clone());
        // edit_stop is synchronous, so a save event already on its way is still queued: deliver
        // what the engine has queued now, while the copy still counts as stopping.
        self.drain_events();
        self.st.borrow_mut().stopping.remove(&key);
        if !unsent || self.st.borrow().session.as_deref() != Some(e.session.as_str()) {
            return;
        }
        self.queue_save(e, true);
    }

    pub(crate) fn on_edit_changed(self: &Rc<Self>, e: EditChanged) {
        if self.st.borrow().session.as_deref() != Some(e.session.as_str()) {
            return;
        }
        // An event the watcher sent before Stop took effect is a save made while watching; one
        // for a copy no longer watched at all is not.
        let watched = self.st.borrow().editing.iter().any(|x| x.session == e.session && x.local == e.local);
        let stopping = self.st.borrow().stopping.contains(&format!("{}|{}", e.session, e.local));
        if !watched && !stopping {
            return;
        }
        self.queue_save(e, true);
    }

    /// Queue an upload of an edit copy, unless one already waiting will carry it. A running one
    /// is sent again after it ends when `again` (the copy holds newer bytes than it read).
    fn queue_save(self: &Rc<Self>, e: EditChanged, again: bool) {
        let same = self.queue.borrow().iter().find(|t| {
            let t = t.borrow();
            t.session == e.session && !t.download && t.dst == e.remote && t.src == e.local && t.status.live()
        }).cloned();
        if let Some(t) = same {
            let status = t.borrow().status;
            if status == Status::Queued {
                return; // already waiting: one upload will carry this save
            }
            if again {
                t.borrow_mut().requeue = true; // let the running upload finish, then send the newer bytes
            }
            return;
        }
        let dir = parent_path(&e.remote, true).unwrap_or_else(|| "/".into());
        self.enqueue(vec![NewTransfer {
            download: false,
            name: e.name.clone(),
            src: e.local.clone(),
            dst: e.remote.clone(),
            is_dir: false,
            policy: Policy::Overwrite,
            refresh: (Side::Remote, dir),
            edit: true,
        }]);
        self.toast(format!("Uploading {}", e.name), ToastKind::Ok);
    }

    pub(crate) fn push_edits(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let rows: Vec<crate::EditRow> = self
            .st
            .borrow()
            .editing
            .iter()
            .map(|e| crate::EditRow { name: crate::format::shown(&e.name).as_ref().into(), remote: crate::format::shown(&e.remote).as_ref().into() })
            .collect();
        ui.set_edits(slint::ModelRc::new(slint::VecModel::from(rows)));
        self.push_transfers();
    }
}
