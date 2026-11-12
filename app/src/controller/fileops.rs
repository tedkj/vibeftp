//! New folder, rename, move into a folder, delete, permissions. Every one captures the folder and
//! session it was asked about before its prompt, and acts on those or not at all.

use super::{App, summarise};
use super::transfers::{overlaps, path_key};
use crate::format::octal;
use crate::pane::Side;
use crate::paths::join_path;
use crate::ToastKind;
use slint::{ModelRc, VecModel};
use std::rc::Rc;
use vibeftp_core::protocol::Looks;
use vibeftp_core::types::Entry;

/// The permissions dialog's subject, with the connection and folder it was opened for.
#[derive(Clone)]
pub(crate) struct Perms {
    entries: Vec<Entry>,
    mode: u32,
    text: String,
    session: String,
    dir: String,
}

/// Said when a confirmed rename or delete finds the folder (or the connection) changed while
/// the question was open: it then does nothing, and must not look as if it had worked.
const MOVED_ON: &str = "The folder changed while you were asked; nothing was";

/// The delete question's line while the folders' hidden items are being counted (FR2-5).
pub const COUNTING: &str = "Counting the items inside with names Windows apps can't show…";

impl App {
    pub async fn mkdir(self: Rc<Self>, side: Side) {
        // The folder and connection as they are now: a navigation that lands while the prompt is
        // open must not move the new folder elsewhere.
        let remote = side == Side::Remote;
        let session = self.st.borrow().session.clone();
        let dir = self.pane(side).borrow().path.clone();
        if remote && session.is_none() {
            return;
        }
        let Some(name) = self.prompt("New folder", "", "Folder name", "Create").await else { return };
        let stale = |a: &App| a.pane(side).borrow().path != dir || (remote && a.st.borrow().session != session);
        if stale(&self) {
            return;
        }
        let path = join_path(&dir, &name, remote);
        let r = if remote {
            self.backend.remote_mkdir(session.clone().unwrap(), path).await
        } else {
            self.backend.local_mkdir(path).await
        };
        match r {
            Ok(()) => {
                if stale(&self) {
                    return; // a navigation landed meanwhile: don't select a namesake there
                }
                // Selected by whichever refresh lands last (one started after this has it too).
                self.pane(side).borrow_mut().select_after = Some(name);
                self.refresh(side).await;
            }
            Err(e) => {
                if !(remote && self.st.borrow().session != session) {
                    self.error(e);
                }
            }
        }
    }

    /// Select by name after a refresh: entry paths may be the real path behind a link. A row the
    /// filter hides stays unselected: F5 or Delete must never act on what is not on screen.
    pub(crate) fn select_by_name(self: &Rc<Self>, side: Side, name: &str) {
        let hit = {
            let p = self.pane(side).borrow();
            p.entries().iter().find(|e| e.name == name).map(|e| e.path.clone()).filter(|h| p.view_index_of(h).is_some())
        };
        let c = self.pane(side).borrow_mut().select_path(hit);
        self.apply(side, c);
        self.push_pane(side);
    }

    /// The watcher of an edit copy uploads every save to the path it was opened from: renaming,
    /// moving or deleting that file (or a folder above it) would send the next save to the old
    /// name and bring it back. Refused instead, with a toast; true when refused.
    fn open_for_editing(self: &Rc<Self>, session: &str, entries: &[Entry]) -> bool {
        let hit = self.st.borrow().editing.iter().filter(|x| x.session == session).find_map(|x| {
            let key = path_key(false, &x.remote);
            entries.iter().find(|e| overlaps(&key, &path_key(false, &e.path))).map(|e| (e.clone(), x.name.clone()))
        });
        let Some((entry, file)) = hit else { return false };
        if entry.is_dir {
            self.info(format!("{file} in {} is open for editing; stop watching it first", entry.name));
        } else {
            self.info(format!("{file} is open for editing; stop watching it first"));
        }
        true
    }

    pub async fn rename(self: Rc<Self>, side: Side) {
        let Some(entry) = self.pane(side).borrow().selected_entries().into_iter().next() else { return };
        // Everything below acts on the folder and connection as they are right now: a switch,
        // or a navigation that lands while the prompt is open or a request is in flight, must
        // not retarget it.
        let remote = side == Side::Remote;
        let session = self.st.borrow().session.clone();
        let dir = self.pane(side).borrow().path.clone();
        if remote && session.is_none() {
            return;
        }
        if remote && self.open_for_editing(session.as_deref().unwrap(), std::slice::from_ref(&entry)) {
            return;
        }
        let stale = |a: &App| a.pane(side).borrow().path != dir || (remote && a.st.borrow().session != session);
        let moved_on = |a: &Rc<App>| a.info(format!("{MOVED_ON} renamed"));
        let stem = entry.name.rfind('.').filter(|&i| i > 0).unwrap_or(entry.name.len());
        let Some(name) = self.prompt_select("Rename", &entry.name, "New name", "Rename", stem as i32).await else { return };
        if name == entry.name {
            return;
        }
        if stale(&self) {
            moved_on(&self);
            return;
        }
        // Look at the folder as it is now, dotfiles included (the listing on screen may be stale).
        let fresh = if remote {
            self.backend.remote_list(session.clone().unwrap(), dir.clone()).await
        } else {
            self.backend.local_list(dir.clone()).await.map(|(e, _)| e)
        };
        let current: Vec<Entry> = fresh.unwrap_or_else(|_| self.pane(side).borrow().entries().to_vec());
        if stale(&self) {
            moved_on(&self);
            return;
        }
        let clash = current.iter().find(|e| {
            e.path != entry.path && if remote { e.name == name } else { e.name.to_lowercase() == name.to_lowercase() }
        });
        // The target the user agreed to replace: its row (remote), its identity (local).
        let mut replace: Option<Entry> = None;
        let mut replace_id = None;
        if let Some(c) = clash {
            if c.is_dir || entry.is_dir {
                self.info(format!("\"{name}\" already exists. Folders are never replaced; pick another name."));
                return;
            }
            // The file being replaced counts too: its watcher would upload the next save over
            // the replacement.
            if remote && self.open_for_editing(session.as_deref().unwrap(), std::slice::from_ref(c)) {
                return;
            }
            // Which file the question is about, taken as it is shown (review SOL-FTP-2).
            let id = (!remote).then(|| self.backend.local_identity(c.path.clone()));
            let ok = self.confirm("Replace?", &format!("\"{name}\" already exists here. Replace it with \"{}\"?", entry.name), "Replace", true).await;
            if !ok {
                return;
            }
            if stale(&self) {
                moved_on(&self);
                return;
            }
            if let Some(id) = id {
                match id.await {
                    Ok(id) => replace_id = Some(id),
                    Err(e) => {
                        self.error(format!("\"{name}\" could not be looked at when you were asked ({e}); nothing was renamed"));
                        return;
                    }
                }
            }
            replace = Some(c.clone());
        }
        let to = join_path(&dir, &name, remote);
        // Replacing is the backend's job: it moves the old file aside and drops it only once the
        // rename went through. Its own check lets a case-only spelling change through on a
        // case-folding server, so only real consent is passed on.
        let r = if remote {
            self.backend.remote_rename(session.clone().unwrap(), entry.path.clone(), to, replace, Looks::default()).await
        } else {
            self.backend.local_rename(entry.path.clone(), to, replace_id).await
        };
        match r {
            Ok(()) => {
                if stale(&self) {
                    return;
                }
                self.pane(side).borrow_mut().select_after = Some(name);
                self.refresh(side).await;
            }
            Err(e) => {
                if !(remote && self.st.borrow().session != session) {
                    self.error(e);
                }
            }
        }
    }

    /// Move entries into a folder within the same pane. Existing files are replaced only on consent.
    pub async fn move_into(self: Rc<Self>, side: Side, entries: Vec<Entry>, folder: Entry) {
        let remote = side == Side::Remote;
        let session = self.st.borrow().session.clone();
        if remote && session.is_none() {
            return;
        }
        if remote && self.open_for_editing(session.as_deref().unwrap(), &entries) {
            return;
        }
        let stale = |a: &App| remote && a.st.borrow().session != session;
        let listing = if remote {
            self.backend.remote_list(session.clone().unwrap(), folder.path.clone()).await
        } else {
            self.backend.local_list(folder.path.clone()).await.map(|(e, _)| e)
        };
        let existing = match listing {
            Ok(l) => l,
            Err(e) => {
                if !stale(&self) {
                    self.error(e);
                }
                return;
            }
        };
        if stale(&self) {
            return;
        }
        let key = |n: &str| if remote { n.to_string() } else { n.to_lowercase() };
        let by_name: std::collections::HashMap<String, Entry> = existing.into_iter().map(|x| (key(&x.name), x)).collect();
        // A local folder that is a junction or link may lead back here, and its listing names the
        // source by the link path: a namesake that is the very same file must not get a
        // "Replace?" (a move onto itself). Leave those alone.
        let mut same: Vec<String> = Vec::new();
        if !remote && folder.is_link {
            for e in &entries {
                if let Some(x) = by_name.get(&key(&e.name))
                    && !x.is_dir && !e.is_dir && self.backend.local_same_file(e.path.clone(), x.path.clone()).await.unwrap_or(false)
                {
                    same.push(e.path.clone());
                }
            }
        }
        if !same.is_empty() {
            let n = same.len();
            self.info(format!(
                "{n} file{} already in \"{}\" (the same file), left as {}",
                if n == 1 { " is" } else { "s are" },
                folder.name,
                if n == 1 { "it is" } else { "they are" }
            ));
        }
        let clashes: Vec<&Entry> = entries.iter().filter(|e| by_name.contains_key(&key(&e.name)) && !same.contains(&e.path)).collect();
        let blocked: Vec<String> = clashes.iter().filter(|e| e.is_dir || by_name[&key(&e.name)].is_dir).map(|e| e.path.clone()).collect();
        let replaceable = clashes.len() - blocked.len();
        if !blocked.is_empty() {
            let n = blocked.len();
            self.info(format!(
                "{n} folder{} already exist{} in \"{}\" and will not be replaced",
                if n == 1 { "" } else { "s" },
                if n == 1 { "s" } else { "" },
                folder.name
            ));
        }
        let mut replace = false;
        // The identities of the local files the question is about, taken as it is shown (SOL-FTP-2).
        let mut ids: std::collections::HashMap<String, vibeftp_core::error::Result<vibeftp_core::identity::LocalId>> = Default::default();
        if replaceable > 0 {
            // As for the sources: a file about to be replaced must not be one open for editing.
            let targets: Vec<Entry> = clashes.iter().filter(|e| !blocked.contains(&e.path)).map(|e| by_name[&key(&e.name)].clone()).collect();
            if remote && self.open_for_editing(session.as_deref().unwrap(), &targets) {
                return;
            }
            let looks: Vec<_> = if remote {
                Vec::new()
            } else {
                targets.iter().map(|t| (t.path.clone(), self.backend.local_identity(t.path.clone()))).collect()
            };
            let n = replaceable;
            replace = self
                .confirm(
                    "Replace?",
                    &format!("{n} file{} already exist{} in \"{}\". Replace?", if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }, folder.name),
                    "Replace",
                    true,
                )
                .await;
            if stale(&self) {
                return;
            }
            if replace {
                for (path, id) in looks {
                    ids.insert(path, id.await);
                }
            }
        }
        let mut failures = Vec::new();
        // One look at the target folder for all the files it replaces (review R-SOL-2).
        let looks = Looks::default();
        for e in &entries {
            if stale(&self) {
                return;
            }
            if e.path == folder.path || blocked.contains(&e.path) || same.contains(&e.path) {
                continue;
            }
            let clash = by_name.get(&key(&e.name));
            // The target folder may be a link back to here: then the "clash" is the source itself.
            if clash.is_some_and(|c| c.path == e.path) {
                continue;
            }
            if clash.is_some() && !replace {
                continue;
            }
            let to = join_path(&folder.path, &e.name, remote);
            let r = if remote {
                self.backend.remote_rename(session.clone().unwrap(), e.path.clone(), to, clash.cloned(), looks.clone()).await
            } else {
                match clash.map(|c| ids.remove(&c.path)) {
                    None => self.backend.local_rename(e.path.clone(), to, None).await,
                    Some(Some(Ok(id))) => self.backend.local_rename(e.path.clone(), to, Some(id)).await,
                    Some(Some(Err(err))) => Err(vibeftp_core::error::AppError::Msg(format!(
                        "the file it would replace could not be looked at when you were asked ({err}); not moved"
                    ))),
                    Some(None) => Err(vibeftp_core::error::AppError::Msg("the file it would replace was not looked at; not moved".into())),
                }
            };
            if let Err(err) = r {
                failures.push(format!("{}: {err}", e.name));
            }
        }
        if !failures.is_empty() {
            self.error(summarise(&failures, ""));
        }
        if !stale(&self) {
            self.refresh(side).await;
        }
    }

    pub async fn remove(self: Rc<Self>, side: Side) {
        let items = self.pane(side).borrow().selected_entries();
        if items.is_empty() {
            return;
        }
        let remote = side == Side::Remote;
        // S43: the target is captured before the confirm (read after it, a switch while the
        // question was open would delete these paths on the new server). Checked again once
        // answered.
        let session = self.st.borrow().session.clone();
        let dir = self.pane(side).borrow().path.clone();
        if remote && session.is_none() {
            return;
        }
        if remote && self.open_for_editing(session.as_deref().unwrap(), &items) {
            return;
        }
        let what = if items.len() == 1 { format!("\"{}\"", items[0].name) } else { format!("{} items", items.len()) };
        let question = format!("Permanently delete {what} from {}?", if remote { "the server" } else { "this computer" });
        // Items whose names Windows apps cannot show are not in any listing, but a folder's
        // delete takes them too: the question says so (review FR-10). It is asked at once and
        // the count fills in when the listings are back: a slow or dead share must not stall
        // the Delete key (FR2-5).
        let looks: Vec<_> = if remote {
            Vec::new()
        } else {
            items.iter().filter(|e| e.is_dir && !e.is_link).map(|e| self.backend.local_list(e.path.clone())).collect()
        };
        let counting = !looks.is_empty();
        // Which items the question is about, taken as it is shown: a delete acts on these, not
        // on whatever has their names by the time it is answered (review SOL-FTP-2). Remote rows
        // are re-checked by the engine against the rows themselves.
        let ids: Vec<_> = if remote { Vec::new() } else { items.iter().map(|e| self.backend.local_identity(e.path.clone())).collect() };
        let body = if counting { format!("{question}\n\n{COUNTING}") } else { question.clone() };
        let ask = std::pin::pin!(self.confirm("Delete", &body, "Delete", true));
        let count = std::pin::pin!(async move {
            let mut hidden = 0;
            for r in futures::future::join_all(looks).await {
                hidden += r.map(|(_, h)| h).unwrap_or(0);
            }
            hidden
        });
        let ok = if !counting {
            ask.await
        } else {
            match futures::future::select(ask, count).await {
                // Answered first: the count no longer matters.
                futures::future::Either::Left((ok, _)) => ok,
                // The question is still open (it is polled first): the count goes into it.
                futures::future::Either::Right((hidden, ask)) => {
                    let also = match hidden {
                        0 => String::new(),
                        1 => "\n\nIt also deletes 1 item inside with a name Windows apps can't show (not listed).".to_string(),
                        n => format!("\n\nIt also deletes {n} items inside with names Windows apps can't show (not listed)."),
                    };
                    self.modal_body(&format!("{question}{also}"));
                    ask.await
                }
            }
        };
        let stale = |a: &App| (remote && a.st.borrow().session != session) || a.pane(side).borrow().path != dir;
        if !ok {
            return;
        }
        if stale(&self) {
            self.info(format!("{MOVED_ON} deleted"));
            return;
        }
        let mut ids = futures::future::join_all(ids).await.into_iter();
        // One refusal must not stop the rest: carry on and name what was not deleted.
        let mut failures = Vec::new();
        // The engine reads the folder once for all the rows, not once per row (review R-SOL-2).
        let looks = Looks::default();
        for e in &items {
            // The paths are absolute: browsing on while it runs is fine, a new session is not.
            if remote && self.st.borrow().session != session {
                return;
            }
            let r = if remote {
                self.backend.remote_delete(session.clone().unwrap(), e.path.clone(), e.is_dir && !e.is_link, e.clone(), looks.clone()).await
            } else {
                match ids.next() {
                    Some(Ok(id)) => self.backend.local_delete(e.path.clone(), e.is_dir, id).await,
                    Some(Err(err)) => Err(vibeftp_core::error::AppError::Msg(format!(
                        "it could not be looked at when you were asked ({err}); nothing was deleted"
                    ))),
                    None => Err(vibeftp_core::error::AppError::Msg("it was not looked at; nothing was deleted".into())),
                }
            };
            if let Err(err) = r {
                failures.push(format!("{}: {err}", e.name));
            }
        }
        if remote && self.st.borrow().session != session {
            return;
        }
        if !failures.is_empty() {
            self.error(summarise(&failures, if items.len() > 1 { "Not deleted" } else { "" }));
        }
        self.refresh(side).await;
    }

    // ---------- permissions ----------

    pub fn open_perms(self: &Rc<Self>) {
        let entries = self.pane(Side::Remote).borrow().selected_entries();
        let Some(first) = entries.first() else { return };
        let Some(session) = self.st.borrow().session.clone() else { return };
        let dir = self.pane(Side::Remote).borrow().path.clone();
        let mode = first.mode.unwrap_or(if first.is_dir { 0o755 } else { 0o644 });
        let subject = if entries.len() == 1 { first.name.clone() } else { format!("{} items", entries.len()) };
        {
            let mut st = self.st.borrow_mut();
            st.perms = Some(Perms { entries, mode, text: octal(mode), session, dir });
        }
        if let Some(ui) = self.ui.upgrade() {
            ui.set_perms_subject(crate::format::shown(&subject).as_ref().into());
        }
        self.push_perms();
        if let Some(ui) = self.ui.upgrade() {
            ui.set_perms_open(true);
        }
    }

    fn push_perms(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let st = self.st.borrow();
        let Some(Perms { mode, text, .. }) = &st.perms else { return };
        let bits: Vec<bool> = (0..9).map(|i| mode & (1 << (8 - i)) != 0).collect();
        ui.set_perms_bits(ModelRc::new(VecModel::from(bits)));
        ui.set_perms_text(text.as_str().into());
    }

    pub fn perms_toggle(&self, i: usize) {
        if let Some(Perms { mode, text, .. }) = self.st.borrow_mut().perms.as_mut() {
            *mode ^= 1 << (8 - i);
            *text = octal(*mode);
        }
        self.push_perms();
    }

    pub fn perms_text(&self, raw: &str) {
        let t = raw.trim().to_string();
        if let Some(Perms { mode, text, .. }) = self.st.borrow_mut().perms.as_mut() {
            *text = t.clone();
            if (3..=4).contains(&t.len()) && t.chars().all(|c| ('0'..='7').contains(&c)) {
                *mode = u32::from_str_radix(&t, 8).unwrap_or(*mode);
            }
        }
        // The grid follows valid input; the text stays what was typed.
        let Some(ui) = self.ui.upgrade() else { return };
        let st = self.st.borrow();
        if let Some(Perms { mode, .. }) = &st.perms {
            let bits: Vec<bool> = (0..9).map(|i| mode & (1 << (8 - i)) != 0).collect();
            ui.set_perms_bits(ModelRc::new(VecModel::from(bits)));
            // The window's copy follows the field, so the next toggle always changes it (the
            // dialog copies it into the field only on a change). Raw, untrimmed: written back,
            // it is the field's own text and moves nothing under the cursor.
            ui.set_perms_text(raw.into());
        }
    }

    pub fn perms_close(&self) {
        self.st.borrow_mut().perms = None;
        if let Some(ui) = self.ui.upgrade() {
            ui.set_perms_open(false);
        }
    }

    pub fn perms_apply(self: &Rc<Self>) {
        let Some(Perms { entries, text, session, dir, .. }) = self.st.borrow().perms.clone() else { return };
        // The paths belong to the connection and folder the dialog was opened for.
        let moved = self.st.borrow().session.as_deref() != Some(session.as_str()) || self.pane(Side::Remote).borrow().path != dir;
        if moved {
            self.perms_close();
            self.info(format!("{MOVED_ON} changed"));
            return;
        }
        let t = text.trim().to_string();
        if !((3..=4).contains(&t.len()) && t.chars().all(|c| ('0'..='7').contains(&c))) {
            self.info("Permissions must be three or four octal digits, like 755 or 2775");
            return;
        }
        self.perms_close();
        // Four digits set the special bits explicitly; three leave each entry's own alone.
        let mode = u32::from_str_radix(&t, 8).unwrap_or(0) & 0o7777;
        let explicit_high = t.len() == 4;
        self.go(move |a| a.chmod(session, entries, mode, explicit_high));
    }

    pub async fn chmod(self: Rc<Self>, session: String, entries: Vec<Entry>, mode: u32, explicit_high: bool) {
        // Folders keep execute wherever they are readable, or they become untraversable.
        // setuid/setgid/sticky stay as each entry had them unless the user typed four digits.
        let mut groups: Vec<(u32, Vec<Entry>)> = Vec::new();
        for e in entries.iter() {
            let mut m = mode & 0o777;
            if e.is_dir {
                m |= (m & 0o444) >> 2;
            }
            m |= if explicit_high { mode & 0o7000 } else { e.mode.unwrap_or(0) & 0o7000 };
            match groups.iter_mut().find(|g| g.0 == m) {
                Some(g) => g.1.push(e.clone()),
                None => groups.push((m, vec![e.clone()])),
            }
        }
        let mine = |a: &App| a.st.borrow().session.as_deref() == Some(session.as_str());
        let mut failures = Vec::new();
        for (m, group) in groups {
            if !mine(&self) {
                return;
            }
            let paths: Vec<String> = group.iter().map(|e| e.path.clone()).collect();
            if let Err(err) = self.backend.remote_chmod(session.clone(), paths, m).await {
                if group.len() == 1 {
                    failures.push(format!("{}: {err}", group[0].name));
                    continue;
                }
                // The backend stops at the first refusal in a group without naming it: redo the
                // group one by one (chmod is idempotent) to carry on and say which ones failed.
                for e in &group {
                    if !mine(&self) {
                        return;
                    }
                    if let Err(err1) = self.backend.remote_chmod(session.clone(), vec![e.path.clone()], m).await {
                        failures.push(format!("{}: {err1}", e.name));
                    }
                }
            }
        }
        if !mine(&self) {
            return;
        }
        if !failures.is_empty() {
            self.error(summarise(&failures, if entries.len() > 1 { "Permissions not changed" } else { "" }));
        } else {
            let shown = mode & if explicit_high { 0o7777 } else { 0o777 };
            self.toast(format!("Permissions set to {shown:o}"), ToastKind::Ok);
        }
        self.refresh(Side::Remote).await;
    }
}
