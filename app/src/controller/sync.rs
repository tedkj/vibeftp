//! Synchronized browsing: from the folders on screen when it is switched on, a step on one side
//! takes the other side the same way.

use super::App;
use crate::pane::Side;
use crate::paths::{is_safe_name, join_segments, relative_segments};
use crate::ToastKind;
use std::rc::Rc;

impl App {
    pub fn toggle_sync(self: &Rc<Self>) {
        if self.st.borrow().sync_root.is_some() {
            self.st.borrow_mut().sync_root = None;
            self.push_sync();
            return;
        }
        if !self.connected() {
            self.info("Connect first to sync browsing");
            return;
        }
        let root = (self.pane(Side::Local).borrow().path.clone(), self.pane(Side::Remote).borrow().path.clone());
        self.st.borrow_mut().sync_root = Some(root);
        self.push_sync();
        self.toast("Synchronized browsing on. Both panes follow each other from here.", ToastKind::Ok);
    }

    pub(crate) fn push_sync(&self) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_sync_on(self.st.borrow().sync_root.is_some());
        }
    }

    /// `side` moved to `path`: take the other pane to the matching folder.
    pub(crate) async fn mirror(self: &Rc<Self>, side: Side, path: String) {
        let Some((local_root, remote_root)) = self.st.borrow().sync_root.clone() else { return };
        let remote = side == Side::Remote;
        let other = if remote { Side::Local } else { Side::Remote };
        let (root, other_root) = if remote { (remote_root, local_root) } else { (local_root, remote_root) };
        let segs = relative_segments(&root, &path, remote);
        // A server name may hold `\`, `..` pieces or characters Windows cannot store: never let
        // one steer the local pane outside the synced tree.
        let unsafe_seg = segs.as_ref().is_some_and(|s| s.iter().any(|x| x == "." || x == ".." || (remote && !is_safe_name(x))));
        let Some(segs) = segs.filter(|_| !unsafe_seg) else {
            let why = if unsafe_seg {
                "This folder has no counterpart on the other side, sync browsing turned off"
            } else {
                "Left the synced tree, sync browsing turned off"
            };
            self.info(why);
            self.toggle_sync();
            return;
        };
        let target = join_segments(&other_root, &segs, other == Side::Remote);
        if target == self.pane(other).borrow().path {
            return;
        }
        if self.navigate(other, target.clone(), true, None).await == Some(false) {
            self.info(format!("No matching folder on the {} side: {target}", if other == Side::Remote { "server" } else { "local" }));
        }
    }
}
