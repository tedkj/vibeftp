//! The file list model: the pane's sorted view, read on demand. Slint asks for the rows it
//! draws (a ListView only instantiates what is on screen), so a 20 000-entry folder builds about
//! thirty rows per frame, and a click repaints only the rows whose state changed.

use crate::format::{bytes, shown, when};
use crate::pane::{Change, Pane};
use crate::FileItem;
use slint::{Model, ModelNotify, ModelTracker};
use std::cell::RefCell;
use std::rc::Rc;

pub struct FileModel {
    pane: Rc<RefCell<Pane>>,
    notify: ModelNotify,
}

impl FileModel {
    pub fn new(pane: Rc<RefCell<Pane>>) -> Rc<Self> {
        Rc::new(FileModel { pane, notify: ModelNotify::default() })
    }

    /// Tell the list what a pane change touched. Call with no borrow of the pane held: Slint
    /// may read rows right away.
    pub fn apply(&self, change: Change) {
        match change {
            Change::None => {}
            Change::Reset => self.notify.reset(),
            Change::Rows(rows) => {
                for r in rows {
                    self.notify.row_changed(r);
                }
            }
        }
    }
}

impl Model for FileModel {
    type Data = FileItem;

    fn row_count(&self) -> usize {
        self.pane.borrow().view_len()
    }

    fn row_data(&self, row: usize) -> Option<FileItem> {
        let p = self.pane.borrow();
        let e = p.view_entry(row)?;
        Some(FileItem {
            name: shown(&e.name).as_ref().into(),
            path: e.path.as_str().into(),
            size: if e.is_dir { Default::default() } else { bytes(e.size).into() },
            modified: when(e.modified).into(),
            is_dir: e.is_dir,
            is_link: e.is_link,
            selected: p.is_selected(&e.path),
            cursor: p.cursor() == Some(e.path.as_str()),
        })
    }

    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }
}

/// The transfer queue, newest first, read on demand (progress repaints one row).
pub struct QueueModel {
    queue: Rc<RefCell<Vec<crate::controller::transfers::TRef>>>,
    pub(crate) notify: ModelNotify,
}

impl QueueModel {
    pub fn new(queue: Rc<RefCell<Vec<crate::controller::transfers::TRef>>>) -> Rc<Self> {
        Rc::new(QueueModel { queue, notify: ModelNotify::default() })
    }
}

impl Model for QueueModel {
    type Data = crate::QueueRow;

    fn row_count(&self) -> usize {
        self.queue.borrow().len()
    }

    fn row_data(&self, row: usize) -> Option<crate::QueueRow> {
        let q = self.queue.borrow();
        let n = q.len();
        let t = q.get(n.checked_sub(row + 1)?)?;
        let row = crate::controller::transfers::queue_row(&t.borrow());
        Some(row)
    }

    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.notify
    }
}
