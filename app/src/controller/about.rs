//! About's "Check this install" (the family's About box, VibeTemplate's controller.rs): one at a
//! time, on a worker thread (it reads the files and may go online), the window polling for the
//! answer meanwhile. The services are handed in: `main` gives the real ones, the tests fakes.

use super::App;
use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::{CheckDot, CheckRow};
use slint::TimerMode;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, TryRecvError, channel};
use std::time::Duration;

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

/// What the install check needs from the outside world; the tests hand it fakes.
#[derive(Clone)]
pub struct Check {
    /// The check's offline half, on its worker: this copy's files, their signatures and hashes
    /// (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The check's online half, on its worker: the release list at a path on the site, waited
    /// for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

impl Check {
    /// The real services. `fetch` is the release-list fetcher: `main` hands in the exe's
    /// `net::fetch_release_list`, and is the only place that names it.
    pub fn system(fetch: Fetcher<str, Fetched>) -> Check {
        // The exe's identity as this process started from it, taken now (`main` builds this once,
        // at start), before an install could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        Check { inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)), fetch, release: Release::this() }
    }

    /// A check that reads no file and fetches nothing (its rows say the list couldn't be
    /// fetched): for windows driven by tests that are not about About (tests/live.rs,
    /// tests/live_checks.rs).
    pub fn none() -> Check {
        Check {
            inspect: Arc::new(|_: &bool| Local { files: Vec::new(), portable: false, replaced: false }),
            fetch: Arc::new(|_: &str| Fetched::Failed("this window has no install check".into())),
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

impl App {
    /// About's version line: VibeFTP installs per user only (no portable mode).
    pub(crate) fn about_line(&self) -> String {
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        format!("version {} · {bits} · installed for you", crate::VERSION)
    }

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    pub(crate) fn check_install(self: &Rc<Self>) {
        let Some(ui) = self.ui.upgrade() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.check.inspect.clone(), self.check.fetch.clone(), self.check.release.clone());
        // Installed: VibeFTP has no portable copy, so the uninstaller is always compared too.
        let installed = true;
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            // (This window's own "Update and restart" quits as the installer starts; another
            // VibeFTP window still open then lands here.)
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = Rc::downgrade(self);
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui.upgrade() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    pub(crate) fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: (*name).into(), text: r.text.as_str().into(), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }
}
