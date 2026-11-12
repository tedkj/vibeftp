//! Prompt, confirm and password: one modal at a time, each an awaitable answer.

use super::App;
use slint::{Model, ModelRc, SharedString, VecModel};
use std::rc::Rc;
use tokio::sync::oneshot;

pub enum Answer {
    Cancel,
    Ok(String, bool),
    /// OK on a confirm with choices: the one chosen (-1 none, which counts as no).
    Chose(i32),
}

const PROMPT: i32 = 1;
const CONFIRM: i32 = 2;
const PASSWORD: i32 = 3;

/// A confirm's warning line and its choices (none chosen at first), with the group's name.
#[derive(Default)]
pub(crate) struct Choice<'a> {
    pub warning: &'a str,
    pub label: &'a str,
    pub options: &'a [&'a str],
}

impl App {
    #[allow(clippy::too_many_arguments)]
    async fn modal(&self, kind: i32, title: &str, body: &str, label: &str, value: &str, ok: &str, danger: bool, select_to: i32, choice: Choice<'_>) -> Answer {
        let (tx, rx) = oneshot::channel();
        // Replace any open modal, answering it as cancelled so its caller never hangs.
        if let Some(old) = self.st.borrow_mut().modal.replace(tx) {
            let _ = old.send(Answer::Cancel);
        }
        if let Some(ui) = self.ui.upgrade() {
            // A replaced modal keeps its dialog instance: the text, the checkbox, the choice and
            // (through the seq) the focus and selection start over explicitly.
            let seq = {
                let mut st = self.st.borrow_mut();
                st.modal_seq += 1;
                st.modal_seq
            };
            ui.set_modal_seq(seq);
            ui.set_modal_title(crate::format::shown(title).as_ref().into());
            ui.set_modal_body(crate::format::shown_lines(body).into());
            ui.set_modal_label(label.into());
            ui.set_modal_typed(value.into());
            ui.set_modal_save(true);
            ui.set_modal_ok(ok.into());
            ui.set_modal_danger(danger);
            ui.set_modal_select_to(select_to);
            ui.set_modal_warning(crate::format::shown_lines(choice.warning).into());
            ui.set_modal_choices_label(choice.label.into());
            let options: Vec<SharedString> = choice.options.iter().map(|&o| o.into()).collect();
            ui.set_modal_choices(ModelRc::new(VecModel::from(options)));
            ui.set_modal_choice(-1);
            ui.set_modal_kind(kind);
        }
        rx.await.unwrap_or(Answer::Cancel)
    }

    /// Change the open modal's text (a count that came in after it opened).
    pub(crate) fn modal_body(&self, body: &str) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_modal_body(crate::format::shown_lines(body).into());
        }
    }

    pub fn modal_answer(&self, answer: Answer) {
        let tx = self.st.borrow_mut().modal.take();
        let mut answer = answer;
        if let Some(ui) = self.ui.upgrade() {
            // OK on a confirm with choices answers with the choice (none chosen counts as no).
            if matches!(answer, Answer::Ok(..)) && ui.get_modal_choices().row_count() > 0 {
                answer = Answer::Chose(ui.get_modal_choice());
            }
            ui.set_modal_kind(0);
            // The answer already carries the text; a typed password must not outlive its dialog.
            ui.set_modal_typed(Default::default());
        }
        if let Some(tx) = tx {
            let _ = tx.send(answer);
        }
    }

    /// The last dialog closed: the keyboard goes back to the list that had it.
    pub(crate) fn refocus(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let side = self.st.borrow().focused;
        ui.invoke_focus_pane(side as i32);
    }

    pub async fn prompt(self: &Rc<Self>, title: &str, value: &str, label: &str, ok: &str) -> Option<String> {
        self.prompt_select(title, value, label, ok, -1).await
    }

    /// A prompt whose text is selected up to `select_to` (a byte offset; -1 for all of it).
    pub async fn prompt_select(self: &Rc<Self>, title: &str, value: &str, label: &str, ok: &str, select_to: i32) -> Option<String> {
        match self.modal(PROMPT, title, "", label, value, ok, false, select_to, Choice::default()).await {
            Answer::Ok(v, _) => {
                let v = v.trim().to_string();
                if v.is_empty() { None } else { Some(v) }
            }
            _ => None,
        }
    }

    pub async fn confirm(self: &Rc<Self>, title: &str, body: &str, ok: &str, danger: bool) -> bool {
        matches!(self.modal(CONFIRM, title, body, "", "", ok, danger, -1, Choice::default()).await, Answer::Ok(..))
    }

    /// A confirm with a warning and options of which none is chosen at first: OK counts only
    /// with one chosen. The option chosen, or None (Cancel, Escape, or another modal over it).
    pub(crate) async fn choose(self: &Rc<Self>, title: &str, body: &str, ok: &str, choice: Choice<'_>) -> Option<usize> {
        let n = choice.options.len();
        match self.modal(CONFIRM, title, body, "", "", ok, false, -1, choice).await {
            Answer::Chose(i) if i >= 0 && (i as usize) < n => Some(i as usize),
            _ => None,
        }
    }

    /// The password (or passphrase) and whether to save it in the keychain.
    pub async fn ask_password(self: &Rc<Self>, title: &str, label: &str) -> Option<(String, bool)> {
        match self.modal(PASSWORD, title, "", label, "", "Connect", false, -1, Choice::default()).await {
            Answer::Ok(v, save) => Some((v, save)),
            _ => None,
        }
    }
}
