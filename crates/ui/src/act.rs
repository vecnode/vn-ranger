//! The Actions view: the quarantine, and the record of what ranger did.
//!
//! Two lists and one small dialog of their own. A restore is one click, because a restore
//! is reversible and the file is verified before it moves. A permanent delete is not: it
//! asks for the word `DELETE` to be typed into the row, and the shell checks the word
//! again before it acts, because a confirmation that only the interface enforces is a
//! suggestion.

use egui::RichText;

use crate::clean::CleanState;
use crate::world::{Action, JournalRow, QuarantineRow, World};
use crate::{theme, widgets};

/// The word a person types to delete a quarantined file for good.
pub(crate) const DELETE_WORD: &str = "DELETE";

/// What the purge row is asking, if anything.
#[derive(Default)]
pub(crate) struct PurgeAsk {
    /// The entry waiting for its word.
    pub target: Option<String>,
    /// What has been typed so far.
    pub typed: String,
}

impl PurgeAsk {
    /// Cancel whatever was being asked.
    fn reset(&mut self) {
        self.target = None;
        self.typed.clear();
    }

    /// Whether the person has typed the word for this entry.
    fn ready(&self, id: &str) -> bool {
        self.target.as_deref() == Some(id) && self.typed.trim() == DELETE_WORD
    }
}

/// The whole view.
///
/// Three cards in the order a person needs them: what ranger could remove (dry run only),
/// what it has already moved aside, and what it has recorded.
pub(crate) fn view(
    ui: &mut egui::Ui,
    world: &World,
    ask: &mut PurgeAsk,
    clean: &mut CleanState,
    actions: &mut Vec<Action>,
) {
    crate::clean::card(ui, world, clean, actions);
    ui.add_space(14.0);
    quarantine(ui, world, ask, actions);
    ui.add_space(14.0);
    journal(ui, world);
}

fn quarantine(ui: &mut egui::Ui, world: &World, ask: &mut PurgeAsk, actions: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::section(
                ui,
                "Quarantine",
                "Files ranger moved out of the way. A restore checks the bytes before it writes.",
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(egui::Button::new(RichText::new("Refresh").size(11.5)).frame(false))
                    .on_hover_text("Read the quarantine and the journal from disk again.")
                    .clicked()
                {
                    actions.push(Action::RefreshActions);
                }
            });
        });
        ui.add_space(8.0);
        if world.quarantine.is_empty() {
            widgets::empty(
                ui,
                "No file is in quarantine",
                "Nothing has been moved here yet. Ranger checks the quarantine folder in \
                 ranger's data directory on every refresh.",
            );
            return;
        }
        for row in &world.quarantine {
            row_line(ui, row, ask, actions);
        }
    });
}

fn row_line(ui: &mut egui::Ui, row: &QuarantineRow, ask: &mut PurgeAsk, actions: &mut Vec<Action>) {
    widgets::border(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(&row.original_path)
                        .size(12.0)
                        .family(theme::semibold()),
                );
                ui.add_space(2.0);
                let detail = format!(
                    "{} · {} · taken {} · {}",
                    widgets::bytes(row.bytes),
                    row.hash_short,
                    row.at_label,
                    row.reason
                );
                ui.label(RichText::new(detail).size(11.0).color(theme::muted(ui)));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ask.target.as_deref() == Some(row.id.as_str()) {
                    let ready = ask.ready(&row.id);
                    if ui
                        .add_enabled(
                            ready,
                            egui::Button::new(RichText::new("Delete for good").size(11.5)).fill(theme::BAD),
                        )
                        .on_hover_text(
                            "There is no undo for this one. Ranger deletes the stored copy and \
                             the manifest.",
                        )
                        .clicked()
                    {
                        actions.push(Action::Purge {
                            id: row.id.clone(),
                            typed: ask.typed.clone(),
                        });
                        ask.reset();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut ask.typed)
                            .hint_text(DELETE_WORD)
                            .desired_width(96.0),
                    );
                    if ui
                        .add(egui::Button::new(RichText::new("Cancel").size(11.5)).frame(false))
                        .clicked()
                    {
                        ask.reset();
                    }
                } else {
                    if ui
                        .add(egui::Button::new(RichText::new("Delete…").size(11.5)).frame(false))
                        .on_hover_text("Delete the stored copy. Ranger will ask for a word.")
                        .clicked()
                    {
                        ask.target = Some(row.id.clone());
                        ask.typed.clear();
                    }
                    if ui
                        .add(egui::Button::new(RichText::new("Restore").size(11.5)))
                        .on_hover_text(
                            "Put the file back where it came from. Ranger verifies its hash first \
                             and never overwrites a file that is already there.",
                        )
                        .clicked()
                    {
                        actions.push(Action::Restore(row.id.clone()));
                    }
                }
            });
        });
    });
}

fn journal(ui: &mut egui::Ui, world: &World) {
    widgets::card(ui, |ui| {
        widgets::section(
            ui,
            "Journal",
            "What ranger observed and what it did, newest first. It is a file in the data \
             directory, not a database.",
        );
        if world.journal_damaged {
            ui.add_space(4.0);
            widgets::dot_line(
                ui,
                theme::ATTENTION,
                "A line of the journal could not be read and was skipped. Nothing before it was lost.",
            );
        }
        ui.add_space(4.0);
        if let Some(seq) = world.journal_chain_broken {
            widgets::dot_line(
                ui,
                theme::ATTENTION,
                &format!(
                    "The hash chain does not verify at entry {seq}: a fact in that line, or a line \
                     around it, is not what was written. The record up to the entry before it still \
                     verifies."
                ),
            );
        } else if let Some(from) = world.journal_unchained_from {
            widgets::dot_line(
                ui,
                theme::muted(ui),
                &format!(
                    "The chain covers entries from {from} onwards. Earlier lines were written before \
                     the chain existed, so they cannot be covered retroactively."
                ),
            );
        } else if !world.journal.is_empty() {
            widgets::dot_line(
                ui,
                theme::OK,
                "The hash chain verifies: every line covers the one before it.",
            );
        }
        ui.add_space(8.0);
        if world.journal.is_empty() {
            widgets::empty(
                ui,
                "The journal is empty",
                "Ranger writes a line when it starts, when it observes something, and when it \
                 acts. Nothing has been recorded yet.",
            );
            return;
        }
        egui::ScrollArea::vertical()
            .max_height(360.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for row in &world.journal {
                    journal_line(ui, row);
                }
            });
    });
}

fn journal_line(ui: &mut egui::Ui, row: &JournalRow) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("#{}", row.seq))
                .size(10.5)
                .monospace()
                .color(theme::muted(ui)),
        );
        let colour = if row.interrupted || row.kind == "error" {
            theme::ATTENTION
        } else {
            theme::muted(ui)
        };
        ui.label(RichText::new(&row.at_label).size(10.5).color(colour));
        let kind = match row.action {
            Some(action) => format!("{} · {action}", row.kind),
            None => row.kind.to_owned(),
        };
        ui.label(
            RichText::new(kind)
                .size(10.5)
                .family(theme::semibold())
                .color(if row.interrupted {
                    theme::ATTENTION
                } else {
                    ui.visuals().text_color()
                }),
        );
        ui.label(
            RichText::new(&row.subject)
                .size(11.0)
                .color(ui.visuals().text_color()),
        );
        if !row.detail.is_empty() {
            ui.label(RichText::new(&row.detail).size(10.5).color(theme::muted(ui)));
        }
        if row.interrupted {
            ui.label(
                RichText::new("no result was recorded")
                    .size(10.5)
                    .color(theme::ATTENTION),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_has_to_hold_the_target_and_be_typed_exactly() {
        let mut ask = PurgeAsk::default();
        assert!(!ask.ready("abc"), "nothing is being asked yet");

        ask.target = Some("abc".to_owned());
        assert!(!ask.ready("abc"), "the target alone is not a confirmation");

        ask.typed = "DELETE".to_owned();
        assert!(ask.ready("abc"));
        assert!(!ask.ready("def"), "the word for one entry does not open another");

        ask.typed = "delete".to_owned();
        assert!(!ask.ready("abc"), "the word is upper case");

        ask.typed = "  DELETE \n".to_owned();
        assert!(ask.ready("abc"), "surrounding space is not a security property");

        ask.typed = "DELET".to_owned();
        assert!(!ask.ready("abc"));

        ask.reset();
        assert!(ask.target.is_none());
        assert!(ask.typed.is_empty());
    }
}
