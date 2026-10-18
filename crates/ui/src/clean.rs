//! The clean surface: an allowlisted walk, laid out so it can be read before it happens.
//!
//! Cleaning is the one act whose object is a list, so the list is the interface. Each
//! surface shows its own count and size, each entry can be unticked, and the removal asks
//! once, naming the totals and the surfaces they come from. What the card draws is the
//! result of a dry run: the walk behind it writes nothing, and the shell walks again after
//! a clean, so what is left on screen is what is left on disk.

use std::collections::BTreeSet;

use egui::RichText;

use crate::world::{Action, CleanChoice, CleanItem, CleanReport, CleanSurface, World};
use crate::{theme, widgets};

/// What the clean card remembers between frames.
#[derive(Default)]
pub(crate) struct CleanState {
    /// Which dry run the selection belongs to, so a new walk starts from its own list.
    run: Option<u64>,
    /// The paths the person has ticked.
    selected: BTreeSet<String>,
    /// The surfaces whose entry list is open.
    open: BTreeSet<String>,
    /// Whether the confirmation is on screen.
    asking: bool,
}

impl CleanState {
    /// Take a new dry run's list, and forget the last one's selection.
    ///
    /// A selection belongs to the list it was made against. Keeping it across a new walk
    /// would let a tick outlive the entry it was made for, and the entry under that path
    /// may now be a different file.
    pub(crate) fn begin(&mut self, report: &CleanReport) {
        if self.run == Some(report.run) {
            return;
        }
        self.run = Some(report.run);
        self.selected = report
            .surfaces
            .iter()
            .filter(|surface| !surface.opt_in)
            .flat_map(|surface| surface.items.iter().map(|item| item.path.clone()))
            .collect();
        self.open.clear();
        self.asking = false;
    }

    fn is_selected(&self, path: &str) -> bool {
        self.selected.contains(path)
    }

    fn set(&mut self, path: &str, on: bool) {
        if on {
            self.selected.insert(path.to_owned());
        } else {
            self.selected.remove(path);
        }
    }

    fn set_surface(&mut self, surface: &CleanSurface, on: bool) {
        for item in &surface.items {
            self.set(&item.path, on);
        }
    }

    fn surface_selected(&self, surface: &CleanSurface) -> bool {
        !surface.items.is_empty() && surface.items.iter().all(|item| self.is_selected(&item.path))
    }

    /// Open the confirmation, which is the only step between a selection and an act.
    pub(crate) fn ask(&mut self) {
        self.asking = true;
    }

    pub(crate) fn toggle_open(&mut self, id: &str) {
        if !self.open.remove(id) {
            self.open.insert(id.to_owned());
        }
    }

    /// What the ticked entries add up to.
    fn totals(&self, report: &CleanReport) -> Totals {
        let mut totals = Totals::default();
        for surface in &report.surfaces {
            for item in &surface.items {
                if self.is_selected(&item.path) {
                    totals.add(item);
                }
            }
        }
        totals
    }

    /// What the shell is asked to remove: one choice per surface, and no surface with
    /// nothing ticked in it.
    fn choices(&self, report: &CleanReport) -> Vec<CleanChoice> {
        report
            .surfaces
            .iter()
            .filter_map(|surface| {
                let paths: Vec<String> = surface
                    .items
                    .iter()
                    .filter(|item| self.is_selected(&item.path))
                    .map(|item| item.path.clone())
                    .collect();
                if paths.is_empty() {
                    None
                } else {
                    Some(CleanChoice {
                        surface: surface.id.clone(),
                        paths,
                    })
                }
            })
            .collect()
    }

    /// The surfaces a selection reaches, by the name a person calls them.
    fn labels<'a>(&self, report: &'a CleanReport) -> Vec<&'a str> {
        report
            .surfaces
            .iter()
            .filter(|surface| surface.items.iter().any(|item| self.is_selected(&item.path)))
            .map(|surface| surface.label.as_str())
            .collect()
    }
}

/// What a set of entries adds up to, in the terms the confirmation uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Totals {
    files: usize,
    directories: usize,
    bytes: u64,
}

impl Totals {
    fn add(&mut self, item: &CleanItem) {
        if item.is_dir {
            self.directories = self.directories.saturating_add(1);
        } else {
            self.files = self.files.saturating_add(1);
            self.bytes = self.bytes.saturating_add(item.bytes);
        }
    }

    fn is_empty(&self) -> bool {
        self.files == 0 && self.directories == 0
    }

    fn entries(&self) -> usize {
        self.files.saturating_add(self.directories)
    }

    /// The phrase a confirmation is made of: what would go, and how much of it.
    ///
    /// An empty directory holds no bytes, so it is named rather than measured. Nothing at
    /// all reads as "nothing", which is a sentence a person can act on.
    fn sentence(&self) -> String {
        let mut parts = Vec::new();
        if self.files > 0 {
            parts.push(plural(self.files, "file", "files"));
        }
        if self.directories > 0 {
            parts.push(format!(
                "{} empty {}",
                count(self.directories),
                if self.directories == 1 {
                    "folder"
                } else {
                    "folders"
                }
            ));
        }
        let mut text = if parts.is_empty() {
            "nothing".to_owned()
        } else {
            parts.join(" and ")
        };
        if self.bytes > 0 {
            text.push_str(&format!(", {}", widgets::bytes(self.bytes)));
        }
        text
    }
}

/// Everything a dry run found, ticked or not.
fn found(report: &CleanReport) -> Totals {
    let mut totals = Totals::default();
    for surface in &report.surfaces {
        for item in &surface.items {
            totals.add(item);
        }
    }
    totals
}

/// A count with thousands separators: `1204` is a number, `1,204` is a quantity.
fn count(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.char_indices() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(character);
    }
    out
}

/// A count and its noun, pluralised by the count rather than by the writer's mood.
fn plural(value: usize, one: &str, many: &str) -> String {
    format!("{} {}", count(value), if value == 1 { one } else { many })
}

/// A list of names as a person reads it: `a`, `a and b`, `a, b and c`.
fn list(labels: &[&str]) -> String {
    match labels {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [first, second] => format!("{first} and {second}"),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The whole card.
pub(crate) fn card(ui: &mut egui::Ui, world: &World, state: &mut CleanState, actions: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        header(ui, world, actions);
        ui.add_space(8.0);
        let Some(report) = &world.clean else {
            widgets::empty(
                ui,
                "Nothing has been counted yet",
                "A dry run walks the folders ranger is allowed to remove from and lists what \
                 is older than each one's age. It writes nothing: no journal line, and no file \
                 leaves its place.",
            );
            return;
        };
        state.begin(report);
        if report.surfaces.is_empty() {
            widgets::empty(
                ui,
                "No folder to clean on this machine",
                "Ranger checked its allowlist — the temporary folders, the caches and the crash \
                 dumps for this operating system — and none of them exists. That is the result \
                 of the check, not a claim about the machine.",
            );
            return;
        }
        body(ui, report, state, actions);
    });
}

fn header(ui: &mut egui::Ui, world: &World, actions: &mut Vec<Action>) {
    ui.horizontal(|ui| {
        widgets::section(
            ui,
            "Clean",
            "Temporary files and caches ranger is allowed to remove from. A dry run lists and \
             counts them; nothing moves until you say so.",
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if world.clean_running {
                ui.spinner();
            }
            let label = if world.clean_running {
                "Counting…"
            } else if world.clean.is_some() {
                "Run again"
            } else {
                "Dry run"
            };
            if ui
                .add_enabled(
                    !world.clean_running,
                    egui::Button::new(RichText::new(label).size(11.5)),
                )
                .on_hover_text(
                    "Walk the allowlisted folders and count what is past each surface's age. \
                     This writes nothing.",
                )
                .clicked()
            {
                actions.push(Action::PreviewClean);
            }
        });
    });
}

fn body(ui: &mut egui::Ui, report: &CleanReport, state: &mut CleanState, actions: &mut Vec<Action>) {
    for surface in &report.surfaces {
        surface_row(ui, surface, state);
    }
    if report.cancelled {
        widgets::dot_line(
            ui,
            theme::ATTENTION,
            "The dry run was stopped before it finished, so this list is partial.",
        );
    }
    ui.add_space(4.0);
    footer(ui, report, state, actions);
}

fn surface_row(ui: &mut egui::Ui, surface: &CleanSurface, state: &mut CleanState) {
    widgets::border(ui, |ui| {
        ui.horizontal(|ui| {
            let has_items = !surface.items.is_empty();
            let mut on = state.surface_selected(surface);
            let check = ui.add_enabled(
                has_items,
                egui::Checkbox::new(
                    &mut on,
                    RichText::new(&surface.label).size(11.5).family(theme::semibold()),
                ),
            );
            if check.changed() {
                state.set_surface(surface, on);
            }
            // The list's control sits beside the name it opens, where the eye already is.
            // Right-aligned it looked like a stray link in the middle of the row, and a row
            // of five of them read as a column of centred text rather than as controls.
            if has_items {
                let open = state.open.contains(&surface.id);
                let label = if open {
                    "Hide".to_owned()
                } else {
                    format!("Show {}", count(surface.entries()))
                };
                if ui
                    .add(egui::Button::new(RichText::new(label).size(10.5)).frame(false))
                    .clicked()
                {
                    state.toggle_open(&surface.id);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if surface.opt_in {
                    widgets::badge(ui, "off by default", theme::ATTENTION);
                }
            });
        });
        ui.add_space(2.0);
        ui.label(RichText::new(detail(surface)).size(10.5).color(theme::muted(ui)));
        let kept = surface.kept_sentence();
        if !kept.is_empty() {
            ui.label(RichText::new(kept).size(10.0).color(theme::muted(ui)));
        }
        if state.open.contains(&surface.id) {
            ui.add_space(4.0);
            entries(ui, surface, state);
        }
    });
}

/// One surface's totals in a sentence, including the reason it has nothing to offer.
fn detail(surface: &CleanSurface) -> String {
    if surface.items.is_empty() {
        return "Nothing here is old enough to offer.".to_owned();
    }
    let folders = plural(surface.roots, "folder", "folders");
    let files = plural(
        surface.items.iter().filter(|item| !item.is_dir).count(),
        "file",
        "files",
    );
    let folders_found = surface.items.iter().filter(|item| item.is_dir).count();
    let mut line = format!("{files} · {} in {folders}", widgets::bytes(surface.bytes()));
    if folders_found > 0 {
        line.push_str(&format!(
            " · {} empty",
            plural(folders_found, "folder", "folders")
        ));
    }
    let kept = surface.kept_sentence();
    if !kept.is_empty() {
        line.push_str(&format!(" · {kept}"));
    }
    line
}

fn entries(ui: &mut egui::Ui, surface: &CleanSurface, state: &mut CleanState) {
    // A uniform row height is what lets the list stay scrollable when a cache holds ten
    // thousand files: only the rows in view are built.
    const ROW_HEIGHT: f32 = 17.0;
    egui::ScrollArea::vertical()
        .id_salt(("clean-entries", surface.id.as_str()))
        .max_height(176.0)
        .auto_shrink([false, true])
        .show_rows(ui, ROW_HEIGHT, surface.items.len(), |ui, range| {
            for index in range {
                let Some(item) = surface.items.get(index) else {
                    continue;
                };
                item_row(ui, item, state);
            }
        });
}

fn item_row(ui: &mut egui::Ui, item: &CleanItem, state: &mut CleanState) {
    ui.horizontal(|ui| {
        let mut on = state.is_selected(&item.path);
        if ui.add(egui::Checkbox::without_text(&mut on)).changed() {
            state.set(&item.path, on);
        }
        let width = (ui.available_width() - 76.0).max(80.0);
        ui.add_sized(
            [width, 15.0],
            egui::Label::new(RichText::new(&item.path).size(10.0).monospace()).truncate(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let text = if item.is_dir {
                "empty folder".to_owned()
            } else {
                widgets::bytes(item.bytes)
            };
            ui.label(RichText::new(text).size(10.0).color(theme::muted(ui)));
        });
    });
}

fn footer(ui: &mut egui::Ui, report: &CleanReport, state: &mut CleanState, actions: &mut Vec<Action>) {
    let selected = state.totals(report);
    let found = found(report);
    if state.asking {
        confirm(ui, report, &selected, state, actions);
        return;
    }
    ui.horizontal(|ui| {
        let line = if found.is_empty() {
            "Nothing is old enough to offer on this machine yet.".to_owned()
        } else if selected.is_empty() {
            format!("Nothing is selected, of {} found.", found.sentence())
        } else {
            format!("{} selected, of {} found.", selected.sentence(), found.sentence())
        };
        ui.label(RichText::new(line).size(11.0).color(theme::muted(ui)));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add_enabled(
                    !selected.is_empty(),
                    egui::Button::new(RichText::new("Remove selected…").size(11.5)),
                )
                .on_hover_text("Ask once, naming what would go.")
                .clicked()
            {
                state.ask();
            }
        });
    });
}

/// The one confirmation, naming the totals and the surfaces they come from.
fn confirm(
    ui: &mut egui::Ui,
    report: &CleanReport,
    totals: &Totals,
    state: &mut CleanState,
    actions: &mut Vec<Action>,
) {
    let labels = state.labels(report);
    widgets::border(ui, |ui| {
        ui.label(
            RichText::new(format!("Remove {} from {}?", totals.sentence(), list(&labels)))
                .size(12.0)
                .family(theme::semibold()),
        );
        ui.add_space(2.0);
        ui.label(
            RichText::new(
                "Every entry is checked again first: one that changed, vanished or became a \
                 link since the dry run is skipped and counted. The act is written to the \
                 journal before it starts.",
            )
            .size(10.5)
            .color(theme::muted(ui)),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(format!("Remove {}", plural(totals.entries(), "entry", "entries")))
                            .size(11.5),
                    )
                    .fill(theme::BAD),
                )
                .on_hover_text("There is no undo for a cache entry. A program rebuilds it.")
                .clicked()
            {
                actions.push(Action::CleanSelected(state.choices(report)));
                state.asking = false;
            }
            if ui
                .add(egui::Button::new(RichText::new("Cancel").size(11.5)).frame(false))
                .clicked()
            {
                state.asking = false;
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(path: &str, bytes: u64, is_dir: bool) -> CleanItem {
        CleanItem {
            path: path.to_owned(),
            bytes,
            is_dir,
        }
    }

    fn surface(id: &str, label: &str, opt_in: bool, items: Vec<CleanItem>) -> CleanSurface {
        CleanSurface {
            id: id.to_owned(),
            label: label.to_owned(),
            roots: 1,
            opt_in,
            items,
            ..CleanSurface::default()
        }
    }

    fn report(run: u64, surfaces: Vec<CleanSurface>) -> CleanReport {
        CleanReport {
            run,
            surfaces,
            cancelled: false,
        }
    }

    fn bed() -> (CleanReport, CleanState) {
        let first = report(
            1,
            vec![
                surface(
                    "win.temp",
                    "Temporary files",
                    false,
                    vec![
                        item("C:/Temp/a.tmp", 100, false),
                        item("C:/Temp/b.tmp", 200, false),
                        item("C:/Temp/empty", 0, true),
                    ],
                ),
                surface(
                    "mac.logs",
                    "User logs",
                    true,
                    vec![item("C:/Logs/old.log", 50, false)],
                ),
            ],
        );
        let mut state = CleanState::default();
        state.begin(&first);
        (first, state)
    }

    #[test]
    fn the_totals_count_files_folders_and_bytes() {
        let (report, state) = bed();
        let totals = state.totals(&report);
        assert_eq!(
            totals,
            Totals {
                files: 2,
                directories: 1,
                bytes: 300,
            },
            "the opt-in log is not in a selection it never asked for"
        );
        assert_eq!(found(&report).files, 3, "but it is in what was found");
    }

    #[test]
    fn a_selection_resets_when_a_new_dry_run_lands() {
        let (first, mut state) = bed();
        state.set("C:/Temp/a.tmp", false);
        assert_eq!(state.totals(&first).files, 1);

        state.begin(&first);
        assert_eq!(state.totals(&first).files, 1, "the same run keeps the selection");

        let next = report(
            2,
            vec![surface(
                "win.temp",
                "Temporary files",
                false,
                vec![item("C:/Temp/a.tmp", 100, false)],
            )],
        );
        state.begin(&next);
        assert_eq!(state.totals(&next).files, 1, "a new run starts from its own list");
        assert!(
            !state.is_selected("C:/Temp/b.tmp"),
            "an entry the new walk did not offer cannot stay ticked"
        );
    }

    #[test]
    fn only_a_surface_with_a_selection_becomes_a_choice() {
        let (report, mut state) = bed();
        assert_eq!(
            state.choices(&report).len(),
            1,
            "the log surface has nothing ticked"
        );

        state.set("C:/Temp/a.tmp", false);
        state.set("C:/Temp/b.tmp", false);
        state.set("C:/Temp/empty", false);
        assert!(
            state.choices(&report).is_empty(),
            "an empty selection is not an act"
        );

        state.set("C:/Temp/b.tmp", true);
        let choices = state.choices(&report);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].surface, "win.temp");
        assert_eq!(choices[0].paths, vec!["C:/Temp/b.tmp".to_owned()]);
    }

    #[test]
    fn a_surface_switch_toggles_every_entry_in_it() {
        let (report, mut state) = bed();
        let row = report.surfaces.first().expect("the fixture has a surface");
        assert!(state.surface_selected(row));

        state.set_surface(row, false);
        assert!(!state.surface_selected(row));
        assert_eq!(state.totals(&report).files, 0);

        state.set_surface(row, true);
        assert!(state.surface_selected(row));
        assert_eq!(state.totals(&report).files, 2);
    }

    #[test]
    fn a_surface_with_nothing_to_offer_is_never_selected() {
        let empty = surface("win.gpu", "GPU shader cache", false, Vec::new());
        assert!(!CleanState::default().surface_selected(&empty));
        assert!(list(&[]).is_empty());
    }

    #[test]
    fn the_confirmation_names_the_totals_the_way_a_person_reads_them() {
        assert_eq!(
            Totals {
                files: 1204,
                directories: 12,
                bytes: 327_155_000,
            }
            .sentence(),
            "1,204 files and 12 empty folders, 312.0 MB"
        );
        assert_eq!(
            Totals {
                files: 1,
                directories: 0,
                bytes: 0,
            }
            .sentence(),
            "1 file"
        );
        assert_eq!(
            Totals {
                files: 0,
                directories: 2,
                bytes: 0,
            }
            .sentence(),
            "2 empty folders",
            "an empty folder holds no bytes to name"
        );
        assert_eq!(Totals::default().sentence(), "nothing");
    }

    #[test]
    fn the_confirmation_names_the_surfaces_in_reading_order() {
        assert_eq!(list(&[]), "");
        assert_eq!(list(&["Temporary files"]), "Temporary files");
        assert_eq!(list(&["a", "b"]), "a and b");
        assert_eq!(list(&["a", "b", "c"]), "a, b and c");
    }

    #[test]
    fn counts_read_like_quantities() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1000), "1,000");
        assert_eq!(count(1_234_567), "1,234,567");
        assert_eq!(plural(1, "file", "files"), "1 file");
        assert_eq!(plural(2, "file", "files"), "2 files");
    }
}
