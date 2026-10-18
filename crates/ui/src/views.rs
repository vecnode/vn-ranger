//! The six surfaces. Each one is a function of the [`World`] and the interface state,
//! and returns nothing but the actions a person asked for.

use egui::{Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use vnr_core::time::{describe_age, format_utc};
use vnr_core::{AutorunScope, ProcessFact, Snapshot};

use crate::{Action, ChangeFilter, FindingSort, ProcessFilter, SortKey, TrayState, Ui, View, theme, widgets};

const PROCESS_FOOTER: f32 = 190.0;
const STARTUP_FOOTER: f32 = 210.0;
const TABLE_HEADER: f32 = 26.0;
const TABLE_ROW: f32 = 24.0;
/// Breathing room below a detail footer, so the card does not merge into the window edge.
const BOTTOM_GAP: f32 = 12.0;

impl Ui {
    /// The overview: the state of the machine at a glance.
    pub(crate) fn overview(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(
                ui,
                "Nothing scanned yet",
                "Ranger has not looked at this machine in this session.",
            );
            if ui
                .add(
                    egui::Button::new(RichText::new("Run the first scan").color(theme::ON_EMBER))
                        .fill(theme::EMBER),
                )
                .clicked()
            {
                actions.push(Action::Scan);
            }
            return;
        };
        let counts = snapshot.counts();
        let process_count = world.processes().len();
        let width = ui.available_width();
        // What the last scan was, where a person reads about the scan, and in the order
        // they ask it: how long ago, how long it took, and what it covered.
        widgets::caption(
            ui,
            &format!(
                "Scanned {} · took {} · {} collectors",
                describe_age(world.now_unix, snapshot.taken_at_unix),
                describe_duration(snapshot.duration_ms),
                snapshot.collectors.len()
            ),
        );
        ui.add_space(6.0);
        let mut facts = vec![
            (process_count, "processes"),
            (counts.autoruns, "startup items"),
            (counts.listeners, "listeners"),
            (counts.packages, "packages"),
        ];
        if !world.changes.is_empty() {
            facts.push((world.changes.len(), "changes from the baseline"));
        }
        widgets::inventory(ui, &facts);
        ui.add_space(10.0);

        let attention = world
            .findings
            .iter()
            .filter(|finding| finding.severity == vnr_core::Severity::Attention)
            .count();
        let notice = world
            .findings
            .iter()
            .filter(|finding| finding.severity == vnr_core::Severity::Notice)
            .count();
        let info = world.findings.len().saturating_sub(attention + notice);
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Findings").family(theme::semibold()));
                if attention > 0 {
                    widgets::badge(ui, "ATTENTION", theme::ATTENTION);
                }
            });
            ui.add_space(4.0);
            if world.findings.is_empty() {
                ui.label(
                    RichText::new(
                        "No rule fired on this scan. That is what ranger saw, not a verdict that the machine is clean.",
                    )
                    .size(11.0)
                    .color(theme::muted(ui)),
                );
            } else {
                ui.label(
                    RichText::new(format!(
                        "{} finding(s) · {attention} attention · {notice} notice · {info} info",
                        world.findings.len()
                    ))
                    .size(11.5),
                );
                if ui.button("Open Findings").clicked() {
                    self.view = View::Findings;
                }
            }
        });
        ui.add_space(10.0);

        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Baseline").family(theme::semibold()));
                if world.baseline.is_some() {
                    widgets::badge(ui, "ACCEPTED", theme::OK);
                }
            });
            ui.add_space(4.0);
            match &world.baseline {
                Some(baseline) => {
                    ui.label(
                        RichText::new(format!(
                            "Accepted {} ago. {} difference(s) from it now.",
                            describe_age(world.now_unix, baseline.taken_at_unix),
                            world.changes.len()
                        ))
                        .size(11.0)
                        .color(theme::muted(ui)),
                    );
                    if ui.button("Re-baseline this scan").clicked() {
                        actions.push(Action::AcceptBaseline);
                    }
                }
                None => {
                    ui.label(
                        RichText::new(
                            "No baseline yet. Accepting a scan records this machine as normal today, so a later scan can say what changed.",
                        )
                        .size(11.0)
                        .color(theme::muted(ui)),
                    );
                    if world.snapshot().is_some() && ui.button("Accept this scan as the baseline").clicked() {
                        actions.push(Action::AcceptBaseline);
                    }
                }
            }
        });
        ui.add_space(10.0);

        if snapshot.has_matches() {
            signature_matches_card(ui, snapshot);
        } else {
            signature_card(ui, snapshot, actions);
        }
        ui.add_space(10.0);

        if width >= 720.0 {
            ui.columns(2, |columns| {
                startup_preview(&mut columns[0], snapshot);
                listener_preview(&mut columns[1], snapshot);
            });
        } else {
            startup_preview(ui, snapshot);
            ui.add_space(8.0);
            listener_preview(ui, snapshot);
        }
        ui.add_space(10.0);
        collectors_card(ui, snapshot);
    }

    /// The rules' findings, with the evidence behind each one.
    pub(crate) fn findings(&mut self, ui: &mut egui::Ui, world: &crate::World, _actions: &mut Vec<Action>) {
        if world.findings.is_empty() {
            widgets::empty(
                ui,
                "No findings",
                "None of the 15 rules fired on this scan. That is a statement about the facts ranger could see, not a verdict that the machine is clean.",
            );
            if !world.suppressions.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "{} suppression(s) are active and may be hiding a finding.",
                        world.suppressions.len()
                    ))
                    .size(11.0)
                    .color(theme::muted(ui)),
                );
            }
            return;
        }

        let attention = world
            .findings
            .iter()
            .filter(|finding| finding.severity == vnr_core::Severity::Attention)
            .count();
        let notice = world
            .findings
            .iter()
            .filter(|finding| finding.severity == vnr_core::Severity::Notice)
            .count();
        let info = world.findings.len().saturating_sub(attention + notice);

        // Filters stay above the list so a long scan remains navigable.
        ui.horizontal_wrapped(|ui| {
            for (label, value, count) in [
                ("All", None, world.findings.len()),
                ("Attention", Some(vnr_core::Severity::Attention), attention),
                ("Notice", Some(vnr_core::Severity::Notice), notice),
                ("Info", Some(vnr_core::Severity::Info), info),
            ] {
                let selected = self.finding_severity == value;
                if widgets::chip(ui, selected, &format!("{label} ({count})")).clicked() {
                    self.finding_severity = value;
                }
            }
            ui.add_space(8.0);
            widgets::filter_field(ui, &mut self.finding_query, "Filter by rule, subject or evidence");
            if (self.finding_severity.is_some() || !self.finding_query.trim().is_empty())
                && ui.button("Clear").clicked()
            {
                self.finding_severity = None;
                self.finding_query.clear();
            }
        });
        ui.add_space(6.0);

        let needle = self.finding_query.trim().to_lowercase();
        let matches = |finding: &vnr_core::Finding| {
            let severity_ok = self
                .finding_severity
                .is_none_or(|severity| finding.severity == severity);
            let text_ok = needle.is_empty()
                || finding.title.to_lowercase().contains(&needle)
                || finding.subject_label.to_lowercase().contains(&needle)
                || finding.rule_id.contains(&needle)
                || finding
                    .evidence
                    .iter()
                    .any(|line| line.to_lowercase().contains(&needle));
            severity_ok && text_ok
        };

        let mut shown: Vec<&vnr_core::Finding> =
            world.findings.iter().filter(|finding| matches(finding)).collect();
        shown.sort_by(|a, b| match self.finding_sort {
            FindingSort::Severity => b
                .severity
                .rank()
                .cmp(&a.severity.rank())
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.subject.cmp(&b.subject)),
            FindingSort::Rule => a
                .rule_id
                .cmp(&b.rule_id)
                .then_with(|| b.severity.rank().cmp(&a.severity.rank()))
                .then_with(|| a.subject.cmp(&b.subject)),
            FindingSort::Subject => a
                .subject_label
                .to_lowercase()
                .cmp(&b.subject_label.to_lowercase())
                .then_with(|| a.rule_id.cmp(&b.rule_id)),
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Sort").size(10.5).color(theme::muted(ui)));
            for sort in FindingSort::ALL {
                if widgets::chip(ui, self.finding_sort == sort, sort.label()).clicked() {
                    self.finding_sort = sort;
                }
            }
        });
        ui.label(
            RichText::new(format!(
                "Showing {} of {} finding(s)",
                shown.len(),
                world.findings.len()
            ))
            .size(10.5)
            .color(theme::muted(ui)),
        );
        ui.add_space(4.0);

        let mut target = None;
        if shown.is_empty() {
            widgets::empty(
                ui,
                "No findings match this filter",
                "Change the severity or the text to see the rest of this scan.",
            );
        } else {
            egui::ScrollArea::vertical()
                .id_salt("findings")
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .show(ui, |ui| {
                    for finding in shown {
                        if finding_card(ui, finding) {
                            target = Some(finding.clone());
                        }
                        ui.add_space(8.0);
                    }
                });
        }
        if let Some(finding) = target {
            self.suppress_target = Some(finding);
            self.suppress_reason.clear();
        }
    }

    /// The process table and its detail footer.
    pub(crate) fn processes(&mut self, ui: &mut egui::Ui, world: &crate::World) {
        let processes = world.processes();
        if processes.is_empty() && world.snapshot().is_none() {
            widgets::empty(ui, "No processes yet", "Run a scan to see what is running.");
            return;
        }
        let needle = self.search.trim().to_lowercase();
        let mut rows: Vec<&ProcessFact> = processes
            .iter()
            .filter(|process| filter_process(process, &needle))
            .collect();

        // Controls stay above the table: sort and quick filters, then the count.
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Sort").size(10.5).color(theme::muted(ui)));
            for key in SortKey::ALL {
                let selected = self.process_sort == key;
                let label = if selected {
                    if self.process_sort_desc {
                        format!("{} ↓", key.label())
                    } else {
                        format!("{} ↑", key.label())
                    }
                } else {
                    key.label().to_owned()
                };
                if widgets::chip(ui, selected, &label).clicked() {
                    if selected {
                        self.process_sort_desc = !self.process_sort_desc;
                    } else {
                        self.process_sort = key;
                        self.process_sort_desc = false;
                    }
                }
            }
            ui.add_space(10.0);
            ui.label(RichText::new("Filter").size(10.5).color(theme::muted(ui)));
            for filter in ProcessFilter::ALL {
                if widgets::chip(ui, self.process_filter == filter, filter.label()).clicked() {
                    self.process_filter = filter;
                }
            }
            ui.add_space(10.0);
            ui.label(RichText::new("Group").size(10.5).color(theme::muted(ui)));
            egui::ComboBox::from_id_salt("process-group")
                .selected_text(self.process_group.label())
                .width(88.0)
                .show_ui(ui, |ui| {
                    for grouping in crate::ProcessGrouping::ALL {
                        ui.selectable_value(&mut self.process_group, grouping, grouping.label());
                    }
                });
        });

        let listening: std::collections::HashSet<u32> = world
            .snapshot()
            .map(|snapshot| {
                snapshot
                    .listeners
                    .iter()
                    .filter_map(|listener| listener.pid)
                    .collect()
            })
            .unwrap_or_default();
        rows.retain(|process| match self.process_filter {
            ProcessFilter::All => true,
            ProcessFilter::Listening => listening.contains(&process.pid),
            ProcessFilter::NoPath => process.exe.is_none(),
            ProcessFilter::Scratch => process.exe.as_deref().is_some_and(scratch_path),
        });
        rows.sort_by(|a, b| {
            let ordering = match self.process_sort {
                SortKey::Name => a
                    .name
                    .to_lowercase()
                    .cmp(&b.name.to_lowercase())
                    .then_with(|| a.pid.cmp(&b.pid)),
                SortKey::Pid => a.pid.cmp(&b.pid),
                SortKey::User => a
                    .user
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .cmp(&b.user.as_deref().unwrap_or("").to_lowercase())
                    .then_with(|| a.pid.cmp(&b.pid)),
                SortKey::Started => a
                    .started_at_unix
                    .cmp(&b.started_at_unix)
                    .then_with(|| a.pid.cmp(&b.pid)),
            };
            if self.process_sort_desc {
                ordering.reverse()
            } else {
                ordering
            }
        });
        // A selection made somewhere else — the palette, a finding, a listener — must not
        // land in a closed group where nobody can see it, so the group of the selected
        // process stays open for as long as it is selected.
        if self.process_group == crate::ProcessGrouping::Name
            && let Some(pid) = self.selected_process
            && let Some(selected) = processes.iter().find(|process| process.pid == pid)
        {
            self.process_expanded.insert(selected.name.to_lowercase());
        }
        let lines = process_lines(&rows, self.process_group, &self.process_expanded);
        // What the keyboard walks: the processes on screen, in the order they are on screen.
        // A collapsed group contributes no stops, which is what keeps j and k honest.
        let visible: Vec<u32> = lines
            .iter()
            .filter_map(|line| match line {
                ProcessLine::Process { process, .. } => Some(process.pid),
                ProcessLine::Group { .. } => None,
            })
            .collect();
        if !ui.ctx().memory(|memory| memory.focused().is_some()) && !self.palette_open {
            let down =
                ui.input(|input| input.key_pressed(egui::Key::J) || input.key_pressed(egui::Key::ArrowDown));
            let up =
                ui.input(|input| input.key_pressed(egui::Key::K) || input.key_pressed(egui::Key::ArrowUp));
            if down || up {
                let current = visible.iter().position(|pid| Some(*pid) == self.selected_process);
                let next = match current {
                    Some(index) if down => Some((index + 1).min(visible.len().saturating_sub(1))),
                    Some(index) => Some(index.saturating_sub(1)),
                    None if down => Some(0),
                    None => None,
                };
                if let Some(pid) = next.and_then(|index| visible.get(index)) {
                    self.selected_process = Some(*pid);
                }
            }
        }
        let live_age = world
            .live
            .as_ref()
            .filter(|live| !live.items.is_empty())
            .map(|live| describe_age(world.now_unix, live.at_unix));
        let live_note = if live_age.is_some() { " · live" } else { "" };
        let groups = lines
            .iter()
            .filter(|line| matches!(line, ProcessLine::Group { .. }))
            .count();
        let group_note = if self.process_group == crate::ProcessGrouping::Name {
            format!(" · {groups} group(s)")
        } else {
            String::new()
        };
        let caption = ui.label(
            RichText::new(format!(
                "{} of {} processes{}{}",
                visible.len(),
                processes.len(),
                group_note,
                live_note
            ))
            .size(11.0)
            .color(theme::muted(ui)),
        );
        if let Some(age) = live_age {
            let _ = caption.on_hover_text(format!("Last poll {age}."));
        }
        if let Some(reason) = world.live.as_ref().and_then(|live| live.reason.as_ref()) {
            ui.label(
                RichText::new(format!("This poll could not read every process: {reason}"))
                    .size(11.0)
                    .color(theme::ATTENTION),
            );
        }
        let selected = self
            .selected_process
            .and_then(|pid| processes.iter().find(|process| process.pid == pid));
        let gap = if selected.is_some() { 8.0 } else { 0.0 };
        let footer = if selected.is_some() { PROCESS_FOOTER } else { 0.0 };
        let bottom = if selected.is_some() { BOTTOM_GAP } else { 0.0 };
        let table_height = (ui.available_height() - footer - gap - bottom).max(140.0);
        let body_height = (table_height - TABLE_HEADER).max(80.0);
        let column_space = ui.spacing().item_spacing.x;
        let process_width = (ui.available_width() - 64.0 - 140.0 - 110.0 - 3.0 * column_space).max(180.0);
        let mut clicked = None;
        let mut toggle: Option<String> = None;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), table_height),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_min_height(table_height);
                TableBuilder::new(ui)
                    .id_salt("process-table")
                    .striped(true)
                    .sense(Sense::click())
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                    .max_scroll_height(body_height)
                    .min_scrolled_height(body_height)
                    .column(Column::exact(64.0))
                    .column(Column::exact(process_width).clip(true))
                    .column(Column::exact(140.0).clip(true))
                    .column(Column::exact(110.0))
                    .header(TABLE_HEADER, |mut head| {
                        head.col(|ui| table_header(ui, "PID"));
                        head.col(|ui| table_header(ui, "Process"));
                        head.col(|ui| table_header(ui, "User"));
                        head.col(|ui| table_header(ui, "Started"));
                    })
                    .body(|body| {
                        body.rows(TABLE_ROW, lines.len(), |mut row| match &lines[row.index()] {
                            ProcessLine::Group {
                                key,
                                name,
                                count,
                                shared_path,
                                open,
                            } => {
                                let (_, response) = row.col(|ui| {
                                    ui.label(
                                        RichText::new(format!("×{count}"))
                                            .size(11.0)
                                            .color(theme::muted(ui)),
                                    );
                                });
                                let mut row_clicked = response.clicked();
                                let (_, response) = row.col(|ui| {
                                    let triangle = if *open { "▾" } else { "▸" };
                                    let label = egui::Label::new(
                                        RichText::new(format!("{triangle} {name}"))
                                            .size(11.5)
                                            .family(theme::semibold()),
                                    )
                                    .truncate();
                                    row_clicked |= ui.add(label).clicked();
                                });
                                row_clicked |= response.clicked();
                                let (_, response) = row.col(|ui| {
                                    if let Some(path) = shared_path {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(path.as_str())
                                                    .size(10.5)
                                                    .color(theme::muted(ui)),
                                            )
                                            .truncate(),
                                        );
                                    }
                                });
                                row_clicked |= response.clicked();
                                let (_, response) = row.col(|ui| {
                                    ui.label(RichText::new("").size(11.5));
                                });
                                row_clicked |= response.clicked();
                                if row_clicked || row.response().clicked() {
                                    toggle = Some(key.clone());
                                }
                            }
                            ProcessLine::Process { process, depth } => {
                                row.set_selected(self.selected_process == Some(process.pid));
                                let mut row_clicked = false;
                                let (_, response) = row.col(|ui| {
                                    ui.label(RichText::new(process.pid.to_string()).size(11.5).monospace());
                                });
                                row_clicked |= response.clicked();
                                let (_, response) = row.col(|ui| {
                                    let indent = "   ".repeat(*depth);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("{indent}{}", process.name)).size(11.5),
                                        )
                                        .truncate(),
                                    );
                                });
                                row_clicked |= response.clicked();
                                let (_, response) = row.col(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(process.user.as_deref().unwrap_or("—"))
                                                .size(11.5)
                                                .color(theme::muted(ui)),
                                        )
                                        .truncate(),
                                    );
                                });
                                row_clicked |= response.clicked();
                                let (_, response) = row.col(|ui| {
                                    ui.label(
                                        RichText::new(process.started_at_unix.map_or_else(
                                            || "—".to_owned(),
                                            |then| describe_age(world.now_unix, then),
                                        ))
                                        .size(11.5)
                                        .color(theme::muted(ui)),
                                    );
                                });
                                row_clicked |= response.clicked();
                                if row_clicked || row.response().clicked() {
                                    clicked = Some(process.pid);
                                }
                            }
                        });
                    });
            },
        );
        if let Some(pid) = clicked {
            self.selected_process = Some(pid);
            ui.ctx().request_repaint();
        }
        if let Some(key) = toggle {
            // Opening and closing are one gesture: the set holds what is open, so a key that
            // is already there is a close.
            if !self.process_expanded.remove(&key) {
                self.process_expanded.insert(key);
            }
            ui.ctx().request_repaint();
        }
        if let Some(process) = selected {
            ui.add_space(8.0);
            detail_footer(ui, PROCESS_FOOTER, |ui| {
                process_detail_body(ui, process, world.now_unix);
            });
            ui.add_space(BOTTOM_GAP);
        }
    }

    /// The startup table and its detail footer.
    pub(crate) fn startup(
        &mut self,
        ui: &mut egui::Ui,
        world: &crate::World,
        actions: &mut Vec<crate::Action>,
    ) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(
                ui,
                "No startup items yet",
                "Run a scan to see what starts on its own.",
            );
            return;
        };
        let needle = self.search.trim().to_lowercase();
        let mut rows: Vec<&vnr_core::AutorunFact> = snapshot
            .autoruns
            .iter()
            .filter(|autorun| filter_autorun(autorun, &needle))
            .collect();

        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Scope").size(10.5).color(theme::muted(ui)));
            for (label, value) in [
                ("All", None),
                ("User", Some(AutorunScope::User)),
                ("Machine", Some(AutorunScope::System)),
            ] {
                if widgets::chip(ui, self.autorun_scope == value, label).clicked() {
                    self.autorun_scope = value;
                }
            }
            ui.add_space(10.0);
            ui.checkbox(&mut self.show_disabled, "Show disabled");
            ui.add_space(10.0);
            // The one place this view writes instead of reading. The card it opens names the
            // key the value goes into, and the value is checked before it is written.
            if ui
                .button("Add a startup entry…")
                .on_hover_text(
                    "Register a program to start with this account. Ranger writes one value in \
                     your own Run key and records it in the journal first.",
                )
                .clicked()
            {
                self.startup_add = true;
                self.startup_name.clear();
                self.startup_command.clear();
            }
        });

        rows.retain(|autorun| {
            self.autorun_scope.is_none_or(|scope| autorun.scope == scope)
                && (self.show_disabled || autorun.enabled)
        });
        if !ui.ctx().memory(|memory| memory.focused().is_some()) && !self.palette_open {
            let down =
                ui.input(|input| input.key_pressed(egui::Key::J) || input.key_pressed(egui::Key::ArrowDown));
            let up =
                ui.input(|input| input.key_pressed(egui::Key::K) || input.key_pressed(egui::Key::ArrowUp));
            if down || up {
                let current = rows
                    .iter()
                    .position(|autorun| Some(&autorun.id) == self.selected_autorun.as_ref());
                let next = match current {
                    Some(index) if down => Some((index + 1).min(rows.len().saturating_sub(1))),
                    Some(index) => Some(index.saturating_sub(1)),
                    None if down => Some(0),
                    None => None,
                };
                if let Some(autorun) = next.and_then(|index| rows.get(index)) {
                    self.selected_autorun = Some(autorun.id.clone());
                }
            }
        }
        ui.label(
            RichText::new(format!(
                "{} of {} startup items",
                rows.len(),
                snapshot.autoruns.len()
            ))
            .size(11.0)
            .color(theme::muted(ui)),
        );
        let selected = self
            .selected_autorun
            .as_deref()
            .and_then(|id| snapshot.autoruns.iter().find(|autorun| autorun.id == id));
        let gap = if selected.is_some() { 8.0 } else { 0.0 };
        let footer = if selected.is_some() { STARTUP_FOOTER } else { 0.0 };
        let bottom = if selected.is_some() { BOTTOM_GAP } else { 0.0 };
        let table_height = (ui.available_height() - footer - gap - bottom).max(140.0);
        let body_height = (table_height - TABLE_HEADER).max(80.0);
        let column_space = ui.spacing().item_spacing.x;
        let name_width = (ui.available_width() - 120.0 - 90.0 - 70.0 - 3.0 * column_space).max(180.0);
        let mut clicked = None;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), table_height),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_min_height(table_height);
                TableBuilder::new(ui)
                    .id_salt("startup-table")
                    .striped(true)
                    .sense(Sense::click())
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                    .max_scroll_height(body_height)
                    .min_scrolled_height(body_height)
                    .column(Column::exact(name_width).clip(true))
                    .column(Column::exact(120.0).clip(true))
                    .column(Column::exact(90.0))
                    .column(Column::exact(70.0))
                    .header(TABLE_HEADER, |mut head| {
                        head.col(|ui| table_header(ui, "Name"));
                        head.col(|ui| table_header(ui, "Kind"));
                        head.col(|ui| table_header(ui, "Scope"));
                        head.col(|ui| table_header(ui, "Enabled"));
                    })
                    .body(|body| {
                        body.rows(TABLE_ROW, rows.len(), |mut row| {
                            let autorun = rows[row.index()];
                            row.set_selected(self.selected_autorun.as_deref() == Some(autorun.id.as_str()));
                            let mut row_clicked = false;
                            let (_, response) = row.col(|ui| {
                                ui.add(
                                    egui::Label::new(RichText::new(autorun.name.as_str()).size(11.5))
                                        .truncate(),
                                );
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(autorun.kind.label())
                                            .size(11.5)
                                            .color(theme::muted(ui)),
                                    )
                                    .truncate(),
                                );
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                widgets::badge(ui, autorun.scope.label(), scope_color(autorun.scope));
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.label(
                                    RichText::new(if autorun.enabled { "yes" } else { "no" })
                                        .size(11.5)
                                        .color(theme::muted(ui)),
                                );
                            });
                            row_clicked |= response.clicked();
                            if row_clicked || row.response().clicked() {
                                clicked = Some(autorun.id.clone());
                            }
                        });
                    });
            },
        );
        if let Some(id) = clicked {
            self.selected_autorun = Some(id);
            ui.ctx().request_repaint();
        }
        if let Some(autorun) = selected {
            ui.add_space(8.0);
            let mut open_path = None;
            let mut quarantine = None;
            let mut remove_startup = None;
            detail_footer(ui, STARTUP_FOOTER, |ui| {
                startup_detail_body(
                    ui,
                    autorun,
                    snapshot,
                    &mut open_path,
                    &mut quarantine,
                    &mut remove_startup,
                );
            });
            if let Some(path) = open_path {
                self.open_path = Some(path);
            }
            if let Some(path) = quarantine {
                actions.push(crate::Action::Quarantine(path));
            }
            if let Some(id) = remove_startup {
                self.startup_ask = Some(id);
            }
            ui.add_space(BOTTOM_GAP);
        }
    }

    /// The places ranger knows how to clean, measured and not touched.
    ///
    /// This view has no delete verb on purpose. It answers "how much is there, and what would
    /// ranger keep" — the two questions a person has before they decide to clean anything —
    /// and the removal itself is the existing allowlisted card in Actions, with its totals,
    /// its confirmation and its journal. A second removal path in a second view is how a
    /// security tool grows two answers to one question.
    pub(crate) fn clean(
        &mut self,
        ui: &mut egui::Ui,
        world: &crate::World,
        actions: &mut Vec<crate::Action>,
    ) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("Measure")
                .on_hover_text(
                    "Walk the places ranger is allowed to clean, count what is past the age each \
                     one keeps, and write nothing anywhere.",
                )
                .clicked()
            {
                actions.push(crate::Action::PreviewClean);
            }
            if ui
                .button("Clean in Actions…")
                .on_hover_text(
                    "The removal is the allowlisted card, with the totals on screen and the \
                     journal written first.",
                )
                .clicked()
            {
                actions.push(crate::Action::SetView(crate::View::Actions));
            }
        });
        ui.add_space(6.0);
        let Some(report) = world.clean.as_ref() else {
            ui.label(
                RichText::new(
                    "Nothing has been measured yet. Measure walks the places ranger is allowed to \
                     clean and counts what is past the age each one keeps; it reads names, sizes \
                     and times, and writes nothing.",
                )
                .size(11.5)
                .color(theme::muted(ui)),
            );
            ui.add_space(8.0);
            places_table(ui, None);
            return;
        };
        ui.label(
            RichText::new(format!(
                "Measured {} place(s) in this dry run, {} across {} entries. Nothing was removed \
                 and nothing was recorded.",
                report.surfaces.len(),
                widgets::bytes(measured_totals(report).1),
                measured_totals(report).2
            ))
            .size(11.5)
            .color(theme::muted(ui)),
        );
        ui.add_space(6.0);
        places_table(ui, Some(report));
        if report.cancelled {
            ui.add_space(4.0);
            ui.label(
                RichText::new("The walk stopped before it finished.")
                    .size(11.0)
                    .color(theme::ATTENTION),
            );
        }
    }

    /// The listener table.
    pub(crate) fn listeners(&mut self, ui: &mut egui::Ui, world: &crate::World) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(ui, "No listeners yet", "Run a scan to see what is listening.");
            return;
        };
        ui.checkbox(&mut self.only_public, "Public interfaces only");
        let needle = self.search.trim().to_lowercase();
        let rows: Vec<_> = snapshot
            .listeners
            .iter()
            .filter(|listener| !self.only_public || listener.public)
            .filter(|listener| filter_listener(listener, &needle))
            .collect();
        ui.label(
            RichText::new(format!("{} of {} sockets", rows.len(), snapshot.listeners.len()))
                .size(11.0)
                .color(theme::muted(ui)),
        );
        let table_height = ui.available_height().max(140.0);
        let body_height = (table_height - TABLE_HEADER).max(80.0);
        let column_space = ui.spacing().item_spacing.x;
        let address_width =
            (ui.available_width() - 70.0 - 64.0 - 170.0 - 80.0 - 70.0 - 5.0 * column_space).max(160.0);
        let mut clicked_pid = None;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), table_height),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_min_height(table_height);
                TableBuilder::new(ui)
                    .id_salt("listener-table")
                    .striped(true)
                    .sense(Sense::click())
                    .cell_layout(Layout::left_to_right(Align::Center))
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                    .max_scroll_height(body_height)
                    .min_scrolled_height(body_height)
                    .column(Column::exact(70.0))
                    .column(Column::exact(address_width).clip(true))
                    .column(Column::exact(64.0))
                    .column(Column::exact(170.0).clip(true))
                    .column(Column::exact(80.0))
                    .column(Column::exact(70.0))
                    .header(TABLE_HEADER, |mut head| {
                        head.col(|ui| table_header(ui, "Protocol"));
                        head.col(|ui| table_header(ui, "Address"));
                        head.col(|ui| table_header(ui, "Port"));
                        head.col(|ui| table_header(ui, "Process"));
                        head.col(|ui| table_header(ui, "PID"));
                        head.col(|ui| table_header(ui, "State"));
                    })
                    .body(|body| {
                        body.rows(TABLE_ROW, rows.len(), |mut row| {
                            let listener = rows[row.index()];
                            let mut row_clicked = false;
                            let (_, response) = row.col(|ui| {
                                ui.label(
                                    RichText::new(listener.protocol.label())
                                        .size(11.5)
                                        .family(theme::semibold()),
                                );
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.horizontal(|ui| {
                                    if listener.public {
                                        widgets::badge(ui, "PUBLIC", theme::ATTENTION);
                                    }
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(listener.address.as_str()).size(11.5).monospace(),
                                        )
                                        .truncate(),
                                    );
                                });
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.label(RichText::new(listener.port.to_string()).size(11.5).monospace());
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(listener.process.as_deref().unwrap_or("unknown"))
                                            .size(11.5),
                                    )
                                    .truncate(),
                                );
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.label(
                                    RichText::new(
                                        listener.pid.map_or_else(|| "—".to_owned(), |pid| pid.to_string()),
                                    )
                                    .size(11.5)
                                    .color(theme::muted(ui)),
                                );
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.label(
                                    RichText::new(listener.state.as_str())
                                        .size(11.5)
                                        .color(theme::muted(ui)),
                                );
                            });
                            row_clicked |= response.clicked();
                            if row_clicked || row.response().clicked() {
                                clicked_pid = listener.pid;
                            }
                        });
                    });
            },
        );
        if let Some(pid) = clicked_pid {
            self.selected_process = Some(pid);
            self.view = View::Processes;
            self.search.clear();
            ui.ctx().request_repaint();
        }
    }

    /// The report surface.
    /// The session timeline and the difference from the accepted baseline.
    pub(crate) fn changes(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        let mut accept = false;
        let mut clear = false;
        let mut clear_timeline = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Source").size(10.5).color(theme::muted(ui)));
            for filter in ChangeFilter::ALL {
                if widgets::chip(ui, self.change_filter == filter, filter.label()).clicked() {
                    self.change_filter = filter;
                }
            }
        });
        ui.add_space(8.0);
        let filter = self.change_filter;
        let changes: Vec<&vnr_core::Change> = world
            .changes
            .iter()
            .filter(|change| change_matches(filter, &change.source))
            .collect();
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Since the baseline").family(theme::semibold()));
                if world.baseline.is_some() {
                    widgets::badge(ui, "ACCEPTED", theme::OK);
                }
            });
            ui.add_space(4.0);
            match &world.baseline {
                None => {
                    if let Some(error) = &world.baseline_error {
                        ui.label(RichText::new(error.as_str()).size(11.5).color(theme::ATTENTION));
                    } else {
                        ui.label(
                            RichText::new(
                                "No baseline yet. Accepting the current scan records this machine as normal today, so a later scan can say what changed. Ranger does not accept one on its own.",
                            )
                            .size(11.5)
                            .color(theme::muted(ui)),
                        );
                    }
                    ui.add_space(6.0);
                    if world.snapshot().is_some() {
                        accept = ui.button("Accept this scan as the baseline").clicked();
                    } else {
                        ui.label(
                            RichText::new("Run a scan first; there is nothing to accept yet.")
                                .size(11.0)
                                .color(theme::muted(ui)),
                        );
                    }
                }
                Some(baseline) => {
                    widgets::key_value(ui, "Accepted", &format_utc(baseline.taken_at_unix));
                    ui.add_space(6.0);
                    if changes.is_empty() {
                        ui.label(
                            RichText::new(if filter == ChangeFilter::All {
                                "No difference from the baseline in this scan. That is a statement about the lists ranger reads, not a verdict about the machine."
                            } else {
                                "No difference from the baseline in this source. Choose another source to see the rest."
                            })
                            .size(11.5)
                            .color(theme::muted(ui)),
                        );
                    } else {
                        ui.label(
                            RichText::new(format!("{} difference(s) from the baseline", changes.len()))
                                .size(11.5),
                        );
                        ui.add_space(4.0);
                        const SHOWN: usize = 200;
                        for change in changes.iter().take(SHOWN) {
                            change_row(ui, change);
                        }
                        if changes.len() > SHOWN {
                            ui.label(
                                RichText::new(format!(
                                    "Showing the first {SHOWN} of {} differences.",
                                    changes.len()
                                ))
                                .size(10.5)
                                .color(theme::muted(ui)),
                            );
                        }
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        accept = ui.button("Accept this scan as the new baseline").clicked();
                        clear = ui.button("Clear the baseline").clicked();
                    });
                }
            }
        });
        ui.add_space(10.0);
        let events: Vec<&vnr_core::TimelineEvent> = world
            .timeline
            .iter()
            .rev()
            .filter(|event| change_matches(filter, &event.source))
            .collect();
        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("This session").family(theme::semibold()));
                widgets::badge(ui, &format!("{} EVENT(S)", events.len()), theme::muted(ui));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !world.timeline.is_empty() && ui.button("Clear").clicked() {
                        clear_timeline = true;
                    }
                });
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "The two-second process poll and the file watchers write here. The list is held in memory, so closing ranger clears it.",
                )
                .size(11.0)
                .color(theme::muted(ui)),
            );
            ui.add_space(6.0);
            if events.is_empty() {
                let (title, body) = if filter != ChangeFilter::All {
                    (
                        "Nothing from this source",
                        "No event from the chosen source has been recorded. Choose another source or All.",
                    )
                } else if world.poll_enabled || world.watch.enabled {
                    (
                        "Nothing has changed yet",
                        "Ranger is watching. A process that starts, or a file that appears in a watched folder, will be listed here.",
                    )
                } else {
                    (
                        "Watching is switched off",
                        "Both the process poll and the file watcher are off in Settings, so this list cannot grow.",
                    )
                };
                widgets::empty(ui, title, body);
            } else {
                const SHOWN: usize = 200;
                for event in events.iter().take(SHOWN) {
                    event_row(ui, event);
                }
                if events.len() > SHOWN {
                    ui.label(
                        RichText::new(format!("Showing the newest {SHOWN} of {} events.", events.len()))
                            .size(10.5)
                            .color(theme::muted(ui)),
                    );
                }
            }
        });
        if clear_timeline {
            actions.push(Action::ClearTimeline);
        }
        if accept {
            actions.push(Action::AcceptBaseline);
        }
        if clear {
            actions.push(Action::ClearBaseline);
        }
    }

    /// Export and read the scan.
    pub(crate) fn report(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(ui, "No report yet", "Run a scan first.");
            return;
        };
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Export").family(theme::semibold()));
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "JSON is the complete snapshot. Markdown is the same report a person can read.",
                )
                .size(11.5)
                .color(theme::muted(ui)),
            );
            ui.horizontal(|ui| {
                if ui.button("Export JSON").clicked() {
                    actions.push(Action::ExportJson);
                }
                if ui.button("Export Markdown").clicked() {
                    actions.push(Action::ExportMarkdown);
                }
                if ui.button("Export findings (JSON)").clicked() {
                    actions.push(Action::ExportFindingsJson);
                }
                if ui
                    .button("Write a triage folder")
                    .on_hover_text(
                        "One folder with the snapshot, the findings, the timeline and a manifest \
                         that names the hash of every file in it. Nothing leaves this machine.",
                    )
                    .clicked()
                {
                    actions.push(Action::ExportTriage);
                }
                if ui.button("Open data folder").clicked() {
                    actions.push(Action::OpenDataDir);
                }
            });
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("This scan").family(theme::semibold()));
            ui.add_space(4.0);
            widgets::key_value(ui, "Generated", &format_utc(snapshot.taken_at_unix));
            widgets::key_value(ui, "Duration", &format!("{} ms", snapshot.duration_ms));
            widgets::key_value(ui, "Elevated", if snapshot.elevated { "yes" } else { "no" });
            widgets::key_value(
                ui,
                "Host",
                &format!("{} {}", snapshot.host.os, snapshot.host.version),
            );
            widgets::key_value(ui, "Data", &world.data_dir.display().to_string());
        });
    }

    /// Preferences, elevation and privacy.
    /// The rule packs: which one is loaded, what is installed, and the keys trusted.
    pub(crate) fn packs(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        let packs = &world.packs;
        if let Some(error) = &packs.error {
            widgets::card(ui, |ui| {
                ui.label(RichText::new("The last pack action failed").family(theme::semibold()));
                ui.add_space(4.0);
                ui.label(RichText::new(error.as_str()).size(11.5).color(theme::ATTENTION));
            });
            ui.add_space(10.0);
        }

        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Loaded pack").family(theme::semibold()));
                if packs.active.is_some() {
                    widgets::badge(ui, "ACTIVE", theme::OK);
                }
            });
            ui.add_space(4.0);
            match &packs.active {
                Some(active) => {
                    ui.label(
                        RichText::new(format!("{} · {}", active.id, active.version))
                            .size(12.5)
                            .family(theme::semibold()),
                    );
                    ui.label(
                        RichText::new(format!("{} · {} rules", active.title, active.rules))
                            .size(11.0)
                            .color(theme::muted(ui)),
                    );
                    ui.add_space(2.0);
                    match &packs.signed_by {
                        Some(fingerprint) => {
                            widgets::key_value(ui, "Signed by", fingerprint);
                        }
                        None => {
                            widgets::dot_line(
                                ui,
                                theme::OK,
                                "Built into ranger: the bytes travel with the build, not a file on disk.",
                            );
                        }
                    }
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let rollback = ui.add_enabled(
                            packs.can_roll_back,
                            egui::Button::new("Roll back to the previous pack"),
                        );
                        if rollback.clicked() {
                            actions.push(Action::RollbackPack);
                        }
                        if !packs.can_roll_back {
                            rollback.on_hover_text("No previous pack is recorded on this machine yet.");
                        }
                        if ui.button("Use the pack built into ranger").clicked() {
                            actions.push(Action::ActivateEmbeddedPack);
                        }
                    });
                }
                None => {
                    ui.label(
                        RichText::new(
                            "No pack is loaded, so only the built-in rules are running. That is what this data folder says, not an error: nothing was read on ranger's behalf while no record was active.",
                        )
                        .size(11.0)
                        .color(theme::muted(ui)),
                    );
                    if ui.button("Load the pack built into ranger").clicked() {
                        actions.push(Action::ActivateEmbeddedPack);
                    }
                }
            }
        });
        ui.add_space(10.0);

        widgets::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Packs in this folder").family(theme::semibold()));
                if ui.small_button("Read again").clicked() {
                    actions.push(Action::RefreshPacks);
                }
            });
            ui.add_space(4.0);
            if packs.installed.is_empty() {
                ui.label(
                    RichText::new(
                        "No pack files were found. Ranger looked for *.json with a *.minisig beside it in the folder below.",
                    )
                    .size(11.0)
                    .color(theme::muted(ui)),
                );
            } else {
                for pack in &packs.installed {
                    widgets::border(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(format!("{} · {}", pack.id, pack.version))
                                        .size(11.5)
                                        .family(theme::semibold()),
                                );
                                ui.label(RichText::new(&pack.status).size(10.5).color(if pack.signed {
                                    theme::OK
                                } else {
                                    theme::muted(ui)
                                }));
                                if !pack.path.is_empty() {
                                    widgets::path(ui, &pack.path);
                                }
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if pack.active {
                                    widgets::badge(ui, "ACTIVE", theme::OK);
                                } else if ui.button("Use this pack").clicked() {
                                    actions.push(Action::ActivatePack(pack.path.clone()));
                                }
                            });
                        });
                    });
                }
            }
            ui.add_space(2.0);
            ui.label(
                RichText::new("Packs are read from")
                    .size(10.5)
                    .color(theme::muted(ui)),
            );
            widgets::path(ui, &packs.directory);
            ui.horizontal(|ui| {
                if ui.button("Open the packs folder").clicked() {
                    actions.push(Action::OpenPath(packs.directory.clone()));
                }
                ui.label(
                    RichText::new("A pack is one .json file and its .minisig; never an archive.")
                        .size(10.5)
                        .color(theme::muted(ui)),
                );
            });
        });
        ui.add_space(10.0);

        widgets::card(ui, |ui| {
            ui.label(RichText::new("Keys ranger trusts").family(theme::semibold()));
            ui.add_space(4.0);
            if packs.keys.is_empty() {
                ui.label(
                    RichText::new(
                        "No key is trusted, so an imported pack cannot be loaded yet. Ranger checked packs/keys.json and found no keys in it.",
                    )
                    .size(11.0)
                    .color(theme::muted(ui)),
                );
            } else {
                for key in &packs.keys {
                    widgets::border(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(&key.fingerprint)
                                        .size(11.5)
                                        .monospace()
                                        .family(theme::semibold()),
                                );
                                ui.label(
                                    RichText::new(format!(
                                        "Added {} · {} pack(s) installed with this key",
                                        key.added, key.packs
                                    ))
                                    .size(10.5)
                                    .color(theme::muted(ui)),
                                );
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Stop trusting").clicked() {
                                    actions.push(Action::RemovePackKey(key.fingerprint.clone()));
                                }
                            });
                        });
                    });
                }
            }
            ui.add_space(6.0);
            ui.label(RichText::new("Trust a key").size(11.0).family(theme::semibold()));
            ui.label(
                RichText::new(
                    "Paste the author's minisign public key, type the fingerprint they gave you, and compare the two. A key trusted here signs every pack ranger will load with it.",
                )
                .size(10.5)
                .color(theme::muted(ui)),
            );
            ui.add(
                egui::TextEdit::multiline(&mut self.pack_public)
                    .hint_text("The minisign public key")
                    .desired_width(f32::INFINITY)
                    .desired_rows(2)
                    .font(egui::TextStyle::Monospace)
                    .margin(egui::Margin::symmetric(8, 5)),
            );
            ui.horizontal(|ui| {
                ui.add_sized(
                    egui::vec2(200.0, 24.0),
                    egui::TextEdit::singleline(&mut self.pack_print)
                        .hint_text("Fingerprint, as typed")
                        .font(egui::TextStyle::Monospace)
                        .margin(egui::Margin::symmetric(8, 5)),
                );
                let ready = !self.pack_public.trim().is_empty() && !self.pack_print.trim().is_empty();
                if ui
                    .add_enabled(ready, egui::Button::new("Trust this key"))
                    .clicked()
                {
                    actions.push(Action::AddPackKey {
                        public: self.pack_public.trim().to_owned(),
                        fingerprint: self.pack_print.trim().to_owned(),
                    });
                    self.pack_public.clear();
                    self.pack_print.clear();
                }
                ui.label(
                    RichText::new("The key is refused when the fingerprint does not match.")
                        .size(10.5)
                        .color(theme::muted(ui)),
                );
            });
        });
    }

    pub(crate) fn settings(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Privacy").family(theme::semibold()));
            ui.add_space(4.0);
            ui.label(
                RichText::new("No network. No telemetry. Everything ranger saw stays on this machine.")
                    .size(11.5),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Every count is a fact read from this machine, and none of it is sent anywhere. There is no update check, no account and no request of any kind: the only files ranger writes are the ones listed below, and the only folder it reads by name is its own.",
                )
                .size(11.0)
                .color(theme::muted(ui)),
            );
            ui.add_space(6.0);
            ui.label(RichText::new("Data folder").size(10.5).color(theme::muted(ui)));
            widgets::path(ui, &world.data_dir.display().to_string());
            if ui.button("Open the data folder").clicked() {
                actions.push(Action::OpenPath(world.data_dir.display().to_string()));
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Appearance").family(theme::semibold()));
            if ui.checkbox(&mut self.dark, "Dark theme").changed() {
                actions.push(Action::SetDark(self.dark));
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Watching").family(theme::semibold()));
            ui.add_space(4.0);
            let mut poll = world.poll_enabled;
            if ui
                .checkbox(&mut poll, "Poll running processes every two seconds")
                .changed()
            {
                actions.push(Action::SetPoll(poll));
            }
            let mut watch = world.watch.enabled;
            if ui
                .checkbox(
                    &mut watch,
                    "Watch Downloads, Desktop, the temporary and startup folders",
                )
                .changed()
            {
                actions.push(Action::SetWatch(watch));
            }
            let mut led = world.poll_led;
            if ui
                .checkbox(&mut led, "Show the live poll indicator in the top bar")
                .changed()
            {
                actions.push(Action::SetPollLed(led));
            }
            ui.label(
                RichText::new("These switches are kept in settings.json in the data folder.")
                    .size(10.5)
                    .color(theme::muted(ui)),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Extra watched folders")
                    .size(10.5)
                    .color(theme::muted(ui)),
            );
            for root in &world.watch_extra {
                ui.horizontal(|ui| {
                    ui.add(egui::Label::new(RichText::new(root.as_str()).size(10.5).monospace()).truncate());
                    if ui.small_button("Remove").clicked() {
                        actions.push(Action::RemoveWatchRoot(root.clone()));
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.watch_new)
                        .hint_text("A folder to watch")
                        .desired_width(240.0)
                        .margin(egui::Margin::symmetric(8, 4)),
                );
                if ui.button("Add folder").clicked() && !self.watch_new.trim().is_empty() {
                    actions.push(Action::AddWatchRoot(self.watch_new.trim().to_owned()));
                    self.watch_new.clear();
                }
            });
            if let Some(reason) = world.live.as_ref().and_then(|live| live.reason.as_ref()) {
                ui.label(
                    RichText::new(format!("The last process poll was incomplete: {reason}"))
                        .size(11.0)
                        .color(theme::ATTENTION),
                );
            }
            if world.watch.enabled {
                if let Some(error) = &world.watch.error {
                    ui.label(
                        RichText::new(format!("The file watcher could not start: {error}"))
                            .size(11.0)
                            .color(theme::ATTENTION),
                    );
                } else if world.watch.roots.is_empty() {
                    ui.label(
                        RichText::new("The file watcher is starting.")
                            .size(11.0)
                            .color(theme::muted(ui)),
                    );
                } else {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Reading the top level of:")
                            .size(10.5)
                            .color(theme::muted(ui)),
                    );
                    for root in &world.watch.roots {
                        widgets::path(ui, root);
                    }
                    for skipped in &world.watch.skipped {
                        ui.label(
                            RichText::new(format!("Not watched — {skipped}"))
                                .size(10.5)
                                .color(theme::muted(ui)),
                        );
                    }
                }
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            let content = &world.content;
            ui.horizontal(|ui| {
                ui.label(RichText::new("Reading file contents").family(theme::semibold()));
                if content.available {
                    widgets::badge(ui, "AVAILABLE", theme::OK);
                } else {
                    widgets::badge(ui, "NOT IN THIS BUILD", theme::muted(ui));
                }
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(content.sentence.as_str())
                    .size(11.0)
                    .color(theme::muted(ui)),
            );
            ui.add_space(4.0);
            if !content.available {
                ui.label(
                    RichText::new(
                        "Everything else ranger does reads names, paths and hashes. Reading bytes is a feature this build was not compiled with, so there is nothing here to turn on.",
                    )
                    .size(10.5)
                    .color(theme::muted(ui)),
                );
            } else {
                ui.horizontal(|ui| {
                    let button = ui.add_enabled(
                        !content.running,
                        egui::Button::new("Read the contents of those folders"),
                    );
                    if button.clicked() {
                        actions.push(Action::RunContentScan);
                    }
                    if content.running {
                        ui.spinner();
                        ui.label(RichText::new("Reading…").size(11.0).color(theme::muted(ui)));
                    }
                });
                if let Some(report) = &content.report {
                    ui.add_space(4.0);
                    if let Some(problem) = &report.problem {
                        ui.label(RichText::new(problem.as_str()).size(11.0).color(theme::ATTENTION));
                    } else {
                        ui.label(
                            RichText::new(format!(
                                "{} file(s) were read; {} matched a rule; {} were skipped and nothing was stored.",
                                report.files,
                                report.hits.len(),
                                report.skipped
                            ))
                            .size(11.0),
                        );
                        for line in &report.hits {
                            widgets::dot_line(ui, theme::ATTENTION, line);
                        }
                    }
                }
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            let deep = &world.deep;
            ui.horizontal(|ui| {
                ui.label(RichText::new("Deep check").family(theme::semibold()));
                widgets::badge(ui, "READS BYTES", theme::ATTENTION);
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(deep.sentence.as_str())
                    .size(11.0)
                    .color(theme::muted(ui)),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if deep.running {
                    if ui.button("Stop").clicked() {
                        actions.push(Action::CancelDeepCheck);
                    }
                    ui.spinner();
                    ui.label(
                        RichText::new(if deep.cancelling {
                            "Stopping after this file…"
                        } else {
                            "Reading…"
                        })
                        .size(11.0)
                        .color(theme::muted(ui)),
                    );
                } else {
                    let button = ui.add(egui::Button::new("Run the deep check"));
                    if button.clicked() {
                        actions.push(Action::RunDeepCheck);
                    }
                    ui.label(
                        RichText::new("It never runs on its own, and it writes no journal line per file.")
                            .size(10.5)
                            .color(theme::muted(ui)),
                    );
                }
            });
            if let Some(summary) = &deep.summary {
                ui.add_space(4.0);
                let files = if summary.files == 1 { "file" } else { "files" };
                let matched = if summary.matched == 1 {
                    "1 matched a signature".to_owned()
                } else {
                    format!("{} matched a signature", summary.matched)
                };
                ui.label(
                    RichText::new(format!(
                        "{} {files} hashed, {} read, {} in {} ms; {matched}; {} could not be read.",
                        summary.files,
                        summary.read,
                        widgets::bytes(summary.bytes),
                        summary.elapsed_ms,
                        summary.refused
                    ))
                    .size(11.0),
                );
                if summary.cancelled {
                    ui.label(
                        RichText::new(
                            "This check was stopped, so it says nothing about the files it had not reached.",
                        )
                        .size(10.5)
                        .color(theme::ATTENTION),
                    );
                }
                if summary.truncated {
                    ui.label(
                        RichText::new("A limit stopped it: the folders hold more than one check reads. Nothing was skipped silently — the count is the limit.")
                            .size(10.5)
                            .color(theme::ATTENTION),
                    );
                }
                if summary.signatures == 0 {
                    ui.label(
                        RichText::new(
                            "No .ndb body signatures were loaded, so this check looked for hashes only.",
                        )
                        .size(10.5)
                        .color(theme::muted(ui)),
                    );
                } else {
                    ui.label(
                        RichText::new(format!(
                            "{} body signature(s) loaded, {} line(s) refused.",
                            summary.signatures, summary.signature_refusals
                        ))
                        .size(10.5)
                        .color(theme::muted(ui)),
                    );
                }
            }
            for note in &deep.notes {
                widgets::dot_line(ui, theme::muted(ui), note);
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Elevation").family(theme::semibold()));
            ui.add_space(4.0);
            if world.elevated {
                widgets::dot_line(ui, theme::OK, "This window is running with administrator rights.");
            } else {
                widgets::dot_line(
                    ui,
                    theme::muted(ui),
                    "This window is running as the signed-in user.",
                );
            }
            ui.label(
                RichText::new(
                    "An administrator scan can read services, other users' startup items and sockets that a standard account cannot. Windows asks for consent; the elevated copy writes one report and exits. It does not stay open and it does not delete anything.",
                )
                .size(11.5)
                .color(theme::muted(ui)),
            );
            let response = ui.add_enabled(
                world.can_elevate && !world.busy(),
                egui::Button::new(RichText::new("Run an administrator scan").color(theme::ON_EMBER))
                    .fill(theme::EMBER),
            );
            if response.clicked() {
                self.confirm_elevate = true;
            }
            if !world.can_elevate {
                ui.label(
                    RichText::new("Administrator scans are not implemented on this platform yet.")
                        .size(11.0)
                        .color(theme::muted(ui)),
                );
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Signatures").family(theme::semibold()));
            ui.add_space(4.0);
            let (loaded, algorithms) = world.snapshot().map_or((0, Vec::new()), |snapshot| {
                (snapshot.signatures.loaded, snapshot.signatures.algorithms.clone())
            });
            ui.label(
                RichText::new(format!(
                    "{} signature(s) loaded{}.",
                    loaded,
                    if algorithms.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", algorithms.join(", "))
                    }
                ))
                .size(11.5)
                .color(theme::muted(ui)),
            );
            ui.label(
                RichText::new(
                    "Drop ClamAV-format .hdb or .hsb files into the signatures folder. They are read locally; nothing is downloaded.",
                )
                .size(11.0)
                .color(theme::muted(ui)),
            );
            ui.horizontal(|ui| {
                if ui.button("Self-test").clicked() {
                    actions.push(Action::SelfTest);
                }
                if ui.button("Open signatures folder").clicked() {
                    actions.push(Action::OpenSignaturesDir);
                }
            });
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Suppressions").family(theme::semibold()));
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("{} active suppression(s).", world.suppressions.len())).size(11.5),
            );
            ui.label(
                RichText::new(
                    "A suppression covers one rule and one subject, carries a reason, and expires after 30 days. There is no ignore-everything switch.",
                )
                .size(10.5)
                .color(theme::muted(ui)),
            );
            if !world.suppressions.is_empty() && ui.button("Clear all suppressions").clicked() {
                actions.push(Action::ClearSuppressions);
            }
            if !world.suppressions.is_empty() {
                ui.add_space(4.0);
                for suppression in &world.suppressions {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("{} · {}", suppression.rule_id, suppression.subject))
                                    .size(10.5)
                                    .color(theme::muted(ui)),
                            )
                            .truncate(),
                        );
                        if ui.small_button("Remove").clicked() {
                            actions.push(Action::RemoveSuppression {
                                rule_id: suppression.rule_id.clone(),
                                subject: suppression.subject.clone(),
                            });
                        }
                    });
                    ui.label(
                        RichText::new(format!(
                            "{} — until {}",
                            suppression.reason,
                            format_utc(suppression.expires_unix)
                        ))
                        .size(10.0)
                        .color(theme::muted(ui)),
                    );
                    ui.add_space(4.0);
                }
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Residency").family(theme::semibold()));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let (button, hint) = if world.paused {
                    (
                        "Resume scheduled scans",
                        "Scheduled scans are postponed. Nothing runs on its own until you resume or scan now.",
                    )
                } else {
                    (
                        "Pause for an hour",
                        "Scheduled scans run on their own; this postpones the next one by an hour.",
                    )
                };
                if ui.button(button).clicked() {
                    actions.push(Action::PauseScan);
                }
                ui.add(
                    egui::Label::new(RichText::new(hint).size(10.5).color(theme::muted(ui)))
                        .wrap(),
                );
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(world.tray.sentence())
                    .size(10.5)
                    .color(theme::muted(ui)),
            );
            ui.add_space(4.0);
            let has_tray = matches!(world.tray, TrayState::Present);
            let mut close_to_tray = world.close_to_tray;
            if ui
                .add_enabled(
                    has_tray,
                    egui::Checkbox::new(
                        &mut close_to_tray,
                        RichText::new("Hide the window to the tray when I close it").size(11.0),
                    ),
                )
                .on_hover_text(
                    "Off by default. When it is on, the tray icon brings the window back and \
                     the journal records each time it is hidden.",
                )
                .changed()
            {
                actions.push(Action::SetCloseToTray(close_to_tray));
            }
            if !has_tray {
                ui.label(
                    RichText::new("With no tray there is nowhere to hide, so closing quits.")
                        .size(10.5)
                        .color(theme::muted(ui)),
                );
            }
            ui.add_space(6.0);
            let mut autostart = world.autostart.is_on();
            let can_start = !matches!(world.autostart, crate::AutostartState::Unavailable(_));
            if ui
                .add_enabled(
                    can_start,
                    egui::Checkbox::new(
                        &mut autostart,
                        RichText::new("Start ranger when I log in").size(11.0),
                    ),
                )
                .on_hover_text(
                    "Off by default. Ranger writes one entry of its own — a registry value, a \
                     LaunchAgent or a desktop file — shows you where it is, and removes only \
                     that entry.",
                )
                .changed()
            {
                actions.push(Action::SetAutostart(autostart));
            }
            ui.label(
                RichText::new(world.autostart.sentence())
                    .size(10.5)
                    .color(theme::muted(ui)),
            );
            ui.add_space(6.0);
            let mut skip = world.skip_on_battery;
            if ui
                .checkbox(
                    &mut skip,
                    RichText::new("Wait while the machine is on battery").size(11.0),
                )
                .on_hover_text(
                    "Off by default. The scheduled scan is the only thing that waits; a scan \
                     you ask for always runs.",
                )
                .changed()
            {
                actions.push(Action::SetSkipOnBattery(skip));
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Privacy").family(theme::semibold()));
            ui.add_space(4.0);
            widgets::dot_line(
                ui,
                theme::OK,
                "No network. No telemetry. No account. Everything ranger saw stays on this machine.",
            );
            widgets::key_value(ui, "Data folder", &world.data_dir.display().to_string());
            widgets::key_value(ui, "Signatures", &world.signatures_dir.display().to_string());
            if ui.button("Open data folder").clicked() {
                actions.push(Action::OpenDataDir);
            }
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("About").family(theme::semibold()));
            ui.label(
                RichText::new(format!(
                    "vn-ranger {} · MIT · Rust and egui, no webview.",
                    world.version
                ))
                .size(11.5)
                .color(theme::muted(ui)),
            );
            ui.label(
                RichText::new(
                    "Not an antivirus. It shows what runs, what persists and what changed, and it says what it cannot see.",
                )
                .size(11.0)
                .color(theme::muted(ui)),
            );
            if ui.button("Quit ranger").clicked() {
                actions.push(Action::Quit);
            }
        });
    }
}

fn signature_matches_card(ui: &mut egui::Ui, snapshot: &Snapshot) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::badge(ui, "SIGNATURE MATCH", theme::BAD);
            ui.label(
                RichText::new(format!(
                    "{} file(s) matched a local signature",
                    snapshot.signatures.matches.len()
                ))
                .size(12.5)
                .family(theme::semibold()),
            );
        });
        ui.add_space(4.0);
        for hit in snapshot.signatures.matches.iter().take(5) {
            ui.label(RichText::new(format!("{} · {}", hit.name, hit.path)).size(11.5));
        }
        if snapshot.signatures.matches.len() > 5 {
            ui.label(
                RichText::new(format!("and {} more", snapshot.signatures.matches.len() - 5))
                    .size(11.5)
                    .color(theme::muted(ui)),
            );
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "A hash match is a fact about a file, not a diagnosis of the machine. Quarantine and removal arrive in v0.1.4.",
            )
            .size(11.0)
            .color(theme::muted(ui)),
        );
    });
}

fn signature_card(ui: &mut egui::Ui, snapshot: &Snapshot, actions: &mut Vec<Action>) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Local signature database").family(theme::semibold()));
            widgets::badge(ui, &format!("{} LOADED", snapshot.signatures.loaded), theme::OK);
        });
        ui.label(
            RichText::new(if snapshot.signatures.algorithms.is_empty() {
                "No algorithms loaded.".to_owned()
            } else {
                format!(
                    "Hash signatures: {}. The built-in EICAR test signature is always present.",
                    snapshot.signatures.algorithms.join(", ")
                )
            })
            .size(11.5)
            .color(theme::muted(ui)),
        );
        for note in snapshot.signatures.notes.iter().take(2) {
            ui.label(RichText::new(note.as_str()).size(11.0).color(theme::muted(ui)));
        }
        ui.horizontal(|ui| {
            if ui.button("Self-test").clicked() {
                actions.push(Action::SelfTest);
            }
            if ui.button("Open signatures folder").clicked() {
                actions.push(Action::OpenSignaturesDir);
            }
        });
    });
}

/// How many entries a dry run counted and how much they weigh.
///
/// One place decides what "the total" means, so the sentence over the table and any later
/// summary cannot disagree about a number a person uses to decide whether to clean.
fn measured_totals(report: &crate::world::CleanReport) -> (usize, u64, usize) {
    let bytes = report
        .surfaces
        .iter()
        .map(crate::world::CleanSurface::bytes)
        .sum();
    let entries = report
        .surfaces
        .iter()
        .map(crate::world::CleanSurface::entries)
        .sum();
    (report.surfaces.len(), bytes, entries)
}

/// Every place ranger is allowed to clean, measured or not.
///
/// The table is the allowlist, not the measurement: a place that was not measured still
/// appears, so "nothing here" and "not looked at" are different rows rather than the same
/// silence.
fn places_table(ui: &mut egui::Ui, report: Option<&crate::world::CleanReport>) {
    egui::Grid::new("clean-places")
        .num_columns(5)
        .spacing([16.0, 6.0])
        .striped(true)
        .show(ui, |ui| {
            for header in ["Place", "Used by", "Entries", "Size", "Kept"] {
                ui.label(
                    RichText::new(header)
                        .size(10.5)
                        .color(theme::muted(ui))
                        .family(theme::semibold()),
                );
            }
            ui.end_row();
            for surface in vnr_core::action::Surface::ALL {
                let measured = report.and_then(|report| {
                    report
                        .surfaces
                        .iter()
                        .find(|measured| measured.id == surface.id())
                });
                ui.label(RichText::new(surface.label()).size(11.5));
                ui.label(
                    RichText::new(match measured {
                        Some(measured) => format!("{} folder(s)", measured.roots),
                        None if report.is_some() => "none here".to_owned(),
                        None => "not measured".to_owned(),
                    })
                    .size(11.0)
                    .color(theme::muted(ui)),
                );
                ui.label(
                    RichText::new(match measured {
                        Some(measured) => measured.entries().to_string(),
                        None => "—".to_owned(),
                    })
                    .size(11.0)
                    .monospace(),
                );
                ui.label(
                    RichText::new(match measured {
                        Some(measured) => widgets::bytes(measured.bytes()),
                        None => "—".to_owned(),
                    })
                    .size(11.0)
                    .monospace(),
                );
                ui.label(
                    RichText::new(match measured {
                        Some(measured) => format!(
                            "{} young, {} links, {} other volume",
                            measured.skipped_young, measured.skipped_links, measured.skipped_devices
                        ),
                        None => "—".to_owned(),
                    })
                    .size(10.5)
                    .color(theme::muted(ui)),
                );
                ui.end_row();
            }
        });
}

fn startup_preview(ui: &mut egui::Ui, snapshot: &Snapshot) {
    widgets::card(ui, |ui| {
        ui.label(RichText::new("Startup items").family(theme::semibold()));
        ui.add_space(4.0);
        if snapshot.autoruns.is_empty() {
            ui.label(RichText::new("None visible.").size(11.5).color(theme::muted(ui)));
        }
        for autorun in snapshot.autoruns.iter().take(6) {
            ui.horizontal(|ui| {
                widgets::badge(ui, autorun.scope.label(), scope_color(autorun.scope));
                ui.add(egui::Label::new(RichText::new(autorun.name.as_str()).size(11.5)).truncate());
            });
        }
    });
}

fn listener_preview(ui: &mut egui::Ui, snapshot: &Snapshot) {
    widgets::card(ui, |ui| {
        ui.label(RichText::new("Listening on all interfaces").family(theme::semibold()));
        ui.add_space(4.0);
        let public: Vec<_> = snapshot
            .listeners
            .iter()
            .filter(|listener| listener.public)
            .collect();
        if public.is_empty() {
            ui.label(
                RichText::new("Nothing is bound to a public interface.")
                    .size(11.5)
                    .color(theme::muted(ui)),
            );
        }
        for listener in public.iter().take(6) {
            ui.horizontal(|ui| {
                widgets::badge(ui, listener.protocol.label(), theme::ATTENTION);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{}:{} · {}",
                            listener.address,
                            listener.port,
                            listener.process.as_deref().unwrap_or("unknown")
                        ))
                        .size(11.0)
                        .monospace(),
                    )
                    .truncate(),
                );
            });
        }
    });
}

fn collectors_card(ui: &mut egui::Ui, snapshot: &Snapshot) {
    widgets::card(ui, |ui| {
        ui.label(RichText::new("What was checked").family(theme::semibold()));
        ui.add_space(4.0);
        for status in &snapshot.collectors {
            ui.horizontal(|ui| {
                widgets::health(ui, status.state);
                ui.add_sized(
                    [180.0, 18.0],
                    egui::Label::new(RichText::new(status.label.as_str()).size(11.5)),
                );
                ui.label(
                    RichText::new(status.items.to_string())
                        .size(11.0)
                        .color(theme::muted(ui)),
                );
            });
            if let Some(reason) = &status.reason {
                ui.label(RichText::new(reason.as_str()).size(11.0).color(theme::muted(ui)));
            }
        }
    });
}

fn detail_footer(ui: &mut egui::Ui, height: f32, add: impl FnOnce(&mut egui::Ui)) {
    let inner_height = (height - 28.0).max(80.0);
    egui::Frame::new()
        .fill(theme::surface(ui))
        .stroke(egui::Stroke::new(1.0, theme::border(ui)))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(inner_height);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                .max_height(inner_height)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    add(ui);
                });
        });
}

fn process_detail_body(ui: &mut egui::Ui, process: &ProcessFact, now: u64) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(process.name.as_str())
                .size(14.0)
                .family(theme::semibold()),
        );
        widgets::badge(ui, &format!("PID {}", process.pid), theme::EMBER);
    });
    ui.add_space(4.0);
    widgets::key_value(ui, "Path", process.exe.as_deref().unwrap_or("not visible"));
    widgets::key_value(ui, "Command", process.command.as_deref().unwrap_or("not visible"));
    ui.columns(3, |columns| {
        widgets::key_value(&mut columns[0], "User", process.user.as_deref().unwrap_or("—"));
        widgets::key_value(
            &mut columns[1],
            "Parent",
            &process
                .parent
                .map_or_else(|| "—".to_owned(), |pid| pid.to_string()),
        );
        widgets::key_value(
            &mut columns[2],
            "Started",
            &process
                .started_at_unix
                .map_or_else(|| "—".to_owned(), |then| describe_age(now, then)),
        );
    });
    if let Some(path) = &process.exe
        && ui.button("Copy path").clicked()
    {
        ui.ctx().copy_text(path.clone());
    }
}

fn startup_detail_body(
    ui: &mut egui::Ui,
    autorun: &vnr_core::AutorunFact,
    snapshot: &Snapshot,
    open_path: &mut Option<String>,
    quarantine: &mut Option<String>,
    remove_startup: &mut Option<String>,
) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(autorun.name.as_str())
                .size(14.0)
                .family(theme::semibold()),
        );
        widgets::badge(ui, autorun.kind.label(), theme::EMBER);
        if snapshot
            .signatures
            .matches
            .iter()
            .any(|hit| hit.subject == autorun.id)
        {
            widgets::badge(ui, "SIGNATURE MATCH", theme::BAD);
        }
    });
    ui.add_space(4.0);
    ui.columns(2, |columns| {
        widgets::key_value(&mut columns[0], "Location", &autorun.location);
        widgets::key_value(
            &mut columns[1],
            "Path",
            autorun.exe.as_deref().unwrap_or("not resolved"),
        );
    });
    ui.columns(2, |columns| {
        widgets::key_value(&mut columns[0], "Command", &autorun.command);
        widgets::key_value(
            &mut columns[1],
            "SHA-256",
            autorun.sha256.as_deref().unwrap_or("not hashed"),
        );
    });
    if let Some(path) = &autorun.exe {
        ui.horizontal(|ui| {
            if ui.button("Open folder").clicked()
                && let Some(parent) = std::path::Path::new(path).parent()
            {
                *open_path = Some(parent.display().to_string());
            }
            if ui.button("Copy path").clicked() {
                ui.ctx().copy_text(path.clone());
            }
            // The panel above is the preview: path, command, hash and signature. One click
            // moves the file, and the journal records that this is what was on screen.
            if ui
                .button("Quarantine the file")
                .on_hover_text(
                    "Move the file into ranger's quarantine. Its hash is recorded first, and \
                     Restore in the Actions view puts it back.",
                )
                .clicked()
            {
                *quarantine = Some(path.clone());
            }
        });
    } else {
        ui.label(
            RichText::new("There is no resolved path to quarantine for this entry.")
                .size(11.0)
                .color(theme::muted(ui)),
        );
    }
    ui.horizontal(|ui| {
        let surface = vnr_core::action::StartupSurface::of(autorun);
        let button = ui.button("Remove from startup…").on_hover_text(
            "Take this entry out of the operating system's startup. The card names where it \
                 lives and what it runs before anything happens.",
        );
        if button.clicked() {
            *remove_startup = Some(autorun.id.clone());
        }
        match surface.refusal() {
            None => {
                ui.label(RichText::new(surface.label()).size(10.5).color(theme::muted(ui)));
            }
            Some(refusal) => {
                ui.label(RichText::new(refusal.label()).size(10.5).color(theme::ATTENTION))
                    .on_hover_text(refusal.sentence());
            }
        }
    });
}

fn finding_card(ui: &mut egui::Ui, finding: &vnr_core::Finding) -> bool {
    let mut suppress = false;
    let colour = match finding.severity {
        vnr_core::Severity::Attention => theme::ATTENTION,
        vnr_core::Severity::Notice => theme::EMBER,
        vnr_core::Severity::Info => theme::muted(ui),
    };
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            widgets::badge(ui, finding.severity.label(), colour);
            ui.label(RichText::new(&finding.title).size(12.5).family(theme::semibold()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Suppress…").clicked() {
                    suppress = true;
                }
                widgets::badge(ui, finding.confidence.label(), theme::muted(ui));
            });
        });
        ui.add_space(2.0);
        ui.label(
            RichText::new(finding.subject_label.as_str())
                .size(10.5)
                .color(theme::muted(ui)),
        );
        ui.add_space(6.0);
        for line in &finding.evidence {
            widgets::dot_line(ui, theme::muted(ui), line);
        }
        ui.add_space(6.0);
        ui.label(RichText::new("Why").size(10.0).color(theme::muted(ui)));
        ui.add(egui::Label::new(RichText::new(&finding.why).size(11.5)).wrap());
        ui.add_space(4.0);
        ui.label(RichText::new("Likely benign").size(10.0).color(theme::OK));
        ui.add(egui::Label::new(RichText::new(&finding.benign).size(11.0).color(theme::muted(ui))).wrap());
        ui.add_space(4.0);
        ui.label(RichText::new("What to do").size(10.0).color(theme::muted(ui)));
        ui.add(egui::Label::new(RichText::new(&finding.remediation).size(11.0)).wrap());
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("{} · {}", finding.rule_id, finding.subject))
                .size(9.5)
                .color(theme::muted(ui)),
        );
    });
    suppress
}

fn change_row(ui: &mut egui::Ui, change: &vnr_core::Change) {
    ui.horizontal_wrapped(|ui| {
        widgets::badge(ui, change.kind.label(), theme::muted(ui));
        ui.add(
            egui::Label::new(
                RichText::new(change.subject.as_str())
                    .size(11.5)
                    .family(theme::semibold()),
            )
            .wrap(),
        );
        ui.add(
            egui::Label::new(
                RichText::new(format!("{} · {}", change.detail, change.source))
                    .size(10.5)
                    .color(theme::muted(ui)),
            )
            .wrap(),
        );
    });
}

fn event_row(ui: &mut egui::Ui, event: &vnr_core::TimelineEvent) {
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format_utc(event.at_unix))
                .size(10.5)
                .monospace()
                .color(theme::muted(ui)),
        );
        widgets::badge(ui, event.kind.label(), theme::muted(ui));
        ui.add(
            egui::Label::new(
                RichText::new(event.subject.as_str())
                    .size(11.5)
                    .family(theme::semibold()),
            )
            .wrap(),
        );
        ui.add(
            egui::Label::new(
                RichText::new(event.detail.as_str())
                    .size(10.5)
                    .color(theme::muted(ui)),
            )
            .wrap(),
        );
    });
}

/// How long a scan took, at the precision a person reads: tenths of a second.
///
/// A scan is either under a second, where milliseconds are the interesting fact, or over
/// it, where a tenth is. Printing `1.438 s` invites a precision nobody acts on.
fn describe_duration(milliseconds: u64) -> String {
    if milliseconds < 1000 {
        format!("{milliseconds} ms")
    } else {
        #[allow(clippy::cast_precision_loss)]
        let seconds = milliseconds as f64 / 1000.0;
        format!("{seconds:.1} s")
    }
}

fn table_header(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(10.0)
            .family(theme::semibold())
            .color(theme::muted(ui)),
    );
}

fn scope_color(scope: AutorunScope) -> Color32 {
    match scope {
        AutorunScope::User => theme::EMBER,
        AutorunScope::System => theme::ATTENTION,
    }
}

/// Whether a change or timeline event belongs to the chosen source.
fn change_matches(filter: ChangeFilter, source: &str) -> bool {
    match filter {
        ChangeFilter::All => true,
        ChangeFilter::Processes => source.eq_ignore_ascii_case("processes"),
        ChangeFilter::Startup => source.eq_ignore_ascii_case("autoruns"),
        ChangeFilter::Network => source.eq_ignore_ascii_case("listeners"),
        ChangeFilter::Files => source.eq_ignore_ascii_case("watch"),
        ChangeFilter::Rules => source.eq_ignore_ascii_case("rules"),
    }
}

/// One line of the process table.
///
/// A group is a line a person can open, and a process is a line they can select. The two are
/// one list rather than two tables, so the scroll position, the striping and the row height
/// are the same for both and a collapse does not renumber anything.
enum ProcessLine<'a> {
    /// Every process of one name.
    Group {
        /// The name as the first member spells it, lowercased for the key.
        key: String,
        /// The name to show, as the first member spells it.
        name: String,
        /// How many processes carry it.
        count: usize,
        /// The one executable they share, when they share one.
        shared_path: Option<String>,
        /// Whether the group is open.
        open: bool,
    },
    /// One process, indented under its parent when the table is a tree.
    Process {
        /// The process.
        process: &'a ProcessFact,
        /// How deep in the tree, 0 for a root.
        depth: usize,
    },
}

/// How deep a tree may go before the rest is listed flat.
///
/// A parent chain from a hand-edited snapshot can be circular, and a walk that trusts it
/// would hang the frame. The bound is a floor on how wrong the data can be.
const MAX_TREE_DEPTH: usize = 12;

/// Turn sorted rows into the lines the table draws.
///
/// Grouping by name orders the groups by name; the sort keys order the members inside a
/// group. Grouping by parent walks the parent chain, so a process whose parent is gone is a
/// root, and anything a cycle hides is listed flat rather than dropped.
fn process_lines<'a>(
    rows: &[&'a ProcessFact],
    grouping: crate::ProcessGrouping,
    expanded: &std::collections::HashSet<String>,
) -> Vec<ProcessLine<'a>> {
    match grouping {
        crate::ProcessGrouping::None => rows
            .iter()
            .map(|process| ProcessLine::Process { process, depth: 0 })
            .collect(),
        crate::ProcessGrouping::Name => {
            let mut lines = Vec::new();
            let mut sorted: Vec<&ProcessFact> = rows.to_vec();
            sorted.sort_by_key(|process| process.name.to_lowercase());
            let mut index = 0;
            while index < sorted.len() {
                let key = sorted[index].name.to_lowercase();
                let mut end = index + 1;
                while end < sorted.len() && sorted[end].name.to_lowercase() == key {
                    end += 1;
                }
                let members = &sorted[index..end];
                let open = expanded.contains(&key);
                let shared_path = shared_exe(members);
                lines.push(ProcessLine::Group {
                    key,
                    name: sorted[index].name.clone(),
                    count: members.len(),
                    shared_path,
                    open,
                });
                if open {
                    lines.extend(
                        members
                            .iter()
                            .map(|process| ProcessLine::Process { process, depth: 0 }),
                    );
                }
                index = end;
            }
            lines
        }
        crate::ProcessGrouping::Parent => tree_lines(rows),
    }
}

/// The executable every member of a group runs, when it is one executable.
fn shared_exe(members: &[&ProcessFact]) -> Option<String> {
    let first = members.first()?.exe.as_deref()?;
    if members
        .iter()
        .all(|process| process.exe.as_deref() == Some(first))
    {
        Some(first.to_owned())
    } else {
        None
    }
}

/// Depth-first order from the roots, so a child sits under the process that started it.
fn tree_lines<'a>(rows: &[&'a ProcessFact]) -> Vec<ProcessLine<'a>> {
    let known: std::collections::HashSet<u32> = rows.iter().map(|process| process.pid).collect();
    let mut children: std::collections::HashMap<u32, Vec<&ProcessFact>> = std::collections::HashMap::new();
    let mut roots: Vec<&ProcessFact> = Vec::new();
    for process in rows {
        match process
            .parent
            .filter(|parent| known.contains(parent) && *parent != process.pid)
        {
            Some(parent) => children.entry(parent).or_default().push(process),
            None => roots.push(process),
        }
    }
    let mut lines = Vec::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut stack: Vec<(&ProcessFact, usize)> = roots.into_iter().rev().map(|process| (process, 0)).collect();
    while let Some((process, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH || !seen.insert(process.pid) {
            continue;
        }
        lines.push(ProcessLine::Process { process, depth });
        if let Some(kids) = children.get(&process.pid) {
            for kid in kids.iter().rev() {
                stack.push((kid, depth.saturating_add(1)));
            }
        }
    }
    // A cycle leaves processes unreachable from any root. They are listed flat rather than
    // dropped: a table that silently loses a row is worse than one that shows it oddly.
    for process in rows {
        if seen.insert(process.pid) {
            lines.push(ProcessLine::Process { process, depth: 0 });
        }
    }
    lines
}

/// Whether a path sits in a temporary, download or desktop folder.
fn scratch_path(path: &str) -> bool {
    let lower = path.replace('/', "\\").to_lowercase();
    lower.contains("\\temp\\") || lower.contains("\\downloads\\") || lower.contains("\\desktop\\")
}

fn filter_process(process: &ProcessFact, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    process.name.to_lowercase().contains(needle)
        || process
            .exe
            .as_deref()
            .is_some_and(|path| path.to_lowercase().contains(needle))
        || process
            .user
            .as_deref()
            .is_some_and(|user| user.to_lowercase().contains(needle))
}

fn filter_autorun(autorun: &vnr_core::AutorunFact, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    autorun.name.to_lowercase().contains(needle)
        || autorun.command.to_lowercase().contains(needle)
        || autorun.location.to_lowercase().contains(needle)
}

fn filter_listener(listener: &vnr_core::ListenerFact, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    listener.address.to_lowercase().contains(needle)
        || listener
            .process
            .as_deref()
            .is_some_and(|process| process.to_lowercase().contains(needle))
        || listener.port.to_string().contains(needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent: Option<u32>, name: &str, exe: Option<&str>) -> ProcessFact {
        ProcessFact {
            pid,
            parent,
            name: name.to_owned(),
            exe: exe.map(str::to_owned),
            command: None,
            user: None,
            started_at_unix: None,
        }
    }

    fn lines_for<'a>(
        rows: &[&'a ProcessFact],
        grouping: crate::ProcessGrouping,
        expanded: &[&str],
    ) -> Vec<ProcessLine<'a>> {
        let expanded: std::collections::HashSet<String> =
            expanded.iter().map(|name| (*name).to_owned()).collect();
        process_lines(rows, grouping, &expanded)
    }

    fn counts(lines: &[ProcessLine<'_>]) -> (usize, usize) {
        let groups = lines
            .iter()
            .filter(|line| matches!(line, ProcessLine::Group { .. }))
            .count();
        let processes = lines
            .iter()
            .filter(|line| matches!(line, ProcessLine::Process { .. }))
            .count();
        (groups, processes)
    }

    #[test]
    fn one_name_is_one_row_until_it_is_opened() {
        let svchost = [
            process(1, None, "svchost.exe", Some(r"C:\Windows\System32\svchost.exe")),
            process(2, None, "svchost.exe", Some(r"C:\Windows\System32\svchost.exe")),
            process(3, None, "svchost.exe", Some(r"C:\Windows\System32\svchost.exe")),
        ];
        let explorer = [process(4, None, "explorer.exe", Some(r"C:\Windows\explorer.exe"))];
        let mut rows: Vec<&ProcessFact> = Vec::new();
        rows.extend(svchost.iter());
        rows.extend(explorer.iter());

        let closed = lines_for(&rows, crate::ProcessGrouping::Name, &[]);
        assert_eq!(counts(&closed), (2, 0), "two names are two closed rows");
        let ProcessLine::Group {
            name,
            count,
            shared_path,
            open,
            ..
        } = &closed[0]
        else {
            panic!("the first line is a group");
        };
        assert_eq!(name, "explorer.exe");
        assert_eq!(*count, 1);
        assert!(!open);
        assert!(shared_path.is_some());
        let ProcessLine::Group { count, key, .. } = &closed[1] else {
            panic!("the second line is a group");
        };
        assert_eq!(*count, 3);
        assert_eq!(key, "svchost.exe");

        let open = lines_for(&rows, crate::ProcessGrouping::Name, &["svchost.exe"]);
        assert_eq!(counts(&open), (2, 3), "opening one group shows its three pids");

        let flat = lines_for(&rows, crate::ProcessGrouping::None, &[]);
        assert_eq!(counts(&flat), (0, 4));
    }

    #[test]
    fn a_dry_run_totals_are_the_sum_of_its_places() {
        let report = crate::world::CleanReport {
            run: 1,
            surfaces: vec![
                crate::world::CleanSurface {
                    id: "win.temp".to_owned(),
                    label: "Temporary files".to_owned(),
                    roots: 2,
                    opt_in: false,
                    items: vec![
                        crate::world::CleanItem {
                            path: "a".to_owned(),
                            bytes: 10,
                            is_dir: false,
                        },
                        crate::world::CleanItem {
                            path: "b".to_owned(),
                            bytes: 0,
                            is_dir: true,
                        },
                    ],
                    skipped_young: 3,
                    skipped_links: 0,
                    skipped_devices: 0,
                    skipped_excluded: 1,
                },
                crate::world::CleanSurface {
                    id: "win.gpu".to_owned(),
                    label: "GPU shader cache".to_owned(),
                    roots: 1,
                    opt_in: false,
                    items: vec![crate::world::CleanItem {
                        path: "c".to_owned(),
                        bytes: 90,
                        is_dir: false,
                    }],
                    skipped_young: 0,
                    skipped_links: 0,
                    skipped_devices: 0,
                    skipped_excluded: 0,
                },
            ],
            cancelled: false,
        };
        let (places, bytes, entries) = measured_totals(&report);
        assert_eq!(places, 2);
        assert_eq!(bytes, 100, "sizes add up across surfaces");
        assert_eq!(entries, 3, "an empty folder is an entry with no bytes");
    }

    #[test]
    fn a_group_says_nothing_about_a_path_its_members_do_not_share() {
        let one = process(1, None, "node.exe", Some(r"C:\a\node.exe"));
        let two = process(2, None, "node.exe", Some(r"D:\b\node.exe"));
        let rows = [&one, &two];
        let lines = lines_for(&rows, crate::ProcessGrouping::Name, &[]);
        let ProcessLine::Group {
            shared_path, count, ..
        } = &lines[0]
        else {
            panic!("a group");
        };
        assert_eq!(*count, 2);
        assert_eq!(*shared_path, None, "two executables are not one path");
    }

    #[test]
    fn the_tree_puts_a_child_under_its_parent_and_a_cycle_costs_a_row_a_place_only() {
        let root = process(1, None, "init.exe", None);
        let child = process(2, Some(1), "child.exe", None);
        let grandchild = process(3, Some(2), "grandchild.exe", None);
        let orphan = process(4, Some(999), "orphan.exe", None);
        let rows = [&root, &child, &grandchild, &orphan];
        let lines = lines_for(&rows, crate::ProcessGrouping::Parent, &[]);
        let depth: Vec<(u32, usize)> = lines
            .iter()
            .filter_map(|line| match line {
                ProcessLine::Process { process, depth } => Some((process.pid, *depth)),
                ProcessLine::Group { .. } => None,
            })
            .collect();
        assert_eq!(
            depth,
            vec![(1, 0), (2, 1), (3, 2), (4, 0)],
            "a parent that has gone is a root, not a lost row"
        );

        let a = process(10, Some(11), "a.exe", None);
        let b = process(11, Some(10), "b.exe", None);
        let cycle = [&a, &b];
        let lines = lines_for(&cycle, crate::ProcessGrouping::Parent, &[]);
        assert_eq!(counts(&lines), (0, 2), "a cycle is listed, never dropped");
    }
}
