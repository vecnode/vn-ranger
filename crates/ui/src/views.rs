//! The six surfaces. Each one is a function of the [`World`] and the interface state,
//! and returns nothing but the actions a person asked for.

use egui::{Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use vnr_core::time::{describe_age, format_utc};
use vnr_core::{AutorunScope, ProcessFact, Snapshot};

use crate::{Action, Ui, View, theme, widgets};

const PROCESS_FOOTER: f32 = 190.0;
const STARTUP_FOOTER: f32 = 210.0;
const TABLE_HEADER: f32 = 26.0;
const TABLE_ROW: f32 = 24.0;

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
        let width = ui.available_width();
        if width >= 720.0 {
            ui.columns(4, |columns| {
                widgets::statistic(&mut columns[0], counts.processes, "Processes");
                widgets::statistic(&mut columns[1], counts.autoruns, "Startup items");
                widgets::statistic(&mut columns[2], counts.listeners, "Listeners");
                widgets::statistic(&mut columns[3], counts.packages, "Packages");
            });
        } else if width >= 560.0 {
            ui.columns(2, |columns| {
                widgets::statistic(&mut columns[0], counts.processes, "Processes");
                widgets::statistic(&mut columns[1], counts.autoruns, "Startup items");
            });
            ui.add_space(6.0);
            ui.columns(2, |columns| {
                widgets::statistic(&mut columns[0], counts.listeners, "Listeners");
                widgets::statistic(&mut columns[1], counts.packages, "Packages");
            });
        } else {
            widgets::statistic(ui, counts.processes, "Processes");
            ui.add_space(6.0);
            widgets::statistic(ui, counts.autoruns, "Startup items");
            ui.add_space(6.0);
            widgets::statistic(ui, counts.listeners, "Listeners");
            ui.add_space(6.0);
            widgets::statistic(ui, counts.packages, "Packages");
        }
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
        ui.add_space(10.0);
        widgets::dot_line(
            ui,
            theme::OK,
            "No network. No telemetry. Everything ranger saw stays on this machine.",
        );
    }

    /// The process table and its detail footer.
    pub(crate) fn processes(&mut self, ui: &mut egui::Ui, world: &crate::World) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(ui, "No processes yet", "Run a scan to see what is running.");
            return;
        };
        let needle = self.search.trim().to_lowercase();
        let rows: Vec<&ProcessFact> = snapshot
            .processes
            .iter()
            .filter(|process| filter_process(process, &needle))
            .collect();
        ui.label(
            RichText::new(format!(
                "{} of {} processes",
                rows.len(),
                snapshot.processes.len()
            ))
            .size(11.0)
            .color(theme::muted(ui)),
        );
        let selected = self
            .selected_process
            .and_then(|pid| snapshot.processes.iter().find(|process| process.pid == pid));
        let gap = if selected.is_some() { 8.0 } else { 0.0 };
        let footer = if selected.is_some() { PROCESS_FOOTER } else { 0.0 };
        let table_height = (ui.available_height() - footer - gap).max(140.0);
        let body_height = (table_height - TABLE_HEADER).max(80.0);
        let column_space = ui.spacing().item_spacing.x;
        let process_width = (ui.available_width() - 64.0 - 140.0 - 110.0 - 3.0 * column_space).max(180.0);
        let mut clicked = None;
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
                        body.rows(TABLE_ROW, rows.len(), |mut row| {
                            let process = rows[row.index()];
                            row.set_selected(self.selected_process == Some(process.pid));
                            let mut row_clicked = false;
                            let (_, response) = row.col(|ui| {
                                ui.label(RichText::new(process.pid.to_string()).size(11.5).monospace());
                            });
                            row_clicked |= response.clicked();
                            let (_, response) = row.col(|ui| {
                                ui.add(
                                    egui::Label::new(RichText::new(process.name.as_str()).size(11.5))
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
                        });
                    });
            },
        );
        if let Some(pid) = clicked {
            self.selected_process = Some(pid);
            ui.ctx().request_repaint();
        }
        if let Some(process) = selected {
            ui.add_space(8.0);
            detail_footer(ui, PROCESS_FOOTER, |ui| {
                process_detail_body(ui, process, world.now_unix);
            });
        }
    }

    /// The startup table and its detail footer.
    pub(crate) fn startup(&mut self, ui: &mut egui::Ui, world: &crate::World) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(
                ui,
                "No startup items yet",
                "Run a scan to see what starts on its own.",
            );
            return;
        };
        let needle = self.search.trim().to_lowercase();
        let rows: Vec<&vnr_core::AutorunFact> = snapshot
            .autoruns
            .iter()
            .filter(|autorun| filter_autorun(autorun, &needle))
            .collect();
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
        let table_height = (ui.available_height() - footer - gap).max(140.0);
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
            detail_footer(ui, STARTUP_FOOTER, |ui| {
                startup_detail_body(ui, autorun, snapshot, &mut open_path);
            });
            if let Some(path) = open_path {
                self.open_path = Some(path);
            }
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
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("What this report is not").family(theme::semibold()));
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "It is an inventory, not a verdict. A fact that is absent does not mean it was not there. No numeric threat score exists, and no data left this machine.",
                )
                .size(11.5)
                .color(theme::muted(ui)),
            );
        });
    }

    /// Preferences, elevation and privacy.
    pub(crate) fn settings(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Appearance").family(theme::semibold()));
            ui.checkbox(&mut self.dark, "Dark theme");
            ui.label(
                RichText::new("The interface follows the suite's palette. A light theme is included.")
                    .size(11.0)
                    .color(theme::muted(ui)),
            );
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
            ui.label(RichText::new("Privacy").family(theme::semibold()));
            ui.add_space(4.0);
            widgets::dot_line(ui, theme::OK, "No network. No telemetry. No account.");
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
                "A hash match is a fact about a file, not a diagnosis of the machine. Quarantine and removal arrive in v0.3.",
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
        });
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
