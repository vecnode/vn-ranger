//! The six surfaces. Each one is a function of the [`World`] and the interface state,
//! and returns nothing but the actions a person asked for.

use egui::{Color32, RichText};
use vnr_core::time::{describe_age, format_utc};
use vnr_core::{AutorunScope, ProcessFact, Snapshot};

use crate::{Action, Ui, View, theme, widgets};

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
        ui.columns(4, |columns| {
            widgets::statistic(&mut columns[0], counts.processes, "Processes");
            widgets::statistic(&mut columns[1], counts.autoruns, "Startup items");
            widgets::statistic(&mut columns[2], counts.listeners, "Listeners");
            widgets::statistic(&mut columns[3], counts.packages, "Packages");
        });
        ui.add_space(10.0);

        if snapshot.has_matches() {
            signature_matches_card(ui, snapshot);
        } else {
            signature_card(ui, snapshot, actions);
        }
        ui.add_space(10.0);

        ui.columns(2, |columns| {
            startup_preview(&mut columns[0], snapshot);
            listener_preview(&mut columns[1], snapshot);
        });
        ui.add_space(10.0);
        collectors_card(ui, snapshot);
        ui.add_space(10.0);
        widgets::dot_line(
            ui,
            theme::OK,
            "No network. No telemetry. Everything ranger saw stays on this machine.",
        );
    }

    /// The process table and its detail card.
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
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(380.0)
            .show(ui, |ui| {
                egui::Grid::new("process-table")
                    .num_columns(4)
                    .spacing([16.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header(ui, "PID");
                        header(ui, "Process");
                        header(ui, "User");
                        header(ui, "Started");
                        ui.end_row();
                        for process in rows.iter().take(600) {
                            let selected = self.selected_process == Some(process.pid);
                            if ui.selectable_label(selected, process.pid.to_string()).clicked() {
                                clicked = Some(process.pid);
                            }
                            if ui.selectable_label(selected, process.name.as_str()).clicked() {
                                clicked = Some(process.pid);
                            }
                            ui.label(
                                RichText::new(process.user.as_deref().unwrap_or("—"))
                                    .size(12.0)
                                    .color(theme::muted(ui)),
                            );
                            ui.label(
                                RichText::new(process.started_at_unix.map_or_else(
                                    || "—".to_owned(),
                                    |then| describe_age(world.now_unix, then),
                                ))
                                .size(12.0)
                                .color(theme::muted(ui)),
                            );
                            ui.end_row();
                        }
                    });
            });
        if let Some(pid) = clicked {
            self.selected_process = Some(pid);
        }
        if let Some(process) = self
            .selected_process
            .and_then(|pid| snapshot.processes.iter().find(|process| process.pid == pid))
        {
            ui.add_space(10.0);
            process_detail(ui, process, world.now_unix);
        }
    }

    /// The startup table and its detail card.
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
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(420.0)
            .show(ui, |ui| {
                egui::Grid::new("startup-table")
                    .num_columns(4)
                    .spacing([16.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header(ui, "Name");
                        header(ui, "Kind");
                        header(ui, "Scope");
                        header(ui, "Enabled");
                        ui.end_row();
                        for autorun in &rows {
                            let selected = self.selected_autorun.as_deref() == Some(autorun.id.as_str());
                            if ui.selectable_label(selected, autorun.name.as_str()).clicked() {
                                clicked = Some(autorun.id.clone());
                            }
                            ui.label(
                                RichText::new(autorun.kind.label())
                                    .size(12.0)
                                    .color(theme::muted(ui)),
                            );
                            widgets::badge(ui, autorun.scope.label(), scope_color(autorun.scope));
                            ui.label(if autorun.enabled { "yes" } else { "no" });
                            ui.end_row();
                        }
                    });
            });
        if let Some(id) = clicked {
            self.selected_autorun = Some(id);
        }
        if let Some(autorun) = self
            .selected_autorun
            .as_deref()
            .and_then(|id| snapshot.autoruns.iter().find(|autorun| autorun.id == id))
        {
            ui.add_space(10.0);
            let mut open_path = None;
            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(autorun.name.as_str()).size(16.0).strong());
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
                widgets::key_value(ui, "Location", &autorun.location);
                widgets::key_value(ui, "Command", &autorun.command);
                widgets::key_value(ui, "Path", autorun.exe.as_deref().unwrap_or("not resolved"));
                widgets::key_value(ui, "SHA-256", autorun.sha256.as_deref().unwrap_or("not hashed"));
                if let Some(path) = &autorun.exe {
                    ui.horizontal(|ui| {
                        if ui.button("Open folder").clicked()
                            && let Some(parent) = std::path::Path::new(path).parent()
                        {
                            open_path = Some(parent.display().to_string());
                        }
                        if ui.button("Copy path").clicked() {
                            ui.ctx().copy_text(path.clone());
                        }
                    });
                }
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
        let mut clicked_pid = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(480.0)
            .show(ui, |ui| {
                egui::Grid::new("listener-table")
                    .num_columns(6)
                    .spacing([16.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        header(ui, "Protocol");
                        header(ui, "Address");
                        header(ui, "Port");
                        header(ui, "Process");
                        header(ui, "PID");
                        header(ui, "State");
                        ui.end_row();
                        for listener in &rows {
                            ui.label(RichText::new(listener.protocol.label()).size(12.0).strong());
                            ui.horizontal(|ui| {
                                if listener.public {
                                    widgets::badge(ui, "PUBLIC", theme::ATTENTION);
                                }
                                ui.label(RichText::new(listener.address.as_str()).size(12.0).monospace());
                            });
                            ui.label(RichText::new(listener.port.to_string()).size(12.0).monospace());
                            if ui
                                .selectable_label(false, listener.process.as_deref().unwrap_or("unknown"))
                                .clicked()
                            {
                                clicked_pid = listener.pid;
                            }
                            ui.label(
                                RichText::new(
                                    listener.pid.map_or_else(|| "—".to_owned(), |pid| pid.to_string()),
                                )
                                .size(12.0)
                                .color(theme::muted(ui)),
                            );
                            ui.label(
                                RichText::new(listener.state.as_str())
                                    .size(11.0)
                                    .color(theme::muted(ui)),
                            );
                            ui.end_row();
                        }
                    });
            });
        if let Some(pid) = clicked_pid {
            self.selected_process = Some(pid);
            self.view = View::Processes;
            self.search.clear();
        }
    }

    /// The report surface.
    pub(crate) fn report(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        let Some(snapshot) = world.snapshot() else {
            widgets::empty(ui, "No report yet", "Run a scan first.");
            return;
        };
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Export").strong());
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "JSON is the complete snapshot. Markdown is the same report a person can read.",
                )
                .size(12.0)
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
            ui.label(RichText::new("This scan").strong());
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
            ui.label(RichText::new("What this report is not").strong());
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "It is an inventory, not a verdict. A fact that is absent does not mean it was not there. No numeric threat score exists, and no data left this machine.",
                )
                .size(12.0)
                .color(theme::muted(ui)),
            );
        });
    }

    /// Preferences, elevation and privacy.
    pub(crate) fn settings(&mut self, ui: &mut egui::Ui, world: &crate::World, actions: &mut Vec<Action>) {
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Appearance").strong());
            ui.checkbox(&mut self.dark, "Dark theme");
            ui.label(
                RichText::new("The interface follows the suite's palette. A light theme is included.")
                    .size(11.0)
                    .color(theme::muted(ui)),
            );
        });
        ui.add_space(10.0);
        widgets::card(ui, |ui| {
            ui.label(RichText::new("Elevation").strong());
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
                .size(12.0)
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
            ui.label(RichText::new("Signatures").strong());
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
                .size(12.0)
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
            ui.label(RichText::new("Privacy").strong());
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
            ui.label(RichText::new("About").strong());
            ui.label(
                RichText::new(format!(
                    "vn-ranger {} · MIT · Rust and egui, no webview.",
                    world.version
                ))
                .size(12.0)
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
                .strong(),
            );
        });
        ui.add_space(4.0);
        for hit in snapshot.signatures.matches.iter().take(5) {
            ui.label(RichText::new(format!("{} · {}", hit.name, hit.path)).size(12.0));
        }
        if snapshot.signatures.matches.len() > 5 {
            ui.label(
                RichText::new(format!("and {} more", snapshot.signatures.matches.len() - 5))
                    .size(12.0)
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
            ui.label(RichText::new("Local signature database").strong());
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
            .size(12.0)
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
        ui.label(RichText::new("Startup items").strong());
        ui.add_space(4.0);
        if snapshot.autoruns.is_empty() {
            ui.label(RichText::new("None visible.").size(12.0).color(theme::muted(ui)));
        }
        for autorun in snapshot.autoruns.iter().take(6) {
            ui.horizontal(|ui| {
                widgets::badge(ui, autorun.scope.label(), scope_color(autorun.scope));
                ui.add(egui::Label::new(RichText::new(autorun.name.as_str()).size(12.0)).truncate());
                ui.label(
                    RichText::new(autorun.kind.label())
                        .size(11.0)
                        .color(theme::muted(ui)),
                );
            });
        }
    });
}

fn listener_preview(ui: &mut egui::Ui, snapshot: &Snapshot) {
    widgets::card(ui, |ui| {
        ui.label(RichText::new("Listening on all interfaces").strong());
        ui.add_space(4.0);
        let public: Vec<_> = snapshot
            .listeners
            .iter()
            .filter(|listener| listener.public)
            .collect();
        if public.is_empty() {
            ui.label(
                RichText::new("Nothing is bound to a public interface.")
                    .size(12.0)
                    .color(theme::muted(ui)),
            );
        }
        for listener in public.iter().take(6) {
            ui.horizontal(|ui| {
                widgets::badge(ui, listener.protocol.label(), theme::ATTENTION);
                ui.label(
                    RichText::new(format!("{}:{}", listener.address, listener.port))
                        .size(12.0)
                        .monospace(),
                );
                ui.label(
                    RichText::new(listener.process.as_deref().unwrap_or("unknown process"))
                        .size(11.0)
                        .color(theme::muted(ui)),
                );
            });
        }
    });
}

fn collectors_card(ui: &mut egui::Ui, snapshot: &Snapshot) {
    widgets::card(ui, |ui| {
        ui.label(RichText::new("What was checked").strong());
        ui.add_space(4.0);
        for status in &snapshot.collectors {
            ui.horizontal(|ui| {
                widgets::health(ui, status.state);
                ui.add_sized(
                    [180.0, 18.0],
                    egui::Label::new(RichText::new(status.label.as_str()).size(12.0)),
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

fn process_detail(ui: &mut egui::Ui, process: &ProcessFact, now: u64) {
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(process.name.as_str()).size(16.0).strong());
            widgets::badge(ui, &format!("PID {}", process.pid), theme::EMBER);
        });
        ui.add_space(4.0);
        widgets::key_value(ui, "Path", process.exe.as_deref().unwrap_or("not visible"));
        widgets::key_value(ui, "Command", process.command.as_deref().unwrap_or("not visible"));
        widgets::key_value(ui, "User", process.user.as_deref().unwrap_or("—"));
        widgets::key_value(
            ui,
            "Parent",
            &process
                .parent
                .map_or_else(|| "—".to_owned(), |pid| pid.to_string()),
        );
        widgets::key_value(
            ui,
            "Started",
            &process
                .started_at_unix
                .map_or_else(|| "—".to_owned(), |then| describe_age(now, then)),
        );
        if let Some(path) = &process.exe
            && ui.button("Copy path").clicked()
        {
            ui.ctx().copy_text(path.clone());
        }
    });
}

fn header(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(11.0).strong().color(theme::muted(ui)));
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
