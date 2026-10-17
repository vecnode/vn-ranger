//! vn-ranger's egui interface.
//!
//! The interface draws a [`World`] and returns [`Action`]s. It does not scan, read a
//! configuration file or start a process: the shell does those things and hands the
//! result back. That boundary is what makes every view a function of data.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod fonts;
pub mod icons;
pub mod theme;
pub mod views;
pub mod widgets;

mod world;

pub use world::{Action, Live, ScanState, View, WatchReport, World};

use egui::{Align2, CornerRadius, FontId, Margin, RichText, Sense, vec2};

/// The interface's own state: what is on screen, not what is true about the machine.
pub struct Ui {
    pub(crate) view: View,
    last_view: View,
    pub(crate) search: String,
    pub(crate) selected_process: Option<u32>,
    pub(crate) selected_autorun: Option<String>,
    pub(crate) only_public: bool,
    pub(crate) confirm_elevate: bool,
    pub(crate) dark: bool,
    pub(crate) open_path: Option<String>,
    mark: egui::TextureHandle,
}

impl Ui {
    /// Build the interface and upload the application mark once.
    #[must_use]
    pub fn new(ctx: &egui::Context) -> Self {
        fonts::install(ctx);
        let pixels: &[u8] = include_bytes!("../../../assets/logo/vn-ranger-app.rgba");
        let image = egui::ColorImage::from_rgba_unmultiplied([64, 64], pixels);
        let mark = ctx.load_texture("vn-ranger-mark", image, egui::TextureOptions::LINEAR);
        Self {
            view: View::Overview,
            last_view: View::Overview,
            search: String::new(),
            selected_process: None,
            selected_autorun: None,
            only_public: false,
            confirm_elevate: false,
            dark: true,
            open_path: None,
            mark,
        }
    }

    /// Draw one frame and return what the person asked for.
    pub fn show(&mut self, root: &mut egui::Ui, world: &World) -> Vec<Action> {
        let ctx = root.ctx().clone();
        theme::apply(&ctx, self.dark);
        let mut actions = Vec::new();
        let view_changed = self.last_view != self.view;
        self.last_view = self.view;
        self.top_bar(root, world, &mut actions);
        self.rail(root, world);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::panel(self.dark))
                    .inner_margin(Margin::symmetric(20, 14)),
            )
            .show(root, |ui| {
                self.page_header(ui, world);
                ui.add_space(10.0);
                let view = self.view;
                if matches!(view, View::Processes | View::Startup | View::Listeners) {
                    self.draw_view(ui, world, &mut actions, view);
                } else {
                    let mut scroll = egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                        .id_salt(self.view.label());
                    if view_changed {
                        scroll = scroll.vertical_scroll_offset(0.0);
                    }
                    scroll.show(ui, |ui| self.draw_view(ui, world, &mut actions, view));
                }
            });
        if let Some(path) = self.open_path.take() {
            actions.push(Action::OpenPath(path));
        }
        self.modal(&ctx, &mut actions);
        actions
    }

    fn draw_view(&mut self, ui: &mut egui::Ui, world: &World, actions: &mut Vec<Action>, view: View) {
        match view {
            View::Overview => self.overview(ui, world, actions),
            View::Processes => self.processes(ui, world),
            View::Startup => self.startup(ui, world),
            View::Listeners => self.listeners(ui, world),
            View::Changes => self.changes(ui, world, actions),
            View::Report => self.report(ui, world, actions),
            View::Settings => self.settings(ui, world, actions),
        }
    }

    fn top_bar(&self, root: &mut egui::Ui, world: &World, actions: &mut Vec<Action>) {
        egui::Panel::top("top")
            .exact_size(58.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::window(self.dark))
                    .inner_margin(Margin::symmetric(18, 8)),
            )
            .show(root, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(
                        self.mark.id(),
                        vec2(28.0, 28.0),
                    )));
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("vn-ranger").size(14.5).family(theme::semibold()));
                        ui.label(
                            RichText::new("A quiet ranger for your machine.")
                                .size(10.5)
                                .color(theme::muted(ui)),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let scan = ui.add_enabled(
                            !world.busy(),
                            egui::Button::new(
                                RichText::new("Scan now")
                                    .size(12.5)
                                    .family(theme::semibold())
                                    .color(theme::ON_EMBER),
                            )
                            .fill(theme::EMBER),
                        );
                        if scan.clicked() {
                            actions.push(Action::Scan);
                        }
                        match &world.scan {
                            ScanState::Running(step) => {
                                ui.spinner();
                                ui.label(RichText::new(step.as_str()).size(11.5).color(theme::muted(ui)));
                            }
                            ScanState::Idle => {
                                if let Some(live) = world.live.as_ref().filter(|live| !live.items.is_empty())
                                {
                                    ui.label(
                                        RichText::new(format!(
                                            "Live · polled {}",
                                            vnr_core::time::describe_age(world.now_unix, live.at_unix)
                                        ))
                                        .size(11.5)
                                        .color(theme::muted(ui)),
                                    );
                                } else if let Some(snapshot) = world.snapshot() {
                                    ui.label(
                                        RichText::new(format!(
                                            "Scanned {}",
                                            vnr_core::time::describe_age(
                                                world.now_unix,
                                                snapshot.taken_at_unix
                                            )
                                        ))
                                        .size(11.5)
                                        .color(theme::muted(ui)),
                                    );
                                }
                                if world.snapshot().is_some_and(|snapshot| snapshot.elevated) {
                                    widgets::badge(ui, "ADMIN", theme::ATTENTION);
                                }
                            }
                        }
                    });
                });
            });
    }

    fn rail(&mut self, root: &mut egui::Ui, world: &World) {
        egui::Panel::left("rail")
            .exact_size(188.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel(self.dark))
                    .inner_margin(Margin::symmetric(10, 12)),
            )
            .show(root, |ui| {
                ui.add_space(2.0);
                for view in View::ALL {
                    self.nav(ui, view);
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("No network · No telemetry")
                            .size(10.0)
                            .color(theme::muted(ui)),
                    );
                    ui.label(
                        RichText::new(format!("v{}", world.version))
                            .size(10.0)
                            .color(theme::muted(ui)),
                    );
                    if world.elevated {
                        widgets::badge(ui, "ADMIN", theme::ATTENTION);
                    }
                });
            });
    }

    fn nav(&mut self, ui: &mut egui::Ui, view: View) {
        let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::click());
        let selected = self.view == view;
        let color = if selected {
            theme::EMBER
        } else if response.hovered() {
            ui.visuals().strong_text_color()
        } else {
            theme::muted(ui)
        };
        if selected {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), theme::EMBER.gamma_multiply(0.14));
        } else if response.hovered() {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), ui.visuals().widgets.hovered.bg_fill);
        }
        icons::paint(
            ui.painter(),
            egui::Rect::from_min_size(rect.min + vec2(10.0, 8.5), vec2(15.0, 15.0)),
            view_icon(view),
            color,
        );
        ui.painter().text(
            rect.min + vec2(36.0, 7.0),
            Align2::LEFT_TOP,
            view.label(),
            FontId::proportional(12.5),
            if selected {
                ui.visuals().strong_text_color()
            } else {
                color
            },
        );
        if response.clicked() {
            self.view = view;
            self.search.clear();
        }
    }

    fn page_header(&mut self, ui: &mut egui::Ui, world: &World) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(self.view.label())
                        .size(21.0)
                        .family(theme::semibold()),
                );
                ui.label(
                    RichText::new(self.view.subtitle())
                        .size(11.5)
                        .color(theme::muted(ui)),
                );
            });
            if matches!(self.view, View::Processes | View::Startup | View::Listeners) {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_sized(
                        vec2(240.0, 26.0),
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("Filter…")
                            .margin(Margin::symmetric(8, 6)),
                    );
                });
            }
        });
        if let Some(error) = &world.error {
            ui.add_space(4.0);
            ui.label(RichText::new(error).size(11.5).color(theme::BAD));
        }
        if let Some(notice) = &world.notice {
            ui.add_space(4.0);
            ui.label(RichText::new(notice).size(11.5).color(theme::OK));
        }
    }

    fn modal(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        if !self.confirm_elevate {
            return;
        }
        let mut open = true;
        egui::Window::new("Administrator scan")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(440.0);
                ui.label(
                    RichText::new(
                        "Windows will ask for consent before the elevated copy starts. The copy reads the machine, writes one snapshot, and exits.",
                    )
                    .size(12.0),
                );
                ui.add_space(6.0);
                widgets::dot_line(ui, theme::OK, "No deletion, quarantine or configuration change.");
                widgets::dot_line(ui, theme::OK, "No service and no standing administrator process.");
                widgets::dot_line(
                    ui,
                    theme::ATTENTION,
                    "The elevated copy can read data the standard window cannot.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.confirm_elevate = false;
                    }
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Continue").color(theme::ON_EMBER))
                                .fill(theme::EMBER),
                        )
                        .clicked()
                    {
                        self.confirm_elevate = false;
                        actions.push(Action::ScanElevated);
                    }
                });
            });
        if !open {
            self.confirm_elevate = false;
        }
    }
}

fn view_icon(view: View) -> icons::Icon {
    match view {
        View::Overview => icons::Icon::Overview,
        View::Processes => icons::Icon::Processes,
        View::Startup => icons::Icon::Startup,
        View::Listeners => icons::Icon::Listeners,
        View::Changes => icons::Icon::Changes,
        View::Report => icons::Icon::Report,
        View::Settings => icons::Icon::Settings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use vnr_core::{EventKind, Host, ProcessFact, Snapshot, Timeline, TimelineEvent};

    fn process() -> ProcessFact {
        ProcessFact {
            pid: 42,
            parent: Some(1),
            name: "agent".to_owned(),
            exe: Some("C:\\agent.exe".to_owned()),
            command: Some("agent.exe --quiet".to_owned()),
            user: Some("me".to_owned()),
            started_at_unix: Some(900),
        }
    }

    fn base_world(snapshot: Option<Snapshot>, baseline: Option<Snapshot>) -> World {
        let changes = match (&baseline, &snapshot) {
            (Some(baseline), Some(snapshot)) => vnr_core::diff_snapshots(baseline, snapshot),
            _ => Vec::new(),
        };
        World {
            snapshot,
            scan: ScanState::Idle,
            error: None,
            notice: None,
            elevated: false,
            can_elevate: false,
            data_dir: PathBuf::from("data"),
            signatures_dir: PathBuf::from("signatures"),
            version: "0.1.2".to_owned(),
            now_unix: 1_000,
            live: None,
            poll_enabled: true,
            watch: WatchReport::default(),
            baseline,
            baseline_error: None,
            changes,
            timeline: Timeline::new(),
        }
    }

    fn draw(view: View, world: &World) {
        egui::__run_test_ui(|root| {
            let ctx = root.ctx().clone();
            let mut ui = Ui::new(&ctx);
            ui.view = view;
            let _ = ui.show(root, world);
        });
    }

    #[test]
    fn every_view_draws_with_an_empty_world() {
        let world = base_world(None, None);
        for view in View::ALL {
            draw(view, &world);
        }
    }

    #[test]
    fn every_view_draws_with_a_scan_a_baseline_and_a_timeline() {
        let mut after = Snapshot::empty(Host::default(), false);
        after.processes.push(process());
        let mut before = after.clone();
        before.processes.clear();
        let mut world = base_world(Some(after.clone()), Some(before));
        world.live = Some(Live {
            items: after.processes.clone(),
            at_unix: 999,
            reason: None,
        });
        world.timeline.push(TimelineEvent::new(
            999,
            EventKind::ProcessStarted,
            "agent (pid 42)",
            "C:\\agent.exe",
            "processes",
        ));
        world.watch = WatchReport {
            enabled: true,
            roots: vec!["C:\\Users\\me\\Downloads".to_owned()],
            skipped: Vec::new(),
            error: None,
        };
        for view in View::ALL {
            draw(view, &world);
        }
    }
}
