//! vn-ranger's egui interface.
//!
//! The interface draws a [`World`] and returns [`Action`]s. It does not scan, read a
//! configuration file or start a process: the shell does those things and hands the
//! result back. That boundary is what makes every view a function of data.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod icons;
pub mod theme;
pub mod views;
pub mod widgets;

mod world;

pub use world::{Action, ScanState, View, World};

use egui::{Align2, CornerRadius, FontId, Margin, RichText, Sense, vec2};

/// The interface's own state: what is on screen, not what is true about the machine.
pub struct Ui {
    pub(crate) view: View,
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
        let pixels: &[u8] = include_bytes!("../../../assets/logo/vn-ranger-app.rgba");
        let image = egui::ColorImage::from_rgba_unmultiplied([64, 64], pixels);
        let mark = ctx.load_texture("vn-ranger-mark", image, egui::TextureOptions::LINEAR);
        Self {
            view: View::Overview,
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
        self.top_bar(root, world, &mut actions);
        self.rail(root, world);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::panel(self.dark))
                    .inner_margin(Margin::symmetric(24, 16)),
            )
            .show(root, |ui| {
                self.page_header(ui, world);
                ui.add_space(10.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.view {
                        View::Overview => self.overview(ui, world, &mut actions),
                        View::Processes => self.processes(ui, world),
                        View::Startup => self.startup(ui, world),
                        View::Listeners => self.listeners(ui, world),
                        View::Report => self.report(ui, world, &mut actions),
                        View::Settings => self.settings(ui, world, &mut actions),
                    });
            });
        if let Some(path) = self.open_path.take() {
            actions.push(Action::OpenPath(path));
        }
        self.modal(&ctx, &mut actions);
        actions
    }

    fn top_bar(&self, root: &mut egui::Ui, world: &World, actions: &mut Vec<Action>) {
        egui::Panel::top("top")
            .exact_size(64.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::window(self.dark))
                    .inner_margin(Margin::symmetric(22, 10)),
            )
            .show(root, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(
                        self.mark.id(),
                        vec2(32.0, 32.0),
                    )));
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("vn-ranger").size(17.0).strong());
                        ui.label(
                            RichText::new("A quiet ranger for your machine.")
                                .size(11.0)
                                .color(theme::muted(ui)),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let scan = ui.add_enabled(
                            !world.busy(),
                            egui::Button::new(RichText::new("Scan now").size(13.0).color(theme::ON_EMBER))
                                .fill(theme::EMBER),
                        );
                        if scan.clicked() {
                            actions.push(Action::Scan);
                        }
                        match &world.scan {
                            ScanState::Running(step) => {
                                ui.spinner();
                                ui.label(RichText::new(step.as_str()).size(12.0).color(theme::muted(ui)));
                            }
                            ScanState::Idle => {
                                if let Some(snapshot) = world.snapshot() {
                                    ui.label(
                                        RichText::new(format!(
                                            "Scanned {}",
                                            vnr_core::time::describe_age(
                                                world.now_unix,
                                                snapshot.taken_at_unix
                                            )
                                        ))
                                        .size(12.0)
                                        .color(theme::muted(ui)),
                                    );
                                    if snapshot.elevated {
                                        widgets::badge(ui, "ADMIN", theme::ATTENTION);
                                    }
                                }
                            }
                        }
                    });
                });
            });
    }

    fn rail(&mut self, root: &mut egui::Ui, world: &World) {
        egui::Panel::left("rail")
            .exact_size(196.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel(self.dark))
                    .inner_margin(Margin::symmetric(12, 14)),
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
        let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 34.0), Sense::click());
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
            egui::Rect::from_min_size(rect.min + vec2(10.0, 9.0), vec2(16.0, 16.0)),
            view_icon(view),
            color,
        );
        ui.painter().text(
            rect.min + vec2(38.0, 8.0),
            Align2::LEFT_TOP,
            view.label(),
            FontId::proportional(13.0),
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
                ui.label(RichText::new(self.view.label()).size(24.0).strong());
                ui.label(
                    RichText::new(self.view.subtitle())
                        .size(12.0)
                        .color(theme::muted(ui)),
                );
            });
            if matches!(self.view, View::Processes | View::Startup | View::Listeners) {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_sized(
                        vec2(260.0, 28.0),
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("Filter…")
                            .margin(Margin::symmetric(8, 6)),
                    );
                });
            }
        });
        if let Some(error) = &world.error {
            ui.add_space(4.0);
            ui.label(RichText::new(error).size(12.0).color(theme::BAD));
        }
        if let Some(notice) = &world.notice {
            ui.add_space(4.0);
            ui.label(RichText::new(notice).size(12.0).color(theme::OK));
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
                    .size(13.0),
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
        View::Report => icons::Icon::Report,
        View::Settings => icons::Icon::Settings,
    }
}
