//! vn-ranger's egui interface.
//!
//! The interface draws a [`World`] and returns [`Action`]s. It does not scan, read a
//! configuration file or start a process: the shell does those things and hands the
//! result back. That boundary is what makes every view a function of data.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod fonts;
pub mod icons;
pub mod theme;
pub mod views;
pub mod widgets;

mod world;

mod act;

mod clean;

pub use world::{
    Action, AutostartState, CleanChoice, CleanItem, CleanReport, CleanSurface, JournalRow, Live,
    QuarantineRow, ScanState, TrayState, View, WatchReport, World,
};

use egui::{Align2, CornerRadius, FontId, Margin, RichText, Sense, vec2};

/// The height of the top bar's action controls, so the circle and the button agree.
const ACTION_HEIGHT: f32 = 26.0;

/// Where the project lives. Shown, never fetched: ranger has no network code.
const PROJECT_URL: &str = "https://github.com/vecnode/vn-ranger";

/// How often the shell polls the process table, in seconds.
///
/// The interface repeats the number rather than importing it, because the interface must
/// not know what a worker is; the two are checked against each other by the indicator's
/// behaviour, which is the only place the number is visible.
const POLL_INTERVAL_SECONDS: u64 = 2;

/// How long the indicator may go without a beat before it says so.
///
/// Three missed polls: long enough that a slow scan does not look like a fault, short
/// enough that a stopped thread is visible within a few seconds.
const POLL_STALE_SECONDS: u64 = 3 * POLL_INTERVAL_SECONDS;

/// How long the flash lasts after a poll arrives. A flash, not a fade: one extra frame is
/// affordable, a permanent animation is not.
const LED_FLASH_SECONDS: f64 = 0.22;

/// What the live indicator is saying right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedState {
    /// The poll is off, or has not reported yet.
    Off,
    /// A poll arrived and the flash is still in its window.
    Flash,
    /// The poll is running and the last beat is recent.
    Steady,
    /// No beat for longer than three intervals.
    Stalled,
}

/// Decide what the indicator should show.
///
/// This is a square wave's opposite: a beat is an event with a timestamp, so the lamp
/// flashes and then goes quiet. A boolean toggled per poll would be a metronome, and a
/// metronome cannot say that the poll has stopped — which is the one thing this lamp is
/// for.
#[must_use]
pub(crate) fn led_state(
    poll_enabled: bool,
    live_beat_unix: Option<u64>,
    now_unix: u64,
    flash_age_seconds: Option<f64>,
) -> LedState {
    if !poll_enabled {
        return LedState::Off;
    }
    let Some(beat_unix) = live_beat_unix else {
        return LedState::Off;
    };
    if now_unix.saturating_sub(beat_unix) > POLL_STALE_SECONDS {
        return LedState::Stalled;
    }
    match flash_age_seconds {
        Some(age) if (0.0..LED_FLASH_SECONDS).contains(&age) => LedState::Flash,
        _ => LedState::Steady,
    }
}

/// How the process table is ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SortKey {
    Name,
    Pid,
    User,
    Started,
}

impl SortKey {
    const ALL: [SortKey; 4] = [SortKey::Name, SortKey::Pid, SortKey::User, SortKey::Started];

    fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Pid => "PID",
            Self::User => "User",
            Self::Started => "Started",
        }
    }
}

/// The quick filters above the process table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessFilter {
    All,
    Listening,
    NoPath,
    Scratch,
}

impl ProcessFilter {
    const ALL: [ProcessFilter; 4] = [
        ProcessFilter::All,
        ProcessFilter::Listening,
        ProcessFilter::NoPath,
        ProcessFilter::Scratch,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Listening => "Listening",
            Self::NoPath => "No path",
            Self::Scratch => "Temp or downloads",
        }
    }
}

/// How findings are ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FindingSort {
    Severity,
    Rule,
    Subject,
}

impl FindingSort {
    const ALL: [FindingSort; 3] = [FindingSort::Severity, FindingSort::Rule, FindingSort::Subject];

    fn label(self) -> &'static str {
        match self {
            Self::Severity => "Severity",
            Self::Rule => "Rule",
            Self::Subject => "Subject",
        }
    }
}

/// Which sources the Changes view shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChangeFilter {
    All,
    Processes,
    Startup,
    Network,
    Files,
    Rules,
}

impl ChangeFilter {
    const ALL: [ChangeFilter; 6] = [
        ChangeFilter::All,
        ChangeFilter::Processes,
        ChangeFilter::Startup,
        ChangeFilter::Network,
        ChangeFilter::Files,
        ChangeFilter::Rules,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Processes => "Processes",
            Self::Startup => "Startup",
            Self::Network => "Network",
            Self::Files => "Files",
            Self::Rules => "Rules",
        }
    }
}

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
    /// When the last poll arrived, on egui's clock. `None` until one has.
    led_flash: Option<f64>,
    project_open: bool,
    project_rect: egui::Rect,
    suppress_target: Option<vnr_core::Finding>,
    suppress_reason: String,
    /// Which quarantine entry is waiting for its word, and what has been typed.
    purge_ask: crate::act::PurgeAsk,
    /// What the clean card has ticked, and against which dry run.
    clean: crate::clean::CleanState,
    finding_severity: Option<vnr_core::Severity>,
    finding_query: String,
    finding_sort: FindingSort,
    process_sort: SortKey,
    process_sort_desc: bool,
    process_filter: ProcessFilter,
    autorun_scope: Option<vnr_core::AutorunScope>,
    show_disabled: bool,
    change_filter: ChangeFilter,
    palette_open: bool,
    palette_query: String,
    palette_index: usize,
    watch_new: String,
    error_seen: Option<(String, u64)>,
    error_dismissed: Option<String>,
    /// The application mark: the crystal on its ink tile, the same bytes the window icon uses.
    mark: egui::TextureHandle,
}

/// One row in the command palette.
struct PaletteEntry {
    label: String,
    hit: PaletteHit,
}

/// What choosing a palette row does.
enum PaletteHit {
    View(View),
    Process(u32),
    Autorun(String),
    Finding(String),
    Action(Action),
}

/// Upload one of the embedded marks as a texture.
///
/// A mark that is the wrong size is a one-pixel transparent texture rather than a panic: an
/// asset edited by hand should cost the picture, not the window.
fn upload(ctx: &egui::Context, name: &str, rgba: &[u8]) -> egui::TextureHandle {
    const SIDE: usize = 64;
    let image = if rgba.len() == SIDE * SIDE * 4 {
        egui::ColorImage::from_rgba_unmultiplied([SIDE, SIDE], rgba)
    } else {
        egui::ColorImage::from_rgba_unmultiplied([1, 1], &[0, 0, 0, 0])
    };
    ctx.load_texture(name, image, egui::TextureOptions::LINEAR)
}

impl Ui {
    /// Build the interface and upload the application mark once.
    ///
    /// One mark for both themes: the crystal on the suite's ink tile, which is what the
    /// window icon is built from too. The tile reads on paper as well as on ink, so the top
    /// bar does not have to swap artwork when the theme changes.
    #[must_use]
    pub fn new(ctx: &egui::Context) -> Self {
        fonts::install(ctx);
        let mark = upload(
            ctx,
            "vn-ranger-mark",
            include_bytes!("../../../assets/logo/vn-ranger-app.rgba"),
        );
        Self {
            view: View::Overview,
            last_view: View::Overview,
            search: String::new(),
            selected_process: None,
            selected_autorun: None,
            only_public: false,
            confirm_elevate: false,
            // Paper is what a new installation opens on. Dark is one click away in the top
            // bar, and the choice is remembered once it is made.
            dark: false,
            open_path: None,
            led_flash: None,
            project_open: false,
            project_rect: egui::Rect::NOTHING,
            suppress_target: None,
            suppress_reason: String::new(),
            purge_ask: crate::act::PurgeAsk::default(),
            clean: crate::clean::CleanState::default(),
            finding_severity: None,
            finding_query: String::new(),
            finding_sort: FindingSort::Severity,
            process_sort: SortKey::Name,
            process_sort_desc: false,
            process_filter: ProcessFilter::All,
            autorun_scope: None,
            show_disabled: true,
            change_filter: ChangeFilter::All,
            palette_open: false,
            palette_query: String::new(),
            palette_index: 0,
            watch_new: String::new(),
            error_seen: None,
            error_dismissed: None,
            mark,
        }
    }

    /// Record that a poll just arrived, so the indicator flashes on this frame.
    ///
    /// The flash is a timestamp rather than a toggle, and one repaint is asked for so the
    /// flash ends even when nothing else is drawing. A toggle would read as a metronome
    /// and would keep looking alive after the thread that feeds it had stopped.
    pub fn note_poll(&mut self, ctx: &egui::Context) {
        self.led_flash = Some(ctx.input(|input| input.time));
        ctx.request_repaint_after(std::time::Duration::from_secs_f64(LED_FLASH_SECONDS));
    }

    /// Apply the theme loaded from the settings file.
    pub fn set_dark(&mut self, dark: bool) {
        self.dark = dark;
    }

    /// Apply the view loaded from the settings file.
    pub fn set_view(&mut self, view: View) {
        self.view = view;
    }

    /// The theme currently on screen.
    #[must_use]
    pub fn is_dark(&self) -> bool {
        self.dark
    }

    /// Draw one frame and return what the person asked for.
    pub fn show(&mut self, root: &mut egui::Ui, world: &World) -> Vec<Action> {
        let ctx = root.ctx().clone();
        theme::apply(&ctx, self.dark);
        let mut actions = Vec::new();
        if ctx.input_mut(|input| {
            input.consume_key(egui::Modifiers::COMMAND, egui::Key::K)
                || input.consume_key(egui::Modifiers::CTRL, egui::Key::K)
        }) {
            self.palette_open = !self.palette_open;
            self.palette_query.clear();
            self.palette_index = 0;
            if self.palette_open {
                let id = palette_input_id();
                ctx.memory_mut(|memory| memory.request_focus(id));
            }
        }
        if self.palette_open
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.palette_open = false;
        }
        if !self.palette_open
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.selected_process = None;
            self.selected_autorun = None;
        }
        let view_changed = self.last_view != self.view;
        self.last_view = self.view;
        self.top_bar(root, world, &mut actions);
        self.rail(root, world);
        let view_before_draw = self.view;
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
                if matches!(
                    view,
                    View::Processes | View::Startup | View::Listeners | View::Findings
                ) {
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
        if self.view != view_before_draw {
            actions.push(Action::SetView(self.view));
        }
        if let Some(path) = self.open_path.take() {
            actions.push(Action::OpenPath(path));
        }
        self.modal(&ctx, &mut actions);
        self.project_modal(&ctx);
        self.suppress_modal(&ctx, &mut actions);
        self.palette(&ctx, world, &mut actions);
        self.toast(&ctx, world);
        actions
    }

    fn draw_view(&mut self, ui: &mut egui::Ui, world: &World, actions: &mut Vec<Action>, view: View) {
        match view {
            View::Overview => self.overview(ui, world, actions),
            View::Findings => self.findings(ui, world, actions),
            View::Processes => self.processes(ui, world),
            View::Startup => self.startup(ui, world, actions),
            View::Listeners => self.listeners(ui, world),
            View::Changes => self.changes(ui, world, actions),
            View::Actions => act::view(ui, world, &mut self.purge_ask, &mut self.clean, actions),
            View::Report => self.report(ui, world, actions),
            View::Settings => self.settings(ui, world, actions),
        }
    }

    fn top_bar(&mut self, root: &mut egui::Ui, world: &World, actions: &mut Vec<Action>) {
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
                        let project = project_button(ui).on_hover_text("About this project");
                        self.project_rect = project.rect;
                        if project.clicked() {
                            self.project_open = true;
                        }
                        let scan = ui.add_enabled(
                            !world.busy(),
                            egui::Button::new(
                                RichText::new("Scan now")
                                    .size(12.5)
                                    .family(theme::semibold())
                                    .color(theme::ON_EMBER),
                            )
                            .fill(theme::EMBER)
                            .min_size(vec2(0.0, ACTION_HEIGHT)),
                        );
                        if scan.clicked() {
                            actions.push(Action::Scan);
                        }
                        if world.poll_enabled && world.poll_led {
                            let now = ui.input(|input| input.time);
                            let state = led_state(
                                world.poll_enabled,
                                world.live.as_ref().map(|live| live.at_unix),
                                world.now_unix,
                                self.led_flash.map(|at| now - at),
                            );
                            poll_led(ui, state);
                        }
                        match &world.scan {
                            ScanState::Running(step) => {
                                ui.spinner();
                                ui.label(RichText::new(step.as_str()).size(11.5).color(theme::muted(ui)));
                                if ui
                                    .add(egui::Button::new(RichText::new("Cancel").size(10.5)).frame(false))
                                    .on_hover_text("Stop after the collector that is running now.")
                                    .clicked()
                                {
                                    actions.push(Action::CancelScan);
                                }
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

    fn project_modal(&mut self, ctx: &egui::Context) {
        if !self.project_open {
            return;
        }
        let mut open = true;
        egui::Window::new("About vn-ranger")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(
                        self.mark.id(),
                        vec2(56.0, 56.0),
                    )));
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("vn-ranger")
                                .size(16.0)
                                .family(theme::semibold()),
                        );
                        ui.label(
                            RichText::new("A quiet ranger for your machine.")
                                .size(11.5)
                                .color(theme::muted(ui)),
                        );
                    });
                });
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Project page")
                        .size(10.5)
                        .color(theme::muted(ui)),
                );
                ui.add(
                    egui::Label::new(
                        RichText::new(PROJECT_URL)
                            .size(12.5)
                            .monospace()
                            .color(ui.visuals().strong_text_color()),
                    )
                    .wrap()
                    .selectable(true),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "Select the address to copy it. Ranger does not open a browser and makes no request of its own.",
                    )
                    .size(10.5)
                    .color(theme::muted(ui)),
                );
                ui.add_space(10.0);
                if ui.button("Close").clicked() {
                    self.project_open = false;
                }
            });
        if !open {
            self.project_open = false;
        }
    }

    fn palette(&mut self, ctx: &egui::Context, world: &World, actions: &mut Vec<Action>) {
        if !self.palette_open {
            return;
        }
        let needle = self.palette_query.trim().to_lowercase();
        let mut entries = self.palette_entries(world);
        if !needle.is_empty() {
            entries.retain(|entry| entry.label.to_lowercase().contains(&needle));
            entries.sort_by_key(|entry| !entry.label.to_lowercase().starts_with(&needle));
        }
        entries.truncate(10);
        if self.palette_index >= entries.len() {
            self.palette_index = entries.len().saturating_sub(1);
        }

        let down = ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown));
        let up = ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp));
        if down && !entries.is_empty() {
            self.palette_index = (self.palette_index + 1) % entries.len();
        }
        if up {
            self.palette_index = self.palette_index.saturating_sub(1);
        }
        let mut chosen = ctx
            .input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
            .then_some(self.palette_index);

        let mut open = true;
        let palette_index = self.palette_index;
        let query = &mut self.palette_query;
        egui::Window::new("Command palette")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_TOP, vec2(0.0, 90.0))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_width(520.0);
                let id = palette_input_id();
                let response = ui.add(
                    egui::TextEdit::singleline(query)
                        .id(id)
                        .hint_text("Go to a view, a process, a startup item, a finding or an action")
                        .margin(Margin::symmetric(10, 8)),
                );
                if !response.has_focus() && ctx.memory(|memory| memory.focused().is_none()) {
                    response.request_focus();
                }
                ui.add_space(6.0);
                for (index, entry) in entries.iter().enumerate() {
                    let selected = index == palette_index;
                    let response = ui.add(
                        egui::Button::new(RichText::new(entry.label.as_str()).size(12.0).color(
                            if selected {
                                ui.visuals().strong_text_color()
                            } else {
                                ui.visuals().text_color()
                            },
                        ))
                        .fill(if selected {
                            ui.visuals().selection.bg_fill
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .frame(false)
                        .min_size(vec2(ui.available_width(), 26.0)),
                    );
                    if response.clicked() {
                        chosen = Some(index);
                    }
                    if response.hovered() {
                        self.palette_index = index;
                    }
                }
                if entries.is_empty() {
                    ui.label(
                        RichText::new("Nothing matches.")
                            .size(11.0)
                            .color(theme::muted(ui)),
                    );
                }
            });
        if !open {
            self.palette_open = false;
        }
        if let Some(index) = chosen
            && let Some(entry) = entries.get(index)
        {
            match &entry.hit {
                PaletteHit::View(view) => self.view = *view,
                PaletteHit::Process(pid) => {
                    self.view = View::Processes;
                    self.selected_process = Some(*pid);
                    self.search.clear();
                }
                PaletteHit::Autorun(id) => {
                    self.view = View::Startup;
                    self.selected_autorun = Some(id.clone());
                    self.search.clear();
                }
                PaletteHit::Finding(title) => {
                    self.view = View::Findings;
                    self.finding_query = title.clone();
                    self.finding_severity = None;
                }
                PaletteHit::Action(action) => actions.push(action.clone()),
            }
            self.palette_open = false;
        }
    }

    fn palette_entries(&self, world: &World) -> Vec<PaletteEntry> {
        let mut entries: Vec<PaletteEntry> = View::ALL
            .iter()
            .map(|view| PaletteEntry {
                label: format!("Go to {}", view.label()),
                hit: PaletteHit::View(*view),
            })
            .collect();
        for process in world.processes().iter().take(200) {
            entries.push(PaletteEntry {
                label: format!("Process · {} (pid {})", process.name, process.pid),
                hit: PaletteHit::Process(process.pid),
            });
        }
        if let Some(snapshot) = world.snapshot() {
            for autorun in snapshot.autoruns.iter().take(200) {
                entries.push(PaletteEntry {
                    label: format!("Startup · {} ({})", autorun.name, autorun.kind.label()),
                    hit: PaletteHit::Autorun(autorun.id.clone()),
                });
            }
        }
        for finding in world.findings.iter().take(100) {
            entries.push(PaletteEntry {
                label: format!("Finding · {}", finding.title),
                hit: PaletteHit::Finding(finding.title.to_owned()),
            });
        }
        let actions = [
            ("Run a scan", Action::Scan),
            ("Export JSON", Action::ExportJson),
            ("Export Markdown", Action::ExportMarkdown),
            ("Export findings as JSON", Action::ExportFindingsJson),
            ("Accept this scan as the baseline", Action::AcceptBaseline),
            ("Open the data folder", Action::OpenDataDir),
            ("Toggle the theme", Action::SetDark(!self.dark)),
            ("Quit ranger", Action::Quit),
        ];
        for (label, action) in actions {
            entries.push(PaletteEntry {
                label: label.to_owned(),
                hit: PaletteHit::Action(action),
            });
        }
        entries
    }

    fn toast(&mut self, ctx: &egui::Context, world: &World) {
        let Some(error) = world.error.clone() else {
            self.error_seen = None;
            self.error_dismissed = None;
            return;
        };
        let now = world.now_unix;
        match &mut self.error_seen {
            Some((text, at)) if *text == error => {
                if now.saturating_sub(*at) > 10 {
                    return;
                }
            }
            _ => {
                self.error_seen = Some((error.clone(), now));
                self.error_dismissed = None;
            }
        }
        if self.error_dismissed.as_deref() == Some(error.as_str()) {
            return;
        }
        let mut dismiss = false;
        egui::Area::new(toast_id())
            .anchor(Align2::RIGHT_TOP, vec2(-16.0, 72.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(theme::panel(self.dark))
                    .stroke(egui::Stroke::new(1.0, theme::BAD))
                    .corner_radius(egui::CornerRadius::same(8))
                    .inner_margin(Margin::same(10))
                    .show(ui, |ui| {
                        ui.set_max_width(380.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(error.as_str()).size(11.5).color(theme::BAD));
                            if ui.small_button("✕").clicked() {
                                dismiss = true;
                            }
                        });
                    });
            });
        if dismiss {
            self.error_dismissed = Some(error);
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }

    fn suppress_modal(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        let Some(finding) = self.suppress_target.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new("Suppress a finding")
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(440.0);
                ui.label(
                    RichText::new(finding.title)
                        .size(12.5)
                        .family(theme::semibold()),
                );
                ui.label(
                    RichText::new(finding.subject_label.as_str())
                        .size(10.5)
                        .color(theme::muted(ui)),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "This hides one rule for one subject until it expires. It carries your reason, expires after 30 days, and hides nothing else.",
                    )
                    .size(11.0)
                    .color(theme::muted(ui)),
                );
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.suppress_reason)
                        .hint_text("Why is this expected?")
                        .margin(Margin::symmetric(8, 6)),
                );
                ui.add_space(6.0);
                let valid = self.suppress_reason.trim().len() >= 4;
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(valid, egui::Button::new("Suppress for 30 days"))
                        .clicked()
                    {
                        actions.push(Action::SuppressFinding {
                            rule_id: finding.rule_id.to_owned(),
                            subject: finding.subject.clone(),
                            reason: self.suppress_reason.trim().to_owned(),
                        });
                        self.suppress_target = None;
                        self.suppress_reason.clear();
                    }
                    if ui.button("Cancel").clicked() {
                        self.suppress_target = None;
                        self.suppress_reason.clear();
                    }
                });
            });
        if !open {
            self.suppress_target = None;
            self.suppress_reason.clear();
        }
    }
}

fn project_button(ui: &mut egui::Ui) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(vec2(ACTION_HEIGHT, ACTION_HEIGHT), Sense::click());
    let painter = ui.painter();
    let fill = if response.hovered() {
        ui.visuals().widgets.hovered.bg_fill
    } else {
        ui.visuals().widgets.inactive.bg_fill
    };
    painter.circle_filled(rect.center(), ACTION_HEIGHT / 2.0, fill);
    painter.circle_stroke(
        rect.center(),
        ACTION_HEIGHT / 2.0 - 0.5,
        egui::Stroke::new(1.0, theme::border(ui)),
    );
    icons::paint(
        painter,
        rect.shrink(ACTION_HEIGHT * 0.28),
        icons::Icon::External,
        if response.hovered() {
            ui.visuals().strong_text_color()
        } else {
            theme::muted(ui)
        },
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn poll_led(ui: &mut egui::Ui, state: LedState) {
    let (rect, response) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
    let center = rect.center();
    let painter = ui.painter();
    match state {
        LedState::Flash => {
            painter.circle_filled(center, 7.5, theme::OK.gamma_multiply(0.18));
            painter.circle_filled(center, 3.5, theme::OK);
        }
        LedState::Steady => {
            painter.circle_filled(center, 3.5, theme::OK.gamma_multiply(0.72));
        }
        LedState::Stalled => {
            painter.circle_filled(center, 7.5, theme::ATTENTION.gamma_multiply(0.18));
            painter.circle_filled(center, 3.5, theme::ATTENTION);
        }
        LedState::Off => {
            painter.circle_filled(center, 2.5, theme::OK.gamma_multiply(0.35));
        }
    }
    let _ = response.on_hover_text(match state {
        LedState::Flash | LedState::Steady => {
            "The process poll is running: one beat every two seconds, and the dot flashes as each poll arrives."
        }
        LedState::Stalled => {
            "No process poll for more than six seconds. The background thread may have stopped; the window still shows the last one."
        }
        LedState::Off => "The process poll is off, or has not reported yet.",
    });
}

fn view_icon(view: View) -> icons::Icon {
    match view {
        View::Overview => icons::Icon::Overview,
        View::Findings => icons::Icon::Shield,
        View::Processes => icons::Icon::Processes,
        View::Startup => icons::Icon::Startup,
        View::Listeners => icons::Icon::Listeners,
        View::Changes => icons::Icon::Changes,
        View::Actions => icons::Icon::Shield,
        View::Report => icons::Icon::Report,
        View::Settings => icons::Icon::Settings,
    }
}

#[allow(deprecated)]
fn palette_input_id() -> egui::Id {
    egui::Id::new("palette-input")
}

#[allow(deprecated)]
fn toast_id() -> egui::Id {
    egui::Id::new("error-toast")
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
            poll_led: true,
            watch: WatchReport::default(),
            tray: TrayState::Present,
            paused: false,
            close_to_tray: false,
            autostart: AutostartState::Off,
            skip_on_battery: false,
            baseline,
            baseline_error: None,
            changes,
            timeline: Timeline::new(),
            findings: Vec::new(),
            suppressions: Vec::new(),
            watch_extra: Vec::new(),
            quarantine: Vec::new(),
            clean: None,
            journal: Vec::new(),
            journal_damaged: false,
        }
    }

    fn clean_report() -> CleanReport {
        CleanReport {
            run: 7,
            surfaces: vec![
                CleanSurface {
                    id: "win.temp".to_owned(),
                    label: "Temporary files".to_owned(),
                    roots: 2,
                    opt_in: false,
                    items: vec![
                        CleanItem {
                            path: "C:\\Temp\\a.tmp".to_owned(),
                            bytes: 4_096,
                            is_dir: false,
                        },
                        CleanItem {
                            path: "C:\\Temp\\empty".to_owned(),
                            bytes: 0,
                            is_dir: true,
                        },
                    ],
                    ..CleanSurface::default()
                },
                CleanSurface {
                    id: "mac.logs".to_owned(),
                    label: "User logs".to_owned(),
                    roots: 1,
                    opt_in: true,
                    items: vec![CleanItem {
                        path: "C:\\Logs\\old.log".to_owned(),
                        bytes: 9_000,
                        is_dir: false,
                    }],
                    ..CleanSurface::default()
                },
            ],
            cancelled: false,
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
    fn the_clean_card_draws_its_list() {
        let mut world = base_world(None, None);
        let report = clean_report();
        world.clean = Some(report.clone());
        egui::__run_test_ui(|root| {
            let ctx = root.ctx().clone();
            let mut ui = Ui::new(&ctx);
            ui.view = View::Actions;
            ui.clean.begin(&report);
            ui.clean.toggle_open("win.temp");
            let actions = ui.show(root, &world);
            assert!(actions.is_empty(), "drawing a list asks for nothing on its own");
        });
    }

    #[test]
    fn the_clean_confirmation_draws_and_dispatches_nothing_until_clicked() {
        let mut world = base_world(None, None);
        let report = clean_report();
        world.clean = Some(report.clone());
        egui::__run_test_ui(|root| {
            let ctx = root.ctx().clone();
            let mut ui = Ui::new(&ctx);
            ui.view = View::Actions;
            ui.clean.begin(&report);
            ui.clean.ask();
            let actions = ui.show(root, &world);
            assert!(actions.is_empty(), "a confirmation is a question, not an act");
        });
    }

    #[test]
    fn a_close_hides_only_when_it_can_be_undone() {
        let mut world = base_world(None, None);
        assert!(
            !world.hide_on_close(false),
            "off by default: a close button closes"
        );

        world.close_to_tray = true;
        assert!(world.hide_on_close(false), "on, with a tray to come back from");

        assert!(
            !world.hide_on_close(true),
            "a quit is a quit, even with close-to-tray on"
        );

        world.tray = TrayState::Absent("no status area".to_owned());
        assert!(
            !world.hide_on_close(false),
            "a window hidden with no tray is a process nobody can reach"
        );

        world.tray = TrayState::Unknown;
        assert!(!world.hide_on_close(false), "an unknown tray is not a tray");
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
        world.findings.push(vnr_core::Finding {
            rule_id: "startup.temp-path",
            title: "A startup item runs from a temporary folder",
            severity: vnr_core::Severity::Attention,
            confidence: vnr_core::Confidence::Observed,
            subject: "autorun:run:user:Agent".to_owned(),
            subject_label: "Agent (Run key)".to_owned(),
            evidence: vec!["Executable: C:\\Temp\\agent.exe".to_owned()],
            why: "Temporary folders are cleaned by the system.",
            benign: "An installer registered a helper.",
            remediation: "Check the file's publisher.",
        });
        world.suppressions.push(vnr_core::Suppression {
            rule_id: "startup.temp-path".to_owned(),
            subject: "autorun:run:user:Other".to_owned(),
            reason: "Known updater".to_owned(),
            expires_unix: 2_000,
        });
        for view in View::ALL {
            draw(view, &world);
        }
    }

    fn screen_input(events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, vec2(1180.0, 780.0))),
            events,
            ..Default::default()
        }
    }

    fn frame(ctx: &egui::Context, ui: &mut Ui, world: &World, input: egui::RawInput) -> Vec<Action> {
        let mut actions = Vec::new();
        let output = ctx.run_pass(input, |ctx| {
            let mut root = egui::Ui::new(
                ctx.clone(),
                egui::Id::unique("root"),
                egui::UiBuilder::new().max_rect(ctx.viewport_rect()),
            );
            actions = ui.show(&mut root, world);
        });
        output.drop_without_applying_deltas();
        actions
    }

    fn press(center: egui::Pos2, pressed: bool) -> egui::Event {
        egui::Event::PointerButton {
            pos: center,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        }
    }

    #[test]
    fn the_project_button_returns_its_action() {
        let ctx = egui::Context::default();
        let mut ui = Ui::new(&ctx);
        let world = base_world(None, None);

        let _ = frame(&ctx, &mut ui, &world, screen_input(Vec::new()));
        let center = ui.project_rect.center();
        assert_ne!(
            ui.project_rect,
            egui::Rect::NOTHING,
            "the circle was laid out in the top bar"
        );

        let _ = frame(
            &ctx,
            &mut ui,
            &world,
            screen_input(vec![egui::Event::PointerMoved(center), press(center, true)]),
        );
        let _ = frame(&ctx, &mut ui, &world, screen_input(vec![press(center, false)]));
        assert!(ui.project_open, "clicking the circle must open the project modal");
        // The modal itself draws without a panic on the next frame.
        let _ = frame(&ctx, &mut ui, &world, screen_input(Vec::new()));
    }

    #[test]
    fn the_indicator_is_off_when_the_poll_is_off_or_has_not_reported() {
        assert_eq!(led_state(false, Some(100), 100, Some(0.0)), LedState::Off);
        assert_eq!(led_state(true, None, 100, None), LedState::Off);
    }

    #[test]
    fn a_fresh_beat_flashes_and_then_goes_quiet() {
        assert_eq!(led_state(true, Some(100), 100, Some(0.0)), LedState::Flash);
        assert_eq!(led_state(true, Some(100), 100, Some(0.2)), LedState::Flash);
        assert_eq!(led_state(true, Some(100), 100, Some(0.5)), LedState::Steady);
        assert_eq!(led_state(true, Some(100), 101, None), LedState::Steady);
    }

    #[test]
    fn three_missed_beats_are_reported_as_stalled() {
        assert_eq!(led_state(true, Some(100), 106, Some(9.0)), LedState::Steady);
        assert_eq!(led_state(true, Some(100), 107, Some(0.0)), LedState::Stalled);
    }

    #[test]
    fn a_backwards_clock_is_not_a_fault() {
        assert_eq!(led_state(true, Some(200), 100, Some(0.0)), LedState::Flash);
    }
}
