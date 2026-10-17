//! The window's owner: the world, the worker, and the actions it carries out.

use std::path::Path;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vnr_core::{EventKind, TimelineEvent};
use vnr_ui::{Action, Live, ScanState, Ui, WatchReport, World};

use crate::worker::{self, ScanMessage};

/// The eframe application.
pub struct App {
    ui: Ui,
    world: World,
    receiver: Option<Receiver<ScanMessage>>,
    watch: worker::WatchService,
}

impl App {
    /// Build the world from the last snapshot and start the first scan if there is
    /// nothing to show.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let snapshot = vnr_native::store::load_last();
        let (baseline, baseline_error) = match vnr_native::store::read_baseline() {
            vnr_native::store::BaselineLoad::Present(snapshot) => (Some(*snapshot), None),
            vnr_native::store::BaselineLoad::Unreadable(reason) => (None, Some(reason)),
            vnr_native::store::BaselineLoad::Missing => (None, None),
        };
        let changes = match (&baseline, &snapshot) {
            (Some(baseline), Some(snapshot)) => vnr_core::diff_snapshots(baseline, snapshot),
            _ => Vec::new(),
        };
        let world = World {
            snapshot,
            scan: ScanState::Idle,
            error: None,
            notice: None,
            elevated: vnr_native::elevation::is_elevated(),
            can_elevate: vnr_native::elevation::can_elevate(),
            data_dir: vnr_native::paths::data_dir(),
            signatures_dir: vnr_native::paths::signatures_dir(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            now_unix: now_unix(),
            live: None,
            poll_enabled: true,
            poll_led: true,
            watch: WatchReport {
                enabled: true,
                ..WatchReport::default()
            },
            baseline,
            baseline_error,
            changes,
            timeline: vnr_core::Timeline::new(),
        };
        let ui = Ui::new(&cc.egui_ctx);
        let watch = worker::WatchService::start(cc.egui_ctx.clone());
        let mut app = Self {
            ui,
            world,
            receiver: None,
            watch,
        };
        if app.world.snapshot.is_none() {
            app.start_scan(&cc.egui_ctx, false);
        }
        app
    }

    fn start_scan(&mut self, ctx: &egui::Context, elevated: bool) {
        if self.world.busy() {
            return;
        }
        self.world.error = None;
        self.world.notice = None;
        self.world.scan = ScanState::Running(if elevated {
            "Waiting for Windows consent".to_owned()
        } else {
            "Starting".to_owned()
        });
        self.receiver = Some(if elevated {
            worker::spawn_elevated_scan(ctx.clone())
        } else {
            worker::spawn_scan(ctx.clone())
        });
    }

    fn drain(&mut self) {
        let mut messages = Vec::new();
        let mut disconnected = false;
        if let Some(receiver) = &self.receiver {
            loop {
                match receiver.try_recv() {
                    Ok(message) => messages.push(message),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        if disconnected {
            // A worker that sends `Done` and then exits is the normal path. Only a
            // channel that closes without a terminal message is a failure.
            let terminal = messages
                .iter()
                .any(|message| matches!(message, ScanMessage::Done(_) | ScanMessage::Failed(_)));
            if !terminal {
                messages.push(ScanMessage::Failed(
                    "The scan worker stopped unexpectedly. The window is still open; run the scan again."
                        .to_owned(),
                ));
            }
        }
        let mut finished = false;
        for message in messages {
            match message {
                ScanMessage::Progress(step) => {
                    self.world.scan = ScanState::Running(step.to_owned());
                }
                ScanMessage::Done(snapshot) => {
                    let snapshot = *snapshot;
                    if let Err(error) = vnr_native::store::save_last(&snapshot) {
                        self.world.error =
                            Some(format!("The scan finished, but it could not be saved: {error}"));
                    }
                    let changes = self
                        .world
                        .baseline
                        .as_ref()
                        .map_or_else(Vec::new, |baseline| vnr_core::diff_snapshots(baseline, &snapshot));
                    self.world.changes = changes;
                    self.world.snapshot = Some(snapshot);
                    self.world.scan = ScanState::Idle;
                    self.world.notice = None;
                    finished = true;
                }
                ScanMessage::Failed(error) => {
                    self.world.scan = ScanState::Idle;
                    self.world.error = Some(error);
                    finished = true;
                }
            }
        }
        if finished {
            self.receiver = None;
        }
    }

    fn drain_watch(&mut self) {
        while let Some(message) = self.watch.try_recv() {
            match message {
                worker::WatchMessage::Processes {
                    items,
                    reason,
                    at_unix,
                } => {
                    self.world.live = Some(Live {
                        items,
                        at_unix,
                        reason,
                    });
                    self.ui.note_poll();
                }
                worker::WatchMessage::Events(events) => {
                    for event in events {
                        self.world.timeline.push(event);
                    }
                }
                worker::WatchMessage::Watching { roots, skipped } => {
                    self.world.watch.roots = roots;
                    self.world.watch.skipped = skipped;
                    self.world.watch.error = None;
                }
                worker::WatchMessage::WatchFailed(reason) => {
                    self.world.watch.roots.clear();
                    self.world.watch.skipped.clear();
                    self.world.watch.error = Some(reason);
                }
            }
        }
    }

    fn accept_baseline(&mut self) {
        let Some(snapshot) = self.world.snapshot.clone() else {
            self.world.error = Some("There is no scan to accept yet.".to_owned());
            return;
        };
        match vnr_native::store::save_baseline(&snapshot) {
            Ok(()) => {
                self.world.timeline.push(TimelineEvent::new(
                    now_unix(),
                    EventKind::BaselineAccepted,
                    "This scan",
                    format!(
                        "{} processes · {} startup items",
                        snapshot.processes.len(),
                        snapshot.autoruns.len()
                    ),
                    "baseline",
                ));
                self.world.baseline = Some(snapshot);
                self.world.baseline_error = None;
                self.world.changes.clear();
                self.world.error = None;
                self.world.notice =
                    Some("This scan is now the baseline. Later scans are compared against it.".to_owned());
            }
            Err(error) => {
                self.world.error = Some(format!("Could not write the baseline: {error}"));
            }
        }
    }

    fn clear_baseline(&mut self) {
        let path = vnr_native::paths::baseline_path();
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                self.world.error = Some(format!("Could not remove the baseline: {error}"));
                return;
            }
        }
        self.world.baseline = None;
        self.world.baseline_error = None;
        self.world.changes.clear();
        self.world.error = None;
        self.world.notice = Some(
            "The baseline was cleared. Ranger has nothing to compare against until you accept one."
                .to_owned(),
        );
    }

    fn apply(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::Scan => self.start_scan(ctx, false),
            Action::ScanElevated => self.start_scan(ctx, true),
            Action::ExportJson => self.export_json(),
            Action::ExportMarkdown => self.export_markdown(),
            Action::OpenDataDir => self.open(&vnr_native::paths::data_dir()),
            Action::OpenSignaturesDir => {
                let directory = vnr_native::paths::signatures_dir();
                if let Err(error) = vnr_native::paths::ensure_dir(&directory) {
                    self.world.error = Some(format!("Could not create the signatures folder: {error}"));
                    return;
                }
                self.open(&directory);
            }
            Action::SelfTest => match vnr_native::signatures::self_test() {
                Ok(name) => {
                    self.world.notice = Some(format!("Signature self-test passed: {name}."));
                    self.world.error = None;
                }
                Err(error) => self.world.error = Some(error),
            },
            Action::OpenPath(path) => self.open(Path::new(&path)),
            Action::AcceptBaseline => self.accept_baseline(),
            Action::ClearBaseline => self.clear_baseline(),
            Action::SetPoll(enabled) => {
                self.world.poll_enabled = enabled;
                self.watch.set_poll(enabled);
            }
            Action::SetWatch(enabled) => {
                self.world.watch.enabled = enabled;
                self.watch.set_watch(enabled);
                if !enabled {
                    self.world.watch.roots.clear();
                    self.world.watch.skipped.clear();
                }
            }
            Action::SetPollLed(enabled) => self.world.poll_led = enabled,
            Action::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        }
    }

    fn export_json(&mut self) {
        let Some(snapshot) = self.world.snapshot.clone() else {
            self.world.error = Some("Nothing has been scanned yet.".to_owned());
            return;
        };
        let path = vnr_native::paths::report_path("json");
        match vnr_native::store::write_json(&snapshot, &path) {
            Ok(()) => {
                self.world.error = None;
                self.world.notice = Some(format!("JSON written to {}", path.display()));
            }
            Err(error) => self.world.error = Some(format!("Could not write the JSON report: {error}")),
        }
    }

    fn export_markdown(&mut self) {
        let Some(snapshot) = self.world.snapshot.clone() else {
            self.world.error = Some("Nothing has been scanned yet.".to_owned());
            return;
        };
        let path = vnr_native::paths::report_path("md");
        let body = vnr_core::report::to_markdown(&snapshot);
        match vnr_native::store::write_markdown(&body, &path) {
            Ok(()) => {
                self.world.error = None;
                self.world.notice = Some(format!("Markdown written to {}", path.display()));
            }
            Err(error) => {
                self.world.error = Some(format!("Could not write the Markdown report: {error}"));
            }
        }
    }

    fn open(&mut self, path: &Path) {
        if let Err(error) = opener::open(path) {
            self.world.error = Some(format!("Could not open {}: {error}", path.display()));
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.world.now_unix = now_unix();
        self.drain();
        self.drain_watch();
        let actions = self.ui.show(ui, &self.world);
        for action in actions {
            self.apply(action, &ctx);
        }
        if self.world.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
