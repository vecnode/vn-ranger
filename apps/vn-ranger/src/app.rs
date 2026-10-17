//! The window's owner: the world, the worker, and the actions it carries out.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vnr_core::{EventKind, Finding, Suppression, TimelineEvent};
use vnr_ui::{Action, Live, ScanState, Ui, WatchReport, World};

use crate::worker::{self, ScanMessage};

/// The eframe application.
pub struct App {
    ui: Ui,
    world: World,
    receiver: Option<Receiver<ScanMessage>>,
    watch: worker::WatchService,
    settings: vnr_native::store::UiSettings,
    instance: Option<vnr_native::instance::InstanceGuard>,
    cancel: Option<Arc<AtomicBool>>,
}

impl App {
    /// Build the world from the last snapshot and start the first scan if there is
    /// nothing to show.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = vnr_native::store::load_ui_settings();
        let (instance, instance_error) = match vnr_native::instance::acquire() {
            Ok(guard) => (Some(guard), None),
            Err(message) => (None, Some(message)),
        };
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
        let suppressions = vnr_native::store::load_suppressions(now_unix());
        let findings = findings_for(snapshot.as_ref(), baseline.as_ref(), &suppressions, now_unix());
        let watch_extra = vnr_native::store::load_watch_roots();
        let world = World {
            snapshot,
            scan: ScanState::Idle,
            error: instance_error,
            notice: None,
            elevated: vnr_native::elevation::is_elevated(),
            can_elevate: vnr_native::elevation::can_elevate(),
            data_dir: vnr_native::paths::data_dir(),
            signatures_dir: vnr_native::paths::signatures_dir(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            now_unix: now_unix(),
            live: None,
            poll_enabled: settings.poll.unwrap_or(true),
            poll_led: settings.led.unwrap_or(true),
            watch: WatchReport {
                enabled: settings.watch.unwrap_or(true),
                ..WatchReport::default()
            },
            baseline,
            baseline_error,
            changes,
            timeline: vnr_core::Timeline::new(),
            findings,
            suppressions,
            watch_extra,
        };
        let mut ui = Ui::new(&cc.egui_ctx);
        if let Some(dark) = settings.dark {
            ui.set_dark(dark);
        }
        if let Some(view) = settings.view.as_deref().and_then(vnr_ui::View::from_label) {
            ui.set_view(view);
        }
        let watch = worker::WatchService::start(cc.egui_ctx.clone());
        let mut app = Self {
            ui,
            world,
            receiver: None,
            watch,
            settings,
            instance,
            cancel: None,
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
        self.cancel = None;
        self.receiver = Some(if elevated {
            worker::spawn_elevated_scan(ctx.clone())
        } else {
            let token = Arc::new(AtomicBool::new(false));
            self.cancel = Some(Arc::clone(&token));
            worker::spawn_scan(ctx.clone(), token)
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
                    if self.instance.is_some()
                        && let Err(error) = vnr_native::store::save_last(&snapshot)
                    {
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
                    self.cancel = None;
                    self.refresh_findings(true);
                    finished = true;
                }
                ScanMessage::Failed(error) => {
                    self.world.scan = ScanState::Idle;
                    self.world.error = Some(error);
                    self.cancel = None;
                    finished = true;
                }
                ScanMessage::Cancelled => {
                    self.world.scan = ScanState::Idle;
                    self.world.notice = Some("Scan cancelled between collectors.".to_owned());
                    self.cancel = None;
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
                self.refresh_findings(false);
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
        self.refresh_findings(false);
        self.world.error = None;
        self.world.notice = Some(
            "The baseline was cleared. Ranger has nothing to compare against until you accept one."
                .to_owned(),
        );
    }

    /// Re-evaluate the rules against the current scan, baseline and suppressions.
    ///
    /// When `announce` is set, findings that were not on screen before are written to the
    /// session timeline. The first evaluation of a launch is silent: it is what was already
    /// true, not something that just happened.
    fn refresh_findings(&mut self, announce: bool) {
        let now = now_unix();
        let previous: std::collections::HashSet<String> = self
            .world
            .findings
            .iter()
            .map(|finding| format!("{}|{}", finding.rule_id, finding.subject))
            .collect();
        let findings = findings_for(
            self.world.snapshot.as_ref(),
            self.world.baseline.as_ref(),
            &self.world.suppressions,
            now,
        );
        if announce {
            for finding in &findings {
                let key = format!("{}|{}", finding.rule_id, finding.subject);
                if !previous.contains(&key) {
                    self.world.timeline.push(TimelineEvent::new(
                        now,
                        EventKind::FindingRaised,
                        finding.title,
                        finding.subject_label.clone(),
                        "rules",
                    ));
                }
            }
        }
        self.world.findings = findings;
    }

    fn apply(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::Scan => self.start_scan(ctx, false),
            Action::CancelScan => {
                if let Some(token) = &self.cancel {
                    token.store(true, Ordering::Relaxed);
                    self.world.notice = Some("Stopping after the current collector…".to_owned());
                }
            }
            Action::ScanElevated => self.start_scan(ctx, true),
            Action::ExportJson => self.export_json(),
            Action::ExportMarkdown => self.export_markdown(),
            Action::ExportFindingsJson => self.export_findings_json(),
            Action::SetDark(dark) => {
                self.ui.set_dark(dark);
                self.settings.dark = Some(dark);
                self.persist_settings();
            }
            Action::SetView(view) => {
                self.settings.view = Some(view.label().to_owned());
                self.persist_settings();
            }
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
                self.persist_settings();
            }
            Action::SetWatch(enabled) => {
                self.world.watch.enabled = enabled;
                self.watch.set_watch(enabled);
                if !enabled {
                    self.world.watch.roots.clear();
                    self.world.watch.skipped.clear();
                }
                self.persist_settings();
            }
            Action::SetPollLed(enabled) => {
                self.world.poll_led = enabled;
                self.persist_settings();
            }
            Action::SuppressFinding {
                rule_id,
                subject,
                reason,
            } => {
                let now = now_unix();
                let expires = now.saturating_add(Suppression::DEFAULT_DAYS.saturating_mul(24 * 60 * 60));
                self.world.suppressions.push(Suppression {
                    rule_id,
                    subject,
                    reason,
                    expires_unix: expires,
                });
                vnr_core::prune_suppressions(&mut self.world.suppressions, now);
                match vnr_native::store::save_suppressions(&self.world.suppressions) {
                    Ok(()) => {
                        self.world.error = None;
                        self.world.notice = Some(format!(
                            "Suppressed until {}.",
                            vnr_core::time::format_utc(expires)
                        ));
                    }
                    Err(error) => {
                        self.world.error = Some(format!(
                            "The suppression applies for this session but could not be saved: {error}"
                        ));
                    }
                }
                self.refresh_findings(false);
            }
            Action::ClearSuppressions => {
                self.world.suppressions.clear();
                match vnr_native::store::save_suppressions(&self.world.suppressions) {
                    Ok(()) => {
                        self.world.error = None;
                        self.world.notice = Some("Suppressions cleared.".to_owned());
                    }
                    Err(error) => {
                        self.world.error = Some(format!(
                            "The suppressions are cleared for this session but the file could not be written: {error}"
                        ));
                    }
                }
                self.refresh_findings(false);
            }
            Action::RemoveSuppression { rule_id, subject } => {
                self.world.suppressions.retain(|suppression| {
                    !(suppression.rule_id == rule_id && suppression.subject == subject)
                });
                match vnr_native::store::save_suppressions(&self.world.suppressions) {
                    Ok(()) => {
                        self.world.error = None;
                        self.world.notice = Some("Suppression removed.".to_owned());
                    }
                    Err(error) => {
                        self.world.error = Some(format!(
                            "The suppression is removed for this session but the file could not be written: {error}"
                        ));
                    }
                }
                self.refresh_findings(false);
            }
            Action::ClearTimeline => self.world.timeline.clear(),
            Action::AddWatchRoot(path) => {
                let candidate = std::path::PathBuf::from(&path);
                if !candidate.is_dir() {
                    self.world.error = Some(format!("{path} is not a folder that exists."));
                } else if self
                    .world
                    .watch_extra
                    .iter()
                    .any(|root| root.eq_ignore_ascii_case(&path))
                {
                    self.world.notice = Some("That folder is already watched.".to_owned());
                } else {
                    self.world.watch_extra.push(path);
                    match vnr_native::store::save_watch_roots(&self.world.watch_extra) {
                        Ok(()) => {
                            self.restart_watch(ctx);
                            self.world.error = None;
                            self.world.notice = Some("Watcher restarted with the new folder.".to_owned());
                        }
                        Err(error) => {
                            self.world.watch_extra.pop();
                            self.world.error = Some(format!("The folder was not saved: {error}"));
                        }
                    }
                }
            }
            Action::RemoveWatchRoot(path) => {
                let before = self.world.watch_extra.len();
                self.world
                    .watch_extra
                    .retain(|root| !root.eq_ignore_ascii_case(&path));
                if before == self.world.watch_extra.len() {
                    return;
                }
                match vnr_native::store::save_watch_roots(&self.world.watch_extra) {
                    Ok(()) => {
                        self.restart_watch(ctx);
                        self.world.error = None;
                        self.world.notice = Some("Watcher restarted without that folder.".to_owned());
                    }
                    Err(error) => {
                        self.world.watch_extra.push(path);
                        self.world.error = Some(format!("The folder was not removed: {error}"));
                    }
                }
            }
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
        let body = vnr_core::report::to_markdown(&snapshot, &self.world.findings);
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

    fn restart_watch(&mut self, ctx: &egui::Context) {
        self.watch = worker::WatchService::start(ctx.clone());
        self.watch.set_poll(self.world.poll_enabled);
        self.watch.set_watch(self.world.watch.enabled);
    }

    fn persist_settings(&mut self) {
        self.settings.dark = Some(self.ui.is_dark());
        self.settings.poll = Some(self.world.poll_enabled);
        self.settings.watch = Some(self.world.watch.enabled);
        self.settings.led = Some(self.world.poll_led);
        if let Err(error) = vnr_native::store::save_ui_settings(&self.settings) {
            self.world.error = Some(format!("The interface preference could not be saved: {error}"));
        }
    }

    fn export_findings_json(&mut self) {
        if self.world.findings.is_empty() {
            self.world.notice = Some("There are no findings to export.".to_owned());
            return;
        }
        let path = vnr_native::paths::report_path("findings.json");
        match vnr_native::store::write_json_value(&self.world.findings, &path) {
            Ok(()) => {
                self.world.error = None;
                self.world.notice = Some(format!("Findings written to {}", path.display()));
            }
            Err(error) => {
                self.world.error = Some(format!("Could not write the findings: {error}"));
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

fn findings_for(
    snapshot: Option<&vnr_core::Snapshot>,
    baseline: Option<&vnr_core::Snapshot>,
    suppressions: &[Suppression],
    now: u64,
) -> Vec<Finding> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    let findings = vnr_core::evaluate(snapshot, baseline);
    vnr_core::apply_suppressions(findings, suppressions, now)
}
