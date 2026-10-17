//! The window's owner: the world, the worker, and the actions it carries out.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vnr_core::{Draft, EventKind, Finding, Suppression, TimelineEvent};
use vnr_ui::{Action, Live, ScanState, Ui, WatchReport, World};

use crate::worker::{self, ScanMessage};

/// How often the soak recorder appends a sample.
const SOAK_INTERVAL_SECONDS: u64 = 60;

/// The eframe application.
pub struct App {
    ui: Ui,
    world: World,
    receiver: Option<Receiver<ScanMessage>>,
    watch: worker::WatchService,
    settings: vnr_native::store::UiSettings,
    instance: Option<vnr_native::instance::InstanceGuard>,
    cancel: Option<Arc<AtomicBool>>,
    /// The one writer of `journal.ndjson`. Observations are written as they arrive;
    /// an intent or a result is synced (§6.10).
    journal: vnr_native::journal::Journal,
    /// Set once the journal has failed, so one broken disk is one message rather than a
    /// notice per event.
    journal_reported: bool,
    /// How often a resident ranger rescans, and how much the interval may drift.
    plan: vnr_core::schedule::Plan,
    /// Mixed into the jitter, so two machines opened together do not scan together.
    schedule_seed: u64,
    /// When the next scheduled scan is due.
    next_scan_unix: u64,
    /// The clock as the previous frame saw it, which is how a resume is noticed.
    last_frame_unix: u64,
    /// What the last dry run walked, per surface. The interface holds the list for display
    /// and returns a selection by path; this is the list a path has to be in before it can
    /// become an item, so the interface never hands the action path something it did not
    /// see itself.
    clean_previews: Vec<(vnr_core::action::Surface, vnr_native::clean::Preview)>,
    /// Counts dry runs, so the interface can tell one from another.
    clean_run: u64,
    /// The tray, when this desktop has one.
    tray: Option<vnr_native::tray::Tray>,
    /// Whether the tray has been attempted, so a machine without one tries once.
    tray_started: bool,
    /// Whether the scheduled scan is postponed.
    paused: bool,
    /// Whether this close is the end of the program rather than a trip to the tray.
    quitting: bool,
    /// Whether this launch came from the login entry, and so starts out of the way.
    background: bool,
    /// The soak recorder, when `--soak` asked for one.
    soak: Option<vnr_native::soak::Soak>,
    /// What the shell has done since the last sample.
    counters: vnr_native::soak::Counters,
    /// When the last soak sample was taken.
    last_soak_unix: u64,
}

impl App {
    /// Build the world from the last snapshot and start the first scan if there is
    /// nothing to show.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        background: bool,
        instance: Option<vnr_native::instance::InstanceGuard>,
        soak_path: Option<std::path::PathBuf>,
    ) -> Self {
        let settings = vnr_native::store::load_ui_settings();
        let soak = match soak_path.as_deref().map(vnr_native::soak::Soak::open) {
            None => None,
            Some(Ok(soak)) => Some(soak),
            Some(Err(reason)) => {
                eprintln!("vn-ranger: {reason}");
                None
            }
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
        let mut world = World {
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
            poll_enabled: settings.poll.unwrap_or(true),
            poll_led: settings.led.unwrap_or(true),
            watch: WatchReport {
                enabled: settings.watch.unwrap_or(true),
                ..WatchReport::default()
            },
            tray: vnr_ui::TrayState::Unknown,
            paused: false,
            close_to_tray: settings.close_to_tray.unwrap_or(false),
            autostart: autostart_view(vnr_native::autostart::state()),
            skip_on_battery: settings.skip_on_battery.unwrap_or(false),
            baseline,
            baseline_error,
            changes,
            timeline: vnr_core::Timeline::new(),
            findings,
            suppressions,
            watch_extra,
            quarantine: Vec::new(),
            clean: None,
            journal: Vec::new(),
            journal_damaged: false,
        };
        let mut ui = Ui::new(&cc.egui_ctx);
        if let Some(dark) = settings.dark {
            ui.set_dark(dark);
        }
        if let Some(view) = settings.view.as_deref().and_then(vnr_ui::View::from_label) {
            ui.set_view(view);
        }
        let watch = worker::WatchService::start(cc.egui_ctx.clone());
        let journal_path = vnr_native::paths::journal_path();
        let mut journal_reported = false;
        let mut journal = match vnr_native::journal::Journal::open() {
            Ok(journal) => journal,
            Err(error) => {
                journal_reported = true;
                world.error = Some(format!(
                    "The journal at {} could not be opened: {error}. Nothing this session does will be recorded.",
                    journal_path.display()
                ));
                vnr_native::journal::Journal::unavailable(journal_path, &error.to_string())
            }
        };
        if world.error.is_none() {
            let _ = journal.record(Draft::event("session started").with_reason(&format!(
                "vn-ranger {} · journal schema {}",
                env!("CARGO_PKG_VERSION"),
                vnr_core::journal::ENTRY_SCHEMA
            )));
            // A long-lived log is only useful if it stays small: the retention window is
            // applied at every launch rather than on a timer nobody would notice.
            let _ = journal.prune(now_unix());
        }
        let plan = vnr_core::schedule::Plan::DEFAULT;
        let schedule_seed = u64::from(std::process::id()) ^ now_unix();
        let next_scan_unix = vnr_core::schedule::next_at(now_unix(), plan, schedule_seed);
        let mut app = Self {
            ui,
            world,
            receiver: None,
            watch,
            settings,
            instance,
            cancel: None,
            journal,
            journal_reported,
            plan,
            schedule_seed,
            next_scan_unix,
            last_frame_unix: now_unix(),
            clean_previews: Vec::new(),
            clean_run: 0,
            tray: None,
            tray_started: false,
            paused: false,
            quitting: false,
            background,
            soak,
            counters: vnr_native::soak::Counters::default(),
            last_soak_unix: 0,
        };
        if app.world.snapshot.is_none() {
            app.start_scan(&cc.egui_ctx, false);
        }
        app.refresh_actions();
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

    /// Write one observation to the journal.
    fn note(&mut self, draft: Draft) {
        if let Err(error) = self.journal.record(draft) {
            self.report_journal(&error);
        }
    }

    /// Say once, where a person will see it, that the record has stopped.
    fn report_journal(&mut self, error: &std::io::Error) {
        if self.journal_reported {
            return;
        }
        self.journal_reported = true;
        self.world.error = Some(format!(
            "The journal could not be written: {error}. Nothing from here on is recorded."
        ));
    }

    /// Roll the journal over and drop what is past its retention window.
    fn maintain_journal(&mut self) {
        match self.journal.rotate_if_needed() {
            Ok(true) => log::info!("journal rotated"),
            Ok(false) => {}
            Err(error) => self.report_journal(&error),
        }
        if let Err(error) = self.journal.prune(now_unix()) {
            log::warn!("could not prune the journal: {error}");
        }
    }

    /// Read the quarantine and the journal from disk into the world.
    ///
    /// Both are files, and the interface draws a `World`; this is the only place that
    /// turns one into the other, so a stale list is a bug in one function rather than a
    /// missing refresh in five.
    fn refresh_actions(&mut self) {
        let read = self.journal.read();
        let open: std::collections::HashSet<String> = vnr_core::journal::interrupted(&read.entries)
            .into_iter()
            .filter_map(|entry| entry.id.clone())
            .collect();
        self.world.journal_damaged = read.is_damaged();
        self.world.journal = read
            .entries
            .iter()
            .rev()
            .take(200)
            .map(|entry| vnr_ui::JournalRow {
                seq: entry.seq,
                at_label: vnr_core::time::format_utc(entry.at),
                kind: entry.kind.label(),
                action: entry.action.map(|action| action.label()),
                subject: entry.subject.clone().unwrap_or_default(),
                detail: entry.reason.clone().unwrap_or_default(),
                interrupted: entry.kind == vnr_core::JournalKind::Intent
                    && entry.id.as_ref().is_some_and(|id| open.contains(id)),
            })
            .collect();

        let (summaries, unreadable) = vnr_native::quarantine::list(&vnr_native::action::RealIo);
        self.world.quarantine = summaries
            .into_iter()
            .map(|summary| vnr_ui::QuarantineRow {
                id: summary.id,
                original_path: summary.manifest.original_path,
                bytes: summary.manifest.size,
                at_label: vnr_core::time::format_utc(summary.manifest.quarantined_at),
                reason: summary.manifest.reason,
                hash_short: summary.manifest.sha256.chars().take(12).collect(),
            })
            .collect();
        if unreadable > 0 {
            self.world.error = Some(format!(
                "{unreadable} folder in the quarantine could not be read, so the list above is incomplete."
            ));
        }
    }

    /// Walk every allowlisted surface and put what a clean would remove into the world.
    ///
    /// This is the dry run: it reads names, sizes and times and writes nothing — no journal
    /// line, no removal, no file of its own. The walk's items stay here rather than in the
    /// world, because the world is what the interface draws and this is the only list the
    /// action path may remove from.
    ///
    /// `fresh` says whether this is a new list or the same one after a clean. A new list
    /// resets the person's ticks; keeping them after a clean is what lets an entry they had
    /// unticked stay unticked instead of quietly returning to a default.
    fn refresh_clean(&mut self, fresh: bool) {
        let now = now_unix();
        let cancel = || false;
        if fresh {
            self.clean_run = self.clean_run.saturating_add(1);
        }
        self.clean_previews.clear();
        let mut report = vnr_ui::CleanReport {
            run: self.clean_run,
            ..vnr_ui::CleanReport::default()
        };
        for surface in vnr_core::action::Surface::ALL {
            let roots = vnr_native::clean::roots(surface);
            if roots.is_empty() {
                // A surface with no folder on this machine is not offered: the list is
                // what exists here, not what the table names.
                continue;
            }
            let preview = vnr_native::clean::preview_roots(surface, &roots, now, &cancel);
            report.cancelled |= preview.cancelled;
            report.surfaces.push(vnr_ui::CleanSurface {
                id: surface.id().to_owned(),
                label: surface.label().to_owned(),
                roots: roots.len(),
                opt_in: surface.is_opt_in(),
                items: preview
                    .items
                    .iter()
                    .map(|item| vnr_ui::CleanItem {
                        path: item.path.display().to_string(),
                        bytes: item.bytes,
                        is_dir: item.is_dir,
                    })
                    .collect(),
                skipped_young: preview.skipped_young,
                skipped_links: preview.skipped_links,
                skipped_devices: preview.skipped_devices,
                skipped_excluded: preview.skipped_excluded,
            });
            self.clean_previews.push((surface, preview));
        }
        self.world.clean = Some(report);
    }

    /// Put the icon in the status area, once, on the first frame.
    ///
    /// A frame is the safe moment to do it: on Windows and macOS the icon needs an event
    /// loop running on this thread, and by the time a frame is drawn there is one. A
    /// desktop with no status area is not an error to recover from, it is a state to say
    /// out loud, in Settings and in the journal.
    fn start_tray(&mut self, ctx: &egui::Context) {
        if self.tray_started {
            return;
        }
        self.tray_started = true;
        let wake = {
            let ctx = ctx.clone();
            move || ctx.request_repaint()
        };
        let started =
            vnr_native::tray::Tray::start(vnr_native::tray::ICON.to_vec(), vnr_native::tray::ICON_SIZE, wake);
        match started {
            Ok(tray) => {
                tray.set_paused(self.paused);
                self.tray = Some(tray);
                self.world.tray = vnr_ui::TrayState::Present;
            }
            Err(reason) => {
                log::warn!("no tray: {reason}");
                self.note(Draft::event("no tray").with_reason(&reason));
                self.world.tray = vnr_ui::TrayState::Absent(reason);
            }
        }
    }

    /// Append one soak sample a minute, when a soak was asked for.
    ///
    /// A minute is the interval the published budget is measured over, and the write is
    /// small: one line, flushed. A failure is reported once and then stops, because a full
    /// disk retried every frame is a second fault.
    fn soak_sample(&mut self) {
        let Some(soak) = self.soak.as_mut() else {
            return;
        };
        let now = now_unix();
        if now.saturating_sub(self.last_soak_unix) < SOAK_INTERVAL_SECONDS {
            return;
        }
        self.last_soak_unix = now;
        let counters = vnr_native::soak::Counters {
            journal_writes: self.journal.writes(),
            ..self.counters
        };
        if let Err(reason) = soak.sample(counters) {
            self.world.error = Some(reason);
            self.soak = None;
        }
    }

    /// Raise the window when a second launch asked it to.
    ///
    /// The file is taken rather than read: one launch is one raise, and a file that stays
    /// behind would raise the window on every frame.
    fn answer_wake(&mut self, ctx: &egui::Context) {
        if !vnr_native::instance::take_wake(&vnr_native::paths::wake_path()) {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        self.note(
            Draft::event("window raised").with_reason("a second launch asked this window to come forward"),
        );
    }
    /// Turn a close request into a hide, when that is what was asked for.
    /// The window is only ever hidden when there is a tray to bring it back, and the journal
    /// says so at the moment it happens: a person who closed a window and finds a process
    /// still running deserves to read why in the one file ranger keeps.
    fn close_or_hide(&mut self, ctx: &egui::Context) {
        if !ctx.input(|input| input.viewport().close_requested()) || !self.world.hide_on_close(self.quitting)
        {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.note(
            Draft::event("window hidden")
                .with_reason("the window was closed while close-to-tray is on; the tray icon opens it again"),
        );
        self.world.notice = Some("The window is in the status area; its menu opens it again.".to_owned());
    }

    /// Carry out whatever the tray menu reported.
    ///
    /// The tray never gets a fifth action: everything here is an [`Action`] the window can
    /// also produce, so the two surfaces cannot diverge.
    fn poll_tray(&mut self, ctx: &egui::Context) {
        let commands = match &self.tray {
            Some(tray) => tray.poll(),
            None => return,
        };
        for command in commands {
            match command {
                vnr_native::tray::Command::Open => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                vnr_native::tray::Command::ScanNow => self.apply(Action::Scan, ctx),
                vnr_native::tray::Command::Pause => self.apply(Action::PauseScan, ctx),
                vnr_native::tray::Command::Quit => self.apply(Action::Quit, ctx),
            }
        }
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
                    self.note(Draft::event("scan").with_reason(&format!(
                        "{} processes · {} startup items · {} listeners · {} packages",
                        snapshot.processes.len(),
                        snapshot.autoruns.len(),
                        snapshot.listeners.len(),
                        snapshot.packages.len()
                    )));
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
                    self.maintain_journal();
                    finished = true;
                }
                ScanMessage::Failed(error) => {
                    self.note(Draft::error(&error));
                    self.world.scan = ScanState::Idle;
                    self.world.error = Some(error);
                    self.cancel = None;
                    finished = true;
                }
                ScanMessage::Cancelled => {
                    self.note(Draft::event("scan cancelled"));
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

    fn drain_watch(&mut self, ctx: &egui::Context) {
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
                    self.counters.polls = self.counters.polls.saturating_add(1);
                    self.ui.note_poll(ctx);
                }
                worker::WatchMessage::Events(events) => {
                    self.counters.events = self
                        .counters
                        .events
                        .saturating_add(u64::try_from(events.len()).unwrap_or(u64::MAX));
                    for event in events {
                        self.note(Draft::event(&event.subject).with_reason(&format!(
                            "{} · {} · {}",
                            event.kind.label(),
                            event.source,
                            event.detail
                        )));
                        self.world.timeline.push(event);
                    }
                }
                worker::WatchMessage::Watching { roots, skipped } => {
                    self.world.watch.roots = roots;
                    self.world.watch.skipped = skipped;
                    self.world.watch.error = None;
                }
                worker::WatchMessage::WatchFailed(reason) => {
                    self.note(Draft::error(&reason));
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
            let mut raised: Vec<(String, String, String)> = Vec::new();
            for finding in &findings {
                let key = format!("{}|{}", finding.rule_id, finding.subject);
                if previous.contains(&key) {
                    continue;
                }
                self.world.timeline.push(TimelineEvent::new(
                    now,
                    EventKind::FindingRaised,
                    finding.title,
                    finding.subject_label.clone(),
                    "rules",
                ));
                raised.push((
                    finding.rule_id.to_owned(),
                    finding.subject_label.clone(),
                    finding.severity.label().to_owned(),
                ));
            }
            for (rule, subject, severity) in raised {
                self.note(
                    Draft::finding(&rule)
                        .with_reason(&format!("{severity} · {subject} · raised from the rules engine")),
                );
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
            Action::PauseScan => {
                self.paused = !self.paused;
                let now = now_unix();
                if self.paused {
                    self.next_scan_unix = now.saturating_add(3600);
                    self.world.notice = Some(
                        "The next scheduled scan is an hour away. Scan now, or press Resume \
                         scheduled scans, to end the postponement."
                            .to_owned(),
                    );
                } else {
                    self.next_scan_unix = vnr_core::schedule::next_at(now, self.plan, self.schedule_seed);
                    self.world.notice = Some("Scheduled scans are back on.".to_owned());
                }
                self.world.paused = self.paused;
                if let Some(tray) = &self.tray {
                    tray.set_paused(self.paused);
                }
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
            Action::Quit => {
                // A quit is a quit even when close-to-tray is on: the setting is about the
                // close button, and a program that cannot be ended from its own menu is
                // worse than one that cannot be hidden.
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Action::SetSkipOnBattery(enabled) => {
                self.world.skip_on_battery = enabled;
                self.persist_settings();
                self.world.notice = Some(if enabled {
                    "A scheduled scan now waits while the machine is on battery. A scan you ask \
                     for always runs."
                        .to_owned()
                } else {
                    "Scheduled scans run whether the machine is on battery or not.".to_owned()
                });
            }
            Action::SetAutostart(enabled) => {
                let outcome = if enabled {
                    vnr_native::autostart::enable().map(|location| {
                        format!(
                            "Ranger starts at login from {}. The same click removes it.",
                            location.at
                        )
                    })
                } else {
                    vnr_native::autostart::disable().map(|()| {
                        "Ranger no longer starts at login. Its entry is gone and nothing else \
                         was touched."
                            .to_owned()
                    })
                };
                match outcome {
                    Ok(message) => {
                        self.world.error = None;
                        self.world.notice = Some(message);
                    }
                    Err(error) => self.world.error = Some(error),
                }
                // Read the entry back rather than trusting the write: what Settings shows
                // is what the operating system would run.
                self.world.autostart = autostart_view(vnr_native::autostart::state());
            }
            Action::SetCloseToTray(enabled) => {
                self.world.close_to_tray = enabled;
                self.settings.close_to_tray = Some(enabled);
                self.persist_settings();
                self.world.notice = Some(if enabled {
                    "Closing the window now hides it; the tray icon brings it back. Quit still quits."
                        .to_owned()
                } else {
                    "Closing the window ends ranger again.".to_owned()
                });
            }
            Action::RefreshActions => {
                self.refresh_actions();
                self.world.notice = Some("The quarantine and the journal were read again.".to_owned());
            }
            Action::Restore(id) => {
                match vnr_native::act::restore(&mut self.journal, &id, &vnr_native::action::RealIo) {
                    Ok(restored) => {
                        self.world.error = None;
                        self.world.notice = Some(format!(
                            "Put back at {}. Its bytes were checked first.",
                            restored.manifest.original_path
                        ));
                    }
                    Err(error) => self.world.error = Some(error.to_string()),
                }
                self.refresh_actions();
            }
            Action::Purge { id, typed } => {
                // The interface disables the button until the word is typed; this checks
                // it again, because the interface is not the only thing that can dispatch
                // an action.
                if typed.trim() != "DELETE" {
                    self.world.error =
                        Some("Deleting for good needs the word DELETE typed exactly.".to_owned());
                } else {
                    match vnr_native::act::purge(
                        &mut self.journal,
                        &id,
                        vnr_core::Confirmation::Typed,
                        &vnr_native::action::RealIo,
                    ) {
                        Ok(purged) => {
                            self.world.error = None;
                            self.world.notice = Some(format!(
                                "{} was deleted for good. The journal has the entry that says so.",
                                purged.manifest.original_path
                            ));
                        }
                        Err(error) => self.world.error = Some(error.to_string()),
                    }
                }
                self.refresh_actions();
            }
            Action::Quarantine(path) => {
                match vnr_native::act::quarantine(
                    &mut self.journal,
                    std::path::Path::new(&path),
                    "quarantined from the Startup view",
                    &vnr_native::action::RealIo,
                ) {
                    Ok(taken) => {
                        self.world.error = None;
                        self.world.notice = Some(format!(
                            "Moved {} into the quarantine. It can be put back from Actions.",
                            taken.manifest.original_path
                        ));
                    }
                    Err(error) => self.world.error = Some(error.to_string()),
                }
                self.refresh_actions();
            }
            Action::PreviewClean => {
                let started = std::time::Instant::now();
                self.refresh_clean(true);
                let (entries, bytes) = self.world.clean.as_ref().map_or((0, 0), |report| {
                    report
                        .surfaces
                        .iter()
                        .fold((0_usize, 0_u64), |(entries, bytes), surface| {
                            (
                                entries.saturating_add(surface.entries()),
                                bytes.saturating_add(surface.bytes()),
                            )
                        })
                });
                let elapsed = started.elapsed().as_millis();
                self.world.error = None;
                self.world.notice = Some(if entries == 0 {
                    format!(
                        "A dry run walked every allowlisted folder in {elapsed} ms and found \
                         nothing past the age each surface keeps. It wrote nothing."
                    )
                } else {
                    format!(
                        "A dry run counted {entries} entries, {}, in {elapsed} ms. Nothing was \
                         removed and nothing was recorded.",
                        vnr_ui::widgets::bytes(bytes)
                    )
                });
            }
            Action::CleanSelected(choices) => {
                let now = now_unix();
                let cancel = || false;
                let mut removed = 0_usize;
                let mut bytes = 0_u64;
                let mut skipped = 0_usize;
                let mut refused = 0_usize;
                let mut surfaces = 0_usize;
                let mut failure: Option<String> = None;
                for choice in &choices {
                    let Some(surface) = vnr_core::action::Surface::from_id(&choice.surface) else {
                        continue;
                    };
                    // The selection is matched against this process's own walk, so a path
                    // the dry run did not offer is dropped rather than resolved.
                    let items = match self.clean_previews.iter().find(|(walked, _)| *walked == surface) {
                        Some((_, preview)) => vnr_native::clean::select(&preview.items, &choice.paths),
                        None => continue,
                    };
                    if items.is_empty() {
                        continue;
                    }
                    surfaces = surfaces.saturating_add(1);
                    match vnr_native::act::clean(&mut self.journal, surface, &items, now, &cancel) {
                        Ok(removal) => {
                            removed = removed.saturating_add(removal.removed);
                            bytes = bytes.saturating_add(removal.bytes);
                            skipped = skipped.saturating_add(removal.skipped);
                            refused = refused.saturating_add(removal.failed.len());
                            if let Some((path, reason)) = removal.failed.first()
                                && failure.is_none()
                            {
                                failure = Some(format!("{} could not be removed: {reason}", path.display()));
                            }
                        }
                        Err(error) => {
                            if failure.is_none() {
                                failure = Some(error.to_string());
                            }
                        }
                    }
                }
                // What is left is what is shown, as the same list rather than a new one:
                // the person's ticks stay where they put them.
                self.refresh_clean(false);
                self.world.error = failure;
                self.world.notice = Some(if removed == 0 && refused == 0 {
                    format!(
                        "Nothing was removed: every selected entry had changed, vanished or \
                         become a link since the dry run. All {skipped} are still in place."
                    )
                } else {
                    format!(
                        "Removed {removed} entries, {}, from {surfaces} surfaces. {skipped} \
                         skipped, {refused} refused. The journal has the record, and the list \
                         below was walked again.",
                        vnr_ui::widgets::bytes(bytes)
                    )
                });
            }
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
        self.settings.close_to_tray = Some(self.world.close_to_tray);
        self.settings.skip_on_battery = Some(self.world.skip_on_battery);
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
        self.start_tray(&ctx);
        if self.background {
            // A login launch starts in the status area rather than on top of whatever the
            // person opened. Without a tray there is nowhere to be, so the window stays.
            self.background = false;
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.note(
                    Draft::event("started at login")
                        .with_reason("the window opened in the status area; the tray icon opens it"),
                );
            }
        }
        self.answer_wake(&ctx);
        self.close_or_hide(&ctx);
        self.drain();
        self.drain_watch(&ctx);
        self.tick(&ctx);
        let actions = self.ui.show(ui, &self.world);
        for action in actions {
            self.apply(action, &ctx);
        }
        if self.world.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

impl App {
    /// The two things the clock decides: a scheduled scan, and a scan after the machine
    /// wakes up.
    ///
    /// Both are skipped while a scan is running, and the next due time moves only when a
    /// scan actually starts, so a slow scan cannot queue a second one behind itself.
    fn tick(&mut self, ctx: &egui::Context) {
        self.poll_tray(ctx);
        self.soak_sample();
        if self.paused {
            // A postponed schedule means the clock has nothing to say; the poll and the
            // watcher still run, and a person can always scan by hand.
            self.last_frame_unix = now_unix();
            return;
        }
        let now = now_unix();
        let gap = now.saturating_sub(self.last_frame_unix);
        // The poll beats every two seconds; three missed beats is a lid that closed.
        if vnr_core::schedule::resumed(self.last_frame_unix, now, 2)
            && self.world.snapshot.is_some()
            && !self.world.busy()
        {
            self.note(Draft::event("resumed after a gap").with_reason(&format!(
                "{gap} seconds passed between two frames; the machine was probably asleep, so one scan runs now."
            )));
            self.start_scan(ctx, false);
            self.next_scan_unix = vnr_core::schedule::next_at(now, self.plan, self.schedule_seed);
        }
        self.last_frame_unix = now;

        if self.world.snapshot.is_some()
            && !self.world.busy()
            && vnr_core::schedule::is_due(now, self.next_scan_unix)
        {
            if self.world.skip_on_battery && vnr_native::power::source().is_battery() {
                // Postponed, not cancelled: the next interval is scheduled as usual, and the
                // journal says why nothing ran, so a quiet day is not mistaken for a clean
                // one.
                self.next_scan_unix = vnr_core::schedule::next_at(now, self.plan, self.schedule_seed);
                self.note(
                    Draft::event("scheduled scan waited").with_reason(
                        "the machine is on battery and the person asked scheduled scans to wait",
                    ),
                );
                return;
            }
            self.note(Draft::event("scheduled scan").with_reason(&format!(
                "the {}-hour interval came round",
                self.plan.every_secs / 3600
            )));
            self.start_scan(ctx, false);
            self.next_scan_unix = vnr_core::schedule::next_at(now, self.plan, self.schedule_seed);
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // The last line is synced: a session that ends normally belongs in the record,
        // and this is the only chance to write it.
        if let Err(error) = self
            .journal
            .record_synced(Draft::event("session stopped").with_reason("the window closed"))
        {
            log::warn!("could not close the journal: {error}");
        }
    }
}

/// The interface's mirror of the entry the operating system would run at login.
fn autostart_view(state: vnr_native::autostart::State) -> vnr_ui::AutostartState {
    match state {
        vnr_native::autostart::State::On(location) => vnr_ui::AutostartState::On {
            at: location.at,
            command: location.command,
        },
        vnr_native::autostart::State::Off => vnr_ui::AutostartState::Off,
        vnr_native::autostart::State::Unavailable(reason) => vnr_ui::AutostartState::Unavailable(reason),
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
