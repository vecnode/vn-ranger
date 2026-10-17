//! What the interface is allowed to know.
//!
//! The UI draws a [`World`] and returns [`Action`]s. It never reads a file, never
//! starts a process and never scans: the shell does those things and hands the result
//! back. That boundary is what makes every view testable with a hand-written world.

use std::path::PathBuf;

use vnr_core::diff::Change;
use vnr_core::timeline::Timeline;
use vnr_core::{Finding, ProcessFact, Snapshot, Suppression};

/// A surface in the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// The state of the machine at a glance.
    Overview,
    /// What the rules observed, with the evidence.
    Findings,
    /// Everything that is running.
    Processes,
    /// Everything that starts on its own.
    Startup,
    /// Everything that is listening.
    Listeners,
    /// What changed while ranger was watching.
    Changes,
    /// What ranger can act on: the quarantine and the journal.
    Actions,
    /// Export and read the scan.
    Report,
    /// Preferences, elevation and privacy.
    Settings,
}

impl View {
    /// Every view, in navigation order.
    pub const ALL: [View; 9] = [
        View::Overview,
        View::Findings,
        View::Processes,
        View::Startup,
        View::Listeners,
        View::Changes,
        View::Actions,
        View::Report,
        View::Settings,
    ];

    /// The label shown in the rail.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Findings => "Findings",
            Self::Processes => "Processes",
            Self::Startup => "Startup",
            Self::Listeners => "Listeners",
            Self::Changes => "Changes",
            Self::Actions => "Actions",
            Self::Report => "Report",
            Self::Settings => "Settings",
        }
    }

    /// Look a view up by its label, for the saved interface state.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|view| view.label().eq_ignore_ascii_case(label.trim()))
    }

    /// The sentence under the view's heading.
    #[must_use]
    pub fn subtitle(self) -> &'static str {
        match self {
            Self::Overview => "What is on this machine, right now.",
            Self::Findings => "What the rules observed, and what they do not mean.",
            Self::Processes => "Every process this account can see.",
            Self::Startup => "What runs without a person clicking it.",
            Self::Listeners => "Sockets waiting for a connection.",
            Self::Changes => "What changed since ranger opened, and since the baseline.",
            Self::Actions => "What ranger has done, and what it can put back.",
            Self::Report => "A record you can read, export and keep.",
            Self::Settings => "How ranger runs, and what it will not do.",
        }
    }
}

/// What the worker is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanState {
    /// Nothing is running.
    Idle,
    /// A scan is running, with the current step.
    Running(String),
}

impl ScanState {
    /// Whether the interface should disable scan actions.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Running(_))
    }
}

/// The newest process poll, which is newer than the snapshot taken around it.
#[derive(Clone, Debug)]
pub struct Live {
    /// Every process the poll could see.
    pub items: Vec<ProcessFact>,
    /// Seconds since the Unix epoch when the poll finished.
    pub at_unix: u64,
    /// Why the poll is incomplete, when it is.
    pub reason: Option<String>,
}

/// One quarantined file, as the interface lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineRow {
    /// The entry id, which is what every act takes.
    pub id: String,
    /// Where the file came from.
    pub original_path: String,
    /// Its size in bytes.
    pub bytes: u64,
    /// When it was taken, already formatted by the shell.
    pub at_label: String,
    /// Why it was taken.
    pub reason: String,
    /// The first twelve characters of its hash, which is enough to compare two rows.
    pub hash_short: String,
}

/// One thing a clean would remove, as the interface lists it.
///
/// The path is the key a selection is made by. It is not a capability: the shell removes
/// only what its own walk offered, and a path that was not in that walk is dropped rather
/// than resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanItem {
    /// Where it is.
    pub path: String,
    /// Its size in bytes; zero for a directory.
    pub bytes: u64,
    /// Whether it is an empty directory waiting to be pruned.
    pub is_dir: bool,
}

/// What one allowlisted surface would give back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanSurface {
    /// The surface's stable id, which is what an act names.
    pub id: String,
    /// What a person calls it.
    pub label: String,
    /// How many folders on this machine belong to it.
    pub roots: usize,
    /// Whether removing this surface's contents is a choice the person makes explicitly.
    pub opt_in: bool,
    /// The things it would remove.
    pub items: Vec<CleanItem>,
    /// How many entries were left alone because they are newer than the surface's age.
    pub skipped_young: usize,
    /// How many links were left alone.
    pub skipped_links: usize,
    /// How many entries on another filesystem were left alone.
    pub skipped_devices: usize,
    /// How many entries this surface keeps by name.
    pub skipped_excluded: usize,
}

impl CleanSurface {
    /// Everything the surface would give back, summed.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.items.iter().map(|item| item.bytes).sum()
    }

    /// How many entries would be removed.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.items.len()
    }

    /// How many entries were left alone, and why, in the surface's own words.
    #[must_use]
    pub fn kept_sentence(&self) -> String {
        let mut parts = Vec::new();
        if self.skipped_young > 0 {
            parts.push(format!("{} too new", self.skipped_young));
        }
        if self.skipped_links > 0 {
            parts.push(format!("{} links", self.skipped_links));
        }
        if self.skipped_devices > 0 {
            parts.push(format!("{} on another filesystem", self.skipped_devices));
        }
        if self.skipped_excluded > 0 {
            parts.push(format!("{} the system keeps", self.skipped_excluded));
        }
        if parts.is_empty() {
            return String::new();
        }
        format!("Kept {}", parts.join(", "))
    }
}

/// What one dry run found across every surface that exists on this machine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanReport {
    /// Which dry run this is. The interface resets a selection when this changes.
    pub run: u64,
    /// One row per surface that resolved to at least one folder.
    pub surfaces: Vec<CleanSurface>,
    /// Whether the walk stopped because it was asked to.
    pub cancelled: bool,
}

impl CleanReport {
    /// Whether there is anything to remove at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.surfaces.iter().all(|surface| surface.items.is_empty())
    }
}

/// One surface's share of what a person chose to remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanChoice {
    /// The surface's stable id.
    pub surface: String,
    /// The paths that were selected, as the dry run listed them.
    pub paths: Vec<String>,
}

/// Whether the application has a tray icon, and why not when it has none.
///
/// "No tray" is a supported state, not a failure: a bare session, a container and a Linux
/// desktop with no StatusNotifier host are all machines ranger has to be honest about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TrayState {
    /// The tray has not been attempted yet.
    #[default]
    Unknown,
    /// The icon is in the status area.
    Present,
    /// There is no tray on this desktop, and this is why.
    Absent(String),
}

impl TrayState {
    /// The sentence Settings shows.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::Unknown => "Not started yet.".to_owned(),
            Self::Present => "The icon is in the status area. Its menu opens this window, scans now, \
                 pauses the schedule or quits — the same four things the window does."
                .to_owned(),
            Self::Absent(reason) => format!(
                "None on this desktop: {reason}. Closing this window quits, and nothing is \
                 hidden in an icon that is not there."
            ),
        }
    }
}

/// One journal line, as the interface lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRow {
    /// Its sequence number in the journal.
    pub seq: u64,
    /// When it was written, already formatted.
    pub at_label: String,
    /// What kind of line it is.
    pub kind: &'static str,
    /// The operation, when the line is about one.
    pub action: Option<&'static str>,
    /// What it is about.
    pub subject: String,
    /// Why, in the entry's own words.
    pub detail: String,
    /// Whether this line is an intent that never got a result.
    pub interrupted: bool,
}

/// What the file watcher is reading, and what it refused.
#[derive(Clone, Debug, Default)]
pub struct WatchReport {
    /// Whether the watcher is switched on.
    pub enabled: bool,
    /// The folders the operating system accepted.
    pub roots: Vec<String>,
    /// The folders it refused, with the reason.
    pub skipped: Vec<String>,
    /// Why the watcher could not start, when it could not.
    pub error: Option<String>,
}

/// Everything the interface draws from.
#[derive(Clone, Debug)]
pub struct World {
    /// The most recent snapshot, from this session or the last launch.
    pub snapshot: Option<Snapshot>,
    /// What the worker is doing.
    pub scan: ScanState,
    /// A failure the person needs to see.
    pub error: Option<String>,
    /// A success message that should fade on the next action.
    pub notice: Option<String>,
    /// Whether this process is running with elevated rights.
    pub elevated: bool,
    /// Whether this platform can ask for an administrator scan.
    pub can_elevate: bool,
    /// Where ranger stores its own files.
    pub data_dir: PathBuf,
    /// Where local signature databases are read from.
    pub signatures_dir: PathBuf,
    /// The application version.
    pub version: String,
    /// Seconds since the Unix epoch, refreshed by the shell.
    pub now_unix: u64,
    /// The newest process poll, when the poll has run.
    pub live: Option<Live>,
    /// Whether the process poll is switched on.
    pub poll_enabled: bool,
    /// Whether the top bar shows the live poll indicator.
    pub poll_led: bool,
    /// What the file watcher is reading.
    pub watch: WatchReport,
    /// Whether the tray icon is on screen, and why not when it is not.
    pub tray: TrayState,
    /// Whether the scheduled scan is postponed.
    pub paused: bool,
    /// Whether closing the window hides it to the tray instead of quitting.
    ///
    /// Off by default. A setting that hides the program has to be one a person chose, and
    /// the only honest default for a close button is that it closes.
    pub close_to_tray: bool,
    /// The baseline a person accepted, when there is one.
    pub baseline: Option<Snapshot>,
    /// Why a baseline file could not be used, when one exists but is unreadable.
    pub baseline_error: Option<String>,
    /// How the snapshot differs from the baseline.
    pub changes: Vec<Change>,
    /// What changed since ranger opened.
    pub timeline: Timeline,
    /// What the rules say about the latest scan, after suppressions.
    pub findings: Vec<Finding>,
    /// The person's active suppressions.
    pub suppressions: Vec<Suppression>,
    /// Folders the person added to the watcher.
    pub watch_extra: Vec<String>,
    /// The quarantine, newest first.
    pub quarantine: Vec<QuarantineRow>,
    /// What the last clean dry run found, and nothing else: the walk writes no file.
    pub clean: Option<CleanReport>,
    /// The journal's newest entries, newest first.
    pub journal: Vec<JournalRow>,
    /// Whether the journal reports a damaged line or a torn tail.
    pub journal_damaged: bool,
}

impl World {
    /// Whether a scan is running.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.scan.is_busy()
    }

    /// The snapshot, when there is one.
    #[must_use]
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Whether a close request should hide the window rather than end the application.
    ///
    /// Three conditions, and all three matter: the person turned it on, there is a tray to
    /// come back from, and this close is not a quit. A window hidden on a desktop with no
    /// tray is a process nobody can reach, which is the one thing this program must never
    /// become.
    #[must_use]
    pub fn hide_on_close(&self, quitting: bool) -> bool {
        !quitting && self.close_to_tray && matches!(self.tray, TrayState::Present)
    }

    /// The newest process list the interface has, preferring a non-empty poll over the
    /// scan. A poll that could read nothing leaves the last scan on screen rather than
    /// claiming the machine has no processes.
    #[must_use]
    pub fn processes(&self) -> &[ProcessFact] {
        match (&self.live, &self.snapshot) {
            (Some(live), _) if !live.items.is_empty() => &live.items,
            (_, Some(snapshot)) => &snapshot.processes,
            (Some(live), None) => &live.items,
            (None, None) => &[],
        }
    }
}

/// Something the person asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Run an ordinary scan.
    Scan,
    /// Ask the running scan to stop between collectors.
    CancelScan,
    /// Ask the operating system for an administrator scan.
    ScanElevated,
    /// Write the snapshot as JSON.
    ExportJson,
    /// Write the snapshot as Markdown.
    ExportMarkdown,
    /// Write the current findings as JSON.
    ExportFindingsJson,
    /// Open ranger's data directory.
    OpenDataDir,
    /// Open the signatures directory.
    OpenSignaturesDir,
    /// Run the EICAR self-test through the signature engine.
    SelfTest,
    /// Keep the current scan as the baseline future scans are compared against.
    AcceptBaseline,
    /// Forget the baseline.
    ClearBaseline,
    /// Turn the two-second process poll on or off.
    SetPoll(bool),
    /// Postpone the next scheduled scan by an hour, or end a postponement.
    ///
    /// The tray's pause item and the Settings button both send this: the tray has no way to
    /// postpone the schedule that the window does not have.
    PauseScan,
    /// Hide the window to the tray when it is closed, or stop doing that.
    SetCloseToTray(bool),
    /// Turn the file watcher on or off.
    SetWatch(bool),
    /// Show or hide the live poll indicator.
    SetPollLed(bool),
    /// Switch between the dark and light theme.
    SetDark(bool),
    /// Remember the view the person chose.
    SetView(View),
    /// Suppress one finding, carrying the reason the person gave.
    SuppressFinding {
        /// The rule to suppress.
        rule_id: String,
        /// The subject to suppress it for.
        subject: String,
        /// Why the person accepted it.
        reason: String,
    },
    /// Forget every suppression.
    ClearSuppressions,
    /// Remove one suppression.
    RemoveSuppression {
        /// The rule it covers.
        rule_id: String,
        /// The subject it covers.
        subject: String,
    },
    /// Clear the in-memory session timeline.
    ClearTimeline,
    /// Add a folder to the watcher.
    AddWatchRoot(String),
    /// Stop watching a folder the person added.
    RemoveWatchRoot(String),
    /// Put a quarantined file back where it came from.
    Restore(String),
    /// Move a file into the quarantine, after the detail panel has shown what it is.
    Quarantine(String),
    /// Walk the allowlisted surfaces and report what a clean would remove.
    ///
    /// This is a dry run: it reads names, sizes and times, and writes nothing — no journal
    /// line, no removal, not even a file of its own.
    PreviewClean,
    /// Remove the entries a person selected, one surface at a time.
    ///
    /// The paths are what the shell's own dry run listed; it drops any that were not, so a
    /// path assembled somewhere else cannot arrive here as an instruction.
    CleanSelected(Vec<CleanChoice>),
    /// Delete a quarantined entry for good, with the word the person typed.
    ///
    /// The typed word travels with the action so the shell can refuse a call that did not
    /// come from a dialog: the interface is not the only thing that may dispatch one.
    Purge {
        /// The entry to delete.
        id: String,
        /// What the person typed. It has to be `DELETE`.
        typed: String,
    },
    /// Read the quarantine and the journal from disk again.
    RefreshActions,
    /// Open a file or directory in the platform's file manager.
    OpenPath(String),
    /// Close the application.
    Quit,
}
