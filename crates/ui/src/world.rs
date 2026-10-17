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
