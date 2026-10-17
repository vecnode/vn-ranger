//! What the interface is allowed to know.
//!
//! The UI draws a [`World`] and returns [`Action`]s. It never reads a file, never
//! starts a process and never scans: the shell does those things and hands the result
//! back. That boundary is what makes every view testable with a hand-written world.

use std::path::PathBuf;

use vnr_core::Snapshot;

/// A surface in the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// The state of the machine at a glance.
    Overview,
    /// Everything that is running.
    Processes,
    /// Everything that starts on its own.
    Startup,
    /// Everything that is listening.
    Listeners,
    /// Export and read the scan.
    Report,
    /// Preferences, elevation and privacy.
    Settings,
}

impl View {
    /// Every view, in navigation order.
    pub const ALL: [View; 6] = [
        View::Overview,
        View::Processes,
        View::Startup,
        View::Listeners,
        View::Report,
        View::Settings,
    ];

    /// The label shown in the rail.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Processes => "Processes",
            Self::Startup => "Startup",
            Self::Listeners => "Listeners",
            Self::Report => "Report",
            Self::Settings => "Settings",
        }
    }

    /// The sentence under the view's heading.
    #[must_use]
    pub fn subtitle(self) -> &'static str {
        match self {
            Self::Overview => "What is on this machine, right now.",
            Self::Processes => "Every process this account can see.",
            Self::Startup => "What runs without a person clicking it.",
            Self::Listeners => "Sockets waiting for a connection.",
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
}

/// Something the person asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Run an ordinary scan.
    Scan,
    /// Ask the operating system for an administrator scan.
    ScanElevated,
    /// Write the snapshot as JSON.
    ExportJson,
    /// Write the snapshot as Markdown.
    ExportMarkdown,
    /// Open ranger's data directory.
    OpenDataDir,
    /// Open the signatures directory.
    OpenSignaturesDir,
    /// Run the EICAR self-test through the signature engine.
    SelfTest,
    /// Open a file or directory in the platform's file manager.
    OpenPath(String),
    /// Close the application.
    Quit,
}
