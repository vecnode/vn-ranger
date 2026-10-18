//! The data ranger collects and the vocabulary it uses to describe it.
//!
//! Everything here is plain data. There is no IO, no clock and no operating-system
//! call: a snapshot can be built in a test, serialised, and compared byte for byte.

use serde::{Deserialize, Serialize};

/// The snapshot schema this build writes.
///
/// A reader that does not understand a newer schema should say so rather than guess.
pub const SCHEMA_VERSION: u32 = 1;

/// The machine a snapshot was taken on.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Host {
    /// The operating system, as `std::env::consts::OS` names it.
    pub os: String,
    /// A human-readable operating-system version.
    pub version: String,
    /// The CPU architecture.
    pub arch: String,
    /// The machine's name, when the platform will give it up.
    pub hostname: Option<String>,
}

/// One running process.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessFact {
    /// The process id at the moment of collection.
    pub pid: u32,
    /// The parent process id, when it could be read.
    pub parent: Option<u32>,
    /// The process name, without a path.
    pub name: String,
    /// The executable path, when the platform exposes it.
    pub exe: Option<String>,
    /// The command line, joined for display.
    pub command: Option<String>,
    /// The account that owns the process.
    pub user: Option<String>,
    /// Seconds since the Unix epoch, derived from the process's run time.
    pub started_at_unix: Option<u64>,
}

/// Where an automatic start lives.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutorunKind {
    /// A Windows `Run` or `RunOnce` registry value.
    RunKey,
    /// A file in a Startup folder.
    StartupFolder,
    /// A Windows service.
    Service,
    /// A macOS launch agent.
    LaunchAgent,
    /// A macOS launch daemon.
    LaunchDaemon,
    /// A systemd unit.
    SystemdUnit,
    /// A cron entry.
    Cron,
    /// A scheduled task.
    ScheduledTask,
    /// An XDG autostart desktop entry.
    XdgAutostart,
    /// A netsh helper DLL, loaded by every `netsh` invocation.
    NetshHelper,
    /// A print monitor DLL, loaded by the spooler.
    PrintMonitor,
    /// A time provider DLL, loaded by the time service.
    TimeProvider,
    /// A screensaver, which runs whenever the session is idle.
    Screensaver,
    /// A COM object registered for the shell, such as a context-menu handler.
    ShellExtension,
    /// A debugger that replaces the program it is registered for.
    Debugger,
    /// A library the dynamic loader maps into every process.
    Preload,
    /// A shell startup file, which runs on every login.
    ShellStartup,
    /// A kernel module whose load is replaced by a command.
    KernelModule,
    /// A udev rule that runs a program on a device event.
    UdevRule,
    /// A kind this build does not understand yet.
    Other,
}

impl AutorunKind {
    /// The stable name a pack rule writes. Interfaces use [`Self::label`].
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::RunKey => "run_key",
            Self::StartupFolder => "startup_folder",
            Self::Service => "service",
            Self::LaunchAgent => "launch_agent",
            Self::LaunchDaemon => "launch_daemon",
            Self::SystemdUnit => "systemd_unit",
            Self::Cron => "cron",
            Self::ScheduledTask => "scheduled_task",
            Self::XdgAutostart => "xdg_autostart",
            Self::Debugger => "debugger",
            Self::Preload => "preload",
            Self::ShellStartup => "shell_startup",
            Self::KernelModule => "kernel_module",
            Self::UdevRule => "udev_rule",
            Self::NetshHelper => "netsh_helper",
            Self::PrintMonitor => "print_monitor",
            Self::TimeProvider => "time_provider",
            Self::Screensaver => "screensaver",
            Self::ShellExtension => "shell_extension",
            Self::Other => "other",
        }
    }

    /// A short label for interfaces and reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::RunKey => "Run key",
            Self::StartupFolder => "Startup folder",
            Self::Service => "Service",
            Self::LaunchAgent => "Launch agent",
            Self::LaunchDaemon => "Launch daemon",
            Self::SystemdUnit => "systemd unit",
            Self::Cron => "Cron",
            Self::ScheduledTask => "Scheduled task",
            Self::XdgAutostart => "XDG autostart",
            Self::Debugger => "Debugger",
            Self::Preload => "Preloaded library",
            Self::ShellStartup => "Shell startup",
            Self::KernelModule => "Kernel module",
            Self::UdevRule => "udev rule",
            Self::NetshHelper => "netsh helper",
            Self::PrintMonitor => "Print monitor",
            Self::TimeProvider => "Time provider",
            Self::Screensaver => "Screensaver",
            Self::ShellExtension => "Shell extension",
            Self::Other => "Other",
        }
    }
}

/// Who an automatic start belongs to.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutorunScope {
    /// The signed-in user.
    User,
    /// The whole machine.
    System,
}

impl AutorunScope {
    /// The stable name a pack rule writes. Interfaces use [`Self::label`].
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
        }
    }

    /// A short label for interfaces and reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::System => "System",
        }
    }
}

/// Whether a binary's signature was evaluated, and what it said.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// This build does not verify signatures yet.
    #[default]
    NotChecked,
    /// A signature is present and the platform trusts it.
    Valid,
    /// A signature is present and the platform does not trust it.
    Invalid,
    /// The file has no signature.
    Unsigned,
    /// The question could not be answered.
    Unknown,
}

impl SignatureStatus {
    /// The stable name a pack rule writes. Interfaces use [`Self::label`].
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unsigned => "unsigned",
            Self::Unknown => "unknown",
        }
    }

    /// A short label for interfaces and reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "Not checked",
            Self::Valid => "Valid",
            Self::Invalid => "Invalid",
            Self::Unsigned => "Unsigned",
            Self::Unknown => "Unknown",
        }
    }
}

/// One thing that starts without a person clicking it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutorunFact {
    /// A stable identity, such as `run:hklm:64:AcmeHelper`.
    pub id: String,
    /// The name shown by the source.
    pub name: String,
    /// The command the source will run.
    pub command: String,
    /// The registry key, file, unit or plist the entry came from.
    pub location: String,
    /// The mechanism.
    pub kind: AutorunKind,
    /// Whether it belongs to the user or the machine.
    pub scope: AutorunScope,
    /// Whether the source says it is enabled.
    pub enabled: bool,
    /// Whether the source hides it from its own list.
    ///
    /// A scheduled task carries a `Hidden` setting that removes it from Task Scheduler's own
    /// view while leaving it scheduled. A registry value has no such thing, and says false.
    #[serde(default)]
    pub hidden: bool,
    /// The executable this entry reaches, when it could be resolved.
    pub exe: Option<String>,
    /// SHA-256 of the executable, when it was small enough to hash.
    pub sha256: Option<String>,
    /// Signature state, which v0.1 does not evaluate.
    pub signature: SignatureStatus,
}

/// A network socket waiting for a connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// A short label for interfaces and reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// A listening or bound socket.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerFact {
    /// The transport.
    pub protocol: Protocol,
    /// The address the socket is bound to.
    pub address: String,
    /// The port.
    pub port: u16,
    /// The owning process id, when the platform exposes it.
    pub pid: Option<u32>,
    /// The owning process name, when it could be resolved.
    pub process: Option<String>,
    /// The transport state, such as `LISTEN` or `UNCONN`.
    pub state: String,
    /// Whether the socket is bound to more than the loopback interface.
    pub public: bool,
}

/// One configuration that can run something on a person's behalf.
///
/// An editor's task, an agent client's server list and an SSH key with a forced command are
/// the same fact in different clothes: a file the person trusts names a program, and the
/// program runs without a click. The fact says what the file is, where it is, and what it
/// would run — not whether that is a good idea.
///
/// From 0.1.7 a fact may also be a **skill**: a `SKILL.md` and the files beside it. What a
/// skill's files would let it do is the [`AgentFact::capabilities`] matrix, one entry per
/// kind with the line that proved it, and [`AgentFact::hash`] is the digest of the package.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentFact {
    /// A stable identity, such as `mcp:claude-desktop:filesystem` or `skill:pdf-analysis`.
    pub id: String,
    /// Which kind of tool the configuration belongs to: `ssh`, `mcp` or `skill`.
    pub tool: String,
    /// The name the configuration gives the thing it would run.
    pub name: String,
    /// The configuration file that names it.
    pub path: String,
    /// The command it would run, when the configuration names one.
    pub command: Option<String>,
    /// What the files would let it do: `(kind, evidence)`, where the kind is one of
    /// `executes`, `network`, `writes`, `credentials` or `model`, and the evidence is the
    /// line that showed it.
    ///
    /// One entry per kind, never one per match: "it can execute" is the fact, and twelve
    /// lines that prove it are not twelve facts. Empty for a configuration that is not a
    /// skill, and empty for a skill whose files prove nothing.
    #[serde(default)]
    pub capabilities: Vec<(String, String)>,
    /// The SHA-256 of the skill package: one line per file it ships, in path order, in the
    /// shape `sha256sum` prints (`digest`, two spaces, path), hashed again.
    ///
    /// A digest of the package rather than of one file, because a skill is a folder: an
    /// edited script has to make a different fact. `None` for a configuration that is not a
    /// skill, and for a skill whose files could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// One installed package or application.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageFact {
    /// The name the source reports.
    pub name: String,
    /// The version, when the source has one.
    pub version: Option<String>,
    /// The publisher or maintainer, when the source has one.
    pub publisher: Option<String>,
    /// Which database the entry came from.
    pub source: String,
}

/// One file the content engine read, and what it found in it.
///
/// A fact about bytes, not a verdict about the machine. `matches` is empty for a file that
/// was read and held nothing, which is a different statement from a file that was never
/// read: `read_bytes` is `None` when only the hash was taken, and the interface says so.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFact {
    /// The full path, as the walk reached it.
    pub path: String,
    /// The file's name without its folder.
    pub name: String,
    /// The extension, lowercased, when there is one.
    pub extension: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// The SHA-256 of the whole file, when it was hashed.
    pub digest: Option<String>,
    /// What the bytes are: `pe`, `elf`, `mach-o`, `pdf`, `ole2` or `zip`, when identified.
    pub kind: Option<String>,
    /// What the platform says about the signature; `not_checked` when nothing asked.
    pub signature: SignatureStatus,
    /// The signer's name, when the signature names one.
    pub signer: Option<String>,
    /// The chain of containers this file was found inside, outermost first.
    #[serde(default)]
    pub container: Vec<String>,
    /// The name of the hash signature whose digest matched this file, when one did.
    pub hash_match: Option<String>,
    /// Every signature that matched, in the order the library holds them.
    #[serde(default)]
    pub matches: Vec<ContentMatch>,
    /// How many bytes of the file the scanner actually looked at.
    ///
    /// Equal to `size` for a file that was read whole, less for one that was truncated by a
    /// cap, and `None` when the file was not read at all.
    pub read_bytes: Option<u64>,
    /// The shape of an executable, when the bytes are one and this build read the header.
    ///
    /// `None` is "not an executable, or not read" — never "no sections": the difference is
    /// the whole point of the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structure: Option<Structure>,
}

/// The shape of an executable, as far as a scanner can see it without running it.
///
/// These are structural facts, not a verdict: a writable and executable section is how a
/// just-in-time compiler works and also how a packer works. Every count here is something a
/// person can check against the file itself with a hex editor, and the rule that reads them
/// names the benign case first.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Structure {
    /// The container format: `pe`, `elf` or `macho`.
    pub format: String,
    /// The machine or architecture, as the header spells it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// How many sections the header declares.
    #[serde(default)]
    pub sections: u32,
    /// How many sections are both writable and executable.
    #[serde(default)]
    pub writable_executable: u32,
    /// The highest Shannon entropy of any section, in hundredths of a bit per byte.
    ///
    /// 800 is 8.0, the ceiling; a section near it is compressed or encrypted data inside an
    /// executable, which is a fact about bytes and not about intent.
    #[serde(default)]
    pub max_entropy_x100: u16,
    /// How many imported symbols the file names.
    #[serde(default)]
    pub imports: u32,
    /// The import hash, when the file imports anything.
    ///
    /// A family hash in the open-source sense: the same imports in the same order give the
    /// same value, so two files of one family share it even when the bytes differ.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    /// Bytes after the last section, where an appended payload sits.
    #[serde(default)]
    pub overlay_bytes: u64,
    /// Whether the file carries an Authenticode signature blob.
    ///
    /// Carrying one is not the same as a valid one; this program reports what is there.
    #[serde(default)]
    pub signature_blob: bool,
}

/// One content signature that matched a file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentMatch {
    /// The signature's name, as its author wrote it.
    pub name: String,
    /// Where in the file it matched.
    pub at: u64,
    /// The line of the signature file it came from.
    pub line: u32,
}

/// The rhythm a connection is on, when repeated samples showed one.
///
/// The jitter is in basis points rather than as a float: a fact is compared, sorted and
/// serialised, and an `f64` would cost the first two for no gain the third can use.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeaconFact {
    /// How many times the connection was seen.
    pub contacts: usize,
    /// The middle interval between contacts, in seconds.
    pub interval_s: u64,
    /// The coefficient of variation, in basis points (150 means 1.5%).
    pub jitter_bp: u32,
}

/// One network connection the machine holds right now.
///
/// A listener is a socket waiting for something; this is a socket talking to somewhere. The
/// distinction matters because the second one names the other end, and "which process is
/// talking to what" is the question a person actually asks about traffic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowFact {
    /// TCP or UDP.
    pub protocol: Protocol,
    /// The local address.
    pub local_addr: String,
    /// The local port.
    pub local_port: u16,
    /// The address at the other end.
    pub remote_addr: String,
    /// The port at the other end.
    pub remote_port: u16,
    /// The state the socket is in, in the platform's own words (`ESTABLISHED`, `SYN_SENT`).
    pub state: String,
    /// The process that holds it, when the platform names one.
    pub pid: Option<u32>,
    /// That process's name, when it is known.
    pub process: Option<String>,
    /// Bytes moved, when the platform reports it per socket. Most do not, and `None` is
    /// printed as unknown rather than as zero: a zero is a measurement.
    pub bytes: Option<u64>,
    /// The rhythm this connection is on, when repeated samples showed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<BeaconFact>,
}
impl FlowFact {
    /// The identity a rhythm is remembered under: the process and the other end.
    ///
    /// The local port is deliberately not part of it. A client that reconnects on a schedule
    /// gets a new source port each time, and a key that carried the port would remember one
    /// contact per connection rather than one rhythm — which is the thing a beacon is.
    ///
    /// A connection this account cannot attribute is remembered as `unknown`, so flows whose
    /// process is invisible share one series. That can only hide a rhythm — several unseen
    /// processes talking to one peer produce a spread — and never invent one.
    #[must_use]
    pub fn beacon_key(&self) -> String {
        format!(
            "{}>{}:{}",
            self.process.as_deref().unwrap_or("unknown"),
            self.remote_addr,
            self.remote_port
        )
    }
}

/// How a collector finished.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    /// It collected everything it claims to.
    Ok,
    /// It collected something, and knows what it could not reach.
    Partial,
    /// It could not run on this machine, or in this mode.
    Unavailable,
}

impl CollectorState {
    /// A short label for interfaces and reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "Complete",
            Self::Partial => "Partial",
            Self::Unavailable => "Unavailable",
        }
    }
}

/// The outcome of one collector, as the interface needs to explain it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorStatus {
    /// A stable id, such as `windows.autoruns`.
    pub id: String,
    /// A human label.
    pub label: String,
    /// How it finished.
    pub state: CollectorState,
    /// Why it is partial or unavailable.
    pub reason: Option<String>,
    /// How many facts it produced.
    pub items: usize,
}

impl CollectorStatus {
    /// A complete collector.
    #[must_use]
    pub fn ok(id: &str, label: &str, items: usize) -> Self {
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            state: CollectorState::Ok,
            reason: None,
            items,
        }
    }

    /// A collector that produced some facts and knows what it missed.
    #[must_use]
    pub fn partial(id: &str, label: &str, items: usize, reason: &str) -> Self {
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            state: CollectorState::Partial,
            reason: Some(reason.to_owned()),
            items,
        }
    }

    /// A collector that could not run.
    #[must_use]
    pub fn unavailable(id: &str, label: &str, reason: &str) -> Self {
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            state: CollectorState::Unavailable,
            reason: Some(reason.to_owned()),
            items: 0,
        }
    }
}

/// One hash match against a local signature database.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureMatch {
    /// The fact this match belongs to, such as an autorun id.
    pub subject: String,
    /// The file that matched.
    pub path: String,
    /// `md5`, `sha1` or `sha256`.
    pub algorithm: String,
    /// The hash, in lower-case hexadecimal.
    pub hash: String,
    /// The signature's name.
    pub name: String,
}

/// What the local signature database contained, and what it found.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureReport {
    /// How many signatures are loaded.
    pub loaded: usize,
    /// Which algorithms the loaded set uses, lower-case.
    pub algorithms: Vec<String>,
    /// How many database lines were rejected as malformed.
    pub rejected: usize,
    /// Matches found during this scan.
    pub matches: Vec<SignatureMatch>,
    /// Human-readable notes about what was loaded or skipped.
    pub notes: Vec<String>,
}

/// How much a scan reads.
///
/// A profile is *which collectors run*, not a second code path: every collector already says
/// what it could not reach, so choosing a profile changes the size of the answer rather than
/// its honesty. The profile is recorded in the snapshot, because a saved scan that does not
/// say how it was taken invites "nothing was found" to mean "nothing was looked at".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    /// What is running and what starts: processes, startup items, listeners, connections.
    Quick,
    /// Everything the read-only collectors can reach. The default, and what a launch does.
    #[default]
    Standard,
    /// Everything, plus the bytes of the programs that start on their own.
    Deep,
}

impl ScanProfile {
    /// Every profile, in the order the interface offers them.
    pub const ALL: [ScanProfile; 3] = [Self::Quick, Self::Standard, Self::Deep];

    /// The stable name, used in a saved snapshot and in the journal.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Deep => "deep",
        }
    }

    /// What the interface calls it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Quick => "Quick scan",
            Self::Standard => "Standard scan",
            Self::Deep => "Deep scan",
        }
    }

    /// One sentence saying what it reads, for the button's tooltip and the report.
    #[must_use]
    pub fn one_line(self) -> &'static str {
        match self {
            Self::Quick => {
                "What is running now and what starts on its own. No packages and no agent \
                 configurations."
            }
            Self::Standard => {
                "Everything the collectors can read without elevation: processes, startup items, \
                 listeners, connections, packages and agent configurations."
            }
            Self::Deep => {
                "A standard scan, and then the bytes of the programs that start on their own, \
                 read against the local signature database."
            }
        }
    }

    /// Whether this profile reads the startup programs' bytes.
    #[must_use]
    pub fn reads_bodies(self) -> bool {
        matches!(self, Self::Deep)
    }

    /// Whether this profile reads the slower inventories.
    #[must_use]
    pub fn reads_inventories(self) -> bool {
        !matches!(self, Self::Quick)
    }
}

/// Everything one scan produced.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// The schema version of this document.
    pub schema: u32,
    /// Seconds since the Unix epoch when the scan finished.
    pub taken_at_unix: u64,
    /// How long collection took.
    pub duration_ms: u64,
    /// How much this scan read.
    ///
    /// Defaulted so a snapshot written before profiles existed loads as a standard scan,
    /// which is what it was.
    #[serde(default)]
    pub profile: ScanProfile,
    /// The host.
    pub host: Host,
    /// Whether this scan ran with elevated rights.
    pub elevated: bool,
    /// Running processes.
    pub processes: Vec<ProcessFact>,
    /// Automatic starts.
    pub autoruns: Vec<AutorunFact>,
    /// Listening sockets.
    pub listeners: Vec<ListenerFact>,
    /// Connections the machine is holding, with the process that holds them.
    #[serde(default)]
    pub flows: Vec<FlowFact>,
    /// Installed packages and applications.
    pub packages: Vec<PackageFact>,
    /// Configurations that can run something on the person's behalf.
    #[serde(default)]
    pub agents: Vec<AgentFact>,
    /// Files the content engine read, and what it found in them.
    ///
    /// Empty on a scan that did not read bytes: a deep check fills it, an inventory scan
    /// does not, and an empty list here means "not read" rather than "nothing found".
    #[serde(default)]
    pub files: Vec<FileFact>,
    /// Per-collector outcomes, including the ones that could not run.
    pub collectors: Vec<CollectorStatus>,
    /// Signature database state and matches.
    pub signatures: SignatureReport,
}

/// The headline counts the overview shows.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    /// Running processes.
    pub processes: usize,
    /// Automatic starts.
    pub autoruns: usize,
    /// Listening sockets.
    pub listeners: usize,
    /// Installed packages and applications.
    pub packages: usize,
}

impl Snapshot {
    /// An empty snapshot for a host.
    #[must_use]
    pub fn empty(host: Host, elevated: bool) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            taken_at_unix: 0,
            duration_ms: 0,
            profile: ScanProfile::Standard,
            host,
            elevated,
            processes: Vec::new(),
            autoruns: Vec::new(),
            listeners: Vec::new(),
            flows: Vec::new(),
            packages: Vec::new(),
            agents: Vec::new(),
            files: Vec::new(),
            collectors: Vec::new(),
            signatures: SignatureReport::default(),
        }
    }

    /// The headline counts.
    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            processes: self.processes.len(),
            autoruns: self.autoruns.len(),
            listeners: self.listeners.len(),
            packages: self.packages.len(),
        }
    }

    /// Whether the snapshot contains no facts at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
            && self.autoruns.is_empty()
            && self.listeners.is_empty()
            && self.packages.is_empty()
    }

    /// How many collectors were partial or unavailable.
    #[must_use]
    pub fn degraded(&self) -> usize {
        self.collectors
            .iter()
            .filter(|status| status.state != CollectorState::Ok)
            .count()
    }

    /// Whether any local signature matched.
    #[must_use]
    pub fn has_matches(&self) -> bool {
        !self.signatures.matches.is_empty()
    }

    /// Put every list in a stable order, so two scans of an unchanged machine can be
    /// compared and a report reads the same way twice.
    pub fn sort(&mut self) {
        self.processes.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.pid.cmp(&b.pid))
        });
        self.autoruns.sort_by(|a, b| {
            a.scope
                .label()
                .cmp(b.scope.label())
                .then_with(|| a.kind.label().cmp(b.kind.label()))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        self.listeners.sort_by(|a, b| {
            a.port
                .cmp(&b.port)
                .then_with(|| a.protocol.label().cmp(b.protocol.label()))
                .then_with(|| a.address.cmp(&b.address))
        });
        self.packages.sort_by_key(|package| package.name.to_lowercase());
        self.agents.sort_by(|a, b| {
            a.tool
                .cmp(&b.tool)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.path.cmp(&b.path))
        });
        self.collectors.sort_by(|a, b| a.id.cmp(&b.id));
        self.signatures
            .matches
            .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        let mut snapshot = Snapshot::empty(Host::default(), false);
        snapshot.processes.push(ProcessFact {
            pid: 2,
            parent: None,
            name: "b".into(),
            exe: None,
            command: None,
            user: None,
            started_at_unix: None,
        });
        snapshot.processes.push(ProcessFact {
            pid: 1,
            parent: None,
            name: "A".into(),
            exe: None,
            command: None,
            user: None,
            started_at_unix: None,
        });
        snapshot
    }

    #[test]
    fn counts_and_degraded() {
        let mut snapshot = snapshot();
        snapshot.collectors.push(CollectorStatus::ok("a", "A", 1));
        snapshot
            .collectors
            .push(CollectorStatus::unavailable("b", "B", "no"));
        assert_eq!(snapshot.counts().processes, 2);
        assert_eq!(snapshot.degraded(), 1);
        assert!(!snapshot.has_matches());
    }

    #[test]
    fn sort_is_case_insensitive_and_stable_by_pid() {
        let mut snapshot = snapshot();
        snapshot.sort();
        assert_eq!(snapshot.processes[0].name, "A");
        assert_eq!(snapshot.processes[0].pid, 1);
    }

    #[test]
    fn a_profile_names_itself_and_says_how_much_it_reads() {
        let mut seen = std::collections::HashSet::new();
        for profile in ScanProfile::ALL {
            assert!(seen.insert(profile.id()), "{} appears twice", profile.id());
            assert!(!profile.label().is_empty());
            assert!(!profile.one_line().is_empty());
        }
        // A quick scan is the only one that skips an inventory, and a deep scan is the only
        // one that reads a file's bytes: the two questions are what the scan asks.
        assert!(!ScanProfile::Quick.reads_inventories());
        assert!(ScanProfile::Standard.reads_inventories());
        assert!(ScanProfile::Deep.reads_inventories());
        assert!(!ScanProfile::Quick.reads_bodies());
        assert!(!ScanProfile::Standard.reads_bodies());
        assert!(ScanProfile::Deep.reads_bodies());
        assert_eq!(ScanProfile::default(), ScanProfile::Standard);
        // A snapshot written before profiles existed is a standard scan, which is what it was.
        assert_eq!(
            serde_json::from_str::<ScanProfile>("\"standard\"").unwrap_or_default(),
            ScanProfile::Standard
        );
    }

    #[test]
    fn a_rhythm_is_remembered_by_process_and_peer_not_by_local_port() {
        let flow = FlowFact {
            protocol: Protocol::Tcp,
            local_addr: "192.168.1.10".into(),
            local_port: 51_000,
            remote_addr: "203.0.113.9".into(),
            remote_port: 443,
            state: "ESTABLISHED".into(),
            pid: Some(7),
            process: Some("agent.exe".into()),
            bytes: None,
            beacon: None,
        };
        assert_eq!(flow.beacon_key(), "agent.exe>203.0.113.9:443");
        // The same client reconnecting gets a different source port and the same rhythm.
        let mut again = flow.clone();
        again.local_port = 51_999;
        assert_eq!(again.beacon_key(), flow.beacon_key());
        // A connection this account cannot attribute is one series, not one per flow.
        let mut anonymous = flow;
        anonymous.process = None;
        assert_eq!(anonymous.beacon_key(), "unknown>203.0.113.9:443");
    }
}
