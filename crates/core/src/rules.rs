//! Rules and findings: what a scan says about the machine, and why.
//!
//! A finding is not a verdict. Every one names the rule that fired, the facts it fired
//! on, why those facts matter, and the most likely innocent explanation. A rule that
//! cannot name a benign explanation may not ship as [`Severity::Attention`].
//!
//! The rules here are Rust functions with fixtures, not data loaded at runtime. Data
//! rules and signed packs arrive with the rule-pack milestone, where the signing and
//! schema work can be done together.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::{AutorunFact, AutorunScope, ProcessFact, Snapshot};

/// How much a finding deserves attention. It is about consequence, not confidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Context: something a person may want to know.
    Info,
    /// Worth a look, with an obvious benign explanation named.
    Notice,
    /// Unusual enough that a person should check it before dismissing it.
    Attention,
}

impl Severity {
    /// A short label for the interface.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Notice => "Notice",
            Self::Attention => "Attention",
        }
    }

    /// Higher is more serious, for sorting.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Notice => 1,
            Self::Attention => 2,
        }
    }
}

/// How sure ranger is of the interpretation. `Observed` means the fact is certain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The fact itself was observed; the interpretation may still be wrong.
    Observed,
    /// Inferred from a pattern, which is named in the evidence.
    Likely,
    /// One of several readings of the facts.
    Possible,
}

impl Confidence {
    /// A short label for the interface.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Observed => "Observed",
            Self::Likely => "Likely",
            Self::Possible => "Possible",
        }
    }
}

/// What a rule says about the facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The stable rule id, never reused for a different meaning.
    pub rule_id: &'static str,
    /// The rule's short title.
    pub title: &'static str,
    /// Consequence, not confidence.
    pub severity: Severity,
    /// How sure the interpretation is.
    pub confidence: Confidence,
    /// A stable identity for this finding, used by suppressions.
    pub subject: String,
    /// The thing a person recognises, in words.
    pub subject_label: String,
    /// What was observed, one fact per line.
    pub evidence: Vec<String>,
    /// Why those facts matter.
    pub why: &'static str,
    /// The most likely innocent explanation.
    pub benign: &'static str,
    /// What a person can do about it.
    pub remediation: &'static str,
}

/// A person's decision to stop seeing one rule fire on one subject, until it expires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    /// The rule it covers.
    pub rule_id: String,
    /// The subject it covers.
    pub subject: String,
    /// Why the person accepted it.
    pub reason: String,
    /// Seconds since the Unix epoch after which it no longer applies.
    pub expires_unix: u64,
}

impl Suppression {
    /// How long a fresh suppression lasts when the interface offers the default.
    pub const DEFAULT_DAYS: u64 = 30;

    /// Whether the suppression still applies at `now`.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        self.expires_unix > now
    }

    /// Whether it covers this finding.
    #[must_use]
    pub fn covers(&self, finding: &Finding) -> bool {
        self.rule_id == finding.rule_id && self.subject == finding.subject
    }
}

/// Remove findings that an active suppression covers.
#[must_use]
pub fn apply_suppressions(findings: Vec<Finding>, suppressions: &[Suppression], now: u64) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| {
            !suppressions
                .iter()
                .any(|suppression| suppression.is_active(now) && suppression.covers(finding))
        })
        .collect()
}

/// Drop suppressions that have expired.
pub fn prune_suppressions(suppressions: &mut Vec<Suppression>, now: u64) {
    suppressions.retain(|suppression| suppression.is_active(now));
}

struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    confidence: Confidence,
    why: &'static str,
    benign: &'static str,
    remediation: &'static str,
}

const TEMP_PATH: Rule = Rule {
    id: "startup.temp-path",
    title: "A startup item runs from a temporary folder",
    severity: Severity::Attention,
    confidence: Confidence::Observed,
    why: "Temporary folders are cleared by the system and are writable by ordinary programs. \
          Software that is meant to keep running is normally installed somewhere that does \
          not get cleaned up.",
    benign: "Some installers and updaters register a helper in a temporary folder and replace \
             it on their next run.",
    remediation: "Open the folder and check the file's publisher and signature. If you did not \
                  install it, remove the startup entry.",
};

const DOWNLOADS_PATH: Rule = Rule {
    id: "startup.downloads-path",
    title: "A startup item runs from Downloads or the Desktop",
    severity: Severity::Attention,
    confidence: Confidence::Observed,
    why: "Downloads and the Desktop are where files arrive from elsewhere. An automatically \
          started program living there is worth a look.",
    benign: "A portable application someone unzipped and pinned to start with the session.",
    remediation: "Open the folder, check where the file came from, and move or remove the entry \
                  if you do not recognise it.",
};

const SCRIPT_EXTENSION: Rule = Rule {
    id: "startup.script-extension",
    title: "A startup item runs a script",
    severity: Severity::Notice,
    confidence: Confidence::Observed,
    why: "Scripts are text and are easy to edit after they are registered. That is common and \
          legitimate, and it is also how a startup entry can change what it does without \
          changing its name.",
    benign: "A backup, sync or keyboard-remapping tool that ships its logic as a script.",
    remediation: "Open the script and read it. If it is unfamiliar, remove the startup entry.",
};

const BARE_COMMAND: Rule = Rule {
    id: "startup.bare-command",
    title: "A startup command does not name a full path",
    severity: Severity::Notice,
    confidence: Confidence::Observed,
    why: "A command that is resolved through the search path can run a different file \
          depending on where it is launched from.",
    benign: "Many installers register `updater.exe` and rely on the working directory.",
    remediation: "Check the entry's command and its working directory; a full path is clearer.",
};

const SHELL_INTERPRETER: Rule = Rule {
    id: "startup.shell-interpreter",
    title: "A startup item launches a shell or script host",
    severity: Severity::Notice,
    confidence: Confidence::Observed,
    why: "A startup entry that runs an interpreter runs whatever text it is pointed at. The \
          entry's name does not tell you what the code does.",
    benign: "Vendor updaters, backup scripts and terminal setups do this routinely.",
    remediation: "Read the script or command the interpreter is given.",
};

const USER_WRITABLE_SYSTEM: Rule = Rule {
    id: "startup.user-writable-system",
    title: "A machine-wide startup item points into a user folder",
    severity: Severity::Attention,
    confidence: Confidence::Observed,
    why: "A machine-wide entry that runs a file from one user's profile is unusual: the file \
          can be replaced by anything running as that user, and the entry runs for every user.",
    benign: "An installer that registered a per-user installation machine-wide by mistake.",
    remediation: "Check the entry's target and whether it belongs to an application you \
                  installed deliberately.",
};

const HASH_CHANGED: Rule = Rule {
    id: "startup.hash-changed",
    title: "A startup binary changed since the baseline",
    severity: Severity::Attention,
    confidence: Confidence::Observed,
    why: "The file is the same startup entry, but its bytes are different from the day you \
          accepted the baseline. Updates do this; so does anything else that writes to that \
          file.",
    benign: "The application updated itself since the baseline was accepted.",
    remediation: "Check the application's version and publisher. If it did not update, look at \
                  the file before trusting it.",
};

const NEW_SINCE_BASELINE: Rule = Rule {
    id: "startup.new-since-baseline",
    title: "A startup item is new since the baseline",
    severity: Severity::Notice,
    confidence: Confidence::Observed,
    why: "This entry was not present when you accepted the baseline. New persistence is worth \
          knowing about even when it is legitimate.",
    benign: "You installed or updated an application that starts with the session.",
    remediation: "Approve it by accepting a new baseline once you recognise it, or remove the \
                  entry.",
};

const PROCESS_TEMP: Rule = Rule {
    id: "process.temp-path",
    title: "A running process is in a temporary folder",
    severity: Severity::Notice,
    confidence: Confidence::Observed,
    why: "Running from a temporary location means the program is not installed in the usual \
          sense; the file may not be there after a reboot.",
    benign: "An installer, an unpacker, or a development tool running from a build directory.",
    remediation: "Identify the parent process that started it and whether it is still running.",
};

const PROCESS_DOWNLOADS: Rule = Rule {
    id: "process.downloads-path",
    title: "A running process is in Downloads or on the Desktop",
    severity: Severity::Notice,
    confidence: Confidence::Observed,
    why: "Programs are usually installed elsewhere. A process running from where files arrive \
          is worth a look, especially if it is long-lived.",
    benign: "A portable tool or a script someone launched directly.",
    remediation: "Check which process started it and whether you launched it.",
};

const PARENT_EXITED: Rule = Rule {
    id: "process.parent-exited",
    title: "A process outlived the process that started it",
    severity: Severity::Info,
    confidence: Confidence::Observed,
    why: "The recorded parent is gone. This is normal for background helpers and is listed so \
          the ancestry in the inventory stays honest.",
    benign: "Almost always: the launcher exits once the real program is running.",
    remediation: "None needed unless the process itself looks unfamiliar.",
};

const PUBLIC_NEW_PROCESS: Rule = Rule {
    id: "listener.public-new-process",
    title: "A recently started process listens beyond loopback",
    severity: Severity::Notice,
    confidence: Confidence::Likely,
    why: "A socket that accepts connections from other machines is reachable. When the process \
          holding it started recently, it is worth knowing what it is.",
    benign: "A file-sharing, remote-desktop, development or media application that was just \
             started or updated.",
    remediation: "Check whether the application is expected to accept network connections and \
                  whether the firewall allows it.",
};

const PUBLIC_UNKNOWN_OWNER: Rule = Rule {
    id: "listener.public-unknown-owner",
    title: "A public socket has no visible owner",
    severity: Severity::Info,
    confidence: Confidence::Observed,
    why: "The socket belongs to a process this account cannot see. That is a permission gap, \
          not evidence of a problem.",
    benign: "A system service or another user's process; an administrator scan may name it.",
    remediation: "Run an administrator scan on Windows if you want the owner named.",
};

const PERSISTENT_LISTENING: Rule = Rule {
    id: "agent.persistent-listening",
    title: "A persistent program is waiting for connections",
    severity: Severity::Notice,
    confidence: Confidence::Likely,
    why: "This program starts on its own and holds a listening socket. That is the shape of a \
          background agent: it acts without a person in the loop.",
    benign: "Remote access, sync, media servers and development tools all have this shape on \
             purpose.",
    remediation: "Check the startup entry and the socket together; if you did not set it up, \
                  remove the entry.",
};

const DUPLICATE_COMMAND: Rule = Rule {
    id: "startup.duplicate-command",
    title: "One command is registered as several startup items",
    severity: Severity::Info,
    confidence: Confidence::Observed,
    why: "Duplicates are usually harmless, but they make it harder to tell which entry is the \
          live one when the command changes.",
    benign: "Two installers registering the same updater, or a user and machine entry for one \
             application.",
    remediation: "Remove the redundant entries if you want the list to say what actually runs.",
};

/// Evaluate every built-in rule against a scan and its baseline.
///
/// The result is sorted by severity and then by rule and subject, so two evaluations of the
/// same facts read the same way twice.
#[must_use]
pub fn evaluate(snapshot: &Snapshot, baseline: Option<&Snapshot>) -> Vec<Finding> {
    let mut findings = Vec::new();
    temp_and_downloads_autoruns(snapshot, &mut findings);
    script_autoruns(snapshot, &mut findings);
    commands(snapshot, &mut findings);
    system_scope(snapshot, &mut findings);
    baseline_changes(snapshot, baseline, &mut findings);
    process_locations(snapshot, &mut findings);
    exited_parents(snapshot, &mut findings);
    public_listeners(snapshot, &mut findings);
    persistent_listeners(snapshot, &mut findings);
    duplicate_commands(snapshot, &mut findings);

    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.rule_id.cmp(b.rule_id))
            .then_with(|| a.subject.cmp(&b.subject))
    });
    findings
}

fn make(rule: &Rule, subject: String, subject_label: String, evidence: Vec<String>) -> Finding {
    Finding {
        rule_id: rule.id,
        title: rule.title,
        severity: rule.severity,
        confidence: rule.confidence,
        subject,
        subject_label,
        evidence,
        why: rule.why,
        benign: rule.benign,
        remediation: rule.remediation,
    }
}

fn temp_and_downloads_autoruns(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    for entry in &snapshot.autoruns {
        let Some(exe) = entry.exe.as_deref() else {
            continue;
        };
        let subject = format!("autorun:{}", entry.id);
        let label = format!("{} ({})", entry.name, entry.kind.label());
        if under(exe, "temp") {
            findings.push(make(
                &TEMP_PATH,
                subject.clone(),
                label.clone(),
                vec![
                    format!("Executable: {exe}"),
                    format!("Registered at: {}", entry.location),
                    format!("Scope: {}", entry.scope.label()),
                ],
            ));
        }
        if under(exe, "downloads") || under(exe, "desktop") {
            findings.push(make(
                &DOWNLOADS_PATH,
                subject,
                label,
                vec![
                    format!("Executable: {exe}"),
                    format!("Registered at: {}", entry.location),
                ],
            ));
        }
    }
}

fn script_autoruns(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    const SCRIPT_EXTENSIONS: [&str; 7] = ["ps1", "vbs", "js", "jse", "bat", "cmd", "hta"];
    for entry in &snapshot.autoruns {
        let Some(exe) = entry.exe.as_deref() else {
            continue;
        };
        let Some(extension) = extension(exe) else {
            continue;
        };
        if !SCRIPT_EXTENSIONS.contains(&extension.as_str()) {
            continue;
        }
        findings.push(make(
            &SCRIPT_EXTENSION,
            format!("autorun:{}", entry.id),
            format!("{} ({})", entry.name, entry.kind.label()),
            vec![
                format!("Executable: {exe}"),
                format!("Command: {}", entry.command),
                format!("Registered at: {}", entry.location),
            ],
        ));
    }
}

fn commands(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    const INTERPRETERS: [&str; 7] = [
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "bash",
    ];
    for entry in &snapshot.autoruns {
        let first = first_token(&entry.command);
        if first.is_empty() {
            continue;
        }
        let subject = format!("autorun:{}", entry.id);
        let label = format!("{} ({})", entry.name, entry.kind.label());
        if !is_absolute(first) && !starts_with_expansion(first) {
            findings.push(make(
                &BARE_COMMAND,
                subject.clone(),
                label.clone(),
                vec![
                    format!("Command: {}", entry.command),
                    format!("Registered at: {}", entry.location),
                ],
            ));
        }
        let file = file_name(first);
        if INTERPRETERS.contains(&file.as_str()) {
            findings.push(make(
                &SHELL_INTERPRETER,
                subject,
                label,
                vec![
                    format!("Command: {}", entry.command),
                    format!("Interpreter: {file}"),
                    format!("Registered at: {}", entry.location),
                ],
            ));
        }
    }
}

fn system_scope(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    for entry in &snapshot.autoruns {
        if entry.scope != AutorunScope::System {
            continue;
        }
        let Some(exe) = entry.exe.as_deref() else {
            continue;
        };
        if !(under(exe, "users") || under(exe, "appdata") || under(exe, "temp")) {
            continue;
        }
        findings.push(make(
            &USER_WRITABLE_SYSTEM,
            format!("autorun:{}", entry.id),
            format!("{} ({})", entry.name, entry.kind.label()),
            vec![
                format!("Executable: {exe}"),
                format!("Scope: {}", entry.scope.label()),
                format!("Registered at: {}", entry.location),
            ],
        ));
    }
}

fn baseline_changes(snapshot: &Snapshot, baseline: Option<&Snapshot>, findings: &mut Vec<Finding>) {
    let Some(baseline) = baseline else {
        return;
    };
    let before: HashMap<&str, &AutorunFact> = baseline
        .autoruns
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();

    for entry in &snapshot.autoruns {
        let subject = format!("autorun:{}", entry.id);
        let label = format!("{} ({})", entry.name, entry.kind.label());
        match before.get(entry.id.as_str()) {
            None => findings.push(make(
                &NEW_SINCE_BASELINE,
                subject,
                label,
                vec![
                    format!("Command: {}", entry.command),
                    format!("Registered at: {}", entry.location),
                ],
            )),
            Some(previous) => {
                if let (Some(old), Some(new)) = (&previous.sha256, &entry.sha256)
                    && old != new
                {
                    findings.push(make(
                        &HASH_CHANGED,
                        subject,
                        label,
                        vec![
                            format!("Executable: {}", entry.exe.as_deref().unwrap_or("—")),
                            format!("Hash at the baseline: {old}"),
                            format!("Hash now: {new}"),
                        ],
                    ));
                }
            }
        }
    }
}

fn process_locations(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    for process in &snapshot.processes {
        let Some(exe) = process.exe.as_deref() else {
            continue;
        };
        let subject = format!("process:{}", process.pid);
        let label = format!("{} (pid {})", process.name, process.pid);
        if under(exe, "temp") {
            findings.push(make(
                &PROCESS_TEMP,
                subject.clone(),
                label.clone(),
                vec![
                    format!("Executable: {exe}"),
                    format!(
                        "Parent pid: {}",
                        process.parent.map_or_else(|| "—".to_owned(), |p| p.to_string())
                    ),
                ],
            ));
        }
        if under(exe, "downloads") || under(exe, "desktop") {
            findings.push(make(
                &PROCESS_DOWNLOADS,
                subject,
                label,
                vec![
                    format!("Executable: {exe}"),
                    format!("User: {}", process.user.as_deref().unwrap_or("—")),
                ],
            ));
        }
    }
}

fn exited_parents(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    let pids: HashSet<u32> = snapshot.processes.iter().map(|process| process.pid).collect();
    for process in &snapshot.processes {
        let Some(parent) = process.parent else {
            continue;
        };
        if parent == 0 || pids.contains(&parent) {
            continue;
        }
        findings.push(make(
            &PARENT_EXITED,
            format!("process:{}", process.pid),
            format!("{} (pid {})", process.name, process.pid),
            vec![
                format!("Parent pid: {parent}"),
                format!("Executable: {}", process.exe.as_deref().unwrap_or("—")),
            ],
        ));
    }
}

fn public_listeners(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    const WEEK: u64 = 7 * 24 * 60 * 60;
    let processes: HashMap<u32, &ProcessFact> = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();

    for listener in &snapshot.listeners {
        if !listener.public {
            continue;
        }
        let subject = format!(
            "listener:{}:{}:{}",
            listener.protocol.label().to_lowercase(),
            listener.address,
            listener.port
        );
        let label = format!(
            "{} {}:{}",
            listener.protocol.label(),
            listener.address,
            listener.port
        );
        match listener.pid.and_then(|pid| processes.get(&pid)) {
            Some(process) => {
                let Some(started) = process.started_at_unix else {
                    continue;
                };
                let age = snapshot.taken_at_unix.saturating_sub(started);
                if age > WEEK {
                    continue;
                }
                findings.push(make(
                    &PUBLIC_NEW_PROCESS,
                    subject,
                    label,
                    vec![
                        format!("Owner: {} (pid {})", process.name, process.pid),
                        format!("Executable: {}", process.exe.as_deref().unwrap_or("—")),
                        format!("Started: {} day(s) ago", age / 86_400),
                    ],
                ));
            }
            None => findings.push(make(
                &PUBLIC_UNKNOWN_OWNER,
                subject,
                label,
                vec![format!("State: {}", listener.state)],
            )),
        }
    }
}

fn persistent_listeners(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    let processes: HashMap<u32, &ProcessFact> = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut seen = HashSet::new();

    for listener in &snapshot.listeners {
        let Some(pid) = listener.pid else {
            continue;
        };
        let Some(process) = processes.get(&pid) else {
            continue;
        };
        let Some(exe) = process.exe.as_deref() else {
            continue;
        };
        if !seen.insert(pid) {
            continue;
        }
        let Some(entry) = snapshot
            .autoruns
            .iter()
            .find(|entry| entry.exe.as_deref().is_some_and(|target| same_path(target, exe)))
        else {
            continue;
        };
        findings.push(make(
            &PERSISTENT_LISTENING,
            format!("process:{pid}"),
            format!("{} (pid {pid})", process.name),
            vec![
                format!("Startup: {} at {}", entry.name, entry.location),
                format!(
                    "Socket: {} {}:{}",
                    listener.protocol.label(),
                    listener.address,
                    listener.port
                ),
                format!("Executable: {exe}"),
            ],
        ));
    }
}

fn duplicate_commands(snapshot: &Snapshot, findings: &mut Vec<Finding>) {
    let mut groups: HashMap<String, Vec<&AutorunFact>> = HashMap::new();
    for entry in &snapshot.autoruns {
        let command = entry.command.trim().to_lowercase();
        if command.len() < 4 {
            continue;
        }
        groups.entry(command).or_default().push(entry);
    }
    for (command, entries) in groups {
        if entries.len() < 2 {
            continue;
        }
        let mut evidence = vec![format!("Command: {command}")];
        for entry in &entries {
            evidence.push(format!("{} at {}", entry.name, entry.location));
        }
        // The label is what a person recognises. A program token with an extension names
        // the program; a command whose path contains spaces but is not quoted tokenises to
        // something like `C:\Program`, which names nothing, so the entry's own name is
        // used instead. Either way the evidence carries the full command.
        let program = first_token(&command);
        let label = match (extension(program), entries.first()) {
            (Some(_), _) => file_name(program),
            (None, Some(entry)) if !entry.name.trim().is_empty() => entry.name.trim().to_lowercase(),
            _ => command.chars().take(40).collect(),
        };
        findings.push(make(
            &DUPLICATE_COMMAND,
            format!("autorun-group:{command}"),
            label,
            evidence,
        ));
    }
}

fn same_path(a: &str, b: &str) -> bool {
    windowsish(a) == windowsish(b)
}

fn windowsish(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

fn under(path: &str, directory: &str) -> bool {
    windowsish(path).contains(&format!("\\{directory}\\"))
}

fn extension(path: &str) -> Option<String> {
    let name = file_name(path);
    name.rsplit_once('.')
        .map(|(_, extension)| extension.to_lowercase())
}

fn file_name(path: &str) -> String {
    let path = path.trim_matches('"');
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_lowercase()
}

fn first_token(command: &str) -> &str {
    let trimmed = command.trim();
    match trimmed.strip_prefix('"') {
        // A quoted program is everything up to the closing quote. Splitting it at the
        // first space would report `C:\Program` as the program, which is how a path with
        // spaces turns into a false "bare command" and a useless subject.
        Some(rest) => rest.split('"').next().unwrap_or(rest),
        None => trimmed.split_whitespace().next().unwrap_or(""),
    }
}

fn is_absolute(token: &str) -> bool {
    let token = token.trim_matches('"');
    token.starts_with('/') || token.starts_with('\\') || token.as_bytes().get(1) == Some(&b':')
}

fn starts_with_expansion(token: &str) -> bool {
    token.starts_with('%') || token.starts_with('$')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AutorunKind, Host, ListenerFact, Protocol};

    fn autorun(id: &str, name: &str, exe: Option<&str>, command: &str) -> AutorunFact {
        AutorunFact {
            id: id.to_owned(),
            name: name.to_owned(),
            command: command.to_owned(),
            location: "HKCU\\Run".to_owned(),
            kind: AutorunKind::RunKey,
            scope: AutorunScope::User,
            enabled: true,
            exe: exe.map(str::to_owned),
            sha256: None,
            signature: crate::model::SignatureStatus::NotChecked,
        }
    }

    fn process(pid: u32, parent: Option<u32>, name: &str, exe: Option<&str>, started: u64) -> ProcessFact {
        ProcessFact {
            pid,
            parent,
            name: name.to_owned(),
            exe: exe.map(str::to_owned),
            command: None,
            user: None,
            started_at_unix: Some(started),
        }
    }

    fn listener(port: u16, pid: Option<u32>, public: bool) -> ListenerFact {
        ListenerFact {
            protocol: Protocol::Tcp,
            address: "0.0.0.0".to_owned(),
            port,
            pid,
            process: pid.map(|_| "owner".to_owned()),
            state: "LISTEN".to_owned(),
            public,
        }
    }

    fn snapshot() -> Snapshot {
        let mut snapshot = Snapshot::empty(Host::default(), false);
        snapshot.taken_at_unix = 1_000_000;
        snapshot
    }

    fn has(findings: &[Finding], rule: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule)
    }

    #[test]
    fn a_clean_machine_produces_no_findings() {
        let mut snapshot = snapshot();
        snapshot
            .processes
            .push(process(1, None, "init", Some("/usr/bin/init"), 900_000));
        snapshot.autoruns.push(autorun(
            "run:user:Acme",
            "Acme",
            Some("C:\\Program Files\\Acme\\acme.exe"),
            "C:\\Program Files\\Acme\\acme.exe",
        ));
        assert!(evaluate(&snapshot, None).is_empty());
    }

    #[test]
    fn a_startup_item_in_temp_is_attention() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:Helper",
            "Helper",
            Some("C:\\Users\\me\\AppData\\Local\\Temp\\helper.exe"),
            "C:\\Users\\me\\AppData\\Local\\Temp\\helper.exe",
        ));
        let findings = evaluate(&snapshot, None);
        assert!(has(&findings, "startup.temp-path"));
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "startup.temp-path")
            .unwrap();
        assert_eq!(finding.severity, Severity::Attention);
        assert!(!finding.benign.is_empty());
    }

    #[test]
    fn a_startup_item_in_downloads_fires() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:Tool",
            "Tool",
            Some("C:\\Users\\me\\Downloads\\tool.exe"),
            "C:\\Users\\me\\Downloads\\tool.exe",
        ));
        assert!(has(&evaluate(&snapshot, None), "startup.downloads-path"));
    }

    #[test]
    fn a_script_startup_item_fires() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:Sync",
            "Sync",
            Some("C:\\Tools\\sync.ps1"),
            "C:\\Tools\\sync.ps1",
        ));
        assert!(has(&evaluate(&snapshot, None), "startup.script-extension"));
    }

    #[test]
    fn a_bare_command_fires_but_an_expanded_one_does_not() {
        let mut snapshot = snapshot();
        snapshot
            .autoruns
            .push(autorun("run:user:A", "A", None, "updater.exe /quiet"));
        snapshot.autoruns.push(autorun(
            "run:user:B",
            "B",
            None,
            "%SystemRoot%\\System32\\rundll32.exe shell32.dll,Control_RunDLL",
        ));
        let findings = evaluate(&snapshot, None);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id == "startup.bare-command")
                .count(),
            1
        );
    }

    #[test]
    fn an_interpreter_startup_item_fires() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:C",
            "C",
            None,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -File C:\\x.ps1",
        ));
        assert!(has(&evaluate(&snapshot, None), "startup.shell-interpreter"));
    }

    #[test]
    fn a_machine_entry_in_a_user_folder_fires() {
        let mut snapshot = snapshot();
        let mut entry = autorun(
            "run:machine:D",
            "D",
            Some("C:\\Users\\me\\AppData\\Local\\D\\d.exe"),
            "C:\\Users\\me\\AppData\\Local\\D\\d.exe",
        );
        entry.scope = AutorunScope::System;
        snapshot.autoruns.push(entry);
        assert!(has(&evaluate(&snapshot, None), "startup.user-writable-system"));
    }

    #[test]
    fn a_changed_binary_is_reported_against_the_baseline() {
        let mut before = snapshot();
        let mut entry = autorun(
            "run:user:E",
            "E",
            Some("C:\\Program Files\\E\\e.exe"),
            "C:\\Program Files\\E\\e.exe",
        );
        entry.sha256 = Some("aa".to_owned());
        before.autoruns.push(entry.clone());

        let mut after = snapshot();
        entry.sha256 = Some("bb".to_owned());
        after.autoruns.push(entry);

        let findings = evaluate(&after, Some(&before));
        assert!(has(&findings, "startup.hash-changed"));
        assert!(!has(&findings, "startup.new-since-baseline"));
    }

    #[test]
    fn a_new_entry_is_reported_against_the_baseline() {
        let before = snapshot();
        let mut after = snapshot();
        after.autoruns.push(autorun(
            "run:user:F",
            "F",
            Some("C:\\Program Files\\F\\f.exe"),
            "C:\\Program Files\\F\\f.exe",
        ));
        assert!(has(
            &evaluate(&after, Some(&before)),
            "startup.new-since-baseline"
        ));
    }

    #[test]
    fn a_process_in_temp_fires() {
        let mut snapshot = snapshot();
        snapshot.processes.push(process(
            7,
            Some(1),
            "installer",
            Some("C:\\Temp\\setup.exe"),
            999_000,
        ));
        assert!(has(&evaluate(&snapshot, None), "process.temp-path"));
    }

    #[test]
    fn a_process_in_downloads_fires() {
        let mut snapshot = snapshot();
        snapshot.processes.push(process(
            8,
            Some(1),
            "tool",
            Some("C:\\Users\\me\\Downloads\\tool.exe"),
            999_000,
        ));
        assert!(has(&evaluate(&snapshot, None), "process.downloads-path"));
    }

    #[test]
    fn a_process_whose_parent_exited_is_info() {
        let mut snapshot = snapshot();
        snapshot.processes.push(process(
            9,
            Some(4242),
            "helper",
            Some("C:\\Helper\\h.exe"),
            999_000,
        ));
        let findings = evaluate(&snapshot, None);
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "process.parent-exited")
            .unwrap();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn a_recent_public_listener_fires_but_an_old_one_does_not() {
        let mut snapshot = snapshot();
        snapshot
            .processes
            .push(process(10, None, "server", Some("C:\\Server\\s.exe"), 999_000));
        snapshot.listeners.push(listener(8080, Some(10), true));
        let fresh = evaluate(&snapshot, None);
        assert!(has(&fresh, "listener.public-new-process"));

        let mut old = snapshot.clone();
        old.processes[0].started_at_unix = Some(100_000);
        assert!(!has(&evaluate(&old, None), "listener.public-new-process"));
    }

    #[test]
    fn a_public_socket_with_no_visible_owner_is_info() {
        let mut snapshot = snapshot();
        snapshot.listeners.push(listener(443, None, true));
        let findings = evaluate(&snapshot, None);
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "listener.public-unknown-owner")
            .unwrap();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn a_persistent_listener_names_its_startup_entry() {
        let mut snapshot = snapshot();
        snapshot
            .processes
            .push(process(11, None, "server", Some("C:\\Server\\s.exe"), 999_000));
        snapshot.autoruns.push(autorun(
            "run:user:S",
            "S",
            Some("C:\\Server\\s.exe"),
            "C:\\Server\\s.exe",
        ));
        snapshot.listeners.push(listener(9000, Some(11), false));
        let findings = evaluate(&snapshot, None);
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "agent.persistent-listening")
            .unwrap();
        assert!(
            finding
                .evidence
                .iter()
                .any(|line| line.contains("run:user:S") || line.contains("S at"))
        );
    }

    #[test]
    fn duplicate_commands_are_reported_once() {
        let mut snapshot = snapshot();
        snapshot
            .autoruns
            .push(autorun("run:user:G1", "G1", None, "C:\\G\\g.exe /start"));
        snapshot
            .autoruns
            .push(autorun("run:user:G2", "G2", None, "C:\\G\\g.exe /start"));
        let findings = evaluate(&snapshot, None);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule_id == "startup.duplicate-command")
                .count(),
            1
        );
    }

    #[test]
    fn a_quoted_program_with_spaces_is_one_token() {
        assert_eq!(
            first_token("\"C:\\Program Files\\App\\app.exe\" --silent"),
            "C:\\Program Files\\App\\app.exe"
        );
        assert_eq!(
            first_token("C:\\Windows\\svchost.exe -k netsvcs"),
            "C:\\Windows\\svchost.exe"
        );
        assert_eq!(first_token("   "), "");
        assert_eq!(first_token("\"C:\\unclosed"), "C:\\unclosed");
    }

    #[test]
    fn a_duplicate_group_is_labelled_with_the_program_it_duplicates() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:D1",
            "D1",
            None,
            "\"C:\\Program Files\\Some App\\some.exe\" --update",
        ));
        snapshot.autoruns.push(autorun(
            "run:user:D2",
            "D2",
            None,
            "\"C:\\Program Files\\Some App\\some.exe\" --update",
        ));
        let findings = evaluate(&snapshot, None);
        let duplicate = findings
            .iter()
            .find(|f| f.rule_id == "startup.duplicate-command")
            .expect("the duplicate is reported");
        assert_eq!(duplicate.subject_label, "some.exe");
        assert!(
            duplicate
                .evidence
                .iter()
                .any(|line| line.to_lowercase().contains("some app")),
            "the evidence still names the full command"
        );
    }

    #[test]
    fn a_duplicate_group_with_an_unquoted_path_falls_back_to_the_entry_name() {
        let mut snapshot = snapshot();
        // An unquoted path with a space really does tokenise to `C:\Program`; the finding
        // must not be labelled with that fragment.
        snapshot.autoruns.push(autorun(
            "run:user:E1",
            "Razer Synapse",
            None,
            "C:\\Program Files\\Razer\\RazerAppEngine.exe -startup",
        ));
        snapshot.autoruns.push(autorun(
            "run:user:E2",
            "Razer Synapse",
            None,
            "C:\\Program Files\\Razer\\RazerAppEngine.exe -startup",
        ));
        let findings = evaluate(&snapshot, None);
        let duplicate = findings
            .iter()
            .find(|f| f.rule_id == "startup.duplicate-command")
            .expect("the duplicate is reported");
        assert_eq!(duplicate.subject_label, "razer synapse");
        assert_ne!(duplicate.subject_label, "program");
    }

    #[test]
    fn suppressions_cover_one_rule_and_expire() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:H",
            "H",
            Some("C:\\Temp\\h.exe"),
            "C:\\Temp\\h.exe",
        ));
        let findings = evaluate(&snapshot, None);
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "startup.temp-path")
            .unwrap();
        let suppression = Suppression {
            rule_id: finding.rule_id.to_owned(),
            subject: finding.subject.clone(),
            reason: "I installed this".to_owned(),
            expires_unix: 2_000_000,
        };
        let kept = apply_suppressions(findings.clone(), std::slice::from_ref(&suppression), 1_500_000);
        assert!(!kept.iter().any(|f| f.rule_id == "startup.temp-path"));
        let expired = apply_suppressions(findings, &[suppression], 2_000_001);
        assert!(expired.iter().any(|f| f.rule_id == "startup.temp-path"));
    }

    #[test]
    fn every_finding_carries_evidence_and_an_explanation() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:J",
            "J",
            Some("C:\\Temp\\j.exe"),
            "C:\\Temp\\j.exe",
        ));
        snapshot
            .autoruns
            .push(autorun("run:user:K", "K", None, "updater.exe"));
        snapshot.processes.push(process(
            13,
            Some(9999),
            "p",
            Some("C:\\Users\\me\\Downloads\\p.exe"),
            999_000,
        ));
        snapshot.listeners.push(listener(8080, Some(13), true));

        let findings = evaluate(&snapshot, None);
        assert!(!findings.is_empty());
        for finding in findings {
            assert!(!finding.rule_id.is_empty());
            assert!(
                !finding.evidence.is_empty(),
                "{} carries no evidence",
                finding.rule_id
            );
            assert!(!finding.why.is_empty());
            assert!(!finding.benign.is_empty());
            assert!(!finding.remediation.is_empty());
            assert!(!finding.subject_label.is_empty());
        }
    }

    #[test]
    fn findings_are_sorted_by_severity_then_rule() {
        let mut snapshot = snapshot();
        snapshot.autoruns.push(autorun(
            "run:user:I",
            "I",
            Some("C:\\Temp\\i.exe"),
            "C:\\Temp\\i.exe",
        ));
        snapshot
            .processes
            .push(process(12, Some(4242), "x", Some("C:\\Temp\\x.exe"), 999_000));
        let findings = evaluate(&snapshot, None);
        let mut sorted = findings.clone();
        sorted.sort_by(|a, b| {
            b.severity
                .rank()
                .cmp(&a.severity.rank())
                .then_with(|| a.rule_id.cmp(b.rule_id))
                .then_with(|| a.subject.cmp(&b.subject))
        });
        assert_eq!(findings, sorted);
    }
}
