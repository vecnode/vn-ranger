//! Comparing two observations of the same machine.
//!
//! A diff is a statement about a difference between two collections, not a judgement
//! about either. Identity is the hard part: a process id is reused by the operating
//! system, so a pid alone is not an identity. A process is keyed by its pid **and** the
//! time it started; a reused pid with a different start time is a new process, not a
//! changed one.

use std::collections::HashMap;

use crate::model::{AutorunFact, ListenerFact, PackageFact, ProcessFact, Snapshot};

/// How a subject changed between two observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeKind {
    /// It is in the new observation and was not in the old one.
    New,
    /// It was in the old observation and is not in the new one.
    Gone,
    /// It is in both, and something ranger records about it differs.
    Changed,
}

impl ChangeKind {
    /// A short label for the interface.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Gone => "Gone",
            Self::Changed => "Changed",
        }
    }
}

/// One difference between two observations.
///
/// `subject` is what the person recognises, `detail` is the evidence for the change,
/// and `source` names the collector that saw it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    /// What kind of difference it is.
    pub kind: ChangeKind,
    /// The thing that changed, in words a person can read.
    pub subject: String,
    /// The evidence for the change.
    pub detail: String,
    /// The collector that observed it.
    pub source: String,
    /// A file the change points at, when there is one: a process or startup binary.
    pub path: Option<String>,
}

impl Change {
    fn new(kind: ChangeKind, subject: impl Into<String>, detail: impl Into<String>, source: &str) -> Self {
        Self {
            kind,
            subject: subject.into(),
            detail: detail.into(),
            source: source.to_owned(),
            path: None,
        }
    }

    fn with_path(mut self, path: Option<String>) -> Self {
        if path.is_some() {
            self.path = path;
        }
        self
    }
}

/// Compare two process lists.
///
/// A process is identified by its pid and start time. When the platform does not expose
/// a start time, the pid alone is the key, and a reused pid cannot be told apart from
/// the same process still running.
#[must_use]
pub fn diff_processes(before: &[ProcessFact], after: &[ProcessFact]) -> Vec<Change> {
    let before_by_key: HashMap<(u32, Option<u64>), &ProcessFact> = before
        .iter()
        .map(|process| (process_key(process), process))
        .collect();
    let after_by_key: HashMap<(u32, Option<u64>), &ProcessFact> = after
        .iter()
        .map(|process| (process_key(process), process))
        .collect();

    let mut changes = Vec::new();
    for (key, process) in &after_by_key {
        match before_by_key.get(key) {
            None => changes.push(
                Change::new(
                    ChangeKind::New,
                    process_subject(process),
                    process_detail(process),
                    "processes",
                )
                .with_path(process.exe.clone()),
            ),
            Some(previous) => {
                if let Some(detail) = process_difference(previous, process) {
                    changes.push(
                        Change::new(ChangeKind::Changed, process_subject(process), detail, "processes")
                            .with_path(process.exe.clone()),
                    );
                }
            }
        }
    }
    for (key, process) in &before_by_key {
        if !after_by_key.contains_key(key) {
            changes.push(
                Change::new(
                    ChangeKind::Gone,
                    process_subject(process),
                    process_detail(process),
                    "processes",
                )
                .with_path(process.exe.clone()),
            );
        }
    }
    changes.sort();
    changes
}

/// Compare every list in two snapshots.
///
/// The result is sorted by kind and then by subject, so two runs over the same pair of
/// snapshots read the same way twice.
#[must_use]
pub fn diff_snapshots(before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let mut changes = diff_processes(&before.processes, &after.processes);
    changes.extend(diff_autoruns(&before.autoruns, &after.autoruns));
    changes.extend(diff_listeners(&before.listeners, &after.listeners));
    changes.extend(diff_packages(&before.packages, &after.packages));
    changes.sort();
    changes
}

fn process_key(process: &ProcessFact) -> (u32, Option<u64>) {
    (process.pid, process.started_at_unix)
}

fn process_subject(process: &ProcessFact) -> String {
    if process.name.is_empty() {
        format!("Process {}", process.pid)
    } else {
        format!("{} (pid {})", process.name, process.pid)
    }
}

fn process_detail(process: &ProcessFact) -> String {
    process
        .exe
        .as_deref()
        .or(process.command.as_deref())
        .unwrap_or("path not visible")
        .to_owned()
}

fn process_difference(before: &ProcessFact, after: &ProcessFact) -> Option<String> {
    if let (Some(old), Some(new)) = (&before.exe, &after.exe)
        && old != new
    {
        return Some(format!("executable changed from {old} to {new}"));
    }
    if before.name != after.name {
        return Some(format!("name changed from {} to {}", before.name, after.name));
    }
    None
}

fn diff_autoruns(before: &[AutorunFact], after: &[AutorunFact]) -> Vec<Change> {
    let before_by_id: HashMap<&str, &AutorunFact> =
        before.iter().map(|entry| (entry.id.as_str(), entry)).collect();
    let after_by_id: HashMap<&str, &AutorunFact> =
        after.iter().map(|entry| (entry.id.as_str(), entry)).collect();

    let mut changes = Vec::new();
    for (id, entry) in &after_by_id {
        match before_by_id.get(id) {
            None => changes.push(
                Change::new(
                    ChangeKind::New,
                    autorun_subject(entry),
                    autorun_detail(entry),
                    "autoruns",
                )
                .with_path(entry.exe.clone()),
            ),
            Some(previous) => {
                if let Some(detail) = autorun_difference(previous, entry) {
                    changes.push(
                        Change::new(ChangeKind::Changed, autorun_subject(entry), detail, "autoruns")
                            .with_path(entry.exe.clone()),
                    );
                }
            }
        }
    }
    for (id, entry) in &before_by_id {
        if !after_by_id.contains_key(id) {
            changes.push(
                Change::new(
                    ChangeKind::Gone,
                    autorun_subject(entry),
                    autorun_detail(entry),
                    "autoruns",
                )
                .with_path(entry.exe.clone()),
            );
        }
    }
    changes
}

fn autorun_subject(entry: &AutorunFact) -> String {
    format!("{} ({})", entry.name, entry.kind.label())
}

fn autorun_detail(entry: &AutorunFact) -> String {
    format!("{} · {}", entry.command, entry.location)
}

fn autorun_difference(before: &AutorunFact, after: &AutorunFact) -> Option<String> {
    if before.sha256 != after.sha256 {
        return Some(match (&before.sha256, &after.sha256) {
            (Some(old), Some(new)) => format!("binary hash changed from {old} to {new}"),
            (None, Some(new)) => format!("binary hash is now {new}"),
            (Some(old), None) => format!("binary hash {old} is no longer available"),
            (None, None) => "binary hash is unchanged".to_owned(),
        });
    }
    if before.exe != after.exe {
        return Some(match (&before.exe, &after.exe) {
            (Some(old), Some(new)) => format!("executable changed from {old} to {new}"),
            (None, Some(new)) => format!("executable is now {new}"),
            (Some(old), None) => format!("executable {old} is no longer visible"),
            (None, None) => "executable is unchanged".to_owned(),
        });
    }
    if before.enabled != after.enabled {
        return Some(if after.enabled {
            "enabled".to_owned()
        } else {
            "disabled".to_owned()
        });
    }
    None
}

fn diff_listeners(before: &[ListenerFact], after: &[ListenerFact]) -> Vec<Change> {
    let before_by_key: HashMap<String, &ListenerFact> = before
        .iter()
        .map(|listener| (listener_key(listener), listener))
        .collect();
    let after_by_key: HashMap<String, &ListenerFact> = after
        .iter()
        .map(|listener| (listener_key(listener), listener))
        .collect();

    let mut changes = Vec::new();
    for (key, listener) in &after_by_key {
        match before_by_key.get(key) {
            None => changes.push(Change::new(
                ChangeKind::New,
                listener_subject(listener),
                listener_detail(listener),
                "listeners",
            )),
            Some(previous) => {
                if previous.pid != listener.pid || previous.process != listener.process {
                    changes.push(Change::new(
                        ChangeKind::Changed,
                        listener_subject(listener),
                        format!("owner is now {}", listener_owner(listener)),
                        "listeners",
                    ));
                }
            }
        }
    }
    for (key, listener) in &before_by_key {
        if !after_by_key.contains_key(key) {
            changes.push(Change::new(
                ChangeKind::Gone,
                listener_subject(listener),
                listener_detail(listener),
                "listeners",
            ));
        }
    }
    changes
}

fn listener_key(listener: &ListenerFact) -> String {
    format!(
        "{}:{}:{}",
        listener.protocol.label(),
        listener.address,
        listener.port
    )
}

fn listener_subject(listener: &ListenerFact) -> String {
    format!(
        "{} {}:{}",
        listener.protocol.label(),
        listener.address,
        listener.port
    )
}

fn listener_detail(listener: &ListenerFact) -> String {
    format!("{} {:?} · {:?}", listener.state, listener.process, listener.pid)
}

fn listener_owner(listener: &ListenerFact) -> String {
    match (&listener.process, listener.pid) {
        (Some(name), Some(pid)) => format!("{name} (pid {pid})"),
        (Some(name), None) => name.clone(),
        (None, Some(pid)) => format!("pid {pid}"),
        (None, None) => "not visible".to_owned(),
    }
}

fn diff_packages(before: &[PackageFact], after: &[PackageFact]) -> Vec<Change> {
    let before_by_key: HashMap<String, &PackageFact> = before
        .iter()
        .map(|package| (package_key(package), package))
        .collect();
    let after_by_key: HashMap<String, &PackageFact> = after
        .iter()
        .map(|package| (package_key(package), package))
        .collect();

    let mut changes = Vec::new();
    for (key, package) in &after_by_key {
        match before_by_key.get(key) {
            None => changes.push(Change::new(
                ChangeKind::New,
                package_subject(package),
                package_detail(package),
                "packages",
            )),
            Some(previous) => {
                if previous.version != package.version {
                    changes.push(Change::new(
                        ChangeKind::Changed,
                        package_subject(package),
                        format!(
                            "version changed from {} to {}",
                            previous.version.as_deref().unwrap_or("unknown"),
                            package.version.as_deref().unwrap_or("unknown")
                        ),
                        "packages",
                    ));
                }
            }
        }
    }
    for (key, package) in &before_by_key {
        if !after_by_key.contains_key(key) {
            changes.push(Change::new(
                ChangeKind::Gone,
                package_subject(package),
                package_detail(package),
                "packages",
            ));
        }
    }
    changes
}

fn package_key(package: &PackageFact) -> String {
    format!("{}:{}", package.source, package.name)
}

fn package_subject(package: &PackageFact) -> String {
    format!("{} ({})", package.name, package.source)
}

fn package_detail(package: &PackageFact) -> String {
    package
        .version
        .clone()
        .unwrap_or_else(|| "version unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AutorunKind, AutorunScope, Protocol};

    fn process(pid: u32, name: &str, started: u64, exe: &str) -> ProcessFact {
        ProcessFact {
            pid,
            parent: None,
            name: name.to_owned(),
            exe: Some(exe.to_owned()),
            command: None,
            user: None,
            started_at_unix: Some(started),
        }
    }

    fn autorun(id: &str, name: &str) -> AutorunFact {
        AutorunFact {
            id: id.to_owned(),
            name: name.to_owned(),
            command: format!("{name}.exe"),
            location: "HKCU\\Run".to_owned(),
            kind: AutorunKind::RunKey,
            scope: AutorunScope::User,
            enabled: true,
            hidden: false,
            exe: Some(format!("C:\\{name}.exe")),
            sha256: None,
            signature: crate::model::SignatureStatus::NotChecked,
        }
    }

    fn listener(port: u16, pid: u32, process: &str) -> ListenerFact {
        ListenerFact {
            protocol: Protocol::Tcp,
            address: "127.0.0.1".to_owned(),
            port,
            pid: Some(pid),
            process: Some(process.to_owned()),
            state: "LISTEN".to_owned(),
            public: false,
        }
    }

    fn package(name: &str, version: &str) -> PackageFact {
        PackageFact {
            name: name.to_owned(),
            version: Some(version.to_owned()),
            publisher: None,
            source: "registry".to_owned(),
        }
    }

    #[test]
    fn a_new_and_a_gone_process_are_both_named() {
        let before = vec![process(10, "old", 100, "C:\\old.exe")];
        let after = vec![process(11, "new", 200, "C:\\new.exe")];
        let changes = diff_processes(&before, &after);
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .any(|change| change.kind == ChangeKind::New && change.subject.contains("new"))
        );
        assert!(
            changes
                .iter()
                .any(|change| change.kind == ChangeKind::Gone && change.subject.contains("old"))
        );
    }

    #[test]
    fn a_reused_pid_with_a_new_start_time_is_new_not_changed() {
        let before = vec![process(4242, "helper", 100, "C:\\helper.exe")];
        let after = vec![process(4242, "helper", 900, "C:\\helper.exe")];
        let changes = diff_processes(&before, &after);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|change| change.kind == ChangeKind::New));
        assert!(changes.iter().any(|change| change.kind == ChangeKind::Gone));
        assert!(!changes.iter().any(|change| change.kind == ChangeKind::Changed));
    }

    #[test]
    fn the_same_pid_and_start_time_with_a_new_executable_is_changed() {
        let before = vec![process(7, "agent", 100, "C:\\one.exe")];
        let after = vec![process(7, "agent", 100, "C:\\two.exe")];
        let changes = diff_processes(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Changed);
        assert!(changes[0].detail.contains("one.exe"));
        assert!(changes[0].detail.contains("two.exe"));
    }

    #[test]
    fn an_unchanged_process_produces_nothing() {
        let list = vec![process(1, "idle", 5, "C:\\idle.exe")];
        assert!(diff_processes(&list, &list).is_empty());
    }

    #[test]
    fn a_new_process_carries_the_executable_the_worker_hashes() {
        let after = vec![process(9, "agent", 50, "C:\\agent.exe")];
        let changes = diff_processes(&[], &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path.as_deref(), Some("C:\\agent.exe"));
    }

    #[test]
    fn a_startup_item_is_tracked_by_its_stable_id() {
        let before = vec![autorun("run:hkcu:Acme", "Acme")];
        let mut after = before.clone();
        after.push(autorun("run:hkcu:Other", "Other"));
        let changes = diff_autoruns(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::New);
        assert_eq!(changes[0].source, "autoruns");
    }

    #[test]
    fn a_startup_item_that_changes_its_hash_is_changed() {
        let before = vec![autorun("run:hkcu:Acme", "Acme")];
        let mut after = before.clone();
        after[0].sha256 = Some("abc".to_owned());
        let changes = diff_autoruns(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Changed);
        assert!(changes[0].detail.contains("abc"));
    }

    #[test]
    fn a_listener_that_changes_owner_is_changed_not_replaced() {
        let before = vec![listener(8080, 10, "first")];
        let after = vec![listener(8080, 20, "second")];
        let changes = diff_listeners(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Changed);
        assert!(changes[0].detail.contains("second"));
    }

    #[test]
    fn a_package_version_bump_is_changed() {
        let before = vec![package("Acme", "1.0")];
        let after = vec![package("Acme", "1.1")];
        let changes = diff_packages(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Changed);
        assert!(changes[0].detail.contains("1.0"));
        assert!(changes[0].detail.contains("1.1"));
    }

    #[test]
    fn a_snapshot_diff_covers_every_collector_and_sorts() {
        let mut before = Snapshot::empty(crate::model::Host::default(), false);
        before.processes = vec![process(1, "one", 1, "C:\\one.exe")];
        let mut after = before.clone();
        after.processes = vec![process(2, "two", 2, "C:\\two.exe")];
        after.autoruns = vec![autorun("run:hkcu:New", "New")];
        after.listeners = vec![listener(443, 5, "svc")];
        after.packages = vec![package("Acme", "2.0")];
        let changes = diff_snapshots(&before, &after);
        let sources: Vec<&str> = changes.iter().map(|change| change.source.as_str()).collect();
        assert!(sources.contains(&"processes"));
        assert!(sources.contains(&"autoruns"));
        assert!(sources.contains(&"listeners"));
        assert!(sources.contains(&"packages"));
        let mut sorted = changes.clone();
        sorted.sort();
        assert_eq!(changes, sorted);
    }
}
