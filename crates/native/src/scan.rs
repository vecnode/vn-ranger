//! One scan, from collectors to a snapshot.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use vnr_core::{HashAlgorithm, ScanProfile, SignatureMatch, Snapshot};

use crate::collect;
use crate::hash::Hasher;

/// The most startup programs a deep scan reads.
pub const DEEP_MAX_FILES: usize = 400;

/// The most bytes a deep scan reads in total.
pub const DEEP_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Progress the worker reports while a scan runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanProgress {
    /// A collector has started.
    Started(&'static str),
    /// Every collector has finished.
    Completed,
}

/// Run one scan with the standard profile.
///
/// Every collector is attempted; a failure becomes a status in the snapshot rather
/// than aborting the scan. A snapshot always has a schema and a host. None means the
/// person cancelled between collectors; nothing was written.
#[must_use]
pub fn scan(progress: &dyn Fn(ScanProgress), cancelled: &dyn Fn() -> bool) -> Option<Snapshot> {
    scan_with(ScanProfile::Standard, progress, cancelled)
}

/// Run one scan at the size a person chose.
///
/// The profile decides which collectors run, not how honestly each of them reports: a quick
/// scan says in its own status that it did not look at packages, and a deep scan adds the
/// bytes of the programs that start on their own.
#[must_use]
pub fn scan_with(
    profile: ScanProfile,
    progress: &dyn Fn(ScanProgress),
    cancelled: &dyn Fn() -> bool,
) -> Option<Snapshot> {
    let started = Instant::now();
    let mut snapshot = Snapshot::empty(collect::host::current(), crate::elevation::is_elevated());
    snapshot.profile = profile;

    progress(ScanProgress::Started("Loading local signatures"));
    let (signatures, signature_report) = crate::signatures::load();
    snapshot.signatures = signature_report;
    let algorithms = signatures.algorithms();
    if cancelled() {
        return None;
    }
    let mut hasher = Hasher::new(
        algorithms.contains(&HashAlgorithm::Md5),
        algorithms.contains(&HashAlgorithm::Sha1),
    );

    progress(ScanProgress::Started("Listing processes"));
    let (processes, process_status) = collect::processes::collect().into_parts("processes", "Processes");
    snapshot.processes = processes;
    if cancelled() {
        return None;
    }

    progress(ScanProgress::Started("Reading startup items"));
    let (autoruns, autorun_status) =
        collect::autoruns::collect(&mut hasher).into_parts("autoruns", "Startup items");
    snapshot.autoruns = autoruns;
    if cancelled() {
        return None;
    }

    progress(ScanProgress::Started("Reading listening sockets"));
    let process_names: HashMap<u32, String> = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process.name.clone()))
        .collect();
    let (listeners, listener_status) =
        collect::listeners::collect(&process_names).into_parts("listeners", "Listening sockets");
    snapshot.listeners = listeners;
    if cancelled() {
        return None;
    }

    progress(ScanProgress::Started("Reading connections"));
    let (flows, flow_status) = collect::flows::collect(&process_names).into_parts("flows", "Connections");
    snapshot.flows = flows;
    if cancelled() {
        return None;
    }

    let package_status = if profile.reads_inventories() {
        progress(ScanProgress::Started("Reading installed packages"));
        let (packages, status) = collect::packages::collect().into_parts("packages", "Installed packages");
        snapshot.packages = packages;
        if cancelled() {
            return None;
        }
        status
    } else {
        vnr_core::CollectorStatus::unavailable(
            "packages",
            "Installed packages",
            "A quick scan does not read installed packages. Run a standard scan for them.",
        )
    };

    // Scheduled tasks are their own collector because their access is their own question: a
    // standard account cannot list the task folder, and that refusal belongs on the status
    // rather than being folded into the startup items' reasons.
    #[cfg(windows)]
    let task_status = {
        let (tasks, status) =
            collect::tasks::collect(&mut hasher).into_parts(collect::tasks::ID, collect::tasks::LABEL);
        snapshot.autoruns.extend(tasks);
        status
    };

    snapshot.autoruns.sort_by(|a, b| {
        a.scope
            .label()
            .cmp(b.scope.label())
            .then_with(|| a.kind.label().cmp(b.kind.label()))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let agent_status = if profile.reads_inventories() {
        let (agents, status) =
            collect::agentstack::collect().into_parts(collect::agentstack::ID, collect::agentstack::LABEL);
        snapshot.agents = agents;
        status
    } else {
        vnr_core::CollectorStatus::unavailable(
            collect::agentstack::ID,
            collect::agentstack::LABEL,
            "A quick scan does not read agent and editor configurations. Run a standard scan for \
             them.",
        )
    };

    snapshot.collectors = vec![process_status, autorun_status];
    snapshot.collectors.push(agent_status);
    #[cfg(windows)]
    snapshot.collectors.push(task_status);
    snapshot
        .collectors
        .extend([listener_status, flow_status, package_status]);

    // A deep scan reads the bytes of the programs that start on their own, and nothing else:
    // "deep" must not quietly become "the whole disk", because a person who asked for a
    // deep scan still expects the window back.
    if profile.reads_bodies() {
        progress(ScanProgress::Started("Reading the files that start on their own"));
        let targets: Vec<std::path::PathBuf> = snapshot
            .autoruns
            .iter()
            .filter_map(|autorun| autorun.exe.as_deref())
            .map(std::path::PathBuf::from)
            .collect();
        let (library, notes) = crate::content::load_library();
        let report = crate::content::scan_files(
            &targets,
            &library,
            &signatures,
            &crate::content::Limits {
                max_files: DEEP_MAX_FILES,
                max_total_bytes: DEEP_MAX_BYTES,
                ..crate::content::Limits::default()
            },
            cancelled,
        );
        if cancelled() {
            return None;
        }
        let matched = report
            .files
            .iter()
            .filter(|file| !file.matches.is_empty())
            .count();
        snapshot.files.extend(report.files);
        let mut status = vnr_core::CollectorStatus::ok("content", "File contents", matched);
        status.reason = Some(if notes.is_empty() {
            format!(
                "{} file(s) that start on their own were read against {} body signature(s).",
                report.seen, report.signatures
            )
        } else {
            format!(
                "{} file(s) that start on their own were read against {} body signature(s). {}",
                report.seen,
                report.signatures,
                notes.join(" ")
            )
        });
        snapshot.collectors.push(status);
    }

    let mut matches = Vec::new();
    for autorun in &snapshot.autoruns {
        if cancelled() {
            return None;
        }
        let Some(exe) = autorun.exe.as_deref() else {
            continue;
        };
        let Some(digests) = hasher.cached(Path::new(exe)) else {
            continue;
        };
        for algorithm in &algorithms {
            let Some(hash) = digests.get(*algorithm) else {
                continue;
            };
            let Some(found) = signatures.lookup(hash) else {
                continue;
            };
            for signature in found {
                if signature.size.is_none_or(|size| size == digests.size) {
                    matches.push(SignatureMatch {
                        subject: autorun.id.clone(),
                        path: exe.to_owned(),
                        algorithm: algorithm.label().to_owned(),
                        hash: hash.to_owned(),
                        name: signature.name.clone(),
                    });
                }
            }
        }
    }
    snapshot.signatures.matches = matches;
    snapshot.taken_at_unix = crate::now_unix();
    snapshot.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    snapshot.sort();
    progress(ScanProgress::Completed);
    Some(snapshot)
}
