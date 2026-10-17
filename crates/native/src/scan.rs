//! One scan, from collectors to a snapshot.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use vnr_core::{HashAlgorithm, SignatureMatch, Snapshot};

use crate::collect;
use crate::hash::Hasher;

/// Progress the worker reports while a scan runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanProgress {
    /// A collector has started.
    Started(&'static str),
    /// Every collector has finished.
    Completed,
}

/// Run one scan.
///
/// Every collector is attempted; a failure becomes a status in the snapshot rather
/// than aborting the scan. The returned snapshot always has a schema and a host.
#[must_use]
pub fn scan(progress: &dyn Fn(ScanProgress)) -> Snapshot {
    let started = Instant::now();
    let mut snapshot = Snapshot::empty(collect::host::current(), crate::elevation::is_elevated());

    progress(ScanProgress::Started("Loading local signatures"));
    let (signatures, signature_report) = crate::signatures::load();
    snapshot.signatures = signature_report;
    let algorithms = signatures.algorithms();
    let mut hasher = Hasher::new(
        algorithms.contains(&HashAlgorithm::Md5),
        algorithms.contains(&HashAlgorithm::Sha1),
    );

    progress(ScanProgress::Started("Listing processes"));
    let (processes, process_status) = collect::processes::collect().into_parts("processes", "Processes");
    snapshot.processes = processes;

    progress(ScanProgress::Started("Reading startup items"));
    let (autoruns, autorun_status) =
        collect::autoruns::collect(&mut hasher).into_parts("autoruns", "Startup items");
    snapshot.autoruns = autoruns;

    progress(ScanProgress::Started("Reading listening sockets"));
    let process_names: HashMap<u32, String> = snapshot
        .processes
        .iter()
        .map(|process| (process.pid, process.name.clone()))
        .collect();
    let (listeners, listener_status) =
        collect::listeners::collect(&process_names).into_parts("listeners", "Listening sockets");
    snapshot.listeners = listeners;

    progress(ScanProgress::Started("Reading installed packages"));
    let (packages, package_status) =
        collect::packages::collect().into_parts("packages", "Installed packages");
    snapshot.packages = packages;

    snapshot.collectors = vec![process_status, autorun_status, listener_status, package_status];

    let mut matches = Vec::new();
    for autorun in &snapshot.autoruns {
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
    snapshot
}
