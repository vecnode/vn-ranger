//! The soak recorder: one line a minute about this process, for a run that lasts a day.
//!
//! The budgets in `docs/PLAN.md` §11 are claims — "idle CPU under 0.5% of one core", "a
//! working set under 200 MB", "growth under 10 MB over 24 hours" — and a claim needs a
//! measurement taken on the configuration a person actually leaves open, not on a
//! developer build with a debugger attached. This is that measurement: NDJSON, one sample a
//! minute, appended and flushed, so a run that ends in a crash still has its history.
//!
//! What it records is what a person can check: CPU, working set, private bytes, handles
//! where the platform reports them, and the work the shell did between two samples. Fields
//! a platform cannot fill are `null` rather than zero — a zero is a measurement.

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use sysinfo::{Pid, ProcessesToUpdate, System};

/// What only the shell knows, because it is the thing doing the work.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    /// Process polls that arrived.
    pub polls: u64,
    /// Watcher events accepted.
    pub events: u64,
    /// Journal lines written.
    pub journal_writes: u64,
}

/// One sample, as it appears on its line.
#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    /// Seconds since the Unix epoch, when the sample was taken.
    pub at_unix: u64,
    /// The application version, because a number without its build is not comparable.
    pub version: String,
    /// Percent of one core, as the interval since the previous sample.
    pub cpu_percent: f32,
    /// Resident set size, in bytes.
    pub working_set: u64,
    /// Private bytes, in bytes, where the platform distinguishes them.
    pub private_bytes: Option<u64>,
    /// Open handles or descriptors, where the platform lets this process count its own.
    pub handles: Option<u64>,
    /// Polls since the previous sample.
    pub polls: u64,
    /// Watcher events since the previous sample.
    pub events: u64,
    /// Journal lines written since the previous sample.
    pub journal_writes: u64,
}

impl Sample {
    /// The line this sample is written as: one object, no newline inside.
    #[must_use]
    pub fn line(&self) -> String {
        // A sample that cannot serialise would be a bug in a struct of numbers; the empty
        // object is the outcome that keeps the file parseable rather than a panic.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// The recorder: an append handle, a process handle, and what the last sample counted.
pub struct Soak {
    file: std::fs::File,
    system: System,
    pid: Pid,
    last: Counters,
    started: bool,
}

impl Soak {
    /// Open the sample file, creating it if it is not there.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            crate::paths::ensure_dir(parent)
                .map_err(|error| format!("Could not prepare {}: {error}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("Could not open {} for the soak: {error}", path.display()))?;
        Ok(Self {
            file,
            system: System::new(),
            pid: Pid::from_u32(std::process::id()),
            last: Counters::default(),
            started: false,
        })
    }

    /// Take one sample and append it.
    ///
    /// `counters` is cumulative; the line carries the difference since the previous sample,
    /// because "12,000 polls in total" answers a different question from "12 polls in the
    /// last minute".
    pub fn sample(&mut self, counters: Counters) -> Result<(), String> {
        self.system
            .refresh_processes(ProcessesToUpdate::Some(&[self.pid]), true);
        let process = self
            .system
            .process(self.pid)
            .ok_or_else(|| "the soak could not see its own process".to_owned())?;
        let sample = Sample {
            at_unix: crate::now_unix(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            cpu_percent: if self.started { process.cpu_usage() } else { 0.0 },
            working_set: process.memory(),
            private_bytes: Some(process.virtual_memory()).filter(|bytes| *bytes > 0),
            handles: handles(),
            polls: counters.polls.saturating_sub(self.last.polls),
            events: counters.events.saturating_sub(self.last.events),
            journal_writes: counters.journal_writes.saturating_sub(self.last.journal_writes),
        };
        self.last = counters;
        self.started = true;
        let mut line = sample.line();
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|error| format!("Could not append to the soak file: {error}"))
    }
}

/// How many descriptors this process holds open, where it can count them.
///
/// Linux exposes them as a directory; Windows and macOS need a call the workspace will not
/// make without a safe wrapper, so the field is `null` there and §11 says so rather than
/// printing a zero that looks measured.
#[cfg(target_os = "linux")]
fn handles() -> Option<u64> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    Some(u64::try_from(entries.count()).unwrap_or(u64::MAX))
}

/// See the Linux implementation: no safe way to count handles from `std` here.
#[cfg(not(target_os = "linux"))]
fn handles() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Sample {
        Sample {
            at_unix: 1_700_000_000,
            version: "0.1.6".to_owned(),
            cpu_percent: 0.4,
            working_set: 96 * 1024 * 1024,
            private_bytes: Some(120 * 1024 * 1024),
            handles: None,
            polls: 30,
            events: 4,
            journal_writes: 1,
        }
    }

    #[test]
    fn a_sample_is_one_line_of_json_with_no_newline_inside() {
        let line = sample().line();
        assert!(!line.contains('\n'), "one sample is one line");
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["at_unix"], 1_700_000_000_u64);
        assert_eq!(value["cpu_percent"], 0.4);
        assert_eq!(value["working_set"], 96 * 1024 * 1024_u64);
        assert!(
            value["handles"].is_null(),
            "a platform that cannot count handles says null, not zero"
        );
    }

    #[test]
    fn two_samples_append_and_each_line_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("soak.ndjson");
        let mut soak = Soak::open(&path).unwrap();
        soak.sample(Counters::default()).unwrap();
        soak.sample(Counters {
            polls: 2,
            events: 1,
            journal_writes: 3,
        })
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["polls"], 2, "the line carries the interval, not the total");
        assert_eq!(second["journal_writes"], 3);
    }

    #[test]
    fn the_first_sample_has_no_cpu_to_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("soak.ndjson");
        let mut soak = Soak::open(&path).unwrap();
        soak.sample(Counters::default()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(
            first["cpu_percent"], 0.0,
            "there is no previous refresh to measure an interval against"
        );
        assert!(
            first["working_set"].as_u64().unwrap_or(0) > 0,
            "but the memory is real from the first sample"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_counts_its_own_descriptors() {
        assert!(handles().is_some(), "this process has descriptors open");
    }
}
