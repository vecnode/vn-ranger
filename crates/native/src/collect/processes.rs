//! Running processes.

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};
use vnr_core::ProcessFact;

use super::Outcome;

/// The process table, kept warm between polls.
///
/// A scan builds one of these, asks once and drops it. The watcher keeps one and
/// refreshes it every two seconds, so the operating system is asked for the change
/// rather than for the whole table read from scratch.
pub struct Poller {
    system: System,
    users: Users,
}

impl Poller {
    /// An empty poller; the first poll fills it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            system: System::new(),
            users: Users::new_with_refreshed_list(),
        }
    }

    /// Refresh the process table and return every process this account can see.
    ///
    /// An empty table is reported as unavailable: on a running machine it means the
    /// platform hid the answer, not that nothing is running.
    pub fn poll(&mut self) -> Outcome<ProcessFact> {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_user(UpdateKind::OnlyIfNotSet),
        );
        if self.system.processes().is_empty() {
            return Outcome::Unavailable {
                reason: "The process table came back empty; this account may not be allowed to read it."
                    .to_owned(),
            };
        }
        Outcome::Items(self.facts())
    }

    fn facts(&self) -> Vec<ProcessFact> {
        let now = crate::now_unix();
        let mut items = Vec::with_capacity(self.system.processes().len());
        for (pid, process) in self.system.processes() {
            let user = process
                .user_id()
                .and_then(|id| self.users.get_user_by_id(id))
                .map(|user| user.name().to_owned());
            let command = {
                let parts: Vec<String> = process
                    .cmd()
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join(" "))
                }
            };
            items.push(ProcessFact {
                pid: pid.as_u32(),
                parent: process.parent().map(|parent| parent.as_u32()),
                name: process.name().to_string_lossy().into_owned(),
                exe: process.exe().map(|path| path.to_string_lossy().into_owned()),
                command,
                user,
                started_at_unix: now.checked_sub(process.run_time()),
            });
        }
        items
    }
}

impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}

/// Enumerate every process the current user can see.
#[must_use]
pub fn collect() -> Outcome<ProcessFact> {
    Poller::new().poll()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_poll_keeps_the_same_identity_for_a_running_process() {
        let mut poller = Poller::new();
        let first = match poller.poll() {
            Outcome::Items(items) => items,
            _ => Vec::new(),
        };
        std::thread::sleep(std::time::Duration::from_millis(120));
        let second = match poller.poll() {
            Outcome::Items(items) => items,
            _ => Vec::new(),
        };
        assert!(!first.is_empty(), "a running machine has processes");
        let now = crate::now_unix();
        assert!(
            first.iter().any(|process| process
                .started_at_unix
                .is_some_and(|started| started > 0 && started <= now)),
            "at least one process has a start time the diff can use as identity"
        );
        let second_by_pid: std::collections::HashMap<u32, &ProcessFact> =
            second.iter().map(|process| (process.pid, process)).collect();
        let mut compared = 0;
        for before in &first {
            if let Some(after) = second_by_pid.get(&before.pid) {
                assert_eq!(
                    before.started_at_unix, after.started_at_unix,
                    "pid {} changed its start time between polls",
                    before.pid
                );
                compared += 1;
            }
        }
        assert!(compared > 0, "the test process is still running");
    }
}
