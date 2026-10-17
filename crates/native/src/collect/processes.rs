//! Running processes.

use sysinfo::{System, Users};
use vnr_core::ProcessFact;

use super::Outcome;

/// Enumerate every process the current user can see.
#[must_use]
pub fn collect() -> Outcome<ProcessFact> {
    let system = System::new_all();
    let users = Users::new_with_refreshed_list();
    let now = crate::now_unix();
    let mut items = Vec::new();
    for (pid, process) in system.processes() {
        let user = process
            .user_id()
            .and_then(|id| users.get_user_by_id(id))
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
    Outcome::Items(items)
}
