//! Scheduled tasks: the second thing that runs without a person clicking it.
//!
//! A task is one XML file under `%SystemRoot%\System32\Tasks`, in a folder per namespace. The
//! folder needs administrative rights to enumerate, which is why a standard scan reports this
//! collector as unavailable rather than as an empty list: "no tasks" and "could not look" are
//! different answers, and only one of them is true on a machine with Windows on it.
//!
//! The XML itself is read by [`parse`], which is pure and fixture-tested, so the parser runs
//! on every platform and a task captured on one machine is checked on all of them.

pub mod parse;

use std::path::{Path, PathBuf};

use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};

use super::Outcome;
use super::winutil;
use crate::hash::Hasher;

/// The collector's id and label, in one place.
pub const ID: &str = "windows.tasks";
/// What the interface calls it.
pub const LABEL: &str = "Scheduled tasks";

/// Read every task this process can see.
#[must_use]
pub fn collect(hasher: &mut Hasher) -> Outcome<AutorunFact> {
    let Some(folder) = task_folder() else {
        return Outcome::Unavailable {
            reason: "Windows' task folder could not be found, so no scheduled task was read.".to_owned(),
        };
    };
    if let Err(reason) = probe(&folder) {
        return Outcome::Unavailable { reason };
    }
    let mut items = Vec::new();
    let mut unreadable = 0_usize;
    walk(&folder, &mut items, &mut unreadable);
    let mut reasons = Vec::new();
    if unreadable > 0 {
        reasons.push(format!(
            "{unreadable} task file(s) could not be read, so the list is incomplete."
        ));
    }
    reasons.push(
        "A task's action is read; its conditions, its history and a task stored in another file \
         are not."
            .to_owned(),
    );
    hash_items(&mut items, hasher);
    if reasons.is_empty() {
        Outcome::Items(items)
    } else {
        Outcome::Partial {
            items,
            reason: reasons.join(" "),
        }
    }
}

/// The folder tasks live in, on the drive Windows is installed on.
fn task_folder() -> Option<PathBuf> {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from)?;
    Some(root.join("System32").join("Tasks"))
}

/// Whether the folder can be listed at all.
///
/// A standard account is refused here, and that refusal is the answer the interface shows.
/// Reading it as "no tasks" would be a claim about a machine nobody looked at.
fn probe(folder: &Path) -> Result<(), String> {
    match std::fs::read_dir(folder) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Err(format!(
            "{} needs administrative rights to list, so scheduled tasks were not read. Run an \
             administrator scan to see them.",
            folder.display()
        )),
        Err(error) => Err(format!("{} could not be listed: {error}", folder.display())),
    }
}

fn walk(folder: &Path, items: &mut Vec<AutorunFact>, unreadable: &mut usize) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        *unreadable = unreadable.saturating_add(1);
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            walk(&path, items, unreadable);
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            *unreadable = unreadable.saturating_add(1);
            continue;
        };
        match parse::parse(&text) {
            Ok(task) => items.push(fact(&task, &path)),
            Err(_) => *unreadable = unreadable.saturating_add(1),
        }
    }
}

fn fact(task: &parse::Task, _path: &Path) -> AutorunFact {
    let command = task.command_line();
    let exe = winutil::executable_from_command(&winutil::expand_env(&command))
        .map(|path| path.to_string_lossy().into_owned());
    // A task that runs as a well-known service account is machine-wide; one that names a
    // person's account is that person's. Anything else is reported as the machine's, and
    // `user` in the fact says which.
    let scope = match task.user.as_deref() {
        Some(user) if is_well_known_principal(user) => AutorunScope::System,
        Some(_) => AutorunScope::User,
        None => AutorunScope::System,
    };
    AutorunFact {
        id: format!("task:{}", task.uri.trim_start_matches('\\')),
        name: task
            .uri
            .rsplit('\\')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or(&task.uri)
            .to_owned(),
        command: winutil::expand_env(&command),
        location: format!(
            "Task Scheduler{}{}",
            task.uri,
            if task.hidden { " (hidden)" } else { "" }
        ),
        kind: AutorunKind::ScheduledTask,
        scope,
        enabled: task.enabled,
        exe,
        sha256: None,
        hidden: false,
        signature: SignatureStatus::NotChecked,
    }
}

/// Whether an account is one of Windows' own, by name or by SID.
fn is_well_known_principal(user: &str) -> bool {
    let user = user.trim();
    matches!(
        user.to_ascii_lowercase().as_str(),
        "s-1-5-18"
            | "s-1-5-19"
            | "s-1-5-20"
            | "system"
            | r"nt authority\system"
            | r"nt authority\localservice"
            | r"nt authority\networkservice"
            | "localsystem"
            | "localservice"
            | "networkservice"
    ) || user.eq_ignore_ascii_case("SYSTEM")
        || user.ends_with("\\SYSTEM")
}

fn hash_items(items: &mut [AutorunFact], hasher: &mut Hasher) {
    for item in items {
        let Some(exe) = item.exe.clone() else {
            continue;
        };
        if let Some(digests) = hasher.digest(Path::new(&exe)) {
            item.sha256 = Some(digests.sha256.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_fact_names_the_task_its_action_and_whether_it_is_hidden() {
        let task = parse::parse(
            r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Acme\Updater</URI></RegistrationInfo>
  <Settings><Hidden>true</Hidden><Enabled>true</Enabled></Settings>
  <Actions><Exec><Command>C:\Acme\updater.exe</Command><Arguments>--quiet</Arguments></Exec></Actions>
</Task>"#,
        )
        .unwrap();
        let fact = fact(&task, Path::new(r"C:\Windows\System32\Tasks\Acme\Updater"));
        assert_eq!(fact.id, r"task:Acme\Updater");
        assert_eq!(fact.name, "Updater");
        assert_eq!(fact.kind, AutorunKind::ScheduledTask);
        assert!(fact.location.contains("(hidden)"), "{}", fact.location);
        assert_eq!(fact.command, r"C:\Acme\updater.exe --quiet");
        assert_eq!(fact.exe.as_deref(), Some(r"C:\Acme\updater.exe"));
    }

    #[test]
    fn a_task_running_as_system_is_machine_wide_and_one_running_as_a_person_is_that_persons() {
        for (user, scope) in [
            ("S-1-5-18", AutorunScope::System),
            (r"NT AUTHORITY\SYSTEM", AutorunScope::System),
            (r"DESKTOP\user", AutorunScope::User),
        ] {
            let task = parse::parse(&format!(
                r#"<Task><RegistrationInfo><URI>\Acme\T</URI></RegistrationInfo>
<Principals><Principal id="Author"><UserId>{user}</UserId></Principal></Principals>
<Actions><Exec><Command>a.exe</Command></Exec></Actions></Task>"#
            ))
            .unwrap();
            assert_eq!(fact(&task, Path::new("x")).scope, scope, "{user}");
        }
    }

    #[test]
    fn a_folder_that_cannot_be_listed_says_that_rather_than_returning_no_tasks() {
        let missing = Path::new(r"C:\vn-ranger\no such folder");
        let reason = probe(missing).unwrap_err();
        assert!(reason.contains("could not be listed"), "{reason}");
    }
}
