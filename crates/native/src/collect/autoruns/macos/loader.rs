//! The macOS surfaces that run something without a click, and the ones still owed.
//!
//! Four sources are read here and none of them is a plist: `periodic` scripts, the system
//! crontab, `ScriptingAdditions` bundles and Folder Action scripts. Each parser takes the
//! file or the directory entry and returns what it says, so it can be tested on a machine
//! that is not a Mac.
//!
//! **The parsers are tested against documents written to the documented shapes, not against
//! captures.** No Mac was available when they were written, and inventing a capture would be
//! worse than saying so: the module's tests assert the shape each parser claims to handle,
//! the collector's status names the gap, and `docs/PLAN.md` §9 carries the row as owed until
//! someone with a Mac runs `tests/fixtures` against it. That is the difference between "this
//! code has not been checked on a real machine" and "this code is known to work", and the
//! release notes say the first.

use std::path::Path;

use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};

use crate::collect::unixutil;

/// The `periodic` directories, whose scripts run daily, weekly or monthly.
pub(crate) const PERIODIC: [&str; 3] = [
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
];

/// The directories a `ScriptingAdditions` bundle can live in.
pub(crate) const SCRIPTING_ADDITIONS: [&str; 2] = [
    "/Library/ScriptingAdditions",
    "/System/Library/ScriptingAdditions",
];

/// Where Folder Action scripts live, machine-wide and per user.
pub(crate) const FOLDER_ACTIONS: [&str; 2] = [
    "/Library/Scripts/Folder Action Scripts",
    "/System/Library/Scripts/Folder Action Scripts",
];

/// One script in a `periodic` directory: it runs on that schedule, from the system's own job.
#[must_use]
pub(crate) fn periodic(directory: &str, name: &str) -> Option<AutorunFact> {
    let schedule = directory.rsplit('/').next()?;
    if name.starts_with('.') || name.trim().is_empty() {
        return None;
    }
    Some(fact(
        format!("periodic:{schedule}:{name}"),
        format!("{schedule} periodic script {name}"),
        format!("{directory}/{name}"),
        directory,
        AutorunKind::Cron,
    ))
}

/// One line of the system crontab, which on macOS has the same six fields as on Linux.
#[must_use]
pub(crate) fn crontab(path: &str, text: &str) -> Vec<AutorunFact> {
    let mut facts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains(' ') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // `MAILTO=...` and friends are `key=value` with no schedule.
        if fields.len() < 6 || fields[0].contains('=') {
            continue;
        }
        let command = fields[5..].join(" ");
        facts.push(fact(
            format!("cron:{path}:{}", index.saturating_add(1)),
            format!("crontab line {} of {}", index.saturating_add(1), base_name(path)),
            command,
            path,
            AutorunKind::Cron,
        ));
    }
    facts
}

/// One `ScriptingAdditions` bundle: a `.osax` is a dictionary of scripting terms that any
/// process can load.
#[must_use]
pub(crate) fn scripting_addition(directory: &str, name: &str) -> Option<AutorunFact> {
    if !name.to_ascii_lowercase().ends_with(".osax") {
        return None;
    }
    Some(fact(
        format!("osax:{directory}:{name}"),
        format!("Scripting addition {name}"),
        format!("{directory}/{name}"),
        directory,
        AutorunKind::Other,
    ))
}

/// One Folder Action script, which Finder runs when a watched folder changes.
#[must_use]
pub(crate) fn folder_action(directory: &str, name: &str) -> Option<AutorunFact> {
    let lower = name.to_ascii_lowercase();
    let script = [".scpt", ".applescript", ".scptd", ".app"]
        .iter()
        .any(|extension| lower.ends_with(extension));
    if !script {
        return None;
    }
    Some(fact(
        format!("folderaction:{directory}:{name}"),
        format!("Folder Action script {name}"),
        format!("{directory}/{name}"),
        directory,
        AutorunKind::Other,
    ))
}

/// The directories the collector walks, with the reader for each kind.
#[must_use]
pub(crate) fn sources() -> Vec<(&'static str, Source)> {
    let mut sources: Vec<(&'static str, Source)> = PERIODIC
        .iter()
        .map(|directory| (*directory, Source::Periodic))
        .collect();
    sources.extend(
        SCRIPTING_ADDITIONS
            .iter()
            .map(|directory| (*directory, Source::ScriptingAddition)),
    );
    sources.extend(
        FOLDER_ACTIONS
            .iter()
            .map(|directory| (*directory, Source::FolderAction)),
    );
    sources.push(("/etc/crontab", Source::Crontab));
    sources
}

/// What kind of thing a source directory holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// A `periodic` script directory.
    Periodic,
    /// A crontab file.
    Crontab,
    /// A directory of `.osax` bundles.
    ScriptingAddition,
    /// A directory of Folder Action scripts.
    FolderAction,
}

/// Read one directory or file through the reader its kind names.
#[must_use]
pub(crate) fn read(path: &Path, source: Source) -> Vec<AutorunFact> {
    let name = base_name(&path.display().to_string());
    match source {
        Source::Crontab => std::fs::read_to_string(path)
            .map(|text| crontab(&path.display().to_string(), &text))
            .unwrap_or_default(),
        Source::Periodic => entry(path)
            .and_then(|_| periodic(&path.parent()?.display().to_string(), &name))
            .into_iter()
            .collect(),
        Source::ScriptingAddition => entry(path)
            .and_then(|_| scripting_addition(&path.parent()?.display().to_string(), &name))
            .into_iter()
            .collect(),
        Source::FolderAction => entry(path)
            .and_then(|_| folder_action(&path.parent()?.display().to_string(), &name))
            .into_iter()
            .collect(),
    }
}

/// Whether the path is there at all, so a directory entry's existence is checked once.
fn entry(path: &Path) -> Option<()> {
    path.exists().then_some(())
}

fn fact(id: String, name: String, command: String, location: &str, kind: AutorunKind) -> AutorunFact {
    let exe = unixutil::executable_from_command(&command).map(|path| path.display().to_string());
    AutorunFact {
        id,
        name,
        command,
        location: location.to_owned(),
        kind,
        // `periodic` and the system crontab are the machine's; the per-user copies the
        // collector passes are the user's, and the scope is decided where the path is known.
        scope: if location.contains("/Library/")
            || location.starts_with("/etc/")
            || location.starts_with("/System/")
        {
            AutorunScope::System
        } else {
            AutorunScope::User
        },
        enabled: true,
        exe,
        sha256: None,
        hidden: false,
        signature: SignatureStatus::NotChecked,
    }
}

fn base_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_periodic_script_is_a_fact_named_for_its_schedule() {
        let fact = periodic("/etc/periodic/daily", "110.clean-tmps").unwrap();
        assert_eq!(fact.kind, AutorunKind::Cron);
        assert_eq!(fact.scope, AutorunScope::System);
        assert_eq!(fact.name, "daily periodic script 110.clean-tmps");
        assert_eq!(fact.command, "/etc/periodic/daily/110.clean-tmps");
        assert!(periodic("/etc/periodic/daily", ".hidden").is_none());
    }

    #[test]
    fn a_system_crontab_line_is_read_without_its_user_field() {
        // macOS' `/etc/crontab` is the BSD shape: five schedule fields, then the command.
        let text = "SHELL=/bin/sh\n\
                    */5 * * * * root /usr/libexec/periodic-wrapper\n\
                    # a comment\n";
        let facts = crontab("/etc/crontab", text);
        assert_eq!(facts.len(), 1, "{facts:?}");
        assert_eq!(facts[0].command, "root /usr/libexec/periodic-wrapper");
        assert_eq!(facts[0].scope, AutorunScope::System);
    }

    #[test]
    fn a_scripting_addition_is_a_bundle_anything_can_load() {
        let fact = scripting_addition("/Library/ScriptingAdditions", "Acme.osax").unwrap();
        assert_eq!(fact.name, "Scripting addition Acme.osax");
        assert_eq!(fact.scope, AutorunScope::System);
        assert!(scripting_addition("/Library/ScriptingAdditions", "readme.txt").is_none());
    }

    #[test]
    fn a_folder_action_script_runs_when_a_folder_changes() {
        let fact = folder_action("/Library/Scripts/Folder Action Scripts", "Sync.scpt").unwrap();
        assert_eq!(fact.name, "Folder Action script Sync.scpt");
        assert!(folder_action("/Library/Scripts/Folder Action Scripts", "notes.txt").is_none());
        assert!(
            folder_action(
                "/Users/user/Library/Scripts/Folder Action Scripts",
                "Mine.applescript"
            )
            .is_some_and(|fact| fact.scope == AutorunScope::User)
        );
    }

    #[test]
    fn every_source_names_a_directory_a_person_can_look_in() {
        let sources = sources();
        assert!(sources.len() >= 6);
        assert!(
            sources
                .iter()
                .any(|(path, kind)| path.starts_with("/etc/periodic") && *kind == Source::Periodic)
        );
        assert!(
            sources
                .iter()
                .any(|(path, kind)| *path == "/etc/crontab" && *kind == Source::Crontab)
        );
        // Nothing here is a browser profile, a keychain or a login-item store.
        assert!(
            sources
                .iter()
                .all(|(path, _)| !path.contains("Keychain") && !path.contains("LoginItems"))
        );
    }
}
