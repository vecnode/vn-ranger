//! Startup items on macOS: launch agents, launch daemons and what we cannot see.
//!
//! Login items live in an opaque system store and cron tabs need elevation, so this
//! collector is partial on purpose and names both gaps.

use std::path::{Path, PathBuf};

use plist::Value;
use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};

use super::super::unixutil;
use crate::collect::Outcome;
use crate::hash::Hasher;

/// Read the launchd plists this account can see.
#[must_use]
pub fn collect(hasher: &mut Hasher) -> Outcome<AutorunFact> {
    let mut items = Vec::new();
    let mut reasons = Vec::new();
    let mut directories = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        directories.push((
            PathBuf::from(home).join("Library/LaunchAgents"),
            AutorunScope::User,
        ));
    }
    directories.push((PathBuf::from("/Library/LaunchAgents"), AutorunScope::System));
    directories.push((PathBuf::from("/Library/LaunchDaemons"), AutorunScope::System));
    directories.push((
        PathBuf::from("/System/Library/LaunchAgents"),
        AutorunScope::System,
    ));
    directories.push((
        PathBuf::from("/System/Library/LaunchDaemons"),
        AutorunScope::System,
    ));

    for (directory, scope) in directories {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("plist") {
                continue;
            }
            if let Some(autorun) = read_plist(&path, scope) {
                items.push(autorun);
            }
        }
    }
    reasons.push(
        "Login items and per-user cron tabs are not listed by this build; cron tabs need elevation."
            .to_owned(),
    );
    hash_items(&mut items, hasher);
    Outcome::Partial {
        items,
        reason: reasons.join(" "),
    }
}

fn read_plist(path: &Path, scope: AutorunScope) -> Option<AutorunFact> {
    let value = Value::from_file(path).ok()?;
    let dictionary = value.as_dictionary()?;
    let label = dictionary
        .get("Label")
        .and_then(Value::as_string)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            path.file_stem().map_or_else(
                || "launchd item".to_owned(),
                |stem| stem.to_string_lossy().into_owned(),
            )
        });
    let arguments: Vec<String> = dictionary
        .get("ProgramArguments")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_string)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let program = dictionary
        .get("Program")
        .and_then(Value::as_string)
        .map(str::to_owned);
    let exe = program.clone().or_else(|| arguments.first().cloned());
    let command = if arguments.is_empty() {
        program.clone().unwrap_or_default()
    } else {
        arguments.join(" ")
    };
    let enabled = dictionary
        .get("Disabled")
        .and_then(Value::as_boolean)
        .is_none_or(|disabled| !disabled);
    let kind = if path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name.to_str() == Some("LaunchDaemons"))
    {
        AutorunKind::LaunchDaemon
    } else {
        AutorunKind::LaunchAgent
    };
    Some(AutorunFact {
        id: format!("launchd:{}:{label}", scope.label()),
        name: label,
        command,
        location: path.display().to_string(),
        kind,
        scope,
        enabled,
        exe: exe.and_then(|candidate| {
            unixutil::executable_from_command(&candidate).map(|path| path.display().to_string())
        }),
        sha256: None,
        signature: SignatureStatus::NotChecked,
    })
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
