//! Startup items on Linux: systemd units, XDG autostart entries and system cron.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};

use super::super::unixutil;
use crate::collect::Outcome;
use crate::hash::Hasher;

/// Read the startup entries this account can see.
#[must_use]
pub fn collect(hasher: &mut Hasher) -> Outcome<AutorunFact> {
    let enabled = enabled_units();
    let mut items = Vec::new();
    let mut reasons = Vec::new();
    collect_systemd(&mut items, &enabled);
    collect_xdg(&mut items, &mut reasons);
    collect_cron(&mut items, &mut reasons);
    reasons.push(
        "Kernel modules, and per-user crontabs that need elevation, are not listed in this build.".to_owned(),
    );
    hash_items(&mut items, hasher);
    Outcome::Partial {
        items,
        reason: reasons.join(" "),
    }
}

fn systemd_dirs() -> Vec<(PathBuf, AutorunScope)> {
    let mut dirs = vec![
        (PathBuf::from("/etc/systemd/system"), AutorunScope::System),
        (PathBuf::from("/usr/lib/systemd/system"), AutorunScope::System),
        (PathBuf::from("/etc/systemd/user"), AutorunScope::User),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push((
            PathBuf::from(home).join(".config/systemd/user"),
            AutorunScope::User,
        ));
    }
    dirs
}

fn enabled_units() -> HashSet<String> {
    let mut names = HashSet::new();
    let mut bases: Vec<PathBuf> = vec![
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/etc/systemd/user"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        bases.push(PathBuf::from(home).join(".config/systemd/user"));
    }
    for base in bases {
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let wants = entry.path();
            if !wants.is_dir() || !entry.file_name().to_string_lossy().ends_with(".wants") {
                continue;
            }
            let Ok(links) = std::fs::read_dir(&wants) else {
                continue;
            };
            for link in links.flatten() {
                if let Some(name) = link.file_name().to_str() {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    names
}

fn collect_systemd(items: &mut Vec<AutorunFact>, enabled: &HashSet<String>) {
    for (directory, scope) in systemd_dirs() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("service") {
                continue;
            }
            let Some(file_name) = path.file_name().map(|name| name.to_string_lossy().into_owned()) else {
                continue;
            };
            let Ok(body) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Some(exec) = unit_value(&body, "ExecStart") else {
                continue;
            };
            let description = unit_value(&body, "Description").unwrap_or_else(|| file_name.clone());
            let command = exec.trim().trim_start_matches(['-', '+', '!', '@']).to_owned();
            let exe = unixutil::executable_from_command(&command).map(|path| path.display().to_string());
            items.push(AutorunFact {
                id: format!("systemd:{}:{file_name}", scope.label()),
                name: description,
                command,
                location: path.display().to_string(),
                kind: AutorunKind::SystemdUnit,
                scope,
                enabled: enabled.contains(&file_name),
                exe,
                sha256: None,
                hidden: false,
                signature: SignatureStatus::NotChecked,
            });
        }
    }
}

fn unit_value(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    body.lines()
        .map(str::trim)
        .find(|line| !line.starts_with('#') && line.starts_with(&prefix))
        .map(|line| line[prefix.len()..].trim().to_owned())
}

fn collect_xdg(items: &mut Vec<AutorunFact>, reasons: &mut Vec<String>) {
    let mut directories = vec![(PathBuf::from("/etc/xdg/autostart"), AutorunScope::System)];
    if let Ok(home) = std::env::var("HOME") {
        directories.push((PathBuf::from(home).join(".config/autostart"), AutorunScope::User));
    }
    let mut saw_entry = false;
    for (directory, scope) in directories {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("desktop") {
                continue;
            }
            let Some(file_name) = path.file_name().map(|name| name.to_string_lossy().into_owned()) else {
                continue;
            };
            let Ok(body) = std::fs::read_to_string(&path) else {
                continue;
            };
            let mut name = None;
            let mut exec = None;
            let mut hidden = false;
            let mut enabled = true;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                match key.trim() {
                    "Name" => name = Some(value.trim().to_owned()),
                    "Exec" => exec = Some(value.trim().to_owned()),
                    "Hidden" => hidden = value.trim().eq_ignore_ascii_case("true"),
                    "X-GNOME-Autostart-enabled" => {
                        enabled = !value.trim().eq_ignore_ascii_case("false");
                    }
                    _ => {}
                }
            }
            if hidden {
                continue;
            }
            let Some(command) = exec else {
                continue;
            };
            saw_entry = true;
            let exe = unixutil::executable_from_command(&command).map(|path| path.display().to_string());
            items.push(AutorunFact {
                id: format!("xdg:{}:{file_name}", scope.label()),
                name: name.unwrap_or(file_name),
                command,
                location: path.display().to_string(),
                kind: AutorunKind::XdgAutostart,
                scope,
                enabled,
                exe,
                sha256: None,
                hidden: false,
                signature: SignatureStatus::NotChecked,
            });
        }
    }
    if !saw_entry {
        reasons.push("No XDG autostart directories were readable.".to_owned());
    }
}

fn collect_cron(items: &mut Vec<AutorunFact>, reasons: &mut Vec<String>) {
    let mut files = vec![PathBuf::from("/etc/crontab")];
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        files.extend(entries.flatten().map(|entry| entry.path()));
    }
    let mut saw = false;
    for path in files {
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        let location = path.display().to_string();
        let file_name = path.file_name().map_or_else(
            || "crontab".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        for (index, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 7 {
                continue;
            }
            let command = fields[6..].join(" ");
            let exe = unixutil::executable_from_command(&command).map(|path| path.display().to_string());
            items.push(AutorunFact {
                id: format!("cron:{file_name}:{}", index + 1),
                name: format!("{file_name}:{}", index + 1),
                command,
                location: location.clone(),
                kind: AutorunKind::Cron,
                scope: AutorunScope::System,
                enabled: true,
                exe,
                sha256: None,
                hidden: false,
                signature: SignatureStatus::NotChecked,
            });
            saw = true;
        }
    }
    if !saw {
        reasons.push("No system cron entries were readable.".to_owned());
    }
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
