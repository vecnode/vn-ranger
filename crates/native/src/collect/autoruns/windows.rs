//! Startup items on Windows.
//!
//! Two sources are read: the registry, through the surface table next door, and the per-user
//! and machine Startup folders. The collector is partial on purpose: scheduled tasks, WMI
//! subscriptions, shortcut targets and kernel drivers are named as gaps rather than silently
//! omitted (`docs/PLAN.md` §9, wave 5).

use std::path::Path;

use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};

use super::super::winutil;
use super::registry::{self, KeyReader, WindowsRegistry};
use crate::collect::Outcome;
use crate::hash::Hasher;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

/// Read the startup entries this build can see.
#[must_use]
pub fn collect(hasher: &mut Hasher) -> Outcome<AutorunFact> {
    let mut items = Vec::new();
    let mut reasons = Vec::new();
    collect_registry(&mut items, &mut reasons);
    collect_startup_folders(&mut items, &mut reasons);
    collect_services(&mut items, &mut reasons);
    // What the table covers, said in the techniques it covers, so the status line is a
    // statement about the registry rather than a count of keys.
    let mut techniques: Vec<&str> = registry::SURFACES
        .iter()
        .filter_map(|surface| surface.technique)
        .collect();
    techniques.sort_unstable();
    techniques.dedup();
    reasons.push(format!(
        "{} registry surfaces were read, covering {}. Scheduled tasks, WMI subscriptions and \
         kernel drivers are not listed in this build.",
        registry::SURFACES.len(),
        techniques.join(", ")
    ));
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

/// Every surface in the table, in both registry views where the table asks for them.
///
/// One loop, one reader, one parser: a surface is a row, and a row that cannot be read is a
/// reason on the status rather than a silent gap. The order is the table's, so two scans of
/// an unchanged machine list the same entries in the same order.
fn collect_registry(items: &mut Vec<AutorunFact>, reasons: &mut Vec<String>) {
    let reader = WindowsRegistry;
    for surface in registry::SURFACES {
        for view in surface.wideness.views() {
            let depth = surface.read.depth();
            match reader.read(surface.hive, *view, surface.key, depth) {
                Ok(data) => {
                    for entry in registry::entries(surface, *view, &data) {
                        let command = winutil::expand_env(&entry.command);
                        let exe = winutil::executable_from_command(&command)
                            .map(|path| path.to_string_lossy().into_owned());
                        items.push(AutorunFact {
                            id: entry.id,
                            name: entry.name,
                            command,
                            location: entry.location,
                            kind: surface.kind,
                            scope: surface.scope,
                            enabled: true,
                            exe,
                            sha256: None,
                            signature: SignatureStatus::NotChecked,
                        });
                    }
                }
                Err(reason) => reasons.push(format!("{}: {reason}", surface.label)),
            }
        }
    }
}

fn collect_startup_folders(items: &mut Vec<AutorunFact>, reasons: &mut Vec<String>) {
    let folders = [
        (
            std::env::var("APPDATA").ok().map(|root| {
                Path::new(&root)
                    .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
                    .to_path_buf()
            }),
            AutorunScope::User,
        ),
        (
            std::env::var("PROGRAMDATA").ok().map(|root| {
                Path::new(&root)
                    .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
                    .to_path_buf()
            }),
            AutorunScope::System,
        ),
    ];
    let mut saw_shortcut = false;
    for (folder, scope) in folders {
        let Some(folder) = folder else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let exe = if matches!(extension.as_str(), "exe" | "com" | "bat" | "cmd") {
                Some(path.to_string_lossy().into_owned())
            } else {
                if extension == "lnk" {
                    saw_shortcut = true;
                }
                None
            };
            items.push(AutorunFact {
                id: format!("startup:{}:{name}", scope.label()),
                name,
                command: path.to_string_lossy().into_owned(),
                location: folder.to_string_lossy().into_owned(),
                kind: AutorunKind::StartupFolder,
                scope,
                enabled: true,
                exe,
                sha256: None,
                signature: SignatureStatus::NotChecked,
            });
        }
    }
    if saw_shortcut {
        reasons.push(
            "Startup shortcuts (.lnk) are listed, but their targets are not resolved in this build."
                .to_owned(),
        );
    }
}

fn collect_services(items: &mut Vec<AutorunFact>, reasons: &mut Vec<String>) {
    let path = r"SYSTEM\CurrentControlSet\Services";
    let root = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .or_else(|_| RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path));
    let Ok(root) = root else {
        reasons.push("The service registry could not be read.".to_owned());
        return;
    };
    for name in root.enum_keys().flatten() {
        let Ok(key) = root.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };
        let Some(image) = winutil::get_string(&key, "ImagePath") else {
            continue;
        };
        let start = key.get_value::<u32, _>("Start").unwrap_or(3);
        let kind = key.get_value::<u32, _>("Type").unwrap_or(0x10);
        let is_win32_service = kind & 0x10 != 0 || kind & 0x20 != 0 || kind & 0x100 != 0;
        if start > 2 || !is_win32_service {
            continue;
        }
        let display = winutil::get_string(&key, "DisplayName").unwrap_or_else(|| name.clone());
        let command = winutil::expand_env(&image);
        let exe = winutil::executable_from_command(&command).map(|path| path.to_string_lossy().into_owned());
        items.push(AutorunFact {
            id: format!("service:{name}"),
            name: display,
            command,
            location: format!(r"HKLM\{path}\{name}"),
            kind: AutorunKind::Service,
            scope: AutorunScope::System,
            enabled: true,
            exe,
            sha256: None,
            signature: SignatureStatus::NotChecked,
        });
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
