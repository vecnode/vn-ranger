//! Startup items on Windows.
//!
//! Three sources are read: the `Run`/`RunOnce` registry keys in both registry views,
//! the per-user and machine Startup folders, and automatic Windows services. The
//! collector is partial on purpose: scheduled tasks, shortcut targets and kernel
//! drivers are named as gaps rather than silently omitted.

use std::path::Path;

use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

use super::super::winutil;
use crate::collect::Outcome;
use crate::hash::Hasher;

/// Read the startup entries this build can see.
#[must_use]
pub fn collect(hasher: &mut Hasher) -> Outcome<AutorunFact> {
    let mut items = Vec::new();
    let mut reasons = Vec::new();
    collect_run_keys(&mut items);
    collect_startup_folders(&mut items, &mut reasons);
    collect_services(&mut items, &mut reasons);
    reasons.push("Scheduled tasks and kernel drivers are not listed in this build.".to_owned());
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

fn collect_run_keys(items: &mut Vec<AutorunFact>) {
    let roots = [
        (HKEY_CURRENT_USER, "HKCU", AutorunScope::User),
        (HKEY_LOCAL_MACHINE, "HKLM", AutorunScope::System),
    ];
    let views = [(64u32, KEY_WOW64_64KEY), (32u32, KEY_WOW64_32KEY)];
    for (hive, hive_label, scope) in roots {
        for (view, flag) in views {
            for key_name in ["Run", "RunOnce"] {
                let path = format!(r"Software\Microsoft\Windows\CurrentVersion\{key_name}");
                let Ok(key) = RegKey::predef(hive).open_subkey_with_flags(&path, KEY_READ | flag) else {
                    continue;
                };
                for (name, _value) in key.enum_values().flatten() {
                    let Some(raw) = winutil::get_string(&key, &name) else {
                        continue;
                    };
                    if raw.trim().is_empty() {
                        continue;
                    }
                    let command = winutil::expand_env(&raw);
                    let exe = winutil::executable_from_command(&command)
                        .map(|path| path.to_string_lossy().into_owned());
                    items.push(AutorunFact {
                        id: format!("run:{hive_label}:{view}:{name}"),
                        name,
                        command,
                        location: format!(r"{hive_label}\{path} ({view}-bit)"),
                        kind: AutorunKind::RunKey,
                        scope,
                        enabled: true,
                        exe,
                        sha256: None,
                        signature: SignatureStatus::NotChecked,
                    });
                }
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
