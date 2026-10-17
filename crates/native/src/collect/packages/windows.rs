//! Installed applications from the Windows uninstall registry.

use std::collections::HashSet;

use vnr_core::PackageFact;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

use super::super::winutil;
use crate::collect::Outcome;

/// Read the uninstall keys in both hives and both registry views.
#[must_use]
pub fn collect() -> Outcome<PackageFact> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    let mut reasons = Vec::new();
    let roots = [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")];
    let views = [(64u32, KEY_WOW64_64KEY), (32u32, KEY_WOW64_32KEY)];
    let path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    for (hive, label) in roots {
        for (view, flag) in views {
            let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ | flag) else {
                continue;
            };
            for name in root.enum_keys().flatten() {
                let Ok(app) = root.open_subkey_with_flags(&name, KEY_READ) else {
                    continue;
                };
                if app.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 {
                    continue;
                }
                let Some(display) = winutil::get_string(&app, "DisplayName") else {
                    continue;
                };
                let display = display.trim();
                if display.is_empty() {
                    continue;
                }
                let version = winutil::get_string(&app, "DisplayVersion");
                let publisher = winutil::get_string(&app, "Publisher");
                let identity = format!(
                    "{}|{}",
                    display.to_lowercase(),
                    version.as_deref().unwrap_or_default()
                );
                if !seen.insert(identity) {
                    continue;
                }
                items.push(PackageFact {
                    name: display.to_owned(),
                    version,
                    publisher,
                    source: format!("Registry ({label}, {view}-bit)"),
                });
            }
        }
    }
    reasons.push("MSIX and Microsoft Store packages are not listed yet.".to_owned());
    if items.is_empty() {
        reasons.push("No uninstall entries were readable.".to_owned());
    }
    Outcome::Partial {
        items,
        reason: reasons.join(" "),
    }
}
