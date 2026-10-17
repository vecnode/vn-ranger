//! Installed applications and Homebrew formulae on macOS.

use std::path::{Path, PathBuf};

use plist::Value;
use vnr_core::PackageFact;

use crate::collect::Outcome;

/// Read `/Applications`, `~/Applications` and the Homebrew Cellar.
#[must_use]
pub fn collect() -> Outcome<PackageFact> {
    let mut items = Vec::new();
    let mut reasons = Vec::new();
    let mut application_directories = vec![PathBuf::from("/Applications")];
    if let Ok(home) = std::env::var("HOME") {
        application_directories.push(PathBuf::from(home).join("Applications"));
    }
    for directory in application_directories {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("app") {
                continue;
            }
            let name = path.file_stem().map_or_else(
                || path.display().to_string(),
                |stem| stem.to_string_lossy().into_owned(),
            );
            let version = info_plist_string(&path.join("Contents/Info.plist"), "CFBundleShortVersionString")
                .or_else(|| info_plist_string(&path.join("Contents/Info.plist"), "CFBundleVersion"));
            items.push(PackageFact {
                name,
                version,
                publisher: None,
                source: "Application".to_owned(),
            });
        }
    }
    for root in [
        PathBuf::from("/opt/homebrew/Cellar"),
        PathBuf::from("/usr/local/Cellar"),
    ] {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let version = std::fs::read_dir(&path)
                .ok()
                .and_then(|versions| versions.flatten().next())
                .map(|version| version.file_name().to_string_lossy().into_owned());
            items.push(PackageFact {
                name,
                version,
                publisher: Some("Homebrew".to_owned()),
                source: "Homebrew".to_owned(),
            });
        }
    }
    reasons.push("Mac App Store receipts and curl-installed tools are not listed yet.".to_owned());
    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    items.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    Outcome::Partial {
        items,
        reason: reasons.join(" "),
    }
}

fn info_plist_string(path: &Path, key: &str) -> Option<String> {
    Value::from_file(path)
        .ok()?
        .as_dictionary()?
        .get(key)?
        .as_string()
        .map(str::to_owned)
}
