//! Installed packages from dpkg or pacman.

use vnr_core::PackageFact;

use crate::collect::Outcome;

/// Read the package database this distribution uses.
#[must_use]
pub fn collect() -> Outcome<PackageFact> {
    let mut items = Vec::new();
    if let Ok(body) = std::fs::read_to_string("/var/lib/dpkg/status") {
        parse_dpkg(&body, &mut items);
    }
    if let Ok(entries) = std::fs::read_dir("/var/lib/pacman/local") {
        for entry in entries.flatten() {
            let desc = entry.path().join("desc");
            if let Ok(body) = std::fs::read_to_string(desc) {
                parse_pacman(&body, &mut items);
            }
        }
    }
    if items.is_empty() {
        return Outcome::Unavailable {
            reason: "No dpkg or pacman package database was readable.".to_owned(),
        };
    }
    items.sort_by_key(|package| package.name.to_lowercase());
    items.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    Outcome::Partial {
        items,
        reason: "Snap, Flatpak and language-specific package managers are not listed yet.".to_owned(),
    }
}

fn parse_dpkg(body: &str, items: &mut Vec<PackageFact>) {
    for block in body.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut publisher = None;
        let mut installed = true;
        for line in block.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Package" => name = Some(value.to_owned()),
                "Version" => version = Some(value.to_owned()),
                "Maintainer" => publisher = Some(value.to_owned()),
                "Status" => installed = value.ends_with(" installed"),
                _ => {}
            }
        }
        if let Some(name) = name
            && installed
        {
            items.push(PackageFact {
                name,
                version,
                publisher,
                source: "dpkg".to_owned(),
            });
        }
    }
}

fn parse_pacman(body: &str, items: &mut Vec<PackageFact>) {
    let mut name = None;
    let mut version = None;
    let mut publisher = None;
    let mut section = "";
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('%') && line.ends_with('%') {
            section = line;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        match section {
            "%NAME%" => name = Some(line.to_owned()),
            "%VERSION%" => version = Some(line.to_owned()),
            "%PACKAGER%" => publisher = Some(line.to_owned()),
            _ => {}
        }
    }
    if let Some(name) = name {
        items.push(PackageFact {
            name,
            version,
            publisher,
            source: "pacman".to_owned(),
        });
    }
}
