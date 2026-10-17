//! Where ranger keeps its own data.
//!
//! One directory per user, chosen by the platform's own convention, holding only
//! files ranger wrote. Removing the directory resets the application.

use std::io;
use std::path::PathBuf;

use directories::ProjectDirs;

/// The application's data directory.
///
/// On Windows this is under `%APPDATA%`, on macOS under `Application Support`, and on
/// Linux under `$XDG_DATA_HOME` or `~/.local/share`.
#[must_use]
pub fn data_dir() -> PathBuf {
    ProjectDirs::from("com", "vecnode", "vn-ranger").map_or_else(
        || PathBuf::from(".vn-ranger"),
        |dirs| dirs.data_dir().to_path_buf(),
    )
}

/// Where exported reports are written.
#[must_use]
pub fn reports_dir() -> PathBuf {
    data_dir().join("reports")
}

/// Where local `.hdb` and `.hsb` signature databases are read from.
#[must_use]
pub fn signatures_dir() -> PathBuf {
    data_dir().join("signatures")
}

/// Where the last snapshot is kept, so a launch shows something before the scan ends.
#[must_use]
pub fn last_snapshot_path() -> PathBuf {
    data_dir().join("last-scan.json")
}

/// Where the accepted baseline is kept.
///
/// The baseline is a snapshot a person chose to keep, not the newest scan. It is only
/// written when someone asks for it.
#[must_use]
pub fn baseline_path() -> PathBuf {
    data_dir().join("baseline.json")
}

/// The folders the file watcher reads.
///
/// Only directories that exist are returned, so the interface never claims to watch a
/// folder the system does not have. The temporary directory is watched on every
/// platform; the startup folders are the ones the collectors already read.
#[must_use]
pub fn watch_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dirs) = directories::UserDirs::new() {
        for dir in [dirs.download_dir(), dirs.desktop_dir()].into_iter().flatten() {
            roots.push(dir.to_path_buf());
        }
        let home = dirs.home_dir();
        roots.push(home.join(".config").join("autostart"));
        roots.push(home.join("Library").join("LaunchAgents"));
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        roots.push(
            PathBuf::from(appdata)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        );
    }
    roots.push(std::env::temp_dir());
    roots.retain(|path| path.is_dir());
    let mut seen = std::collections::HashSet::new();
    roots.retain(|path| seen.insert(path.clone()));
    roots
}

/// Create a directory and every parent that is missing.
pub fn ensure_dir(path: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// A report path with a sortable, human-readable timestamp.
#[must_use]
pub fn report_path(extension: &str) -> PathBuf {
    reports_dir().join(format!(
        "vn-ranger-{}.{}",
        crate::now_unix(),
        extension.trim_start_matches('.')
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_roots_exist_and_are_unique() {
        let roots = watch_roots();
        assert!(
            !roots.is_empty(),
            "the temporary directory always exists and is watched"
        );
        let mut unique = std::collections::HashSet::new();
        for root in &roots {
            assert!(root.is_dir(), "{} should be a directory", root.display());
            assert!(unique.insert(root.clone()), "{} appears twice", root.display());
        }
    }
}
