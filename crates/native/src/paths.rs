//! Where ranger keeps its own data.
//!
//! One directory per user, chosen by the platform's own convention, holding only
//! files ranger wrote. Removing the directory resets the application.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// The environment variable that moves ranger's data directory.
///
/// It exists for two callers that cannot use the platform directory: the soak harness,
/// which needs a disposable profile, and a person who wants a second, inspectable
/// profile beside their daily one. The value must be an absolute path; a relative one is
/// ignored, because a data directory that moves with the working directory is how a
/// "portable" tool ends up writing into whatever folder launched it.
pub const DATA_DIR_ENV: &str = "VN_RANGER_DATA_DIR";

/// The application's data directory.
///
/// On Windows this is under `%APPDATA%`, on macOS under `Application Support`, and on
/// Linux under `$XDG_DATA_HOME` or `~/.local/share`. `VN_RANGER_DATA_DIR`, when it holds
/// an absolute path, replaces all three.
#[must_use]
pub fn data_dir() -> PathBuf {
    if let Some(directory) = override_dir(std::env::var_os(DATA_DIR_ENV).as_deref()) {
        return directory;
    }
    ProjectDirs::from("com", "vecnode", "vn-ranger").map_or_else(
        || PathBuf::from(".vn-ranger"),
        |dirs| dirs.data_dir().to_path_buf(),
    )
}

/// The override, when it is one: absolute, and therefore not a function of the working
/// directory.
fn override_dir(value: Option<&OsStr>) -> Option<PathBuf> {
    let path = Path::new(value?);
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        log::warn!(
            "ignoring {DATA_DIR_ENV}={}: it is not an absolute path",
            path.display()
        );
        None
    }
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

/// Where the person's suppressions are kept.
#[must_use]
pub fn suppressions_path() -> PathBuf {
    data_dir().join("suppressions.json")
}

/// Where the interface preferences are kept.
#[must_use]
pub fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

/// The action journal: one append-only file plus its rotations.
#[must_use]
pub fn journal_path() -> PathBuf {
    data_dir().join("journal.ndjson")
}

/// Where quarantined files live, one directory per entry.
#[must_use]
pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

/// Where rule packs and their public keys live.
#[must_use]
pub fn packs_dir() -> PathBuf {
    data_dir().join("packs")
}

/// Where the extra watched folders are kept.
#[must_use]
pub fn watch_roots_path() -> PathBuf {
    data_dir().join("watch-roots.json")
}

/// The instance lock that keeps one window per data directory.
#[must_use]
pub fn instance_path() -> PathBuf {
    data_dir().join("instance.lock")
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
    fn an_absolute_data_directory_override_is_honoured() {
        let absolute = if cfg!(windows) {
            "C:\\vn-ranger-data"
        } else {
            "/var/tmp/vn-ranger-data"
        };
        assert_eq!(
            override_dir(Some(OsStr::new(absolute))),
            Some(PathBuf::from(absolute))
        );
    }

    #[test]
    fn a_relative_or_empty_override_is_ignored() {
        assert_eq!(override_dir(Some(OsStr::new("data"))), None);
        assert_eq!(override_dir(Some(OsStr::new(""))), None);
        assert_eq!(override_dir(None), None);
    }

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
