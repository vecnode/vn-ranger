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
