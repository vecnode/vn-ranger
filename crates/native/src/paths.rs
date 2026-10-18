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
///
/// When the roaming folder cannot be written — a folder policy, a sandbox around the
/// process, an antivirus rule — the local application folder is used instead, because a
/// journal nobody can write is worse than a journal in the second-best place. Which one was
/// used is never a guess: [`data_dir_note`] says so in words the window shows.
#[must_use]
pub fn data_dir() -> PathBuf {
    static CHOSEN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    CHOSEN.get_or_init(choose_data_dir).clone()
}

/// Why the data directory is the one it is, when it is not the usual one.
#[must_use]
pub fn data_dir_note() -> Option<String> {
    let chosen = data_dir();
    let usual = usual_data_dir();
    if chosen == usual {
        return None;
    }
    Some(format!(
        "The usual folder ({}) cannot be written by this program, so this session records into {} instead. Everything is still local and still yours.",
        usual.display(),
        chosen.display()
    ))
}

/// Pick the data directory once, at the first call.
fn choose_data_dir() -> PathBuf {
    if let Some(directory) = override_dir(std::env::var_os(DATA_DIR_ENV).as_deref()) {
        return directory;
    }
    let usual = usual_data_dir();
    if writable(&usual) {
        return usual;
    }
    let local = local_data_dir();
    if local != usual && writable(&local) {
        log::warn!(
            "{} cannot be written, so the data directory is {}",
            usual.display(),
            local.display()
        );
        return local;
    }
    usual
}

/// The folder the platform's own convention names.
fn usual_data_dir() -> PathBuf {
    ProjectDirs::from("com", "vecnode", "vn-ranger").map_or_else(
        || PathBuf::from(".vn-ranger"),
        |dirs| dirs.data_dir().to_path_buf(),
    )
}

/// The same folder under the local application data root.
fn local_data_dir() -> PathBuf {
    ProjectDirs::from("com", "vecnode", "vn-ranger").map_or_else(
        || PathBuf::from(".vn-ranger"),
        |dirs| dirs.data_local_dir().to_path_buf(),
    )
}

/// Whether this program may create a file in `directory`, creating it if it is missing.
///
/// A probe rather than a permission query: the answer that matters is what happens when a
/// file is written, and a folder that reports itself writable but refuses a create is
/// exactly the case this is here to catch.
fn writable(directory: &Path) -> bool {
    let probe = directory.join(".write-probe");
    let created = std::fs::create_dir_all(directory).is_ok();
    let wrote = std::fs::write(&probe, b"").is_ok();
    if wrote {
        let _ = std::fs::remove_file(&probe);
    }
    created && wrote
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

/// The file a second launch touches to ask the running window to come forward.
///
/// A file rather than a socket or a pipe: it needs no protocol, and clearing it at start is
/// what stops a stale one from raising a window at launch (`docs/PLAN.md` §6.5).
#[must_use]
pub fn wake_path() -> PathBuf {
    data_dir().join("wake")
}

/// The file a launch writes to ask a running window to stop.
///
/// Beside the wake file and for the same reason: one file, one meaning, no protocol. It is
/// only ever written by `--replace`, so an ordinary second launch still just raises the
/// window that is there.
#[must_use]
pub fn stop_path() -> PathBuf {
    data_dir().join("stop")
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
    fn a_folder_that_holds_a_file_is_writable_and_a_file_in_the_way_is_not() {
        let directory = tempfile::tempdir().unwrap();
        assert!(writable(directory.path()));
        let file = directory.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(!writable(&file), "a file is not a folder to write into");
        assert!(
            !writable(&file.join("child")),
            "a folder cannot be created under a file"
        );
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
