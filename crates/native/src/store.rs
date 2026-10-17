//! Reading and writing ranger's own files, atomically.

use std::io::Write;
use std::path::Path;

use vnr_core::{Snapshot, Suppression};

/// Load the last snapshot, if it is present and this build understands its schema.
#[must_use]
pub fn load_last() -> Option<Snapshot> {
    load(&crate::paths::last_snapshot_path())
}

/// What ranger found where the baseline should be.
#[derive(Clone, Debug)]
pub enum BaselineLoad {
    /// No baseline has been accepted.
    Missing,
    /// A file is there, but this build cannot use it.
    Unreadable(String),
    /// A baseline this build can diff against.
    Present(Box<Snapshot>),
}

/// Read the accepted baseline, saying why when it cannot be used.
///
/// "No baseline" and "a baseline this build cannot read" are different answers: the
/// second one still means a person accepted something, and the interface must offer to
/// replace it rather than pretending the file is not there.
#[must_use]
pub fn read_baseline() -> BaselineLoad {
    let path = crate::paths::baseline_path();
    if !path.exists() {
        return BaselineLoad::Missing;
    }
    match load(&path) {
        Some(snapshot) => BaselineLoad::Present(Box::new(snapshot)),
        None => BaselineLoad::Unreadable(format!(
            "{} exists, but this build cannot read it. Accepting a new baseline replaces it.",
            path.display()
        )),
    }
}

/// Save the last snapshot, replacing the previous one atomically.
pub fn save_last(snapshot: &Snapshot) -> std::io::Result<()> {
    write_json(snapshot, &crate::paths::last_snapshot_path())
}

/// Save a snapshot as the accepted baseline, replacing the previous one atomically.
///
/// Nothing calls this except a person asking for it: a baseline that moved on its own
/// would make every diff a comparison against the wrong day.
pub fn save_baseline(snapshot: &Snapshot) -> std::io::Result<()> {
    write_json(snapshot, &crate::paths::baseline_path())
}

/// Read the person's suppressions, dropping any that have expired.
#[must_use]
pub fn load_suppressions(now: u64) -> Vec<Suppression> {
    read_suppressions(&crate::paths::suppressions_path(), now)
}

fn read_suppressions(path: &Path, now: u64) -> Vec<Suppression> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<Suppression>>(&text) {
        Ok(mut list) => {
            vnr_core::prune_suppressions(&mut list, now);
            list
        }
        Err(error) => {
            log::warn!("ignoring {}: {error}", path.display());
            Vec::new()
        }
    }
}

/// Save the suppressions, replacing the previous file atomically.
pub fn save_suppressions(suppressions: &[Suppression]) -> std::io::Result<()> {
    let path = crate::paths::suppressions_path();
    let bytes = serde_json::to_vec_pretty(suppressions)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(&path, &bytes)
}

/// What the interface remembers between launches.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct UiSettings {
    /// Dark theme.
    pub dark: Option<bool>,
    /// The view to open.
    pub view: Option<String>,
    /// The process poll.
    pub poll: Option<bool>,
    /// The file watcher.
    pub watch: Option<bool>,
    /// The live indicator.
    pub led: Option<bool>,
}

/// Read the interface preferences, falling back to the defaults.
#[must_use]
pub fn load_ui_settings() -> UiSettings {
    std::fs::read_to_string(crate::paths::settings_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Save the interface preferences.
pub fn save_ui_settings(settings: &UiSettings) -> std::io::Result<()> {
    write_json_value(settings, &crate::paths::settings_path())
}

fn load(path: &Path) -> Option<Snapshot> {
    let text = std::fs::read_to_string(path).ok()?;
    let snapshot: Snapshot = serde_json::from_str(&text).ok()?;
    if snapshot.schema != vnr_core::model::SCHEMA_VERSION {
        log::warn!(
            "ignoring {}: schema {} is not {}",
            path.display(),
            snapshot.schema,
            vnr_core::model::SCHEMA_VERSION
        );
        return None;
    }
    Some(snapshot)
}

/// Write any serialisable value as pretty JSON, replacing the target atomically.
pub fn write_json_value<T: serde::Serialize + ?Sized>(value: &T, path: &Path) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(path, &bytes)
}

/// Write a snapshot as pretty JSON, replacing the target atomically.
pub fn write_json(snapshot: &Snapshot, path: &Path) -> std::io::Result<()> {
    write_json_value(snapshot, path)
}

/// Write bytes to a file by writing a temporary sibling and renaming it into place.
///
/// A crash leaves the previous file intact rather than a half-written one.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    crate::paths::ensure_dir(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    // Replacing a file can be refused for a moment on Windows while another handle —
    // an antivirus scanner, the search indexer, a second ranger window — still has it
    // open. A scan result is worth a few short retries rather than a lost save.
    let mut attempt = 0_u32;
    let mut result = temp.persist(path);
    loop {
        match result {
            Ok(_) => return Ok(()),
            Err(error) => {
                let transient = is_transient_replace(&error.error);
                if attempt < 3 && transient {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(60 * u64::from(attempt)));
                    result = error.file.persist(path);
                } else {
                    return Err(error.error);
                }
            }
        }
    }
}

fn is_transient_replace(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::PermissionDenied)
        || matches!(error.raw_os_error(), Some(5) | Some(32))
}

/// Write a Markdown report next to the JSON exports.
pub fn write_markdown(body: &str, path: &Path) -> std::io::Result<()> {
    write_atomic(path, body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::{Host, Snapshot};

    #[test]
    fn round_trips_a_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.json");
        let mut snapshot = Snapshot::empty(Host::default(), false);
        snapshot.taken_at_unix = 42;
        write_json(&snapshot, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let read: Snapshot = serde_json::from_str(&text).unwrap();
        assert_eq!(read.taken_at_unix, 42);
        assert_eq!(read.schema, vnr_core::model::SCHEMA_VERSION);
    }

    #[test]
    fn atomic_write_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.txt");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
    }

    #[test]
    fn suppressions_are_pruned_and_malformed_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("suppressions.json");
        let list = vec![
            Suppression {
                rule_id: "r".to_owned(),
                subject: "s".to_owned(),
                reason: "active".to_owned(),
                expires_unix: 200,
            },
            Suppression {
                rule_id: "r".to_owned(),
                subject: "t".to_owned(),
                reason: "expired".to_owned(),
                expires_unix: 50,
            },
        ];
        write_atomic(&path, &serde_json::to_vec_pretty(&list).unwrap()).unwrap();
        let read = read_suppressions(&path, 100);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].subject, "s");

        write_atomic(&path, b"not json").unwrap();
        assert!(read_suppressions(&path, 100).is_empty());
    }
}
