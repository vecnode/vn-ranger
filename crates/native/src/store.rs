//! Reading and writing ranger's own files, atomically.

use std::io::Write;
use std::path::Path;

use vnr_core::Snapshot;

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

/// Write a snapshot as pretty JSON, replacing the target atomically.
pub fn write_json(snapshot: &Snapshot, path: &Path) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    write_atomic(path, &bytes)
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
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
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
    fn ignores_a_snapshot_from_another_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let mut snapshot = Snapshot::empty(Host::default(), false);
        snapshot.schema = vnr_core::model::SCHEMA_VERSION + 1;
        write_json(&snapshot, &path).unwrap();
        assert!(load(&path).is_none());
    }
}
