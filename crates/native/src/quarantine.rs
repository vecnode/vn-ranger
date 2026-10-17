//! Quarantine: move a file into app-managed storage, and put it back verified.
//!
//! One directory per entry, named by an id:
//!
//! ```text
//! quarantine/<id>/manifest.json    what it was, where it came from, what it hashed to
//! quarantine/<id>/payload          the bytes themselves
//! ```
//!
//! The manifest is written and synced **before** the payload moves, so an entry that can
//! be seen is always describable. Restore verifies the payload against that description
//! and refuses to write over anything, which is what makes "reversible" a property of the
//! code rather than a promise in a dialog.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use vnr_core::action::{EntryId, Refusal};

use crate::action::{ActionError, ActionIo, Entry, Result, Source, ensure_root, open_source, resolve_entry};

/// The schema of a manifest.
pub const MANIFEST_SCHEMA: u32 = 1;

/// The file that holds the description of an entry.
pub const MANIFEST_NAME: &str = "manifest.json";

/// The file that holds the bytes.
pub const PAYLOAD_NAME: &str = "payload";

/// What an entry holds, written before the bytes arrive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The schema this manifest was written with.
    pub schema: u32,
    /// The entry's id, as hex.
    pub id: String,
    /// Where the file came from, as the person saw it.
    pub original_path: String,
    /// Its SHA-256 at the moment it was taken.
    pub sha256: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its permission bits on Unix, where they can be restored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Seconds since the Unix epoch.
    pub quarantined_at: u64,
    /// Why it was taken, in the words the finding used.
    pub reason: String,
    /// Which build took it.
    pub app: String,
}

/// A file that has been quarantined.
#[derive(Debug)]
pub struct Quarantined {
    /// Its id.
    pub id: EntryId,
    /// What was recorded about it.
    pub manifest: Manifest,
}

/// A file that has been put back.
#[derive(Debug)]
pub struct Restored {
    /// What was recorded about it.
    pub manifest: Manifest,
}

/// A file that has been deleted for good.
#[derive(Debug)]
pub struct Purged {
    /// What was recorded about it.
    pub manifest: Manifest,
}

/// Take a file into the quarantine in the platform data directory.
pub fn quarantine(path: &Path, reason: &str, io: &dyn ActionIo) -> Result<Quarantined> {
    take(
        &crate::paths::quarantine_dir(),
        path,
        reason,
        crate::now_unix(),
        io,
    )
}

/// Take a file into the quarantine under a chosen root.
///
/// The root is a parameter so that a test uses its own sandbox and the soak harness uses a
/// disposable profile; the writer never invents one.
pub fn take(
    root_path: &Path,
    path: &Path,
    reason: &str,
    now_unix: u64,
    io: &dyn ActionIo,
) -> Result<Quarantined> {
    let root = ensure_root(root_path, io)?;
    let source = open_source(path, io)?;
    source.verify_unchanged(io)?;

    let (id, entry) = create_entry(&root, &source, now_unix)?;
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA,
        id: id.to_hex(),
        original_path: source.path.display().to_string(),
        sha256: source.sha256.clone(),
        size: source.size(),
        mode: mode_of(&source),
        quarantined_at: now_unix,
        reason: reason.to_owned(),
        app: env!("CARGO_PKG_VERSION").to_owned(),
    };
    write_manifest(&entry.dir, &manifest, io)?;

    source.verify_unchanged(io)?;
    source.move_into(io, &entry.dir, &OsString::from(PAYLOAD_NAME))?;

    // A move that landed bytes nobody can verify is not a quarantine. The entry stays, so
    // a recovery verdict can find it, and the refusal says what happened.
    if read_payload(&entry.dir, io)? != source.sha256 {
        return Err(ActionError::Refused(Refusal::HashMismatch));
    }
    Ok(Quarantined { id, manifest })
}

/// Put a quarantined file back where it came from, verifying it first.
pub fn restore(id_text: &str, io: &dyn ActionIo) -> Result<Restored> {
    restore_at(&crate::paths::quarantine_dir(), id_text, io)
}

/// Restore an entry under a chosen root.
pub fn restore_at(root_path: &Path, id_text: &str, io: &dyn ActionIo) -> Result<Restored> {
    let root = ensure_root(root_path, io)?;
    let entry = resolve_entry(&root, id_text, io)?;
    let manifest = read_manifest(&entry.dir)?;
    let payload_name = OsString::from(PAYLOAD_NAME);

    if read_payload(&entry.dir, io)? != manifest.sha256 {
        return Err(ActionError::Refused(Refusal::HashMismatch));
    }

    let original = PathBuf::from(&manifest.original_path);
    let name = original
        .file_name()
        .ok_or(ActionError::Refused(Refusal::NotAFile))?
        .to_os_string();
    let parent_path = original.parent().unwrap_or_else(|| Path::new("."));
    let parent = io
        .open_dir(parent_path)
        .map_err(|error| ActionError::io("open the original folder", error))?;
    if io.exists(&parent, &name) {
        return Err(ActionError::Refused(Refusal::DestinationOccupied));
    }
    io.hard_link(&entry.dir, &payload_name, &parent, &name)
        .map_err(|error| ActionError::io("put the file back", error))?;
    io.remove_file(&entry.dir, &payload_name)
        .map_err(|error| ActionError::io("remove the quarantined copy", error))?;
    finish_entry(&root, entry, io)?;
    Ok(Restored { manifest })
}

/// Delete a quarantined entry for good.
pub fn purge(id_text: &str, io: &dyn ActionIo) -> Result<Purged> {
    purge_at(&crate::paths::quarantine_dir(), id_text, io)
}

/// Purge an entry under a chosen root.
pub fn purge_at(root_path: &Path, id_text: &str, io: &dyn ActionIo) -> Result<Purged> {
    let root = ensure_root(root_path, io)?;
    let entry = resolve_entry(&root, id_text, io)?;
    let manifest = read_manifest(&entry.dir)?;
    match io.remove_file(&entry.dir, &OsString::from(PAYLOAD_NAME)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ActionError::io("remove the quarantine payload", error)),
    }
    finish_entry(&root, entry, io)?;
    Ok(Purged { manifest })
}

/// What an entry says about itself, without touching the bytes.
pub fn read_manifest(dir: &cap_std::fs::Dir) -> Result<Manifest> {
    let mut file = dir
        .open(MANIFEST_NAME)
        .map(cap_std::fs::File::into_std)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ActionError::Refused(Refusal::SourceMissing),
            _ => ActionError::io("read the quarantine manifest", error),
        })?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| ActionError::io("read the quarantine manifest", error))?;
    serde_json::from_str(&text)
        .map_err(|error| ActionError::io("parse the quarantine manifest", std::io::Error::other(error)))
}

fn create_entry(root: &cap_std::fs::Dir, source: &Source, now_unix: u64) -> Result<(EntryId, Entry)> {
    // The id is derived, not random: the same file at the same moment lands on the same
    // entry, and the attempt number is what resolves a collision instead of guessing.
    let mut attempt = 0_u32;
    loop {
        let id = derive_id(source, now_unix, attempt);
        let hex = id.to_hex();
        match root.create_dir(&hex) {
            Ok(()) => {
                let dir = root
                    .open_dir(&hex)
                    .map_err(|error| ActionError::io("open the quarantine entry", error))?;
                return Ok((id, Entry { id, dir }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.saturating_add(1);
                if attempt > 32 {
                    return Err(ActionError::io("find a free quarantine entry", error));
                }
            }
            Err(error) => return Err(ActionError::io("create the quarantine entry", error)),
        }
    }
}

fn derive_id(source: &Source, now_unix: u64, attempt: u32) -> EntryId {
    let mut hasher = Sha256::new();
    hasher.update(source.sha256.as_bytes());
    hasher.update(source.path.display().to_string().as_bytes());
    hasher.update(now_unix.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(attempt.to_le_bytes());
    let digest = hasher.finalize();
    EntryId::from_digest(&digest).unwrap_or(EntryId::from_bytes([0; 8]))
}

fn mode_of(source: &Source) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        source.file.metadata().ok().map(|meta| meta.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = source;
        None
    }
}

fn write_manifest(dir: &cap_std::fs::Dir, manifest: &Manifest, io: &dyn ActionIo) -> Result<()> {
    let mut file = io
        .create(dir, &OsString::from(MANIFEST_NAME))
        .map_err(|error| ActionError::io("create the quarantine manifest", error))?;
    let text = serde_json::to_vec_pretty(manifest)
        .map_err(|error| ActionError::io("write the quarantine manifest", std::io::Error::other(error)))?;
    file.write_all(&text)
        .map_err(|error| ActionError::io("write the quarantine manifest", error))?;
    file.sync_all()
        .map_err(|error| ActionError::io("write the quarantine manifest", error))?;
    Ok(())
}

fn read_payload(dir: &cap_std::fs::Dir, io: &dyn ActionIo) -> Result<String> {
    let mut file = io
        .open(dir, &OsString::from(PAYLOAD_NAME))
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ActionError::Refused(Refusal::SourceMissing),
            _ => ActionError::io("open the quarantined file", error),
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ActionError::io("read the quarantined file", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Remove the manifest and then the entry directory, so an interrupted purge leaves the
/// payload rather than an empty entry nobody can explain.
fn finish_entry(root: &cap_std::fs::Dir, entry: Entry, io: &dyn ActionIo) -> Result<()> {
    let hex = entry.id.to_hex();
    match io.remove_file(&entry.dir, &OsString::from(MANIFEST_NAME)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ActionError::io("remove the quarantine manifest", error)),
    }
    // The handle is closed before the name is removed: on Windows an open handle to a
    // directory prevents removing it, and the error reads "access denied", not "in use".
    drop(entry);
    root.remove_dir(hex)
        .map_err(|error| ActionError::io("remove the quarantine entry", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::RealIo;

    fn real() -> RealIo {
        RealIo
    }

    /// A root and a file, both inside the test's own temporary directory.
    fn setup(body: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("quarantine");
        let path = dir.path().join("thing.bin");
        std::fs::write(&path, body).unwrap();
        (dir, root, path)
    }

    #[test]
    fn quarantine_moves_the_bytes_and_describes_them() {
        let (dir, root, path) = setup(b"quarantine me");
        let taken = take(&root, &path, "a rule fired", 1_700_000_000, &real()).unwrap();

        assert!(!path.exists(), "the original is gone");
        assert_eq!(taken.manifest.original_path, path.display().to_string());
        assert_eq!(taken.manifest.size, 13);
        assert_eq!(taken.manifest.reason, "a rule fired");
        assert_eq!(taken.manifest.quarantined_at, 1_700_000_000);
        assert_eq!(taken.manifest.schema, MANIFEST_SCHEMA);

        let entry = dir.path().join("quarantine").join(taken.id.to_hex());
        assert_eq!(std::fs::read(entry.join(PAYLOAD_NAME)).unwrap(), b"quarantine me");
        let written: Manifest =
            serde_json::from_slice(&std::fs::read(entry.join(MANIFEST_NAME)).unwrap()).unwrap();
        assert_eq!(written, taken.manifest);
    }

    #[test]
    fn quarantine_then_restore_returns_the_same_bytes_and_clears_the_entry() {
        let (dir, root, path) = setup(b"round trip");
        let taken = take(&root, &path, "test", 1, &real()).unwrap();
        assert!(!path.exists());

        let restored = restore_at(&root, &taken.id.to_hex(), &real()).unwrap();
        assert_eq!(restored.manifest, taken.manifest);
        assert_eq!(std::fs::read(&path).unwrap(), b"round trip");
        assert!(
            !dir.path().join("quarantine").join(taken.id.to_hex()).exists(),
            "the entry is gone after a restore"
        );
    }

    #[test]
    fn restore_refuses_a_payload_that_no_longer_matches_the_manifest() {
        let (dir, root, path) = setup(b"authentic");
        let taken = take(&root, &path, "test", 1, &real()).unwrap();
        let payload = dir
            .path()
            .join("quarantine")
            .join(taken.id.to_hex())
            .join(PAYLOAD_NAME);
        std::fs::write(&payload, b"swapped").unwrap();

        let error = restore_at(&root, &taken.id.to_hex(), &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::HashMismatch));
        assert!(!path.exists(), "nothing was written back");
        assert!(payload.exists(), "the evidence stays where it is");
    }

    #[test]
    fn restore_refuses_to_overwrite_a_file_that_reappeared() {
        let (_dir, root, path) = setup(b"original");
        let taken = take(&root, &path, "test", 1, &real()).unwrap();
        std::fs::write(&path, b"a new file with the same name").unwrap();

        let error = restore_at(&root, &taken.id.to_hex(), &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::DestinationOccupied));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"a new file with the same name",
            "the new file is untouched"
        );
    }

    #[test]
    fn purge_removes_the_entry_and_says_what_it_was() {
        let (dir, root, path) = setup(b"delete me");
        let taken = take(&root, &path, "test", 1, &real()).unwrap();
        let purged = purge_at(&root, &taken.id.to_hex(), &real()).unwrap();
        assert_eq!(purged.manifest, taken.manifest);
        assert!(!dir.path().join("quarantine").join(taken.id.to_hex()).exists());
    }

    #[test]
    fn a_path_shaped_id_is_refused_before_anything_is_looked_up() {
        let (_dir, root, _path) = setup(b"x");
        for bad in ["..", "../0123456789abcdef", "C:\\Windows", ""] {
            let error = purge_at(&root, bad, &real()).unwrap_err();
            assert_eq!(error.refusal(), Some(Refusal::NotAnEntry), "{bad:?}");
        }
    }

    #[test]
    fn an_entry_that_is_not_there_is_missing_rather_than_a_failure() {
        let (_dir, root, _path) = setup(b"x");
        let error = restore_at(&root, "0123456789abcdef", &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::SourceMissing));
        assert!(error.is_missing());
    }

    #[test]
    fn the_same_file_at_the_same_moment_derives_the_same_id() {
        let (_dir, _root, path) = setup(b"same");
        let source = open_source(&path, &real()).unwrap();
        assert_eq!(derive_id(&source, 42, 0), derive_id(&source, 42, 0));
        assert_ne!(derive_id(&source, 42, 0), derive_id(&source, 43, 0));
        assert_ne!(
            derive_id(&source, 42, 0),
            derive_id(&source, 42, 1),
            "a collision retries on the attempt number"
        );
    }

    #[test]
    fn a_collision_lands_on_a_second_entry_rather_than_an_error() {
        let (_dir, root, path) = setup(b"collide");
        let source = open_source(&path, &real()).unwrap();
        let (first, _) = create_entry(&ensure_root(&root, &real()).unwrap(), &source, 7).unwrap();
        let (second, _) = create_entry(&ensure_root(&root, &real()).unwrap(), &source, 7).unwrap();
        assert_ne!(first, second);
    }
}
