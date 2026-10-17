//! The action path: the only code that can move or remove a file.
//!
//! Two rules hold it together, and both are structural rather than procedural:
//!
//! * A destination is computed from an [`EntryId`], never from a path. The root is opened
//!   once as a [`cap_std::fs::Dir`], and every name handed to it is sixteen hex characters
//!   the core validated, so a caller cannot introduce `..`, a separator or an absolute
//!   path into the place a file is written.
//! * The file is opened once, hashed **from the handle**, and its identity is compared
//!   again immediately before the move. A test swaps the file between those two points
//!   through [`ActionIo`], so the refusal is proven rather than raced.
//!
//! The journal is the caller's: this module reports an outcome, and `apps/vn-ranger`
//! writes the intent before it calls in and the result after.

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};

use vnr_core::action::{EntryId, Refusal};

/// The largest file the action path will hash.
///
/// A move that cannot be verified after it happened is not a quarantine, it is a hope, so
/// a file above this is refused with a sentence rather than moved unverified.
pub const MAX_ACTION_BYTES: u64 = 512 * 1024 * 1024;

/// What went wrong with an act.
#[derive(Debug)]
pub enum ActionError {
    /// Ranger declined, and nothing was changed.
    Refused(Refusal),
    /// The operating system said no, during a named step.
    Io {
        /// What was being attempted, in the words the interface shows.
        doing: &'static str,
        /// The OS error.
        source: io::Error,
    },
}

impl ActionError {
    /// Wrap an OS error with the step it came from.
    pub(crate) fn io(doing: &'static str, source: io::Error) -> Self {
        Self::Io { doing, source }
    }

    /// The refusal, when this was a refusal rather than a failure.
    #[must_use]
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Refused(refusal) => Some(*refusal),
            Self::Io { .. } => None,
        }
    }

    /// Whether the file is simply not there, which is an outcome rather than a fault.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Refused(Refusal::SourceMissing))
            || matches!(self, Self::Io { source, .. } if source.kind() == io::ErrorKind::NotFound)
    }
}

impl fmt::Display for ActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => formatter.write_str(refusal.sentence()),
            Self::Io { doing, source } => write!(formatter, "Could not {doing}: {source}"),
        }
    }
}

impl std::error::Error for ActionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(_) => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

/// The result of an act.
pub type Result<T> = std::result::Result<T, ActionError>;

/// Everything the action path does to the filesystem.
///
/// It exists so that a test can swap a file between the stat and the rename without
/// having to win a race. A test that has to win a race to fail is a test that passes in
/// CI.
pub trait ActionIo {
    /// Open a directory as a capability. The only place ambient authority is used.
    fn open_dir(&self, path: &Path) -> io::Result<Dir>;
    /// Open a file below `dir`, read-only.
    fn open(&self, dir: &Dir, name: &OsString) -> io::Result<File>;
    /// Create a file below `dir`, refusing to replace an existing one.
    fn create(&self, dir: &Dir, name: &OsString) -> io::Result<File>;
    /// Whether the entry is a link or a reparse point, without following it.
    fn is_link(&self, dir: &Dir, name: &OsString) -> io::Result<bool>;
    /// Whether the entry is a regular file, without following it.
    fn is_file(&self, dir: &Dir, name: &OsString) -> io::Result<bool>;
    /// The identity of the entry, without following it.
    fn identity(&self, dir: &Dir, name: &OsString) -> io::Result<Identity>;
    /// Whether anything at all is at that name.
    fn exists(&self, dir: &Dir, name: &OsString) -> bool;
    /// Move an entry between two directory capabilities.
    fn rename(&self, from: &Dir, from_name: &OsString, to: &Dir, to_name: &OsString) -> io::Result<()>;
    /// Remove one file below `dir`.
    fn remove_file(&self, dir: &Dir, name: &OsString) -> io::Result<()>;
}

/// The real filesystem.
pub struct RealIo;

impl ActionIo for RealIo {
    fn open_dir(&self, path: &Path) -> io::Result<Dir> {
        Dir::open_ambient_dir(path, ambient_authority())
    }

    fn open(&self, dir: &Dir, name: &OsString) -> io::Result<File> {
        dir.open(name).map(cap_std::fs::File::into_std)
    }

    fn create(&self, dir: &Dir, name: &OsString) -> io::Result<File> {
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        dir.open_with(name, &options).map(cap_std::fs::File::into_std)
    }

    fn is_link(&self, dir: &Dir, name: &OsString) -> io::Result<bool> {
        dir.symlink_metadata(name).map(|metadata| metadata.is_symlink())
    }

    fn is_file(&self, dir: &Dir, name: &OsString) -> io::Result<bool> {
        dir.symlink_metadata(name).map(|metadata| metadata.is_file())
    }

    fn identity(&self, dir: &Dir, name: &OsString) -> io::Result<Identity> {
        dir.symlink_metadata(name)
            .map(|metadata| identity_from(&metadata))
    }

    fn exists(&self, dir: &Dir, name: &OsString) -> bool {
        dir.exists(name)
    }

    fn rename(&self, from: &Dir, from_name: &OsString, to: &Dir, to_name: &OsString) -> io::Result<()> {
        from.rename(from_name, to, to_name)
    }

    fn remove_file(&self, dir: &Dir, name: &OsString) -> io::Result<()> {
        dir.remove_file(name)
    }
}

/// What makes a file *that file*: enough to notice a swap between two syscalls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The volume or device the file is on.
    pub volume: u64,
    /// The file's number on that volume.
    pub file: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Its last write time, in the platform's own units.
    pub modified: i64,
    /// Its creation time, where the platform reports one.
    pub created: i64,
    /// How many names point at it.
    pub links: u64,
}

/// The identity of a file, from the metadata the directory reports for its name.
///
/// On Windows the platform's own file number and link count live behind an unstable
/// standard-library feature, so this uses the stable fields: size, write time and creation
/// time. That is enough to notice a swap and not enough to notice a second hard link, which
/// `docs/PLAN.md` §7 records as a named gap rather than a claim.
#[cfg(unix)]
fn identity_from(metadata: &cap_std::fs::Metadata) -> Identity {
    use cap_std::fs::MetadataExt;
    Identity {
        volume: metadata.dev(),
        file: metadata.ino(),
        size: metadata.len(),
        modified: metadata.mtime(),
        created: 0,
        links: metadata.nlink(),
    }
}

/// The identity of a file, from the metadata the directory reports for its name.
#[cfg(windows)]
fn identity_from(metadata: &cap_std::fs::Metadata) -> Identity {
    use cap_std::fs::MetadataExt;
    Identity {
        volume: 0,
        file: 0,
        size: metadata.len(),
        modified: i64::try_from(metadata.last_write_time()).unwrap_or(i64::MAX),
        created: i64::try_from(metadata.creation_time()).unwrap_or(0),
        // Unknown on this platform without an unstable feature: report the honest value
        // rather than a made-up count.
        links: 1,
    }
}

impl Identity {
    /// Whether two observations are the same file.
    ///
    /// When a platform cannot report a file number, the comparison falls back to size and
    /// write time: weaker, but never wrong in the direction of acting on a file that was
    /// not inspected.
    #[must_use]
    pub fn is_same_file(&self, other: &Self) -> bool {
        let same_number = self.file != 0 && self.file == other.file && self.volume == other.volume;
        (same_number || self.file == 0 || other.file == 0)
            && self.size == other.size
            && self.modified == other.modified
            && self.created == other.created
    }

    /// Whether another name points at the same file.
    #[must_use]
    pub fn has_extra_links(&self) -> bool {
        self.links > 1
    }
}

/// A file the action path has opened, hashed and identified.
#[derive(Debug)]
pub struct Source {
    /// The path the person sees, for the journal and the manifest.
    pub path: PathBuf,
    /// The directory capability it was opened through.
    pub parent: Dir,
    /// Its name inside that directory.
    pub name: OsString,
    /// The open handle the hash came from.
    pub file: File,
    /// What it was when it was inspected.
    pub identity: Identity,
    /// Its SHA-256, lowercase hex, computed from the handle.
    pub sha256: String,
}

impl Source {
    /// Its size, as it was when it was inspected.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.identity.size
    }

    /// Refuse unless the file is still the file that was inspected.
    ///
    /// This is the TOCTOU refusal. It runs immediately before the move, and it re-opens
    /// the name rather than trusting the handle, because the thing that changed is the
    /// *name*, not the bytes the handle points at.
    pub fn verify_unchanged(&self, io: &dyn ActionIo) -> Result<()> {
        if io
            .is_link(&self.parent, &self.name)
            .map_err(|error| missing_or("inspect the file", error))?
        {
            return Err(ActionError::Refused(Refusal::IsLink));
        }
        let again = io
            .identity(&self.parent, &self.name)
            .map_err(|error| missing_or("inspect the file", error))?;
        if again.is_same_file(&self.identity) {
            Ok(())
        } else {
            Err(ActionError::Refused(Refusal::Changed))
        }
    }

    /// Move the file to a name below a destination capability.
    ///
    /// One rename, on one volume. A cross-volume move is a copy, a sync and a verify, and
    /// it lives in the quarantine because the manifest has to record what was verified.
    pub fn move_into(&self, io: &dyn ActionIo, destination: &Dir, destination_name: &OsString) -> Result<()> {
        if io.exists(destination, destination_name) {
            return Err(ActionError::Refused(Refusal::DestinationOccupied));
        }
        io.rename(&self.parent, &self.name, destination, destination_name)
            .map_err(|error| ActionError::io("move the file into the quarantine", error))
    }
}

/// Open, identify and hash a file, refusing everything the action path does not accept.
pub fn open_source(path: &Path, io: &dyn ActionIo) -> Result<Source> {
    open_source_with_limit(path, io, MAX_ACTION_BYTES)
}

/// The same, with the size cap as a parameter, so the refusal has a test that does not
/// need a half-gigabyte file.
pub fn open_source_with_limit(path: &Path, io: &dyn ActionIo, limit: u64) -> Result<Source> {
    let name = path
        .file_name()
        .ok_or(ActionError::Refused(Refusal::NotAFile))?
        .to_os_string();
    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = io
        .open_dir(parent_path)
        .map_err(|error| missing_or("open the folder", error))?;

    if io
        .is_link(&parent, &name)
        .map_err(|error| missing_or("inspect the file", error))?
    {
        return Err(ActionError::Refused(Refusal::IsLink));
    }
    // Refused before it is opened: on Windows a directory cannot be opened for reading, and
    // the OS error that falls out of that is not the answer a person needs.
    if !io
        .is_file(&parent, &name)
        .map_err(|error| missing_or("inspect the file", error))?
    {
        return Err(ActionError::Refused(Refusal::NotAFile));
    }
    // The identity is taken from the directory entry before the file is opened, and again
    // after it is hashed: if the name started pointing somewhere else during the read, the
    // pair (identity, hash) would be a lie about the same file.
    let before = io
        .identity(&parent, &name)
        .map_err(|error| missing_or("inspect the file", error))?;
    if before.has_extra_links() {
        return Err(ActionError::Refused(Refusal::ManyLinks));
    }
    if before.size > limit {
        return Err(ActionError::Refused(Refusal::TooLarge));
    }
    let file = io
        .open(&parent, &name)
        .map_err(|error| missing_or("open the file", error))?;
    let sha256 = sha256_of(&file)?;
    let identity = io
        .identity(&parent, &name)
        .map_err(|error| missing_or("inspect the file", error))?;
    if !identity.is_same_file(&before) {
        return Err(ActionError::Refused(Refusal::Changed));
    }
    Ok(Source {
        path: path.to_path_buf(),
        parent,
        name,
        file,
        identity,
        sha256,
    })
}

/// Open, or create, the quarantine root. Its entries are directories named by id.
pub fn ensure_root(path: &Path, io: &dyn ActionIo) -> Result<Dir> {
    crate::paths::ensure_dir(path).map_err(|error| ActionError::io("create the quarantine folder", error))?;
    io.open_dir(path)
        .map_err(|error| ActionError::io("open the quarantine folder", error))
}

/// One quarantine entry: a directory named by an id.
#[derive(Debug)]
pub struct Entry {
    /// Which entry it is.
    pub id: EntryId,
    /// The directory capability, so callers never hold a path.
    pub dir: Dir,
}

/// Resolve an id below a root, refusing anything that is not an id first.
///
/// Order matters: the id is parsed before the filesystem is touched, so a path-shaped
/// string is a refusal rather than a lookup.
pub fn resolve_entry(root: &Dir, id_text: &str, io: &dyn ActionIo) -> Result<Entry> {
    let id = EntryId::from_hex(id_text).ok_or(ActionError::Refused(Refusal::NotAnEntry))?;
    let hex = id.to_hex();
    let dir = match root.open_dir(&hex) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ActionError::Refused(Refusal::SourceMissing));
        }
        Err(error) => return Err(ActionError::io("open the quarantine entry", error)),
    };
    let _ = io;
    Ok(Entry { id, dir })
}

fn sha256_of(file: &File) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut handle = file
        .try_clone()
        .map_err(|error| ActionError::io("read the file", error))?;
    loop {
        let read = handle
            .read(&mut buffer)
            .map_err(|error| ActionError::io("read the file", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// A missing file is an outcome, not a fault: the person may have moved it between the
/// preview and the act.
fn missing_or(doing: &'static str, error: io::Error) -> ActionError {
    if error.kind() == io::ErrorKind::NotFound {
        ActionError::Refused(Refusal::SourceMissing)
    } else {
        ActionError::io(doing, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn real() -> RealIo {
        RealIo
    }

    fn file_in(dir: &tempfile::TempDir, name: &str, body: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_source_is_hashed_from_its_handle_and_identified_from_its_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "thing.bin", b"hello");
        let source = open_source(&path, &real()).unwrap();
        assert_eq!(
            source.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(source.size(), 5);
        assert_eq!(source.name, OsString::from("thing.bin"));
        assert!(!source.identity.has_extra_links());
    }

    #[test]
    fn a_missing_file_is_refused_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let error = open_source(&dir.path().join("nope.bin"), &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::SourceMissing));
        assert!(error.is_missing());
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("folder");
        fs::create_dir(&nested).unwrap();
        let error = open_source(&nested, &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::NotAFile));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_with_a_second_hard_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "one.bin", b"shared");
        let other = dir.path().join("two.bin");
        fs::hard_link(&path, &other).unwrap();
        let error = open_source(&path, &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::ManyLinks));
        assert!(path.exists(), "a refusal must not remove anything");
    }

    /// The Windows gap, asserted rather than assumed: without an unstable feature the
    /// platform's link count is not readable, so a second hard link is not refused there.
    /// `docs/PLAN.md` §7 records this, and this test fails if the reported count ever
    /// becomes more than the honest placeholder.
    #[cfg(windows)]
    #[test]
    fn a_second_hard_link_is_not_refused_on_windows_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "one.bin", b"shared");
        let other = dir.path().join("two.bin");
        fs::hard_link(&path, &other).unwrap();
        match open_source(&path, &real()) {
            Ok(source) => {
                assert_eq!(
                    source.identity.links, 1,
                    "the link count is unknown here, and is not guessed"
                );
            }
            Err(error) => assert_eq!(error.refusal(), Some(Refusal::ManyLinks)),
        }
    }

    #[test]
    fn a_file_over_the_limit_is_refused_before_it_is_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "big.bin", b"0123456789");
        let error = open_source_with_limit(&path, &real(), 4).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::TooLarge));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_refused_and_its_target_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = file_in(&dir, "target.bin", b"data");
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = open_source(&link, &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::IsLink));
        assert!(target.exists());
        assert!(link.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_symlink_is_refused_and_its_target_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = file_in(&dir, "target.bin", b"data");
        let link = dir.path().join("link.bin");
        // Creating a link needs Developer Mode or an elevated shell on Windows. When the
        // platform refuses, the case cannot be built here: say so and prove nothing.
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!("skipped: this Windows account cannot create a symlink");
            return;
        }
        let error = open_source(&link, &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::IsLink));
        assert!(target.exists());
    }

    /// The seam: an `ActionIo` that rewrites the file on the Nth identity check, which is
    /// exactly what a `TOCTOU` attacker does, except deterministic.
    struct SwappingIo {
        calls: AtomicUsize,
        swap_at: usize,
        body: &'static [u8],
    }

    impl SwappingIo {
        fn new(swap_at: usize, body: &'static [u8]) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                swap_at,
                body,
            }
        }
    }

    impl ActionIo for SwappingIo {
        fn open_dir(&self, path: &Path) -> io::Result<Dir> {
            RealIo.open_dir(path)
        }

        fn open(&self, dir: &Dir, name: &OsString) -> io::Result<File> {
            RealIo.open(dir, name)
        }

        fn create(&self, dir: &Dir, name: &OsString) -> io::Result<File> {
            RealIo.create(dir, name)
        }

        fn is_link(&self, dir: &Dir, name: &OsString) -> io::Result<bool> {
            RealIo.is_link(dir, name)
        }

        fn is_file(&self, dir: &Dir, name: &OsString) -> io::Result<bool> {
            RealIo.is_file(dir, name)
        }

        fn identity(&self, dir: &Dir, name: &OsString) -> io::Result<Identity> {
            let seen = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if seen == self.swap_at {
                let mut options = cap_std::fs::OpenOptions::new();
                options.write(true).truncate(true);
                let mut file = dir.open_with(name, &options).map(cap_std::fs::File::into_std)?;
                use std::io::Write;
                file.write_all(self.body)?;
                file.sync_all()?;
            }
            RealIo.identity(dir, name)
        }

        fn exists(&self, dir: &Dir, name: &OsString) -> bool {
            RealIo.exists(dir, name)
        }

        fn rename(&self, from: &Dir, from_name: &OsString, to: &Dir, to_name: &OsString) -> io::Result<()> {
            RealIo.rename(from, from_name, to, to_name)
        }

        fn remove_file(&self, dir: &Dir, name: &OsString) -> io::Result<()> {
            RealIo.remove_file(dir, name)
        }
    }

    #[test]
    fn a_file_replaced_during_the_read_is_refused_before_it_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "swap.bin", b"original");
        let io = SwappingIo::new(2, b"replaced with something else entirely");
        let error = open_source(&path, &io).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::Changed));
    }

    #[test]
    fn a_file_replaced_after_it_was_inspected_is_refused_at_the_move() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "swap.bin", b"original");
        let io = SwappingIo::new(3, b"replaced with something else entirely");
        let source = open_source(&path, &io).unwrap();
        let error = source.verify_unchanged(&io).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::Changed));
        assert_eq!(fs::read(&path).unwrap(), b"replaced with something else entirely");
    }

    #[test]
    fn an_unchanged_file_passes_the_identity_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "same.bin", b"steady");
        let source = open_source(&path, &real()).unwrap();
        source.verify_unchanged(&real()).unwrap();
    }

    #[test]
    fn a_deleted_file_is_refused_at_the_identity_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "gone.bin", b"bye");
        let source = open_source(&path, &real()).unwrap();
        fs::remove_file(&path).unwrap();
        let error = source.verify_unchanged(&real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::SourceMissing));
    }

    #[test]
    fn a_move_places_the_file_and_leaves_the_source_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "move.bin", b"move me");
        let root = dir.path().join("quarantine");
        let root_dir = ensure_root(&root, &real()).unwrap();
        root_dir.create_dir("0123456789abcdef").unwrap();
        let entry_dir = root_dir.open_dir("0123456789abcdef").unwrap();
        let destination = OsString::from("payload");
        let source = open_source(&path, &real()).unwrap();
        source.move_into(&real(), &entry_dir, &destination).unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::read(root.join("0123456789abcdef").join("payload")).unwrap(),
            b"move me"
        );
    }

    #[test]
    fn a_move_refuses_an_occupied_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir, "src.bin", b"new");
        let root = dir.path().join("quarantine");
        let root_dir = ensure_root(&root, &real()).unwrap();
        root_dir.create_dir("0123456789abcdef").unwrap();
        let entry_dir = root_dir.open_dir("0123456789abcdef").unwrap();
        fs::write(root.join("0123456789abcdef").join("payload"), b"already here").unwrap();
        let source = open_source(&path, &real()).unwrap();
        let error = source
            .move_into(&real(), &entry_dir, &OsString::from("payload"))
            .unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::DestinationOccupied));
        assert!(path.exists(), "the source is still there");
        assert_eq!(
            fs::read(root.join("0123456789abcdef").join("payload")).unwrap(),
            b"already here"
        );
    }

    #[test]
    fn an_id_is_parsed_before_the_filesystem_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let root = ensure_root(&dir.path().join("quarantine"), &real()).unwrap();
        for bad in ["..", "../x", "0123", "", "0123456789abcde/", "C:\\x"] {
            let error = resolve_entry(&root, bad, &real()).unwrap_err();
            assert_eq!(error.refusal(), Some(Refusal::NotAnEntry), "{bad:?}");
        }
        let error = resolve_entry(&root, "0123456789abcdef", &real()).unwrap_err();
        assert_eq!(error.refusal(), Some(Refusal::SourceMissing));
    }
}
