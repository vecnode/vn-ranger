//! The journal writer: the one place that appends to `journal.ndjson`.
//!
//! One process writes it — the single window the instance guard allows — and one thread
//! owns that writer, so a sequence number is assigned once and never contested. The
//! record types and the reader are in `vnr_core::journal`; this module owns the file, the
//! clock and the `sync_data` that makes "recorded before it happened" true.
//!
//! An `intent` and its `result` are synced. Everything else — an observed event, a
//! finding, an error — is written but not synced, because losing the last observed event
//! to a power cut is acceptable and waiting for a disk on every process poll is not.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use vnr_core::journal::{self, Draft, ENTRIES_PER_FILE, JournalEntry, KEEP_SECONDS, Read as JournalRead};

/// Where the journal lives, and what state the writer is in.
pub struct Journal {
    path: PathBuf,
    inner: Option<Open>,
    /// Why the journal is unusable, when it is. Kept so the sentence the interface shows
    /// names the cause rather than "an error".
    blocked: Option<String>,
}

struct Open {
    file: File,
    seq: u64,
    lines: u64,
    first_seq: u64,
    /// How many lines this process has written, across rotations. The soak reads it, so it
    /// is a fact about the writer rather than an estimate from the file's size.
    written: u64,
}

impl Journal {
    /// Open the journal in the platform data directory.
    pub fn open() -> io::Result<Self> {
        Self::open_at(crate::paths::journal_path())
    }

    /// Open the journal at a chosen path. The caller owns creating the parent directory;
    /// this does it too, because a first launch has no data directory yet.
    ///
    /// A refusal is diagnosed before it is reported. "Access is denied" is three different
    /// problems — this program may not write in that folder, the file itself may not be
    /// opened, or another handle may be holding it — and only one of them is something a
    /// person can fix, so the sentence says which one it is (`docs/PLAN.md` §6.10).
    pub fn open_at(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            crate::paths::ensure_dir(parent).map_err(|error| diagnose(parent, error))?;
        }
        // Read bytes rather than text: a torn tail can split a multi-byte character, and
        // a lossy read that counts one corrupt line beats refusing to open the journal.
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(diagnose(&path, error)),
        };
        let mut file = match open_for_append(&path) {
            Ok(file) => file,
            // The file exists and cannot be opened. If this program can write in the folder,
            // the file is the problem — a stale handle, an attribute, an ACL somebody set —
            // and moving it aside is what turns a lost session back into a recorded one.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied && path.exists() => {
                match set_aside(&path) {
                    Some(kept) => match open_for_append(&path) {
                        Ok(file) => {
                            log::warn!(
                                "the journal could not be opened, so it was kept as {} and a new one started",
                                kept.display()
                            );
                            file
                        }
                        Err(error) => return Err(diagnose(&path, error)),
                    },
                    None => return Err(diagnose(&path, error)),
                }
            }
            Err(error) => return Err(diagnose(&path, error)),
        };
        let existing = journal::parse(&String::from_utf8_lossy(&bytes));
        let seq = existing.last_seq();
        let lines = u64::try_from(existing.entries.len()).unwrap_or(u64::MAX);
        let first_seq = existing.entries.first().map_or(0, |entry| entry.seq);
        // A crash can leave the last line without its newline. Appending straight onto
        // it would swallow the next entry into the damaged line, so the tail is closed
        // first: it becomes one corrupt line in the middle of the file, which the reader
        // reports, instead of a growing one.
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            file.write_all(b"\n")?;
        }
        Ok(Self {
            path,
            inner: Some(Open {
                file,
                seq,
                lines,
                first_seq,
                written: 0,
            }),
            blocked: None,
        })
    }

    /// A journal that cannot write, because opening it failed. Every record reports why.
    #[must_use]
    pub fn unavailable(path: PathBuf, reason: &str) -> Self {
        Self {
            path,
            inner: None,
            blocked: Some(reason.to_owned()),
        }
    }

    /// Where the active file is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Why the journal cannot be written, when it cannot.
    #[must_use]
    pub fn blocked(&self) -> Option<&str> {
        self.blocked.as_deref()
    }

    /// Append an entry without syncing. For observations, which are cheap and frequent.
    pub fn record(&mut self, draft: Draft) -> io::Result<JournalEntry> {
        self.append(draft, false)
    }

    /// Append an entry and sync it. For an intent or a result, which must survive.
    pub fn record_synced(&mut self, draft: Draft) -> io::Result<JournalEntry> {
        self.append(draft, true)
    }

    /// How many lines this process has written, across rotations.
    ///
    /// A fact about the writer rather than an estimate from the file: the soak publishes it
    /// next to the CPU it cost, and a number guessed from a file's size would be a lie that
    /// looks like a measurement.
    #[must_use]
    pub fn writes(&self) -> u64 {
        self.inner.as_ref().map_or(0, |open| open.written)
    }

    fn append(&mut self, draft: Draft, synced: bool) -> io::Result<JournalEntry> {
        let seq = match self.inner.as_ref() {
            Some(open) => open.seq.saturating_add(1),
            None => {
                return Err(io::Error::other(
                    self.blocked
                        .clone()
                        .unwrap_or_else(|| "the journal is unavailable".to_owned()),
                ));
            }
        };
        let entry = draft.seal(seq, now_unix());
        let mut line = entry
            .to_line()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        line.push('\n');
        let written = match self.inner.as_mut() {
            Some(open) => {
                let result = open
                    .file
                    .write_all(line.as_bytes())
                    .and_then(|()| if synced { open.file.sync_data() } else { Ok(()) });
                if result.is_ok() {
                    open.seq = entry.seq;
                    open.lines = open.lines.saturating_add(1);
                    open.written = open.written.saturating_add(1);
                    if open.first_seq == 0 {
                        open.first_seq = entry.seq;
                    }
                }
                result
            }
            None => Err(io::Error::other("the journal is unavailable")),
        };
        match written {
            Ok(()) => Ok(entry),
            Err(error) => {
                // A partial line is worse than no line: the next append would land inside
                // it. Stop writing rather than corrupt the record that explains the
                // failure.
                self.blocked = Some(format!("the journal could not be written: {error}"));
                self.inner = None;
                Err(error)
            }
        }
    }

    /// Roll the active file over when it holds enough entries.
    ///
    /// The new file starts at the next sequence number, so the journal's order survives
    /// the split and a reader sorts the files by the number in their name.
    pub fn rotate_if_needed(&mut self) -> io::Result<bool> {
        let (lines, first_seq, seq, written) = match self.inner.as_ref() {
            Some(open) => (open.lines, open.first_seq, open.seq, open.written),
            None => return Ok(false),
        };
        if lines < ENTRIES_PER_FILE || first_seq == 0 {
            return Ok(false);
        }
        let rotated = self.path.with_file_name(journal::rotated_name(first_seq));
        self.inner = None;
        std::fs::rename(&self.path, &rotated)?;
        let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.inner = Some(Open {
            file,
            seq,
            lines: 0,
            first_seq: 0,
            written,
        });
        Ok(true)
    }

    /// Delete rotated files older than the retention window, and say how many went.
    pub fn prune(&mut self, now: u64) -> io::Result<usize> {
        let Some(parent) = self.path.parent() else {
            return Ok(0);
        };
        let Ok(entries) = std::fs::read_dir(parent) else {
            return Ok(0);
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if journal::parse_rotated_name(name).is_none() {
                continue;
            }
            let path = entry.path();
            let Ok(metadata) = path.metadata() else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            let at = modified
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            if now.saturating_sub(at) > KEEP_SECONDS && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Read every journal file, oldest first, as one record.
    #[must_use]
    pub fn read(&self) -> JournalRead {
        let mut combined = JournalRead::default();
        let Some(parent) = self.path.parent() else {
            return combined;
        };
        let mut rotated: Vec<(u64, PathBuf)> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if let Some(first) = journal::parse_rotated_name(name) {
                    rotated.push((first, entry.path()));
                }
            }
        }
        rotated.sort_by_key(|(first, _)| *first);
        for (_, path) in rotated {
            merge(&mut combined, &path);
        }
        merge(&mut combined, &self.path);
        combined
    }
}

/// Open the journal for appending, retrying a transient sharing denial.
///
/// A file created a moment ago can be held briefly by a scanner or an indexer on Windows,
/// and the atomic save already retries for the same reason. A journal that refuses to open
/// leaves the whole session unrecorded, so the retry is worth more here than anywhere else.
fn open_for_append(path: &Path) -> io::Result<File> {
    let mut attempt = 0_u32;
    loop {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => return Ok(file),
            Err(error) => {
                let transient = error.kind() == io::ErrorKind::PermissionDenied
                    || matches!(error.raw_os_error(), Some(5) | Some(32));
                if attempt >= 3 || !transient {
                    return Err(error);
                }
                attempt = attempt.saturating_add(1);
                std::thread::sleep(std::time::Duration::from_millis(60 * u64::from(attempt)));
            }
        }
    }
}

/// Whether this process can create a file in a folder at all.
///
/// The probe is what makes the refusal actionable: "access is denied" on the journal means
/// one thing when the folder is writable and another when it is not, and a person can only
/// act on the second one. It writes one empty file with a name of its own and removes it.
#[must_use]
pub fn folder_is_writable(folder: &Path) -> bool {
    let probe = folder.join(format!(".vn-ranger-write-probe-{}", std::process::id()));
    let writable = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    writable
}

/// Turn a refusal into a sentence that names which of the three problems it is.
///
/// The three are: this program may not write in the folder; the file itself may not be
/// opened; and everything else, which is reported as it came.
fn diagnose(path: &Path, error: io::Error) -> io::Error {
    if error.kind() != io::ErrorKind::PermissionDenied && error.raw_os_error() != Some(5) {
        return error;
    }
    let folder = path.parent().unwrap_or_else(|| Path::new("."));
    let subject = path.display();
    if !folder_is_writable(folder) {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{error} at {subject}: ranger could not create a test file in {} either, so this \
                 program is not allowed to write in that folder. A security program, a folder \
                 policy, or a sandbox around the process all look like this. VN_RANGER_DATA_DIR \
                 points ranger at a folder it may write to.",
                folder.display()
            ),
        );
    }
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{error} at {subject}: other files in {} can be written, so the journal file itself \
             is the problem — another program holding it open, or an attribute or permission \
             ranger cannot change. Nothing is recorded until it can be moved.",
            folder.display()
        ),
    )
}

/// Move an unopenable journal out of the way, so the next attempt starts a fresh one.
///
/// The old file is kept rather than deleted: it may be the only record of what happened
/// before the refusal, and a person can read it later even if ranger could not.
fn set_aside(path: &Path) -> Option<PathBuf> {
    let at = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let kept = path.with_file_name(format!("journal.kept-{at}.ndjson"));
    std::fs::rename(path, &kept).ok().map(|()| kept)
}

/// What an attempt to open the journal would find, as facts rather than as an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnosis {
    /// The journal file.
    pub path: PathBuf,
    /// The folder it lives in.
    pub folder: PathBuf,
    /// Whether the folder exists.
    pub folder_exists: bool,
    /// Whether this process can create a file in the folder.
    pub folder_writable: bool,
    /// Whether the journal file exists, and how large it is.
    pub file: Option<u64>,
    /// What opening it for append said, when it was tried.
    pub opens: Option<String>,
}

impl Diagnosis {
    /// One line per fact, for a person reading a terminal.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("journal: {}", self.path.display()));
        lines.push(format!(
            "folder:  {} ({}, {})",
            self.folder.display(),
            if self.folder_exists { "exists" } else { "missing" },
            if self.folder_writable {
                "writable by this program"
            } else {
                "NOT writable by this program"
            }
        ));
        match self.file {
            Some(bytes) => lines.push(format!("file:    present, {bytes} bytes")),
            None => lines.push("file:    not created yet".to_owned()),
        }
        if let Some(opens) = &self.opens {
            lines.push(format!("open:    {opens}"));
        }
        lines
    }
}

/// Look at the journal without changing it.
///
/// Opening an existing file for append opens a handle and writes nothing. When the file is
/// not there, the append is asked for *without* `create`, so a diagnosis never brings a
/// journal into existence — the answer "not created yet" is itself a fact worth having.
#[must_use]
pub fn diagnose_folder(path: &Path) -> Diagnosis {
    let folder = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let folder_exists = folder.is_dir();
    let file = std::fs::metadata(path).ok().map(|metadata| metadata.len());
    let opens = Some(match OpenOptions::new().append(true).open(path) {
        Ok(_) => "opened for append".to_owned(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            "not there, so nothing could be opened".to_owned()
        }
        Err(error) => format!("{error}"),
    });
    Diagnosis {
        path: path.to_path_buf(),
        folder: folder.clone(),
        folder_exists,
        folder_writable: folder_exists && folder_is_writable(&folder),
        file,
        opens,
    }
}

fn merge(combined: &mut JournalRead, path: &Path) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let read = journal::parse(&String::from_utf8_lossy(&bytes));
    combined.entries.extend(read.entries);
    combined.corrupt.extend(read.corrupt);
    combined.torn_tail |= read.torn_tail;
}

fn now_unix() -> u64 {
    crate::now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::journal::{Action, Confirmation, Outcome};

    fn journal_in(dir: &tempfile::TempDir) -> Journal {
        Journal::open_at(dir.path().join("journal.ndjson")).unwrap()
    }

    #[test]
    fn a_record_is_on_disk_before_the_call_returns() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = journal_in(&dir);
        let entry = journal
            .record_synced(Draft::intent(Action::Quarantine).with_path("C:\\Temp\\x.exe"))
            .unwrap();
        assert_eq!(entry.seq, 1);
        assert!(entry.at > 0);
        let text = std::fs::read_to_string(journal.path()).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.contains("\"kind\":\"intent\""));
    }

    #[test]
    fn sequence_numbers_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut journal = journal_in(&dir);
            journal.record(Draft::event("one")).unwrap();
            journal.record(Draft::event("two")).unwrap();
        }
        let mut journal = journal_in(&dir);
        let third = journal.record(Draft::event("three")).unwrap();
        assert_eq!(third.seq, 3);
    }

    #[test]
    fn an_intent_and_its_result_share_an_id_and_read_back_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = journal_in(&dir);
        let intent = journal
            .record_synced(
                Draft::intent(Action::Quarantine)
                    .with_id("0123456789abcdef")
                    .with_path("C:\\Temp\\x.exe")
                    .with_confirmation(Confirmation::Preview),
            )
            .unwrap();
        journal
            .record_synced(
                Draft::result(Action::Quarantine, Outcome::Ok)
                    .with_id("0123456789abcdef")
                    .with_reason("moved into quarantine"),
            )
            .unwrap();
        let read = journal.read();
        assert_eq!(read.entries.len(), 2);
        assert_eq!(read.entries[0].id, intent.id);
        assert_eq!(read.entries[1].outcome, Some(Outcome::Ok));
        assert!(!read.is_damaged());
    }

    #[test]
    fn rotation_moves_the_file_and_keeps_the_sequence_moving() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = journal_in(&dir);
        for index in 0..ENTRIES_PER_FILE {
            journal.record(Draft::event(&format!("event {index}"))).unwrap();
        }
        assert!(journal.rotate_if_needed().unwrap());
        assert!(!journal.rotate_if_needed().unwrap());
        let rotated = dir.path().join(journal::rotated_name(1));
        assert!(
            rotated.exists(),
            "the rotated file is named for its first sequence"
        );
        let next = journal.record(Draft::event("after rotation")).unwrap();
        assert_eq!(next.seq, ENTRIES_PER_FILE + 1);
        let read = journal.read();
        assert_eq!(read.entries.len(), usize::try_from(ENTRIES_PER_FILE).unwrap() + 1);
        assert_eq!(read.last_seq(), ENTRIES_PER_FILE + 1);
        assert!(!read.is_damaged());
    }

    #[test]
    fn prune_removes_only_old_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = journal_in(&dir);
        journal.record(Draft::event("x")).unwrap();
        let rotated = dir.path().join(journal::rotated_name(1));
        std::fs::write(&rotated, "{}\n").unwrap();
        let keep = dir.path().join("journal-0000000002.ndjson");
        std::fs::write(&keep, "{}\n").unwrap();
        std::fs::write(dir.path().join("settings.json"), "{}").unwrap();

        // Nothing is old yet.
        assert_eq!(journal.prune(now_unix()).unwrap(), 0);
        // A clock far ahead ages both rotated files, and only them.
        let future = now_unix() + KEEP_SECONDS + 60;
        assert_eq!(journal.prune(future).unwrap(), 2);
        assert!(!rotated.exists());
        assert!(!keep.exists());
        assert!(journal.path().exists());
        assert!(dir.path().join("settings.json").exists());
    }

    #[test]
    fn an_unavailable_journal_refuses_every_record_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::unavailable(dir.path().join("nope.ndjson"), "disk full");
        assert_eq!(journal.blocked(), Some("disk full"));
        let error = journal.record(Draft::event("x")).unwrap_err();
        assert!(error.to_string().contains("disk full"));
    }

    #[test]
    fn a_refusal_says_whether_the_folder_or_the_file_is_the_problem() {
        let dir = tempfile::tempdir().unwrap();
        let denied = || io::Error::from_raw_os_error(5);
        // A writable folder: the file is the problem, and the sentence says so.
        let writable = diagnose(&dir.path().join("journal.ndjson"), denied()).to_string();
        assert!(
            writable.contains("the journal file itself is the problem"),
            "{writable}"
        );
        assert!(writable.contains("Nothing is recorded"), "{writable}");
        // A folder that is not there, so a test file cannot be made in it either.
        let missing = dir.path().join("gone").join("journal.ndjson");
        let refused = diagnose(&missing, denied()).to_string();
        assert!(
            refused.contains("not allowed to write in that folder"),
            "{refused}"
        );
        assert!(refused.contains("VN_RANGER_DATA_DIR"), "{refused}");
        // Anything that is not a refusal is passed through untouched.
        let other = diagnose(&missing, io::Error::from_raw_os_error(32)).to_string();
        assert_eq!(
            other,
            "The process cannot access the file because it is being used by another process. (os error 32)"
        );
    }

    #[test]
    fn the_probe_leaves_no_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        assert!(folder_is_writable(dir.path()));
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert!(entries.is_empty(), "the probe removed its own file");
        assert!(!folder_is_writable(&dir.path().join("gone")));
    }

    #[test]
    fn a_diagnosis_does_not_create_the_journal_it_looks_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        let diagnosis = diagnose_folder(&path);
        assert!(diagnosis.folder_exists);
        assert!(diagnosis.folder_writable);
        assert_eq!(diagnosis.file, None);
        assert!(
            !path.exists(),
            "a diagnosis that created the journal would answer its own question"
        );
        let lines = diagnosis.lines().join("\n");
        assert!(lines.contains("not created yet"), "{lines}");
        assert!(lines.contains("writable by this program"), "{lines}");
    }

    #[test]
    fn a_journal_that_cannot_be_opened_is_kept_aside_rather_than_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        std::fs::write(&path, b"{\"schema\":1}\n").unwrap();
        let kept = set_aside(&path).expect("a writable folder can move a file");
        assert_eq!(std::fs::read(&kept).unwrap(), b"{\"schema\":1}\n");
        assert!(!path.exists(), "the file moved rather than copied");
        assert!(
            kept.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("journal.kept-")
        );
    }

    #[test]
    fn a_journal_with_a_torn_tail_still_opens_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ndjson");
        let mut first = Journal::open_at(path.clone()).unwrap();
        first.record(Draft::event("kept")).unwrap();
        drop(first);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"schema\":1,\"seq\":2,\"at\"");
        std::fs::write(&path, &text).unwrap();

        let mut journal = Journal::open_at(path.clone()).unwrap();
        let entry = journal.record(Draft::event("after the tear")).unwrap();
        assert_eq!(entry.seq, 2, "the torn line did not consume a number");
        let read = journal.read();
        assert_eq!(read.entries.len(), 2);
        assert_eq!(read.entries[0].subject.as_deref(), Some("kept"));
        assert!(read.is_damaged(), "the tear is reported, not hidden");
        assert_eq!(read.corrupt.len(), 1, "the tear is one corrupt line");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("at\"{\"schema\""),
            "the new entry was not appended onto the damaged line"
        );
    }
}
