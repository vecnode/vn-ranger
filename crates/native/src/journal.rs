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
    pub fn open_at(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            crate::paths::ensure_dir(parent)?;
        }
        // Read bytes rather than text: a torn tail can split a multi-byte character, and
        // a lossy read that counts one corrupt line beats refusing to open the journal.
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let existing = journal::parse(&String::from_utf8_lossy(&bytes));
        let seq = existing.last_seq();
        let lines = u64::try_from(existing.entries.len()).unwrap_or(u64::MAX);
        let first_seq = existing.entries.first().map_or(0, |entry| entry.seq);
        let mut file = open_for_append(&path)?;
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
