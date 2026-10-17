//! Journaled acts: the intent line, the act, the result line.
//!
//! This is the only path from "a person asked" to "a file moved". It exists so that the
//! order in `docs/PLAN.md` §6.10 cannot be got wrong by a caller in a hurry:
//!
//! 1. derive an act id,
//! 2. append the intent and sync it — if that fails, the act is **not attempted**,
//! 3. act,
//! 4. append the result with the same id.
//!
//! The act id is not the quarantine entry id. The entry id is derived inside the act from
//! the bytes, so it cannot exist before the act does; the act id exists only to pair two
//! journal lines, and the entry id travels in the result's subject.

use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};
use vnr_core::action::Surface;
use vnr_core::journal::{Action, Confirmation, Draft, JournalEntry, Outcome};

use crate::action::{ActionError, ActionIo};
use crate::clean::{self, Item, Removal};
use crate::journal::Journal;
use crate::quarantine::{self, Manifest, Purged, Quarantined, Restored};

/// What went wrong with a journaled act.
#[derive(Debug)]
pub enum ActError {
    /// The intent could not be recorded, so nothing was attempted.
    Unrecorded(std::io::Error),
    /// The act itself was refused or failed. Its result is in the journal.
    Act(ActionError),
}

impl fmt::Display for ActError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unrecorded(error) => write!(
                formatter,
                "The action was not attempted, because it could not be recorded first: {error}"
            ),
            Self::Act(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ActError {}

/// Take a file into the quarantine in the platform data directory.
pub fn quarantine(
    journal: &mut Journal,
    path: &Path,
    reason: &str,
    io: &dyn ActionIo,
) -> std::result::Result<Quarantined, ActError> {
    quarantine_in(journal, &crate::paths::quarantine_dir(), path, reason, io)
}

/// Take a file into the quarantine under a chosen root, with both journal lines.
pub fn quarantine_in(
    journal: &mut Journal,
    root: &Path,
    path: &Path,
    reason: &str,
    io: &dyn ActionIo,
) -> std::result::Result<Quarantined, ActError> {
    let act_id = next_act_id();
    record(
        journal,
        Draft::intent(Action::Quarantine)
            .with_id(&act_id)
            .with_path(&path.display().to_string())
            .with_reason(reason)
            .with_confirmation(Confirmation::Preview),
    )?;

    match quarantine::take(root, path, reason, crate::now_unix(), io) {
        Ok(taken) => {
            journal_ok(
                journal,
                &act_id,
                Action::Quarantine,
                &taken.id.to_hex(),
                Some(&taken.manifest),
            );
            Ok(taken)
        }
        Err(error) => {
            journal_failure(journal, &act_id, Action::Quarantine, &error, path, None);
            Err(ActError::Act(error))
        }
    }
}

/// Put a quarantined file back, with both journal lines.
pub fn restore(
    journal: &mut Journal,
    entry_id: &str,
    io: &dyn ActionIo,
) -> std::result::Result<Restored, ActError> {
    restore_in(journal, &crate::paths::quarantine_dir(), entry_id, io)
}

/// Restore an entry under a chosen root.
pub fn restore_in(
    journal: &mut Journal,
    root: &Path,
    entry_id: &str,
    io: &dyn ActionIo,
) -> std::result::Result<Restored, ActError> {
    let act_id = next_act_id();
    record(
        journal,
        Draft::intent(Action::Restore)
            .with_id(&act_id)
            .with_subject(entry_id)
            .with_confirmation(Confirmation::Restore),
    )?;

    match quarantine::restore_at(root, entry_id, io) {
        Ok(restored) => {
            journal_ok(
                journal,
                &act_id,
                Action::Restore,
                entry_id,
                Some(&restored.manifest),
            );
            Ok(restored)
        }
        Err(error) => {
            journal_failure(
                journal,
                &act_id,
                Action::Restore,
                &error,
                Path::new(""),
                Some(entry_id),
            );
            Err(ActError::Act(error))
        }
    }
}

/// Delete a quarantined entry for good, with both journal lines.
///
/// `confirmation` is passed in rather than assumed, so the journal records what the person
/// actually gave: the interface asks for `DELETE` to be typed, and the record is only worth
/// as much as the honesty of that call.
pub fn purge(
    journal: &mut Journal,
    entry_id: &str,
    confirmation: Confirmation,
    io: &dyn ActionIo,
) -> std::result::Result<Purged, ActError> {
    purge_in(
        journal,
        &crate::paths::quarantine_dir(),
        entry_id,
        confirmation,
        io,
    )
}

/// Purge an entry under a chosen root.
pub fn purge_in(
    journal: &mut Journal,
    root: &Path,
    entry_id: &str,
    confirmation: Confirmation,
    io: &dyn ActionIo,
) -> std::result::Result<Purged, ActError> {
    let act_id = next_act_id();
    record(
        journal,
        Draft::intent(Action::Purge)
            .with_id(&act_id)
            .with_subject(entry_id)
            .with_confirmation(confirmation),
    )?;

    match quarantine::purge_at(root, entry_id, io) {
        Ok(purged) => {
            journal_ok(journal, &act_id, Action::Purge, entry_id, Some(&purged.manifest));
            Ok(purged)
        }
        Err(error) => {
            journal_failure(
                journal,
                &act_id,
                Action::Purge,
                &error,
                Path::new(""),
                Some(entry_id),
            );
            Err(ActError::Act(error))
        }
    }
}

/// Write the intent, syncing it. If this fails the act must not happen.
fn record(journal: &mut Journal, draft: Draft) -> std::result::Result<JournalEntry, ActError> {
    journal.record_synced(draft).map_err(ActError::Unrecorded)
}

/// Remove the items a person selected from an allowlisted surface, with both journal lines.
///
/// The preview has already happened: the items carry what was shown, and the removal
/// re-checks each one. A surface with nothing selected is not an act and is not journalled,
/// because a record of "removed nothing" is noise in the one file that has to stay
/// readable.
pub fn clean(
    journal: &mut Journal,
    surface: Surface,
    items: &[Item],
    now_unix: u64,
    cancel: &dyn Fn() -> bool,
) -> std::result::Result<Removal, ActError> {
    if items.is_empty() {
        return Ok(Removal::default());
    }
    let bytes: u64 = items.iter().map(|item| item.bytes).sum();
    let act_id = next_act_id();
    record(
        journal,
        Draft::intent(Action::Clean)
            .with_id(&act_id)
            .with_subject(surface.id())
            .with_size(bytes)
            .with_reason(&format!(
                "{} entries, {} bytes, from {}",
                items.len(),
                bytes,
                surface.label()
            ))
            .with_confirmation(Confirmation::Clean),
    )?;

    let removal = clean::remove_surface(surface, items, now_unix, cancel);
    let outcome = if removal.failed.is_empty() {
        Outcome::Ok
    } else {
        Outcome::Failed
    };
    let reason = format!(
        "{} removed, {} bytes, {} skipped, {} refused",
        removal.removed,
        removal.bytes,
        removal.skipped,
        removal.failed.len()
    );
    let draft = Draft::result(Action::Clean, outcome)
        .with_id(&act_id)
        .with_subject(surface.id())
        .with_size(removal.bytes)
        .with_reason(&reason);
    if let Err(error) = journal.record_synced(draft) {
        log::warn!("the result of a clean could not be recorded: {error}");
    }
    Ok(removal)
}

/// Whether a clean would remove anything at all, for a caller that wants to ask first.
#[must_use]
pub fn clean_preview(surface: Surface, now_unix: u64, cancel: &dyn Fn() -> bool) -> clean::Preview {
    clean::preview(surface, now_unix, cancel)
}

fn journal_ok(
    journal: &mut Journal,
    act_id: &str,
    action: Action,
    subject: &str,
    manifest: Option<&Manifest>,
) {
    let mut draft = Draft::result(action, Outcome::Ok)
        .with_id(act_id)
        .with_subject(subject);
    if let Some(manifest) = manifest {
        draft = draft
            .with_path(&manifest.original_path)
            .with_hash(&manifest.sha256)
            .with_size(manifest.size);
    }
    // Synced as well: a pair that is half on disk is a puzzle, and the puzzle is what the
    // recovery verdict has to solve.
    if let Err(error) = journal.record_synced(draft) {
        log::warn!("the result of an action could not be recorded: {error}");
    }
}

fn journal_failure(
    journal: &mut Journal,
    act_id: &str,
    action: Action,
    error: &ActionError,
    path: &Path,
    subject: Option<&str>,
) {
    let outcome = if error.refusal().is_some() {
        Outcome::Refused
    } else {
        Outcome::Failed
    };
    let mut draft = Draft::result(action, outcome)
        .with_id(act_id)
        .with_reason(&error.to_string());
    if !path.as_os_str().is_empty() {
        draft = draft.with_path(&path.display().to_string());
    }
    if let Some(subject) = subject {
        draft = draft.with_subject(subject);
    }
    if let Err(write) = journal.record_synced(draft) {
        log::warn!("the failure of an action could not be recorded: {write}");
    }
}

/// Sixteen hex characters that pair one intent with one result.
///
/// Derived from the clock, the process and a counter, so two acts in one second are two
/// ids. It is not a capability and nothing is resolved from it: the entry id is the only
/// id the filesystem ever sees.
fn next_act_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(crate::now_unix().to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hex::encode(&hasher.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::RealIo;
    use vnr_core::JournalKind;

    fn real() -> RealIo {
        RealIo
    }

    struct Bed {
        dir: tempfile::TempDir,
        journal: Journal,
        root: std::path::PathBuf,
    }

    impl Bed {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let journal = Journal::open_at(dir.path().join("journal.ndjson")).unwrap();
            let root = dir.path().join("quarantine");
            Self { dir, journal, root }
        }

        fn file(&self, name: &str, body: &[u8]) -> std::path::PathBuf {
            let path = self.dir.path().join(name);
            std::fs::write(&path, body).unwrap();
            path
        }

        fn entries(&self) -> Vec<JournalEntry> {
            self.journal.read().entries
        }

        fn pair(&self) -> (JournalEntry, JournalEntry) {
            let entries = self.entries();
            let intent = entries
                .iter()
                .find(|entry| entry.kind == JournalKind::Intent)
                .cloned()
                .expect("an intent was written");
            let result = entries
                .iter()
                .find(|entry| entry.kind == JournalKind::Result)
                .cloned()
                .expect("a result was written");
            (intent, result)
        }
    }

    #[test]
    fn a_quarantine_writes_the_intent_first_and_the_result_after() {
        let mut bed = Bed::new();
        let path = bed.file("target.bin", b"take me");
        let taken = quarantine_in(&mut bed.journal, &bed.root, &path, "a rule fired", &real()).unwrap();

        let (intent, result) = bed.pair();
        assert_eq!(intent.seq, 1, "the intent comes first");
        assert_eq!(intent.action, Some(Action::Quarantine));
        assert_eq!(intent.path.as_deref(), Some(path.display().to_string().as_str()));
        assert_eq!(intent.confirmation, Some(Confirmation::Preview));
        assert_eq!(intent.subject, None, "the entry id cannot exist before the act");

        assert_eq!(result.seq, 2);
        assert_eq!(result.id, intent.id, "the pair shares an act id");
        assert_eq!(result.outcome, Some(Outcome::Ok));
        assert_eq!(result.subject, Some(taken.id.to_hex()));
        assert_eq!(result.hash.as_deref(), Some(taken.manifest.sha256.as_str()));
        assert_eq!(result.size, Some(taken.manifest.size));

        assert!(!path.exists(), "the file moved");
    }

    #[test]
    fn a_restore_writes_both_lines_and_puts_the_bytes_back() {
        let mut bed = Bed::new();
        let path = bed.file("back.bin", b"round trip");
        let taken = quarantine_in(&mut bed.journal, &bed.root, &path, "test", &real()).unwrap();
        let first_id = taken.id.to_hex();

        restore_in(&mut bed.journal, &bed.root, &first_id, &real()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"round trip");

        let entries = bed.entries();
        let restores: Vec<&JournalEntry> = entries
            .iter()
            .filter(|entry| entry.action == Some(Action::Restore))
            .collect();
        assert_eq!(restores.len(), 2, "one intent and one result");
        assert_eq!(restores[0].kind, JournalKind::Intent);
        assert_eq!(restores[1].kind, JournalKind::Result);
        assert_eq!(restores[1].subject.as_deref(), Some(first_id.as_str()));
    }

    #[test]
    fn a_purge_records_the_confirmation_it_was_given() {
        let mut bed = Bed::new();
        let path = bed.file("delete.bin", b"gone");
        let taken = quarantine_in(&mut bed.journal, &bed.root, &path, "test", &real()).unwrap();
        purge_in(
            &mut bed.journal,
            &bed.root,
            &taken.id.to_hex(),
            Confirmation::Typed,
            &real(),
        )
        .unwrap();

        let entries = bed.entries();
        let intent = entries
            .iter()
            .find(|entry| entry.action == Some(Action::Purge) && entry.kind == JournalKind::Intent)
            .expect("the purge intent");
        assert_eq!(intent.confirmation, Some(Confirmation::Typed));
        assert_eq!(intent.subject.as_deref(), Some(taken.id.to_hex().as_str()));
    }

    #[test]
    fn a_refused_act_still_leaves_a_result_that_says_so() {
        let mut bed = Bed::new();
        let missing = bed.dir.path().join("not-here.bin");
        let error = quarantine_in(&mut bed.journal, &bed.root, &missing, "test", &real()).unwrap_err();
        assert!(matches!(error, ActError::Act(_)));

        let (intent, result) = bed.pair();
        assert_eq!(intent.action, Some(Action::Quarantine));
        assert_eq!(result.outcome, Some(Outcome::Refused));
        assert!(
            result.reason.as_deref().is_some_and(|reason| !reason.is_empty()),
            "a refusal says why"
        );
        assert_eq!(result.id, intent.id);
    }

    #[test]
    fn an_unrecordable_journal_refuses_before_anything_moves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kept.bin");
        std::fs::write(&path, b"keep me").unwrap();
        let mut journal = Journal::unavailable(dir.path().join("no-journal.ndjson"), "disk full");
        let root = dir.path().join("quarantine");

        let error = quarantine_in(&mut journal, &root, &path, "test", &real()).unwrap_err();
        assert!(matches!(error, ActError::Unrecorded(_)));
        assert!(path.exists(), "an unrecorded act must not happen");
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
        assert!(!root.exists(), "the quarantine root was not even created");
    }

    #[test]
    fn every_act_pairs_its_lines_with_a_fresh_id() {
        let mut bed = Bed::new();
        let first = bed.file("one.bin", b"one");
        let second = bed.file("two.bin", b"two");
        quarantine_in(&mut bed.journal, &bed.root, &first, "test", &real()).unwrap();
        quarantine_in(&mut bed.journal, &bed.root, &second, "test", &real()).unwrap();

        let ids: Vec<String> = bed.entries().into_iter().filter_map(|entry| entry.id).collect();
        assert_eq!(ids.len(), 4, "two intents and two results");
        assert_eq!(ids[0], ids[1]);
        assert_eq!(ids[2], ids[3]);
        assert_ne!(ids[0], ids[2], "two acts, two ids");
    }

    #[test]
    fn a_clean_journals_what_it_removed_under_the_surface_it_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open_at(dir.path().join("journal.ndjson")).unwrap();
        let path = dir.path().join("old.tmp");
        std::fs::write(&path, b"1234").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        drop(file);
        let now = 1_000 + 48 * 60 * 60;

        // The item is the one this test made, so the removal is asked for it specifically
        // rather than for everything the machine's real temp directory holds.
        let items = vec![Item {
            path,
            bytes: 4,
            modified_unix: 1_000,
            is_dir: false,
        }];
        let removal = clean(&mut journal, Surface::WinTemp, &items, now, &|| false).unwrap();
        assert_eq!(removal.removed, 1);
        assert_eq!(removal.bytes, 4);

        let entries = journal.read().entries;
        let intent = entries
            .iter()
            .find(|entry| entry.kind == JournalKind::Intent)
            .expect("an intent");
        assert_eq!(intent.action, Some(Action::Clean));
        assert_eq!(intent.subject.as_deref(), Some(Surface::WinTemp.id()));
        assert_eq!(intent.confirmation, Some(Confirmation::Clean));
        let result = entries
            .iter()
            .find(|entry| entry.kind == JournalKind::Result)
            .expect("a result");
        assert_eq!(result.outcome, Some(Outcome::Ok));
        assert_eq!(result.id, intent.id);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("1 removed")),
            "the result says what happened: {:?}",
            result.reason
        );
    }

    #[test]
    fn a_clean_with_nothing_selected_is_not_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::open_at(dir.path().join("journal.ndjson")).unwrap();
        let removal = clean(&mut journal, Surface::WinTemp, &[], 5, &|| false).unwrap();
        assert_eq!(removal.removed, 0);
        assert!(
            journal.read().entries.is_empty(),
            "a record of removing nothing is noise in the one file that must stay readable"
        );
    }

    #[test]
    fn a_dry_run_writes_no_journal_and_removes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open_at(dir.path().join("journal.ndjson")).unwrap();
        let path = dir.path().join("old.tmp");
        std::fs::write(&path, b"still here").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        file.set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        drop(file);
        let now = 1_000 + 48 * 60 * 60;

        let preview = clean::preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now, &|| false);
        assert_eq!(preview.items.len(), 1, "the walk offers the old file");
        assert!(path.exists(), "and leaves it where it is");
        assert_eq!(std::fs::read(&path).unwrap(), b"still here");
        assert!(
            journal.read().entries.is_empty(),
            "a dry run is not an act, so it is not a record"
        );
    }

    #[test]
    fn an_act_id_is_sixteen_hex_and_two_acts_differ() {
        let first = next_act_id();
        let second = next_act_id();
        assert_eq!(first.len(), 16);
        assert!(first.chars().all(|character| character.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
