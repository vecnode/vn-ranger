//! The action journal: a record written before the act it describes.
//!
//! One line, one entry, append-only, because a file that is only ever appended to is the
//! one file a crash cannot rewrite. The record types and the reader live here, where
//! they are pure and have a test beside them; the writer, which syncs to a disk and
//! therefore knows what a disk is, lives in `vnr-native`.
//!
//! Reading is deliberately forgiving and deliberately honest. A crash can tear the last
//! line in half, so a line that does not parse is not an error the reader throws: the
//! complete entries before it are returned, the tear is counted, and the interface can
//! say what happened. Losing a whole journal because its last byte was unlucky would be
//! the opposite of what this file exists for.

use serde::{Deserialize, Serialize};

/// The schema of one journal line.
///
/// It travels on every line rather than in a header, because an append-only file has no
/// place to put a header that a crash cannot separate from its data.
pub const ENTRY_SCHEMA: u32 = 1;

/// Entries one active file holds before it is rolled over.
pub const ENTRIES_PER_FILE: u64 = 10_000;

/// How long a rotated journal file is kept, in seconds.
pub const KEEP_SECONDS: u64 = 90 * 24 * 60 * 60;

/// What one line is for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// An action is about to happen. Written and synced **before** it does.
    Intent,
    /// What became of the intent with the same id.
    Result,
    /// A fact ranger observed: a process, a file event, a startup item.
    #[default]
    Event,
    /// A rule fired.
    Finding,
    /// Something went wrong that is not tied to an action.
    Error,
}

impl Kind {
    /// A one-word label for the interface and the exports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Result => "result",
            Self::Event => "event",
            Self::Finding => "finding",
            Self::Error => "error",
        }
    }
}

/// The named operations a person can ask ranger to perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Move a file into app-managed storage.
    Quarantine,
    /// Put a quarantined file back where it came from.
    Restore,
    /// Delete a quarantined file for good.
    Purge,
    /// Remove files under an allowlisted surface.
    Clean,
    /// A scan, as an action with a start and an end.
    Scan,
    /// Activate, roll back or remove a rule pack.
    Pack,
    /// Enable or disable autostart.
    Autostart,
    /// A change to ranger's own configuration.
    Config,
}

impl Action {
    /// A one-word label for the interface and the exports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::Restore => "restore",
            Self::Purge => "purge",
            Self::Clean => "clean",
            Self::Scan => "scan",
            Self::Pack => "pack",
            Self::Autostart => "autostart",
            Self::Config => "config",
        }
    }

    /// Whether the action removes something. These are the entries the interface
    /// highlights, and the ones a recovery verdict is written for.
    #[must_use]
    pub fn is_destructive(self) -> bool {
        matches!(self, Self::Quarantine | Self::Purge | Self::Clean)
    }
}

/// How an action ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// It happened.
    Ok,
    /// Ranger declined, and said why. Nothing was changed.
    Refused,
    /// It was attempted and failed. The partial state was cleaned up where it could be.
    Failed,
}

/// Which confirmation the person gave, recorded so the journal can prove it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confirmation {
    /// A preview was shown and one click accepted it.
    Preview,
    /// A restore was asked for.
    Restore,
    /// A cleanup was confirmed with its totals on screen.
    Clean,
    /// A word was typed.
    Typed,
    /// Nothing was asked for, because nothing destructive happened.
    None,
}

/// An entry as a caller describes it.
///
/// The writer adds the sequence number and the time, because those are the two fields a
/// caller must not be able to invent: a journal whose order can be chosen by its author
/// is not a record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Draft {
    /// What the line is for.
    pub kind: Kind,
    /// The operation, when the line is about one.
    pub action: Option<Action>,
    /// The entry id an intent and its result share.
    pub id: Option<String>,
    /// A stable subject: a rule and a target, a path, a package name.
    pub subject: Option<String>,
    /// The path the action concerns, as the person would see it.
    pub path: Option<String>,
    /// The file's SHA-256 at the time it was inspected.
    pub hash: Option<String>,
    /// The file's size in bytes.
    pub size: Option<u64>,
    /// What became of the action.
    pub outcome: Option<Outcome>,
    /// Why, in a sentence a person can act on.
    pub reason: Option<String>,
    /// Which confirmation was given.
    pub confirmation: Option<Confirmation>,
}

impl Draft {
    /// A line of the given kind, about nothing in particular yet.
    #[must_use]
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// An intent: the action is about to happen.
    #[must_use]
    pub fn intent(action: Action) -> Self {
        Self::new(Kind::Intent).with_action(action)
    }

    /// A result, which must carry the same id as its intent.
    #[must_use]
    pub fn result(action: Action, outcome: Outcome) -> Self {
        Self::new(Kind::Result).with_action(action).with_outcome(outcome)
    }

    /// A fact ranger observed.
    #[must_use]
    pub fn event(subject: &str) -> Self {
        Self::new(Kind::Event).with_subject(subject)
    }

    /// A finding, named by its rule.
    #[must_use]
    pub fn finding(rule: &str) -> Self {
        Self::new(Kind::Finding).with_subject(rule)
    }

    /// Something went wrong, with the reason in the entry itself.
    #[must_use]
    pub fn error(reason: &str) -> Self {
        Self::new(Kind::Error).with_reason(reason)
    }

    /// Attach the operation.
    #[must_use]
    pub fn with_action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Attach the id that links an intent to its result.
    #[must_use]
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_owned());
        self
    }

    /// Attach the subject.
    #[must_use]
    pub fn with_subject(mut self, subject: &str) -> Self {
        self.subject = Some(subject.to_owned());
        self
    }

    /// Attach the path.
    #[must_use]
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_owned());
        self
    }

    /// Attach the hash.
    #[must_use]
    pub fn with_hash(mut self, hash: &str) -> Self {
        self.hash = Some(hash.to_owned());
        self
    }

    /// Attach the size.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Attach the outcome.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Attach the reason.
    #[must_use]
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_owned());
        self
    }

    /// Attach the confirmation.
    #[must_use]
    pub fn with_confirmation(mut self, confirmation: Confirmation) -> Self {
        self.confirmation = Some(confirmation);
        self
    }

    /// Turn the description into a line, with the sequence and time the writer chose.
    #[must_use]
    pub fn seal(self, seq: u64, at: u64) -> JournalEntry {
        JournalEntry {
            schema: ENTRY_SCHEMA,
            seq,
            at,
            kind: self.kind,
            action: self.action,
            id: self.id,
            subject: self.subject,
            path: self.path,
            hash: self.hash,
            size: self.size,
            outcome: self.outcome,
            reason: self.reason,
            confirmation: self.confirmation,
            chain: None,
        }
    }
}

/// One line of the journal.
///
/// Optional fields are omitted when empty, so the file stays readable in a text editor.
/// Unknown fields are ignored when reading, so a newer build's line does not make an
/// older build declare its own journal corrupt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// The schema this line was written with.
    pub schema: u32,
    /// The line's position in the journal, starting at one and never reused.
    pub seq: u64,
    /// Seconds since the Unix epoch, as the writer's clock saw them.
    pub at: u64,
    /// What the line is for.
    pub kind: Kind,
    /// The operation, when the line is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    /// The id that links an intent to its result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// A stable subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The path the line concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// A SHA-256, lowercase hex, when the line is about a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// A size in bytes, when the line is about a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// What became of the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// Why, in a sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Which confirmation was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<Confirmation>,
    /// The hash chain: a digest over the previous entry's chain and this line's content.
    ///
    /// Absent on a line written before the chain existed, and on a line a person wrote by
    /// hand. Its absence is a state the verifier reports — "before this point there is no
    /// chain" — rather than a failure: the record is older, not wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
}

/// The bytes an entry's chain is computed over.
///
/// The previous chain, a newline, and the entry as it is written *without* its chain field —
/// so the digest covers every fact in the line and nothing that depends on itself. Two
/// builds that serialise the same entry produce the same input, which is what makes the
/// chain checkable by a different version of this program.
pub fn chain_input(previous: Option<&str>, entry: &JournalEntry) -> Result<String, serde_json::Error> {
    let mut copy = entry.clone();
    copy.chain = None;
    let body = copy.to_line()?;
    Ok(format!("{}\n{body}", previous.unwrap_or("")))
}

impl JournalEntry {
    /// The line as the journal stores it: one line of JSON, no trailing newline.
    ///
    /// The writer adds the newline. The serialiser cannot emit one inside the object,
    /// because JSON escapes a newline in a string, so one entry is always one line.
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// A line that could not be read, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorruptLine {
    /// The one-based line number in the file it was read from.
    pub line: usize,
    /// What the parser said, for the person who opens the file.
    pub reason: String,
}

/// What one file's worth of text held.
#[derive(Clone, Debug, Default)]
pub struct Read {
    /// Every complete entry, in file order.
    pub entries: Vec<JournalEntry>,
    /// Lines that were not empty and did not parse.
    pub corrupt: Vec<CorruptLine>,
    /// Whether the last line was cut in half, which is what a crash during a write
    /// looks like.
    pub torn_tail: bool,
}

impl Read {
    /// The highest sequence number present, or zero.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.entries.last().map_or(0, |entry| entry.seq)
    }

    /// The sequence number a new entry should take.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.last_seq().saturating_add(1)
    }

    /// Whether anything was lost: a torn tail or a corrupt line.
    #[must_use]
    pub fn is_damaged(&self) -> bool {
        self.torn_tail || !self.corrupt.is_empty()
    }
}

/// Parse journal text into whole entries, counting what it could not read.
///
/// A torn tail is normal after a crash and is reported rather than treated as damage to
/// the entries before it.
#[must_use]
pub fn parse(text: &str) -> Read {
    let mut read = Read::default();
    let segments: Vec<&str> = text.split('\n').collect();
    let last = segments.len().saturating_sub(1);
    for (index, segment) in segments.iter().enumerate() {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<JournalEntry>(trimmed) {
            Ok(entry) => read.entries.push(entry),
            Err(error) => {
                if index == last {
                    read.torn_tail = true;
                } else {
                    read.corrupt.push(CorruptLine {
                        line: index.saturating_add(1),
                        reason: error.to_string(),
                    });
                }
            }
        }
    }
    read
}

/// The file name a rotated journal takes, given the sequence its first entry had.
#[must_use]
pub fn rotated_name(first_seq: u64) -> String {
    format!("journal-{first_seq:010}.ndjson")
}

/// The first sequence number a rotated file's name claims, if it is one of ours.
#[must_use]
pub fn parse_rotated_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("journal-")?.strip_suffix(".ndjson")?;
    if digits.len() != 10 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The actions that were started and never finished, newest first.
///
/// An intent is finished by a result with the same id. Anything else — a missing id, a
/// result with no intent, two intents for one id — is not an interruption and is not
/// reported as one.
#[must_use]
pub fn interrupted(entries: &[JournalEntry]) -> Vec<&JournalEntry> {
    let mut open: Vec<&JournalEntry> = Vec::new();
    for entry in entries {
        match entry.kind {
            Kind::Intent => {
                let Some(id) = entry.id.as_deref() else {
                    continue;
                };
                open.retain(|started| started.id.as_deref() != Some(id));
                open.push(entry);
            }
            Kind::Result => {
                if let Some(id) = entry.id.as_deref() {
                    open.retain(|started| started.id.as_deref() != Some(id));
                }
            }
            Kind::Event | Kind::Finding | Kind::Error => {}
        }
    }
    open.reverse();
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_entries() -> Vec<JournalEntry> {
        vec![
            Draft::intent(Action::Quarantine)
                .with_id("0123456789abcdef")
                .with_path("C:\\Temp\\thing.exe")
                .with_hash("aa")
                .with_size(7)
                .seal(1, 100),
            Draft::result(Action::Quarantine, Outcome::Ok)
                .with_id("0123456789abcdef")
                .with_confirmation(Confirmation::Preview)
                .seal(2, 101),
        ]
    }

    fn as_text(entries: &[JournalEntry]) -> String {
        let mut text = String::new();
        for entry in entries {
            text.push_str(&entry.to_line().unwrap());
            text.push('\n');
        }
        text
    }

    #[test]
    fn a_line_is_one_line_and_round_trips() {
        let entry = two_entries().remove(0);
        let line = entry.to_line().unwrap();
        assert!(!line.contains('\n'));
        let read = parse(&format!("{line}\n"));
        assert_eq!(read.entries, vec![entry]);
        assert!(!read.is_damaged());
    }

    #[test]
    fn optional_fields_are_omitted() {
        let line = Draft::event("process:4242").seal(3, 5).to_line().unwrap();
        assert!(!line.contains("hash"));
        assert!(!line.contains("confirmation"));
        assert!(line.contains("\"kind\":\"event\""));
    }

    #[test]
    fn unknown_fields_from_a_newer_build_are_ignored() {
        let line = r#"{"schema":1,"seq":4,"at":9,"kind":"event","subject":"x","future":{"a":1}}"#;
        let read = parse(line);
        assert_eq!(read.entries.len(), 1);
        assert!(read.corrupt.is_empty());
        assert_eq!(read.entries[0].seq, 4);
    }

    #[test]
    fn blank_lines_are_not_damage() {
        let text = "\n\n";
        let read = parse(text);
        assert!(read.entries.is_empty());
        assert!(!read.is_damaged());
    }

    #[test]
    fn a_corrupt_line_is_counted_and_the_rest_survives() {
        let text = "not json\n{\"schema\":1,\"seq\":2,\"at\":1,\"kind\":\"event\"}\n";
        let read = parse(text);
        assert_eq!(read.entries.len(), 1);
        assert_eq!(read.corrupt.len(), 1);
        assert_eq!(read.corrupt[0].line, 1);
        assert!(!read.torn_tail);
        assert!(read.is_damaged());
    }

    #[test]
    fn a_torn_tail_is_reported_and_the_entries_before_it_survive() {
        let text = as_text(&two_entries());
        let cut = text.len() - 12;
        let read = parse(&text[..cut]);
        assert!(read.torn_tail);
        assert_eq!(read.entries.len(), 1);
        assert_eq!(read.entries[0].seq, 1);
        assert!(read.corrupt.is_empty());
    }

    #[test]
    fn truncation_at_every_offset_never_panics_and_never_loses_a_whole_line() {
        let entries = two_entries();
        let text = as_text(&entries);
        for cut in 0..=text.len() {
            let read = parse(&text[..cut]);
            assert!(
                read.entries.len() <= entries.len(),
                "cut {cut} produced more entries than exist"
            );
            for (index, entry) in read.entries.iter().enumerate() {
                assert_eq!(entry, &entries[index], "cut {cut} damaged entry {index}");
            }
            if read.entries.len() == entries.len() {
                assert!(!read.is_damaged(), "cut {cut} claims damage with every entry");
            }
        }
    }

    #[test]
    fn sequence_numbers_continue_from_the_last_entry() {
        let read = parse(&as_text(&two_entries()));
        assert_eq!(read.last_seq(), 2);
        assert_eq!(read.next_seq(), 3);
        assert_eq!(Read::default().next_seq(), 1);
    }

    #[test]
    fn rotated_names_round_trip_and_reject_anything_else() {
        assert_eq!(rotated_name(1), "journal-0000000001.ndjson");
        assert_eq!(
            parse_rotated_name(&rotated_name(9_999_999_999)),
            Some(9_999_999_999)
        );
        assert_eq!(parse_rotated_name("journal.ndjson"), None);
        assert_eq!(parse_rotated_name("journal-12.ndjson"), None);
        assert_eq!(parse_rotated_name("journal-0000000001.txt"), None);
        assert_eq!(parse_rotated_name("notes-0000000001.ndjson"), None);
    }

    #[test]
    fn an_intent_without_a_result_is_interrupted() {
        let entries = two_entries();
        assert!(interrupted(&entries).is_empty());

        let hanging = vec![entries[0].clone()];
        let found = interrupted(&hanging);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id.as_deref(), Some("0123456789abcdef"));
    }

    #[test]
    fn a_result_without_an_intent_is_not_an_interruption() {
        let entries = vec![two_entries().remove(1)];
        assert!(interrupted(&entries).is_empty());
    }

    #[test]
    fn an_intent_without_an_id_is_not_reported_as_interrupted() {
        let entries = vec![Draft::intent(Action::Clean).seal(1, 1)];
        assert!(interrupted(&entries).is_empty());
    }

    #[test]
    fn the_newest_interruption_is_first() {
        let entries = vec![
            Draft::intent(Action::Quarantine).with_id("a").seal(1, 1),
            Draft::intent(Action::Clean).with_id("b").seal(2, 2),
        ];
        let found = interrupted(&entries);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id.as_deref(), Some("b"));
    }

    #[test]
    fn the_chain_input_is_the_line_without_its_own_chain() {
        let mut entry = Draft::intent(Action::Quarantine).with_id("a").seal(1, 1);
        entry.chain = Some("deadbeef".to_owned());
        let input = chain_input(Some("previous"), &entry).expect("an entry serialises");
        assert!(
            !input.contains("deadbeef"),
            "a chain that covered itself could never be computed"
        );
        assert!(input.starts_with("previous\n"), "{input}");
        assert!(input.contains("\"seq\":1"), "{input}");
    }

    #[test]
    fn a_different_previous_link_or_a_different_fact_changes_the_input() {
        let entry = Draft::event("scan").seal(1, 1);
        let base = chain_input(None, &entry).expect("an entry serialises");
        let with_previous = chain_input(Some("abc"), &entry).expect("an entry serialises");
        assert_ne!(base, with_previous);
        let mut changed = entry.clone();
        changed.reason = Some("something else".to_owned());
        assert_ne!(base, chain_input(None, &changed).expect("an entry serialises"));
        assert_eq!(
            base,
            chain_input(None, &entry).expect("an entry serialises"),
            "the same entry twice is the same input"
        );
    }
}
