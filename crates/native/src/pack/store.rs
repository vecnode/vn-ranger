//! Which pack is loaded, the record that says so, and the journal line each way.
//!
//! Activation and rollback are the two acts that change what ranger knows. Both are one
//! record swap plus a journal entry, and neither of them touches a fact, a baseline, a
//! quarantine entry or a rule file: rolling a bad pack back leaves every other file
//! byte-identical (`docs/PLAN.md` §9, wave 4).
//!
//! The order is the action path's order, because this is an act: the intent is journalled
//! and synced, then the record is written, then the result is journalled. A crash between
//! the two steps leaves an `intent` without a `result`, which is a named recovery state
//! rather than a mystery.
//!
//! `previous.json` is written before `active.json` is replaced. That is what makes rollback
//! a swap rather than a copy, and what makes a crash in the middle leave the old record
//! readable instead of gone.

use std::path::{Path, PathBuf};

use vnr_core::pack::active::{Active, FILE as ACTIVE_FILE, PREVIOUS};
use vnr_core::pack::{self, MAX_BYTES, Pack, Reject};
use vnr_core::{Action, Draft, Outcome};

use super::{embedded, keys::Keys, signature};
use crate::journal::Journal;

/// The extension a pack file has.
pub const PACK_EXTENSION: &str = "json";

/// The extension a detached signature has.
pub const SIGNATURE_EXTENSION: &str = "minisig";

/// One pack file in the packs directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The JSON file.
    pub path: PathBuf,
    /// Whether a `.minisig` sits beside it.
    pub signed: bool,
}

/// A pack that is loaded, with the record that says why.
#[derive(Clone, Debug)]
pub struct Loaded {
    /// The validated pack.
    pub pack: Pack,
    /// The record describing the bytes it came from.
    pub active: Active,
}

/// The directory packs and their keys live in.
#[must_use]
pub fn directory() -> PathBuf {
    crate::paths::packs_dir()
}

/// Every pack file in a directory, in a stable order.
///
/// The bookkeeping files are not packs: `active.json` and `previous.json` are records, and
/// `keys.json` is the trust store. A file that is none of those is something a person put
/// there, and it is listed with whether it was signed rather than being verified here.
#[must_use]
pub fn candidates(directory: &Path) -> Vec<Candidate> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<Candidate> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some(PACK_EXTENSION) {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            if matches!(name, ACTIVE_FILE | PREVIOUS) || name == super::keys::FILE {
                return None;
            }
            let signed = path.with_extension(SIGNATURE_EXTENSION).is_file();
            Some(Candidate { path, signed })
        })
        .collect();
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// The record in a directory, when there is one.
pub fn record(directory: &Path) -> Result<Option<Active>, String> {
    read_record(directory, ACTIVE_FILE)
}

/// The previous record in a directory, when there is one.
pub fn previous(directory: &Path) -> Result<Option<Active>, String> {
    read_record(directory, PREVIOUS)
}

fn read_record(directory: &Path, name: &str) -> Result<Option<Active>, String> {
    let path = directory.join(name);
    match std::fs::read_to_string(&path) {
        Ok(text) => Active::parse(&text).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("Could not read {}: {error}", path.display())),
    }
}

/// Verify and validate one pack file, changing nothing.
///
/// The Packs view lists what is in the folder with what ranger would say about it, and that
/// answer has to come from the same checks as activation: a listing that said "fine" and an
/// activation that refused would be two answers to one question.
pub fn inspect(path: &Path, builtin_ids: &[&str], keys: &Keys) -> Result<(Pack, String), String> {
    let bytes = read_pack(path)?;
    let fingerprint = verify(&bytes, path, keys)?;
    let pack = parse(&bytes, path, builtin_ids)?;
    Ok((pack, fingerprint))
}

/// Load the pack the record names, verifying it again as it is loaded.
///
/// Verification is repeated here rather than trusted from activation for one reason: the
/// trust store is a file a person can edit, and removing a key has to unload the packs that
/// key signed. A record that names a pack whose key is no longer trusted is a record that
/// describes a pack this machine no longer accepts, and the answer is a refusal with the
/// fingerprint in it.
pub fn load_active(directory: &Path, builtin_ids: &[&str], keys: &Keys) -> Result<Option<Loaded>, String> {
    let Some(active) = record(directory)? else {
        return Ok(None);
    };
    if active.fingerprint.is_none() {
        return load_embedded(&active, builtin_ids).map(Some);
    }
    let Some(candidate) = candidates(directory)
        .into_iter()
        .find(|candidate| digest_of(&candidate.path).as_deref() == Some(active.sha256.as_str()))
    else {
        return Err(format!(
            "{} names {} {}, and no pack in {} has that digest. Ranger will not load a \
             different file under the same name.",
            ACTIVE_FILE,
            active.id,
            active.version,
            directory.display()
        ));
    };
    let bytes = read_pack(&candidate.path)?;
    verify(&bytes, &candidate.path, keys)?;
    let pack = parse(&bytes, &candidate.path, builtin_ids)?;
    Ok(Some(Loaded { pack, active }))
}

fn load_embedded(active: &Active, builtin_ids: &[&str]) -> Result<Loaded, String> {
    let digest = embedded::sha256();
    if digest != active.sha256 {
        return Err(format!(
            "{} describes an embedded pack whose digest is not the one this build carries. \
             Activate the pack from the build again.",
            ACTIVE_FILE
        ));
    }
    let pack = embedded::load(builtin_ids).map_err(|rejects| refusal(embedded::SOURCE, &rejects))?;
    Ok(Loaded {
        pack,
        active: active.clone(),
    })
}

/// Record the pack compiled into this build as active.
///
/// This is what a first launch does, and what a person does after replacing a bad pack with
/// the built-in catalogue. It is journalled like any other activation.
pub fn activate_embedded(
    directory: &Path,
    builtin_ids: &[&str],
    journal: &mut Journal,
    now_unix: u64,
) -> Result<Loaded, String> {
    let pack = embedded::load(builtin_ids).map_err(|rejects| refusal(embedded::SOURCE, &rejects))?;
    let active = Active {
        id: pack.header.id.clone(),
        version: pack.header.version.clone(),
        sha256: embedded::sha256(),
        fingerprint: None,
        activated_at_unix: now_unix,
    };
    write_record(
        directory,
        journal,
        &active,
        &pack,
        "activated the pack built into this build",
    )?;
    Ok(Loaded { pack, active })
}

/// Verify, validate and record a pack as the active one.
///
/// The signature is checked before a byte is parsed, and the parse happens before anything
/// is written. A pack that fails either step leaves the record exactly as it was.
pub fn activate(
    directory: &Path,
    pack_path: &Path,
    builtin_ids: &[&str],
    keys: &Keys,
    journal: &mut Journal,
    now_unix: u64,
) -> Result<Loaded, String> {
    let bytes = read_pack(pack_path)?;
    let fingerprint = verify(&bytes, pack_path, keys)?;
    let pack = parse(&bytes, pack_path, builtin_ids)?;
    let active = Active {
        id: pack.header.id.clone(),
        version: pack.header.version.clone(),
        sha256: digest_of_bytes(&bytes),
        fingerprint: Some(fingerprint),
        activated_at_unix: now_unix,
    };
    write_record(
        directory,
        journal,
        &active,
        &pack,
        &format!("activated {}", pack_path.display()),
    )?;
    Ok(Loaded { pack, active })
}

/// Return to the pack that was active before this one.
///
/// The two records swap, so rolling back twice returns to where the person started. It is
/// the same act as activation, journalled the same way, and it changes nothing else.
pub fn rollback(
    directory: &Path,
    builtin_ids: &[&str],
    keys: &Keys,
    journal: &mut Journal,
    now_unix: u64,
) -> Result<Loaded, String> {
    let Some(current) = record(directory)? else {
        return Err("No pack is active, so there is nothing to roll back from.".to_owned());
    };
    let Some(previous) = previous(directory)? else {
        return Err("No previous pack is recorded, so there is nothing to roll back to.".to_owned());
    };
    // The bytes have to be checkable before the record moves, or the rollback would leave
    // ranger pointing at a pack it cannot load.
    let loaded = load_named(directory, &previous, builtin_ids, keys)?;
    let intent = Draft::intent(Action::Pack)
        .with_subject(&previous.id)
        .with_path(&directory.join(ACTIVE_FILE).display().to_string())
        .with_hash(&previous.sha256)
        .with_reason(&format!(
            "roll back from {} {} to {} {}",
            current.id, current.version, previous.id, previous.version
        ));
    let intent = journal
        .record_synced(intent)
        .map_err(|error| format!("The rollback was not recorded, so it did not happen: {error}"))?;
    write_json_record(directory, PREVIOUS, &current)?;
    write_json_record(directory, ACTIVE_FILE, &previous)?;
    let outcome = journal.record_synced(
        Draft::result(Action::Pack, Outcome::Ok)
            .with_id(intent.id.as_deref().unwrap_or_default())
            .with_subject(&previous.id)
            .with_hash(&previous.sha256)
            .with_reason(&format!(
                "rolled back to {} {}, activated {}",
                previous.id,
                previous.version,
                format_time(now_unix)
            )),
    );
    let _ = outcome;
    Ok(Loaded {
        pack: loaded,
        active: previous,
    })
}

fn load_named(directory: &Path, active: &Active, builtin_ids: &[&str], keys: &Keys) -> Result<Pack, String> {
    if active.fingerprint.is_none() {
        return embedded::load(builtin_ids)
            .map_err(|rejects| refusal(embedded::SOURCE, &rejects))
            .and_then(|pack| {
                if embedded::sha256() == active.sha256 {
                    Ok(pack)
                } else {
                    Err(format!(
                        "{} describes a different build's pack, and this build cannot roll back to it.",
                        PREVIOUS
                    ))
                }
            });
    }
    let Some(candidate) = candidates(directory)
        .into_iter()
        .find(|candidate| digest_of(&candidate.path).as_deref() == Some(active.sha256.as_str()))
    else {
        return Err(format!(
            "The pack named by {} is no longer in {}. Put it back before rolling back.",
            PREVIOUS,
            directory.display()
        ));
    };
    let bytes = read_pack(&candidate.path)?;
    verify(&bytes, &candidate.path, keys)?;
    parse(&bytes, &candidate.path, builtin_ids)
}

/// Write the new record, journaling the intent before the write and the result after it.
fn write_record(
    directory: &Path,
    journal: &mut Journal,
    active: &Active,
    pack: &Pack,
    reason: &str,
) -> Result<(), String> {
    crate::paths::ensure_dir(directory)
        .map_err(|error| format!("Could not prepare {}: {error}", directory.display()))?;
    let path = directory.join(ACTIVE_FILE);
    let intent = Draft::intent(Action::Pack)
        .with_subject(&active.id)
        .with_path(&path.display().to_string())
        .with_hash(&active.sha256)
        .with_reason(&format!("{reason}: {} {}", active.id, active.version));
    let intent = journal
        .record_synced(intent)
        .map_err(|error| format!("The activation was not recorded, so it did not happen: {error}"))?;
    // The previous record is written first, so a crash between the two writes leaves both a
    // readable current record and a readable way back.
    if let Ok(Some(current)) = record(directory) {
        write_json_record(directory, PREVIOUS, &current)?;
    }
    write_json_record(directory, ACTIVE_FILE, active)?;
    let result = journal.record_synced(
        Draft::result(Action::Pack, Outcome::Ok)
            .with_id(intent.id.as_deref().unwrap_or_default())
            .with_subject(&active.id)
            .with_hash(&active.sha256)
            .with_size(u64::try_from(pack.rules.len()).unwrap_or(u64::MAX))
            .with_reason(&format!("{} rules now active", pack.rules.len())),
    );
    if let Err(error) = result {
        return Err(format!(
            "The pack was activated but the result could not be recorded: {error}"
        ));
    }
    Ok(())
}

fn write_json_record(directory: &Path, name: &str, active: &Active) -> Result<(), String> {
    let path = directory.join(name);
    let line = active.to_line()?;
    crate::store::write_atomic(&path, line.as_bytes())
        .map_err(|error| format!("Could not write {}: {error}", path.display()))
}

fn read_pack(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::metadata(path).map_err(|error| format!("Could not read {}: {error}", path.display()))?;
    if metadata.len() > MAX_BYTES as u64 {
        return Err(format!(
            "{} is {} bytes, and the limit for a pack is {MAX_BYTES}.",
            path.display(),
            metadata.len()
        ));
    }
    std::fs::read(path).map_err(|error| format!("Could not read {}: {error}", path.display()))
}

fn verify(bytes: &[u8], path: &Path, keys: &Keys) -> Result<String, String> {
    let signature_path = path.with_extension(SIGNATURE_EXTENSION);
    let signature = std::fs::read_to_string(&signature_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!(
                "{} has no {SIGNATURE_EXTENSION} beside it, and ranger only loads a signed pack.",
                path.display()
            )
        } else {
            format!("Could not read {}: {error}", signature_path.display())
        }
    })?;
    signature::verify(bytes, &signature, &keys.trusted())
        .map_err(|refusal| format!("{} was refused: {refusal}", path.display()))
}

fn parse(bytes: &[u8], path: &Path, builtin_ids: &[&str]) -> Result<Pack, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("{} is not UTF-8 text: {error}", path.display()))?;
    pack::parse(text, builtin_ids).map_err(|rejects| refusal(&path.display().to_string(), &rejects))
}

fn refusal(source: &str, rejects: &[Reject]) -> String {
    let mut out = format!("{source} was refused:");
    for reject in rejects {
        out.push_str("\n  ");
        out.push_str(&reject.to_string());
    }
    out
}

fn digest_of(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(digest_of_bytes(&bytes))
}

fn digest_of_bytes(bytes: &[u8]) -> String {
    crate::hash::digest_bytes(bytes, false, false).sha256
}

fn format_time(unix: u64) -> String {
    vnr_core::time::format_utc(unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::rules::builtin_ids;

    fn pack_text(version: &str, rule_id: &str) -> String {
        format!(
            r#"{{
  "schema": 1,
  "pack": {{ "id": "test.pack", "version": "{version}", "title": "Test pack" }},
  "rules": [
    {{
      "id": "{rule_id}",
      "title": "A test rule",
      "severity": "notice",
      "confidence": "observed",
      "match": {{ "subject": "startup", "all": [ {{ "field": "path", "op": "under", "value": "{{TEMP}}" }} ] }},
      "why": "Because the test says so.",
      "benign": "A test.",
      "remediation": "Nothing."
    }}
  ]
}}"#
        )
    }

    /// Write a pack and its detached signature, and return the key that signed it.
    fn signed_pack(directory: &std::path::Path, name: &str, version: &str) -> (Keys, PathBuf) {
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let body = pack_text(version, "test.rule-one");
        let signature =
            minisign::sign(None, &pair.sk, body.as_bytes(), Some("vn-ranger test"), None).unwrap();
        let path = directory.join(format!("{name}.json"));
        std::fs::write(&path, &body).unwrap();
        std::fs::write(path.with_extension(SIGNATURE_EXTENSION), signature.to_string()).unwrap();
        let mut keys = Keys::default();
        keys.add(&pair.pk.to_base64(), 1).unwrap();
        (keys, path)
    }

    fn journal(directory: &std::path::Path) -> Journal {
        Journal::open_at(directory.join("journal.ndjson")).unwrap()
    }

    #[test]
    fn an_unsigned_pack_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.json");
        std::fs::write(&path, pack_text("1", "test.rule-one")).unwrap();
        let mut log = journal(dir.path());
        let refused = activate(dir.path(), &path, builtin_ids(), &Keys::default(), &mut log, 10).unwrap_err();
        assert!(refused.contains("no minisig"), "{refused}");
        assert_eq!(record(dir.path()).unwrap(), None, "nothing was recorded");
    }

    #[test]
    fn activating_a_signed_pack_records_it_and_journals_both_steps() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, path) = signed_pack(dir.path(), "candidate", "1.0.0");
        let mut log = journal(dir.path());
        let loaded = activate(dir.path(), &path, builtin_ids(), &keys, &mut log, 1_700_000_000).unwrap();
        assert_eq!(loaded.active.version, "1.0.0");
        assert!(loaded.active.fingerprint.is_some());

        let written = record(dir.path()).unwrap().unwrap();
        assert_eq!(written, loaded.active);
        assert_eq!(written.sha256.len(), 64);

        let read = log.read();
        assert_eq!(read.entries.len(), 2, "an intent and a result");
        assert_eq!(read.entries[0].kind, vnr_core::JournalKind::Intent);
        assert_eq!(read.entries[1].outcome, Some(Outcome::Ok));
    }

    #[test]
    fn a_pack_changed_after_it_was_signed_is_refused_and_the_record_stays() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, path) = signed_pack(dir.path(), "candidate", "1.0.0");
        let mut log = journal(dir.path());
        let first = activate(dir.path(), &path, builtin_ids(), &keys, &mut log, 1).unwrap();

        let mut body = std::fs::read(&path).unwrap();
        let at = body.windows(4).position(|window| window == b"1.0.").unwrap();
        body[at] = b'2';
        std::fs::write(&path, &body).unwrap();

        let refused = activate(dir.path(), &path, builtin_ids(), &keys, &mut log, 2).unwrap_err();
        assert!(refused.contains("refused"), "{refused}");
        assert_eq!(record(dir.path()).unwrap().unwrap(), first.active);
    }

    #[test]
    fn a_pack_signed_by_a_key_this_machine_does_not_trust_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_keys, path) = signed_pack(dir.path(), "candidate", "1.0.0");
        let mut log = journal(dir.path());
        let other = Keys::default();
        let refused = activate(dir.path(), &path, builtin_ids(), &other, &mut log, 1).unwrap_err();
        assert!(
            refused.contains("no key is trusted") || refused.contains("No key is trusted"),
            "{refused}"
        );
        assert_eq!(record(dir.path()).unwrap(), None);
    }

    #[test]
    fn rolling_back_returns_to_the_previous_record_and_touches_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let (mut keys, first) = signed_pack(dir.path(), "v1", "1.0.0");
        let second = {
            let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            let body = pack_text("2.0.0", "test.rule-one");
            let signature = minisign::sign(None, &pair.sk, body.as_bytes(), Some("v2"), None).unwrap();
            let path = dir.path().join("v2.json");
            std::fs::write(&path, &body).unwrap();
            std::fs::write(path.with_extension(SIGNATURE_EXTENSION), signature.to_string()).unwrap();
            keys.add(&pair.pk.to_base64(), 2).unwrap();
            path
        };
        let mut log = journal(dir.path());
        let first_loaded = activate(dir.path(), &first, builtin_ids(), &keys, &mut log, 10).unwrap();
        let second_loaded = activate(dir.path(), &second, builtin_ids(), &keys, &mut log, 20).unwrap();
        let before: Vec<(PathBuf, Vec<u8>)> = candidates(dir.path())
            .into_iter()
            .map(|candidate| {
                let bytes = std::fs::read(&candidate.path).unwrap();
                (candidate.path, bytes)
            })
            .collect();

        let back = rollback(dir.path(), builtin_ids(), &keys, &mut log, 30).unwrap();
        assert_eq!(back.active, first_loaded.active);
        assert_eq!(previous(dir.path()).unwrap().unwrap(), second_loaded.active);
        assert_eq!(record(dir.path()).unwrap().unwrap(), first_loaded.active);
        assert_eq!(back.pack.header.version, "1.0.0");

        let after: Vec<(PathBuf, Vec<u8>)> = candidates(dir.path())
            .into_iter()
            .map(|candidate| {
                let bytes = std::fs::read(&candidate.path).unwrap();
                (candidate.path, bytes)
            })
            .collect();
        assert_eq!(before, after, "every pack file is byte-identical");
        assert_eq!(log.read().entries.len(), 6, "three intents, three results");
    }

    #[test]
    fn removing_the_key_unloads_the_pack_it_signed() {
        let dir = tempfile::tempdir().unwrap();
        let (keys, path) = signed_pack(dir.path(), "candidate", "1.0.0");
        let mut log = journal(dir.path());
        let loaded = activate(dir.path(), &path, builtin_ids(), &keys, &mut log, 1).unwrap();

        let reloaded = load_active(dir.path(), builtin_ids(), &keys).unwrap().unwrap();
        assert_eq!(reloaded.active, loaded.active);

        let refused = load_active(dir.path(), builtin_ids(), &Keys::default()).unwrap_err();
        assert!(refused.contains("refused"), "{refused}");
    }

    #[test]
    fn the_pack_built_into_this_build_activates_and_loads_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = journal(dir.path());
        let loaded = activate_embedded(dir.path(), builtin_ids(), &mut log, 5).unwrap();
        assert_eq!(loaded.active.fingerprint, None);
        assert_eq!(record(dir.path()).unwrap().unwrap(), loaded.active);

        let again = load_active(dir.path(), builtin_ids(), &Keys::default())
            .unwrap()
            .unwrap();
        assert_eq!(again.pack.header.id, "ranger.core");
        assert_eq!(again.active.sha256, embedded::sha256());
    }

    #[test]
    fn a_record_that_names_bytes_this_build_does_not_carry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = journal(dir.path());
        let loaded = activate_embedded(dir.path(), builtin_ids(), &mut log, 5).unwrap();
        let mut record_in_file = loaded.active.clone();
        record_in_file.sha256 = "cd".repeat(32);
        write_json_record(dir.path(), ACTIVE_FILE, &record_in_file).unwrap();
        let refused = load_active(dir.path(), builtin_ids(), &Keys::default()).unwrap_err();
        assert!(refused.contains("digest"), "{refused}");
    }

    #[test]
    fn a_rollback_with_no_previous_record_says_so_rather_than_guessing() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = journal(dir.path());
        activate_embedded(dir.path(), builtin_ids(), &mut log, 5).unwrap();
        let refused = rollback(dir.path(), builtin_ids(), &Keys::default(), &mut log, 6).unwrap_err();
        assert!(refused.contains("nothing to roll back to"), "{refused}");
    }
}
