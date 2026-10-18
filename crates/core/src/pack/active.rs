//! The record of which pack is active, and what it was when it was activated.
//!
//! `packs/active.json` names one pack by id, version, SHA-256, the fingerprint of the key
//! that signed it, and when it was activated (`docs/PLAN.md` §6.11). It is a record, not a
//! configuration: rollback flips this file back to the previous verified version and
//! touches nothing else — no fact, no baseline, no quarantine entry, no rule.
//!
//! The file lives beside the packs because a person should be able to read it, and because
//! a record that only a binary can interpret is not a record. This module is the shape and
//! the checks; reading and writing it through `cap-std`, and the journal entry that names
//! the change, are the next row.

use serde::{Deserialize, Serialize};

/// The file's name, inside the packs directory.
pub const FILE: &str = "active.json";

/// The record of the pack that was active before this one.
///
/// Rollback swaps the two files and touches nothing else, so returning to the previous pack
/// is one rename rather than a second copy of its rules. It is written before `active.json`
/// is replaced, so a crash in between leaves the old record readable.
pub const PREVIOUS: &str = "previous.json";

/// Which pack is loaded, and the bytes it was loaded from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Active {
    /// The pack's id, such as `ranger.core`.
    pub id: String,
    /// The version the author gave it.
    pub version: String,
    /// SHA-256 of the exact bytes that were validated and loaded, lowercase hexadecimal.
    pub sha256: String,
    /// The fingerprint of the key that signed those bytes, as the interface shows it.
    ///
    /// `None` is the pack compiled into this build. There is no key on the machine to name:
    /// the build is the trust anchor, and the digest above is what ties the record to the
    /// bytes that came with it.
    pub fingerprint: Option<String>,
    /// Seconds since the Unix epoch, when it was activated.
    pub activated_at_unix: u64,
}

impl Active {
    /// Read a record, refusing one that could not have been written by ranger.
    ///
    /// A record with a malformed digest is not a record to trust and then reconcile: it is
    /// a file that has been edited, and the honest answer is to refuse it by name rather
    /// than to load whatever it now points at.
    pub fn parse(text: &str) -> Result<Self, String> {
        let active: Self =
            serde_json::from_str(text).map_err(|error| format!("{FILE} is not a pack record: {error}"))?;
        active.check()?;
        Ok(active)
    }

    /// The record as one line of JSON, which is how it is written.
    pub fn to_line(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|error| format!("could not write {FILE}: {error}"))
    }

    /// Whether this record still describes these bytes.
    ///
    /// The check that matters before loading: a pack that changed after it was activated is
    /// a different pack, whatever its id and version say.
    #[must_use]
    pub fn describes(&self, sha256: &str) -> bool {
        self.sha256 == sha256
    }

    fn check(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err(format!("{FILE} names no pack id"));
        }
        if self.version.trim().is_empty() {
            return Err(format!("{FILE} gives {} no version", self.id));
        }
        if !valid_sha256(&self.sha256) {
            return Err(format!(
                "{FILE} has a digest that is not 64 lowercase hexadecimal characters: {:?}",
                self.sha256
            ));
        }
        if let Some(fingerprint) = &self.fingerprint
            && !valid_fingerprint(fingerprint)
        {
            return Err(format!(
                "{FILE} has a key fingerprint ranger does not write: {fingerprint:?}"
            ));
        }
        Ok(())
    }
}

/// Whether a digest is one ranger writes: 64 lowercase hexadecimal characters.
#[must_use]
pub fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

/// Whether a fingerprint is one ranger writes: four groups of four uppercase hex characters.
#[must_use]
pub fn valid_fingerprint(fingerprint: &str) -> bool {
    let groups: Vec<&str> = fingerprint.split(' ').collect();
    groups.len() == 4
        && groups.iter().all(|group| {
            group.len() == 4
                && group
                    .chars()
                    .all(|character| character.is_ascii_digit() || ('A'..='F').contains(&character))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Active {
        Active {
            id: "ranger.core".to_owned(),
            version: "2026.11.1".to_owned(),
            sha256: "ab".repeat(32),
            fingerprint: Some("0123 4567 89AB CDEF".to_owned()),
            activated_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn a_record_round_trips_through_its_line() {
        let record = record();
        let line = record.to_line().unwrap();
        assert!(!line.contains('\n'), "the record is one line");
        assert_eq!(Active::parse(&line).unwrap(), record);
    }

    #[test]
    fn a_digest_that_is_not_one_is_refused_by_name() {
        for bad in [
            String::new(),
            "ab".repeat(31),
            "AB".repeat(32),
            "zz".repeat(32),
            "ab".repeat(33),
        ] {
            let mut record = record();
            record.sha256 = bad.clone();
            let refused = Active::parse(&record.to_line().unwrap()).unwrap_err();
            assert!(refused.contains(FILE), "{refused}");
            assert!(refused.contains("digest"), "{bad:?} names the digest");
        }
    }

    #[test]
    fn a_fingerprint_ranger_did_not_write_is_refused() {
        for bad in [
            "",
            "0123456789ABCDEF",
            "0123 4567 89AB",
            "0123 4567 89ab CDEF",
            "0123 4567 89AB CDEF 0000",
            "012g 4567 89AB CDEF",
        ] {
            let mut record = record();
            record.fingerprint = Some(bad.to_owned());
            assert!(
                Active::parse(&record.to_line().unwrap()).is_err(),
                "{bad:?} is not a fingerprint"
            );
        }
    }

    #[test]
    fn a_record_without_an_id_or_a_version_is_refused() {
        let mut blank_id = record();
        blank_id.id = "  ".to_owned();
        assert!(Active::parse(&blank_id.to_line().unwrap()).is_err());

        let mut blank_version = record();
        blank_version.version = String::new();
        assert!(Active::parse(&blank_version.to_line().unwrap()).is_err());
    }

    #[test]
    fn a_record_only_describes_the_bytes_it_was_written_for() {
        let record = record();
        assert!(record.describes(&record.sha256));
        assert!(
            !record.describes(&"cd".repeat(32)),
            "a changed pack is another pack"
        );
    }

    #[test]
    fn a_file_that_is_not_a_record_says_so() {
        let refused = Active::parse("{\"id\": \"x\"}").unwrap_err();
        assert!(refused.contains(FILE));
        assert!(Active::parse("not json").is_err());
    }
}
