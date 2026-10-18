//! The keys ranger trusts, and the two operations the interface needs from them.
//!
//! A pack is only as good as the key it was signed with, so the list of keys is the whole
//! trust decision (`docs/PLAN.md` §6.11). It is a file a person can read: the public key,
//! the fingerprint they were asked to compare, and when they added it. Adding is an act, not
//! a consequence — nothing here is called by a scan, and no code path adds a key because a
//! pack asked it to.
//!
//! Keys are public data. There is no secret half on a machine running ranger, and there is
//! nothing in this file worth stealing.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::signature::Key;

/// The file's name, inside the packs directory.
pub(crate) const FILE: &str = "keys.json";

/// One trusted key, as the file holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    /// The public key, exactly as minisign writes it.
    pub public: String,
    /// The fingerprint the person compared before typing it in.
    pub fingerprint: String,
    /// Seconds since the Unix epoch, when it was added.
    pub added_at_unix: u64,
}

/// The trust store: a list, in the order the person added them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Keys {
    /// The trusted keys.
    #[serde(default)]
    pub keys: Vec<Stored>,
}

impl Keys {
    /// Read the store from a directory. No file is an empty store, not an error.
    pub fn load(directory: &Path) -> Result<Self, String> {
        let path = directory.join(FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(format!("Could not read {}: {error}", path.display())),
        };
        serde_json::from_str(&text).map_err(|error| {
            format!(
                "{} is not a key store: {error}. Ranger will not guess which keys were trusted.",
                path.display()
            )
        })
    }

    /// Write the store, atomically, through the same writer the rest of the data uses.
    pub fn save(&self, directory: &Path) -> Result<(), String> {
        crate::paths::ensure_dir(directory)
            .map_err(|error| format!("Could not prepare {}: {error}", directory.display()))?;
        crate::store::write_json_value(self, &directory.join(FILE))
            .map_err(|error| format!("Could not write {}: {error}", directory.join(FILE).display()))
    }

    /// Trust a key the person pasted. The same key twice is refused rather than duplicated.
    pub fn add(&mut self, public: &str, now_unix: u64) -> Result<Stored, String> {
        let key = Key::parse(public).ok_or_else(|| "That is not a minisign public key.".to_owned())?;
        if self
            .keys
            .iter()
            .any(|stored| stored.fingerprint == key.fingerprint)
        {
            return Err(format!("That key is already trusted: {}.", key.fingerprint));
        }
        let stored = Stored {
            public: key.public,
            fingerprint: key.fingerprint,
            added_at_unix: now_unix,
        };
        self.keys.push(stored.clone());
        Ok(stored)
    }

    /// Stop trusting one key, by the fingerprint a person was shown.
    ///
    /// Returns whether it was there. Removing a key that is not there is not an error: the
    /// state the person asked for is the state they get.
    pub fn remove(&mut self, fingerprint: &str) -> bool {
        let before = self.keys.len();
        self.keys
            .retain(|stored| stored.fingerprint != fingerprint.trim());
        self.keys.len() != before
    }

    /// The keys as the verifier wants them.
    #[must_use]
    pub fn trusted(&self) -> Vec<Key> {
        self.keys
            .iter()
            .filter_map(|stored| Key::parse(&stored.public))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_key() -> String {
        minisign::KeyPair::generate_unencrypted_keypair()
            .unwrap()
            .pk
            .to_base64()
    }

    #[test]
    fn a_key_added_is_a_key_that_stays_added() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys = Keys::load(dir.path()).unwrap();
        assert!(keys.keys.is_empty(), "no file is an empty store");

        let stored = keys.add(&a_key(), 1_700_000_000).unwrap();
        keys.save(dir.path()).unwrap();

        let again = Keys::load(dir.path()).unwrap();
        assert_eq!(again.keys, vec![stored]);
        assert_eq!(again.trusted().len(), 1, "and it is usable by the verifier");
    }

    #[test]
    fn the_same_key_twice_is_refused_rather_than_duplicated() {
        let mut keys = Keys::default();
        let public = a_key();
        let first = keys.add(&public, 1).unwrap();
        let refused = keys.add(&public, 2).unwrap_err();
        assert!(refused.contains(&first.fingerprint), "{refused}");
        assert_eq!(keys.keys.len(), 1);
    }

    #[test]
    fn something_that_is_not_a_key_is_refused() {
        let mut keys = Keys::default();
        assert!(keys.add("hello", 1).is_err());
        assert!(keys.add("", 1).is_err());
        assert!(keys.keys.is_empty());
    }

    #[test]
    fn a_key_is_removed_by_its_fingerprint_and_a_missing_one_is_not_an_error() {
        let mut keys = Keys::default();
        let kept = keys.add(&a_key(), 1).unwrap();
        let removed = keys.add(&a_key(), 2).unwrap();

        assert!(keys.remove(&removed.fingerprint));
        assert_eq!(keys.keys, vec![kept.clone()]);
        assert!(
            !keys.remove(&removed.fingerprint),
            "already gone is the state that was asked for"
        );
        assert!(!keys.remove("  "), "and a blank fingerprint removes nothing");
    }

    #[test]
    fn a_store_that_cannot_be_read_is_an_error_rather_than_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), b"not json").unwrap();
        let refused = Keys::load(dir.path()).unwrap_err();
        assert!(
            refused.contains("will not guess"),
            "an unreadable store must not pass for no keys: {refused}"
        );
    }

    #[test]
    fn a_trusted_key_is_the_one_the_signature_check_uses() {
        let mut keys = Keys::default();
        let stored = keys.add(&a_key(), 1).unwrap();
        let trusted = keys.trusted();
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].fingerprint, stored.fingerprint);
    }
}
