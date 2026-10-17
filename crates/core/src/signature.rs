//! A hash-signature database with ClamAV's on-disk shape.
//!
//! This is a clean-room reader for the documented `.hdb` and `.hsb` formats:
//!
//! ```text
//! md5-or-sha1-or-sha256 : file-size-or-* : name
//! ```
//!
//! No ClamAV code is copied and no ClamAV database is bundled. A person may point the
//! application at a database they already have; the parser accepts it because the
//! format is documented, not because the engine was ported.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

/// A hash algorithm a signature can use.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    /// MD5, as used by ClamAV's `.hdb` files.
    Md5,
    /// SHA-1, as used by older `.hsb` files.
    Sha1,
    /// SHA-256, as used by newer `.hsb` files and by ranger's own tests.
    Sha256,
}

impl HashAlgorithm {
    /// The lower-case name used in JSON and interfaces.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// The number of hexadecimal characters a digest of this algorithm has.
    #[must_use]
    pub fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// Infer the algorithm from a digest's length, as ClamAV's `.hsb` format does.
    #[must_use]
    pub fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::Md5),
            40 => Some(Self::Sha1),
            64 => Some(Self::Sha256),
            _ => None,
        }
    }
}

/// One hash signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashSignature {
    /// The digest, lower-case hexadecimal.
    pub hash: String,
    /// The name a match reports.
    pub name: String,
    /// The exact file size, when the database knows it.
    pub size: Option<u64>,
    /// The algorithm the digest uses.
    pub algorithm: HashAlgorithm,
}

/// A set of hash signatures, indexed by digest.
#[derive(Clone, Debug, Default)]
pub struct SignatureSet {
    by_hash: HashMap<String, Vec<HashSignature>>,
    algorithms: BTreeSet<HashAlgorithm>,
}

impl SignatureSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one signature. Returns `false` when the digest or name is not usable.
    pub fn insert(&mut self, algorithm: HashAlgorithm, hash: &str, size: Option<u64>, name: &str) -> bool {
        let hash = hash.trim().to_ascii_lowercase();
        if hash.len() != algorithm.hex_len() || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        self.algorithms.insert(algorithm);
        self.by_hash.entry(hash.clone()).or_default().push(HashSignature {
            hash,
            name: name.to_owned(),
            size,
            algorithm,
        });
        true
    }

    /// Read a ClamAV `.hdb` (MD5) or `.hsb` (MD5, SHA-1 or SHA-256, by length) body.
    ///
    /// Returns `(added, rejected)`. A rejected line is counted, never guessed at.
    pub fn parse_clamav(&mut self, body: &str, forced: Option<HashAlgorithm>) -> (usize, usize) {
        let mut added = 0;
        let mut rejected = 0;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(4, ':');
            let (Some(hash), Some(size), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
                rejected += 1;
                continue;
            };
            let Some(algorithm) = forced.or_else(|| HashAlgorithm::from_hex_len(hash.trim().len())) else {
                rejected += 1;
                continue;
            };
            let size = if size.trim() == "*" {
                None
            } else {
                match size.trim().parse::<u64>() {
                    Ok(size) => Some(size),
                    Err(_) => {
                        rejected += 1;
                        continue;
                    }
                }
            };
            if self.insert(algorithm, hash, size, name) {
                added += 1;
            } else {
                rejected += 1;
            }
        }
        (added, rejected)
    }

    /// Find the signatures for a digest.
    #[must_use]
    pub fn lookup(&self, hash: &str) -> Option<&[HashSignature]> {
        self.by_hash.get(&hash.to_ascii_lowercase()).map(Vec::as_slice)
    }

    /// How many signatures are loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_hash.values().map(Vec::len).sum()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Which algorithms the set uses, in a stable order.
    #[must_use]
    pub fn algorithms(&self) -> Vec<HashAlgorithm> {
        self.algorithms.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MD5_A: &str = "44d88612fea8a8f36de82e1278abb02f";
    const SHA1_A: &str = "3395856ce81f2b7382dee72602f798b642f14140";
    const SHA256_A: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn reads_the_three_lengths() {
        let mut set = SignatureSet::new();
        assert!(set.insert(HashAlgorithm::Md5, MD5_A, Some(68), "a"));
        assert!(set.insert(HashAlgorithm::Sha1, SHA1_A, None, "b"));
        assert!(set.insert(HashAlgorithm::Sha256, SHA256_A, Some(68), "c"));
        assert_eq!(set.len(), 3);
        assert_eq!(set.algorithms().len(), 3);
        assert_eq!(set.lookup(MD5_A).map(<[HashSignature]>::len), Some(1));
        assert!(set.lookup(&MD5_A.to_ascii_uppercase()).is_some());
    }

    #[test]
    fn reads_a_clamav_body_and_counts_rejects() {
        let body = format!(
            "# comment\n{MD5_A}:68:Eicar-Test-Signature\n{SHA1_A}:*:sha1 name\nnot-a-line\n{MD5_A}:xx:bad size\n"
        );
        let mut set = SignatureSet::new();
        let (added, rejected) = set.parse_clamav(&body, None);
        assert_eq!(added, 2);
        assert_eq!(rejected, 2);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn forced_algorithm_rejects_the_wrong_length() {
        let mut set = SignatureSet::new();
        let (added, rejected) = set.parse_clamav(&format!("{SHA1_A}:68:name\n"), Some(HashAlgorithm::Md5));
        assert_eq!((added, rejected), (0, 1));
    }

    #[test]
    fn rejects_non_hex_and_empty_names() {
        let mut set = SignatureSet::new();
        assert!(!set.insert(HashAlgorithm::Md5, "zzzz", None, "name"));
        assert!(!set.insert(HashAlgorithm::Md5, MD5_A, None, "  "));
        assert!(set.is_empty());
    }
}
