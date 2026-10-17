//! Hashing the binaries a startup item reaches.
//!
//! A file is hashed once per scan and cached by path, because one executable often
//! appears in several startup entries. Files above the cap are not hashed: a partial
//! digest would be a lie, and reading a huge installer to prove it is not malware is
//! not worth the disk time.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::Digest;

/// The largest file ranger will hash in a scan.
pub const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// Every digest ranger computed for one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digests {
    /// The file's size at the moment it was read.
    pub size: u64,
    /// MD5, when a loaded signature database needs it.
    pub md5: Option<String>,
    /// SHA-1, when a loaded signature database needs it.
    pub sha1: Option<String>,
    /// SHA-256, always computed.
    pub sha256: String,
}

impl Digests {
    /// The digest for an algorithm, if it was computed.
    #[must_use]
    pub fn get(&self, algorithm: vnr_core::HashAlgorithm) -> Option<&str> {
        match algorithm {
            vnr_core::HashAlgorithm::Md5 => self.md5.as_deref(),
            vnr_core::HashAlgorithm::Sha1 => self.sha1.as_deref(),
            vnr_core::HashAlgorithm::Sha256 => Some(&self.sha256),
        }
    }
}

/// Hash a byte slice in memory.
///
/// The self-test uses this so it can prove the matcher even on a machine whose
/// antivirus removes the EICAR test file the instant it is written.
#[must_use]
pub fn digest_bytes(bytes: &[u8], want_md5: bool, want_sha1: bool) -> Digests {
    let mut sha256 = sha2::Sha256::new();
    let mut sha1 = want_sha1.then(sha1::Sha1::new);
    let mut md5 = want_md5.then(md5::Md5::new);
    sha256.update(bytes);
    if let Some(hasher) = sha1.as_mut() {
        hasher.update(bytes);
    }
    if let Some(hasher) = md5.as_mut() {
        hasher.update(bytes);
    }
    Digests {
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        md5: md5.map(|hasher| hex::encode(hasher.finalize())),
        sha1: sha1.map(|hasher| hex::encode(hasher.finalize())),
        sha256: hex::encode(sha256.finalize()),
    }
}

/// Hash one file, computing only the algorithms the caller asks for (plus SHA-256).
#[must_use]
pub fn digest_file(path: &Path, want_md5: bool, want_sha1: bool) -> Option<Digests> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut sha256 = sha2::Sha256::new();
    let mut sha1 = want_sha1.then(sha1::Sha1::new);
    let mut md5 = want_md5.then(md5::Md5::new);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                log::debug!("could not read {}: {error}", path.display());
                return None;
            }
        };
        total += read as u64;
        if total > MAX_HASH_BYTES {
            return None;
        }
        let bytes = &buffer[..read];
        sha256.update(bytes);
        if let Some(hasher) = sha1.as_mut() {
            hasher.update(bytes);
        }
        if let Some(hasher) = md5.as_mut() {
            hasher.update(bytes);
        }
    }
    Some(Digests {
        size: total,
        md5: md5.map(|hasher| hex::encode(hasher.finalize())),
        sha1: sha1.map(|hasher| hex::encode(hasher.finalize())),
        sha256: hex::encode(sha256.finalize()),
    })
}

/// A per-scan digest cache.
#[derive(Debug)]
pub struct Hasher {
    want_md5: bool,
    want_sha1: bool,
    cache: HashMap<PathBuf, Option<Digests>>,
}

impl Hasher {
    /// A cache that computes MD5 and SHA-1 only when the signature set needs them.
    #[must_use]
    pub fn new(want_md5: bool, want_sha1: bool) -> Self {
        Self {
            want_md5,
            want_sha1,
            cache: HashMap::new(),
        }
    }

    /// Hash a file, reusing an earlier answer for the same path.
    pub fn digest(&mut self, path: &Path) -> Option<&Digests> {
        if !self.cache.contains_key(path) {
            let digests = digest_file(path, self.want_md5, self.want_sha1);
            self.cache.insert(path.to_path_buf(), digests);
        }
        self.cache.get(path).and_then(Option::as_ref)
    }

    /// A digest already computed in this scan.
    #[must_use]
    pub fn cached(&self, path: &Path) -> Option<&Digests> {
        self.cache.get(path).and_then(Option::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_hello() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello").unwrap();
        let digests = digest_file(&path, true, true).unwrap();
        assert_eq!(digests.size, 5);
        assert_eq!(
            digests.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(digests.md5.as_deref(), Some("5d41402abc4b2a76b9719d911017c592"));
        assert_eq!(
            digests.sha1.as_deref(),
            Some("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        );
    }

    #[test]
    fn caches_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello").unwrap();
        let mut hasher = Hasher::new(false, false);
        assert!(hasher.digest(&path).is_some());
        assert!(hasher.cached(&path).is_some());
        assert!(hasher.digest(&dir.path().join("missing")).is_none());
    }
}
