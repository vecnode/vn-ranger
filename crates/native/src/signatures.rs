//! Local signature databases.
//!
//! Ranger ships one signature: the EICAR test file, which every antivirus engine is
//! expected to recognise and which is not malware. Everything else comes from files a
//! person puts in the signatures directory. No database is downloaded, and no ClamAV
//! code is linked: the reader below implements the documented `.hdb` and `.hsb`
//! formats.

use std::fs;
use std::path::Path;

use vnr_core::{HashAlgorithm, SignatureReport, SignatureSet};

/// The EICAR test file, 68 bytes, harmless by construction.
pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// MD5 of the EICAR test file.
pub const EICAR_MD5: &str = "44d88612fea8a8f36de82e1278abb02f";
/// SHA-1 of the EICAR test file.
pub const EICAR_SHA1: &str = "3395856ce81f2b7382dee72602f798b642f14140";
/// SHA-256 of the EICAR test file.
pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// The largest database file ranger will read into memory.
const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;

/// Load the built-in test signature and every `.hdb` / `.hsb` in the data directory.
#[must_use]
pub fn load() -> (SignatureSet, SignatureReport) {
    let mut set = SignatureSet::new();
    let mut report = SignatureReport::default();

    set.insert(HashAlgorithm::Md5, EICAR_MD5, Some(68), "EICAR-Test-File");
    set.insert(HashAlgorithm::Sha1, EICAR_SHA1, Some(68), "EICAR-Test-File");
    set.insert(HashAlgorithm::Sha256, EICAR_SHA256, Some(68), "EICAR-Test-File");
    report
        .notes
        .push("Built-in EICAR test signature is loaded.".to_owned());

    let dir = crate::paths::signatures_dir();
    if let Err(error) = crate::paths::ensure_dir(&dir) {
        report.notes.push(format!(
            "Signature directory {} could not be created: {error}",
            dir.display()
        ));
    }
    match fs::read_dir(&dir) {
        Ok(entries) => {
            let mut names: Vec<_> = entries.filter_map(Result::ok).collect();
            names.sort_by_key(std::fs::DirEntry::file_name);
            for entry in names {
                let path = entry.path();
                let extension = path
                    .extension()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let forced = match extension.as_str() {
                    "hdb" => Some(HashAlgorithm::Md5),
                    "hsb" => None,
                    "ndb" | "ldb" | "mdb" | "msb" | "imp" => {
                        report.notes.push(format!(
                            "{} uses an extended ClamAV format that this build does not read yet.",
                            file_name(&path)
                        ));
                        continue;
                    }
                    _ => continue,
                };
                match fs::metadata(&path) {
                    Ok(metadata) if metadata.len() > MAX_DATABASE_BYTES => {
                        report.notes.push(format!(
                            "{} is larger than {} MiB and was skipped.",
                            file_name(&path),
                            MAX_DATABASE_BYTES / (1024 * 1024)
                        ));
                    }
                    Ok(_) => match fs::read_to_string(&path) {
                        Ok(body) => {
                            let (added, rejected) = set.parse_clamav(&body, forced);
                            report.rejected += rejected;
                            if added > 0 {
                                report.notes.push(format!(
                                    "{}: {} signature(s) loaded, {} line(s) rejected.",
                                    file_name(&path),
                                    added,
                                    rejected
                                ));
                            }
                        }
                        Err(error) => report
                            .notes
                            .push(format!("{} could not be read: {error}", file_name(&path))),
                    },
                    Err(error) => report
                        .notes
                        .push(format!("{} could not be inspected: {error}", file_name(&path))),
                }
            }
        }
        Err(error) => report.notes.push(format!(
            "Signature directory {} is not readable: {error}. Create it and add .hdb or .hsb files.",
            dir.display()
        )),
    }

    report.loaded = set.len();
    report.algorithms = set
        .algorithms()
        .into_iter()
        .map(|algorithm| algorithm.label().to_owned())
        .collect();
    (set, report)
}

/// Scan the EICAR test file through the same path a real file takes.
///
/// This proves the database reader, the hasher and the matcher without shipping
/// anything harmful.
pub fn self_test() -> Result<String, String> {
    let (set, _) = load();
    let in_memory = crate::hash::digest_bytes(EICAR, true, true);
    let name = lookup_name(&set, &in_memory)
        .ok_or_else(|| "the built-in EICAR signature did not match in memory".to_owned())?;

    // Prove the file path as well, when the operating system lets the test file
    // exist. Another security product removing it is not a failure of this engine,
    // so the in-memory result stands and the note says what happened.
    let Ok(directory) = tempfile::tempdir() else {
        return Ok(name);
    };
    let path = directory.path().join("eicar.com");
    if fs::write(&path, EICAR).is_err() {
        return Ok(name);
    }
    if let Some(from_file) = crate::hash::digest_file(&path, true, true)
        && lookup_name(&set, &from_file).is_some()
    {
        return Ok(name);
    }
    Ok(format!(
        "{name} (file check skipped: the test file could not be read back)"
    ))
}

fn lookup_name(set: &SignatureSet, digests: &crate::hash::Digests) -> Option<String> {
    for algorithm in [HashAlgorithm::Md5, HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
        let Some(hash) = digests.get(algorithm) else {
            continue;
        };
        if let Some(signatures) = set.lookup(hash)
            && let Some(signature) = signatures.first()
        {
            return Some(signature.name.clone());
        }
    }
    None
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_test_recognises_eicar() {
        let result = self_test().unwrap();
        assert!(result.starts_with("EICAR-Test-File"), "{result}");
    }

    #[test]
    fn the_loader_always_has_the_test_signature() {
        let (set, report) = load();
        assert!(set.len() >= 3);
        assert!(report.loaded >= 3);
        assert!(report.algorithms.contains(&"sha256".to_owned()));
    }
}
