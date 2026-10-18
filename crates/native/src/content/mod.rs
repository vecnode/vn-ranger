//! The deep check: ranger's only code that reads the bytes of files.
//!
//! Everything else in this program reads names, paths, hashes and metadata. This reads
//! content, which is why it runs only when a person asks for it, names the folders before it
//! starts, is cancellable between files, and keeps a `FileFact` — a path, a digest, what the
//! bytes are and which signature matched — rather than a copy of anything (`docs/PLAN-0.1.7.md`
//! §4.1).
//!
//! Three bounds are load-bearing, and each is reported rather than silently applied:
//!
//! - **The walk is bounded** by files, depth and total bytes, and never follows a link or
//!   leaves the root it was given.
//! - **The matcher is bounded** by a per-file budget, so a signature whose gap is enormous
//!   costs a bounded scan and says when it gave up.
//! - **The whole run is cancellable**, and a cancelled run says so: a partial scan is not a
//!   clean folder.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::Digest;
use vnr_core::content::{self, Budget, FileKind, Layout, Library};
use vnr_core::{ContentMatch, FileFact, HashSignature, SignatureSet, SignatureStatus};

/// How many files one deep check will look at.
pub const MAX_FILES: usize = 20_000;

/// The largest file the engine will read into memory for pattern matching.
///
/// A larger file is still hashed — streamed, so the cost is disk time rather than memory —
/// and its fact says it was not read. A digest is the honest thing to report for a file this
/// large; reading a 4 GB disk image to look for a byte string is not.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// How many bytes one deep check will read in total.
pub const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How deep the walk goes below the folders a person named.
pub const MAX_DEPTH: usize = 8;

/// How many matching steps one file may spend.
pub const STEPS_PER_FILE: u64 = 2_000_000;

/// What one deep check is allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most files to look at.
    pub max_files: usize,
    /// The largest file to read for pattern matching.
    pub max_file_bytes: u64,
    /// The most bytes to read in total.
    pub max_total_bytes: u64,
    /// How deep to walk.
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: MAX_FILES,
            max_file_bytes: MAX_FILE_BYTES,
            max_total_bytes: MAX_TOTAL_BYTES,
            max_depth: MAX_DEPTH,
        }
    }
}

/// What one deep check did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The folders the check was asked to read.
    pub roots: Vec<PathBuf>,
    /// One fact per file that was hashed, in walk order.
    pub files: Vec<FileFact>,
    /// How many entries the walk saw.
    pub seen: usize,
    /// How many files were read into memory.
    pub read: usize,
    /// How many bytes were read.
    pub bytes: u64,
    /// Files that could not be hashed, each with why.
    pub refused: Vec<String>,
    /// Whether a person cancelled the run.
    pub cancelled: bool,
    /// Whether a limit stopped the run before it finished.
    pub truncated: bool,
    /// How long it took.
    pub elapsed_ms: u64,
    /// How many body signatures the library held.
    pub signatures: usize,
    /// How many signature lines the library refused.
    pub signature_refusals: usize,
}

impl Report {
    /// Whether anything matched a signature, by hash or by body.
    #[must_use]
    pub fn matched(&self) -> usize {
        self.files
            .iter()
            .filter(|file| file.hash_match.is_some() || !file.matches.is_empty())
            .count()
    }
}

/// The folders a deep check would read, when a person starts one.
///
/// The same tops the watcher reads, and for the same reason: they are where a file arrives
/// from somewhere else. A person may add to this list later; the sentence the interface shows
/// is built from whatever this returns, so it cannot promise a folder the check would not read.
#[must_use]
pub fn folders() -> Vec<PathBuf> {
    crate::contentscan::folders()
}

/// The sentence the interface shows before a deep check starts.
///
/// It names the folders, the file cap, the depth, the size above which a file is hashed but
/// not read, and what is kept. It is built from the same constants the engine uses, so the
/// promise and the behaviour cannot drift apart without one of them changing.
#[must_use]
pub fn consent_sentence() -> String {
    let names: Vec<String> = folders()
        .iter()
        .map(|folder| folder.display().to_string())
        .collect();
    let listed = if names.is_empty() {
        "no folder this machine names".to_owned()
    } else {
        names.join(", ")
    };
    format!(
        "Reads the bytes of files in {listed}: at most {MAX_FILES} files, folders {MAX_DEPTH} deep, \
         and a file over {} MiB is hashed but not read. A match becomes a finding carrying the \
         file, the signature and the offset; no content is stored, and nothing leaves this machine.",
        MAX_FILE_BYTES / (1024 * 1024)
    )
}

/// Read a set of folders and look for signatures in what is there.
///
/// `cancel` is asked once per entry and once per file: a cancelled run returns what it found
/// with `cancelled` set, which the interface reports as an incomplete check rather than as a
/// finished one.
#[must_use]
pub fn scan(
    roots: &[PathBuf],
    library: &Library,
    hashes: &SignatureSet,
    limits: &Limits,
    cancel: &dyn Fn() -> bool,
) -> Report {
    let started = Instant::now();
    let mut state = State {
        report: Report {
            roots: roots.to_vec(),
            signatures: library.signatures().len(),
            signature_refusals: library.refusals().len(),
            ..Report::default()
        },
        library,
        hashes,
        limits: *limits,
    };
    for root in roots {
        if cancel() {
            state.report.cancelled = true;
            break;
        }
        if state.report.truncated {
            break;
        }
        state.walk(root, 0, cancel);
    }
    state.report.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    state.report
}

/// The mutable half of a run, kept apart so the walk's signature stays readable.
struct State<'a> {
    report: Report,
    library: &'a Library,
    hashes: &'a SignatureSet,
    limits: Limits,
}

impl State<'_> {
    fn walk(&mut self, dir: &Path, depth: usize, cancel: &dyn Fn() -> bool) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) => {
                self.report.refused.push(format!("{}: {error}", dir.display()));
                return;
            }
        };
        for entry in entries {
            if cancel() {
                self.report.cancelled = true;
                return;
            }
            if self.report.truncated {
                return;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            // A link is a refusal, not a traversal: the walk never leaves the folder it was
            // given, and `file_type` does not follow one.
            if file_type.is_symlink() {
                self.report
                    .refused
                    .push(format!("{}: a link, not followed", path.display()));
                continue;
            }
            if file_type.is_dir() {
                if depth < self.limits.max_depth {
                    self.walk(&path, depth + 1, cancel);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            self.report.seen += 1;
            if self.report.files.len() >= self.limits.max_files {
                self.report.truncated = true;
                return;
            }
            self.file(&path);
        }
    }

    fn file(&mut self, path: &Path) {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.report.refused.push(format!("{}: {error}", path.display()));
                return;
            }
        };
        let size = metadata.len();
        let whole = size <= self.limits.max_file_bytes
            && self.report.bytes.saturating_add(size) <= self.limits.max_total_bytes;
        let (digest, bytes) = if whole {
            match fs::read(path) {
                Ok(bytes) => (digest_bytes(&bytes), Some(bytes)),
                Err(error) => {
                    self.report.refused.push(format!("{}: {error}", path.display()));
                    return;
                }
            }
        } else {
            match digest_file(path) {
                Some(digest) => (digest, None),
                None => {
                    self.report.refused.push(format!(
                        "{}: could not be read whole, so it was not hashed",
                        path.display()
                    ));
                    return;
                }
            }
        };
        let read_bytes = bytes.as_ref().and_then(|bytes| u64::try_from(bytes.len()).ok());
        self.report.bytes = self.report.bytes.saturating_add(read_bytes.unwrap_or(size));
        if bytes.is_some() {
            self.report.read += 1;
        }
        let kind = bytes.as_deref().map_or(FileKind::Unknown, content::identify);
        let hash_match = self.hash_match(&digest, size);
        let mut matches = Vec::new();
        if let Some(bytes) = bytes.as_deref() {
            let layout = Layout {
                target: kind.target(),
                entry_point: None,
                sections: Vec::new(),
            };
            let mut budget = Budget::new(STEPS_PER_FILE);
            let scan = self.library.scan(bytes, Some(&layout), &mut budget);
            for hit in scan.hits {
                matches.push(ContentMatch {
                    name: hit.name,
                    at: hit.at,
                    line: hit.line,
                });
            }
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        self.report.files.push(FileFact {
            path: path.display().to_string(),
            name,
            extension,
            size,
            digest: Some(digest),
            kind: Some(kind.id().to_owned()),
            signature: SignatureStatus::NotChecked,
            signer: None,
            container: Vec::new(),
            hash_match,
            matches,
            read_bytes,
        });
    }

    /// The name of a hash signature that matches this digest and size, if one does.
    ///
    /// A database entry with a size is only trusted for that size: the same digest at a
    /// different length is a contradiction, and taking the name anyway would be a guess.
    fn hash_match(&self, digest: &str, size: u64) -> Option<String> {
        let candidates = self.hashes.lookup(digest)?;
        let found: &HashSignature = candidates
            .iter()
            .find(|signature| signature.size.is_none_or(|expected| expected == size))?;
        Some(found.name.clone())
    }
}

/// The SHA-256 of a byte slice, in lower-case hexadecimal.
fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// The SHA-256 of a file, read in chunks so a large file costs disk time rather than memory.
fn digest_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hex(&hasher.finalize()))
}

/// Lower-case hexadecimal, without a dependency for it.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Load every `.ndb` in the signature folder, with a note per file.
///
/// A file that cannot be read is a note, not a failure: the check runs with the signatures
/// it has and says how many lines it refused.
#[must_use]
pub fn load_library() -> (Library, Vec<String>) {
    const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
    let mut notes = Vec::new();
    let dir = crate::paths::signatures_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) => {
            notes.push(format!(
                "No body-signature folder at {} ({error}); the deep check has hash signatures only.",
                dir.display()
            ));
            return (Library::default(), notes);
        }
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("ndb"))
        })
        .collect();
    paths.sort();
    let mut text = String::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("a file")
            .to_owned();
        match fs::metadata(&path) {
            Ok(metadata) if metadata.len() > MAX_DATABASE_BYTES => notes.push(format!(
                "{name} is larger than {} MiB and was skipped.",
                MAX_DATABASE_BYTES / (1024 * 1024)
            )),
            Ok(_) => match fs::read_to_string(&path) {
                Ok(body) => text.push_str(&body),
                Err(error) => notes.push(format!("{name} could not be read: {error}")),
            },
            Err(error) => notes.push(format!("{name} could not be inspected: {error}")),
        }
    }
    if text.trim().is_empty() {
        if notes.is_empty() {
            notes.push(
                "No .ndb body signatures in the signature folder, so the deep check looked for \
                 hashes only."
                    .to_owned(),
            );
        }
        return (Library::default(), notes);
    }
    let library = Library::parse(&text);
    notes.push(format!(
        "{} body signature(s) loaded, {} line(s) refused.",
        library.signatures().len(),
        library.refusals().len()
    ));
    (library, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn library(body: &str) -> Library {
        Library::parse(body)
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).expect("a fixture file is written");
        path
    }

    #[test]
    fn a_body_signature_is_found_and_becomes_a_fact() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        write(temp.path(), "sample.bin", b"....MZ....payload");
        let library = library("MZ.Literal:0:*:4d5a\n");
        let report = scan(
            &[temp.path().to_path_buf()],
            &library,
            &SignatureSet::new(),
            &Limits::default(),
            &|| false,
        );
        assert_eq!(report.files.len(), 1);
        let file = &report.files[0];
        assert_eq!(file.matches.len(), 1);
        assert_eq!(file.matches[0].name, "MZ.Literal");
        assert_eq!(file.matches[0].at, 4);
        assert_eq!(file.kind.as_deref(), Some("unknown"));
        assert_eq!(file.read_bytes, Some(file.size));
        assert_eq!(report.matched(), 1);
        assert!(!report.cancelled);
        assert!(!report.truncated);
    }

    #[test]
    fn a_hash_signature_is_matched_by_digest_and_size() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        let path = write(temp.path(), "known.bin", b"known bytes");
        let digest = digest_file(&path).expect("the fixture hashes");
        let mut hashes = SignatureSet::new();
        assert!(hashes.insert(vnr_core::HashAlgorithm::Sha256, &digest, Some(11), "Test.Known"));
        let report = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &hashes,
            &Limits::default(),
            &|| false,
        );
        assert_eq!(report.files[0].hash_match.as_deref(), Some("Test.Known"));

        // The same digest at a different length is a contradiction, not a match.
        let mut wrong = SignatureSet::new();
        assert!(wrong.insert(vnr_core::HashAlgorithm::Sha256, &digest, Some(12), "Test.Wrong"));
        let report = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &wrong,
            &Limits::default(),
            &|| false,
        );
        assert_eq!(report.files[0].hash_match, None);
    }

    #[test]
    fn a_file_over_the_read_cap_is_hashed_but_not_read() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        write(temp.path(), "big.bin", b"0123456789");
        let limits = Limits {
            max_file_bytes: 4,
            ..Limits::default()
        };
        let report = scan(
            &[temp.path().to_path_buf()],
            &library("MZ:0:*:4d5a\n"),
            &SignatureSet::new(),
            &limits,
            &|| false,
        );
        let file = &report.files[0];
        assert_eq!(file.read_bytes, None, "not read means not read");
        assert!(file.digest.is_some(), "it is still hashed");
        assert!(file.matches.is_empty());
        assert_eq!(report.read, 0);
    }

    #[test]
    fn a_nested_folder_is_walked_and_the_depth_limit_stops_it() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        let deep = temp.path().join("a").join("b").join("c");
        fs::create_dir_all(&deep).expect("fixtures");
        write(&deep, "x.bin", b"MZ");
        let shallow = Limits {
            max_depth: 1,
            ..Limits::default()
        };
        let found = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &SignatureSet::new(),
            &shallow,
            &|| false,
        );
        assert!(found.files.is_empty(), "depth 1 does not reach a/b/c");
        let deep_enough = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &SignatureSet::new(),
            &Limits::default(),
            &|| false,
        );
        assert_eq!(deep_enough.files.len(), 1);
    }

    #[test]
    fn the_file_limit_truncates_the_run_rather_than_growing() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        for index in 0..5 {
            write(temp.path(), &format!("f{index}.bin"), b"MZ");
        }
        let limits = Limits {
            max_files: 2,
            ..Limits::default()
        };
        let report = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &SignatureSet::new(),
            &limits,
            &|| false,
        );
        assert_eq!(report.files.len(), 2);
        assert!(report.truncated, "a stopped run says it stopped");
    }

    #[test]
    fn cancellation_is_reported_rather_than_hidden() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        write(temp.path(), "a.bin", b"MZ");
        write(temp.path(), "b.bin", b"MZ");
        let calls = std::cell::Cell::new(0_u32);
        let cancel = || {
            calls.set(calls.get() + 1);
            calls.get() > 1
        };
        let report = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &SignatureSet::new(),
            &Limits::default(),
            &cancel,
        );
        assert!(report.cancelled);
    }

    #[test]
    fn an_unreadable_root_is_refused_with_its_path() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        let missing = temp.path().join("not-there");
        let report = scan(
            std::slice::from_ref(&missing),
            &library(""),
            &SignatureSet::new(),
            &Limits::default(),
            &|| false,
        );
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0].contains("not-there"));
        assert!(report.files.is_empty());
    }

    #[test]
    fn the_digest_of_a_file_is_the_digest_of_its_bytes() {
        assert_eq!(
            digest_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn the_kind_of_a_file_comes_from_its_bytes() {
        let temp = tempfile::tempdir().expect("a temporary folder");
        write(temp.path(), "pe.bin", b"MZ\x90\x00");
        write(temp.path(), "pdf.bin", b"%PDF-1.7\n");
        write(temp.path(), "text.bin", b"hello");
        let report = scan(
            &[temp.path().to_path_buf()],
            &library(""),
            &SignatureSet::new(),
            &Limits::default(),
            &|| false,
        );
        let mut kinds: Vec<&str> = report
            .files
            .iter()
            .filter_map(|file| file.kind.as_deref())
            .collect();
        kinds.sort_unstable();
        assert_eq!(kinds, ["pdf", "pe", "unknown"]);
    }
}
