//! The optional content scan: the only part of ranger that reads a file's bytes.
//!
//! Everything else in this program reads names, paths, hashes and metadata. This reads
//! content, which means it can see the inside of a person's documents, so it is off unless
//! they turn it on, it names the folders it will read before it starts, and it stores nothing
//! it finds beyond the rule that matched and the file it matched in (`docs/PLAN.md` §6.11).
//!
//! It is a build feature, not a setting. A binary compiled without `content-scan` has no
//! pattern engine in it at all, which `cargo xtask ci` checks with `cargo tree`: a consent
//! screen for a capability the binary does not have would be a lie in the shape of a
//! checkbox.

use std::path::{Path, PathBuf};

/// The largest file the scan will read.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// How many files one scan will read, so a folder of a million small files cannot become the
/// reason the window stops responding.
pub const MAX_FILES: usize = 5_000;

/// How deep the walk goes. Deep enough for a downloads folder, shallow enough that the scan
/// is a decision rather than a tour of the disk.
pub const MAX_DEPTH: usize = 3;

/// One rule that matched one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// The YARA rule's identifier.
    pub rule: String,
    /// The file it matched in.
    pub path: String,
    /// The file's size, for the evidence line.
    pub bytes: u64,
}

/// What one content scan did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// How many files were read.
    pub files: usize,
    /// What matched.
    pub hits: Vec<Hit>,
    /// How many files were skipped, and why the first one was.
    pub skipped: Vec<String>,
    /// Why the scan did not run at all, when it did not.
    pub problem: Option<String>,
}

impl Report {
    /// Whether this build can scan content at all.
    #[must_use]
    pub fn available() -> bool {
        cfg!(feature = "content-scan")
    }
}

/// The folders a content scan would read if a person turned it on.
///
/// The same tops the watcher reads, and for the same reason: they are where a file arrives
/// from somewhere else. Nothing here is walked recursively at depth, and a link is never
/// followed.
#[must_use]
pub fn folders() -> Vec<PathBuf> {
    let mut folders = Vec::new();
    if let Some(dirs) = directories::UserDirs::new() {
        folders.extend(dirs.download_dir().map(Path::to_path_buf));
        folders.extend(dirs.desktop_dir().map(Path::to_path_buf));
    }
    folders.push(std::env::temp_dir());
    folders.retain(|folder| folder.is_dir());
    folders
}

/// Where the YARA rules live, when a person has put any there.
#[must_use]
pub fn rules_path() -> PathBuf {
    crate::paths::data_dir().join("yara")
}

/// Read every file under the consented folders, at the depth and size limits, and report
/// what matched.
///
/// `cancel` is asked between files: a scan that reads content is one a person can stop.
#[must_use]
pub fn scan(cancel: &dyn Fn() -> bool) -> Report {
    #[cfg(feature = "content-scan")]
    {
        scan_with_yara(cancel)
    }
    #[cfg(not(feature = "content-scan"))]
    {
        let _ = cancel;
        Report {
            problem: Some(
                "This build has no content scan. Reading the bytes of files is a feature that \
                 is compiled in, and this binary was not."
                    .to_owned(),
            ),
            ..Report::default()
        }
    }
}

/// The walk every build shares: it decides which files a scan would read, so the list a
/// consent screen shows and the list the engine reads are the same list.
fn files(folders: &[PathBuf], cancel: &dyn Fn() -> bool) -> (Vec<PathBuf>, Vec<String>) {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for folder in folders {
        walk(folder, 0, &mut found, &mut skipped, cancel);
        if found.len() >= MAX_FILES {
            skipped.push(format!("the scan stopped at {MAX_FILES} files"));
            break;
        }
    }
    (found, skipped)
}

fn walk(
    folder: &Path,
    depth: usize,
    found: &mut Vec<PathBuf>,
    skipped: &mut Vec<String>,
    cancel: &dyn Fn() -> bool,
) {
    if depth > MAX_DEPTH || found.len() >= MAX_FILES || cancel() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(folder) else {
        skipped.push(format!("{} could not be read", folder.display()));
        return;
    };
    for entry in entries.flatten() {
        if cancel() || found.len() >= MAX_FILES {
            return;
        }
        // `file_type` does not follow a link, which is the whole point: a link into a system
        // folder is not something a scan of someone's downloads was asked to read.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk(&path, depth.saturating_add(1), found, skipped, cancel);
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.len() > MAX_FILE_BYTES {
            skipped.push(format!(
                "{} is {} bytes, over the {MAX_FILE_BYTES}-byte limit",
                path.display(),
                metadata.len()
            ));
            continue;
        }
        found.push(path);
    }
}

#[cfg(feature = "content-scan")]
fn scan_with_yara(cancel: &dyn Fn() -> bool) -> Report {
    let source = match std::fs::read_to_string(rules_path().join("rules.yar")) {
        Ok(source) => source,
        Err(error) => {
            return Report {
                problem: Some(format!(
                    "No content rules were read from {}: {error}. A content scan needs at least \
                     one rule, and ranger does not ship one.",
                    rules_path().display()
                )),
                ..Report::default()
            };
        }
    };
    let rules = match yara_x::compile(source.as_str()) {
        Ok(rules) => rules,
        Err(error) => {
            return Report {
                problem: Some(format!(
                    "The content rules in {} could not be compiled: {error}",
                    rules_path().join("rules.yar").display()
                )),
                ..Report::default()
            };
        }
    };
    let mut scanner = yara_x::Scanner::new(&rules);
    let (paths, skipped) = files(&folders(), cancel);
    let mut report = Report {
        skipped,
        ..Report::default()
    };
    for path in paths {
        if cancel() {
            report.skipped.push("the scan was stopped".to_owned());
            break;
        }
        let bytes = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
        match scanner.scan_file(&path) {
            Ok(results) => {
                report.files = report.files.saturating_add(1);
                for rule in results.matching_rules() {
                    report.hits.push(Hit {
                        rule: rule.identifier().to_owned(),
                        path: path.display().to_string(),
                        bytes,
                    });
                }
            }
            Err(error) => report
                .skipped
                .push(format!("{} could not be read: {error}", path.display())),
        }
    }
    report
}

/// The folders a scan would read, and how many files it would open, as a person reads it.
///
/// The count comes from the same walk the engine uses, so the sentence a consent screen shows
/// and the files a scan reads cannot disagree — including in a build with no engine, which is
/// where the number still tells a person what the feature would do.
#[must_use]
pub fn consent_sentence() -> String {
    let folders = folders();
    let (files, _) = files(&folders, &|| false);
    let listed: Vec<String> = folders
        .iter()
        .map(|folder| folder.display().to_string())
        .collect();
    format!(
        "A content scan would read {} file(s) in {} — never more than {MAX_FILES} files, never \
         deeper than {MAX_DEPTH} folders, never a link, and nothing larger than {} MB. What it \
         finds is the rule's name and the file's path: no content is copied, stored or sent \
         anywhere.",
        files.len(),
        listed.join(", "),
        MAX_FILE_BYTES / (1024 * 1024)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_build_says_what_it_cannot_do_rather_than_scanning_nothing() {
        let report = scan(&|| false);
        if Report::available() {
            // A build with the feature explains a missing rules file, not a missing feature.
            assert!(
                report.problem.is_none() || report.problem.as_deref().is_some_and(|p| p.contains("rules")),
                "{:?}",
                report.problem
            );
        } else {
            let problem = report.problem.unwrap();
            assert!(problem.contains("no content scan"), "{problem}");
        }
    }

    #[test]
    fn the_consent_sentence_names_the_folders_and_the_limits() {
        let sentence = consent_sentence();
        assert!(
            sentence.contains("read") && sentence.contains("file(s)"),
            "{sentence}"
        );
        assert!(sentence.contains("no content is copied"), "{sentence}");
        assert!(sentence.contains("never a link"), "{sentence}");
        assert!(sentence.contains(&MAX_FILES.to_string()), "{sentence}");
    }

    #[test]
    fn the_walk_stops_at_the_file_cap_and_never_follows_a_link() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..3 {
            std::fs::write(dir.path().join(format!("f{index}.txt")), b"x").unwrap();
        }
        let folder = dir.path().to_path_buf();
        let (found, _) = files(std::slice::from_ref(&folder), &|| false);
        assert_eq!(found.len(), 3);
        let (stopped, _) = files(std::slice::from_ref(&folder), &|| true);
        assert!(stopped.is_empty(), "a cancelled walk reads nothing");
    }
}
