//! One folder a person can hand to somebody else.
//!
//! A finding on screen is worth what a person can carry out of the program: to a colleague, a
//! ticket, or their own notes a week later. This module writes one folder with the evidence in
//! it — the snapshot, the findings as Markdown, the timeline as CSV, and a manifest that names
//! the hash and size of every file inside — plus a README that says what the folder is and
//! what it is not.
//!
//! Nothing leaves this machine. The folder is written where ranger keeps its own data, the
//! caller says where that is, and the manifest is written last so that it covers what is
//! actually there rather than what was intended.

use std::path::{Path, PathBuf};

use sha2::Digest as _;
use vnr_core::{Finding, Snapshot};

/// One export, as it ended up on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// The folder written.
    pub folder: PathBuf,
    /// Every file in it, in the order the manifest lists them.
    pub files: Vec<File>,
}

/// One file inside an export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    /// Its name, without the folder.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, as lower-case hexadecimal.
    pub sha256: String,
}

impl Package {
    /// The total size of everything written.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|file| file.size).sum()
    }
}

/// The folder name for one export: `triage-<utc>`, sortable and unambiguous.
#[must_use]
pub fn folder_name(now_unix: u64) -> String {
    let stamp = vnr_core::time::format_utc(now_unix);
    // `2026-10-20 10:15:00` becomes `20261020T101500Z`: the digits keep their order, and the
    // `T` and `Z` make it an instant rather than a local reading.
    let digits: String = stamp.chars().filter(char::is_ascii_digit).collect();
    if digits.len() >= 12 {
        format!("triage-{}T{}Z", &digits[..8], &digits[8..12])
    } else {
        format!("triage-{digits}Z")
    }
}

/// Write one export folder.
///
/// `timeline_csv` is the caller's, because the timeline is the session's rather than the
/// snapshot's. A folder that already exists is refused rather than merged: two exports in one
/// folder would make the manifest a lie.
pub fn write(
    parent: &Path,
    snapshot: &Snapshot,
    findings: &[Finding],
    timeline_csv: &str,
    now_unix: u64,
) -> std::io::Result<Package> {
    let folder = parent.join(folder_name(now_unix));
    std::fs::create_dir_all(parent)?;
    if folder.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", folder.display()),
        ));
    }
    std::fs::create_dir(&folder)?;

    let snapshot_json =
        serde_json::to_vec_pretty(snapshot).map_err(|error| std::io::Error::other(error.to_string()))?;
    let findings_md = vnr_core::report::to_markdown(snapshot, findings);
    let readme_md = readme(snapshot, findings);
    let mut files = vec![
        write_one(&folder, "snapshot.json", &snapshot_json)?,
        write_one(&folder, "findings.md", findings_md.as_bytes())?,
        write_one(&folder, "timeline.csv", timeline_csv.as_bytes())?,
        write_one(&folder, "README.md", readme_md.as_bytes())?,
    ];

    // The manifest is written last and lists everything above it, so that checking the folder
    // is one command against one file.
    let mut manifest = String::from(
        "# vn-ranger triage export\n\
         # sha256, bytes, name\n",
    );
    for file in &files {
        manifest.push_str(&format!("{}  {}  {}\n", file.sha256, file.size, file.name));
    }
    manifest.push_str(&format!(
        "\n{} file(s), {} byte(s)\n",
        files.len(),
        files.iter().map(|f| f.size).sum::<u64>()
    ));
    files.push(write_one(&folder, "manifest.txt", manifest.as_bytes())?);

    Ok(Package { folder, files })
}

/// Write one file and describe it.
fn write_one(folder: &Path, name: &str, bytes: &[u8]) -> std::io::Result<File> {
    let path: PathBuf = folder.join(name);
    std::fs::write(&path, bytes)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    Ok(File {
        name: name.to_owned(),
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

/// What the folder is, and what it is not.
///
/// The two paragraphs that matter are the last two: what this program did **not** read, taken
/// from the collectors' own statuses, and the sentence that a clean result is a statement
/// about a database rather than about the machine.
fn readme(snapshot: &Snapshot, findings: &[Finding]) -> String {
    let mut out = String::from("# vn-ranger triage export\n\n");
    out.push_str(&format!(
        "Host: {} {} ({})\n\nTaken: {}\n\nScan: {} · {} processes · {} startup items · {} \
         listeners · {} connections · {} packages · {} agent configurations\n\n",
        snapshot.host.os,
        snapshot.host.arch,
        if snapshot.elevated {
            "administrator"
        } else {
            "as the signed-in user"
        },
        vnr_core::time::format_utc(snapshot.taken_at_unix),
        snapshot.profile.label(),
        snapshot.processes.len(),
        snapshot.autoruns.len(),
        snapshot.listeners.len(),
        snapshot.flows.len(),
        snapshot.packages.len(),
        snapshot.agents.len(),
    ));
    out.push_str(&format!(
        "## What is in this folder\n\n\
         - `snapshot.json` — every fact this scan collected, as ranger holds it.\n\
         - `findings.md` — {} finding(s), each with its evidence and the most likely benign \
         explanation.\n\
         - `timeline.csv` — what changed while ranger was watching, in UTC.\n\
         - `manifest.txt` — the SHA-256 and size of every file here.\n\n",
        findings.len()
    ));
    out.push_str(
        "## What this is not\n\n\
         A clean result means nothing in this program's database matched. It does not mean the \
         machine is clean, and it is not a diagnosis: it is a statement about a database and \
         the files that were read against it.\n\n\
         Nothing in this folder was sent anywhere. It was written to this machine's own data \
         directory, and it is yours to keep, move or delete.\n\n",
    );
    out.push_str("## What was not read, in the collectors' own words\n\n");
    for collector in &snapshot.collectors {
        let state = collector.state.label();
        let note = collector.reason.as_deref().unwrap_or("no note");
        out.push_str(&format!(
            "- {} ({}) — {}: {note}\n",
            collector.label, collector.id, state
        ));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::Host;

    fn snapshot() -> Snapshot {
        let mut snapshot = Snapshot::empty(Host::default(), false);
        snapshot.taken_at_unix = 1_700_000_000;
        snapshot.collectors.push(vnr_core::CollectorStatus::unavailable(
            "events",
            "Event records",
            "This build does not read the operating system's logs.",
        ));
        snapshot
    }

    #[test]
    fn one_export_has_a_manifest_that_covers_every_file_it_wrote() {
        let parent = tempfile::tempdir().unwrap();
        let package = write(
            parent.path(),
            &snapshot(),
            &[],
            "at,utc,kind,subject,detail,source\n",
            1_700_000_000,
        )
        .expect("the export");
        assert!(package.folder.ends_with("triage-20231114T2213Z"));
        let named: Vec<&str> = package.files.iter().map(|file| file.name.as_str()).collect();
        assert_eq!(
            named,
            [
                "snapshot.json",
                "findings.md",
                "timeline.csv",
                "README.md",
                "manifest.txt"
            ]
        );
        // The manifest is the last file and lists the four before it.
        let manifest = std::fs::read_to_string(package.folder.join("manifest.txt")).expect("read");
        for file in package.files.iter().filter(|file| file.name != "manifest.txt") {
            assert!(
                manifest.contains(&file.sha256),
                "{} is in the manifest",
                file.name
            );
        }
        // Every hash in it is the hash of the file that is there.
        for file in package.files.iter().filter(|file| file.name != "manifest.txt") {
            let bytes = std::fs::read(package.folder.join(&file.name)).expect("read");
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            let digest: String = hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(digest, file.sha256, "{} hashes as listed", file.name);
        }
        assert!(package.bytes() > 0);
    }

    #[test]
    fn the_readme_says_what_was_not_read() {
        let parent = tempfile::tempdir().unwrap();
        let package = write(parent.path(), &snapshot(), &[], "at\n", 1_700_000_000).expect("export");
        let readme = std::fs::read_to_string(package.folder.join("README.md")).expect("read");
        assert!(readme.contains("does not read the operating system's logs"));
        assert!(readme.contains("does not mean the machine is clean"));
        assert!(readme.contains("Nothing in this folder was sent anywhere"));
    }

    #[test]
    fn a_second_export_in_the_same_second_is_refused_rather_than_merged() {
        let parent = tempfile::tempdir().unwrap();
        assert!(write(parent.path(), &snapshot(), &[], "at\n", 1_700_000_000).is_ok());
        assert!(
            write(parent.path(), &snapshot(), &[], "at\n", 1_700_000_000).is_err(),
            "two exports in one folder would make the manifest untrue"
        );
    }

    #[test]
    fn a_folder_name_sorts_and_names_no_timezone() {
        assert_eq!(folder_name(0), "triage-19700101T0000Z");
        assert!(
            folder_name(1_700_000_060) > folder_name(1_700_000_000),
            "a later minute sorts later"
        );
        assert_eq!(
            folder_name(1_700_000_001),
            folder_name(1_700_000_000),
            "the name is accurate to the minute, which is what format_utc gives"
        );
    }
}
