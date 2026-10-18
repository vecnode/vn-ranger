//! What a container holds, read in memory and never unpacked to disk.
//!
//! A dropper shipped as a `.zip`, an `.iso`, a macro document or an installer is the ordinary
//! shape of malware distribution, and a scanner that only reads the outer file sees none of
//! it. This module reads the bytes an archive holds and hands them to the signature engine as
//! memory, so nothing is ever extracted: there is no folder to clean, no file to leave behind
//! and no path for an archive to write through.
//!
//! Everything is bounded, because an archive is attacker-controlled input:
//!
//! * at most [`MAX_MEMBERS`] members are read from one container;
//! * no member above [`MAX_MEMBER_BYTES`], and no more than [`MAX_TOTAL_BYTES`] from one
//!   container;
//! * a member that claims more than [`MAX_RATIO`] bytes for every byte it occupies on disk is
//!   not read — that is what a decompression bomb looks like;
//! * containment is followed [`MAX_DEPTH`] deep, so an archive of archives ends.
//!
//! What was skipped is reported, not hidden: "the ratio cap stopped one member" is a fact a
//! person can act on, and the alternative is an archive that looks empty.

use std::io::{Cursor, Read};

/// The most members one container contributes.
pub const MAX_MEMBERS: usize = 32;

/// The largest member that is read, in bytes.
pub const MAX_MEMBER_BYTES: u64 = 16 * 1024 * 1024;

/// The most bytes one container contributes in total.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// The most a member may claim per byte it occupies, before it is treated as a bomb.
pub const MAX_RATIO: u64 = 200;

/// How deep a container inside a container is followed.
pub const MAX_DEPTH: u32 = 3;

/// One file read out of a container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Its name inside the container, as the container spells it.
    pub name: String,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

impl Member {
    /// The size of the member, in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }
}

/// What a container gave up.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expansion {
    /// The members that were read.
    pub members: Vec<Member>,
    /// What was skipped, and why, in words the report shows.
    pub notes: Vec<String>,
}

/// Whether a name looks like a container this build reads.
///
/// The extension is a hint and not a decision: a `.zip` that is not one is refused by the
/// parser, and the caller reports that refusal rather than pretending the file held nothing.
#[must_use]
pub fn is_container(name: &str) -> bool {
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    matches!(
        extension.as_deref(),
        Some(
            "zip"
                | "jar"
                | "xpi"
                | "docx"
                | "xlsx"
                | "pptx"
                | "odt"
                | "ods"
                | "odp"
                | "epub"
                | "apk"
                | "vsix"
                | "nupkg"
                | "whl"
                | "egg"
                | "aar"
                | "ipa"
                | "doc"
                | "xls"
                | "ppt"
                | "msi"
                | "msg"
                | "vsd"
        )
    )
}

/// Whether a member may be read, given what it claims and what has been read already.
///
/// A pure function so the cap can be tested without building a two-gigabyte archive.
pub fn member_allowed(declared: u64, compressed: u64, read_so_far: u64) -> Result<(), &'static str> {
    if declared > MAX_MEMBER_BYTES {
        return Err("it is larger than a member ranger reads");
    }
    if declared > compressed.saturating_mul(MAX_RATIO) && declared > 1024 * 1024 {
        return Err("it claims far more than it occupies, which is how a bomb looks");
    }
    if read_so_far.saturating_add(declared) > MAX_TOTAL_BYTES {
        return Err("the container's total is larger than ranger reads");
    }
    Ok(())
}

/// Read what a container holds.
///
/// A container this build cannot open is an error, not an empty expansion: "unreadable" and
/// "empty" are different answers and a person acts on them differently.
pub fn expand(name: &str, bytes: &[u8]) -> Result<Expansion, String> {
    if !is_container(name) {
        return Err("not a container this build reads".to_owned());
    }
    let mut expansion = Expansion::default();
    if !read_zip(name, bytes, &mut expansion)? {
        read_ole(name, bytes, &mut expansion)?;
    }
    if expansion.members.is_empty() && expansion.notes.is_empty() {
        expansion
            .notes
            .push(format!("{name}: the container held no file ranger reads"));
    }
    Ok(expansion)
}

/// Read a zip-shaped container. `Ok(false)` means it was not one.
fn read_zip(name: &str, bytes: &[u8], expansion: &mut Expansion) -> Result<bool, String> {
    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(archive) => archive,
        Err(zip::result::ZipError::InvalidArchive(_)) | Err(zip::result::ZipError::UnsupportedArchive(_)) => {
            return Ok(false);
        }
        Err(error) => return Err(format!("{name}: {error}")),
    };
    let mut read_so_far = 0_u64;
    for index in 0..archive.len().min(MAX_MEMBERS) {
        let entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                expansion
                    .notes
                    .push(format!("{name}: one member could not be opened ({error})"));
                continue;
            }
        };
        if entry.is_dir() {
            continue;
        }
        let member_name = match entry.name() {
            Ok(name) => name.to_string(),
            Err(error) => {
                expansion.notes.push(format!(
                    "{name}: one member has a name ranger cannot read ({error})"
                ));
                continue;
            }
        };
        let declared = entry.size();
        let compressed = entry.compressed_size();
        if let Err(reason) = member_allowed(declared, compressed, read_so_far) {
            expansion
                .notes
                .push(format!("{name}: {member_name} was not read because {reason}"));
            continue;
        }
        let mut body = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
        if let Err(error) = entry.take(declared.saturating_add(1)).read_to_end(&mut body) {
            expansion
                .notes
                .push(format!("{name}: {member_name} could not be read ({error})"));
            continue;
        }
        if u64::try_from(body.len()).unwrap_or(u64::MAX) != declared {
            expansion.notes.push(format!(
                "{name}: {member_name} holds less than it claims, so it was not scanned"
            ));
            continue;
        }
        read_so_far = read_so_far.saturating_add(declared);
        expansion.members.push(Member {
            name: member_name,
            bytes: body,
        });
    }
    if archive.len() > MAX_MEMBERS {
        expansion.notes.push(format!(
            "{name}: only the first {MAX_MEMBERS} of {} member(s) were read",
            archive.len()
        ));
    }
    Ok(true)
}

/// Read an OLE (`cfb`) container: the shape a macro document and an installer have.
fn read_ole(name: &str, bytes: &[u8], expansion: &mut Expansion) -> Result<(), String> {
    // A file that is neither zip nor OLE is simply not a container ranger opens; the caller
    // has already been told the name looked like one, and this is the answer.
    let Ok(mut compound) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
        return Ok(());
    };
    let mut paths: Vec<String> = Vec::new();
    for entry in compound.walk() {
        if entry.is_stream() {
            paths.push(entry.path().to_string_lossy().replace('\\', "/"));
        }
        if paths.len() >= MAX_MEMBERS {
            break;
        }
    }
    let mut read_so_far = 0_u64;
    for path in paths {
        let stream = match compound.open_stream(&path) {
            Ok(stream) => stream,
            Err(error) => {
                expansion
                    .notes
                    .push(format!("{name}: {path} could not be opened ({error})"));
                continue;
            }
        };
        let declared = stream.len();
        // An OLE stream reports its own length and stores it uncompressed, so the ratio cap
        // has nothing to say here; the size and total caps still do.
        if let Err(reason) = member_allowed(declared, declared.max(1), read_so_far) {
            expansion
                .notes
                .push(format!("{name}: {path} was not read because {reason}"));
            continue;
        }
        let mut body = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
        if let Err(error) = stream.take(declared.saturating_add(1)).read_to_end(&mut body) {
            expansion
                .notes
                .push(format!("{name}: {path} could not be read ({error})"));
            continue;
        }
        read_so_far = read_so_far.saturating_add(u64::try_from(body.len()).unwrap_or(0));
        expansion.members.push(Member {
            name: path,
            bytes: body,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_is_bounded_by_size_ratio_and_total() {
        assert_eq!(member_allowed(1024, 1024, 0), Ok(()));
        assert!(
            member_allowed(MAX_MEMBER_BYTES + 1, MAX_MEMBER_BYTES + 1, 0).is_err(),
            "a member above the cap is not read"
        );
        assert!(
            member_allowed(8 * 1024 * 1024, 1024, 0).is_err(),
            "8 MB from 1 KB compressed is a bomb"
        );
        assert!(
            member_allowed(1024, 1, 0).is_ok(),
            "a small member with a large ratio is ordinary text compressing well"
        );
        assert!(
            member_allowed(2 * 1024 * 1024, 2 * 1024 * 1024, MAX_TOTAL_BYTES).is_err(),
            "the container's total is capped"
        );
    }

    #[test]
    fn only_container_names_are_opened() {
        for name in ["a.zip", "b.ZIP", "c.docx", "d.jar", "e.msi", "f.doc"] {
            assert!(is_container(name), "{name} looks like a container");
        }
        for name in ["a.exe", "b.txt", "c", "d.zip.txt", "e.pdf"] {
            assert!(!is_container(name), "{name} is not one ranger opens");
        }
    }

    #[test]
    fn a_zip_round_trips_through_memory() {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;

        const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("inside/payload.txt", SimpleFileOptions::default())
            .expect("a member");
        writer.write_all(EICAR.as_bytes()).expect("its bytes");
        let bytes = writer.finish().expect("a finished archive").into_inner();

        let expansion = expand("test.zip", &bytes).expect("a zip is read");
        assert_eq!(expansion.members.len(), 1);
        assert_eq!(expansion.members[0].name, "inside/payload.txt");
        assert_eq!(expansion.members[0].bytes, EICAR.as_bytes());
        assert!(expansion.members[0].size() > 0);
    }

    #[test]
    fn a_file_that_is_not_a_container_is_refused_rather_than_reported_empty() {
        assert!(
            expand("test.zip", b"not a zip at all").is_ok(),
            "the name decides"
        );
        let expansion = expand("test.zip", b"not a zip at all").expect("read");
        assert!(expansion.members.is_empty());
        assert!(
            !expansion.notes.is_empty(),
            "an unreadable container says so rather than looking empty"
        );
        assert!(expand("test.exe", b"anything").is_err());
    }
}
