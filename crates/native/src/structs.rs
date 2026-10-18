//! The shape of an executable, read from its own header.
//!
//! A hash says "this is a file we know". A header says what the file *is*: how many sections
//! it declares, whether any of them are both writable and executable, how much of it is
//! high-entropy data, what it imports, whether something was appended after the last section,
//! and whether a signature blob is present. Those are the facts a packer, a dropper and an
//! ordinary installer differ in — and each one is checkable by a person with a hex editor,
//! which is the standard this program holds itself to.
//!
//! Nothing here decides anything. `object` parses the header; this module turns it into the
//! bounded struct a rule can match, and every number it reports is a count of something in
//! the file rather than an opinion about it.

use vnr_core::model::Structure;

/// How many imported names the family hash covers.
///
/// The open-source convention hashes the whole import table; a cap keeps a file that imports
/// thirty thousand names from costing more than the scan it is part of.
pub const MAX_IMPORTS: usize = 4_096;

/// Read the structure of an executable, when the bytes are one.
///
/// `None` means "not an executable this build reads". A header that parses but holds nothing
/// recognisable is still a `Structure`, with zeros: the file *is* an executable and saying so
/// is true.
#[must_use]
pub fn read(bytes: &[u8]) -> Option<Structure> {
    use object::Object as _;
    use object::ObjectSection as _;

    let file = object::File::parse(bytes).ok()?;
    let format = match file.format() {
        object::BinaryFormat::Pe => "pe",
        object::BinaryFormat::Elf => "elf",
        object::BinaryFormat::MachO => "macho",
        _ => return None,
    };
    let machine = Some(format!("{:?}", file.architecture()).to_lowercase());
    let mut sections = 0_u32;
    let mut writable_executable = 0_u32;
    let mut max_entropy_x100 = 0_u16;
    let mut end_of_sections = 0_u64;
    for section in file.sections() {
        sections = sections.saturating_add(1);
        if section.kind() == object::SectionKind::Text {
            // counted, not judged: the entropy below is what makes a packed section visible
        }
        let (executable, writable) = match section.flags() {
            object::SectionFlags::Coff { characteristics } => (
                characteristics.0 & object::pe::IMAGE_SCN_MEM_EXECUTE.0 != 0,
                characteristics.0 & object::pe::IMAGE_SCN_MEM_WRITE.0 != 0,
            ),
            object::SectionFlags::Elf { sh_flags, .. } => (
                sh_flags.0 & object::elf::SHF_EXECINSTR.0 != 0,
                sh_flags.0 & object::elf::SHF_WRITE.0 != 0,
            ),
            _ => (section.kind() == object::SectionKind::Text, false),
        };
        if executable && writable {
            writable_executable = writable_executable.saturating_add(1);
        }
        if let Ok(data) = section.data() {
            let entropy = entropy_x100(data);
            max_entropy_x100 = max_entropy_x100.max(entropy);
            end_of_sections = end_of_sections.max(
                section
                    .file_range()
                    .map_or(0, |(offset, size)| offset.saturating_add(size)),
            );
        }
    }
    let mut imports = 0_u32;
    let mut names: Vec<String> = Vec::new();
    if let Ok(table) = file.imports() {
        for import in table {
            let Ok(import) = import else {
                continue;
            };
            imports = imports.saturating_add(1);
            if names.len() >= MAX_IMPORTS {
                continue;
            }
            // The library and the symbol, in the order the table lists them: that pair, in
            // that order, is what makes one family's import hash. A symbol named by ordinal
            // rather than by name is reported as the ordinal, which is what the file says.
            let (library, name) = (import.library(), import.name());
            names.push(format!(
                "{}!{}",
                String::from_utf8_lossy(library),
                match name {
                    object::read::NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
                    object::read::NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                }
            ));
        }
    }
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Some(Structure {
        format: format.to_owned(),
        machine,
        sections,
        writable_executable,
        max_entropy_x100,
        imports,
        imphash: family_hash(&names),
        overlay_bytes: size.saturating_sub(end_of_sections),
        signature_blob: has_signature_blob(bytes),
    })
}

/// The import hash: the file's imports, in order, as one value.
///
/// The order matters, so this is a hash of the list rather than of a sorted set: two builds of
/// one family list the same imports in the same order even when their bytes differ.
#[must_use]
pub fn family_hash(names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for name in names {
        hasher.update(name.to_lowercase().as_bytes());
        hasher.update([0_u8]);
    }
    let digest = hasher.finalize();
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Shannon entropy of a section, in hundredths of a bit per byte.
///
/// 800 is 8.0, the ceiling for a byte stream; a section near it is compressed or encrypted.
#[must_use]
pub fn entropy_x100(data: &[u8]) -> u16 {
    if data.is_empty() {
        return 0;
    }
    let mut counts = [0_u32; 256];
    for byte in data {
        counts[usize::from(*byte)] = counts[usize::from(*byte)].saturating_add(1);
    }
    let total = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    let mut entropy = 0.0_f64;
    for count in counts {
        if count == 0 {
            continue;
        }
        let probability = f64::from(count) / total;
        entropy -= probability * probability.log2();
    }
    // Clamped rather than cast: a NaN or an absurd value would become a nonsense fact.
    let scaled = (entropy * 100.0).round();
    if !scaled.is_finite() || scaled <= 0.0 {
        return 0;
    }
    scaled.min(800.0) as u16
}

/// Whether the file carries an Authenticode signature blob.
///
/// The check is the security directory in the PE header, not a validation of the certificate:
/// a blob can be present and invalid, and saying "a signature is attached" is a fact while
/// saying "this is signed by its publisher" is a different check this build does not make.
#[must_use]
pub fn has_signature_blob(bytes: &[u8]) -> bool {
    // A PE's optional header keeps its data directories at a fixed offset; the security
    // directory is the fifth, and its size field is what says a blob is attached.
    const PE_OFFSET_AT: usize = 0x3c;
    const DATA_DIRECTORIES_AT: usize = 0x80;
    const SECURITY_DIRECTORY: usize = 4 * 8;
    let Some(pe_offset) = read_u32(bytes, PE_OFFSET_AT).and_then(|offset| usize::try_from(offset).ok())
    else {
        return false;
    };
    if pe_offset
        .checked_add(DATA_DIRECTORIES_AT + SECURITY_DIRECTORY + 8)
        .is_none_or(|end| end > bytes.len())
    {
        return false;
    }
    if bytes.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        return false;
    }
    read_u32(
        bytes,
        pe_offset.saturating_add(DATA_DIRECTORIES_AT + SECURITY_DIRECTORY + 4),
    )
    .is_some_and(|size| size > 0)
}

/// A little-endian `u32` at an offset, when the file is long enough to hold one.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_is_a_number_a_person_can_reason_about() {
        assert_eq!(entropy_x100(b""), 0);
        assert_eq!(entropy_x100(b"aaaaaaaa"), 0, "one byte is no entropy at all");
        let random: Vec<u8> = (0..=255_u8).cycle().take(4096).collect();
        assert_eq!(entropy_x100(&random), 800, "a flat distribution is the ceiling");
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(100);
        let measured = entropy_x100(&text);
        assert!(
            (350..500).contains(&measured),
            "prose sits in the middle: {measured}"
        );
    }

    #[test]
    fn an_import_hash_needs_imports_and_depends_on_their_order() {
        assert_eq!(family_hash(&[]), None);
        let one = family_hash(&["KERNEL32.dll!CreateFile".to_owned()]);
        let two = family_hash(&["kernel32.dll!createfile".to_owned()]);
        assert_eq!(one, two, "the hash is not case-sensitive");
        let reversed = family_hash(&[
            "USER32.dll!MessageBox".to_owned(),
            "KERNEL32.dll!CreateFile".to_owned(),
        ]);
        let ordered = family_hash(&[
            "KERNEL32.dll!CreateFile".to_owned(),
            "USER32.dll!MessageBox".to_owned(),
        ]);
        assert_ne!(reversed, ordered, "the order is part of the identity");
        assert_eq!(one.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn something_that_is_not_an_executable_has_no_structure() {
        assert!(read(b"").is_none());
        assert!(read(b"just some text\n").is_none());
        assert!(!has_signature_blob(b"MZ"));
    }
}
