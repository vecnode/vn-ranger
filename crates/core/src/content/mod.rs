//! Content signatures: what is inside a file, rather than what it is called.
//!
//! The layer this module implements is the one ClamAV calls an **extended body signature**
//! (a `.ndb` line): a name, a target file type, an offset and a hex pattern with wildcards,
//! gaps and choices. It is a documented format, it is data rather than code, and every
//! construct in it can be bounded before it runs — which is why it is here and a bytecode
//! signature is not (`docs/PLAN-0.1.7.md` §6).
//!
//! What this module deliberately does not do:
//!
//! - **No file reading.** It is pure: bytes come in, hits go out. `vnr-native` owns the
//!   walk, the size cap and the cancellation, and this crate never sees a path.
//! - **No regular expressions, no bytecode, no unpackers.** PCRE subsignatures are refused
//!   by the parser with a reason, because a regex engine over attacker-chosen bytes is a
//!   denial-of-service surface the release cannot pay for.
//! - **No interpretation.** A hit says a byte pattern is at an offset. It does not say the
//!   file is malicious; the finding that carries it names the rule, the file and the
//!   offset, and the benign explanation is the signature author's to write.
//!
//! The budget is the promise that a hostile or careless signature set cannot make a scan
//! hang: every match spends from a [`Budget`], and an exhausted budget is reported as
//! [`Scan::exhausted`] rather than silently stopping.

pub mod ndb;
pub mod pattern;

pub use pattern::{Pattern, Token};

/// How many matching steps one scan may spend.
///
/// The unit is one token visit, so a literal pattern costs its own length. This is a
/// ceiling on work rather than on time: a scan that reaches it has found something it
/// cannot finish bounding, and says so.
pub const DEFAULT_STEPS: u64 = 50_000_000;

/// How many signatures one library may hold.
///
/// A corpus is data from outside the program. The limit is high enough for a curated set
/// and low enough that loading one cannot be used to exhaust memory.
pub const MAX_SIGNATURES: usize = 100_000;

/// The longest one signature line may be.
pub const MAX_LINE: usize = 8 * 1024;

/// A matching budget, counted in token visits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    remaining: u64,
    exhausted: bool,
}

impl Budget {
    /// A budget that may spend this many steps.
    #[must_use]
    pub fn new(steps: u64) -> Self {
        Self {
            remaining: steps,
            exhausted: false,
        }
    }

    /// Spend some steps. `false` means the budget is now exhausted and the caller must stop.
    pub fn spend(&mut self, steps: u64) -> bool {
        if self.exhausted {
            return false;
        }
        match self.remaining.checked_sub(steps) {
            Some(remaining) => {
                self.remaining = remaining;
                true
            }
            None => {
                self.remaining = 0;
                self.exhausted = true;
                false
            }
        }
    }

    /// Whether the budget ran out. A scan that stopped here did not finish, and must not be
    /// reported as a clean file.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// How much is left, for a diagnostic.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

/// The file type a signature applies to, as ClamAV numbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Any file.
    Any,
    /// A PE executable.
    Pe,
    /// An OLE2 compound document (a legacy Office file).
    Ole2,
    /// HTML.
    Html,
    /// A mail message.
    Mail,
    /// An image.
    Graphics,
    /// An ELF executable.
    Elf,
    /// Plain text.
    Text,
    /// A Mach-O executable.
    MachO,
    /// A PDF.
    Pdf,
    /// A type this build has no number for.
    Other(u8),
}

impl Target {
    /// The target a number names.
    #[must_use]
    pub fn from_number(number: u8) -> Self {
        match number {
            0 => Self::Any,
            1 => Self::Pe,
            2 => Self::Ole2,
            3 => Self::Html,
            4 => Self::Mail,
            5 => Self::Graphics,
            6 => Self::Elf,
            7 => Self::Text,
            8 => Self::MachO,
            9 => Self::Pdf,
            other => Self::Other(other),
        }
    }

    /// The number the format uses.
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Pe => 1,
            Self::Ole2 => 2,
            Self::Html => 3,
            Self::Mail => 4,
            Self::Graphics => 5,
            Self::Elf => 6,
            Self::Text => 7,
            Self::MachO => 8,
            Self::Pdf => 9,
            Self::Other(other) => other,
        }
    }

    /// A name a person reads.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Any => "any file",
            Self::Pe => "PE",
            Self::Ole2 => "OLE2",
            Self::Html => "HTML",
            Self::Mail => "mail",
            Self::Graphics => "image",
            Self::Elf => "ELF",
            Self::Text => "text",
            Self::MachO => "Mach-O",
            Self::Pdf => "PDF",
            Self::Other(_) => "an unknown type",
        }
    }
}

/// Where a signature's pattern must start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Offset {
    /// Anywhere in the file.
    Anywhere,
    /// This absolute offset.
    Absolute(u64),
    /// An offset from the PE entry point.
    EntryPoint(i64),
    /// An offset from the start of a section, by index.
    Section {
        /// Which section, in the order the header lists them.
        index: u32,
        /// The offset inside it.
        delta: i64,
    },
    /// An offset from the start of the last section.
    LastSection(i64),
    /// An offset from the end of the file.
    FromEnd(i64),
}

impl Offset {
    /// Parse the offset column of an `.ndb` line.
    ///
    /// The shapes are the format's own: `*`, a number, `EP+n`, `S0+n`, `SL+n`, `EOF-n`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text == "*" {
            return Ok(Self::Anywhere);
        }
        let (sign, rest) = match text.as_bytes().first() {
            Some(b'E') if text.starts_with("EOF") => ("end", &text[3..]),
            Some(b'E') if text.starts_with("EP") => ("entry", &text[2..]),
            Some(b'S') if text.starts_with("SL") => ("last", &text[2..]),
            Some(b'S') => ("section", &text[1..]),
            _ => ("absolute", text),
        };
        match sign {
            "absolute" => {
                let value = number(rest).ok_or_else(|| format!("`{text}` is not an offset"))?;
                Ok(Self::Absolute(value))
            }
            "entry" => Ok(Self::EntryPoint(relative(rest)?)),
            "last" => Ok(Self::LastSection(relative(rest)?)),
            "end" => Ok(Self::FromEnd(relative(rest)?)),
            "section" => {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if digits.is_empty() {
                    return Err(format!("`{text}` names no section number"));
                }
                let index: u32 = digits
                    .parse()
                    .map_err(|_| format!("`{text}` has a section number too large"))?;
                let delta = relative(&rest[digits.len()..])?;
                Ok(Self::Section { index, delta })
            }
            _ => Err(format!("`{text}` is not an offset")),
        }
    }

    /// Whether this offset needs a parsed executable header to resolve.
    #[must_use]
    pub fn needs_layout(&self) -> bool {
        !matches!(self, Self::Anywhere | Self::Absolute(_))
    }

    /// Where a match may start, given the file's length and, when it has one, its layout.
    ///
    /// `None` means no match is possible here — an offset past the end of the file, or a
    /// layout-dependent offset with no layout. The caller tells those two apart with
    /// [`Offset::needs_layout`].
    #[must_use]
    pub fn resolve(&self, len: usize, layout: Option<&Layout>) -> Option<usize> {
        match self {
            Self::Anywhere => Some(0),
            Self::Absolute(value) => usize::try_from(*value).ok().filter(|at| *at <= len),
            Self::EntryPoint(delta) => {
                let layout = layout?;
                let base = layout.entry_point?;
                shift(base, *delta, len)
            }
            Self::Section { index, delta } => {
                let layout = layout?;
                let section = layout.sections.get(usize::try_from(*index).ok()?)?;
                shift(section.offset, *delta, len)
            }
            Self::LastSection(delta) => {
                let layout = layout?;
                let section = layout.sections.last()?;
                shift(section.offset, *delta, len)
            }
            Self::FromEnd(delta) => {
                let base = i64::try_from(len).ok()?;
                shift(u64::try_from(base.saturating_add(*delta)).unwrap_or(0), 0, len)
            }
        }
    }
}

/// A base plus a signed delta, kept inside the file.
fn shift(base: u64, delta: i64, len: usize) -> Option<usize> {
    let base = i64::try_from(base).ok()?;
    let at = base.checked_add(delta)?;
    let at = u64::try_from(at).ok()?;
    let at = usize::try_from(at).ok()?;
    (at <= len).then_some(at)
}

/// A number in decimal, or in hex with a `0x` prefix.
fn number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    text.parse().ok()
}

/// `+n` or `-n`.
fn relative(text: &str) -> Result<i64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'+') => (false, &text[1..]),
        Some(b'-') => (true, &text[1..]),
        _ => return Err(format!("`{text}` is not a relative offset")),
    };
    let value: i64 = digits
        .parse()
        .map_err(|_| format!("`{text}` is not a relative offset"))?;
    Ok(if negative { -value } else { value })
}

/// One section of an executable, as the header describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    /// Where the section's bytes start in the file.
    pub offset: u64,
    /// How many bytes it holds.
    pub size: u64,
}

/// What a signature offset may need to know about the file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    /// What the file is, when the format was identified.
    pub target: Option<Target>,
    /// The entry point, as a file offset.
    pub entry_point: Option<u64>,
    /// The sections, in header order.
    pub sections: Vec<Section>,
}

/// One signature, compiled and ready to look for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signature's name, as the author wrote it.
    pub name: String,
    /// The file type it applies to.
    pub target: Target,
    /// Where its pattern must start.
    pub offset: Offset,
    /// The pattern itself.
    pub pattern: Pattern,
    /// The lowest engine level the signature declares, if it declares one.
    pub min_level: Option<u16>,
    /// The highest engine level it declares.
    pub max_level: Option<u16>,
    /// The line it came from, for a refusal or an evidence line.
    pub line: u32,
}

/// What looking for one signature found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// The pattern is at this offset.
    Hit {
        /// Where the match starts.
        at: usize,
        /// How many bytes it spans.
        length: usize,
    },
    /// The pattern is not in this file.
    NotHere,
    /// The signature cannot be evaluated against this file, and why.
    Skipped {
        /// What stopped it, in a sentence a person can act on.
        reason: &'static str,
    },
}

impl Signature {
    /// Look for this signature in a buffer.
    #[must_use]
    pub fn find(&self, bytes: &[u8], layout: Option<&Layout>, budget: &mut Budget) -> Found {
        if self.target != Target::Any {
            match layout.and_then(|layout| layout.target) {
                Some(actual) if actual == self.target => {}
                Some(_) => return Found::NotHere,
                None => {
                    return Found::Skipped {
                        reason: "the file type was not identified, so a typed signature cannot be checked",
                    };
                }
            }
        }
        let Some(start) = self.offset.resolve(bytes.len(), layout) else {
            return if self.offset.needs_layout() && layout.is_none() {
                Found::Skipped {
                    reason: "the signature needs an executable header this build did not parse",
                }
            } else {
                Found::NotHere
            };
        };
        match self.pattern.find(bytes, start, budget) {
            Some((at, end)) => Found::Hit {
                at,
                length: end.saturating_sub(at),
            },
            None if budget.exhausted() => Found::Skipped {
                reason: "the pattern spent the scan's matching budget",
            },
            None => Found::NotHere,
        }
    }
}

/// One signature that matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// The signature's name.
    pub name: String,
    /// Where it matched.
    pub at: u64,
    /// How many bytes it matched.
    pub length: usize,
    /// The line of the signature file it came from.
    pub line: u32,
}

/// One line the parser refused, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The line's number in the file.
    pub line: u32,
    /// What was wrong, in a sentence a person can act on.
    pub reason: String,
}

/// A set of signatures, and the lines that did not become one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Library {
    signatures: Vec<Signature>,
    refusals: Vec<Refusal>,
    truncated: bool,
}

impl Library {
    /// Parse a signature file.
    ///
    /// A file is a line per signature; `#` starts a comment and a blank line is skipped.
    /// Every other line either compiles or is refused with its line number, so a file with
    /// one bad line still loads the rest — and says how many it refused.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut library = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() > MAX_LINE {
                library.refusals.push(Refusal {
                    line: number,
                    reason: format!("the line is longer than the {MAX_LINE}-byte limit"),
                });
                continue;
            }
            if library.signatures.len() >= MAX_SIGNATURES {
                library.truncated = true;
                break;
            }
            match ndb::parse_line(line, number) {
                Ok(signature) => library.signatures.push(signature),
                Err(reason) => library.refusals.push(Refusal { line: number, reason }),
            }
        }
        library
    }

    /// The signatures that compiled.
    #[must_use]
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The lines that were refused.
    #[must_use]
    pub fn refusals(&self) -> &[Refusal] {
        &self.refusals
    }

    /// Whether the library stopped before the end of the file because of a limit.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the library holds no signature at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Look for every signature in a buffer.
    ///
    /// The scan stops early only when the budget runs out, and says so: a partial scan is
    /// not a clean file.
    #[must_use]
    pub fn scan(&self, bytes: &[u8], layout: Option<&Layout>, budget: &mut Budget) -> Scan {
        let mut scan = Scan::default();
        for signature in &self.signatures {
            match signature.find(bytes, layout, budget) {
                Found::Hit { at, length } => scan.hits.push(Hit {
                    name: signature.name.clone(),
                    at: u64::try_from(at).unwrap_or(u64::MAX),
                    length,
                    line: signature.line,
                }),
                Found::NotHere => {}
                Found::Skipped { .. } => scan.skipped += 1,
            }
            if budget.exhausted() {
                scan.exhausted = true;
                break;
            }
        }
        scan
    }
}

/// The outcome of one scan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Every signature that matched, in the library's order.
    pub hits: Vec<Hit>,
    /// How many signatures could not be checked against this file.
    pub skipped: usize,
    /// Whether the scan stopped because the budget ran out.
    pub exhausted: bool,
}

impl Scan {
    /// Whether anything matched.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty() && !self.exhausted && self.skipped == 0
    }
}

/// What a file's first bytes say it is.
///
/// The identifier is a fact about the bytes, and it is what a typed signature is checked
/// against: a `.ndb` line written for a PE file must not fire on a text file that happens to
/// contain the same bytes. `Unknown` is not an error — a file can be anything — and a
/// signature that targets a type is skipped rather than guessed at when the type is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// A PE executable or DLL.
    Pe,
    /// An ELF executable or library.
    Elf,
    /// A Mach-O executable or universal binary.
    MachO,
    /// A PDF document.
    Pdf,
    /// An OLE2 compound document, which is what a legacy Office file is.
    Ole2,
    /// A zip archive, including the formats built on it.
    Zip,
    /// A gzip stream.
    Gzip,
    /// A 7-zip archive.
    SevenZip,
    /// A RAR archive.
    Rar,
    /// None of the above, from the bytes this build looked at.
    Unknown,
}

impl FileKind {
    /// The stable name a fact and a rule carry.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "mach-o",
            Self::Pdf => "pdf",
            Self::Ole2 => "ole2",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::SevenZip => "7z",
            Self::Rar => "rar",
            Self::Unknown => "unknown",
        }
    }

    /// The signature target this kind satisfies, when the format has one.
    #[must_use]
    pub fn target(self) -> Option<Target> {
        match self {
            Self::Pe => Some(Target::Pe),
            Self::Elf => Some(Target::Elf),
            Self::MachO => Some(Target::MachO),
            Self::Pdf => Some(Target::Pdf),
            Self::Ole2 => Some(Target::Ole2),
            Self::Zip | Self::Gzip | Self::SevenZip | Self::Rar | Self::Unknown => None,
        }
    }
}

/// Identify a file from its first bytes.
///
/// The list is deliberately short: the formats a signature targets, and the containers
/// ranger walks. A longer list is a file-type database, and a file-type database is a
/// dependency with a size.
#[must_use]
pub fn identify(bytes: &[u8]) -> FileKind {
    if bytes.starts_with(b"MZ") {
        return FileKind::Pe;
    }
    if bytes.starts_with(b"\x7fELF") {
        return FileKind::Elf;
    }
    if bytes.starts_with(b"%PDF") {
        return FileKind::Pdf;
    }
    if bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return FileKind::Ole2;
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return FileKind::Zip;
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return FileKind::Gzip;
    }
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return FileKind::SevenZip;
    }
    if bytes.starts_with(b"Rar!\x1a\x07") {
        return FileKind::Rar;
    }
    if let Some(magic) = bytes.get(..4).and_then(|head| <[u8; 4]>::try_from(head).ok()) {
        let magic = u32::from_be_bytes(magic);
        if matches!(
            magic,
            0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe | 0xcafe_babe | 0xbeba_feca
        ) {
            return FileKind::MachO;
        }
    }
    FileKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget::new(DEFAULT_STEPS)
    }

    const LIBRARY: &str = "\
# a comment
Eicar-Test-Signature:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a
MZ.Literal:0:0:4d5a
";

    #[test]
    fn a_library_parses_its_lines_and_counts_the_refusals() {
        let library = Library::parse(&format!("{LIBRARY}broken:line\n"));
        assert_eq!(library.signatures().len(), 2);
        assert_eq!(library.refusals().len(), 1);
        assert_eq!(library.refusals()[0].line, 4);
        assert!(!library.truncated());
    }

    #[test]
    fn a_signature_finds_its_bytes_and_names_itself() {
        let library = Library::parse("MZ:0:0:4d5a\n");
        let scan = library.scan(b"..MZ..", None, &mut budget());
        assert_eq!(scan.hits.len(), 1);
        assert_eq!(scan.hits[0].name, "MZ");
        assert_eq!(scan.hits[0].at, 2);
        assert!(!scan.is_clean());
        assert!(library.scan(b"..zm..", None, &mut budget()).is_clean());
    }

    #[test]
    fn an_absolute_offset_means_that_offset() {
        let library = Library::parse("at.two:0:2:4d5a\n");
        assert_eq!(library.scan(b"xxMZ", None, &mut budget()).hits.len(), 1);
        assert!(
            library.scan(b"MZxx", None, &mut budget()).is_clean(),
            "the pattern is elsewhere, so it is not at 2"
        );
    }

    #[test]
    fn a_typed_signature_without_an_identified_file_is_skipped_rather_than_matched() {
        let library = Library::parse("pe.only:1:*:4d5a\n");
        let scan = library.scan(b"MZ", None, &mut budget());
        assert!(scan.hits.is_empty());
        assert_eq!(scan.skipped, 1);
        assert!(!scan.is_clean(), "a skipped signature is not a clean file");

        let layout = Layout {
            target: Some(Target::Pe),
            ..Layout::default()
        };
        assert_eq!(library.scan(b"MZ", Some(&layout), &mut budget()).hits.len(), 1);
        let other = Layout {
            target: Some(Target::Elf),
            ..Layout::default()
        };
        assert!(library.scan(b"MZ", Some(&other), &mut budget()).hits.is_empty());
    }

    #[test]
    fn a_layout_offset_resolves_through_the_header() {
        let layout = Layout {
            target: Some(Target::Pe),
            entry_point: Some(4096),
            sections: vec![
                Section {
                    offset: 512,
                    size: 1024,
                },
                Section {
                    offset: 2048,
                    size: 512,
                },
            ],
        };
        let at_entry = Library::parse("ep:1:EP+2:4d5a\n");
        let bytes = vec![0_u8; 8192];
        assert!(
            at_entry
                .scan(&bytes, Some(&layout), &mut budget())
                .hits
                .is_empty()
        );
        let mut bytes = vec![0_u8; 8192];
        bytes[4098] = b'M';
        bytes[4099] = b'Z';
        assert_eq!(at_entry.scan(&bytes, Some(&layout), &mut budget()).hits.len(), 1);

        let last = Library::parse("last:1:SL+1:4d5a\n");
        let mut bytes = vec![0_u8; 8192];
        bytes[2049] = b'M';
        bytes[2050] = b'Z';
        assert_eq!(last.scan(&bytes, Some(&layout), &mut budget()).hits.len(), 1);

        let end = Library::parse("end:1:EOF-2:4d5a\n");
        let mut bytes = vec![0_u8; 16];
        bytes[14] = b'M';
        bytes[15] = b'Z';
        assert_eq!(end.scan(&bytes, Some(&layout), &mut budget()).hits.len(), 1);
    }

    #[test]
    fn an_offset_past_the_end_is_not_a_match() {
        let library = Library::parse("far:0:999:4d5a\n");
        assert!(library.scan(b"MZ", None, &mut budget()).is_clean());
    }

    #[test]
    fn an_exhausted_scan_says_so() {
        let library = Library::parse("wide:0:*:4d{0-1048576}??5a\n");
        let bytes = vec![b'M'; 4096];
        let mut small = Budget::new(16);
        let scan = library.scan(&bytes, None, &mut small);
        assert!(scan.exhausted);
        assert!(!scan.is_clean());
    }

    #[test]
    fn offsets_parse_in_the_shapes_the_format_has() {
        for (text, expected) in [
            ("*", Offset::Anywhere),
            ("0", Offset::Absolute(0)),
            ("0x10", Offset::Absolute(16)),
            ("EP+8", Offset::EntryPoint(8)),
            ("EP-8", Offset::EntryPoint(-8)),
            ("SL+1", Offset::LastSection(1)),
            ("EOF-2", Offset::FromEnd(-2)),
            ("S2+4", Offset::Section { index: 2, delta: 4 }),
            ("S0", Offset::Section { index: 0, delta: 0 }),
        ] {
            assert_eq!(Offset::parse(text), Ok(expected), "{text}");
        }
        for text in ["", "EP+x", "S+1", "S99999999999+1", "banana"] {
            assert!(Offset::parse(text).is_err(), "{text} should be refused");
        }
    }

    #[test]
    fn a_budget_cannot_be_overdrawn() {
        let mut budget = Budget::new(2);
        assert!(budget.spend(2));
        assert_eq!(budget.remaining(), 0);
        assert!(!budget.spend(1));
        assert!(budget.exhausted());
        assert!(!budget.spend(0));
    }

    #[test]
    fn the_library_limit_stops_loading_rather_than_growing() {
        let mut text = String::new();
        for index in 0..(MAX_SIGNATURES + 5) {
            text.push_str(&format!("s{index}:0:*:4d5a\n"));
        }
        let library = Library::parse(&text);
        assert_eq!(library.signatures().len(), MAX_SIGNATURES);
        assert!(library.truncated());
    }

    #[test]
    fn the_identifier_names_the_formats_a_signature_can_target() {
        for (bytes, kind) in [
            (b"MZ\x90\x00".as_slice(), FileKind::Pe),
            (b"\x7fELF\x02\x01".as_slice(), FileKind::Elf),
            (b"%PDF-1.7".as_slice(), FileKind::Pdf),
            (
                [0xd0_u8, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].as_slice(),
                FileKind::Ole2,
            ),
            (b"PK\x03\x04".as_slice(), FileKind::Zip),
            ([0x1f_u8, 0x8b, 0x08].as_slice(), FileKind::Gzip),
            (b"7z\xbc\xaf\x27\x1c".as_slice(), FileKind::SevenZip),
            (b"Rar!\x1a\x07\x00".as_slice(), FileKind::Rar),
            ([0xfe_u8, 0xed, 0xfa, 0xce].as_slice(), FileKind::MachO),
            ([0xca_u8, 0xfe, 0xba, 0xbe].as_slice(), FileKind::MachO),
            (b"hello".as_slice(), FileKind::Unknown),
            (b"".as_slice(), FileKind::Unknown),
        ] {
            assert_eq!(identify(bytes), kind, "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn a_kind_maps_to_the_target_a_signature_declares() {
        assert_eq!(FileKind::Pe.target(), Some(Target::Pe));
        assert_eq!(FileKind::Ole2.target(), Some(Target::Ole2));
        assert_eq!(
            FileKind::Zip.target(),
            None,
            "a container is not a signature target"
        );
        assert_eq!(FileKind::Unknown.id(), "unknown");
    }

    #[test]
    fn a_typed_signature_fires_only_on_the_kind_it_names() {
        let library = Library::parse("pe.only:1:*:4d5a\n");
        let pe = Layout {
            target: FileKind::Pe.target(),
            ..Layout::default()
        };
        let elf = Layout {
            target: FileKind::Elf.target(),
            ..Layout::default()
        };
        assert_eq!(library.scan(b"MZ", Some(&pe), &mut budget()).hits.len(), 1);
        assert!(library.scan(b"MZ", Some(&elf), &mut budget()).hits.is_empty());
    }
}
