//! The `.ndb` line: `Name:Target:Offset:HexSignature[:MinLevel[:MaxLevel]]`.
//!
//! One line is one signature, and the parser's job is to refuse everything that is not
//! exactly that, with the reason and the field. A ClamAV body signature can be malformed in
//! a dozen ways — a name with a colon in it, a target that is not a number, a pattern with
//! an odd digit — and the honest response to each is a refusal that names it, never a
//! guess at what the author meant. The signature engine has the same discipline as the
//! hash reader for the same reason (`docs/PLAN.md` §11).
//!
//! The format is documented by ClamAV and implemented here clean-room: no ClamAV code is
//! linked, which is what keeps this application MIT while reading the format the ecosystem
//! writes.

use super::pattern;
use super::{Offset, Signature, Target};

/// The longest name a signature may carry.
pub const MAX_NAME: usize = 128;

/// Parse one signature line.
///
/// `line` is the text without its newline, already trimmed; `number` is where it came from,
/// so a refusal can point at it.
pub fn parse_line(line: &str, number: u32) -> Result<Signature, String> {
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 4 {
        return Err(
            "a signature line needs a name, a target, an offset and a pattern, separated by `:`".to_owned(),
        );
    }
    if fields.len() > 6 {
        return Err(format!(
            "the line has {} fields and the format has at most six",
            fields.len()
        ));
    }
    let name = validate_name(fields[0])?;
    let target = parse_target(fields[1])?;
    let offset = Offset::parse(fields[2]).map_err(|reason| format!("the offset: {reason}"))?;
    let compiled = pattern::compile(fields[3]).map_err(|reason| format!("the pattern: {reason}"))?;
    let min_level = fields
        .get(4)
        .map(|level| parse_level(level, "minimum"))
        .transpose()?;
    let max_level = fields
        .get(5)
        .map(|level| parse_level(level, "maximum"))
        .transpose()?;
    if let (Some(min), Some(max)) = (min_level, max_level)
        && min > max
    {
        return Err(format!("the level range is reversed: {min} is above {max}"));
    }
    Ok(Signature {
        name,
        target,
        offset,
        pattern: compiled,
        min_level,
        max_level,
        line: number,
    })
}

/// A name is what a person reads in a finding, so it has to survive being printed.
fn validate_name(field: &str) -> Result<String, String> {
    let name = field.trim();
    if name.is_empty() {
        return Err("the signature has no name".to_owned());
    }
    if name.len() > MAX_NAME {
        return Err(format!(
            "the name is {} bytes; the limit is {MAX_NAME}",
            name.len()
        ));
    }
    if name.starts_with('-') {
        return Err(format!("`{name}` starts with `-`, which is not a name"));
    }
    for byte in name.bytes() {
        if !(0x20..0x7f).contains(&byte) {
            return Err(format!(
                "the name contains byte 0x{byte:02x}, which is not printable ASCII"
            ));
        }
    }
    Ok(name.to_owned())
}

/// The target column is a small integer, and `9` is the last one with a name.
fn parse_target(field: &str) -> Result<Target, String> {
    let number: u16 = field
        .trim()
        .parse()
        .map_err(|_| format!("`{field}` is not a target type number"))?;
    let number =
        u8::try_from(number).map_err(|_| format!("the target type `{number}` is outside the format"))?;
    Ok(Target::from_number(number))
}

/// A functionality level is a small integer, and `0` is meaningful, so an empty field is not
/// the same as an absent one.
fn parse_level(field: &str, which: &str) -> Result<u16, String> {
    let field = field.trim();
    if field.is_empty() {
        return Err(format!("the {which} level is empty"));
    }
    field
        .parse()
        .map_err(|_| format!("`{field}` is not a {which} level"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_line_parses_into_every_field() {
        let signature = parse_line("Win.Trojan.Example-1:1:EP+8:4d5a9000??03:120:255", 7).unwrap();
        assert_eq!(signature.name, "Win.Trojan.Example-1");
        assert_eq!(signature.target, Target::Pe);
        assert_eq!(signature.offset, Offset::EntryPoint(8));
        assert_eq!(&signature.pattern.anchor()[..2], b"MZ");
        assert_eq!(signature.min_level, Some(120));
        assert_eq!(signature.max_level, Some(255));
        assert_eq!(signature.line, 7);
    }

    #[test]
    fn the_optional_levels_may_be_absent() {
        let signature = parse_line("Name:0:*:4d5a", 1).unwrap();
        assert_eq!(signature.min_level, None);
        assert_eq!(signature.max_level, None);
        let only_min = parse_line("Name:0:*:4d5a:90", 1).unwrap();
        assert_eq!(only_min.min_level, Some(90));
        assert_eq!(only_min.max_level, None);
    }

    #[test]
    fn a_line_with_too_few_or_too_many_fields_is_refused() {
        for line in ["Name:0", "Name", "Name:0:*:4d5a:1:2:3", ""] {
            assert!(parse_line(line, 1).is_err(), "{line:?} should be refused");
        }
    }

    #[test]
    fn a_name_that_cannot_be_printed_is_refused() {
        for (line, needle) in [
            (":0:*:4d5a", "no name"),
            ("-name:0:*:4d5a", "starts with"),
            ("na\u{7}me:0:*:4d5a", "not printable"),
        ] {
            let error = parse_line(line, 1).err().unwrap_or_default();
            assert!(error.contains(needle), "{line:?}: {error}");
        }
    }

    #[test]
    fn a_long_name_is_refused() {
        let name = "a".repeat(MAX_NAME + 1);
        let error = parse_line(&format!("{name}:0:*:4d5a"), 1)
            .err()
            .unwrap_or_default();
        assert!(error.contains("limit"), "{error}");
    }

    #[test]
    fn a_target_that_is_not_a_small_number_is_refused() {
        for (target, needle) in [("pe", "not a target"), ("300", "outside the format")] {
            let error = parse_line(&format!("Name:{target}:*:4d5a"), 1)
                .err()
                .unwrap_or_default();
            assert!(error.contains(needle), "{target}: {error}");
        }
    }

    #[test]
    fn an_empty_level_is_not_zero() {
        let error = parse_line("Name:0:*:4d5a::255", 1).err().unwrap_or_default();
        assert!(error.contains("empty"), "{error}");
        let zero = parse_line("Name:0:*:4d5a:0:0", 1).unwrap();
        assert_eq!(zero.min_level, Some(0));
    }

    #[test]
    fn a_reversed_level_range_is_refused() {
        let error = parse_line("Name:0:*:4d5a:255:120", 1).err().unwrap_or_default();
        assert!(error.contains("reversed"), "{error}");
    }

    #[test]
    fn a_malformed_offsets_names_the_offsets_and_not_the_pattern() {
        let error = parse_line("Name:0:EP+x:4d5a", 1).err().unwrap_or_default();
        assert!(error.starts_with("the offset:"), "{error}");
    }

    #[test]
    fn a_malformed_pattern_names_the_pattern() {
        let error = parse_line("Name:0:*:4d5", 1).err().unwrap_or_default();
        assert!(error.starts_with("the pattern:"), "{error}");
    }
}
