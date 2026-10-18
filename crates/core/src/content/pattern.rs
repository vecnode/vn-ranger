//! A compiled hex pattern, and the matcher that runs it over a buffer.
//!
//! This is the vocabulary of a ClamAV extended body signature (`.ndb`), and nothing more:
//! bytes, `??` for one unknown byte, `{n-m}` and `*` for a gap, and `(aa|bb)` for a
//! choice. There is no regular expression, no back-reference and no code: a pattern is a
//! list of what must be where, which is why it can be read, counted and bounded before it
//! is ever run.
//!
//! Two properties are load-bearing:
//!
//! - **Every match is budgeted.** A gap followed by a long run is the one construct that can
//!   cost more than the buffer is long, so each token visit spends from a [`Budget`] and an
//!   exhausted budget ends the match without a panic and without a hang. The caller reports
//!   it; a scanner that quietly gives up is the failure this exists to prevent.
//! - **The anchor is the first literal run.** A pattern that begins with bytes is searched
//!   for by those bytes, so the common case costs one scan of the buffer rather than one
//!   attempted match per offset.

use super::Budget;

/// The most tokens one pattern may compile to.
///
/// A signature is data from outside the program, so its size is a bound the program sets.
/// Eight thousand tokens is far more than any published body signature needs, and small
/// enough that the matcher's recursion stays shallow.
pub const MAX_TOKENS: usize = 8192;

/// The largest gap one `{n-m}` or `*` may express, in bytes.
///
/// One megabyte is roughly the largest shift a real signature uses (the format's own
/// examples stay in the hundreds). A larger gap is a rule that would cost more than the
/// file it is matching.
pub const MAX_GAP: u32 = 1 << 20;

/// The most alternatives one `(…)` group may hold.
pub const MAX_ALTERNATIVES: usize = 64;

/// The deepest a `(…)` group may nest.
pub const MAX_DEPTH: u8 = 4;

/// One token of a compiled pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// Exactly this byte.
    Byte(u8),
    /// `??`: one byte, any value.
    AnyByte,
    /// A gap: between `min` and `max` bytes, inclusive.
    Gap {
        /// The fewest bytes the gap may consume.
        min: u32,
        /// The most bytes the gap may consume.
        max: u32,
    },
    /// `(aa|bb)`: one of several token sequences.
    Alt(Vec<Vec<Token>>),
}

/// A pattern that compiled, ready to match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    tokens: Vec<Token>,
    /// The leading literal bytes, the same ones `tokens[..anchor_len]` holds.
    anchor: Vec<u8>,
    anchor_len: usize,
}

impl Pattern {
    /// The tokens, for a test or a diagnostic.
    #[must_use]
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// The leading literal run the scan is anchored on, empty when the pattern starts with
    /// a wildcard, a gap or a choice.
    #[must_use]
    pub fn anchor(&self) -> &[u8] {
        &self.anchor
    }

    /// Whether the pattern holds no token. A pattern from [`compile`] never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Find the first match at or after `from`, as `(start, end)` byte offsets.
    ///
    /// `None` means the pattern is not there, or the budget ran out: the caller checks
    /// [`Budget::exhausted`] to tell those apart, because one is a fact about the file and
    /// the other is a fact about the scan.
    #[must_use]
    pub fn find(&self, haystack: &[u8], from: usize, budget: &mut Budget) -> Option<(usize, usize)> {
        if self.tokens.is_empty() || from > haystack.len() {
            return None;
        }
        if self.anchor.is_empty() {
            for start in from..=haystack.len() {
                if let Some(end) = self.match_at(0, haystack, start, budget, 0) {
                    return Some((start, end));
                }
                if budget.exhausted() {
                    return None;
                }
            }
            return None;
        }
        let mut search = from;
        while search <= haystack.len() {
            let rel = find_slice(&haystack[search..], &self.anchor)?;
            let start = search + rel;
            let after = start + self.anchor_len;
            if let Some(end) = self.match_at(self.anchor_len, haystack, after, budget, 0) {
                return Some((start, end));
            }
            if budget.exhausted() {
                return None;
            }
            search = start + 1;
        }
        None
    }

    /// The pattern's length, when every token has one. `None` when a gap or a choice makes
    /// the length a property of the match rather than of the pattern.
    #[must_use]
    pub fn fixed_length(&self) -> Option<usize> {
        let mut length = 0_usize;
        for token in &self.tokens {
            match token {
                Token::Byte(_) | Token::AnyByte => length += 1,
                Token::Gap { min, max } if min == max => {
                    length = length.saturating_add(usize::try_from(*min).unwrap_or(0));
                }
                Token::Gap { .. } | Token::Alt(_) => return None,
            }
        }
        Some(length)
    }

    fn match_at(
        &self,
        index: usize,
        haystack: &[u8],
        position: usize,
        budget: &mut Budget,
        depth: u8,
    ) -> Option<usize> {
        if !budget.spend(1) {
            return None;
        }
        let Some(token) = self.tokens.get(index) else {
            return Some(position);
        };
        match token {
            Token::Byte(expected) => {
                if haystack.get(position) == Some(expected) {
                    self.match_at(index + 1, haystack, position + 1, budget, depth)
                } else {
                    None
                }
            }
            Token::AnyByte => {
                if position < haystack.len() {
                    self.match_at(index + 1, haystack, position + 1, budget, depth)
                } else {
                    None
                }
            }
            Token::Alt(alternatives) => {
                if depth >= MAX_DEPTH {
                    return None;
                }
                for alternative in alternatives {
                    let inner = Pattern {
                        tokens: alternative.clone(),
                        anchor: Vec::new(),
                        anchor_len: 0,
                    };
                    if let Some(after) = inner.match_at(0, haystack, position, budget, depth + 1)
                        && let Some(end) = self.match_at(index + 1, haystack, after, budget, depth)
                    {
                        return Some(end);
                    }
                    if budget.exhausted() {
                        return None;
                    }
                }
                None
            }
            Token::Gap { min, max } => {
                let lowest = position.saturating_add(usize::try_from(*min).unwrap_or(0));
                let highest = position
                    .saturating_add(usize::try_from(*max).unwrap_or(usize::MAX))
                    .min(haystack.len());
                if lowest > highest {
                    return None;
                }
                // A gap followed by literal bytes is the expensive shape, and the common
                // one. Jumping to each place the literal run appears is what keeps the cost
                // proportional to the buffer rather than to the gap.
                if let Some(run) = self.literal_run(index + 1) {
                    let mut at = lowest;
                    while at <= highest {
                        let rel = find_slice(&haystack[at..], &run)?;
                        let candidate = at + rel;
                        if candidate > highest {
                            return None;
                        }
                        if let Some(end) = self.match_at(
                            index + 1 + run.len(),
                            haystack,
                            candidate + run.len(),
                            budget,
                            depth,
                        ) {
                            return Some(end);
                        }
                        if budget.exhausted() {
                            return None;
                        }
                        at = candidate + 1;
                    }
                    return None;
                }
                for skip in lowest..=highest {
                    if let Some(end) = self.match_at(index + 1, haystack, skip, budget, depth) {
                        return Some(end);
                    }
                    if budget.exhausted() {
                        return None;
                    }
                }
                None
            }
        }
    }

    /// The literal bytes at `index`, if the tokens there are plain bytes.
    fn literal_run(&self, index: usize) -> Option<Vec<u8>> {
        let mut run = Vec::new();
        for token in self.tokens.get(index..)? {
            let Token::Byte(byte) = token else { break };
            run.push(*byte);
        }
        (!run.is_empty()).then_some(run)
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} token(s)", self.tokens.len())
    }
}

/// Compile the hex body of a signature.
///
/// The grammar is the whole of what ranger accepts, and every other character is a refusal
/// with the offset it was found at — a signature that half-parses is worse than one that is
/// refused, because the half that parsed looks like coverage.
pub fn compile(hex: &str) -> Result<Pattern, String> {
    let mut parser = Parser {
        bytes: hex.as_bytes(),
        at: 0,
        tokens: 0,
        depth: 0,
    };
    let tokens = parser.sequence(false)?;
    if parser.at < parser.bytes.len() {
        return Err(format!(
            "unexpected `{}` at byte {}",
            parser.bytes[parser.at] as char, parser.at
        ));
    }
    if tokens.is_empty() {
        return Err("the pattern is empty".to_owned());
    }
    if parser.tokens > MAX_TOKENS {
        return Err(format!(
            "the pattern is {} tokens; the limit is {MAX_TOKENS}",
            parser.tokens
        ));
    }
    let mut anchor = Vec::new();
    for token in &tokens {
        let Token::Byte(byte) = token else { break };
        anchor.push(*byte);
    }
    let anchor_len = anchor.len();
    Ok(Pattern {
        tokens,
        anchor,
        anchor_len,
    })
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    tokens: usize,
    depth: u8,
}

impl Parser<'_> {
    /// Parse a token sequence, stopping at `)` when `nested`, or at the end otherwise.
    fn sequence(&mut self, nested: bool) -> Result<Vec<Token>, String> {
        let mut out = Vec::new();
        while let Some(byte) = self.bytes.get(self.at).copied() {
            match byte {
                b')' if nested => return Ok(out),
                b'|' if nested => return Ok(out),
                b')' => return Err(format!("unbalanced `)` at byte {}", self.at)),
                b'(' => {
                    if self.depth >= MAX_DEPTH {
                        return Err(format!(
                            "a group nests more than {MAX_DEPTH} deep at byte {}",
                            self.at
                        ));
                    }
                    self.at += 1;
                    self.depth += 1;
                    let group = self.group()?;
                    self.depth -= 1;
                    self.at += 1;
                    out.push(group);
                }
                b'*' => {
                    self.at += 1;
                    self.bump()?;
                    out.push(Token::Gap { min: 0, max: MAX_GAP });
                }
                b'{' => {
                    let gap = self.gap()?;
                    self.bump()?;
                    out.push(gap);
                }
                b'?' => {
                    if self.bytes.get(self.at + 1) != Some(&b'?') {
                        return Err(format!(
                            "a single `?` at byte {} is not a wildcard; write `??`",
                            self.at
                        ));
                    }
                    self.at += 2;
                    self.bump()?;
                    out.push(Token::AnyByte);
                }
                b' ' | b'\t' => {
                    return Err(format!(
                        "whitespace inside a pattern at byte {} is not part of the format",
                        self.at
                    ));
                }
                _ => {
                    let high = hex_value(byte)
                        .ok_or_else(|| format!("`{}` at byte {} is not hex", byte as char, self.at))?;
                    let Some(low_byte) = self.bytes.get(self.at + 1).copied() else {
                        return Err(format!("odd number of hex digits at byte {}", self.at));
                    };
                    let low = hex_value(low_byte).ok_or_else(|| {
                        format!("`{}` at byte {} is not hex", low_byte as char, self.at + 1)
                    })?;
                    self.at += 2;
                    self.bump()?;
                    out.push(Token::Byte((high << 4) | low));
                }
            }
        }
        if nested {
            return Err(format!("a group is not closed at byte {}", self.at));
        }
        Ok(out)
    }

    /// Parse the body of a `(…)` group. The opening parenthesis is already consumed.
    fn group(&mut self) -> Result<Token, String> {
        let mut alternatives = Vec::new();
        loop {
            let alternative = self.sequence(true)?;
            if alternative.is_empty() {
                return Err(format!("an empty alternative at byte {}", self.at));
            }
            alternatives.push(alternative);
            if alternatives.len() > MAX_ALTERNATIVES {
                return Err(format!(
                    "a group has more than {MAX_ALTERNATIVES} alternatives at byte {}",
                    self.at
                ));
            }
            match self.bytes.get(self.at) {
                Some(b'|') => self.at += 1,
                Some(b')') => break,
                Some(other) => {
                    return Err(format!(
                        "`{}` at byte {} is not part of a group",
                        *other as char, self.at
                    ));
                }
                None => return Err(format!("a group is not closed at byte {}", self.at)),
            }
        }
        Ok(Token::Alt(alternatives))
    }

    /// Parse `{n}`, `{n-m}`, `{n-}` or `{-m}`. The opening brace is already consumed.
    fn gap(&mut self) -> Result<Token, String> {
        let start = self.at;
        self.at += 1;
        let min = self.number()?;
        let (min, max) = match self.bytes.get(self.at) {
            Some(b'}') => match min {
                Some(min) => (min, min),
                None => return Err(format!("an empty gap at byte {start}")),
            },
            Some(b'-') => {
                self.at += 1;
                let max = self.number()?;
                let min = min.unwrap_or(0);
                let max = max.ok_or_else(|| format!("a gap with no end at byte {start}"))?;
                (min, max)
            }
            _ => {
                return Err(format!("a gap at byte {start} is neither a number nor `-`"));
            }
        };
        if self.bytes.get(self.at) != Some(&b'}') {
            return Err(format!("a gap is not closed at byte {}", self.at));
        }
        self.at += 1;
        if min > max {
            return Err(format!("a gap of {min}-{max} has its ends reversed"));
        }
        if max > MAX_GAP {
            return Err(format!(
                "a gap of {max} bytes is larger than the {MAX_GAP}-byte limit"
            ));
        }
        Ok(Token::Gap { min, max })
    }

    /// A decimal number, or `None` when there is not one here.
    fn number(&mut self) -> Result<Option<u32>, String> {
        let start = self.at;
        let mut value: u32 = 0;
        while let Some(byte) = self.bytes.get(self.at).copied() {
            if !byte.is_ascii_digit() {
                break;
            }
            let digit = u32::from(byte - b'0');
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or_else(|| format!("a number at byte {start} is too large"))?;
            self.at += 1;
        }
        if self.at == start {
            return Ok(None);
        }
        Ok(Some(value))
    }

    fn bump(&mut self) -> Result<(), String> {
        self.tokens = self.tokens.saturating_add(1);
        if self.tokens > MAX_TOKENS {
            return Err(format!("the pattern is longer than {MAX_TOKENS} tokens"));
        }
        Ok(())
    }
}

/// The value of one hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The first place `needle` appears in `haystack`.
fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget::new(1_000_000)
    }

    fn matches(hex: &str, haystack: &[u8]) -> bool {
        let Ok(pattern) = compile(hex) else {
            return false;
        };
        pattern.find(haystack, 0, &mut Budget::new(1_000_000)).is_some()
    }

    #[test]
    fn a_literal_pattern_matches_where_it_is() {
        let pattern = compile("4d5a").unwrap();
        let (start, end) = pattern.find(b"xxMZyy", 0, &mut budget()).unwrap();
        assert_eq!((start, end), (2, 4));
        assert_eq!(pattern.anchor(), b"MZ");
        assert!(
            pattern.find(b"xxmzyy", 0, &mut budget()).is_none(),
            "hex is case-insensitive, matched bytes are not"
        );
    }

    #[test]
    fn a_wildcard_matches_one_byte_and_no_more() {
        assert!(matches("4d??5a", b"MxZ"));
        assert!(!matches("4d??5a", b"MZ"), "a wildcard is not optional");
        assert!(!matches("4d??5a", b"MxyZ"), "a wildcard is exactly one byte");
        assert!(matches("4d5a", b"MZ"), "the pattern is not anchored to the end");
    }

    #[test]
    fn a_gap_of_exact_length_is_exact() {
        assert!(matches("4d{2}5a", b"MxxZ"));
        assert!(!matches("4d{2}5a", b"MxZ"));
        assert!(!matches("4d{2}5a", b"MxxxZ"));
    }

    #[test]
    fn a_gap_range_takes_the_shortest_that_finishes() {
        let pattern = compile("4d{1-3}5a").unwrap();
        let (start, end) = pattern.find(b"MxxxZ", 0, &mut budget()).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 5, "the range must reach the literal that ends it");
        assert!(matches("4d{0-2}5a", b"MZ"), "a range may be empty");
    }

    #[test]
    fn a_star_gap_can_be_empty_and_can_be_long() {
        assert!(matches("4d*5a", b"MZ"));
        assert!(matches("4d*5a", b"MxyzZ"));
        assert!(!matches("4d*5a", b"Z"));
    }

    #[test]
    fn a_choice_matches_any_of_its_alternatives() {
        assert!(matches("4d(61|62)5a", b"MaZ"));
        assert!(matches("4d(61|62)5a", b"MbZ"));
        assert!(!matches("4d(61|62)5a", b"McZ"));
        assert!(
            matches("4d(6162|63)5a", b"MabZ"),
            "an alternative may be several bytes"
        );
    }

    #[test]
    fn a_choice_can_be_followed_by_more_pattern() {
        assert!(matches("(41|42)43", b"AC"));
        assert!(matches("(41|42)43", b"BC"));
        assert!(!matches("(41|42)43", b"CC"));
    }

    #[test]
    fn a_pattern_that_starts_with_a_wildcard_still_matches() {
        assert!(matches("??4d5a", b"xMZ"));
        assert!(!matches("??4d5a", b"MZ"));
        assert!(
            compile("??4d5a").unwrap().anchor().is_empty(),
            "a leading wildcard is not an anchor"
        );
    }

    #[test]
    fn the_match_is_budgeted_and_says_when_it_gave_up() {
        // A gap followed by a wildcard has no literal to jump to, so it genuinely walks the
        // range and spends the budget. A gap followed by a literal would not, by design.
        let pattern = compile("4d{0-1048576}??56").unwrap();
        // Every byte is the anchor, so each attempt enters the gap and walks it: this is
        // the shape the budget exists for.
        let haystack = vec![b'M'; 4096];
        let mut small = Budget::new(64);
        assert!(pattern.find(&haystack, 0, &mut small).is_none());
        assert!(
            small.exhausted(),
            "a budget that runs out is reported, not hidden"
        );
    }

    #[test]
    fn every_malformed_shape_is_refused_with_a_reason() {
        for (hex, needle) in [
            ("", "empty"),
            ("4", "odd"),
            ("4g", "not hex"),
            ("4d?? 5a", "whitespace"),
            ("4d5a)", "unbalanced"),
            ("4d(61|62", "not closed"),
            ("4d(61|)5a", "empty alternative"),
            ("4d{3-1}5a", "reversed"),
            ("4d{}5a", "empty gap"),
            ("4d{2-", "no end"),
            ("?", "`??`"),
        ] {
            let error = compile(hex).err();
            assert!(
                error.as_deref().is_some_and(|error| error.contains(needle)),
                "{hex:?} should be refused for {needle:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn a_gap_larger_than_the_limit_is_refused() {
        let error = compile("4d{0-2000000}5a").err().unwrap_or_default();
        assert!(error.contains("limit"), "{error}");
    }

    #[test]
    fn a_long_literal_finds_its_place_in_a_large_buffer() {
        let mut haystack = vec![b'x'; 1 << 20];
        let tail = [0x4d, 0x5a, 0x90, 0x00, 0x03];
        haystack.extend_from_slice(&tail);
        let pattern = compile("4d5a900003").unwrap();
        let (start, end) = pattern
            .find(&haystack, 0, &mut Budget::new(1_000_000_000))
            .unwrap();
        assert_eq!(start, 1 << 20);
        assert_eq!(end, (1 << 20) + 5);
    }

    #[test]
    fn a_fixed_length_is_reported_only_when_it_is_certain() {
        assert_eq!(compile("4d5a").unwrap().fixed_length(), Some(2));
        assert_eq!(compile("4d??5a").unwrap().fixed_length(), Some(3));
        assert_eq!(compile("4d{2}5a").unwrap().fixed_length(), Some(4));
        assert_eq!(compile("4d{1-2}5a").unwrap().fixed_length(), None);
        assert_eq!(compile("4d*5a").unwrap().fixed_length(), None);
        assert_eq!(compile("4d(61|62)5a").unwrap().fixed_length(), None);
    }

    #[test]
    fn a_gap_followed_by_a_literal_does_not_walk_every_offset() {
        // The literal after the gap is what the matcher jumps to. If it tried every skip
        // instead, this would spend hundreds of thousands of steps and fail.
        let pattern = compile("4d*5a5a5a5a").unwrap();
        let mut haystack = vec![b'M'];
        haystack.extend(std::iter::repeat_n(b'x', 200_000));
        haystack.extend_from_slice(b"ZZZZ");
        let mut small = Budget::new(50_000);
        assert!(pattern.find(&haystack, 0, &mut small).is_some());
        assert!(!small.exhausted());
    }
}
