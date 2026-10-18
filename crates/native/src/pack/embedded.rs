//! The first-party pack, compiled into the binary.
//!
//! `packs/ranger.core.json` is a pack like any other: one JSON file, checked by the same
//! validator a third-party pack is checked by, with no rule id that shadows a built-in
//! (`cargo xtask packs` is that check). Compiling it in is the trust decision: the bytes
//! travel with the build, so there is no signature to verify at run time and no file on
//! disk that can be swapped after the fact. An imported pack is the one that needs a
//! signature, because it is the one that arrives from outside.
//!
//! It is embedded as text rather than as a parsed structure so that the parse — and every
//! refusal it can produce — happens through the same code path as an imported pack.

use vnr_core::pack::{Pack, Reject, parse};

/// The pack's bytes, exactly as the repository holds them.
pub const TEXT: &str = include_str!("../../../../packs/ranger.core.json");

/// A file name for the embedded pack in messages and in the journal.
pub const SOURCE: &str = "embedded:ranger.core.json";

/// Read and validate the embedded pack.
pub fn load(builtin_ids: &[&str]) -> Result<Pack, Vec<Reject>> {
    parse(TEXT, builtin_ids)
}

/// The pack's SHA-256, so the record of activation can name the bytes it was made from.
#[must_use]
pub fn sha256() -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(TEXT.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::rules::builtin_ids;

    #[test]
    fn the_pack_in_the_build_is_a_pack_this_build_accepts() {
        let pack = load(builtin_ids()).expect("the embedded pack is valid");
        assert_eq!(pack.header.id, "ranger.core");
        assert!(!pack.rules.is_empty());
    }

    #[test]
    fn its_digest_is_sixty_four_lowercase_hexadecimal_characters() {
        let digest = sha256();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
    }
}
