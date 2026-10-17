//! Pack signatures: minisign, detached, verified before a byte of the pack is parsed.
//!
//! A pack is data with an author, and the author is only knowable if the bytes were signed
//! and the signature was checked against a key the person deliberately trusted. This module
//! is the checking half (`docs/PLAN.md` §6.11): Ed25519 over BLAKE2b-512, one detached
//! `.minisig` beside the JSON, one public key per author.
//!
//! It never signs. The private half of a key does not exist on a machine running ranger, so
//! the signing code is a dev-dependency in the tests — used to produce one genuinely valid
//! signature that the refusal tests can then break.

use sha2::{Digest, Sha256};

/// A public key ranger has been told to trust, and the name a person can compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// The key as minisign writes it: one base64 line, without the comment line.
    pub public: String,
    /// Eight groups of four uppercase hexadecimal characters, derived from the key itself.
    ///
    /// A fingerprint has to be checkable by a person reading it out loud over a call, so it
    /// is short, has a shape, and is computed from the same bytes it names.
    pub fingerprint: String,
}

impl Key {
    /// A key from the text a person pasted, or `None` when that text is not a minisign key.
    #[must_use]
    pub fn parse(public: &str) -> Option<Self> {
        let public = public.trim();
        if public.is_empty() {
            return None;
        }
        // Parsing is the check: a string that the verifier cannot read is not a key, and a
        // key ranger cannot use is worse than no key at all.
        minisign_verify::PublicKey::from_base64(public).ok()?;
        Some(Self {
            fingerprint: fingerprint(public),
            public: public.to_owned(),
        })
    }
}

/// Why a pack was refused, in the words a person can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// There is no signature beside the pack.
    NoSignature,
    /// The signature is not a minisign signature.
    Unreadable(String),
    /// No key has been trusted yet, so nothing can be verified.
    NoTrustedKey,
    /// No trusted key signed these bytes: the pack was signed by someone else, or the bytes
    /// changed after they were signed.
    NotVerified(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignature => formatter
                .write_str("The pack has no signature beside it, and ranger only loads a signed pack."),
            Self::Unreadable(reason) => {
                write!(formatter, "The signature could not be read: {reason}.")
            }
            Self::NoTrustedKey => formatter.write_str(
                "No key is trusted yet, so there is nothing to check the signature against. \
                 Add the author's public key first.",
            ),
            Self::NotVerified(reason) => write!(
                formatter,
                "None of the trusted keys signed these bytes: {reason}. This is what a pack \
                 signed by someone else, or changed after signing, looks like."
            ),
        }
    }
}

/// Check a pack's signature against the trusted keys.
///
/// Returns the fingerprint of the key that signed it, so the interface can say who wrote
/// what is loaded rather than only that something is loaded.
pub fn verify(pack: &[u8], signature: &str, trusted: &[Key]) -> Result<String, Refusal> {
    if signature.trim().is_empty() {
        return Err(Refusal::NoSignature);
    }
    if trusted.is_empty() {
        return Err(Refusal::NoTrustedKey);
    }
    let parsed = minisign_verify::Signature::decode(signature)
        .map_err(|error| Refusal::Unreadable(error.to_string()))?;
    let mut last = String::new();
    for key in trusted {
        let Ok(public) = minisign_verify::PublicKey::from_base64(&key.public) else {
            continue;
        };
        match public.verify(pack, &parsed, false) {
            Ok(()) => return Ok(key.fingerprint.clone()),
            Err(error) => last = error.to_string(),
        }
    }
    Err(Refusal::NotVerified(if last.is_empty() {
        "the signature names a key that is not on this machine".to_owned()
    } else {
        last
    }))
}

/// The fingerprint of a public key: the first eight bytes of its SHA-256, in four groups.
#[must_use]
pub fn fingerprint(public: &str) -> String {
    let digest = Sha256::digest(public.trim().as_bytes());
    let mut out = String::with_capacity(19);
    for (index, byte) in digest.iter().take(8).enumerate() {
        if index > 0 && index % 2 == 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed() -> (String, String, String) {
        // A key pair, a pack, and a signature over it — the shape a real author produces.
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pack = "{\"schema\":1}".to_owned();
        let signature =
            minisign::sign(None, &pair.sk, pack.as_bytes(), Some("vn-ranger test pack"), None).unwrap();
        (pair.pk.to_base64(), pack, signature.to_string())
    }

    #[test]
    fn a_genuinely_signed_pack_verifies_and_names_its_key() {
        let (public, pack, signature) = signed();
        let key = Key::parse(&public).unwrap();
        let signed_by = verify(pack.as_bytes(), &signature, std::slice::from_ref(&key)).unwrap();
        assert_eq!(signed_by, key.fingerprint);
    }

    #[test]
    fn one_flipped_byte_of_the_pack_is_refused() {
        let (public, pack, signature) = signed();
        let key = Key::parse(&public).unwrap();
        for index in [0, pack.len() / 2, pack.len() - 1] {
            let mut tampered = pack.clone().into_bytes();
            tampered[index] ^= 0x01;
            assert!(
                matches!(
                    verify(&tampered, &signature, std::slice::from_ref(&key)),
                    Err(Refusal::NotVerified(_))
                ),
                "a byte changed at {index} must not verify"
            );
        }
    }

    #[test]
    fn one_flipped_byte_of_the_signature_is_refused() {
        let (public, pack, signature) = signed();
        let key = Key::parse(&public).unwrap();
        let mut tampered = signature.clone();
        // Flip the first character of the signature body, not of the comment line.
        let start = tampered.find('\n').map_or(0, |index| index + 1);
        let at = tampered[start..]
            .char_indices()
            .find(|(_, character)| character.is_ascii_alphanumeric())
            .map(|(index, _)| start + index)
            .expect("a signature has a body");
        let replacement = if tampered.as_bytes()[at] == b'A' { "B" } else { "A" };
        tampered.replace_range(at..at + 1, replacement);
        assert!(
            matches!(
                verify(pack.as_bytes(), &tampered, std::slice::from_ref(&key)),
                Err(Refusal::NotVerified(_)) | Err(Refusal::Unreadable(_))
            ),
            "a changed signature must not verify"
        );
    }

    #[test]
    fn a_pack_signed_by_another_key_is_refused_and_the_refusal_says_so() {
        let (_public, pack, signature) = signed();
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let trusted = Key::parse(&other.pk.to_base64()).unwrap();
        let refusal = verify(pack.as_bytes(), &signature, &[trusted]).unwrap_err();
        assert!(matches!(refusal, Refusal::NotVerified(_)));
        assert!(refusal.to_string().contains("signed by someone else"));
    }

    #[test]
    fn nothing_trusted_yet_is_its_own_refusal() {
        let (_public, pack, signature) = signed();
        assert_eq!(
            verify(pack.as_bytes(), &signature, &[]).unwrap_err(),
            Refusal::NoTrustedKey
        );
        assert_eq!(
            verify(pack.as_bytes(), "  ", &[]).unwrap_err(),
            Refusal::NoSignature
        );
    }

    #[test]
    fn something_that_is_not_a_signature_is_unreadable_rather_than_believed() {
        let (public, pack, _signature) = signed();
        let key = Key::parse(&public).unwrap();
        let refusal = verify(pack.as_bytes(), "not a signature", std::slice::from_ref(&key)).unwrap_err();
        assert!(matches!(refusal, Refusal::Unreadable(_)), "{refusal:?}");
    }

    #[test]
    fn a_key_that_is_not_a_key_cannot_be_parsed() {
        assert_eq!(Key::parse(""), None);
        assert_eq!(Key::parse("hello"), None);
    }

    #[test]
    fn a_fingerprint_is_short_uppercase_and_stable() {
        let (public, _, _) = signed();
        let key = Key::parse(&public).unwrap();
        assert_eq!(key.fingerprint.len(), 19, "eight groups and three spaces");
        assert_eq!(key.fingerprint, fingerprint(&public));
        assert!(
            key.fingerprint
                .chars()
                .all(|character| character.is_ascii_hexdigit() || character == ' ')
        );
        assert_ne!(
            key.fingerprint,
            Key::parse(&public).unwrap().fingerprint.to_lowercase(),
            "hexadecimal is written in one case"
        );
    }
}
