//! The grammar of a destructive act: ids, roots and refusals.
//!
//! Nothing here touches a filesystem. It is the vocabulary the action path uses, kept
//! pure so that "which act, under which root, refused for which reason" can be tested
//! without a disk, and so that the only place a path is resolved is one function in
//! `vnr-native::action`.

use std::fmt;

/// An entry inside a root, named by sixteen hexadecimal characters.
///
/// It is not a file name and not a path. The action layer builds every string it hands
/// the filesystem from this value, so a caller cannot introduce a separator, `..`, an
/// absolute path or a Unicode trick into a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryId([u8; 8]);

impl EntryId {
    /// The number of characters an id is written with.
    pub const HEX_LEN: usize = 16;

    /// The id for a sequence of bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Take the first eight bytes of a digest as an id.
    ///
    /// The caller supplies the digest; the core does not know how to make one, because
    /// making one means reading a clock or a random source.
    #[must_use]
    pub fn from_digest(digest: &[u8]) -> Option<Self> {
        let bytes: [u8; 8] = digest.get(..8)?.try_into().ok()?;
        Some(Self(bytes))
    }

    /// The id as sixteen lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(Self::HEX_LEN);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }

    /// Read an id back, refusing anything that is not exactly sixteen hex characters.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != Self::HEX_LEN {
            return None;
        }
        let mut bytes = [0_u8; 8];
        for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            bytes[index] = u8::try_from(high * 16 + low).ok()?;
        }
        Some(Self(bytes))
    }

    /// Whether a string could be an id. Used before anything is resolved.
    #[must_use]
    pub fn is_valid(text: &str) -> bool {
        Self::from_hex(text).is_some()
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// An allowlisted place cleaning may happen in.
///
/// Each name is one row of the table in `docs/PLAN.md` §6.10. A surface carries its own
/// age threshold, because "a day old" is right for a cache and wrong for a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// `%TEMP%` and `%LOCALAPPDATA%\Temp`.
    WinTemp,
    /// `%LOCALAPPDATA%\CrashDumps`.
    WinCrashDumps,
    /// `%LOCALAPPDATA%\Microsoft\Windows\INetCache`.
    WinInetCache,
    /// `%LOCALAPPDATA%\D3DSCache`.
    WinGpuCache,
    /// The package-manager caches under `%LOCALAPPDATA%`.
    WinPackageCache,
    /// `~/Library/Caches`, except the system's own entries.
    MacCaches,
    /// `$TMPDIR` on macOS.
    MacTemp,
    /// `~/Library/Logs`: opt-in, and older than a week.
    MacLogs,
    /// `$XDG_CACHE_HOME` or `~/.cache`.
    LinuxCache,
    /// `$TMPDIR` on Linux.
    LinuxTemp,
    /// Files directly in `/tmp` owned by the current user.
    LinuxTmpFiles,
}

impl Surface {
    /// Every surface, for the interface and the tests.
    pub const ALL: [Surface; 11] = [
        Self::WinTemp,
        Self::WinCrashDumps,
        Self::WinInetCache,
        Self::WinGpuCache,
        Self::WinPackageCache,
        Self::MacCaches,
        Self::MacTemp,
        Self::MacLogs,
        Self::LinuxCache,
        Self::LinuxTemp,
        Self::LinuxTmpFiles,
    ];

    /// The stable name, used in the journal, the settings file and a `RootId`.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::WinTemp => "win.temp",
            Self::WinCrashDumps => "win.crashdumps",
            Self::WinInetCache => "win.inetcache",
            Self::WinGpuCache => "win.gpu",
            Self::WinPackageCache => "win.pkgcache",
            Self::MacCaches => "mac.caches",
            Self::MacTemp => "mac.temp",
            Self::MacLogs => "mac.logs",
            Self::LinuxCache => "linux.cache",
            Self::LinuxTemp => "linux.temp",
            Self::LinuxTmpFiles => "linux.tmpfiles",
        }
    }

    /// What a person calls it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::WinTemp => "Temporary files",
            Self::WinCrashDumps => "Crash dumps",
            Self::WinInetCache => "Internet cache",
            Self::WinGpuCache => "GPU shader cache",
            Self::WinPackageCache => "Package manager caches",
            Self::MacCaches => "User caches",
            Self::MacTemp => "Temporary files",
            Self::MacLogs => "User logs",
            Self::LinuxCache => "User cache",
            Self::LinuxTemp => "Temporary files",
            Self::LinuxTmpFiles => "Files in /tmp",
        }
    }

    /// How old an entry must be before it may go, in seconds.
    ///
    /// A cache that was written a minute ago is still in use. A day is the default; logs
    /// get a week, because a log is what you read the morning after.
    #[must_use]
    pub fn minimum_age_seconds(self) -> u64 {
        match self {
            Self::MacLogs => 7 * 24 * 60 * 60,
            _ => 24 * 60 * 60,
        }
    }

    /// Whether removing this surface's contents is a choice the person makes explicitly.
    ///
    /// Logs are off by default: they are small, and they are evidence.
    #[must_use]
    pub fn is_opt_in(self) -> bool {
        matches!(self, Self::MacLogs)
    }

    /// The surface with this id, if there is one.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|surface| surface.id() == id)
    }
}

/// Where an act may happen.
///
/// There is no variant for "an arbitrary path", and that is the entire point: a clean
/// cannot name a directory that is not a surface, and a quarantine destination is
/// computed from an [`EntryId`] under the quarantine root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RootId {
    /// The app-managed quarantine.
    Quarantine,
    /// One allowlisted surface.
    Clean(Surface),
}

impl RootId {
    /// The stable name, for the journal.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::Clean(surface) => surface.id(),
        }
    }
}

/// Why an act was refused.
///
/// Each variant is an outcome with a sentence, because {"something went wrong"} is not
/// something a person can act on and an unexplained refusal trains people to click
/// through dialogs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The id was not sixteen hex characters.
    NotAnEntry,
    /// The entry is not below the root it claims.
    OutsideRoot,
    /// The file is a link, a junction or a reparse point.
    IsLink,
    /// The file has another name on the same volume, so moving it would leave one behind.
    ManyLinks,
    /// The file is no longer the file that was inspected.
    Changed,
    /// The target is a directory, a device or something else that is not a regular file.
    NotAFile,
    /// The file is gone.
    SourceMissing,
    /// Something already exists where the act would write.
    DestinationOccupied,
    /// The stored bytes are not the bytes the manifest recorded.
    HashMismatch,
    /// The file is larger than the action path will hash, so it cannot be verified.
    TooLarge,
}

impl Refusal {
    /// The sentence the interface and the journal show.
    #[must_use]
    pub fn sentence(self) -> &'static str {
        match self {
            Self::NotAnEntry => "That is not an entry id; ranger only acts on an id, never on a path.",
            Self::OutsideRoot => "The entry is not inside the root it claims, so nothing was touched.",
            Self::IsLink => "The file is a link or a reparse point. Ranger does not follow one when it acts.",
            Self::ManyLinks => {
                "The file has another name elsewhere on this volume, so moving it would leave that name behind."
            }
            Self::Changed => {
                "The file changed after it was inspected, so it is no longer the file that was checked."
            }
            Self::NotAFile => "That is not a regular file, so there is nothing to act on.",
            Self::SourceMissing => "The file is not there any more.",
            Self::DestinationOccupied => {
                "Something already exists at the destination, and ranger does not overwrite it."
            }
            Self::HashMismatch => {
                "The stored bytes no longer match the hash in the manifest, so this is not the file that was quarantined."
            }
            Self::TooLarge => {
                "The file is larger than ranger will hash, so it could not be verified after the move."
            }
        }
    }

    /// A short label, for a list row.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAnEntry => "not an entry",
            Self::OutsideRoot => "outside the root",
            Self::IsLink => "a link",
            Self::ManyLinks => "another link exists",
            Self::Changed => "changed since it was inspected",
            Self::NotAFile => "not a file",
            Self::SourceMissing => "missing",
            Self::DestinationOccupied => "destination occupied",
            Self::HashMismatch => "hash mismatch",
            Self::TooLarge => "too large to verify",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_sixteen_hex_characters_and_round_trips() {
        let id = EntryId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(id.to_hex(), "0123456789abcdef");
        assert_eq!(EntryId::from_hex("0123456789abcdef"), Some(id));
        assert_eq!(id.to_string(), "0123456789abcdef");
    }

    #[test]
    fn an_id_refuses_everything_that_is_not_one() {
        for bad in [
            "",
            "0123456789abcde",
            "0123456789abcdef0",
            "../0123456789abc",
            "0123456789abcde/",
            "0123456789ABCDE-",
            "0123456789abcdef\n",
            "0123456789ABCDEZ",
        ] {
            assert_eq!(EntryId::from_hex(bad), None, "{bad:?} must not parse");
            assert!(!EntryId::is_valid(bad));
        }
        assert!(
            EntryId::is_valid("0123456789ABCDEF"),
            "case is not a security property"
        );
    }

    #[test]
    fn an_id_cannot_contain_a_separator_or_a_dot() {
        for bad in ["..", "a/b", "a\\b", ":", ".", "0.123456789abc"] {
            assert!(!EntryId::is_valid(bad));
        }
    }

    #[test]
    fn an_id_from_a_digest_needs_eight_bytes() {
        assert_eq!(EntryId::from_digest(&[0; 7]), None);
        assert!(EntryId::from_digest(&[0; 8]).is_some());
        assert_eq!(
            EntryId::from_digest(&[0xff; 32]).map(EntryId::to_hex),
            Some("ffffffffffffffff".to_owned())
        );
    }

    #[test]
    fn every_surface_has_a_unique_id_and_a_label() {
        let mut seen = std::collections::HashSet::new();
        for surface in Surface::ALL {
            assert!(seen.insert(surface.id()), "{} appears twice", surface.id());
            assert!(!surface.label().is_empty());
            assert_eq!(Surface::from_id(surface.id()), Some(surface));
            assert!(surface.minimum_age_seconds() >= 60 * 60);
        }
        assert_eq!(Surface::from_id("win.temp"), Some(Surface::WinTemp));
        assert_eq!(Surface::from_id("nope"), None);
    }

    #[test]
    fn logs_are_opt_in_and_kept_longer() {
        assert!(Surface::MacLogs.is_opt_in());
        assert!(!Surface::MacCaches.is_opt_in());
        assert!(Surface::MacLogs.minimum_age_seconds() > Surface::MacCaches.minimum_age_seconds());
    }

    #[test]
    fn every_refusal_says_what_it_means() {
        for refusal in [
            Refusal::NotAnEntry,
            Refusal::OutsideRoot,
            Refusal::IsLink,
            Refusal::ManyLinks,
            Refusal::Changed,
            Refusal::NotAFile,
            Refusal::SourceMissing,
            Refusal::DestinationOccupied,
            Refusal::HashMismatch,
            Refusal::TooLarge,
        ] {
            assert!(
                refusal.sentence().ends_with('.'),
                "{} is a sentence",
                refusal.label()
            );
            assert!(!refusal.label().is_empty());
            assert_ne!(refusal.sentence(), "Something went wrong.");
        }
    }

    #[test]
    fn a_root_names_itself_for_the_journal() {
        assert_eq!(RootId::Quarantine.id(), "quarantine");
        assert_eq!(RootId::Clean(Surface::LinuxCache).id(), "linux.cache");
    }
}
