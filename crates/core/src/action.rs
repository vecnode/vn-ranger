//! The grammar of a destructive act: ids, roots and refusals.
//!
//! Nothing here touches a filesystem. It is the vocabulary the action path uses, kept
//! pure so that "which act, under which root, refused for which reason" can be tested
//! without a disk, and so that the only place a path is resolved is one function in
//! `vnr-native::action`.

use std::fmt;

use crate::model::{AutorunFact, AutorunKind, AutorunScope};

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
    /// The entry starts for every account, and changing it needs an administrator.
    MachineScope,
    /// This build reads that kind of startup entry and does not change it.
    UnsupportedSurface,
    /// The name a startup entry would be written under is not one ranger will write.
    NotAName,
    /// The command is not something ranger will put in a startup entry.
    NotACommand,
    /// The scan and the screen do not agree about which entry is meant.
    NotTheSameEntry,
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
            Self::MachineScope => {
                "That entry starts for every account on this machine. Changing it needs an administrator, and ranger has no standing elevation."
            }
            Self::UnsupportedSurface => {
                "This build reads that kind of startup entry and does not change it yet."
            }
            Self::NotAName => {
                "A startup entry needs a name of one to 64 characters, with no control characters and no backslash."
            }
            Self::NotACommand => {
                "A startup entry needs a command: one line, starting with a program path, optionally followed by arguments."
            }
            Self::NotTheSameEntry => {
                "The scan and this screen do not agree about which entry that is, so nothing was done."
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
            Self::MachineScope => "needs an administrator",
            Self::UnsupportedSurface => "not changed by this build",
            Self::NotAName => "not a name",
            Self::NotACommand => "not a command",
            Self::NotTheSameEntry => "not the entry that was scanned",
        }
    }
}

/// A startup surface a change may be made in.
///
/// Deliberately not a [`Surface`]: that table describes folders whose files are cleaned,
/// where a file is named by an [`EntryId`]. A startup entry is a registry value or a `.lnk`,
/// identified by the [`AutorunFact`] a scan produced, and this is the row that governs it —
/// which knows whether this build may write it, and why not when it may not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StartupSurface {
    /// `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
    WinUserRun,
    /// `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`.
    WinUserRunOnce,
    /// The user's Startup folder, where one fact is one `.lnk`.
    UserStartupFolder,
    /// `HKLM`'s `Run` and `RunOnce`: machine scope, read and refused.
    WinMachineRun,
    /// The machine's Startup folder: read and refused.
    MachineStartupFolder,
    /// An XDG autostart entry in the user's home: read in this build.
    LinuxXdgAutostart,
    /// A user systemd unit: read in this build.
    LinuxSystemdUser,
    /// A cron entry: read in this build.
    LinuxCron,
    /// A launch agent in the user's home: read in this build.
    MacLaunchAgent,
    /// Anything else the scan reports, which this build does not change.
    Other,
}

impl StartupSurface {
    /// Every surface, for the interface and the tests.
    pub const ALL: [StartupSurface; 10] = [
        Self::WinUserRun,
        Self::WinUserRunOnce,
        Self::UserStartupFolder,
        Self::WinMachineRun,
        Self::MachineStartupFolder,
        Self::LinuxXdgAutostart,
        Self::LinuxSystemdUser,
        Self::LinuxCron,
        Self::MacLaunchAgent,
        Self::Other,
    ];

    /// The stable name, used in the journal and in a settings file.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::WinUserRun => "win.user.run",
            Self::WinUserRunOnce => "win.user.runonce",
            Self::UserStartupFolder => "win.user.startupfolder",
            Self::WinMachineRun => "win.machine.run",
            Self::MachineStartupFolder => "win.machine.startupfolder",
            Self::LinuxXdgAutostart => "linux.xdg.autostart",
            Self::LinuxSystemdUser => "linux.systemd.user",
            Self::LinuxCron => "linux.cron",
            Self::MacLaunchAgent => "mac.launchagent",
            Self::Other => "other",
        }
    }

    /// What a person calls it.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::WinUserRun => "This account's Run key",
            Self::WinUserRunOnce => "This account's RunOnce key",
            Self::UserStartupFolder => "This account's Startup folder",
            Self::WinMachineRun => "The machine's Run keys",
            Self::MachineStartupFolder => "The machine's Startup folder",
            Self::LinuxXdgAutostart => "Autostart entries in your home folder",
            Self::LinuxSystemdUser => "Your systemd user units",
            Self::LinuxCron => "Your cron entries",
            Self::MacLaunchAgent => "Launch agents in your home folder",
            Self::Other => "A startup surface this build does not change",
        }
    }

    /// Whether this build may write this surface.
    ///
    /// It is a table rather than a check at the call site: a surface is writable because a
    /// row says so, and a new surface without a row cannot be acted on by accident.
    #[must_use]
    pub fn writable(self) -> bool {
        self.refusal().is_none()
    }

    /// Why this build may not write it, when it may not.
    #[must_use]
    pub fn refusal(self) -> Option<Refusal> {
        match self {
            Self::WinUserRun | Self::WinUserRunOnce | Self::UserStartupFolder => None,
            // A machine-wide entry is a two-hundred-millisecond UAC prompt away from being
            // removable, and that is exactly the standing privilege this program refuses.
            Self::WinMachineRun | Self::MachineStartupFolder => Some(Refusal::MachineScope),
            // Read today, written later: saying "not yet" is the truth, and a refusal a
            // person can read is worth more than a button that fails.
            Self::LinuxXdgAutostart
            | Self::LinuxSystemdUser
            | Self::LinuxCron
            | Self::MacLaunchAgent
            | Self::Other => Some(Refusal::UnsupportedSurface),
        }
    }

    /// The surface a scan's fact belongs to.
    ///
    /// `Run` and `RunOnce` share one [`AutorunKind`], so the location is what tells them
    /// apart: a fact whose location names `RunOnce` is not the same key as one that does not.
    #[must_use]
    pub fn of(entry: &AutorunFact) -> Self {
        let location = entry.location.to_lowercase();
        match (entry.kind, entry.scope) {
            (AutorunKind::RunKey, AutorunScope::User) if location.contains("runonce") => Self::WinUserRunOnce,
            (AutorunKind::RunKey, AutorunScope::User) => Self::WinUserRun,
            (AutorunKind::RunKey, AutorunScope::System) => Self::WinMachineRun,
            (AutorunKind::StartupFolder, AutorunScope::User) => Self::UserStartupFolder,
            (AutorunKind::StartupFolder, AutorunScope::System) => Self::MachineStartupFolder,
            (AutorunKind::XdgAutostart, _) => Self::LinuxXdgAutostart,
            (AutorunKind::SystemdUnit, _) => Self::LinuxSystemdUser,
            (AutorunKind::Cron, _) => Self::LinuxCron,
            (AutorunKind::LaunchAgent, _) => Self::MacLaunchAgent,
            _ => Self::Other,
        }
    }
}

/// A change to one startup entry.
///
/// The unit is the entry a scan produced, never a path and never a key name a caller made up:
/// `Remove` carries the fact, so the implementation can re-read that entry and refuse when it
/// is no longer the entry a person was shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupChange {
    /// Put a command in this account's startup.
    Add {
        /// Where it goes.
        surface: StartupSurface,
        /// The name it is registered under.
        name: String,
        /// The command line, as a person typed it.
        command: String,
    },
    /// Take one entry away, keeping what it said so it can be put back by hand.
    Remove {
        /// Where it lives.
        surface: StartupSurface,
        /// The entry as the scan reported it.
        entry: AutorunFact,
    },
}

impl StartupChange {
    /// The surface this change happens in.
    #[must_use]
    pub fn surface(&self) -> StartupSurface {
        match self {
            Self::Add { surface, .. } | Self::Remove { surface, .. } => *surface,
        }
    }

    /// Why this change may not be made, when it may not.
    ///
    /// Everything that can be decided without touching the machine is decided here, so the
    /// implementation only has to re-read and compare.
    pub fn check(&self) -> Result<(), Refusal> {
        let surface = self.surface();
        if let Some(refusal) = surface.refusal() {
            return Err(refusal);
        }
        match self {
            Self::Add { name, command, .. } => {
                if !name_is_writable(name) {
                    return Err(Refusal::NotAName);
                }
                if !command_is_writable(command) {
                    return Err(Refusal::NotACommand);
                }
                Ok(())
            }
            Self::Remove { entry, .. } => {
                if StartupSurface::of(entry) != surface {
                    return Err(Refusal::NotTheSameEntry);
                }
                if entry.scope != AutorunScope::User {
                    return Err(Refusal::MachineScope);
                }
                Ok(())
            }
        }
    }
}

/// The longest name a startup entry may be given.
pub const MAX_STARTUP_NAME: usize = 64;

/// The longest command a startup entry may be given.
pub const MAX_STARTUP_COMMAND: usize = 4096;

/// Whether a name is one this program will write into a startup surface.
///
/// It is not a path, a key path or an escape: a backslash in a registry value name reads as
/// a key beneath another key, and a control character reads as two entries in a file.
#[must_use]
pub fn name_is_writable(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_STARTUP_NAME
        || trimmed != name
        || trimmed == "."
        || trimmed == ".."
    {
        return false;
    }
    !trimmed
        .chars()
        .any(|character| character == '\\' || character.is_control())
}

/// Whether a command is one this program will write into a startup surface.
#[must_use]
pub fn command_is_writable(command: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_STARTUP_COMMAND || trimmed.contains(['\n', '\r', '\0']) {
        return false;
    }
    // The first token is the program: quoted, so a path with spaces is one token, or bare.
    let program = match trimmed.strip_prefix('"') {
        Some(rest) => match rest.split_once('"') {
            Some((program, tail)) => {
                // A quoted path must be followed by nothing or by a space, or the quote did
                // not close where it looked like it closed.
                if !tail.is_empty() && !tail.starts_with(' ') {
                    return false;
                }
                program
            }
            None => return false,
        },
        None => trimmed.split_whitespace().next().unwrap_or(""),
    };
    is_absolute_program(program)
}

/// Whether a program token names a program by its whole path.
fn is_absolute_program(program: &str) -> bool {
    let bytes = program.as_bytes();
    program.starts_with('/')
        || program.starts_with('\\')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/'))
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
            Refusal::MachineScope,
            Refusal::UnsupportedSurface,
            Refusal::NotAName,
            Refusal::NotACommand,
            Refusal::NotTheSameEntry,
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

    fn entry(kind: AutorunKind, scope: AutorunScope, location: &str, command: &str) -> AutorunFact {
        AutorunFact {
            id: "autorun:test".to_owned(),
            name: "Thing".to_owned(),
            command: command.to_owned(),
            location: location.to_owned(),
            kind,
            scope,
            enabled: true,
            hidden: false,
            exe: None,
            sha256: None,
            signature: crate::model::SignatureStatus::NotChecked,
        }
    }

    #[test]
    fn a_user_surface_is_writable_and_a_machine_one_says_who_can_change_it() {
        for surface in StartupSurface::ALL {
            match surface {
                StartupSurface::WinUserRun
                | StartupSurface::WinUserRunOnce
                | StartupSurface::UserStartupFolder => {
                    assert!(surface.writable(), "{} must be writable", surface.id());
                    assert_eq!(surface.refusal(), None);
                }
                StartupSurface::WinMachineRun | StartupSurface::MachineStartupFolder => {
                    assert!(!surface.writable());
                    assert_eq!(surface.refusal(), Some(Refusal::MachineScope));
                }
                _ => {
                    assert!(!surface.writable(), "{} is not written here", surface.id());
                    assert_eq!(surface.refusal(), Some(Refusal::UnsupportedSurface));
                }
            }
        }
    }

    #[test]
    fn a_run_once_entry_is_not_the_run_key() {
        let run = entry(
            AutorunKind::RunKey,
            AutorunScope::User,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Program Files\A\a.exe",
        );
        let once = entry(
            AutorunKind::RunKey,
            AutorunScope::User,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"C:\Program Files\A\a.exe",
        );
        assert_eq!(StartupSurface::of(&run), StartupSurface::WinUserRun);
        assert_eq!(StartupSurface::of(&once), StartupSurface::WinUserRunOnce);
        let folder = entry(
            AutorunKind::StartupFolder,
            AutorunScope::User,
            r"C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk",
            "",
        );
        assert_eq!(StartupSurface::of(&folder), StartupSurface::UserStartupFolder);
        let machine = entry(
            AutorunKind::RunKey,
            AutorunScope::System,
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Windows\a.exe",
        );
        assert_eq!(StartupSurface::of(&machine), StartupSurface::WinMachineRun);
    }

    #[test]
    fn a_removal_that_is_not_the_entry_that_was_scanned_is_refused() {
        let machine = entry(
            AutorunKind::RunKey,
            AutorunScope::System,
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Windows\a.exe",
        );
        let wrong_surface = StartupChange::Remove {
            surface: StartupSurface::WinUserRun,
            entry: machine,
        };
        assert_eq!(wrong_surface.check(), Err(Refusal::NotTheSameEntry));

        let machine = entry(
            AutorunKind::RunKey,
            AutorunScope::System,
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Windows\a.exe",
        );
        let scope = StartupChange::Remove {
            surface: StartupSurface::WinMachineRun,
            entry: machine,
        };
        assert_eq!(scope.check(), Err(Refusal::MachineScope));

        let user = entry(
            AutorunKind::RunKey,
            AutorunScope::User,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"C:\Program Files\A\a.exe",
        );
        let ok = StartupChange::Remove {
            surface: StartupSurface::WinUserRun,
            entry: user,
        };
        assert_eq!(ok.check(), Ok(()));
    }

    #[test]
    fn a_name_that_could_be_a_key_path_is_not_a_name() {
        for bad in ["", " ", " a", "a ", ".", "..", "a\\b", "line\nbreak", "tab\tkey"] {
            assert!(!name_is_writable(bad), "{bad:?} must be refused");
        }
        for good in ["Acme Agent", "a", "A-1_2", "Ünïcode"] {
            assert!(name_is_writable(good), "{good:?} must be accepted");
        }
        assert!(!name_is_writable(&"n".repeat(MAX_STARTUP_NAME + 1)));
        assert!(name_is_writable(&"n".repeat(MAX_STARTUP_NAME)));
    }

    #[test]
    fn a_command_that_is_not_a_program_is_not_written() {
        for bad in [
            "",
            "updater.exe",
            "start acme",
            "C:\\a.exe\nb",
            "\"C:\\Program Files\\A\\a.exe\"x",
            "\"C:\\never closed",
        ] {
            assert!(!command_is_writable(bad), "{bad:?} must be refused");
        }
        for good in [
            r"C:\Program Files\Acme\acme.exe",
            "\"C:\\Program Files\\Acme\\acme.exe\" --quiet",
            "/opt/acme/acme",
            r"C:\a.exe",
        ] {
            assert!(command_is_writable(good), "{good:?} must be accepted");
        }
    }

    #[test]
    fn an_add_is_checked_before_anything_is_written() {
        let ok = StartupChange::Add {
            surface: StartupSurface::WinUserRun,
            name: "Acme".to_owned(),
            command: r"C:\Program Files\Acme\acme.exe".to_owned(),
        };
        assert_eq!(ok.check(), Ok(()));
        let bad_name = StartupChange::Add {
            surface: StartupSurface::WinUserRun,
            name: "a\\b".to_owned(),
            command: r"C:\a.exe".to_owned(),
        };
        assert_eq!(bad_name.check(), Err(Refusal::NotAName));
        let bad_command = StartupChange::Add {
            surface: StartupSurface::WinUserRun,
            name: "Acme".to_owned(),
            command: "acme.exe".to_owned(),
        };
        assert_eq!(bad_command.check(), Err(Refusal::NotACommand));
        let machine = StartupChange::Add {
            surface: StartupSurface::WinMachineRun,
            name: "Acme".to_owned(),
            command: r"C:\a.exe".to_owned(),
        };
        assert_eq!(machine.check(), Err(Refusal::MachineScope));
    }

    #[test]
    fn every_startup_surface_names_itself_once() {
        let mut seen = std::collections::HashSet::new();
        for surface in StartupSurface::ALL {
            assert!(seen.insert(surface.id()), "{} appears twice", surface.id());
            assert!(!surface.label().is_empty());
        }
    }
}
