//! Opt-in autostart: one entry, named, shown, removable.
//!
//! Ranger does not install itself. This module is the only place that writes an entry the
//! operating system will run at login, it writes exactly one, and it names that entry so
//! Settings can show the person what they are turning on before they turn it on
//! (`docs/PLAN.md` §6.5).
//!
//! Three mechanisms, one contract:
//!
//! - **written idempotently** — asking twice is one entry, not two;
//! - **removed precisely** — only ranger's own value, file or key, and a removal that finds
//!   nothing is a success rather than an error, because "it is already gone" is the state
//!   the person asked for;
//! - **never privileged** — `HKCU`, `~/Library/LaunchAgents` and `~/.config/autostart`.
//!   Nothing here needs an administrator, and nothing here can be made to.
//!
//! The texts themselves live in [`entry`], with no IO, so every host tests all three
//! formats.

mod entry;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// The entry's name, used by the plist `Label` and by the desktop file's name.
pub const NAME: &str = "dev.vecnode.ranger";

/// The registry value name on Windows. `Run` values are free-form, so this is the whole
/// identity of ranger's entry there.
pub const RUN_VALUE: &str = "vn-ranger";

/// The flag a login launch carries, so the window starts in the status area rather than in
/// the middle of whatever the person was doing.
pub const BACKGROUND_FLAG: &str = "--background";

/// Where an entry is, and what it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// The registry key with its value name, the plist path, or the desktop file path —
    /// exactly as a person would go and look at it.
    pub at: String,
    /// The command line the operating system will run.
    pub command: String,
}

/// What ranger found when it looked for its own entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Ranger starts at login, from this entry.
    On(Location),
    /// There is no entry, or there is one and it is not ranger's.
    Off,
    /// This machine cannot carry an entry, and this is why.
    Unavailable(String),
}

impl State {
    /// Whether the person has asked for autostart.
    #[must_use]
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On(_))
    }
}

/// Look for ranger's entry without writing anything.
#[must_use]
pub fn state() -> State {
    platform::state()
}

/// Write the entry, or say why it could not be written.
///
/// Calling this when the entry already exists rewrites the same bytes: the mechanism is one
/// value, one file, one key, and the command is derived from where the binary is now.
pub fn enable() -> Result<Location, String> {
    platform::enable()
}

/// Remove ranger's entry, and only ranger's entry.
///
/// A missing entry is `Ok(())`. Nothing else in the registry key or the directory is read,
/// rewritten or deleted.
pub fn disable() -> Result<(), String> {
    platform::disable()
}

/// The command line a login launch runs.
///
/// Only the Windows backend builds one from a registry value: the macOS and Linux backends
/// take the executable's path directly, so on those targets this function has no caller and
/// `-D warnings` would refuse it. Gating it is the fix the platform rules in `AGENTS.md` §5
/// ask for: an item, not a statement, so nothing else changes shape.
#[cfg(windows)]
fn command_line() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("Could not find where ranger is running from: {error}"))?;
    Ok(entry::run_value(&exe))
}

#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
mod platform {
    use super::{Location, State};

    pub(super) fn state() -> State {
        State::Unavailable("ranger knows no autostart mechanism for this system".to_owned())
    }

    pub(super) fn enable() -> Result<Location, String> {
        Err("ranger knows no autostart mechanism for this system".to_owned())
    }

    pub(super) fn disable() -> Result<(), String> {
        Err("ranger knows no autostart mechanism for this system".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_is_one_the_suite_owns() {
        assert_eq!(NAME, "dev.vecnode.ranger");
        assert_eq!(RUN_VALUE, "vn-ranger");
        assert_eq!(BACKGROUND_FLAG, "--background");
        assert!(NAME.contains("vecnode"), "the entry is identifiable as ours");
    }

    #[test]
    fn only_an_entry_that_is_there_counts_as_on() {
        assert!(!State::Off.is_on());
        assert!(!State::Unavailable("none".to_owned()).is_on());
        assert!(
            State::On(Location {
                at: "x".to_owned(),
                command: "y".to_owned(),
            })
            .is_on()
        );
    }
}
