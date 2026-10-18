//! Autostart on Windows: one value under `HKCU\...\Run`.
//!
//! A per-user value in the run key, never `HKLM`, never a service, never a scheduled task
//! running as SYSTEM (§6.5). The value's *name* is ranger's identity: the key is shared with
//! every other program that starts at login, so writing and removing are done by name and
//! nothing else in the key is touched.
//!
//! The three operations ranger needs — read one value, write one value, delete one value —
//! sit behind [`Store`], so the behaviour that matters (idempotent write, precise removal,
//! "already gone" as success) is tested on every host against an in-memory store. The
//! registry itself is then three lines per operation, which is the only part that cannot be
//! exercised without a machine that allows the write.

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

use super::{Location, RUN_VALUE, State};

/// Where the entry lives. Shown with the value name, because the key alone is not enough
/// for a person to find it.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// One startup entry: one name, one command line.
trait Store {
    fn get(&self) -> Result<Option<String>, String>;
    fn set(&self, command: &str) -> Result<(), String>;
    fn delete(&self) -> Result<(), String>;
}

/// The real thing: one value of one key.
struct Registry;

impl Store for Registry {
    fn get(&self) -> Result<Option<String>, String> {
        let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_READ) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("Could not open HKCU\\{RUN_KEY}: {error}")),
        };
        match key.get_value::<String, _>(RUN_VALUE) {
            Ok(command) => Ok(Some(command)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Could not read HKCU\\{RUN_KEY}\\{RUN_VALUE}: {error}")),
        }
    }

    fn set(&self, command: &str) -> Result<(), String> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE)
            .map_err(|error| format!("Could not open HKCU\\{RUN_KEY} to write an entry: {error}"))?;
        key.set_value(RUN_VALUE, &command.to_owned())
            .map_err(|error| format!("Could not write HKCU\\{RUN_KEY}\\{RUN_VALUE}: {error}"))
    }

    fn delete(&self) -> Result<(), String> {
        let key = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("Could not open HKCU\\{RUN_KEY}: {error}")),
        };
        match key.delete_value(RUN_VALUE) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("Could not remove HKCU\\{RUN_KEY}\\{RUN_VALUE}: {error}")),
        }
    }
}

/// What a person reads in `regedit`: the key and the value name, not the key alone.
fn shown_name() -> String {
    format!("HKCU\\{RUN_KEY}\\{RUN_VALUE}")
}

pub(super) fn state() -> State {
    state_with(&Registry)
}

pub(super) fn enable() -> Result<Location, String> {
    let command = super::command_line()?;
    enable_with(&Registry, &command)
}

pub(super) fn disable() -> Result<(), String> {
    disable_with(&Registry)
}

fn state_with(store: &dyn Store) -> State {
    match store.get() {
        Ok(Some(command)) => State::On(Location {
            at: shown_name(),
            command,
        }),
        Ok(None) => State::Off,
        Err(reason) => State::Unavailable(reason),
    }
}

fn enable_with(store: &dyn Store, command: &str) -> Result<Location, String> {
    store.set(command)?;
    Ok(Location {
        at: shown_name(),
        command: command.to_owned(),
    })
}

fn disable_with(store: &dyn Store) -> Result<(), String> {
    store.delete()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    /// A run key with one value in it, and nothing else.
    #[derive(Default)]
    struct Memory {
        values: RefCell<BTreeMap<String, String>>,
        refuse: bool,
    }

    impl Store for Memory {
        fn get(&self) -> Result<Option<String>, String> {
            if self.refuse {
                return Err("access denied".to_owned());
            }
            Ok(self.values.borrow().get(RUN_VALUE).cloned())
        }

        fn set(&self, command: &str) -> Result<(), String> {
            if self.refuse {
                return Err("access denied".to_owned());
            }
            self.values
                .borrow_mut()
                .insert(RUN_VALUE.to_owned(), command.to_owned());
            Ok(())
        }

        fn delete(&self) -> Result<(), String> {
            if self.refuse {
                return Err("access denied".to_owned());
            }
            self.values.borrow_mut().remove(RUN_VALUE);
            Ok(())
        }
    }

    fn command() -> String {
        "\"C:\\Program Files\\vn-ranger.exe\" --background".to_owned()
    }

    #[test]
    fn nothing_written_is_off() {
        assert_eq!(state_with(&Memory::default()), State::Off);
    }

    #[test]
    fn a_second_enable_is_the_same_entry() {
        let store = Memory::default();
        let first = enable_with(&store, &command()).unwrap();
        let second = enable_with(&store, &command()).unwrap();
        assert_eq!(first, second);
        assert_eq!(store.values.borrow().len(), 1, "one entry, not two");
        assert_eq!(state_with(&store), State::On(first));
    }

    #[test]
    fn the_entry_is_read_back_exactly_as_it_was_written() {
        let store = Memory::default();
        enable_with(&store, &command()).unwrap();
        match state_with(&store) {
            State::On(location) => {
                assert_eq!(location.command, command());
                assert_eq!(location.at, format!("HKCU\\{RUN_KEY}\\{RUN_VALUE}"));
                assert!(location.at.contains("vn-ranger"), "the value name is shown");
            }
            other => panic!("expected an entry, got {other:?}"),
        }
    }

    #[test]
    fn removing_twice_succeeds_twice() {
        let store = Memory::default();
        enable_with(&store, &command()).unwrap();
        disable_with(&store).unwrap();
        assert_eq!(state_with(&store), State::Off);
        assert!(disable_with(&store).is_ok(), "already gone is what was asked for");
    }

    #[test]
    fn a_registry_that_refuses_is_a_state_and_not_a_silent_off() {
        let store = Memory {
            refuse: true,
            ..Memory::default()
        };
        assert!(
            matches!(state_with(&store), State::Unavailable(reason) if !reason.is_empty()),
            "cannot look is not the same as not there"
        );
        assert!(enable_with(&store, &command()).is_err());
        assert!(disable_with(&store).is_err());
    }
}
