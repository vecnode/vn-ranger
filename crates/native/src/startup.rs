//! Changing a startup entry: the first verb that writes to the machine.
//!
//! Quarantine moves a file ranger owns the record of; this changes a place the operating
//! system reads at login. Three rules hold it:
//!
//! * The unit is the entry, not a path and not a key name: a removal carries the
//!   [`AutorunFact`] a scan produced, and the value on the machine is re-read and compared
//!   with it before anything is deleted. A value that changed since the scan is refused.
//! * The surface is a row of [`StartupSurface`], which knows whether this build may write
//!   it. No function here takes a key path, so a caller cannot reach a place the table does
//!   not name.
//! * The key is reached through [`Key`], a four-method trait. The registry is one
//!   implementation and a map is the other, which is what lets the refusals be proved on a
//!   machine that will not let a test binary write a registry value.
//!
//! The journal is the caller's, as everywhere in the action path: this module reports what
//! it did, and `apps/vn-ranger` writes the intent before the call and the result after it.

#[cfg(windows)]
use std::io;

use vnr_core::AutorunFact;
use vnr_core::action::{Refusal, StartupChange, StartupSurface};

use crate::action::{ActionError, Result};

/// One value in a startup surface, as the machine holds it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The name it is registered under.
    pub name: String,
    /// Its command line, as the surface holds it.
    pub command: String,
}

/// What an act did, so the journal can say it afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// A value was written.
    Added {
        /// Where it went.
        surface: StartupSurface,
        /// The name it is registered under.
        name: String,
        /// The command that was written.
        command: String,
    },
    /// A value was removed, with what it said before it went.
    Removed {
        /// Where it was.
        surface: StartupSurface,
        /// The name it was registered under.
        name: String,
        /// Its command line, kept so it can be put back by hand.
        previous: String,
    },
}

impl Applied {
    /// A sentence for the journal.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::Added {
                surface,
                name,
                command,
            } => format!("added {name} to {} as {command}", surface.label()),
            Self::Removed {
                surface,
                name,
                previous,
            } => format!("removed {name} from {}, which ran {previous}", surface.label()),
        }
    }
}

/// The few things this module needs from a key, so a test can be a map.
pub trait Key {
    /// The value under `name`, when the key holds one.
    fn value(&mut self, name: &str) -> Result<Option<String>>;
    /// Every value name the key holds.
    fn names(&mut self) -> Result<Vec<String>>;
    /// Write one value.
    fn write(&mut self, name: &str, command: &str) -> Result<()>;
    /// Remove one value.
    fn delete(&mut self, name: &str) -> Result<()>;
}

/// Read one surface's values, in name order.
///
/// A surface that is not there is empty rather than an error: an absent `RunOnce` key is the
/// ordinary state of a machine that has never installed anything.
pub fn read(surface: StartupSurface) -> Result<Vec<Entry>> {
    match open_read(surface)? {
        Some(mut key) => read_with(key.as_mut()),
        None => Ok(Vec::new()),
    }
}

/// Read a surface through a key the caller supplies.
pub fn read_with(key: &mut dyn Key) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for name in key.names()? {
        if let Some(command) = key.value(&name)? {
            entries.push(Entry { name, command });
        }
    }
    entries.sort_by_key(|a| a.name.to_lowercase());
    Ok(entries)
}

/// Carry out one change, after checking everything the core can check.
pub fn apply(change: &StartupChange) -> Result<Applied> {
    change.check().map_err(ActionError::Refused)?;
    let surface = change.surface();
    let Some(mut key) = open_write(surface)? else {
        return Err(ActionError::Refused(Refusal::UnsupportedSurface));
    };
    let key = key.as_mut();
    match change {
        StartupChange::Add { name, command, .. } => add_with(key, surface, name, command),
        StartupChange::Remove { entry, .. } => remove_with(key, surface, entry),
    }
}

/// Write one value, refusing to overwrite a name that is already there.
///
/// `Add` replacing an existing entry is what a startup hijack looks like, and a person who
/// meant to change one can remove it first: two acts, each visible, rather than one that
/// silently replaces a command they never saw.
pub fn add_with(key: &mut dyn Key, surface: StartupSurface, name: &str, command: &str) -> Result<Applied> {
    if key.value(name)?.is_some() {
        return Err(ActionError::Refused(Refusal::DestinationOccupied));
    }
    key.write(name, command)?;
    Ok(Applied::Added {
        surface,
        name: name.to_owned(),
        command: command.to_owned(),
    })
}

/// Remove one value, but only the value the scan reported.
///
/// The comparison is the whole safety of this function: a name alone is not an identity,
/// because the program behind it may have been replaced since it was inspected.
pub fn remove_with(key: &mut dyn Key, surface: StartupSurface, entry: &AutorunFact) -> Result<Applied> {
    let Some(previous) = key.value(&entry.name)? else {
        return Err(ActionError::Refused(Refusal::SourceMissing));
    };
    if previous != entry.command {
        return Err(ActionError::Refused(Refusal::Changed));
    }
    key.delete(&entry.name)?;
    Ok(Applied::Removed {
        surface,
        name: entry.name.clone(),
        previous,
    })
}

/// Open the key a surface lives in, for reading. `None` is "this build does not read it as a
/// registry value"; a missing key is also `None`, because a surface nobody has written is
/// empty rather than broken.
#[cfg(windows)]
fn open_read(surface: StartupSurface) -> Result<Option<Box<dyn Key>>> {
    match RegistryKey::open_read(surface) {
        Ok(Some(key)) => Ok(Some(Box::new(key))),
        Ok(None) => Ok(None),
        Err(refusal) => Err(ActionError::Refused(refusal)),
    }
}

#[cfg(not(windows))]
fn open_read(_surface: StartupSurface) -> Result<Option<Box<dyn Key>>> {
    Ok(None)
}

/// Open the key a surface lives in, for writing.
#[cfg(windows)]
fn open_write(surface: StartupSurface) -> Result<Option<Box<dyn Key>>> {
    match RegistryKey::open_write(surface) {
        Ok(key) => Ok(Some(Box::new(key))),
        Err(refusal) => Err(ActionError::Refused(refusal)),
    }
}

#[cfg(not(windows))]
fn open_write(_surface: StartupSurface) -> Result<Option<Box<dyn Key>>> {
    Ok(None)
}

/// A surface this build cannot write, for a caller that has to say why.
#[must_use]
pub fn refusal_for(surface: StartupSurface) -> Option<Refusal> {
    surface.refusal()
}

/// A key that is a `BTreeMap`, for tests on every host.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct Map(std::collections::BTreeMap<String, String>);

#[cfg(test)]
impl Map {
    /// A key holding the values the fixture names.
    #[must_use]
    pub fn with(values: &[(&str, &str)]) -> Self {
        Self(
            values
                .iter()
                .map(|(name, command)| ((*name).to_owned(), (*command).to_owned()))
                .collect(),
        )
    }

    /// The value under `name`, for an assertion.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// How many values the key holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the key holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
impl Key for Map {
    fn value(&mut self, name: &str) -> Result<Option<String>> {
        Ok(self.0.get(name).cloned())
    }

    fn names(&mut self) -> Result<Vec<String>> {
        Ok(self.0.keys().cloned().collect())
    }

    fn write(&mut self, name: &str, command: &str) -> Result<()> {
        self.0.insert(name.to_owned(), command.to_owned());
        Ok(())
    }

    fn delete(&mut self, name: &str) -> Result<()> {
        self.0.remove(name);
        Ok(())
    }
}

/// The registry, when there is one.
#[cfg(windows)]
pub struct RegistryKey {
    key: winreg::RegKey,
}

#[cfg(windows)]
impl RegistryKey {
    /// The key a writable surface lives in.
    fn path(surface: StartupSurface) -> std::result::Result<&'static str, Refusal> {
        match surface {
            StartupSurface::WinUserRun => Ok(r"Software\Microsoft\Windows\CurrentVersion\Run"),
            StartupSurface::WinUserRunOnce => Ok(r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            _ => Err(Refusal::UnsupportedSurface),
        }
    }

    /// Open it for reading, refusing a surface this build does not write.
    ///
    /// A key that is not there is `Ok(None)`: reading an absent `RunOnce` is the ordinary
    /// state of a machine, and creating the key to read it would be a change, not a read.
    fn open_read(surface: StartupSurface) -> std::result::Result<Option<Self>, Refusal> {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};

        let path = Self::path(surface)?;
        match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(path, KEY_READ) {
            Ok(key) => Ok(Some(Self { key })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Refusal::UnsupportedSurface),
        }
    }

    /// Open it for writing, creating the key when the machine does not have one yet.
    fn open_write(surface: StartupSurface) -> std::result::Result<Self, Refusal> {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let path = Self::path(surface)?;
        RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(path)
            .map(|(key, _)| Self { key })
            .map_err(|_| Refusal::UnsupportedSurface)
    }
}

#[cfg(windows)]
impl Key for RegistryKey {
    fn value(&mut self, name: &str) -> Result<Option<String>> {
        match self.key.get_value::<String, _>(name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ActionError::io("read the startup entry", error)),
        }
    }

    fn names(&mut self) -> Result<Vec<String>> {
        Ok(self
            .key
            .enum_values()
            .filter_map(|value| value.ok().map(|(name, _kind)| name))
            .collect())
    }

    fn write(&mut self, name: &str, command: &str) -> Result<()> {
        self.key
            .set_value(name, &command)
            .map_err(|error| ActionError::io("write the startup entry", error))
    }

    fn delete(&mut self, name: &str) -> Result<()> {
        self.key
            .delete_value(name)
            .map_err(|error| ActionError::io("remove the startup entry", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::model::{AutorunKind, AutorunScope, SignatureStatus};

    fn entry(name: &str, command: &str) -> AutorunFact {
        AutorunFact {
            id: format!("run:user:{name}"),
            name: name.to_owned(),
            command: command.to_owned(),
            location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_owned(),
            kind: AutorunKind::RunKey,
            scope: AutorunScope::User,
            enabled: true,
            hidden: false,
            exe: None,
            sha256: None,
            signature: SignatureStatus::NotChecked,
        }
    }

    #[test]
    fn an_add_writes_the_value_and_a_second_add_is_refused() {
        let mut key = Map::default();
        let surface = StartupSurface::WinUserRun;
        let applied = add_with(&mut key, surface, "Acme", r"C:\Program Files\Acme\acme.exe")
            .expect("the value is written");
        assert_eq!(
            applied,
            Applied::Added {
                surface,
                name: "Acme".to_owned(),
                command: r"C:\Program Files\Acme\acme.exe".to_owned(),
            }
        );
        assert_eq!(key.get("Acme"), Some(r"C:\Program Files\Acme\acme.exe"));
        assert_eq!(key.len(), 1);

        let again =
            add_with(&mut key, surface, "Acme", r"C:\Other\acme.exe").expect_err("a name is not overwritten");
        assert_eq!(again.refusal(), Some(Refusal::DestinationOccupied));
        assert_eq!(
            key.get("Acme"),
            Some(r"C:\Program Files\Acme\acme.exe"),
            "the refused add changed nothing"
        );
    }

    #[test]
    fn a_removal_needs_the_value_the_scan_reported() {
        let mut key = Map::with(&[("Acme", r"C:\Program Files\Acme\acme.exe")]);
        let surface = StartupSurface::WinUserRun;

        let changed = remove_with(&mut key, surface, &entry("Acme", r"C:\Somewhere\else.exe"))
            .expect_err("a different command is not the entry that was scanned");
        assert_eq!(changed.refusal(), Some(Refusal::Changed));
        assert_eq!(key.len(), 1, "the refused removal changed nothing");

        let missing = remove_with(&mut key, surface, &entry("Gone", r"C:\a.exe"))
            .expect_err("a value that is not there cannot be removed");
        assert_eq!(missing.refusal(), Some(Refusal::SourceMissing));

        let removed = remove_with(
            &mut key,
            surface,
            &entry("Acme", r"C:\Program Files\Acme\acme.exe"),
        )
        .expect("the value goes");
        assert_eq!(
            removed,
            Applied::Removed {
                surface,
                name: "Acme".to_owned(),
                previous: r"C:\Program Files\Acme\acme.exe".to_owned(),
            }
        );
        assert!(key.get("Acme").is_none(), "it is gone");
        assert!(key.is_empty(), "it is gone");
        assert_eq!(
            removed.sentence(),
            format!(
                "removed Acme from {}, which ran {}",
                surface.label(),
                r"C:\Program Files\Acme\acme.exe"
            )
        );
    }

    #[test]
    fn reading_a_surface_sorts_it_and_skips_what_is_not_a_string() {
        let mut key = Map::with(&[("zeta", r"C:\z.exe"), ("Alpha", r"C:\a.exe")]);
        let entries = read_with(&mut key).expect("it reads");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "Alpha");
        assert_eq!(entries[1].name, "zeta");
    }

    #[test]
    fn a_surface_this_build_will_not_write_says_so_before_anything_is_opened() {
        let add = StartupChange::Add {
            surface: StartupSurface::WinMachineRun,
            name: "Acme".to_owned(),
            command: r"C:\a.exe".to_owned(),
        };
        assert_eq!(
            apply(&add).err().and_then(|error| error.refusal()),
            Some(Refusal::MachineScope)
        );
        let folder = StartupChange::Add {
            surface: StartupSurface::UserStartupFolder,
            name: "Acme".to_owned(),
            command: r"C:\a.exe".to_owned(),
        };
        // The folder is a file, not a registry value, and this module does not move files:
        // the row is writable in the table and refused here until the `.lnk` move lands.
        assert!(folder.check().is_ok());
        assert!(refusal_for(StartupSurface::UserStartupFolder).is_none());
    }
}
