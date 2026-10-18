//! The registry surfaces that start something, as a table.
//!
//! Windows has a long list of places that cause code to run, and every one of them was
//! written as its own function until this table existed. A function per surface is a
//! surface that gets forgotten: the table makes a missing row a missing row, and every row
//! is read by the same parser, so a fixture for `Image File Execution Options` runs on a
//! machine that has never seen Windows (`docs/PLAN.md` §9, wave 5).
//!
//! Nothing here touches the registry. [`KeyReader`] does that, one implementation per
//! platform, and the parser is a pure function of the table and what the reader returned.
//! That split is what makes a surface testable from a captured fixture: the fixture is the
//! registry, and the test is the answer.

use serde::Deserialize;
use vnr_core::{AutorunKind, AutorunScope};

/// Which hive a surface lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hive {
    /// The signed-in user's own settings.
    CurrentUser,
    /// The machine.
    LocalMachine,
}

impl Hive {
    /// The label a person and an id use.
    #[must_use]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CurrentUser => "HKCU",
            Self::LocalMachine => "HKLM",
        }
    }
}

/// Which registry view a surface is read through.
///
/// A 32-bit program's `Run` key is a different key from a 64-bit one's, and something that
/// registers there starts only for programs of that width — which is why both are read
/// rather than assuming the machine's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Widening {
    /// Both views, each as its own entry.
    Both,
    /// Only the 64-bit view.
    SixtyFour,
}

impl Widening {
    /// The views this surface is read through.
    #[must_use]
    pub(crate) fn views(self) -> &'static [View] {
        match self {
            Self::Both => &[View::SixtyFour, View::ThirtyTwo],
            Self::SixtyFour => &[View::SixtyFour],
        }
    }
}

/// One registry view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum View {
    /// The 64-bit view.
    #[serde(rename = "64")]
    SixtyFour,
    /// The 32-bit view.
    #[serde(rename = "32")]
    ThirtyTwo,
}

impl View {
    /// The width, as an id and as a person reads it.
    #[must_use]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::SixtyFour => "64",
            Self::ThirtyTwo => "32",
        }
    }
}

/// What in a key is one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Read {
    /// Every value in the key is one entry: a `Run` key.
    Values,
    /// One named value in the key is one entry: `Winlogon\Shell`.
    Value(&'static str),
    /// Each subkey holds one named value, under a path inside the subkey.
    ///
    /// `Image File Execution Options\<program>\Debugger` has an empty path;
    /// `Services\<name>\Parameters\ServiceDll` does not.
    SubkeyValue {
        /// The path inside each subkey, empty for the subkey itself.
        path: &'static str,
        /// The value inside it.
        value: &'static str,
    },
}

impl Read {
    /// How many levels of subkeys a reader has to fetch for this shape.
    ///
    /// Reading deeper than a surface needs is not free: the services key holds hundreds of
    /// subkeys, and opening each one's `Parameters` for a surface that only wants values is
    /// work that buys nothing.
    #[must_use]
    pub(crate) fn depth(self) -> usize {
        match self {
            Self::Values | Self::Value(_) => 0,
            Self::SubkeyValue { path, .. } => {
                1 + path.split('\\').filter(|segment| !segment.is_empty()).count()
            }
        }
    }
}

/// The registry value types a startup command can be written as.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_MULTI_SZ: u32 = 7;

/// A registry value's data as text, for the types a command can be written in.
///
/// A `REG_DWORD` in a `Run` key is not a command, and guessing at its bytes would invent a
/// fact: anything that is not one of these three types is not an entry.
#[must_use]
pub(crate) fn text_of(value_type: u32, bytes: &[u8]) -> Option<String> {
    if !matches!(value_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ) {
        return None;
    }
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let text = text.trim_end_matches('\u{0}');
    if value_type == REG_MULTI_SZ {
        let parts: Vec<&str> = text.split('\u{0}').filter(|part| !part.is_empty()).collect();
        return Some(parts.join("; "));
    }
    Some(text.to_owned())
}

/// One place that starts something.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Surface {
    /// A stable id, such as `run`.
    pub id: &'static str,
    /// What it is called in the interface.
    pub label: &'static str,
    /// The hive.
    pub hive: Hive,
    /// The key, without the trailing name of the value.
    pub key: &'static str,
    /// Which views to read it through.
    pub wideness: Widening,
    /// What in the key is one entry.
    pub read: Read,
    /// What kind of startup entry this is.
    pub kind: AutorunKind,
    /// Whether it belongs to the user or the machine.
    pub scope: AutorunScope,
    /// The ATT&CK technique the surface is an instance of, where one is the honest mapping.
    pub technique: Option<&'static str>,
}

/// The surfaces this build reads.
///
/// It is a table, and a surface that is not in it is not read. Adding one means adding a
/// row, a fixture and — when the fixture shows something a person needs to know about — a
/// rule (`docs/PLAN.md` §9, wave 5).
pub(crate) const SURFACES: &[Surface] = &[
    Surface {
        id: "run",
        label: "Run key",
        hive: Hive::CurrentUser,
        key: r"Software\Microsoft\Windows\CurrentVersion\Run",
        wideness: Widening::Both,
        read: Read::Values,
        kind: AutorunKind::RunKey,
        scope: AutorunScope::User,
        technique: Some("T1547.001"),
    },
    Surface {
        id: "run-machine",
        label: "Run key (machine)",
        hive: Hive::LocalMachine,
        key: r"Software\Microsoft\Windows\CurrentVersion\Run",
        wideness: Widening::Both,
        read: Read::Values,
        kind: AutorunKind::RunKey,
        scope: AutorunScope::System,
        technique: Some("T1547.001"),
    },
    Surface {
        id: "run-once",
        label: "RunOnce key",
        hive: Hive::CurrentUser,
        key: r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        wideness: Widening::Both,
        read: Read::Values,
        kind: AutorunKind::RunKey,
        scope: AutorunScope::User,
        technique: Some("T1547.001"),
    },
    Surface {
        id: "run-once-machine",
        label: "RunOnce key (machine)",
        hive: Hive::LocalMachine,
        key: r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        wideness: Widening::Both,
        read: Read::Values,
        kind: AutorunKind::RunKey,
        scope: AutorunScope::System,
        technique: Some("T1547.001"),
    },
    Surface {
        id: "run-services",
        label: "RunServices key (legacy)",
        hive: Hive::LocalMachine,
        key: r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        wideness: Widening::SixtyFour,
        read: Read::Values,
        kind: AutorunKind::RunKey,
        scope: AutorunScope::System,
        technique: Some("T1547.001"),
    },
    Surface {
        id: "run-services-once",
        label: "RunServicesOnce key (legacy)",
        hive: Hive::LocalMachine,
        key: r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        wideness: Widening::SixtyFour,
        read: Read::Values,
        kind: AutorunKind::RunKey,
        scope: AutorunScope::System,
        technique: Some("T1547.001"),
    },
    Surface {
        id: "winlogon-shell",
        label: "Winlogon shell",
        hive: Hive::LocalMachine,
        key: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        wideness: Widening::SixtyFour,
        read: Read::Value("Shell"),
        kind: AutorunKind::Other,
        scope: AutorunScope::System,
        technique: Some("T1547.004"),
    },
    Surface {
        id: "winlogon-userinit",
        label: "Winlogon userinit",
        hive: Hive::LocalMachine,
        key: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        wideness: Widening::SixtyFour,
        read: Read::Value("Userinit"),
        kind: AutorunKind::Other,
        scope: AutorunScope::System,
        technique: Some("T1547.004"),
    },
    Surface {
        id: "winlogon-notify",
        label: "Winlogon notify",
        hive: Hive::LocalMachine,
        key: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        wideness: Widening::SixtyFour,
        read: Read::Values,
        kind: AutorunKind::Other,
        scope: AutorunScope::System,
        technique: Some("T1547.004"),
    },
    Surface {
        id: "appinit",
        label: "AppInit_DLLs",
        hive: Hive::LocalMachine,
        key: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        wideness: Widening::Both,
        read: Read::Value("AppInit_DLLs"),
        kind: AutorunKind::Other,
        scope: AutorunScope::System,
        technique: Some("T1546.010"),
    },
    Surface {
        id: "ifeo-debugger",
        label: "Image File Execution Options debugger",
        hive: Hive::LocalMachine,
        key: r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        wideness: Widening::Both,
        read: Read::SubkeyValue {
            path: "",
            value: "Debugger",
        },
        kind: AutorunKind::Other,
        scope: AutorunScope::System,
        technique: Some("T1546.012"),
    },
    Surface {
        id: "active-setup",
        label: "Active Setup",
        hive: Hive::LocalMachine,
        key: r"SOFTWARE\Microsoft\Active Setup\Installed Components",
        wideness: Widening::Both,
        read: Read::SubkeyValue {
            path: "",
            value: "StubPath",
        },
        kind: AutorunKind::Other,
        scope: AutorunScope::System,
        technique: Some("T1547.014"),
    },
    Surface {
        id: "service-dll",
        label: "A service's ServiceDll",
        hive: Hive::LocalMachine,
        key: r"SYSTEM\CurrentControlSet\Services",
        wideness: Widening::SixtyFour,
        read: Read::SubkeyValue {
            path: "Parameters",
            value: "ServiceDll",
        },
        kind: AutorunKind::Service,
        scope: AutorunScope::System,
        technique: Some("T1543.003"),
    },
];

/// The surface with this id. Used by the fixture tests, which name a row rather than an
/// index so a reordered table fails a test instead of the wrong surface.
#[cfg(test)]
#[must_use]
pub(crate) fn surface(id: &str) -> Option<&'static Surface> {
    SURFACES.iter().find(|surface| surface.id == id)
}

/// One value in a key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct Value {
    /// The value's name. `""` is the default value.
    pub name: String,
    /// Its data, as text. A value that is not text is not a startup command.
    pub data: String,
}

/// One key: its values and its children.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct KeyData {
    /// The values in this key.
    #[serde(default)]
    pub values: Vec<Value>,
    /// Its subkeys.
    #[serde(default)]
    pub subkeys: Vec<Subkey>,
}

/// A subkey of a key, with what it holds.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct Subkey {
    /// The subkey's name.
    pub name: String,
    /// Its values.
    #[serde(default)]
    pub values: Vec<Value>,
    /// Its own subkeys.
    #[serde(default)]
    pub subkeys: Vec<Subkey>,
}

impl Subkey {
    /// Descend a `\`-separated path, for a surface that reads one level in.
    #[must_use]
    pub(crate) fn descend(&self, path: &str) -> Option<&Subkey> {
        let mut node = self;
        for segment in path.split('\\').filter(|segment| !segment.is_empty()) {
            node = node
                .subkeys
                .iter()
                .find(|child| child.name.eq_ignore_ascii_case(segment))?;
        }
        Some(node)
    }

    /// The value with this name, or the default value for `""`.
    #[must_use]
    pub(crate) fn value(&self, name: &str) -> Option<&Value> {
        self.values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(name))
    }
}

/// One startup entry, as the table and the registry describe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// A stable id, including the hive, the view and the name.
    pub id: String,
    /// The name the source gives it.
    pub name: String,
    /// The command the source will run.
    pub command: String,
    /// Where it came from, in words a person can find in `regedit`.
    pub location: String,
}

/// Read one surface's entries out of what a reader returned.
///
/// The rules are the same for every surface, which is the point of the table: a value with
/// no data is not an entry (an empty `AppInit_DLLs` is a normal machine), a name with no
/// value is not an entry, and a surface with nothing under it produces nothing rather than
/// an error — an absent `RunOnce` is a fact about the machine, not a failure to read it.
#[must_use]
pub(crate) fn entries(surface: &Surface, view: View, data: &KeyData) -> Vec<Entry> {
    let mut entries = Vec::new();
    match surface.read {
        Read::Values => {
            for value in &data.values {
                push(
                    &mut entries,
                    surface,
                    view,
                    &value.name,
                    &value.data,
                    &format!("{} ({}-bit)", value.name, view.label()),
                );
            }
        }
        Read::Value(name) => {
            if let Some(value) = data
                .values
                .iter()
                .find(|value| value.name.eq_ignore_ascii_case(name))
            {
                push(
                    &mut entries,
                    surface,
                    view,
                    name,
                    &value.data,
                    &format!("{} ({}-bit)", value.name, view.label()),
                );
            }
        }
        Read::SubkeyValue { path, value } => {
            for subkey in &data.subkeys {
                let Some(node) = subkey.descend(path) else {
                    continue;
                };
                let Some(found) = node.value(value) else {
                    continue;
                };
                push(
                    &mut entries,
                    surface,
                    view,
                    &subkey.name,
                    &found.data,
                    &format!("{}\\{} ({}-bit)", subkey.name, value, view.label()),
                );
            }
        }
    }
    entries
}

fn push(entries: &mut Vec<Entry>, surface: &Surface, view: View, name: &str, data: &str, location: &str) {
    if data.trim().is_empty() {
        return;
    }
    let name = if name.is_empty() { "(default)" } else { name };
    entries.push(Entry {
        id: format!(
            "{}:{}:{}:{}",
            surface.id,
            surface.hive.label(),
            view.label(),
            name
        ),
        name: name.to_owned(),
        command: data.trim().to_owned(),
        location: format!("{}\\{}\\{}", surface.hive.label(), surface.key, location),
    });
}

/// Read one key, in one view.
///
/// A key that is not there is `Ok` with nothing in it: most of these surfaces do not exist
/// on an ordinary machine, and "not present" is the fact, not a failure. A key that exists
/// and could not be read is `Err`, because that is a gap a person needs to see.
pub(crate) trait KeyReader {
    /// Read a key, fetching `depth` levels of subkeys.
    fn read(&self, hive: Hive, view: View, key: &str, depth: usize) -> Result<KeyData, String>;
}

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::WindowsRegistry;

#[cfg(test)]
mod tests;
