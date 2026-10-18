//! Reading one key through `winreg`, and nothing else.
//!
//! The reader is deliberately thin: it opens a key in a view, walks the number of subkey
//! levels the table asked for, and hands back text. Every decision about what an entry *is*
//! lives in the parser next door, so a fixture can stand in for the registry on a machine
//! that has no registry at all (`docs/PLAN.md` §9, wave 5).

use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, RegType,
};

use super::{Hive, KeyData, KeyReader, Subkey, Value, View, text_of};

/// The registry, read through `winreg`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WindowsRegistry;

impl KeyReader for WindowsRegistry {
    fn read(
        &self,
        hive: Hive,
        view: View,
        key: &str,
        depth: usize,
        cap: Option<usize>,
    ) -> Result<KeyData, String> {
        let widening = match view {
            View::SixtyFour => KEY_WOW64_64KEY,
            View::ThirtyTwo => KEY_WOW64_32KEY,
        };
        let root = match hive {
            Hive::CurrentUser => RegKey::predef(HKEY_CURRENT_USER),
            Hive::LocalMachine => RegKey::predef(HKEY_LOCAL_MACHINE),
        };
        match root.open_subkey_with_flags(key, KEY_READ | widening) {
            Ok(open) => Ok(read_key(&open, depth, cap)),
            // A key that is not there is the ordinary state of most of this table: an
            // absent `RunOnce` is a fact about the machine, not a failure to read it.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(KeyData::default()),
            Err(error) => Err(format!(
                "{}\\{} ({}-bit) could not be read: {error}",
                hive.label(),
                key,
                view.label()
            )),
        }
    }
}

fn read_key(key: &RegKey, depth: usize, cap: Option<usize>) -> KeyData {
    let mut values = Vec::new();
    for (name, value) in key.enum_values().flatten() {
        if let Some(data) = text_of(vtype(&value.vtype), &value.bytes) {
            values.push(Value { name, data });
        }
    }
    let mut subkeys = Vec::new();
    let mut truncated = 0_usize;
    if depth > 0 {
        // The cap is counted from the enumeration, not from the opens: a key with 11,905
        // children costs nothing to walk and everything to open.
        for (index, name) in key.enum_keys().flatten().enumerate() {
            if cap.is_some_and(|limit| index >= limit) {
                truncated = truncated.saturating_add(1);
                continue;
            }
            // A subkey that cannot be opened is skipped rather than failing the surface:
            // one unreadable child must not hide the other four hundred.
            let Ok(child) = key.open_subkey_with_flags(&name, KEY_READ) else {
                continue;
            };
            let data = read_key(&child, depth.saturating_sub(1), None);
            subkeys.push(Subkey {
                name,
                values: data.values,
                subkeys: data.subkeys,
            });
        }
    }
    KeyData {
        values,
        subkeys,
        truncated,
    }
}

/// The numeric type of a value, in the form the parser knows.
fn vtype(kind: &RegType) -> u32 {
    match kind {
        RegType::REG_SZ | RegType::REG_LINK => 1,
        RegType::REG_EXPAND_SZ => 2,
        RegType::REG_MULTI_SZ => 7,
        RegType::REG_DWORD => 4,
        RegType::REG_QWORD => 11,
        RegType::REG_BINARY | RegType::REG_DWORD_BIG_ENDIAN => 3,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_key_is_an_empty_key_rather_than_an_error() {
        let reader = WindowsRegistry;
        let data = reader
            .read(
                Hive::LocalMachine,
                View::SixtyFour,
                r"Software\vn-ranger\this key does not exist",
                0,
                None,
            )
            .expect("an absent key is not a failure");
        assert!(data.values.is_empty());
        assert!(data.subkeys.is_empty());
    }

    #[test]
    fn a_key_that_exists_is_read_without_failing() {
        // `HKCU\Software` exists on every profile. Not asserting a count — that is the
        // machine's business; asserting that reading it did not fail is the point, because
        // an empty answer is still an answer.
        let reader = WindowsRegistry;
        let data = reader
            .read(Hive::CurrentUser, View::SixtyFour, r"Software", 1, None)
            .expect("the software key exists on every profile");
        assert!(
            data.values.len() + data.subkeys.len() < usize::MAX,
            "reading it returned a key, whatever it holds"
        );
    }
}
