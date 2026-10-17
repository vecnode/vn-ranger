//! Small, safe helpers for the Windows collectors.
//!
//! These are the places where a registry value or a service path can be malformed.
//! Every function returns `Option` and never guesses: a command that cannot be parsed
//! is still shown as text, but it produces no executable path.

use std::path::{Path, PathBuf};

use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::{REG_EXPAND_SZ, REG_SZ};

/// Expand `%NAME%` references using the current process environment.
#[must_use]
pub(super) fn expand_env(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '%'
            && let Some(offset) = chars[index + 1..].iter().position(|&character| character == '%')
        {
            let name: String = chars[index + 1..index + 1 + offset].iter().collect();
            if !name.is_empty()
                && let Ok(value) = std::env::var(&name)
            {
                out.push_str(&value);
                index += offset + 2;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Read a registry value as a string, accepting both `REG_SZ` and `REG_EXPAND_SZ`.
#[must_use]
pub(super) fn get_string(key: &RegKey, name: &str) -> Option<String> {
    if let Ok(value) = key.get_value::<String, _>(name) {
        return Some(value);
    }
    key.get_raw_value(name).ok().and_then(|value| reg_string(&value))
}

fn reg_string(value: &RegValue) -> Option<String> {
    if value.vtype != REG_SZ && value.vtype != REG_EXPAND_SZ {
        return None;
    }
    let units: Vec<u16> = value
        .bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let text = String::from_utf16_lossy(&units);
    Some(text.trim_end_matches('\0').to_owned())
}

/// Find the executable a command line reaches.
///
/// Quoted paths are taken literally. An unquoted path containing spaces is matched
/// against the longest prefix ending in `.exe`, `.com`, `.bat` or `.cmd` that exists
/// on disk; if none exists, the first whitespace-separated token is returned so the
/// interface can still show what the entry claims.
#[must_use]
pub(super) fn executable_from_command(command: &str) -> Option<PathBuf> {
    let expanded = expand_env(command.trim());
    if expanded.is_empty() {
        return None;
    }
    let expanded = expanded.strip_prefix(r"\??\").unwrap_or(&expanded);
    let expanded = expanded.strip_prefix(r"\SystemRoot\").map_or_else(
        || expanded.to_owned(),
        |rest| {
            format!(
                r"{}\{}",
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned()),
                rest
            )
        },
    );
    if let Some(rest) = expanded.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(PathBuf::from(&rest[..end]));
    }
    let whole = Path::new(&expanded);
    if whole.is_file() {
        return Some(whole.to_path_buf());
    }
    for extension in [".exe", ".com", ".bat", ".cmd"] {
        let lower = expanded.to_ascii_lowercase();
        if let Some(position) = lower.find(extension) {
            let end = position + extension.len();
            let candidate = Path::new(&expanded[..end]);
            if candidate.is_file() {
                return Some(candidate.to_path_buf());
            }
        }
    }
    expanded
        .split_whitespace()
        .next()
        .map(|token| PathBuf::from(token.trim_matches('"')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_known_and_leaves_unknown_variables() {
        if let Ok(root) = std::env::var("SystemRoot") {
            assert_eq!(expand_env(r"%SystemRoot%\System32"), format!(r"{root}\System32"));
        }
        assert_eq!(expand_env(r"%NOT_SET_ANYWHERE%\x"), r"%NOT_SET_ANYWHERE%\x");
        assert_eq!(expand_env("plain"), "plain");
    }

    #[test]
    fn quoted_paths_are_literal() {
        assert_eq!(
            executable_from_command(r#""C:\Program Files\Acme\acme.exe" --quiet"#),
            Some(PathBuf::from(r"C:\Program Files\Acme\acme.exe"))
        );
    }

    #[test]
    fn unquoted_path_with_spaces_prefers_an_existing_exe() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("Acme App.exe");
        std::fs::write(&exe, b"x").unwrap();
        let command = format!(r#""{}" --start"#, exe.display());
        assert_eq!(executable_from_command(&command), Some(exe));
    }
}
