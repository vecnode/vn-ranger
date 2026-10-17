//! Parsing a command line into the executable it starts, on Unix.

use std::path::{Path, PathBuf};

/// The executable a command line reaches.
///
/// Unix command lines do not quote paths the way Windows does, so the first token is
/// the executable; when it starts with a quote, the quoted section wins.
#[must_use]
pub(super) fn executable_from_command(command: &str) -> Option<PathBuf> {
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    if let Some(rest) = command.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return Some(PathBuf::from(&rest[..end]));
        }
    }
    let first = command.split_whitespace().next()?;
    let path = Path::new(first);
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    // A command can start with environment assignments (`FOO=bar /usr/bin/x`).
    for token in command.split_whitespace() {
        if token.contains('=') {
            continue;
        }
        let path = Path::new(token);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
        return Some(PathBuf::from(token));
    }
    Some(PathBuf::from(first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_first_token() {
        assert_eq!(
            executable_from_command("/usr/bin/foo --bar"),
            Some(PathBuf::from("/usr/bin/foo"))
        );
        assert_eq!(
            executable_from_command(r#""/opt/Acme App/app" --quiet"#),
            Some(PathBuf::from("/opt/Acme App/app"))
        );
    }
}
