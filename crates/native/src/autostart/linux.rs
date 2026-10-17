//! Autostart on Linux: one `.desktop` file in the user's own autostart folder.
//!
//! `~/.config/autostart` (or `$XDG_CONFIG_HOME`), never a systemd system unit and never a
//! root-owned file (§6.5). The file name is the entry's identity. Anything already in the
//! folder stays there: ranger writes one file and removes one file.

use std::path::{Path, PathBuf};

use super::{Location, NAME, State, entry};

fn path() -> Result<PathBuf, String> {
    let config = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(config) if !config.is_empty() => PathBuf::from(config),
        _ => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".config"),
            None => {
                return Err(
                    "Neither XDG_CONFIG_HOME nor HOME is set, so there is no autostart \
                            folder to write"
                        .to_owned(),
                );
            }
        },
    };
    Ok(config.join("autostart").join(format!("{NAME}.desktop")))
}

pub(super) fn state() -> State {
    let Ok(at) = path() else {
        return State::Unavailable("no home directory to write an entry into".to_owned());
    };
    state_at(&at)
}

/// The same question, asked of a path a caller names, so a test does not need the real home.
fn state_at(at: &Path) -> State {
    match read(at) {
        Ok(Some(command)) => State::On(Location {
            at: at.display().to_string(),
            command,
        }),
        Ok(None) => State::Off,
        Err(reason) => State::Unavailable(reason),
    }
}

pub(super) fn enable() -> Result<Location, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("Could not find where ranger is running from: {error}"))?;
    let at = path()?;
    write(&at, &exe)?;
    Ok(Location {
        at: at.display().to_string(),
        command: entry::run_value(&exe),
    })
}

pub(super) fn disable() -> Result<(), String> {
    remove(&path()?)
}

/// The `Exec` line of the file, which is the part a person cares about.
fn read(at: &Path) -> Result<Option<String>, String> {
    let text = match std::fs::read_to_string(at) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!("Could not read {}: {error}", at.display()));
        }
    };
    let command = text
        .lines()
        .find_map(|line| line.strip_prefix("Exec="))
        .map(str::trim)
        .unwrap_or("")
        .to_owned();
    Ok(Some(command))
}

fn write(at: &Path, exe: &Path) -> Result<(), String> {
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create {}: {error}", parent.display()))?;
    }
    std::fs::write(at, entry::desktop_entry(exe, "vn-ranger"))
        .map_err(|error| format!("Could not write {}: {error}", at.display()))
}

/// Removing an entry that is not there is the state the person asked for.
fn remove(at: &Path) -> Result<(), String> {
    match std::fs::remove_file(at) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Could not remove {}: {error}", at.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bed() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("autostart").join(format!("{NAME}.desktop"));
        (dir, at)
    }

    #[test]
    fn an_entry_round_trips_and_reads_back_as_the_command_it_runs() {
        let (_dir, at) = bed();
        assert_eq!(read(&at).unwrap(), None, "nothing written yet");
        write(&at, Path::new("/opt/vn ranger/vn-ranger")).unwrap();
        let command = read(&at).unwrap().expect("the file is there");
        assert_eq!(command, "\"/opt/vn ranger/vn-ranger\" --background");
        assert!(matches!(state_at(&at), State::On(_)));
    }

    #[test]
    fn a_second_write_is_the_same_file() {
        let (_dir, at) = bed();
        let exe = Path::new("/opt/vn-ranger");
        write(&at, exe).unwrap();
        let first = std::fs::read_to_string(&at).unwrap();
        write(&at, exe).unwrap();
        assert_eq!(std::fs::read_to_string(&at).unwrap(), first);
    }

    #[test]
    fn removing_twice_is_success_twice() {
        let (_dir, at) = bed();
        write(&at, Path::new("/opt/vn-ranger")).unwrap();
        remove(&at).unwrap();
        assert!(remove(&at).is_ok(), "already gone is what was asked for");
        assert_eq!(read(&at).unwrap(), None);
    }

    #[test]
    fn another_programs_entry_is_left_alone() {
        let (_dir, at) = bed();
        let theirs = at.with_file_name("someone-else.desktop");
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(&theirs, b"[Desktop Entry]\nName=theirs\n").unwrap();
        write(&at, Path::new("/opt/vn-ranger")).unwrap();
        remove(&at).unwrap();
        assert!(theirs.exists(), "only ranger's own file is ranger's to remove");
    }

    #[test]
    fn an_absent_entry_is_off() {
        let (_dir, at) = bed();
        assert_eq!(state_at(&at), State::Off);
    }
}
