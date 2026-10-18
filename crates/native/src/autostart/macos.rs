//! Autostart on macOS: one `LaunchAgent` plist in the user's own folder.
//!
//! `~/Library/LaunchAgents`, never `/Library/LaunchDaemons` and never a privileged helper
//! (§6.5). The label is the entry's identity; the file is the whole entry, so removal is
//! one `remove_file` and nothing else in the folder is read.

use std::path::{Path, PathBuf};

use super::{Location, NAME, State, entry};

fn path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "HOME is not set, so there is no LaunchAgents folder to write".to_owned())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{NAME}.plist")))
}

pub(super) fn state() -> State {
    let Ok(at) = path() else {
        return State::Unavailable("HOME is not set".to_owned());
    };
    state_at(&at)
}

/// The same question, asked of a path a caller names, so a test does not need the real HOME.
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

/// Read the file, if there is one, and say what it would run.
fn read(at: &Path) -> Result<Option<String>, String> {
    let text = match std::fs::read_to_string(at) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!("Could not read {}: {error}", at.display()));
        }
    };
    let value: plist::Value = plist::from_bytes(text.as_bytes())
        .map_err(|error| format!("{} is not a plist: {error}", at.display()))?;
    let program = value
        .as_dictionary()
        .and_then(|dict| dict.get("ProgramArguments"))
        .and_then(plist::Value::as_array)
        .map(|arguments| {
            arguments
                .iter()
                .filter_map(plist::Value::as_string)
                .collect::<Vec<_>>()
                .join(" ")
        });
    Ok(Some(program.unwrap_or_else(|| text.trim().to_owned())))
}

fn write(at: &Path, exe: &Path) -> Result<(), String> {
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create {}: {error}", parent.display()))?;
    }
    std::fs::write(at, entry::launch_agent(NAME, exe))
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
        let at = dir.path().join("LaunchAgents").join(format!("{NAME}.plist"));
        (dir, at)
    }

    #[test]
    fn an_entry_round_trips_and_reads_back_as_the_command_it_runs() {
        let (_dir, at) = bed();
        assert_eq!(read(&at).unwrap(), None, "nothing written yet");
        write(
            &at,
            Path::new("/Applications/vn-ranger.app/Contents/MacOS/vn-ranger"),
        )
        .unwrap();
        let command = read(&at).unwrap().expect("the file is there");
        assert!(command.contains("vn-ranger"));
        assert!(command.contains("--background"));
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
    fn an_unreadable_entry_is_a_state_rather_than_off() {
        let (_dir, at) = bed();
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(&at, b"not a plist at all").unwrap();
        assert!(
            matches!(state_at(&at), State::Unavailable(_)),
            "a file ranger cannot parse is not silently treated as off"
        );
    }

    #[test]
    fn an_absent_entry_is_off() {
        let (_dir, at) = bed();
        assert_eq!(state_at(&at), State::Off);
    }
}
