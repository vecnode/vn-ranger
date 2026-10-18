//! One ranger window per data directory.
//!
//! Two windows would each scan and each write `last-scan.json`, and the loser of that
//! race sees an access denial. A pid file with a liveness check is enough: the file is
//! removed on a clean exit, and a stale file from a crash is replaced.

use std::io::Write;

use sysinfo::{Pid, ProcessesToUpdate, System};

/// Why the instance lock is not held.
#[derive(Debug)]
pub enum LockError {
    /// Another ranger window is running, and it is the one to use.
    Running(String),
    /// The lock file could not be created. That is a fact about this machine, not a reason
    /// to refuse to open a window.
    Unwritable(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running(reason) | Self::Unwritable(reason) => formatter.write_str(reason),
        }
    }
}

/// Read a failure to create the lock.
///
/// Only "another window holds it" is about another window. A denial, a read-only volume or a
/// full disk is about this machine, and a program that will not open because it cannot write
/// one file is a program with no window and no visible reason.
fn classify(error: &std::io::Error) -> LockError {
    LockError::Unwritable(format!(
        "The instance lock could not be written: {error}. Ranger will run anyway, without it."
    ))
}

/// A held instance lock. It removes the file when it is dropped.
pub struct InstanceGuard {
    path: std::path::PathBuf,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        // Only the process that created the file removes it; a stale replacement by
        // another process has a different pid inside, and this one is already gone.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Take the data directory's instance lock, or say which process holds it.
pub fn acquire() -> Result<InstanceGuard, LockError> {
    let path = crate::paths::instance_path();
    if let Some(parent) = path.parent()
        && let Err(reason) = crate::paths::ensure_dir(parent)
    {
        return Err(LockError::Unwritable(format!(
            "The data directory could not be prepared: {reason}"
        )));
    }

    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                return Ok(InstanceGuard { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if let Some(pid) = holder(&path)
                    && pid != std::process::id()
                    && is_running(pid)
                {
                    return Err(LockError::Running(format!(
                        "Another ranger window is already running (pid {pid}). Close it, or use that window."
                    )));
                }
                // The holder is gone; replace the stale file and try once more.
                let _ = std::fs::remove_file(&path);
            }
            Err(error) => return Err(classify(&error)),
        }
    }
    Err(LockError::Unwritable(
        "The instance lock was removed as stale and still could not be taken.".to_owned(),
    ))
}

fn holder(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse().ok())
}

/// Ask the running window to come forward.
///
/// A second launch takes the instance lock, fails, and leaves this file behind; the running
/// window sees it on its next frame, raises itself and removes it. Nothing is sent to a
/// process, and nothing needs a protocol.
pub fn wake() -> Result<(), String> {
    let path = crate::paths::wake_path();
    if let Some(parent) = path.parent() {
        crate::paths::ensure_dir(parent)
            .map_err(|error| format!("Could not prepare {}: {error}", parent.display()))?;
    }
    touch(&path).map_err(|error| format!("Could not write {}: {error}", path.display()))
}

/// Clear a wake file left by a crash, without raising anything.
pub fn clear_stale_wake() {
    let _ = std::fs::remove_file(crate::paths::wake_path());
}

/// Ask the running window to stop, so this build can take its place.
///
/// Only `--replace` writes this. An ordinary second launch raises the window instead, because
/// ending a program a person is reading is not something a shortcut should do quietly.
pub fn request_stop() -> Result<(), String> {
    let path = crate::paths::stop_path();
    if let Some(parent) = path.parent() {
        crate::paths::ensure_dir(parent)
            .map_err(|error| format!("Could not prepare {}: {error}", parent.display()))?;
    }
    touch(&path).map_err(|error| format!("Could not write {}: {error}", path.display()))
}

/// Take a stop request, which is the same question as "quit cleanly now".
#[must_use]
pub fn take_stop() -> bool {
    take_wake(&crate::paths::stop_path())
}

/// Clear a stop file left by a crash, so a launch that crashed while replacing does not end
/// the next window the moment it opens.
pub fn clear_stale_stop() {
    let _ = std::fs::remove_file(crate::paths::stop_path());
}

fn touch(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::write(path, b"1")
}

/// Take the wake file if there is one, which is the same question as "raise the window".
#[must_use]
pub fn take_wake(path: &std::path::Path) -> bool {
    std::fs::remove_file(path).is_ok()
}

fn is_running(pid: u32) -> bool {
    let mut system = System::new();
    let pid = Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wake_file_is_taken_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wake");
        assert!(!take_wake(&path), "nothing was asked for");
        assert!(matches!(
            classify(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            LockError::Unwritable(_)
        ));
        touch(&path).unwrap();
        assert!(take_wake(&path), "the first frame raises the window");
        assert!(
            !take_wake(&path),
            "and the second frame does not, because the file is gone"
        );
    }

    #[test]
    fn a_stop_request_is_not_a_wake_request() {
        // Two files, two meanings: if these were ever the same path, an ordinary second
        // launch would end the window it was supposed to raise.
        let stop = crate::paths::stop_path();
        let wake = crate::paths::wake_path();
        assert_ne!(stop, wake);
        assert_eq!(stop.parent(), wake.parent(), "both live in the data directory");
        assert_eq!(stop.file_name().and_then(|name| name.to_str()), Some("stop"));
        assert_eq!(wake.file_name().and_then(|name| name.to_str()), Some("wake"));
    }

    #[test]
    fn a_stale_wake_file_is_cleared_without_a_window_to_raise() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wake");
        touch(&path).unwrap();
        assert!(path.exists());
        // The clear works on the real data directory, so this asserts the primitive the
        // clear is made of rather than the path.
        assert!(take_wake(&path));
        assert!(!path.exists());
    }
}
