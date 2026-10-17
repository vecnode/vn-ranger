//! One ranger window per data directory.
//!
//! Two windows would each scan and each write `last-scan.json`, and the loser of that
//! race sees an access denial. A pid file with a liveness check is enough: the file is
//! removed on a clean exit, and a stale file from a crash is replaced.

use std::io::Write;

use sysinfo::{Pid, ProcessesToUpdate, System};

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
pub fn acquire() -> Result<InstanceGuard, String> {
    let path = crate::paths::instance_path();
    if let Some(parent) = path.parent()
        && let Err(reason) = crate::paths::ensure_dir(parent)
    {
        return Err(format!("Could not prepare the data directory: {reason}"));
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
                    return Err(format!(
                        "Another ranger window is already running (pid {pid}). Close it, or use that window."
                    ));
                }
                // The holder is gone; replace the stale file and try once more.
                let _ = std::fs::remove_file(&path);
            }
            Err(error) => {
                return Err(format!(
                    "Could not take the instance lock at {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Err("Could not take the instance lock after removing a stale one.".to_owned())
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
        touch(&path).unwrap();
        assert!(take_wake(&path), "the first frame raises the window");
        assert!(
            !take_wake(&path),
            "and the second frame does not, because the file is gone"
        );
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
