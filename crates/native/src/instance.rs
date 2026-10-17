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

fn is_running(pid: u32) -> bool {
    let mut system = System::new();
    let pid = Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some()
}
