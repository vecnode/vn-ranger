//! Elevation, asked for one operation at a time.
//!
//! Ranger never starts elevated and never keeps privilege. When a person asks for an
//! administrator scan, the unelevated interface starts a second, short-lived copy of
//! the binary with `--elevated-scan <file>`. The operating system asks for consent,
//! the copy writes one snapshot, and it exits. The window that asked stays
//! unelevated, and nothing is deleted with the elevated token.

use std::path::Path;

/// Whether the current process is running with elevated rights.
#[must_use]
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        is_elevated::is_elevated()
    }
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().is_root()
    }
}

/// Whether this build can ask the operating system to elevate.
#[must_use]
pub const fn can_elevate() -> bool {
    cfg!(windows)
}

/// Run an administrator scan and write its snapshot to `output`.
///
/// On Windows this is the one interactive UAC prompt in the application. The caller
/// is responsible for the consent screen that precedes it; this function only asks
/// the operating system.
pub fn run_elevated_scan(output: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|error| format!("could not find this binary: {error}"))?;
        let status = runas::Command::new(exe)
            .arg("--elevated-scan")
            .arg(output)
            .gui(true)
            .status()
            .map_err(|error| format!("Windows did not start the administrator scan: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("The administrator scan did not finish successfully.".to_owned())
        }
    }
    #[cfg(not(windows))]
    {
        let _ = output;
        Err("Administrator scans are not implemented on this platform yet.".to_owned())
    }
}
