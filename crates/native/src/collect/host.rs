//! The machine ranger is running on.

use vnr_core::Host;

/// Read the host's operating system, version, architecture and name.
#[must_use]
pub fn current() -> Host {
    Host {
        os: std::env::consts::OS.to_owned(),
        version: sysinfo::System::long_os_version().unwrap_or_else(|| std::env::consts::OS.to_owned()),
        arch: std::env::consts::ARCH.to_owned(),
        hostname: sysinfo::System::host_name(),
    }
}
