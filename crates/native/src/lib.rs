//! vn-ranger's desktop backend.
//!
//! This is the only crate that touches the machine: it enumerates processes, startup
//! items, listeners and packages, hashes the binaries a startup item reaches, reads
//! local signature databases, and stores the last snapshot. It keeps every platform
//! difference behind a collector, and a collector that cannot see something says so
//! rather than returning an empty list.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod act;
pub mod action;
pub mod autostart;
pub mod clean;
pub mod collect;
pub mod content;
pub mod contentscan;
pub mod elevation;
pub mod export;
pub mod hash;
pub mod instance;
pub mod journal;
pub mod pack;
pub mod paths;
pub mod power;
pub mod quarantine;
pub mod signatures;
pub mod soak;
pub mod startup;
pub mod store;
pub mod structs;
pub mod tray;
pub mod watch;

mod scan;

pub use scan::{DEEP_MAX_BYTES, DEEP_MAX_FILES, ScanProgress, scan, scan_with};

/// Seconds since the Unix epoch, or zero if the clock is before 1970.
///
/// The core never calls the clock; this is the one place that does.
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
