//! Listening sockets.

#[cfg(windows)]
mod windows;

#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) mod linux;

#[cfg(windows)]
pub use windows::collect;

#[cfg(all(unix, not(target_os = "macos")))]
pub use linux::collect;

#[cfg(target_os = "macos")]
/// macOS listener enumeration is not implemented without a C dependency.
pub fn collect(
    _process_names: &std::collections::HashMap<u32, String>,
) -> crate::collect::Outcome<vnr_core::ListenerFact> {
    crate::collect::Outcome::Unavailable {
        reason: "Listening sockets are not collected on macOS yet; the safe wrapper would pull a C build dependency."
            .to_owned(),
    }
}

#[cfg(not(any(windows, unix)))]
/// A platform this build does not collect yet.
pub fn collect(
    _process_names: &std::collections::HashMap<u32, String>,
) -> crate::collect::Outcome<vnr_core::ListenerFact> {
    crate::collect::Outcome::Unavailable {
        reason: "Listening sockets are not collected on this platform yet.".to_owned(),
    }
}
