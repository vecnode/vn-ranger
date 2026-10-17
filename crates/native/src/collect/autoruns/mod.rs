//! Automatic starts.

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(all(unix, not(target_os = "macos")))]
mod linux;

#[cfg(windows)]
pub use windows::collect;

#[cfg(target_os = "macos")]
pub use macos::collect;

#[cfg(all(unix, not(target_os = "macos")))]
pub use linux::collect;

#[cfg(not(any(windows, unix)))]
/// A platform this build does not collect yet.
pub fn collect(_hasher: &mut crate::hash::Hasher) -> crate::collect::Outcome<vnr_core::AutorunFact> {
    crate::collect::Outcome::Unavailable {
        reason: "Startup items are not collected on this platform yet.".to_owned(),
    }
}
