//! Installed packages and applications.

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
pub fn collect() -> crate::collect::Outcome<vnr_core::PackageFact> {
    crate::collect::Outcome::Unavailable {
        reason: "Installed packages are not collected on this platform yet.".to_owned(),
    }
}
