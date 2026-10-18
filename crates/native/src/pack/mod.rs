//! Rule packs on this machine: their bytes, their signature, and what is loaded.

pub mod embedded;
pub mod keys;
pub mod signature;
pub mod store;

pub use keys::{Keys, Stored};

pub use signature::{Key, Refusal, fingerprint, verify};

pub use store::{
    Candidate, Loaded, PACK_EXTENSION, SIGNATURE_EXTENSION, activate, activate_embedded, candidates,
    directory, load_active, previous, record, rollback,
};

/// The paths this machine resolves a pack's placeholders to.
///
/// The core refuses to know what a home directory is, so the one crate that may read the
/// environment turns the names into paths here. A place this machine cannot name is left
/// out rather than guessed: a rule that asks about it then cannot hold, which is the honest
/// answer instead of a path that looks like somebody's home folder.
#[must_use]
pub fn places() -> vnr_core::pack::evaluate::Places {
    use vnr_core::pack::evaluate::Places;
    fn path_of(name: &str) -> Option<std::path::PathBuf> {
        std::env::var_os(name).map(std::path::PathBuf::from)
    }
    let mut places = Places::new();
    let add = |places: Places, name: &str, path: Option<std::path::PathBuf>| -> Places {
        match path.as_deref().and_then(std::path::Path::to_str) {
            Some(text) => places.with(name, text),
            None => places,
        }
    };
    places = add(places, "TEMP", Some(std::env::temp_dir()));
    places = add(places, "APPDATA", path_of("APPDATA"));
    places = add(places, "LOCALAPPDATA", path_of("LOCALAPPDATA"));
    places = add(places, "PROGRAMDATA", path_of("PROGRAMDATA"));
    places = add(places, "SYSTEMDRIVE", path_of("SystemDrive"));
    places = add(places, "SYSTEMROOT", path_of("SystemRoot"));
    if let Some(dirs) = directories::UserDirs::new() {
        places = add(places, "HOME", Some(dirs.home_dir().to_path_buf()));
        places = add(
            places,
            "DOWNLOADS",
            dirs.download_dir().map(std::path::Path::to_path_buf),
        );
        places = add(
            places,
            "DESKTOP",
            dirs.desktop_dir().map(std::path::Path::to_path_buf),
        );
        places = add(places, "STARTUP", Some(startup_folder(dirs.home_dir())));
    }
    places
}

/// Where this platform puts the per-user startup folder, when it has one.
fn startup_folder(home: &std::path::Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let _ = home;
        std::env::var_os("APPDATA")
            .map_or_else(|| home.join("AppData").join("Roaming"), std::path::PathBuf::from)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup")
    }
    #[cfg(target_os = "macos")]
    {
        home.join("Library").join("LaunchAgents")
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        home.join(".config").join("autostart")
    }
}
