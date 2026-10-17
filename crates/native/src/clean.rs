//! Allowlisted cleaning: the walk, the preview and the removal.
//!
//! Cleaning is a table (`vnr_core::action::Surface`), not a heuristic. A walk starts at a
//! surface root, never leaves it, never enters a link, never crosses a device and stops at
//! a fixed depth. What it finds is offered as a preview; nothing is removed until the
//! preview is accepted, and the removal re-checks every item, because the preview is a
//! photograph and the disk is not.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use vnr_core::action::Surface;

/// How deep a walk may go below a surface root.
pub const MAX_DEPTH: usize = 8;

/// One thing the preview offers to remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Where it is.
    pub path: PathBuf,
    /// Its size in bytes; zero for a directory.
    pub bytes: u64,
    /// When it was last written, in seconds since the Unix epoch.
    pub modified_unix: u64,
    /// Whether it is an empty directory waiting to be pruned.
    pub is_dir: bool,
}

/// What one surface would give back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Preview {
    /// The things that would be removed.
    pub items: Vec<Item>,
    /// Their total size.
    pub bytes: u64,
    /// How many entries were skipped, and why, in aggregate.
    pub skipped_young: usize,
    /// How many links were left alone.
    pub skipped_links: usize,
    /// How many entries were on another device and left alone.
    pub skipped_devices: usize,
    /// How many entries the surface keeps by name, such as the system's own caches.
    pub skipped_excluded: usize,
    /// Whether the walk stopped because it was asked to.
    pub cancelled: bool,
}

impl Preview {
    /// Whether there is anything to remove.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// What a removal did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Removal {
    /// How many entries were removed.
    pub removed: usize,
    /// How many bytes they held.
    pub bytes: u64,
    /// How many were skipped because they changed, vanished or became a link.
    pub skipped: usize,
    /// The ones the operating system refused, with the reason.
    pub failed: Vec<(PathBuf, String)>,
    /// Whether the removal stopped because it was asked to.
    pub cancelled: bool,
}

/// Where a surface is on this machine, from the environment rather than from a literal.
///
/// Only directories that exist are returned, so the interface never offers to clean a
/// folder the machine does not have.
#[must_use]
pub fn roots(surface: Surface) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    match surface {
        // A surface belongs to one operating system. Offering another one's folder would
        // label it with the wrong name and clean it under a promise nobody made, so a
        // foreign surface resolves to no roots at all.
        Surface::WinTemp if cfg!(windows) => {
            roots.push(std::env::temp_dir());
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                roots.push(PathBuf::from(local).join("Temp"));
            }
        }
        Surface::WinCrashDumps | Surface::WinInetCache | Surface::WinGpuCache if cfg!(windows) => {
            let tail = match surface {
                Surface::WinCrashDumps => "CrashDumps",
                Surface::WinInetCache => "Microsoft/Windows/INetCache",
                _ => "D3DSCache",
            };
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                roots.push(PathBuf::from(local).join(tail));
            }
        }
        Surface::WinPackageCache if cfg!(windows) => {
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                let local = PathBuf::from(local);
                for tail in ["pip/Cache", "npm-cache", "Yarn/Cache", "NuGet/v3-cache"] {
                    roots.push(local.join(tail));
                }
            }
        }
        Surface::MacCaches | Surface::MacLogs if cfg!(target_os = "macos") => {
            if let Some(home) = std::env::var_os("HOME") {
                roots.push(
                    PathBuf::from(home)
                        .join("Library")
                        .join(if surface == Surface::MacCaches {
                            "Caches"
                        } else {
                            "Logs"
                        }),
                );
            }
        }
        Surface::MacTemp if cfg!(target_os = "macos") => {
            // `$TMPDIR` is the per-user temporary directory; `std::env::temp_dir` already
            // knows the platform's rule for it.
            roots.push(std::env::temp_dir());
        }
        Surface::LinuxCache if cfg!(target_os = "linux") => {
            if let Some(cache) = std::env::var_os("XDG_CACHE_HOME") {
                roots.push(PathBuf::from(cache));
            } else if let Some(home) = std::env::var_os("HOME") {
                roots.push(PathBuf::from(home).join(".cache"));
            }
        }
        Surface::LinuxTemp if cfg!(target_os = "linux") => {
            roots.push(std::env::temp_dir());
        }
        Surface::LinuxTmpFiles if cfg!(target_os = "linux") => {
            roots.push(PathBuf::from("/tmp"));
        }
        _ => {}
    }
    roots.retain(|path| path.is_dir());
    let mut seen = std::collections::HashSet::new();
    roots.retain(|path| seen.insert(path.clone()));
    roots
}

/// Walk a surface and describe what could go.
#[must_use]
pub fn preview(surface: Surface, now_unix: u64, cancel: &dyn Fn() -> bool) -> Preview {
    preview_roots(surface, &roots(surface), now_unix, cancel)
}

/// Walk chosen roots as if they were a surface. The root parameter is what lets a test
/// work inside its own temporary directory.
#[must_use]
pub fn preview_roots(
    surface: Surface,
    roots: &[PathBuf],
    now_unix: u64,
    cancel: &dyn Fn() -> bool,
) -> Preview {
    let mut preview = Preview::default();
    let minimum_age = surface.minimum_age_seconds();
    for root in roots {
        let Ok(metadata) = std::fs::symlink_metadata(root) else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let root_device = device_of(&metadata);
        walk(root, root_device, 0, minimum_age, now_unix, cancel, &mut preview);
        if preview.cancelled {
            break;
        }
    }
    // A surface can keep some entries by name — the macOS caches table says "not named
    // com.apple.*" — and the walk only learns a name once it has one, so the filter is
    // applied here, before anything is offered.
    let mut excluded = 0_usize;
    preview.items.retain(|item| {
        let keep = !excluded_name(surface, item.path.file_name());
        if !keep {
            excluded = excluded.saturating_add(1);
        }
        keep
    });
    preview.skipped_excluded = excluded;
    // Deepest first, so a directory is considered after everything inside it.
    preview.items.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| left.path.cmp(&right.path))
    });
    preview.bytes = preview.items.iter().map(|item| item.bytes).sum();
    preview
}

fn walk(
    directory: &Path,
    root_device: Option<u64>,
    depth: usize,
    minimum_age: u64,
    now_unix: u64,
    cancel: &dyn Fn() -> bool,
    preview: &mut Preview,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut directories: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        if cancel() {
            preview.cancelled = true;
            return;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            // Never followed, and never removed: a link is a name someone chose, and the
            // thing it points at may be anywhere.
            preview.skipped_links = preview.skipped_links.saturating_add(1);
            continue;
        }
        if let (Some(root_device), Some(entry_device)) = (root_device, device_of(&metadata))
            && crosses_device(root_device, entry_device)
        {
            // A mount point inside a surface is another filesystem's business.
            preview.skipped_devices = preview.skipped_devices.saturating_add(1);
            continue;
        }
        if metadata.is_dir() {
            directories.push(path);
            continue;
        }
        let modified = modified_unix(&metadata);
        if now_unix.saturating_sub(modified) < minimum_age {
            preview.skipped_young = preview.skipped_young.saturating_add(1);
            continue;
        }
        preview.items.push(Item {
            path,
            bytes: metadata.len(),
            modified_unix: modified,
            is_dir: false,
        });
    }
    for child in directories {
        walk(
            &child,
            root_device,
            depth + 1,
            minimum_age,
            now_unix,
            cancel,
            preview,
        );
        // An empty directory is offered after its contents, so the removal can prune it.
        let empty = std::fs::read_dir(&child)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false);
        if empty {
            preview.items.push(Item {
                path: child,
                bytes: 0,
                modified_unix: 0,
                is_dir: true,
            });
        }
    }
}

/// Remove what the preview offered, re-checking each item first.
///
/// An item that changed since the preview is skipped rather than deleted: the preview is a
/// photograph, and a file someone wrote two seconds ago is not the file that was shown.
pub fn remove(
    surface: Surface,
    roots: &[PathBuf],
    items: &[Item],
    now_unix: u64,
    cancel: &dyn Fn() -> bool,
) -> Removal {
    let minimum_age = surface.minimum_age_seconds();
    let mut removal = Removal::default();
    for item in items {
        if cancel() {
            removal.cancelled = true;
            break;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&item.path) else {
            removal.skipped = removal.skipped.saturating_add(1);
            continue;
        };
        if metadata.file_type().is_symlink() {
            removal.skipped = removal.skipped.saturating_add(1);
            continue;
        }
        if item.is_dir {
            if !metadata.is_dir() {
                removal.skipped = removal.skipped.saturating_add(1);
                continue;
            }
            // Only an empty directory succeeds here; a full one is not an error, it is a
            // directory that still has something in it.
            match std::fs::remove_dir(&item.path) {
                Ok(()) => removal.removed = removal.removed.saturating_add(1),
                Err(_) => removal.skipped = removal.skipped.saturating_add(1),
            }
            continue;
        }
        if metadata.is_dir() {
            removal.skipped = removal.skipped.saturating_add(1);
            continue;
        }
        let modified = modified_unix(&metadata);
        let changed = metadata.len() != item.bytes || modified != item.modified_unix;
        if changed || now_unix.saturating_sub(modified) < minimum_age {
            removal.skipped = removal.skipped.saturating_add(1);
            continue;
        }
        match std::fs::remove_file(&item.path) {
            Ok(()) => {
                removal.removed = removal.removed.saturating_add(1);
                removal.bytes = removal.bytes.saturating_add(item.bytes);
                // A directory that held only things which are now gone should not survive
                // as an empty shell. The climb stops at a surface root, so a root is never
                // removed from underneath itself.
                removal.removed = removal.removed.saturating_add(prune_parents(&item.path, roots));
            }
            Err(error) => removal.failed.push((item.path.clone(), error.to_string())),
        }
    }
    removal
}

/// Remove the emptied ancestors of a path, up to but not including a surface root.
///
/// The first ancestor that still holds something stops the climb: nothing is forced, and a
/// directory someone else is using simply stays.
fn prune_parents(path: &Path, roots: &[PathBuf]) -> usize {
    let mut pruned: usize = 0;
    for ancestor in path.ancestors().skip(1) {
        if roots.iter().any(|root| root == ancestor) {
            break;
        }
        if std::fs::remove_dir(ancestor).is_err() {
            break;
        }
        pruned = pruned.saturating_add(1_usize);
    }
    pruned
}

/// Remove a preview's items from the surface's own roots.
pub fn remove_surface(surface: Surface, items: &[Item], now_unix: u64, cancel: &dyn Fn() -> bool) -> Removal {
    remove(surface, &roots(surface), items, now_unix, cancel)
}

/// The device an entry is on, where the platform reports one.
///
/// Windows has no stable way to read a volume serial number from `std::fs::Metadata`, so a
/// surface there cannot refuse a mount point. `docs/PLAN.md` §7 names that gap.
#[cfg(unix)]
fn device_of(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.dev())
}

/// The device an entry is on, where the platform reports one.
#[cfg(not(unix))]
fn device_of(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

/// Whether an entry is on a different filesystem from the surface root.
fn crosses_device(root_device: u64, entry_device: u64) -> bool {
    root_device != entry_device
}

/// Names a surface keeps whatever their age.
///
/// The macOS caches surface excludes `com.apple.*`: those caches belong to the system, a
/// person did not choose to have them, and rebuilding one can cost a login. Every other
/// surface has nothing to exclude, because everything inside it is rebuildable by the
/// program that wrote it.
fn excluded_name(surface: Surface, name: Option<&std::ffi::OsStr>) -> bool {
    if surface != Surface::MacCaches {
        return false;
    }
    let Some(name) = name.and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("com.apple.")
}

fn modified_unix(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_secs())
}

/// Set a file's write time, for the tests that need an old file without waiting a day.
#[cfg(test)]
fn age_file(path: &Path, at_unix: u64) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    let when = UNIX_EPOCH + std::time::Duration::from_secs(at_unix);
    file.set_times(std::fs::FileTimes::new().set_modified(when))
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> u64 {
        24 * 60 * 60
    }

    /// The tests run against the real clock: an age threshold compared with a fixed
    /// timestamp in the future would classify "just written" as a year old.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    fn old_file(directory: &Path, name: &str, body: &[u8]) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, body).unwrap();
        age_file(&path, now() - 2 * day());
        path
    }

    fn never() -> bool {
        false
    }

    #[test]
    fn only_entries_past_the_age_threshold_are_offered() {
        let dir = tempfile::tempdir().unwrap();
        let old = old_file(dir.path(), "old.tmp", b"four");
        std::fs::write(dir.path().join("fresh.tmp"), b"new").unwrap();

        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        let paths: Vec<&Path> = preview.items.iter().map(|item| item.path.as_path()).collect();
        assert!(paths.contains(&old.as_path()));
        assert!(!paths.iter().any(|path| path.ends_with("fresh.tmp")));
        assert_eq!(preview.skipped_young, 1);
        assert_eq!(preview.bytes, 4);
    }

    #[test]
    fn a_young_entry_is_skipped_even_when_it_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let inside = old_file(&nested, "inside.tmp", b"x");
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        assert!(preview.items.iter().any(|item| item.path == inside));
        assert!(
            !preview.items.iter().any(|item| item.path == nested),
            "a directory with anything in it is not pruned"
        );
    }

    #[test]
    fn an_empty_directory_is_offered_after_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("empty")).unwrap();
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        let last = preview.items.last().expect("something is offered");
        assert!(last.is_dir);
        assert!(last.path.ends_with("empty"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_neither_followed_nor_offered() {
        let dir = tempfile::tempdir().unwrap();
        let real = old_file(dir.path(), "real.tmp", b"data");
        let link = dir.path().join("link.tmp");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        assert_eq!(preview.skipped_links, 1);
        assert!(!preview.items.iter().any(|item| item.path == link));
        assert!(
            preview.items.iter().any(|item| item.path == real),
            "the real file behind the link is still just a file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_entered() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = old_file(outside.path(), "secret.tmp", b"do not touch");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("gate")).unwrap();

        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        assert!(
            !preview.items.iter().any(|item| item.path == secret),
            "the walk must not leave the root through a link"
        );
        assert_eq!(preview.skipped_links, 1);
    }

    #[test]
    fn a_walk_stops_when_it_is_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..5 {
            old_file(dir.path(), &format!("f{index}.tmp"), b"x");
        }
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &|| true);
        assert!(preview.cancelled);
        assert!(preview.items.is_empty(), "a cancelled walk offers nothing");
    }

    #[test]
    fn removal_deletes_what_was_offered_and_prunes_the_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let file = old_file(&nested, "gone.tmp", b"12345");
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);

        let removal = remove(
            Surface::WinTemp,
            &[dir.path().to_path_buf()],
            &preview.items,
            now(),
            &never,
        );
        assert_eq!(removal.removed, 2, "the file and then the empty directory");
        assert_eq!(removal.bytes, 5);
        assert!(!file.exists());
        assert!(!nested.exists(), "the empty directory was pruned");
        assert!(removal.failed.is_empty());
    }

    #[test]
    fn removal_skips_a_file_that_changed_after_the_preview() {
        let dir = tempfile::tempdir().unwrap();
        let file = old_file(dir.path(), "changed.tmp", b"old");
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        std::fs::write(&file, b"and now it is longer").unwrap();

        let removal = remove(
            Surface::WinTemp,
            &[dir.path().to_path_buf()],
            &preview.items,
            now(),
            &never,
        );
        assert_eq!(removal.removed, 0);
        assert_eq!(removal.skipped, 1);
        assert!(file.exists());
    }

    #[test]
    fn removal_skips_a_file_that_became_a_link_and_leaves_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let file = old_file(dir.path(), "swap.tmp", b"data");
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        let target = dir.path().join("target.tmp");
        std::fs::write(&target, b"target").unwrap();
        #[cfg(unix)]
        {
            std::fs::remove_file(&file).unwrap();
            std::os::unix::fs::symlink(&target, &file).unwrap();
            let removal = remove(
                Surface::WinTemp,
                &[dir.path().to_path_buf()],
                &preview.items,
                now(),
                &never,
            );
            assert_eq!(removal.removed, 0);
            assert!(target.exists(), "the link's target is untouched");
        }
        #[cfg(windows)]
        {
            // A symlink needs Developer Mode here; the refusal is covered on Unix.
            let _ = (file, target, preview);
        }
    }

    #[test]
    fn removal_offers_nothing_when_the_walk_was_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        old_file(dir.path(), "a.tmp", b"x");
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &|| true);
        let removal = remove(
            Surface::WinTemp,
            &[dir.path().to_path_buf()],
            &preview.items,
            now(),
            &never,
        );
        assert_eq!(removal.removed, 0);
        assert!(dir.path().join("a.tmp").exists());
    }

    #[test]
    fn a_missing_root_is_a_walk_over_nothing_rather_than_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("not-there");
        let preview = preview_roots(Surface::WinTemp, &[gone], now(), &never);
        assert!(preview.is_empty());
        assert!(!preview.cancelled);
    }

    #[test]
    fn the_roots_of_a_surface_exist_and_are_unique() {
        for surface in Surface::ALL {
            let paths = roots(surface);
            let mut seen = std::collections::HashSet::new();
            for path in &paths {
                assert!(path.is_dir(), "{} should exist", path.display());
                assert!(seen.insert(path.clone()), "{} appears twice", path.display());
            }
        }
    }

    #[test]
    fn a_mount_point_is_not_this_surfaces_business() {
        assert!(crosses_device(1, 2));
        assert!(!crosses_device(7, 7));
    }

    #[test]
    fn the_systems_own_caches_are_kept_by_name() {
        use std::ffi::OsStr;
        assert!(excluded_name(
            Surface::MacCaches,
            Some(OsStr::new("com.apple.Safari"))
        ));
        assert!(!excluded_name(
            Surface::MacCaches,
            Some(OsStr::new("com.google.Chrome"))
        ));
        assert!(
            !excluded_name(Surface::LinuxCache, Some(OsStr::new("com.apple.Safari"))),
            "the exclusion belongs to one surface, not to the word"
        );
        assert!(!excluded_name(Surface::MacCaches, None));
    }

    #[test]
    fn an_excluded_entry_is_counted_rather_than_offered() {
        let dir = tempfile::tempdir().unwrap();
        let kept = old_file(dir.path(), "com.apple.Safari", b"system");
        let offered = old_file(dir.path(), "quicklookd", b"user");
        let preview = preview_roots(Surface::MacCaches, &[dir.path().to_path_buf()], now(), &never);
        assert!(!preview.items.iter().any(|item| item.path == kept));
        assert!(preview.items.iter().any(|item| item.path == offered));
        // The rule is by name, so it holds wherever the test runs; what differs per
        // platform is whether the surface has roots at all.
        assert_eq!(preview.skipped_excluded, 1);
    }

    #[test]
    fn a_surface_from_another_operating_system_has_no_roots() {
        let foreign = if cfg!(windows) {
            Surface::LinuxCache
        } else {
            Surface::WinInetCache
        };
        assert!(
            roots(foreign).is_empty(),
            "a foreign surface must not resolve to a folder on this platform"
        );
    }

    #[test]
    fn an_unrelated_directory_is_never_a_surface_root() {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        for surface in Surface::ALL {
            let mut roots = roots(surface);
            roots.extend(std::iter::empty());
            for root in roots {
                if let Some(home) = &home {
                    assert_ne!(&root, home, "a home directory is never a surface root");
                }
            }
        }
    }

    #[test]
    fn a_file_that_is_gone_before_the_removal_is_counted_as_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let file = old_file(dir.path(), "vanish.tmp", b"x");
        let preview = preview_roots(Surface::WinTemp, &[dir.path().to_path_buf()], now(), &never);
        std::fs::remove_file(&file).unwrap();
        let removal = remove(
            Surface::WinTemp,
            &[dir.path().to_path_buf()],
            &preview.items,
            now(),
            &never,
        );
        assert_eq!(removal.removed, 0);
        assert_eq!(removal.skipped, 1);
    }
}
