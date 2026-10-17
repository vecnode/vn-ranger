//! Watching the folders a person actually downloads into.
//!
//! The watcher is deliberately shallow: it reads the top level of each folder, not a
//! whole tree, and it reports the paths the operating system names. Deciding what an
//! event means — debouncing a burst, hashing a finished file — belongs to the worker,
//! not to the platform wrapper.

use std::path::PathBuf;
use std::sync::mpsc::Sender;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use vnr_core::FileTouch;

/// One thing the operating system said about a watched path.
#[derive(Clone, Debug)]
pub struct WatchEvent {
    /// The path the event names.
    pub path: PathBuf,
    /// Whether it appeared or changed.
    pub touch: FileTouch,
}

/// A running watcher. Dropping it stops the events.
pub struct WatchHandle {
    _watcher: RecommendedWatcher,
}

/// A watcher that started, and the folders it could and could not read.
pub struct Started {
    /// Keeps the watcher alive; dropping it stops the events.
    pub handle: WatchHandle,
    /// The folders the operating system accepted.
    pub watching: Vec<PathBuf>,
    /// The folders it refused, with the reason it gave.
    pub skipped: Vec<(PathBuf, String)>,
}

/// Start watching the top level of every folder that exists.
///
/// # Errors
///
/// Returns a sentence for the interface when the platform offers no watcher at all, or
/// when not one of the folders could be opened. A folder that fails while others
/// succeed is reported in [`Started::skipped`] instead, because a partial watch is still
/// worth running as long as the interface says it is partial.
pub fn start(roots: &[PathBuf], sender: Sender<WatchEvent>) -> Result<Started, String> {
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let event = match result {
            Ok(event) => event,
            Err(error) => {
                log::debug!("vn-ranger watcher: {error}");
                return;
            }
        };
        let touch = match event.kind {
            EventKind::Create(_) => FileTouch::Appeared,
            EventKind::Modify(_) => FileTouch::Changed,
            _ => return,
        };
        for path in event.paths {
            let _ = sender.send(WatchEvent { path, touch });
        }
    })
    .map_err(|error| format!("The file watcher could not start: {error}"))?;

    let mut watching = Vec::new();
    let mut skipped = Vec::new();
    for root in roots {
        match watcher.watch(root, RecursiveMode::NonRecursive) {
            Ok(()) => watching.push(root.clone()),
            Err(error) => skipped.push((root.clone(), error.to_string())),
        }
    }
    if watching.is_empty() {
        let reasons: Vec<String> = skipped
            .iter()
            .map(|(path, reason)| format!("{}: {reason}", path.display()))
            .collect();
        return Err(if reasons.is_empty() {
            "There was no folder to watch.".to_owned()
        } else {
            format!(
                "None of the watched folders could be opened — {}",
                reasons.join("; ")
            )
        });
    }
    Ok(Started {
        handle: WatchHandle { _watcher: watcher },
        watching,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_folder_is_reported_rather_than_ignored() {
        let (sender, _receiver) = std::sync::mpsc::channel();
        let missing =
            std::env::temp_dir().join(format!("vn-ranger-missing-{}-{}", std::process::id(), "watch"));
        let result = start(&[missing], sender);
        assert!(result.is_err(), "a folder that does not exist is not watched");
    }

    #[test]
    #[ignore = "waits for a real filesystem event; run it with --ignored on a desktop"]
    fn a_written_file_produces_an_event() {
        let dir = tempfile::tempdir().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let _started = start(&[dir.path().to_path_buf()], sender).unwrap();
        std::fs::write(dir.path().join("probe.txt"), b"hello").unwrap();
        let event = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the operating system reports the write");
        assert_eq!(
            event.path.file_name().and_then(|name| name.to_str()),
            Some("probe.txt")
        );
    }
}
