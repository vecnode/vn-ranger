//! Turning a burst of file events into one scan.
//!
//! An editor that writes a file once can produce three or four operating-system events
//! for it. Hashing each one wastes the disk and fills the timeline with noise, so a path
//! is held until it has been quiet for a short window. The clock is a parameter, which is
//! what lets the behaviour have a test without a filesystem or a sleep.

use std::collections::BTreeMap;

/// What the operating system said happened to a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileTouch {
    /// The path was created.
    Appeared,
    /// The path was modified, renamed into place, or written again.
    Changed,
}

impl FileTouch {
    /// Combine two touches of the same path. An appearance outranks a later write,
    /// because "this file appeared" is the more useful sentence.
    #[must_use]
    fn merge(self, other: Self) -> Self {
        if self == Self::Appeared || other == Self::Appeared {
            Self::Appeared
        } else {
            Self::Changed
        }
    }
}

/// Which paths have gone quiet for long enough to be scanned.
#[derive(Clone, Debug)]
pub struct Debounce {
    quiet_ms: u64,
    pending: BTreeMap<String, (u64, FileTouch)>,
}

impl Debounce {
    /// A debounce that waits `quiet_ms` after the last touch of a path.
    #[must_use]
    pub fn new(quiet_ms: u64) -> Self {
        Self {
            quiet_ms,
            pending: BTreeMap::new(),
        }
    }

    /// Record a touch. The newest timestamp wins, and an appearance is not downgraded by
    /// a write that follows it.
    pub fn note(&mut self, path: impl Into<String>, at_ms: u64, touch: FileTouch) {
        let path = path.into();
        self.pending
            .entry(path)
            .and_modify(|(seen, kind)| {
                *seen = (*seen).max(at_ms);
                *kind = kind.merge(touch);
            })
            .or_insert((at_ms, touch));
    }

    /// Take every path that has been quiet for the whole window, oldest path first.
    pub fn ready(&mut self, now_ms: u64) -> Vec<(String, FileTouch)> {
        let ready: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, (seen, _))| seen.saturating_add(self.quiet_ms) <= now_ms)
            .map(|(path, _)| path.clone())
            .collect();
        ready
            .into_iter()
            .filter_map(|path| self.pending.remove(&path).map(|(_, touch)| (path, touch)))
            .collect()
    }

    /// How many paths are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Forget every waiting path, for example when the watcher is switched off.
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_not_ready_until_the_window_has_passed() {
        let mut debounce = Debounce::new(500);
        debounce.note("a.txt", 1_000, FileTouch::Appeared);
        assert!(debounce.ready(1_499).is_empty());
        assert_eq!(debounce.pending(), 1);
        let ready = debounce.ready(1_500);
        assert_eq!(ready, [("a.txt".to_owned(), FileTouch::Appeared)]);
        assert_eq!(debounce.pending(), 0);
    }

    #[test]
    fn a_second_write_restarts_the_window() {
        let mut debounce = Debounce::new(500);
        debounce.note("a.txt", 0, FileTouch::Changed);
        debounce.note("a.txt", 400, FileTouch::Changed);
        assert!(debounce.ready(800).is_empty());
        assert_eq!(debounce.ready(900).len(), 1);
    }

    #[test]
    fn several_writes_to_one_path_produce_one_event() {
        let mut debounce = Debounce::new(500);
        for at in [0, 50, 100, 150] {
            debounce.note("a.txt", at, FileTouch::Changed);
        }
        assert_eq!(debounce.pending(), 1);
        assert_eq!(debounce.ready(650).len(), 1);
    }

    #[test]
    fn an_appearance_outranks_a_following_write() {
        let mut debounce = Debounce::new(100);
        debounce.note("a.txt", 0, FileTouch::Appeared);
        debounce.note("a.txt", 10, FileTouch::Changed);
        assert_eq!(debounce.ready(110), [("a.txt".to_owned(), FileTouch::Appeared)]);
    }

    #[test]
    fn paths_are_returned_in_a_stable_order() {
        let mut debounce = Debounce::new(100);
        debounce.note("z.txt", 0, FileTouch::Changed);
        debounce.note("a.txt", 0, FileTouch::Changed);
        let ready: Vec<String> = debounce.ready(100).into_iter().map(|(path, _)| path).collect();
        assert_eq!(ready, ["a.txt", "z.txt"]);
    }

    #[test]
    fn clearing_drops_everything_waiting() {
        let mut debounce = Debounce::new(100);
        debounce.note("a.txt", 0, FileTouch::Changed);
        debounce.clear();
        assert_eq!(debounce.pending(), 0);
        assert!(debounce.ready(1_000).is_empty());
    }
}
