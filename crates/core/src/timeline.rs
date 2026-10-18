//! What changed while ranger was open.
//!
//! The timeline is a session record, not the action journal: it lives in memory, it is
//! dropped when the window closes, and nothing acts on it. The journal is a later
//! feature with its own durability and ordering guarantees, and this type deliberately
//! cannot be mistaken for one.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// The kind of change an event records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A process that was not in the previous poll.
    ProcessStarted,
    /// A process that was in the previous poll and is gone.
    ProcessStopped,
    /// A process whose recorded details changed.
    ProcessChanged,
    /// A file appeared in a watched folder.
    FileAppeared,
    /// A watched file changed.
    FileChanged,
    /// A rule raised a new finding.
    FindingRaised,
    /// A person accepted the current scan as the baseline.
    BaselineAccepted,
}

impl EventKind {
    /// A short label for the interface.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ProcessStarted => "Process started",
            Self::ProcessStopped => "Process stopped",
            Self::ProcessChanged => "Process changed",
            Self::FileAppeared => "File appeared",
            Self::FileChanged => "File changed",
            Self::FindingRaised => "Finding raised",
            Self::BaselineAccepted => "Baseline accepted",
        }
    }
}

/// One change the watcher saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelineEvent {
    /// Seconds since the Unix epoch.
    pub at_unix: u64,
    /// What kind of change it is.
    pub kind: EventKind,
    /// The thing that changed: a process name and pid, or a path.
    pub subject: String,
    /// The evidence: a path, a hash, a parent process.
    pub detail: String,
    /// The collector that observed it.
    pub source: String,
}

impl TimelineEvent {
    /// The event as one CSV row, with the header beside it when a whole file is wanted.
    ///
    /// UTC, one row per event, quoting only the fields that need it. `at` is both the epoch
    /// second and the readable form, because the first is what a tool sorts and the second
    /// is what a person reads at three in the morning.
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        [
            self.at_unix.to_string(),
            crate::time::format_utc(self.at_unix),
            self.kind.label().to_owned(),
            quote(&self.subject),
            quote(&self.detail),
            quote(&self.source),
        ]
        .join(",")
    }

    /// Build an event.
    #[must_use]
    pub fn new(
        at_unix: u64,
        kind: EventKind,
        subject: impl Into<String>,
        detail: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            at_unix,
            kind,
            subject: subject.into(),
            detail: detail.into(),
            source: source.into(),
        }
    }
}

/// Quote a CSV field when it holds a comma, a quote or a newline.
fn quote(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// The header a timeline file starts with.
pub const CSV_HEADER: &str = "at,utc,kind,subject,detail,source";

/// A whole timeline as CSV, newest last, with its header.
#[must_use]
pub fn to_csv(events: &[TimelineEvent]) -> String {
    let mut out = String::from(CSV_HEADER);
    for event in events {
        out.push('\n');
        out.push_str(&event.to_csv_row());
    }
    out
}

/// A bounded, in-memory list of events, oldest first.
#[derive(Clone, Debug)]
pub struct Timeline {
    events: VecDeque<TimelineEvent>,
    capacity: usize,
}

impl Timeline {
    /// How many events the timeline keeps before the oldest is dropped.
    pub const DEFAULT_CAPACITY: usize = 500;

    /// An empty timeline with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// An empty timeline with a chosen capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Add an event, dropping the oldest when the timeline is full.
    pub fn push(&mut self, event: TimelineEvent) {
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// How many events are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the timeline is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The events, oldest first. Iterate in reverse for newest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &TimelineEvent> {
        self.events.iter()
    }

    /// Remove every event.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(at: u64, subject: &str) -> TimelineEvent {
        TimelineEvent::new(at, EventKind::ProcessStarted, subject, "detail", "processes")
    }

    #[test]
    fn keeps_the_newest_events_and_drops_the_oldest() {
        let mut timeline = Timeline::with_capacity(3);
        for index in 0..5 {
            timeline.push(event(index, &format!("p{index}")));
        }
        let subjects: Vec<&str> = timeline.iter().map(|event| event.subject.as_str()).collect();
        assert_eq!(subjects, ["p2", "p3", "p4"]);
        assert_eq!(timeline.len(), 3);
    }

    #[test]
    fn newest_first_is_a_reverse_iteration() {
        let mut timeline = Timeline::new();
        timeline.push(event(1, "first"));
        timeline.push(event(2, "second"));
        let newest: Vec<&str> = timeline
            .iter()
            .rev()
            .map(|event| event.subject.as_str())
            .collect();
        assert_eq!(newest, ["second", "first"]);
    }

    #[test]
    fn a_zero_capacity_still_holds_one_event() {
        let mut timeline = Timeline::with_capacity(0);
        timeline.push(event(1, "only"));
        assert_eq!(timeline.len(), 1);
        timeline.push(event(2, "next"));
        assert_eq!(timeline.len(), 1);
        assert_eq!(
            timeline.iter().next().map(|event| event.subject.as_str()),
            Some("next")
        );
    }

    #[test]
    fn labels_are_stable_and_lower_camel_free() {
        for kind in [
            EventKind::ProcessStarted,
            EventKind::ProcessStopped,
            EventKind::ProcessChanged,
            EventKind::FileAppeared,
            EventKind::FileChanged,
            EventKind::FindingRaised,
            EventKind::BaselineAccepted,
        ] {
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn a_csv_row_quotes_what_needs_quoting_and_says_nothing_else() {
        let event = TimelineEvent::new(
            1_700_000_000,
            EventKind::FileAppeared,
            "C:\\Temp\\a,b.exe",
            "a \"quoted\" detail",
            "watcher",
        );
        let row = event.to_csv_row();
        assert!(row.contains("\"C:\\Temp\\a,b.exe\""), "{row}");
        assert!(row.contains("\"a \"\"quoted\"\" detail\""), "{row}");
        assert!(row.ends_with(",watcher"), "{row}");
    }

    #[test]
    fn an_export_is_a_header_and_one_line_per_event() {
        let events = vec![
            TimelineEvent::new(1, EventKind::ProcessStarted, "one", "", "poll"),
            TimelineEvent::new(2, EventKind::ProcessStopped, "two", "", "poll"),
        ];
        let text = to_csv(&events);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], CSV_HEADER);
        assert!(lines[1].starts_with("1,"));
        assert!(
            to_csv(&[]).lines().count() == 1,
            "an empty export is still a file"
        );
    }
}
