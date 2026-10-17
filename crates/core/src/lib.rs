//! vn-ranger's pure core.
//!
//! The core knows what a fact, a finding, a signature and a report are, and it knows
//! how to compare them. It does not know what time it is, which files exist, or what
//! operating system it is running on: every one of those is a parameter or a caller's
//! job. That is what lets every decision here have a test beside it.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod action;
pub mod diff;
pub mod fields;
pub mod journal;
pub mod model;
pub mod pack;
pub mod recovery;
pub mod report;
pub mod rules;
pub mod schedule;
pub mod signature;
pub mod time;
pub mod timeline;
pub mod watch;

pub use diff::{Change, ChangeKind, diff_processes, diff_snapshots};
pub use journal::{
    Action, Confirmation, Draft, JournalEntry, Kind as JournalKind, Outcome, Read as JournalRead,
};
pub use model::{
    AutorunFact, AutorunKind, AutorunScope, CollectorState, CollectorStatus, Counts, Host, ListenerFact,
    PackageFact, ProcessFact, Protocol, SignatureMatch, SignatureReport, SignatureStatus, Snapshot,
};
pub use recovery::{Phase as RecoveryPhase, Verdict as RecoveryVerdict};
pub use rules::{
    Confidence, Finding, Severity, Suppression, apply_suppressions, evaluate, prune_suppressions,
};
pub use signature::{HashAlgorithm, HashSignature, SignatureSet};
pub use timeline::{EventKind, Timeline, TimelineEvent};
pub use watch::{Debounce, FileTouch};
