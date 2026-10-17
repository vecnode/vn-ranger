//! Collectors, and the one shape every collector returns.
//!
//! A collector never returns a bare error. "I could not see this" is an answer the
//! interface can explain, and an empty list is a claim ranger is not allowed to make
//! on behalf of a permission it did not have.

pub mod autoruns;
pub mod host;
pub mod listeners;
pub mod packages;
pub mod processes;

#[cfg(windows)]
mod winutil;

#[cfg(unix)]
mod unixutil;

use vnr_core::CollectorStatus;

/// What one collector produced.
#[derive(Clone, Debug)]
pub enum Outcome<T> {
    /// Everything the collector claims to collect.
    Items(Vec<T>),
    /// Some facts, and a statement of what was missed.
    Partial {
        /// The facts that were collected.
        items: Vec<T>,
        /// What could not be reached, in a sentence.
        reason: String,
    },
    /// Nothing, and why.
    Unavailable {
        /// Why the collector could not run.
        reason: String,
    },
}

impl<T> Outcome<T> {
    /// Split the outcome into facts and the status the interface shows.
    #[must_use]
    pub fn into_parts(self, id: &str, label: &str) -> (Vec<T>, CollectorStatus) {
        match self {
            Self::Items(items) => {
                let count = items.len();
                (items, CollectorStatus::ok(id, label, count))
            }
            Self::Partial { items, reason } => {
                let count = items.len();
                (items, CollectorStatus::partial(id, label, count, &reason))
            }
            Self::Unavailable { reason } => (Vec::new(), CollectorStatus::unavailable(id, label, &reason)),
        }
    }
}
