//! The field vocabulary a pack rule may name.
//!
//! A pack is data, so every name it can use is a name this file publishes. An unknown field
//! is a load error rather than a rule that never fires (`docs/PLAN.md` §6.11): a rule that
//! silently matches nothing is worse than one that is refused, because it looks like
//! coverage.
//!
//! The table is per subject, and it is deliberately small. A field arrives here when a fact
//! model carries it, a rule needs it, and `docs/RULES.md` documents it — in that order, so
//! the documentation and the table cannot drift apart without one of them failing a test.

use std::fmt;

/// One subject a rule can be written about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// A startup entry: a registry value, a plist, a unit, a desktop file.
    Startup,
    /// A running process.
    Process,
    /// A socket waiting for a connection.
    Listener,
    /// An installed package.
    Package,
    /// A change under a watched folder.
    FileEvent,
    /// An editor, agent or package-manager configuration that can run something.
    Agent,
}

impl Subject {
    /// Every subject, in the order `docs/RULES.md` lists them.
    pub const ALL: [Subject; 6] = [
        Subject::Startup,
        Subject::Process,
        Subject::Listener,
        Subject::Package,
        Subject::FileEvent,
        Subject::Agent,
    ];

    /// The stable name a pack writes.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Process => "process",
            Self::Listener => "listener",
            Self::Package => "package",
            Self::FileEvent => "file-event",
            Self::Agent => "agent",
        }
    }

    /// The subject with this name, if there is one.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|subject| subject.id() == id)
    }

    /// The fields a rule about this subject may name, sorted.
    #[must_use]
    pub fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Startup => &["command", "hash", "name", "path", "scope", "signed", "user"],
            Self::Process => &["command", "name", "parent", "path", "pid", "started_at", "user"],
            Self::Listener => &["address", "port", "process", "protocol", "public"],
            Self::Package => &["name", "path", "publisher", "version"],
            Self::FileEvent => &["kind", "path", "source"],
            Self::Agent => &["config", "name", "path", "tool"],
        }
    }

    /// Whether a rule about this subject may name this field.
    #[must_use]
    pub fn has_field(self, field: &str) -> bool {
        self.fields().contains(&field)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_subject_round_trips_and_has_fields() {
        for subject in Subject::ALL {
            assert_eq!(Subject::from_id(subject.id()), Some(subject));
            assert!(!subject.fields().is_empty(), "{subject} has no fields");
        }
        assert_eq!(Subject::from_id("registry"), None);
    }

    #[test]
    fn the_field_lists_are_sorted_and_unique() {
        for subject in Subject::ALL {
            let fields = subject.fields();
            let mut sorted = fields.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(fields, sorted.as_slice(), "{subject}'s fields are a table");
        }
    }

    #[test]
    fn a_field_belongs_to_a_subject_rather_than_to_the_vocabulary() {
        assert!(Subject::Startup.has_field("path"));
        assert!(Subject::Process.has_field("path"));
        assert!(
            !Subject::Startup.has_field("port"),
            "a port on a registry value is a rule that never fires"
        );
        assert!(!Subject::Startup.has_field(""));
    }
}
