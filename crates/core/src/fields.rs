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
//!
//! Each field has a kind. The kind is what lets the validator refuse `gt` on a path and
//! `prefix` on a port before a pack is loaded: an operator that cannot hold for a field is a
//! rule that never fires, and that is a load error here too.

use std::fmt;

/// What a field holds, which decides the operators that can apply to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// Text, compared case-insensitively.
    Text,
    /// A whole number, compared with `eq`, `ne`, `gt` and `lt`.
    Number,
    /// A yes or no, compared with `eq` and `ne` only.
    Bool,
}

impl FieldKind {
    /// Whether a field of this kind can be compared with a value of this kind.
    #[must_use]
    pub fn accepts(self, other: Self) -> bool {
        self == other
    }

    /// What this kind is called in a refusal a pack author has to act on.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "a number",
            Self::Bool => "true or false",
        }
    }
}

/// One field: its stable name and what it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// The name a pack writes.
    pub name: &'static str,
    /// What it holds.
    pub kind: FieldKind,
}

const fn text(name: &'static str) -> Field {
    Field {
        name,
        kind: FieldKind::Text,
    }
}

const fn number(name: &'static str) -> Field {
    Field {
        name,
        kind: FieldKind::Number,
    }
}

const fn boolean(name: &'static str) -> Field {
    Field {
        name,
        kind: FieldKind::Bool,
    }
}

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

/// The fields of a startup entry, as the fact model carries them.
const STARTUP: &[Field] = &[
    text("command"),
    boolean("enabled"),
    text("hash"),
    text("kind"),
    text("location"),
    text("name"),
    text("path"),
    text("scope"),
    text("signed"),
];

/// The fields of a running process.
const PROCESS: &[Field] = &[
    text("command"),
    text("name"),
    number("parent"),
    text("path"),
    number("pid"),
    number("started_at"),
    text("user"),
];

/// The fields of a listening socket.
const LISTENER: &[Field] = &[
    text("address"),
    number("port"),
    text("process"),
    text("protocol"),
    boolean("public"),
    text("state"),
];

/// The fields of an installed package or application.
const PACKAGE: &[Field] = &[text("name"), text("publisher"), text("source"), text("version")];

/// The fields of a watched file change.
const FILE_EVENT: &[Field] = &[text("kind"), text("path"), text("source")];

/// The fields of an editor, agent or package-manager configuration.
const AGENT: &[Field] = &[text("config"), text("name"), text("path"), text("tool")];

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

    /// The fields a rule about this subject may name, sorted by name.
    #[must_use]
    pub fn fields(self) -> &'static [Field] {
        match self {
            Self::Startup => STARTUP,
            Self::Process => PROCESS,
            Self::Listener => LISTENER,
            Self::Package => PACKAGE,
            Self::FileEvent => FILE_EVENT,
            Self::Agent => AGENT,
        }
    }

    /// The field with this name, if the subject has one.
    #[must_use]
    pub fn field(self, field: &str) -> Option<Field> {
        self.fields().iter().copied().find(|entry| entry.name == field)
    }

    /// Whether a rule about this subject may name this field.
    #[must_use]
    pub fn has_field(self, field: &str) -> bool {
        self.field(field).is_some()
    }

    /// What this field holds, when the subject has it.
    #[must_use]
    pub fn kind_of(self, field: &str) -> Option<FieldKind> {
        self.field(field).map(|entry| entry.kind)
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
            let names: Vec<&str> = subject.fields().iter().map(|field| field.name).collect();
            let mut sorted = names.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(names, sorted, "{subject}'s fields are a table");
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

    #[test]
    fn a_field_carries_the_kind_the_fact_model_has() {
        assert_eq!(Subject::Listener.kind_of("port"), Some(FieldKind::Number));
        assert_eq!(Subject::Listener.kind_of("public"), Some(FieldKind::Bool));
        assert_eq!(Subject::Startup.kind_of("path"), Some(FieldKind::Text));
        assert_eq!(Subject::Startup.kind_of("port"), None);
    }
}
