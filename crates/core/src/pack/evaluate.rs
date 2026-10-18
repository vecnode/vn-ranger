//! Evaluating a pack rule against the facts: the half that makes a pack mean something.
//!
//! A validated pack is a set of rules that *could* fire; this module is what fires them.
//! It is a pure function of a rule and one fact view — no clock, no disk, no operating
//! system — so a rule can be tested with a fixture the way a built-in rule is, and the same
//! rule fires the same way on every platform (`docs/PLAN.md` §6.11).
//!
//! Two rules govern the vocabulary here, and both are promises to the pack author:
//!
//! - Text comparisons are case-insensitive. A path is written `C:\Users` by Windows, `C:/Users`
//!   by a tool, and `c:\users` by a careless one; none of those differences is a fact.
//! - A field that the fact does not carry is absent, not empty. `exists` is what asks whether
//!   it is there, and every other operator is false when it is not. An absent optional is not
//!   an empty string, because those are different facts.
//!
//! Evidence is the matched predicate itself: the field, and what the fact actually said. A
//! finding a person cannot trace back to a line of observed data is the thing this project
//! refuses to emit.

use crate::fields::Subject;
use crate::model::{AgentFact, AutorunFact, FileFact, ListenerFact, PackageFact, ProcessFact, Snapshot};
use crate::pack::{Operator, Pack, Rule};
use crate::rules::Finding;

/// The locations a rule may name without knowing the machine.
///
/// A pack cannot spell `C:\Users\someone\AppData\Local\Temp`, and it should not: that is a
/// fact about a machine, not about a technique. A rule writes a placeholder, the caller
/// resolves it, and this list is the whole of what a pack may name. An unknown placeholder
/// is a load error, the same as an unknown field.
pub const PLACES: [&str; 10] = [
    "TEMP",
    "HOME",
    "DOWNLOADS",
    "DESKTOP",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "STARTUP",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
];

/// Whether a placeholder is one a pack may write.
#[must_use]
pub fn known_place(name: &str) -> bool {
    PLACES.contains(&name)
}

/// The paths this machine resolves the placeholders to.
///
/// Supplied by the caller, because the core has no environment and no filesystem. A place
/// with no path is one this machine could not name: a predicate that asks about it cannot
/// hold, which is the honest answer rather than a guess.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Places {
    entries: Vec<(&'static str, String)>,
}

impl Places {
    /// An empty set: every placeholder is unresolvable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// This set with one more place resolved.
    #[must_use]
    pub fn with(mut self, name: &str, path: impl Into<String>) -> Self {
        if let Some(known) = PLACES.iter().find(|known| **known == name) {
            let path = path.into();
            if !path.trim().is_empty() {
                self.entries.push((known, path));
            }
        }
        self
    }

    /// The path this machine resolved a place to, when it did.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, path)| path.as_str())
    }

    /// Substitute every placeholder in a value.
    ///
    /// `None` when the value names a place this machine could not resolve, because a
    /// comparison against a path nobody knows is a rule that cannot be checked here.
    #[must_use]
    pub fn expand(&self, text: &str) -> Option<String> {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let end = after.find('}')?;
            let name = &after[..end];
            if !known_place(name) {
                return None;
            }
            out.push_str(self.get(name)?);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Some(out)
    }
}

/// Every placeholder a string value names, so the validator can refuse an unknown one.
#[must_use]
pub fn placeholders_in(text: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            break;
        };
        names.push(&after[..end]);
        rest = &after[end + 1..];
    }
    names
}

/// One value a fact carries, in the kinds the field table names.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// Text, compared case-insensitively.
    Text(String),
    /// A whole number.
    Number(i64),
    /// A yes or no.
    Bool(bool),
}

impl Value {
    /// The value as a person reads it in the evidence line.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Number(number) => number.to_string(),
            Self::Bool(flag) => {
                if *flag {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                }
            }
        }
    }
}

/// One fact, seen the way a rule sees it: a stable identity, a label, and its fields.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Fact {
    /// The stable subject a suppression is scoped to.
    pub subject: String,
    /// The thing a person recognises, in words.
    pub label: String,
    /// The fields this fact carries. A field that is absent is not in the list.
    pub fields: Vec<(&'static str, Value)>,
}

impl Fact {
    /// The value of a field, when the fact carries it.
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(name, _)| *name == field)
            .map(|(_, value)| value)
    }

    fn push(&mut self, field: &'static str, value: Value) {
        self.fields.push((field, value));
    }

    fn push_text(&mut self, field: &'static str, value: Option<&str>) {
        if let Some(value) = value
            && !value.is_empty()
        {
            self.push(field, Value::Text(value.to_owned()));
        }
    }

    fn push_number(&mut self, field: &'static str, value: Option<i64>) {
        if let Some(value) = value {
            self.push(field, Value::Number(value));
        }
    }
}

/// A startup entry as a rule sees it.
#[must_use]
pub fn startup_fact(autorun: &AutorunFact) -> Fact {
    let mut fact = Fact {
        subject: autorun.id.clone(),
        label: format!("{} — {}", autorun.name, autorun.location),
        fields: Vec::new(),
    };
    fact.push_text("name", Some(&autorun.name));
    fact.push_text("command", Some(&autorun.command));
    fact.push_text("location", Some(&autorun.location));
    fact.push_text("path", autorun.exe.as_deref());
    fact.push_text("hash", autorun.sha256.as_deref());
    fact.push_text("kind", Some(autorun.kind.id()));
    fact.push_text("scope", Some(autorun.scope.id()));
    fact.push_text("signed", Some(autorun.signature.id()));
    fact.push("enabled", Value::Bool(autorun.enabled));
    fact.push("hidden", Value::Bool(autorun.hidden));
    fact
}

/// A running process as a rule sees it.
#[must_use]
pub fn process_fact(process: &ProcessFact) -> Fact {
    let mut fact = Fact {
        subject: format!("process:{}", process.pid),
        label: format!("{} (pid {})", process.name, process.pid),
        fields: Vec::new(),
    };
    fact.push_text("name", Some(&process.name));
    fact.push_text("command", process.command.as_deref());
    fact.push_text("path", process.exe.as_deref());
    fact.push_text("user", process.user.as_deref());
    fact.push_number("pid", i64::from(process.pid).into());
    fact.push_number("parent", process.parent.map(i64::from));
    fact.push_number(
        "started_at",
        process
            .started_at_unix
            .and_then(|seconds| i64::try_from(seconds).ok()),
    );
    fact
}

/// A listening socket as a rule sees it.
#[must_use]
pub fn listener_fact(listener: &ListenerFact) -> Fact {
    let mut fact = Fact {
        subject: format!("listener:{}:{}", listener.protocol.label(), listener.port),
        label: format!("{} :{}", listener.address, listener.port),
        fields: Vec::new(),
    };
    fact.push_text("address", Some(&listener.address));
    fact.push_text("process", listener.process.as_deref());
    fact.push_text("protocol", Some(listener.protocol.label()));
    fact.push_text("state", Some(&listener.state));
    fact.push_number("port", i64::from(listener.port).into());
    fact.push("public", Value::Bool(listener.public));
    fact
}

/// An installed package as a rule sees it.
#[must_use]
pub fn package_fact(package: &PackageFact) -> Fact {
    let mut fact = Fact {
        subject: format!("package:{}", package.name),
        label: match &package.version {
            Some(version) => format!("{} {}", package.name, version),
            None => package.name.clone(),
        },
        fields: Vec::new(),
    };
    fact.push_text("name", Some(&package.name));
    fact.push_text("version", package.version.as_deref());
    fact.push_text("publisher", package.publisher.as_deref());
    fact.push_text("source", Some(&package.source));
    fact
}

/// An editor, agent or package-manager configuration as a rule sees it.
#[must_use]
pub fn agent_fact(agent: &AgentFact) -> Fact {
    let mut fact = Fact {
        subject: agent.id.clone(),
        label: format!("{} ({})", agent.name, agent.path),
        fields: Vec::new(),
    };
    fact.push_text("tool", Some(&agent.tool));
    fact.push_text("name", Some(&agent.name));
    fact.push_text("path", Some(&agent.path));
    fact.push_text("command", agent.command.as_deref());
    fact
}

/// A file the content engine read, as a rule sees it.
///
/// One fact per file. What a signature matched is a different subject ([`file_match_fact`]),
/// so a rule about a file's shape and a rule about a signature that hit it cannot double
/// count each other.
#[must_use]
pub fn file_fact(file: &FileFact) -> Fact {
    let mut fact = Fact {
        subject: format!("file:{}", file.path),
        label: file.path.clone(),
        fields: Vec::new(),
    };
    fact.push_text("path", Some(&file.path));
    fact.push_text("name", Some(&file.name));
    fact.push_text("extension", file.extension.as_deref());
    fact.push_text("digest", file.digest.as_deref());
    fact.push_text("kind", file.kind.as_deref());
    fact.push_text("hash_match", file.hash_match.as_deref());
    fact.push_text("signed", Some(file.signature.id()));
    fact.push_text("signer", file.signer.as_deref());
    fact.push_number("size", i64::try_from(file.size).ok());
    if !file.container.is_empty() {
        fact.push_text("container", Some(&file.container.join(" > ")));
        fact.push_number("depth", i64::try_from(file.container.len()).ok());
    }
    fact
}

/// One content signature that matched a file, as a rule sees it.
///
/// The file's own fields are repeated here so a rule can say "this signature, in an
/// executable, in a user folder" and read all three from one fact.
#[must_use]
pub fn file_match_fact(file: &FileFact, hit: &crate::model::ContentMatch) -> Fact {
    let mut fact = Fact {
        subject: format!("file-match:{}#{}", file.path, hit.name),
        label: format!("{} — {}", file.path, hit.name),
        fields: Vec::new(),
    };
    fact.push_text("name", Some(&hit.name));
    fact.push_text("path", Some(&file.path));
    fact.push_text("kind", file.kind.as_deref());
    fact.push_text("signed", Some(file.signature.id()));
    fact.push_text("signer", file.signer.as_deref());
    fact.push_number("at", i64::try_from(hit.at).ok());
    fact.push_number("line", Some(i64::from(hit.line)));
    if !file.container.is_empty() {
        fact.push_text("container", Some(&file.container.join(" > ")));
    }
    fact
}

/// Every fact in a snapshot that a rule could be about, as rule views.
///
/// The order is the snapshot's own, so two scans of an unchanged machine produce the same
/// findings in the same order.
#[must_use]
pub fn facts_of(snapshot: &Snapshot, subject: Subject) -> Vec<Fact> {
    match subject {
        Subject::Startup => snapshot.autoruns.iter().map(startup_fact).collect(),
        Subject::Process => snapshot.processes.iter().map(process_fact).collect(),
        Subject::Listener => snapshot.listeners.iter().map(listener_fact).collect(),
        Subject::Package => snapshot.packages.iter().map(package_fact).collect(),
        Subject::Agent => snapshot.agents.iter().map(agent_fact).collect(),
        // A watched change is a fact the scan does not carry: the watcher reports them as
        // they happen. A rule about it evaluates against the views it is handed.
        Subject::FileEvent => Vec::new(),
        Subject::File => snapshot.files.iter().map(file_fact).collect(),
        Subject::FileMatch => snapshot
            .files
            .iter()
            .flat_map(|file| file.matches.iter().map(|hit| file_match_fact(file, hit)))
            .collect(),
    }
}

/// Evaluate one rule against one fact.
///
/// `all` and `any` compose the way the pack says: every predicate in `all`, and at least
/// one in `any`. A rule with only one of the two needs only that one.
#[must_use]
pub fn evaluate_rule(rule: &Rule, fact: &Fact, places: &Places) -> Option<Finding> {
    let mut evidence = Vec::new();
    for predicate in &rule.matches.all {
        evidence.push(matched(predicate, fact, places)?);
    }
    if !rule.matches.any.is_empty() {
        let mut any_evidence = None;
        for predicate in &rule.matches.any {
            if let Some(line) = matched(predicate, fact, places) {
                any_evidence = Some(line);
                break;
            }
        }
        evidence.push(any_evidence?);
    }
    Some(Finding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        // The validator refuses `urgent` before a pack is loaded, so this is the severity
        // as written. A pack's ceiling is enforced where a pack is refused, which is one
        // place, rather than defended for twice and forgotten once.
        severity: rule.severity,
        confidence: rule.confidence,
        technique: rule.technique.clone(),
        subject: fact.subject.clone(),
        subject_label: fact.label.clone(),
        evidence,
        why: rule.why.clone(),
        benign: rule.benign.clone(),
        remediation: rule.remediation.clone(),
        pack: None,
    })
}

/// One predicate, as evidence, when it holds.
///
/// The line names the operator and what the pack asked for, then what the fact actually
/// said. That is the difference between evidence and a verdict: a person can check it.
fn matched(predicate: &crate::pack::Predicate, fact: &Fact, places: &Places) -> Option<String> {
    let observed = fact.get(&predicate.field)?;
    if predicate.operator == Operator::Exists {
        return Some(format!(
            "{} is present — observed {}",
            predicate.field,
            observed.display()
        ));
    }
    let expected = predicate.value.as_ref()?;
    if !holds_for(observed, predicate.operator, expected, places) {
        return None;
    }
    Some(format!(
        "{} {} {} — observed {}",
        predicate.field,
        predicate.operator.id(),
        render(expected),
        observed.display()
    ))
}

/// Whether one observed value satisfies one operator against one expected value.
fn holds_for(observed: &Value, operator: Operator, expected: &serde_json::Value, places: &Places) -> bool {
    if operator == Operator::In {
        let serde_json::Value::Array(items) = expected else {
            return false;
        };
        return items
            .iter()
            .any(|item| holds_for(observed, Operator::Eq, item, places));
    }
    match (observed, expected) {
        (Value::Text(text), serde_json::Value::String(expected)) => {
            // A value may name a place rather than a path. This machine either resolved it
            // or it did not; a comparison against a path nobody knows is not made.
            let Some(expected) = places.expand(expected) else {
                return false;
            };
            match operator {
                Operator::Eq => text.eq_ignore_ascii_case(&expected),
                Operator::Ne => !text.eq_ignore_ascii_case(&expected),
                Operator::Prefix => starts_with(text, &expected),
                Operator::Suffix => ends_with(text, &expected),
                Operator::Contains => contains(text, &expected),
                Operator::Glob => glob(&expected, text),
                Operator::Under => under(text, &expected),
                Operator::Exists => true,
                Operator::In | Operator::Gt | Operator::Lt => false,
            }
        }
        (Value::Number(number), serde_json::Value::Number(expected)) => {
            let Some(expected) = expected.as_i64() else {
                return false;
            };
            match operator {
                Operator::Eq => *number == expected,
                Operator::Ne => *number != expected,
                Operator::Gt => *number > expected,
                Operator::Lt => *number < expected,
                _ => false,
            }
        }
        (Value::Bool(flag), serde_json::Value::Bool(expected)) => match operator {
            Operator::Eq => flag == expected,
            Operator::Ne => flag != expected,
            _ => false,
        },
        _ => false,
    }
}

/// How a pack's value is written in an evidence line.
fn render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(render).collect();
            rendered.join(", ")
        }
        other => other.to_string(),
    }
}

fn starts_with(text: &str, prefix: &str) -> bool {
    text.to_lowercase().starts_with(&prefix.to_lowercase())
}

fn ends_with(text: &str, suffix: &str) -> bool {
    text.to_lowercase().ends_with(&suffix.to_lowercase())
}

fn contains(text: &str, needle: &str) -> bool {
    text.to_lowercase().contains(&needle.to_lowercase())
}

/// Whether a path is the directory or under it.
///
/// Separators are compared after being made the same, because a pack author writes the
/// separator of their own platform and a path arrives with the one of the machine. A
/// directory of `/tmp` does not contain `/tmpfoo`.
#[must_use]
pub fn under(path: &str, directory: &str) -> bool {
    let path = normalise_path(path);
    let directory = normalise_path(directory);
    if directory.is_empty() {
        return false;
    }
    path == directory
        || path
            .strip_prefix(&directory)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn normalise_path(path: &str) -> String {
    let mut normalised = path.trim().replace('\\', "/").to_lowercase();
    while normalised.len() > 1 && normalised.ends_with('/') {
        normalised.pop();
    }
    normalised
}

/// A shell-style pattern with `*` and `?`, matched case-insensitively over the whole text.
///
/// Deliberately not a regular expression: the vocabulary of a pack is closed, and a pattern
/// language with alternation and groups is a program by another name (`docs/PLAN.md` §6.11).
/// The matcher is the two-pointer algorithm, so a pattern full of stars cannot make it
/// backtrack into an exponential walk.
#[must_use]
pub fn glob(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();
    let (mut p, mut t) = (0_usize, 0_usize);
    let mut star: Option<usize> = None;
    let mut resume = 0_usize;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// Evaluate a whole pack against a snapshot.
///
/// A pack that fires produces findings in the pack's own order, then the facts' order, so
/// the same pack on the same machine reads the same way twice.
#[must_use]
pub fn evaluate(pack: &Pack, snapshot: &Snapshot, places: &Places) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in &pack.rules {
        let Some(subject) = rule.matches.subject else {
            continue;
        };
        for fact in facts_of(snapshot, subject) {
            if let Some(mut finding) = evaluate_rule(rule, &fact, places) {
                finding.pack = Some(pack_source(pack));
                findings.push(finding);
            }
        }
    }
    findings
}

/// Evaluate one subject's rules against facts the scan did not produce.
///
/// The watcher and the agent collector hand their own facts in through this, so a
/// `file-event` or `agent` rule fires on the same matcher as everything else rather than
/// on a second implementation of it.
#[must_use]
pub fn evaluate_facts(pack: &Pack, subject: Subject, facts: &[Fact], places: &Places) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in &pack.rules {
        if rule.matches.subject != Some(subject) {
            continue;
        }
        for fact in facts {
            if let Some(mut finding) = evaluate_rule(rule, fact, places) {
                finding.pack = Some(pack_source(pack));
                findings.push(finding);
            }
        }
    }
    findings
}

/// How a pack names itself on a finding.
fn pack_source(pack: &Pack) -> String {
    format!("{} {}", pack.header.id, pack.header.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AutorunKind, AutorunScope, SignatureStatus};
    use crate::pack::{Match, Predicate};
    use crate::rules::{Confidence, Severity};
    use serde_json::json;

    fn predicate(field: &str, operator: Operator, value: serde_json::Value) -> Predicate {
        Predicate {
            field: field.to_owned(),
            operator,
            value: Some(value),
        }
    }

    fn rule(subject: Subject, all: Vec<Predicate>, any: Vec<Predicate>) -> Rule {
        Rule {
            id: "test.rule".to_owned(),
            title: "A test rule".to_owned(),
            severity: Severity::Notice,
            confidence: Confidence::Observed,
            technique: None,
            matches: Match {
                subject: Some(subject),
                all,
                any,
            },
            why: "Because the test says so.".to_owned(),
            benign: "A test.".to_owned(),
            remediation: "Nothing.".to_owned(),
        }
    }

    fn startup(id: &str, name: &str, command: &str, exe: Option<&str>) -> AutorunFact {
        AutorunFact {
            id: id.to_owned(),
            name: name.to_owned(),
            command: command.to_owned(),
            location: "HKCU\\...\\Run".to_owned(),
            kind: AutorunKind::RunKey,
            scope: AutorunScope::User,
            enabled: true,
            hidden: false,
            exe: exe.map(str::to_owned),
            sha256: Some("ab".repeat(32)),
            signature: SignatureStatus::Valid,
        }
    }

    fn fact(autorun: &AutorunFact) -> Fact {
        startup_fact(autorun)
    }

    #[test]
    fn all_and_any_compose_the_way_the_pack_says() {
        let entry = startup("run:x", "X", "C:\\Tools\\x.exe --run", Some("C:\\Tools\\x.exe"));
        let subject = fact(&entry);

        let both = rule(
            Subject::Startup,
            vec![predicate("name", Operator::Eq, json!("x"))],
            vec![predicate("path", Operator::Contains, json!("tools"))],
        );
        assert!(evaluate_rule(&both, &subject, &Places::new()).is_some());

        let missing_any = rule(
            Subject::Startup,
            vec![predicate("name", Operator::Eq, json!("x"))],
            vec![predicate("path", Operator::Contains, json!("nowhere"))],
        );
        assert!(
            evaluate_rule(&missing_any, &subject, &Places::new()).is_none(),
            "one predicate in `any` must hold"
        );

        let missing_all = rule(
            Subject::Startup,
            vec![predicate("name", Operator::Eq, json!("y"))],
            vec![],
        );
        assert!(evaluate_rule(&missing_all, &subject, &Places::new()).is_none());
    }

    #[test]
    fn a_finding_carries_the_evidence_that_fired_it() {
        let entry = startup("run:x", "X", "C:\\Tools\\x.exe", Some("C:\\Tools\\x.exe"));
        let subject = fact(&entry);
        let rule = rule(
            Subject::Startup,
            vec![predicate("path", Operator::Contains, json!("tools"))],
            vec![],
        );
        let finding = evaluate_rule(&rule, &subject, &Places::new()).unwrap();
        assert_eq!(finding.subject, "run:x");
        assert_eq!(finding.evidence.len(), 1);
        assert!(
            finding.evidence[0].contains("C:\\Tools\\x.exe"),
            "the evidence names the observed value: {:?}",
            finding.evidence
        );
        assert!(finding.benign.contains("test"));
    }

    #[test]
    fn text_is_compared_without_regard_to_case() {
        let entry = startup("run:x", "Acme", "C:\\TOOLS\\X.EXE", Some("C:\\TOOLS\\X.EXE"));
        let subject = fact(&entry);
        for (field, operator, value, expected) in [
            ("name", Operator::Eq, json!("acme"), true),
            ("name", Operator::Eq, json!("ACME"), true),
            ("name", Operator::Eq, json!("other"), false),
            ("name", Operator::Ne, json!("acme"), false),
            ("path", Operator::Prefix, json!("c:\\tools"), true),
            ("path", Operator::Suffix, json!(".exe"), true),
            ("path", Operator::Contains, json!("tools"), true),
        ] {
            let rule = rule(
                Subject::Startup,
                vec![predicate(field, operator, value.clone())],
                vec![],
            );
            let holds = evaluate_rule(&rule, &subject, &Places::new()).is_some();
            assert_eq!(holds, expected, "{operator:?} {value} on {field}");
        }
    }

    #[test]
    fn an_absent_field_is_absent_rather_than_empty() {
        let entry = startup("run:x", "X", "x.exe", None);
        let subject = fact(&entry);
        assert_eq!(subject.get("path"), None);
        let never = rule(
            Subject::Startup,
            vec![predicate("path", Operator::Contains, json!(""))],
            vec![],
        );
        assert!(
            evaluate_rule(&never, &subject, &Places::new()).is_none(),
            "an empty value must not match a field that is not there"
        );
        let exists = Predicate {
            field: "path".to_owned(),
            operator: Operator::Exists,
            value: None,
        };
        assert!(
            evaluate_rule(
                &rule(Subject::Startup, vec![exists], vec![]),
                &subject,
                &Places::new()
            )
            .is_none()
        );
        let name_exists = Predicate {
            field: "name".to_owned(),
            operator: Operator::Exists,
            value: None,
        };
        assert!(
            evaluate_rule(
                &rule(Subject::Startup, vec![name_exists], vec![]),
                &subject,
                &Places::new()
            )
            .is_some()
        );
    }

    #[test]
    fn a_glob_matches_the_whole_string_with_two_wildcards() {
        assert!(glob("*.exe", "C:\\Tools\\X.EXE"));
        assert!(glob("c:\\tools\\?.exe", "C:\\Tools\\x.exe"));
        assert!(!glob("*.exe", "C:\\Tools\\x.exe.txt"));
        assert!(
            !glob("tools/*", "C:\\Tools\\x.exe"),
            "the whole string, not a suffix"
        );
        assert!(glob("*", ""));
        assert!(glob("*tools*", "C:\\Tools\\x.exe"));
        // A pattern of stars must not blow up on a long string.
        let long = "a".repeat(4096);
        assert!(glob("****************a", &long));
        assert!(!glob("****************a", &"b".repeat(4096)));
    }

    #[test]
    fn under_is_a_directory_relationship() {
        assert!(under("C:\\Temp\\x.exe", "c:\\temp"));
        assert!(under("C:\\Temp\\x.exe", "C:\\Temp\\"));
        assert!(under("/tmp/x.sh", "/tmp"));
        assert!(under("/tmp", "/tmp"));
        assert!(!under("/tmpfoo/x.sh", "/tmp"), "a prefix is not a directory");
        assert!(!under("", "/tmp"));
        assert!(!under("/tmp", ""));
        assert!(under("C:/Users/x", "c:\\users"), "the separator is not the fact");
    }

    #[test]
    fn numbers_and_booleans_compare_the_way_their_kind_allows() {
        let listener = ListenerFact {
            protocol: crate::model::Protocol::Tcp,
            address: "0.0.0.0".to_owned(),
            port: 4444,
            pid: Some(7),
            process: Some("x".to_owned()),
            state: "LISTEN".to_owned(),
            public: true,
        };
        let subject = listener_fact(&listener);
        let high = rule(
            Subject::Listener,
            vec![predicate("port", Operator::Gt, json!(1024))],
            vec![],
        );
        assert!(evaluate_rule(&high, &subject, &Places::new()).is_some());
        let low = rule(
            Subject::Listener,
            vec![predicate("port", Operator::Lt, json!(1024))],
            vec![],
        );
        assert!(evaluate_rule(&low, &subject, &Places::new()).is_none());
        let public = rule(
            Subject::Listener,
            vec![predicate("public", Operator::Eq, json!(true))],
            vec![],
        );
        assert!(evaluate_rule(&public, &subject, &Places::new()).is_some());
        let in_list = rule(
            Subject::Listener,
            vec![predicate("port", Operator::In, json!([80, 443, 4444]))],
            vec![],
        );
        assert!(evaluate_rule(&in_list, &subject, &Places::new()).is_some());
    }

    #[test]
    fn a_pack_fires_on_a_snapshot_and_names_itself() {
        let mut snapshot = Snapshot::empty(crate::model::Host::default(), false);
        snapshot.autoruns.push(startup(
            "run:one",
            "One",
            "C:\\Temp\\one.exe",
            Some("C:\\Temp\\one.exe"),
        ));
        snapshot.autoruns.push(startup(
            "run:two",
            "Two",
            "C:\\Program Files\\two.exe",
            Some("C:\\Program Files\\two.exe"),
        ));
        let rule = rule(
            Subject::Startup,
            vec![predicate("path", Operator::Under, json!("C:\\Temp"))],
            vec![],
        );
        let pack = Pack {
            header: crate::pack::Header {
                id: "ranger.core".to_owned(),
                version: "2026.11.1".to_owned(),
                title: "Ranger core".to_owned(),
            },
            rules: vec![rule],
        };
        let findings = evaluate(&pack, &snapshot, &Places::new());
        assert_eq!(findings.len(), 1, "only the entry in the temporary folder");
        assert_eq!(findings[0].subject, "run:one");
        assert_eq!(findings[0].pack.as_deref(), Some("ranger.core 2026.11.1"));
        assert!(findings[0].from_pack());
    }

    #[test]
    fn a_rule_for_another_subject_does_not_fire_on_this_one() {
        let entry = startup("run:x", "X", "x.exe", Some("x.exe"));
        let subject = fact(&entry);
        let rule = rule(
            Subject::Process,
            vec![predicate("name", Operator::Eq, json!("x.exe"))],
            vec![],
        );
        assert!(evaluate_rule(&rule, &subject, &Places::new()).is_none());
    }

    #[test]
    fn a_file_fact_carries_its_shape_and_a_match_is_its_own_subject() {
        let file = FileFact {
            path: "C:\\Temp\\report.docx".to_owned(),
            name: "report.docx".to_owned(),
            extension: Some("docx".to_owned()),
            size: 2048,
            digest: Some("ab".repeat(32)),
            kind: Some("ole2".to_owned()),
            signature: SignatureStatus::Unsigned,
            signer: None,
            container: vec!["word/embeddings/oleObject1.bin".to_owned()],
            hash_match: None,
            matches: vec![crate::model::ContentMatch {
                name: "Win.Trojan.X-1".to_owned(),
                at: 512,
                line: 3,
            }],
            read_bytes: Some(2048),
        };
        let fact = file_fact(&file);
        assert_eq!(fact.subject, "file:C:\\Temp\\report.docx");
        assert_eq!(fact.get("signed"), Some(&Value::Text("unsigned".to_owned())));
        assert_eq!(fact.get("depth"), Some(&Value::Number(1)));
        assert_eq!(
            fact.get("container"),
            Some(&Value::Text("word/embeddings/oleObject1.bin".to_owned()))
        );
        assert!(
            fact.get("at").is_none(),
            "where a signature matched belongs to the match, not the file"
        );

        let hit = file_match_fact(&file, &file.matches[0]);
        assert_eq!(hit.subject, "file-match:C:\\Temp\\report.docx#Win.Trojan.X-1");
        assert_eq!(hit.get("name"), Some(&Value::Text("Win.Trojan.X-1".to_owned())));
        assert_eq!(hit.get("at"), Some(&Value::Number(512)));
        assert_eq!(hit.get("line"), Some(&Value::Number(3)));
        assert_eq!(
            hit.get("signed"),
            Some(&Value::Text("unsigned".to_owned())),
            "the match repeats the file's shape so one rule can read both"
        );

        let mut snapshot = Snapshot::empty(crate::model::Host::default(), false);
        snapshot.files.push(file);
        let pack = |subject: Subject, field: &str, value: serde_json::Value| Pack {
            header: crate::pack::Header {
                id: "test.file".to_owned(),
                version: "1".to_owned(),
                title: "File rules".to_owned(),
            },
            rules: vec![rule(subject, vec![predicate(field, Operator::Eq, value)], vec![])],
        };
        assert_eq!(
            evaluate(
                &pack(Subject::File, "signed", json!("unsigned")),
                &snapshot,
                &Places::new()
            )
            .len(),
            1,
            "a rule about the file fires once"
        );
        assert_eq!(
            evaluate(
                &pack(Subject::FileMatch, "name", json!("Win.Trojan.X-1")),
                &snapshot,
                &Places::new()
            )
            .len(),
            1,
            "a rule about the match fires once per hit"
        );
        assert!(
            evaluate(
                &pack(Subject::File, "name", json!("Win.Trojan.X-1")),
                &snapshot,
                &Places::new()
            )
            .is_empty(),
            "the two subjects do not answer each other's questions"
        );
    }

    #[test]
    fn facts_for_a_subject_the_scan_does_not_carry_are_empty_rather_than_invented() {
        let snapshot = Snapshot::empty(crate::model::Host::default(), false);
        assert!(facts_of(&snapshot, Subject::Agent).is_empty());
        assert!(facts_of(&snapshot, Subject::FileEvent).is_empty());
    }
}
