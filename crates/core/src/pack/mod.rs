//! The rule-pack schema, and the validator that refuses what it does not understand.
//!
//! A pack is one UTF-8 JSON file plus a detached signature — never an archive, so there is
//! no extraction, no path inside a pack and no zip-slip (`docs/PLAN.md` §6.11). This module
//! is the part that reads it: the closed vocabulary of subjects, fields and operators, the
//! limits, and the four promises a pack cannot break.
//!
//! It validates **before** anything is evaluated, and it names the rule and the line for
//! each refusal. A pack is refused as a whole rather than partially loaded: half a pack is a
//! set of rules whose absence nobody can see. The one thing a bad pack may not do is stop the
//! built-ins, which is why nothing here is called from a path the built-in rules depend on.
//!
//! Signature verification happens before this file is reached: a pack that was not signed by
//! a trusted key is refused, and its bytes are never parsed.

pub mod active;
pub mod evaluate;

use std::fmt;

use serde::Deserialize;

use crate::fields::{FieldKind, Subject};
use crate::rules::{Confidence, Severity};

/// The only schema version this build understands.
pub const SCHEMA: u32 = 1;

/// The largest pack a person may load, in bytes.
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

/// How many rules one pack may hold.
pub const MAX_RULES: usize = 512;

/// The longest string a pack may contain.
pub const MAX_STRING: usize = 4 * 1024;

/// How many predicates one rule may hold, across `all` and `any`.
pub const MAX_PREDICATES: usize = 32;

/// An operator a predicate may use. Closed: there is no variant here a pack can invent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    /// Equal, case-insensitively.
    Eq,
    /// Not equal.
    Ne,
    /// Starts with.
    Prefix,
    /// Ends with.
    Suffix,
    /// Contains.
    Contains,
    /// A shell-style pattern, `*` and `?` only.
    Glob,
    /// Is a path under a directory, after both are normalised in the core.
    Under,
    /// Is one of a list.
    In,
    /// Greater than, for a number.
    Gt,
    /// Less than.
    Lt,
    /// The field is present.
    Exists,
}

impl Operator {
    /// Every operator, in the order `docs/RULES.md` documents them.
    pub const ALL: [Operator; 11] = [
        Operator::Eq,
        Operator::Ne,
        Operator::Prefix,
        Operator::Suffix,
        Operator::Contains,
        Operator::Glob,
        Operator::Under,
        Operator::In,
        Operator::Gt,
        Operator::Lt,
        Operator::Exists,
    ];

    /// The name a pack writes.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
            Self::Contains => "contains",
            Self::Glob => "glob",
            Self::Under => "under",
            Self::In => "in",
            Self::Gt => "gt",
            Self::Lt => "lt",
            Self::Exists => "exists",
        }
    }

    /// The operator with this name, if there is one.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|operator| operator.id() == id)
    }

    /// Whether the operator compares against a value.
    #[must_use]
    pub fn takes_value(self) -> bool {
        !matches!(self, Self::Exists)
    }

    /// Whether this operator can hold for a field of this kind.
    ///
    /// `gt` on a path and `prefix` on a port are not style choices: neither can ever be
    /// true, so a rule that writes one is a rule that never fires. The validator refuses
    /// them the way it refuses an unknown field.
    #[must_use]
    pub fn applies_to(self, kind: FieldKind) -> bool {
        match kind {
            FieldKind::Text => !matches!(self, Self::Gt | Self::Lt),
            FieldKind::Number => matches!(
                self,
                Self::Eq | Self::Ne | Self::Gt | Self::Lt | Self::In | Self::Exists
            ),
            FieldKind::Bool => matches!(self, Self::Eq | Self::Ne | Self::In | Self::Exists),
        }
    }

    /// The operators a field of this kind accepts, for a refusal that says what to write.
    #[must_use]
    pub fn accepted_by(kind: FieldKind) -> Vec<&'static str> {
        Self::ALL
            .into_iter()
            .filter(|operator| operator.applies_to(kind))
            .map(Operator::id)
            .collect()
    }
}

/// One comparison in a rule.
#[derive(Clone, Debug, PartialEq)]
pub struct Predicate {
    /// The field, from [`Subject::fields`].
    pub field: String,
    /// How it is compared.
    pub operator: Operator,
    /// What it is compared with. Absent only for `exists`.
    pub value: Option<serde_json::Value>,
}

/// What a rule matches: every predicate in `all`, and at least one in `any`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Match {
    /// The subject the rule is about.
    pub subject: Option<Subject>,
    /// Predicates that must all hold.
    pub all: Vec<Predicate>,
    /// Predicates of which at least one must hold.
    pub any: Vec<Predicate>,
}

impl Match {
    /// How many predicates the rule holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.all.len().saturating_add(self.any.len())
    }

    /// Whether the rule has no condition at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One rule, as the pack wrote it.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Its stable id.
    pub id: String,
    /// What it says happened.
    pub title: String,
    /// How loudly it says it. `attention` is the ceiling for a pack.
    pub severity: Severity,
    /// How sure the rule is of its own reading.
    pub confidence: Confidence,
    /// The ATT&CK technique, where one applies.
    pub technique: Option<String>,
    /// What it matches.
    pub matches: Match,
    /// Why it fired: the reasoning a person reads.
    pub why: String,
    /// The most likely innocent explanation. Required: a rule without one is not a finding.
    pub benign: String,
    /// What a person can do about it.
    pub remediation: String,
}

/// A pack's own identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// `ranger.core` for the first-party pack; a name a third party owns otherwise.
    pub id: String,
    /// A version the author moves when the rules change.
    pub version: String,
    /// What a person sees in the pack list.
    pub title: String,
}

/// A validated pack.
#[derive(Clone, Debug, PartialEq)]
pub struct Pack {
    /// The pack's identity.
    pub header: Header,
    /// Its rules, in the order they were written.
    pub rules: Vec<Rule>,
}

/// One reason a pack was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    /// The rule it is about, when it is about one.
    pub rule: Option<String>,
    /// The line in the file, when the validator could find it.
    pub line: Option<usize>,
    /// What is wrong, in a sentence a pack author can act on.
    pub problem: String,
}

impl fmt::Display for Reject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.rule, self.line) {
            (Some(rule), Some(line)) => write!(formatter, "rule {rule} at line {line}: {}", self.problem),
            (Some(rule), None) => write!(formatter, "rule {rule}: {}", self.problem),
            (None, Some(line)) => write!(formatter, "line {line}: {}", self.problem),
            (None, None) => formatter.write_str(&self.problem),
        }
    }
}

/// The wire shape, before validation. Private: a caller never sees an unvalidated pack.
#[derive(Deserialize)]
struct Wire {
    schema: Option<u32>,
    pack: Option<WireHeader>,
    rules: Option<Vec<WireRule>>,
}

#[derive(Deserialize)]
struct WireHeader {
    id: Option<String>,
    version: Option<String>,
    title: Option<String>,
}

#[derive(Deserialize)]
struct WireRule {
    id: Option<String>,
    title: Option<String>,
    severity: Option<String>,
    confidence: Option<String>,
    technique: Option<String>,
    #[serde(rename = "match")]
    matches: Option<WireMatch>,
    why: Option<String>,
    benign: Option<String>,
    remediation: Option<String>,
}

#[derive(Deserialize)]
struct WireMatch {
    subject: Option<String>,
    all: Option<Vec<WirePredicate>>,
    any: Option<Vec<WirePredicate>>,
}

#[derive(Deserialize)]
struct WirePredicate {
    field: Option<String>,
    op: Option<String>,
    value: Option<serde_json::Value>,
}

/// Read and validate a pack.
///
/// `builtin_ids` are the rule ids this build already has: a pack may not shadow one, because
/// a suppression is scoped to `(rule, subject)` and two rules with one id would make it
/// impossible to say which one a person meant.
pub fn parse(text: &str, builtin_ids: &[&str]) -> Result<Pack, Vec<Reject>> {
    if text.len() > MAX_BYTES {
        return Err(vec![Reject {
            rule: None,
            line: None,
            problem: format!("the pack is {} bytes, and the limit is {MAX_BYTES}", text.len()),
        }]);
    }
    let wire: Wire = match serde_json::from_str(text) {
        Ok(wire) => wire,
        Err(error) => {
            return Err(vec![Reject {
                rule: None,
                line: Some(error.line()),
                problem: format!("the pack is not valid JSON: {error}"),
            }]);
        }
    };

    let mut rejects = Vec::new();
    if wire.schema != Some(SCHEMA) {
        rejects.push(Reject {
            rule: None,
            line: line_of(text, "\"schema\""),
            problem: format!("the schema is {:?}, and this build reads {SCHEMA}", wire.schema),
        });
    }

    let header = match wire.pack {
        Some(header) => Header {
            id: text_or(header.id, "pack.id", text, &mut rejects),
            version: text_or(header.version, "pack.version", text, &mut rejects),
            title: text_or(header.title, "pack.title", text, &mut rejects),
        },
        None => {
            rejects.push(Reject {
                rule: None,
                line: None,
                problem: "the pack has no `pack` block, so it has no id or version".to_owned(),
            });
            Header {
                id: String::new(),
                version: String::new(),
                title: String::new(),
            }
        }
    };

    let wire_rules = wire.rules.unwrap_or_default();
    if wire_rules.is_empty() {
        rejects.push(Reject {
            rule: None,
            line: None,
            problem: "the pack holds no rules".to_owned(),
        });
    }
    if wire_rules.len() > MAX_RULES {
        rejects.push(Reject {
            rule: None,
            line: None,
            problem: format!(
                "the pack holds {} rules, and the limit is {MAX_RULES}",
                wire_rules.len()
            ),
        });
    }

    let mut rules = Vec::with_capacity(wire_rules.len());
    let mut seen: Vec<String> = Vec::new();
    for (index, wire_rule) in wire_rules.into_iter().enumerate() {
        let rule_id = wire_rule.id.clone().unwrap_or_else(|| format!("#{index}"));
        let line = line_of(text, &format!("\"{rule_id}\""));
        let mut rule_rejects = Vec::new();
        let rule = validate_rule(wire_rule, &rule_id, line, text, &mut rule_rejects);
        for reject in &mut rule_rejects {
            if reject.rule.is_none() {
                reject.rule = Some(rule_id.clone());
            }
            if reject.line.is_none() {
                reject.line = line;
            }
        }
        rejects.append(&mut rule_rejects);
        if let Some(rule) = rule {
            if seen.contains(&rule.id) {
                rejects.push(Reject {
                    rule: Some(rule.id.clone()),
                    line,
                    problem: "this id appears twice in the pack".to_owned(),
                });
            } else if builtin_ids.contains(&rule.id.as_str()) {
                rejects.push(Reject {
                    rule: Some(rule.id.clone()),
                    line,
                    problem: "this id is a built-in rule, and a pack may not shadow one".to_owned(),
                });
            }
            seen.push(rule.id.clone());
            rules.push(rule);
        }
    }

    if rejects.is_empty() {
        Ok(Pack { header, rules })
    } else {
        Err(rejects)
    }
}

fn validate_rule(
    wire: WireRule,
    id: &str,
    line: Option<usize>,
    text: &str,
    rejects: &mut Vec<Reject>,
) -> Option<Rule> {
    let mut ok = true;
    let mut push = |problem: String| {
        rejects.push(Reject {
            rule: Some(id.to_owned()),
            line,
            problem,
        });
    };

    if !valid_id(id) {
        push("an id is lowercase, dot-separated, and matches [a-z0-9]+(\\.[a-z0-9-]+)+".to_owned());
        ok = false;
    }
    let severity = match wire.severity.as_deref() {
        Some("attention") => Severity::Attention,
        Some("notice") => Severity::Notice,
        Some("info") => Severity::Info,
        Some("urgent") => {
            push("`urgent` cannot come from a pack: the ceiling is `attention`".to_owned());
            ok = false;
            Severity::Attention
        }
        Some(other) => {
            push(format!(
                "`{other}` is not a severity; use attention, notice or info"
            ));
            ok = false;
            Severity::Attention
        }
        None => {
            push("the rule has no severity".to_owned());
            ok = false;
            Severity::Attention
        }
    };
    let confidence = match wire.confidence.as_deref() {
        Some("observed") => Confidence::Observed,
        Some("likely") => Confidence::Likely,
        Some("possible") => Confidence::Possible,
        Some(other) => {
            push(format!(
                "`{other}` is not a confidence; use observed, likely or possible"
            ));
            ok = false;
            Confidence::Possible
        }
        None => {
            push("the rule has no confidence".to_owned());
            ok = false;
            Confidence::Possible
        }
    };

    let title = required(wire.title, "title", &mut push, &mut ok);
    let why = required(wire.why, "why", &mut push, &mut ok);
    let benign = match wire.benign {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            push(
                "the rule has no `benign` explanation, and a rule that cannot name one is not \
                 a finding"
                    .to_owned(),
            );
            ok = false;
            String::new()
        }
    };
    let remediation = required(wire.remediation, "remediation", &mut push, &mut ok);
    let technique = wire.technique.filter(|technique| {
        let shape = valid_technique(technique);
        if !shape {
            push(format!(
                "`{technique}` is not an ATT&CK technique id (T followed by four digits, then an optional .NNN)"
            ));
        }
        shape
    });

    for value in [&title, &why, &benign, &remediation] {
        if value.len() > MAX_STRING {
            push(format!(
                "a string is {} bytes, and the limit is {MAX_STRING}",
                value.len()
            ));
            ok = false;
        }
    }

    let matches = match wire.matches {
        Some(matches) => validate_match(matches, &mut push, &mut ok),
        None => {
            push("the rule has no `match` block".to_owned());
            ok = false;
            Match::default()
        }
    };
    let _ = text;
    ok.then_some(Rule {
        id: id.to_owned(),
        title,
        severity,
        confidence,
        technique,
        matches,
        why,
        benign,
        remediation,
    })
}

fn validate_match(wire: WireMatch, push: &mut impl FnMut(String), ok: &mut bool) -> Match {
    let subject = match wire.subject.as_deref() {
        Some(id) => match Subject::from_id(id) {
            Some(subject) => Some(subject),
            None => {
                push(format!(
                    "`{id}` is not a subject; use startup, process, listener, package, file-event or agent"
                ));
                *ok = false;
                None
            }
        },
        None => {
            push("the rule's `match` has no subject".to_owned());
            *ok = false;
            None
        }
    };

    let mut all = Vec::new();
    let mut any = Vec::new();
    for (which, predicates) in [("all", wire.all), ("any", wire.any)] {
        for wire_predicate in predicates.unwrap_or_default() {
            let Some(predicate) = validate_predicate(wire_predicate, subject, which, push, ok) else {
                continue;
            };
            if which == "all" {
                all.push(predicate);
            } else {
                any.push(predicate);
            }
        }
    }
    let total = all.len().saturating_add(any.len());
    if total == 0 {
        push("the rule matches nothing: it has no predicates".to_owned());
        *ok = false;
    }
    if total > MAX_PREDICATES {
        push(format!(
            "the rule has {total} predicates, and the limit is {MAX_PREDICATES}"
        ));
        *ok = false;
    }
    Match { subject, all, any }
}

fn validate_predicate(
    wire: WirePredicate,
    subject: Option<Subject>,
    which: &str,
    push: &mut impl FnMut(String),
    ok: &mut bool,
) -> Option<Predicate> {
    let Some(field) = wire.field else {
        push(format!("a predicate in `{which}` has no field"));
        *ok = false;
        return None;
    };
    if field.len() > MAX_STRING {
        push(format!(
            "the field name is {} bytes, and the limit is {MAX_STRING}",
            field.len()
        ));
        *ok = false;
        return None;
    }
    let kind = match subject {
        Some(subject) => match subject.kind_of(&field) {
            Some(kind) => Some(kind),
            None => {
                push(format!(
                    "`{field}` is not a field of `{subject}`; docs/RULES.md lists the ones that are"
                ));
                *ok = false;
                return None;
            }
        },
        None => None,
    };
    let operator = match wire.op.as_deref().map(Operator::from_id) {
        Some(Some(operator)) => operator,
        Some(None) => {
            push(format!(
                "`{}` is not an operator; use eq, ne, prefix, suffix, contains, glob, under, in, gt, lt or exists",
                wire.op.as_deref().unwrap_or_default()
            ));
            *ok = false;
            return None;
        }
        None => {
            push(format!("a predicate in `{which}` has no operator"));
            *ok = false;
            return None;
        }
    };
    if let Some(kind) = kind
        && !operator.applies_to(kind)
    {
        push(format!(
            "`{}` cannot hold for `{field}`, which is {}: use {}",
            operator.id(),
            kind.label(),
            Operator::accepted_by(kind).join(", ")
        ));
        *ok = false;
        return None;
    }
    if operator.takes_value() && wire.value.is_none() {
        push(format!("`{}` needs a value", operator.id()));
        *ok = false;
        return None;
    }
    if !operator.takes_value() && wire.value.is_some() {
        push(format!("`{}` takes no value", operator.id()));
        *ok = false;
        return None;
    }
    // A string value is length-limited like every other string a pack carries; a number or a
    // list of them is bounded by the pack's own size.
    let value = wire.value;
    if let Some(value) = &value
        && let Err(problem) = value_fits(kind, operator, value)
    {
        push(problem);
        *ok = false;
        return None;
    }
    Some(Predicate {
        field,
        operator,
        value,
    })
}

/// Whether a predicate's value is the kind its field holds, and says what to write instead.
///
/// `in` takes a non-empty list; every other operator that takes a value takes one value.
/// This is checked at load because a predicate that can never be true is a rule that never
/// fires, whatever its prose claims.
fn value_fits(kind: Option<FieldKind>, operator: Operator, value: &serde_json::Value) -> Result<(), String> {
    if let serde_json::Value::String(text) = value
        && text.len() > MAX_STRING
    {
        return Err(format!(
            "a value is {} bytes, and the limit is {MAX_STRING}",
            text.len()
        ));
    }
    if operator == Operator::In {
        let serde_json::Value::Array(items) = value else {
            return Err(format!(
                "`in` takes a list of values, and this one is not a list: {value}"
            ));
        };
        if items.is_empty() {
            return Err("`in` takes a list, and this one is empty".to_owned());
        }
        for item in items {
            single_fits(kind, item)?;
        }
        return Ok(());
    }
    single_fits(kind, value)
}

fn single_fits(kind: Option<FieldKind>, value: &serde_json::Value) -> Result<(), String> {
    if let serde_json::Value::String(text) = value {
        for name in evaluate::placeholders_in(text) {
            if !evaluate::known_place(name) {
                return Err(format!(
                    "`{{{name}}}` is not a place ranger resolves; use {}",
                    evaluate::PLACES
                        .iter()
                        .map(|place| format!("{{{place}}}"))
                        .collect::<Vec<String>>()
                        .join(", ")
                ));
            }
        }
    }
    let Some(kind) = kind else {
        return Ok(());
    };
    let fits = match kind {
        FieldKind::Text => value.is_string(),
        FieldKind::Number => value.is_number(),
        FieldKind::Bool => value.is_boolean(),
    };
    if fits {
        return Ok(());
    }
    Err(format!(
        "the value {value} is not {}, which is what this field holds",
        kind.label()
    ))
}

fn required(value: Option<String>, name: &str, push: &mut impl FnMut(String), ok: &mut bool) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            push(format!("the rule has no `{name}`"));
            *ok = false;
            String::new()
        }
    }
}

fn text_or(value: Option<String>, name: &str, _text: &str, rejects: &mut Vec<Reject>) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            rejects.push(Reject {
                rule: None,
                line: None,
                problem: format!("the pack has no `{name}`"),
            });
            String::new()
        }
    }
}

/// Whether an id is lowercase, dot-separated, and has at least two segments.
#[must_use]
pub fn valid_id(id: &str) -> bool {
    let segments: Vec<&str> = id.split('.').collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().all(|segment| {
        !segment.is_empty()
            && segment.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
            && !segment.starts_with('-')
            && !segment.ends_with('-')
    })
}

/// Whether a technique is an ATT&CK id: `T` and four digits, then an optional sub-technique.
#[must_use]
pub fn valid_technique(technique: &str) -> bool {
    let (base, sub) = match technique.split_once('.') {
        Some((base, sub)) => (base, Some(sub)),
        None => (technique, None),
    };
    let base_ok = base.len() == 5
        && base.starts_with('T')
        && base[1..].chars().all(|character| character.is_ascii_digit());
    let sub_ok =
        sub.is_none_or(|sub| sub.len() == 3 && sub.chars().all(|character| character.is_ascii_digit()));
    base_ok && sub_ok
}

/// The 1-based line a literal appears on, for a refusal that has to be findable.
fn line_of(text: &str, needle: &str) -> Option<usize> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|index| index.saturating_add(1))
}

#[cfg(test)]
mod shipped;
#[cfg(test)]
mod tests;
