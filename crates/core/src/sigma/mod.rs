//! A Sigma importer for the subset ranger can honestly express.
//!
//! Sigma is a shared language for detection rules, and most of it is about logs: a field
//! name from an event schema, a condition over selections, a level. A pack rule is about
//! *facts this machine collected*, which is a different vocabulary, so an importer that
//! promised to take a Sigma rule and make it work would be lying about most of them.
//!
//! What this does instead is convert the part that maps, count the part that does not by
//! reason, and produce a pack — which then has to be signed before ranger will load it. The
//! import is a translation with a footnote, not an adoption.
//!
//! The mapping is small on purpose, and `docs/RULES.md` documents it:
//!
//! | Sigma field | pack field |
//! |---|---|
//! | `Image` | `process.path` |
//! | `CommandLine` | `process.command` |
//! | `User` | `process.user` |
//! | `User\|contains` and the other text modifiers | the same field, same modifier |
//!
//! A rule that names any other field is skipped with a reason naming that field. A rule with
//! no `falsepositives` is skipped too: a rule that cannot say what innocent thing it looks
//! like is a rule ranger's own validator would refuse.

pub mod yaml;

use crate::pack::{Match, Pack, Predicate, Rule, SCHEMA, valid_id};
use crate::rules::{Confidence, Severity};
use yaml::Node;

/// The pack a Sigma import produces before anything is signed.
#[derive(Clone, Debug, PartialEq)]
pub struct Import {
    /// The rules that could be expressed as pack rules.
    pub rules: Vec<Rule>,
    /// The rules that could not, each with the reason a person can act on.
    pub skipped: Vec<Skipped>,
    /// The document's own title, for the pack header.
    pub title: String,
}

/// One Sigma rule that was left out, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// The rule's title, as the file wrote it.
    pub title: String,
    /// Why it is not in the pack.
    pub reason: String,
}

impl Import {
    /// The pack these rules make, ready to be written as JSON and signed.
    #[must_use]
    pub fn pack(&self, id: &str, version: &str) -> Pack {
        Pack {
            header: crate::pack::Header {
                id: id.to_owned(),
                version: version.to_owned(),
                title: self.title.clone(),
            },
            rules: self.rules.clone(),
        }
    }
}

/// The fields a Sigma rule may name, and what each becomes.
const FIELDS: [(&str, &str); 3] = [("image", "path"), ("commandline", "command"), ("user", "user")];

/// Read one Sigma rule and convert what can be converted.
pub fn import(text: &str) -> Result<Import, String> {
    let node = yaml::parse(text).map_err(|refusal| refusal.to_string())?;
    let title = node
        .get("title")
        .and_then(Node::as_str)
        .unwrap_or("A Sigma rule")
        .trim()
        .to_owned();
    let mut import = Import {
        rules: Vec::new(),
        skipped: Vec::new(),
        title: format!("Sigma import: {title}"),
    };
    let Some(detection) = node.get("detection") else {
        import.skipped.push(Skipped {
            title,
            reason: "the rule has no `detection` block".to_owned(),
        });
        return Ok(import);
    };
    let condition = detection
        .get("condition")
        .and_then(Node::as_str)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let Some(selection_name) = single_selection(&condition) else {
        import.skipped.push(Skipped {
            title,
            reason: format!(
                "the condition `{condition}` is not one selection; ranger imports `selection` and `1 of selection*`"
            ),
        });
        return Ok(import);
    };
    let Some(selection) = detection.as_map().and_then(|entries| {
        entries
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&selection_name))
            .map(|(_, node)| node)
    }) else {
        import.skipped.push(Skipped {
            title,
            reason: format!("the condition names `{selection_name}`, which the rule does not define"),
        });
        return Ok(import);
    };
    let Some(entries) = selection.as_map() else {
        import.skipped.push(Skipped {
            title,
            reason: "the selection is not a set of field and value pairs".to_owned(),
        });
        return Ok(import);
    };
    let Some(benign) = false_positives(&node) else {
        import.skipped.push(Skipped {
            title,
            reason: "the rule names no `falsepositives`, and a rule that cannot name an innocent \
                     explanation is not a finding"
                .to_owned(),
        });
        return Ok(import);
    };

    let mut predicates = Vec::new();
    for (key, value) in entries {
        match predicate(key, value) {
            Ok(predicate) => predicates.push(predicate),
            Err(reason) => {
                import.skipped.push(Skipped { title, reason });
                return Ok(import);
            }
        }
    }
    if predicates.is_empty() {
        import.skipped.push(Skipped {
            title,
            reason: "the selection has no fields".to_owned(),
        });
        return Ok(import);
    }
    let severity = severity(node.get("level").and_then(Node::as_str));
    let why = node
        .get("description")
        .and_then(Node::as_str)
        .filter(|text| !text.trim().is_empty())
        .unwrap_or("The rule's author wrote this as a detection for the field it names.");
    let id = rule_id(&title, import.rules.len());
    import.rules.push(Rule {
        id,
        title: title.clone(),
        severity,
        confidence: Confidence::Possible,
        technique: node.get("tags").and_then(Node::as_list).and_then(|tags| {
            tags.iter()
                .filter_map(Node::as_str)
                .find(|tag| valid_technique_tag(tag))
                .map(|tag| tag.trim_start_matches("attack.").to_uppercase())
        }),
        matches: Match {
            subject: Some(crate::fields::Subject::Process),
            all: predicates,
            any: Vec::new(),
        },
        why: why.to_owned(),
        benign: benign.clone(),
        remediation: "Read the rule's description, then look at the process this finding names \
                      before deciding anything."
            .to_owned(),
    });
    Ok(import)
}

/// The one selection a condition names, when it names exactly one.
fn single_selection(condition: &str) -> Option<String> {
    let trimmed = condition.trim();
    let lower = trimmed.to_lowercase();
    if trimmed.is_empty()
        || lower.contains(" and ")
        || lower.contains(" or ")
        || lower.contains("not ")
        || lower.contains('(')
        || trimmed.contains('|')
    {
        return None;
    }
    for prefix in ["1 of ", "all of "] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return Some(rest.trim().trim_end_matches('*').to_owned());
        }
    }
    Some(lower)
}

fn false_positives(node: &Node) -> Option<String> {
    let list = node.get("falsepositives")?.as_list()?;
    let text: Vec<&str> = list
        .iter()
        .filter_map(Node::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty() && !text.eq_ignore_ascii_case("unknown"))
        .collect();
    if text.is_empty() {
        return None;
    }
    Some(format!("The rule's author lists: {}.", text.join("; ")))
}

fn severity(level: Option<&str>) -> Severity {
    match level.map(str::trim).map(str::to_lowercase).as_deref() {
        // `critical` and `high` are an author's reading of consequence, and a pack's ceiling
        // is `attention`: ranger does not let a file claim more than a fact it observed.
        Some("critical" | "high") => Severity::Attention,
        Some("medium") => Severity::Notice,
        _ => Severity::Info,
    }
}

/// Turn `field|modifier` into a pack predicate, or say what about it does not map.
fn predicate(key: &str, value: &Node) -> Result<Predicate, String> {
    let (field, modifiers) = key.split_once('|').unwrap_or((key, ""));
    let Some((_, mapped)) = FIELDS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(field.trim()))
    else {
        return Err(format!(
            "`{}` is not a field this machine collects; ranger imports Image, CommandLine and User",
            field.trim()
        ));
    };
    let Some(text) = value.as_str() else {
        return Err(format!(
            "`{key}` holds a list, and a list needs `1 of` in the condition, which this importer does not map"
        ));
    };
    let modifiers: Vec<&str> = modifiers
        .split('|')
        .map(str::trim)
        .filter(|modifier| !modifier.is_empty())
        .collect();
    let operator = match modifiers.as_slice() {
        [] => crate::pack::Operator::Eq,
        [one] => match one.to_lowercase().as_str() {
            "contains" => crate::pack::Operator::Contains,
            "startswith" => crate::pack::Operator::Prefix,
            "endswith" => crate::pack::Operator::Suffix,
            "re" => {
                return Err(
                    "`|re` is a regular expression, and the vocabulary of a pack is closed: no \
                     regular expressions, by design"
                        .to_owned(),
                );
            }
            other => {
                return Err(format!(
                    "`|{other}` is not a modifier ranger maps; use contains, startswith or endswith"
                ));
            }
        },
        more => {
            return Err(format!(
                "`{}` combines modifiers, and a pack predicate holds one",
                more.join("|")
            ));
        }
    };
    Ok(Predicate {
        field: (*mapped).to_owned(),
        operator,
        value: Some(serde_json::Value::String(text.to_owned())),
    })
}

fn valid_technique_tag(tag: &str) -> bool {
    let Some(rest) = tag
        .trim()
        .to_lowercase()
        .strip_prefix("attack.t")
        .map(str::to_owned)
    else {
        return false;
    };
    rest.chars()
        .all(|character| character.is_ascii_digit() || character == '.')
        && !rest.is_empty()
}

/// A stable rule id derived from the title, with a counter for a second rule of one name.
fn rule_id(title: &str, index: usize) -> String {
    let mut slug = String::with_capacity(title.len());
    for character in title.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "unnamed" } else { slug };
    let mut id = format!("sigma.{slug}");
    if index > 0 {
        id.push_str(&format!("-{}", index.saturating_add(1)));
    }
    if valid_id(&id) {
        id
    } else {
        format!("sigma.rule-{}", index.saturating_add(1))
    }
}

/// The schema the written pack declares, so the importer and the reader agree.
#[must_use]
pub fn schema() -> u32 {
    SCHEMA
}

#[cfg(test)]
mod tests;
