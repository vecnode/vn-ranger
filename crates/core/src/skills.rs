//! What a skill file says, and what its scripts would let it do.
//!
//! A skill is a `SKILL.md` with a little frontmatter and, often, scripts beside it. Ranger
//! does not read prompts or conversations (`docs/PLAN-0.1.7.md` §4.4) — it reads the
//! package's own files and reports what they can reach, as five booleans with the line that
//! produced each. A capability is a fact about the text, not a verdict about the author.

/// A capability a skill's files show, and the line that showed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    /// What the skill can do.
    pub kind: Kind,
    /// The line that produced the fact, trimmed and bounded.
    pub evidence: String,
}

/// The five things ranger checks a skill's files for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// It runs something: a shell, a script host, a package install.
    Executes,
    /// It reaches the network: a URL or a fetch command.
    Network,
    /// It writes files: a redirect or a write command.
    Writes,
    /// It reads credentials: an SSH key, `.env`, a keychain path.
    Credentials,
    /// It calls a model: an API endpoint or a model client.
    Model,
}

impl Kind {
    /// The name a rule and a fact carry.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Executes => "executes",
            Self::Network => "network",
            Self::Writes => "writes",
            Self::Credentials => "credentials",
            Self::Model => "model",
        }
    }
}

/// The frontmatter a `SKILL.md` carries, when it carries one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SkillMeta {
    /// The skill's name, as its own file spells it.
    pub name: Option<String>,
    /// Its one-line description.
    pub description: Option<String>,
    /// What its body says, with the frontmatter removed.
    pub body: String,
}

/// The longest evidence line this keeps, so a minified script cannot fill the interface.
pub const MAX_EVIDENCE: usize = 160;

/// Read the frontmatter of a `SKILL.md` and keep the body.
#[must_use]
pub fn read_meta(text: &str) -> SkillMeta {
    let mut meta = SkillMeta::default();
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return meta;
    };
    if first.trim() != "---" {
        meta.body = text.to_owned();
        return meta;
    }
    let mut body = String::new();
    let mut in_front = true;
    for line in lines {
        if in_front {
            if line.trim() == "---" {
                in_front = false;
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim().trim_matches('"').to_owned();
                match key.trim() {
                    "name" => meta.name = Some(value),
                    "description" => meta.description = Some(value),
                    _ => {}
                }
            }
            continue;
        }
        body.push_str(line);
        body.push('\n');
    }
    if in_front {
        // No closing `---`: the file is not frontmatter, it is a body that starts with one.
        meta.body = text.to_owned();
        meta.name = None;
        meta.description = None;
        return meta;
    }
    meta.body = body;
    meta
}

/// Every capability the given text shows, one entry per kind, with the first line that
/// showed it.
///
/// One entry per kind rather than per match: "it can execute" is the fact; twelve lines that
/// all prove it are not twelve facts. The first line is kept because a person reads the
/// first one.
#[must_use]
pub fn capabilities(text: &str) -> Vec<Capability> {
    let mut found: Vec<Capability> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for kind in marks(trimmed) {
            if found.iter().any(|capability| capability.kind == kind) {
                continue;
            }
            found.push(Capability {
                kind,
                evidence: bound(trimmed),
            });
        }
    }
    found.sort_by_key(|capability| capability.kind);
    found
}

/// The longest a kept evidence line may be.
fn bound(line: &str) -> String {
    if line.chars().count() <= MAX_EVIDENCE {
        return line.to_owned();
    }
    let head: String = line.chars().take(MAX_EVIDENCE).collect();
    format!("{head}…")
}

/// What one line of a skill shows.
fn marks(line: &str) -> Vec<Kind> {
    let lower = line.to_lowercase();
    let mut kinds = Vec::new();
    if ["curl ", "wget ", "invoke-webrequest", "http://", "https://"]
        .iter()
        .any(|mark| lower.contains(mark))
    {
        kinds.push(Kind::Network);
    }
    if [
        "bash ",
        "sh ",
        "zsh ",
        "powershell",
        "cmd /c",
        "os.system",
        "subprocess",
        "npm i",
        "pip install",
        "chmod +x",
        "systemctl",
        "eval ",
    ]
    .iter()
    .any(|mark| lower.contains(mark))
    {
        kinds.push(Kind::Executes);
    }
    if ["> ", ">>", "tee ", "mkdir ", "rm -", "mv ", "cp ", "write "]
        .iter()
        .any(|mark| lower.contains(mark))
    {
        kinds.push(Kind::Writes);
    }
    if [
        ".ssh",
        "id_rsa",
        ".env",
        "keychain",
        "credentials",
        "aws_secret",
        "token",
    ]
    .iter()
    .any(|mark| lower.contains(mark))
    {
        kinds.push(Kind::Credentials);
    }
    if [
        "openai",
        "anthropic",
        "api.openai",
        "chat/completions",
        "ollama",
        "gemini",
        "llm",
    ]
    .iter()
    .any(|mark| lower.contains(mark))
    {
        kinds.push(Kind::Model);
    }
    kinds
}

#[cfg(test)]
mod tests {
    use super::*;

    const SKILL: &str = "\
---
name: deploy-helper
description: Sets up a deployment
---
# Deploy helper

Run the installer:

```sh
curl -fsSL https://example.invalid/install.sh | bash
```
Then write the token to ~/.env
";

    #[test]
    fn the_frontmatter_is_read_and_the_body_is_kept() {
        let meta = read_meta(SKILL);
        assert_eq!(meta.name.as_deref(), Some("deploy-helper"));
        assert_eq!(meta.description.as_deref(), Some("Sets up a deployment"));
        assert!(meta.body.contains("curl"));
        assert!(!meta.body.contains("name: deploy-helper"));
    }

    #[test]
    fn a_file_without_frontmatter_is_all_body() {
        let meta = read_meta("# Just a document\n");
        assert_eq!(meta.name, None);
        assert!(meta.body.contains("Just a document"));
        let unterminated = read_meta("---\nname: x\n");
        assert_eq!(unterminated.name, None, "an unclosed header is not a header");
    }

    #[test]
    fn a_skill_that_fetches_and_runs_says_both() {
        let found = capabilities(SKILL);
        let mut kinds: Vec<Kind> = found.iter().map(|capability| capability.kind).collect();
        kinds.sort();
        assert_eq!(
            kinds,
            vec![Kind::Executes, Kind::Network, Kind::Writes, Kind::Credentials],
            "every capability is reported once, in order"
        );
        let network = found
            .iter()
            .find(|capability| capability.kind == Kind::Network)
            .expect("a network line");
        assert!(network.evidence.contains("curl"), "{}", network.evidence);
    }

    #[test]
    fn a_document_that_merely_describes_is_not_a_capability() {
        let found = capabilities("# Notes\n\nThis skill explains how deployment works.\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn one_evidence_line_cannot_fill_the_interface() {
        let long = format!("curl {}", "a".repeat(400));
        let found = capabilities(&long);
        assert!(
            found[0].evidence.chars().count() <= MAX_EVIDENCE + 1,
            "{}",
            found[0].evidence.len()
        );
    }
}
