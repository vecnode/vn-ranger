//! A YAML reader for Sigma rules, and nothing else.
//!
//! A Sigma rule is YAML written by someone else, which makes it user input, which makes it
//! the one format in this tree that could ask a parser to do something surprising. The
//! answer is not a YAML library: it is a reader for the subset a Sigma rule actually uses —
//! mappings, lists, scalars — and an outright refusal of the features whose only purpose is
//! to make a small file mean something large (`docs/PLAN.md` §6.11, `docs/RULES.md`).
//!
//! Refused, by name: anchors (`&a`), aliases (`*a`), tags (`!t`), multi-document files
//! (`---`, `...`), and tabs for indentation. Each is a way to have the file mean something
//! other than what a person reading it would think, and a rule that a person cannot read is
//! not a rule they can trust.

use std::fmt;

/// One value in a restricted YAML document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// A scalar, kept as text: nothing here needs to know that `1` is a number.
    Scalar(String),
    /// A list, in the order the file wrote it.
    List(Vec<Node>),
    /// A mapping, in the order the file wrote it.
    Map(Vec<(String, Node)>),
}

impl Node {
    /// The scalar's text, when this is a scalar.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Scalar(text) => Some(text),
            _ => None,
        }
    }

    /// The entry with this key, when this is a mapping.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Self::Map(entries) => entries
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, node)| node),
            _ => None,
        }
    }

    /// The items, when this is a list.
    #[must_use]
    pub fn as_list(&self) -> Option<&[Node]> {
        match self {
            Self::List(items) => Some(items),
            _ => None,
        }
    }

    /// The entries, when this is a mapping.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(String, Node)]> {
        match self {
            Self::Map(entries) => Some(entries),
            _ => None,
        }
    }
}

/// Why a document could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The 1-based line, when the reader could find it.
    pub line: usize,
    /// What is wrong, in a sentence a person can act on.
    pub problem: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}: {}", self.line, self.problem)
    }
}

/// One line of the document, with what the reader needs to know about it.
#[derive(Clone)]
struct Line {
    number: usize,
    indent: usize,
    text: String,
}

/// Read a restricted YAML document into one node.
///
/// The document is expected to be a mapping at the top level, which is what a Sigma rule is.
pub fn parse(text: &str) -> Result<Node, Refusal> {
    let lines = split(text)?;
    if lines.is_empty() {
        return Err(Refusal {
            line: 1,
            problem: "the file is empty".to_owned(),
        });
    }
    let mut cursor = 0;
    let base = lines[0].indent;
    let node = block(&lines, &mut cursor, base)?;
    if cursor < lines.len() {
        return Err(Refusal {
            line: lines[cursor].number,
            problem: "this line is indented under nothing".to_owned(),
        });
    }
    Ok(node)
}

/// Split and screen the document: this is where the refusals live.
fn split(text: &str) -> Result<Vec<Line>, Refusal> {
    let mut lines = Vec::new();
    let mut documents: u32 = 0;
    for (index, raw) in text.lines().enumerate() {
        let number = index.saturating_add(1);
        if raw.contains('\t') {
            return Err(Refusal {
                line: number,
                problem: "a tab is used for indentation; YAML wants spaces".to_owned(),
            });
        }
        let without_comment = strip_comment(raw);
        let trimmed = without_comment.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        let content = trimmed.trim_start();
        if content == "---" || content == "..." {
            documents = documents.saturating_add(1);
            if documents > 1 || index > 0 {
                return Err(Refusal {
                    line: number,
                    problem: "a multi-document file is refused: ranger reads one rule per file".to_owned(),
                });
            }
            continue;
        }
        if let Some(problem) = forbidden(content) {
            return Err(Refusal {
                line: number,
                problem,
            });
        }
        lines.push(Line {
            number,
            indent: trimmed.len().saturating_sub(content.len()),
            text: content.to_owned(),
        });
    }
    Ok(lines)
}

/// The features whose whole purpose is to make the file mean something else.
fn forbidden(content: &str) -> Option<String> {
    let value = content
        .split_once(':')
        .map_or(content, |(_, rest)| rest.trim_start());
    for (marker, what) in [
        ('&', "an anchor (`&name`)"),
        ('*', "an alias (`*name`)"),
        ('!', "a tag (`!!binary`)"),
    ] {
        if value.starts_with(marker) {
            return Some(format!(
                "{what} is refused: a rule a person cannot read is one they cannot check"
            ));
        }
    }
    None
}

fn strip_comment(line: &str) -> &str {
    // A `#` starts a comment at the beginning of a line or after whitespace. A `#` inside a
    // quoted string is text, and Sigma regexes contain them, so quotes are honoured.
    let mut quote: Option<char> = None;
    let mut previous = ' ';
    for (index, character) in line.char_indices() {
        match character {
            '\'' | '"' if quote.is_none() => quote = Some(character),
            '\'' | '"' if quote == Some(character) => quote = None,
            '#' if quote.is_none() && previous.is_whitespace() => return &line[..index],
            _ => {}
        }
        previous = character;
    }
    line
}

/// Read one block at this indentation.
fn block(lines: &[Line], cursor: &mut usize, indent: usize) -> Result<Node, Refusal> {
    if lines[*cursor].text.starts_with("- ") || lines[*cursor].text == "-" {
        return list(lines, cursor, indent);
    }
    mapping(lines, cursor, indent)
}

fn mapping(lines: &[Line], cursor: &mut usize, indent: usize) -> Result<Node, Refusal> {
    let mut entries: Vec<(String, Node)> = Vec::new();
    while *cursor < lines.len() && lines[*cursor].indent == indent {
        let line = &lines[*cursor];
        if line.text.starts_with("- ") || line.text == "-" {
            return Err(Refusal {
                line: line.number,
                problem: "a list item starts inside a mapping".to_owned(),
            });
        }
        let Some((key, rest)) = line.text.split_once(':') else {
            return Err(Refusal {
                line: line.number,
                problem: "this line is not `key: value`".to_owned(),
            });
        };
        let key = unquote(key.trim());
        if key.is_empty() {
            return Err(Refusal {
                line: line.number,
                problem: "a key is empty".to_owned(),
            });
        }
        let value = rest.trim();
        let number = line.number;
        *cursor += 1;
        let node = if value.is_empty() {
            if *cursor < lines.len() && lines[*cursor].indent > indent {
                let inner = lines[*cursor].indent;
                block(lines, cursor, inner)?
            } else {
                Node::Scalar(String::new())
            }
        } else {
            Node::Scalar(unquote(value))
        };
        if entries.iter().any(|(existing, _)| *existing == key) {
            return Err(Refusal {
                line: number,
                problem: format!("`{key}` appears twice in one block"),
            });
        }
        entries.push((key, node));
    }
    if *cursor < lines.len() && lines[*cursor].indent > indent {
        return Err(Refusal {
            line: lines[*cursor].number,
            problem: "this line is indented further than the key above it".to_owned(),
        });
    }
    Ok(Node::Map(entries))
}

fn list(lines: &[Line], cursor: &mut usize, indent: usize) -> Result<Node, Refusal> {
    let mut items = Vec::new();
    while *cursor < lines.len() && lines[*cursor].indent == indent {
        let line = &lines[*cursor];
        let Some(rest) = line.text.strip_prefix("- ") else {
            if line.text == "-" {
                *cursor += 1;
                items.push(Node::Scalar(String::new()));
                continue;
            }
            break;
        };
        let number = line.number;
        // `- key: value` is a mapping item: the dash is punctuation, and the item's lines are
        // indented past it. Anything else is a scalar, which is the common case in a Sigma
        // list of false positives or tags.
        let is_mapping = !quoted(rest)
            && rest
                .split_once(':')
                .is_some_and(|(key, _)| !key.trim().is_empty());
        if !is_mapping {
            items.push(Node::Scalar(unquote(rest)));
            *cursor += 1;
            continue;
        }
        let item_indent = indent.saturating_add(2);
        let mut rewritten = vec![Line {
            number,
            indent: item_indent,
            text: rest.to_owned(),
        }];
        *cursor += 1;
        while *cursor < lines.len() && lines[*cursor].indent >= item_indent {
            rewritten.push(lines[*cursor].clone());
            *cursor += 1;
        }
        let mut inner = 0;
        let node = block(&rewritten, &mut inner, item_indent)?;
        items.push(node);
    }
    Ok(Node::List(items))
}

/// Whether a scalar is quoted, in which case a `:` inside it is punctuation in the text.
fn quoted(text: &str) -> bool {
    let text = text.trim();
    ['"', '\'']
        .iter()
        .any(|quote| text.len() >= 2 && text.starts_with(*quote) && text.ends_with(*quote))
}

fn unquote(text: &str) -> String {
    let text = text.trim();
    for quote in ['"', '\''] {
        if text.len() >= 2 && text.starts_with(quote) && text.ends_with(quote) {
            return text[1..text.len() - 1].to_owned();
        }
    }
    text.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sigma_shaped_document_reads_as_a_mapping() {
        let text = "\
title: Suspicious PowerShell
id: 1234
description: A PowerShell process with an encoded command.
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
falsepositives:
  - Admin scripts
";
        let node = parse(text).unwrap();
        assert_eq!(
            node.get("title").and_then(Node::as_str),
            Some("Suspicious PowerShell")
        );
        let detection = node.get("detection").unwrap();
        let selection = detection.get("selection").unwrap();
        assert_eq!(
            selection.get("Image|endswith").and_then(Node::as_str),
            Some("\\powershell.exe")
        );
        assert_eq!(
            detection.get("condition").and_then(Node::as_str),
            Some("selection")
        );
        let positives = node.get("falsepositives").unwrap().as_list().unwrap();
        assert_eq!(positives.len(), 1);
        assert_eq!(positives[0].as_str(), Some("Admin scripts"));
    }

    #[test]
    fn a_list_of_mappings_reads_in_order() {
        let node = parse("items:\n  - name: a\n    value: 1\n  - name: b\n").unwrap();
        let items = node.get("items").unwrap().as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].get("name").and_then(Node::as_str), Some("a"));
        assert_eq!(items[1].get("name").and_then(Node::as_str), Some("b"));
    }

    #[test]
    fn an_anchor_an_alias_a_tag_and_a_second_document_are_refused_by_line() {
        for (text, expected) in [
            ("title: &a x\n", "anchor"),
            ("title: *a\n", "alias"),
            ("title: !!binary x\n", "tag"),
            ("---\ntitle: a\n---\ntitle: b\n", "multi-document"),
            ("title: a\nthe: b\n", ""),
        ] {
            match (parse(text), expected) {
                (Err(refusal), what) if !what.is_empty() => {
                    assert!(
                        refusal.problem.contains(what),
                        "{:?} does not mention {what}: {}",
                        text,
                        refusal.problem
                    );
                    assert!(refusal.line >= 1);
                }
                (Ok(node), _) => assert!(node.get("title").is_some()),
                (other, expected) => panic!("{text:?} gave {other:?}, wanted {expected:?}"),
            }
        }
    }

    #[test]
    fn a_tab_and_a_duplicate_key_are_refused() {
        assert!(parse("title: a\n\tkey: b\n").unwrap_err().problem.contains("tab"));
        let duplicate = parse("title: a\ntitle: b\n").unwrap_err();
        assert!(duplicate.problem.contains("twice"), "{}", duplicate.problem);
    }

    #[test]
    fn a_comment_is_not_a_value_and_a_hash_inside_quotes_is_text() {
        let node = parse("title: a # the title\ncommand: 'a # b'\n").unwrap();
        assert_eq!(node.get("title").and_then(Node::as_str), Some("a"));
        assert_eq!(node.get("command").and_then(Node::as_str), Some("a # b"));
    }

    #[test]
    fn an_empty_file_says_so_rather_than_producing_nothing() {
        assert!(parse("").is_err());
        assert!(parse("\n\n").is_err());
    }
}
