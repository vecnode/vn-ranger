//! Configurations that can run something on a person's behalf.
//!
//! An editor task, an agent client's server list and an SSH key with a forced command are
//! one fact in three costumes: **a file the person trusts names a program, and the program
//! runs without a click.** None of them is a verdict — a forced command and an MCP server
//! are both ordinary things to have — so this collector says what the file is, where it is,
//! and what it would run, and leaves the judgement to a rule (`docs/PLAN.md` §9, wave 5).
//!
//! **Only the files listed here are read**, and every one of them is a configuration the
//! person could open themselves:
//!
//! | Surface | What is one fact |
//! |---|---|
//! | `~/.ssh/authorized_keys` | a line with a forced `command=`, or with `environment=` |
//! | `~/.ssh/rc` | the script itself: it runs on every login through that key |
//! | `~/.ssh/config` | a `ProxyCommand`, `LocalCommand` or `Match exec` that names a command |
//! | an MCP client's configuration | one server entry, with its command |
//!
//! Nothing here reads a private key, a known-hosts file, or anything under a browser
//! profile. A file that is not there contributes nothing, and the status line says which
//! files were looked for, so "none" is distinguishable from "not looked".

pub mod mcp;
pub mod ssh;

use std::path::PathBuf;

use vnr_core::AgentFact;

use super::Outcome;

/// The collector's id and label, in one place.
pub const ID: &str = "agentstack";
/// What the interface calls it.
pub const LABEL: &str = "Agent and editor configurations";

/// A configuration file this collector tried to read, and what came of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Looked {
    /// The file.
    pub path: String,
    /// How many facts it produced, or that it was not there.
    pub found: Option<usize>,
}

/// Read every configuration this build knows how to read.
#[must_use]
pub fn collect() -> Outcome<AgentFact> {
    let Some(home) = home_dir() else {
        return Outcome::Unavailable {
            reason: "There is no home directory to read a configuration from, so no agent or \
                     editor configuration was read."
                .to_owned(),
        };
    };
    let mut items = Vec::new();
    let mut looked: Vec<Looked> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();

    // SSH: the files that let a machine run something when someone signs in through it.
    for file in ["authorized_keys", "rc", "config"] {
        let path = home.join(".ssh").join(file);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let facts = ssh::read(file, &path.to_string_lossy(), &text);
                looked.push(Looked {
                    path: path.display().to_string(),
                    found: Some(facts.len()),
                });
                items.extend(facts);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => looked.push(Looked {
                path: path.display().to_string(),
                found: None,
            }),
            Err(error) => unreadable.push(format!("{}: {error}", path.display())),
        }
    }

    // MCP clients, in the places their own documentation puts the file.
    for path in mcp::candidates(&home) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let facts = mcp::read(&path.to_string_lossy(), &text);
        looked.push(Looked {
            path: path.display().to_string(),
            found: Some(facts.len()),
        });
        items.extend(facts);
    }

    let read: Vec<&str> = looked
        .iter()
        .filter(|entry| entry.found.is_some())
        .map(|entry| entry.path.as_str())
        .collect();
    let absent: usize = looked.iter().filter(|entry| entry.found.is_none()).count();
    let mut reasons: Vec<String> = Vec::new();
    if !unreadable.is_empty() {
        reasons.push(format!(
            "{} configuration file(s) could not be read: {}",
            unreadable.len(),
            unreadable.join("; ")
        ));
    }
    reasons.push(format!(
        "{} file(s) were read ({}), {} were not there, and a configuration is a fact rather \
         than a verdict. Editor tasks and package-manager hooks are not read in this build.",
        read.len(),
        if read.is_empty() {
            "no configuration in this home directory".to_owned()
        } else {
            read.join(", ")
        },
        absent
    ));
    if reasons.is_empty() {
        Outcome::Items(items)
    } else {
        Outcome::Partial {
            items,
            reason: reasons.join(" "),
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_home_directory_with_no_configurations_produces_nothing_and_says_what_it_looked_for() {
        // The collector reads the real home directory, so this test asserts the shape of the
        // answer rather than its contents: a fact list and a status that names the files.
        let (facts, status) = collect().into_parts(ID, LABEL);
        assert!(facts.len() < 100_000, "a plausible number of facts");
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("file(s) were read")),
            "{:?}",
            status.reason
        );
        assert_eq!(status.state, vnr_core::CollectorState::Partial);
    }
}
