//! The three SSH files that can run something without a click.
//!
//! `authorized_keys` is where a key's forced command lives: a line may say that the key can
//! run exactly one program, which is both good practice and a persistence mechanism. `rc`
//! is a script that runs when a session opens through that machine. `config` is the client
//! side: `ProxyCommand`, `LocalCommand` and `Match exec` all name programs to run.
//!
//! A private key is never read. Each reader takes the file's text and returns facts, so a
//! fixture stands in for the file on any host.

use vnr_core::AgentFact;

/// Read one SSH file by name.
#[must_use]
pub fn read(file: &str, path: &str, text: &str) -> Vec<AgentFact> {
    match file {
        "authorized_keys" => authorized_keys(path, text),
        "rc" => rc(path, text),
        "config" => config(path, text),
        _ => Vec::new(),
    }
}

/// The directives in a client configuration that name a program to run.
const RUNS_A_COMMAND: [&str; 3] = ["proxycommand", "localcommand", "matchexec"];

/// Each line of `authorized_keys` that constrains the key with an option.
///
/// A plain key is a fact about who can sign in; an option is a fact about what happens when
/// they do. Only lines with `command=` or `environment=` are reported, because a key with
/// neither cannot start a program by itself.
#[must_use]
pub fn authorized_keys(path: &str, text: &str) -> Vec<AgentFact> {
    let mut facts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let options = options_of(line);
        let command = option_value(&options, "command");
        let environment = option_value(&options, "environment");
        if command.is_none() && environment.is_none() {
            continue;
        }
        let comment = key_comment(line);
        let name = match &comment {
            Some(comment) => format!("key {comment}"),
            None => format!("key on line {}", index.saturating_add(1)),
        };
        facts.push(AgentFact {
            id: format!("ssh:authorized_keys:{index}"),
            tool: "ssh".to_owned(),
            name,
            path: path.to_owned(),
            command: command
                .clone()
                .or_else(|| environment.map(|environment| format!("environment: {environment}"))),
            capabilities: Vec::new(),
            hash: None,
        });
    }
    facts
}

/// The `rc` file is one fact: it runs whenever a session opens.
#[must_use]
pub fn rc(path: &str, text: &str) -> Vec<AgentFact> {
    let body = text.trim();
    if body.is_empty() {
        return Vec::new();
    }
    let lines = body.lines().filter(|line| !line.trim().is_empty()).count();
    vec![AgentFact {
        id: "ssh:rc".to_owned(),
        tool: "ssh".to_owned(),
        name: "rc file".to_owned(),
        path: path.to_owned(),
        command: Some(format!("runs when a session opens ({lines} line(s))")),
        capabilities: Vec::new(),
        hash: None,
    }]
}

/// The client configuration, for the directives that run a program.
#[must_use]
pub fn config(path: &str, text: &str) -> Vec<AgentFact> {
    let mut facts = Vec::new();
    let mut host = String::from("(before any Host line)");
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let written = parts.next().unwrap_or_default();
        let directive = written.to_ascii_lowercase();
        let value = parts.next().unwrap_or_default().trim();
        if directive == "host" {
            host = value.to_owned();
            continue;
        }
        let compacts: String = directive.chars().filter(|c| *c != '-').collect();
        let runs = RUNS_A_COMMAND
            .iter()
            .any(|wanted| *wanted == compacts || *wanted == format!("{compacts}="));
        if !runs || value.is_empty() {
            continue;
        }
        facts.push(AgentFact {
            id: format!("ssh:config:{index}"),
            tool: "ssh".to_owned(),
            name: format!("{written} for {host}"),
            path: path.to_owned(),
            command: Some(value.to_owned()),
            capabilities: Vec::new(),
            hash: None,
        });
    }
    facts
}

/// The option list in front of the key type.
///
/// Options are comma-separated, may be quoted, and some of them (`no-port-forwarding`) have
/// no value at all — so a token without an `=` is an option rather than the end of the list.
/// The list ends at the key type.
fn options_of(line: &str) -> Vec<(String, Option<String>)> {
    let mut options = Vec::new();
    let mut rest = line.trim();
    while let Some((head, tail)) = split_top_level(rest) {
        let token = head.trim();
        if token.is_empty() || is_key_type(token) {
            break;
        }
        match token.split_once('=') {
            Some((name, value)) => options.push((
                name.trim().to_ascii_lowercase(),
                Some(value.trim().trim_matches('"').to_owned()),
            )),
            None => options.push((token.to_ascii_lowercase(), None)),
        }
        rest = tail.trim_start();
        if rest.is_empty() {
            break;
        }
    }
    options
}

/// Whether a token is the type of a key, which is where the option list ends.
fn is_key_type(token: &str) -> bool {
    ["ssh-", "ecdsa-", "sk-", "rsa-", "dsa-"]
        .iter()
        .any(|prefix| token.starts_with(prefix))
}

/// Split the first comma- or space-separated token off, honouring double quotes.
fn split_top_level(text: &str) -> Option<(&str, &str)> {
    let mut inside = false;
    for (index, character) in text.char_indices() {
        match character {
            '"' => inside = !inside,
            ',' | ' ' if !inside => return Some((&text[..index], &text[index + 1..])),
            _ => {}
        }
    }
    if text.is_empty() { None } else { Some((text, "")) }
}

fn option_value(options: &[(String, Option<String>)], wanted: &str) -> Option<String> {
    options
        .iter()
        .find(|(name, _)| name == wanted)
        .and_then(|(_, value)| value.clone())
}

/// The comment after the key body, which is how a person recognises their own key.
fn key_comment(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words.iter().position(|word| is_key_type(word))?;
    // The type, then the base64 body, then whatever the person wrote.
    let comment = words.get(at.saturating_add(2)..)?.join(" ");
    if comment.trim().is_empty() {
        None
    } else {
        Some(comment.trim().to_owned())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_with_a_forced_command_is_a_fact_naming_the_command() {
        let facts = authorized_keys(
            "/home/user/.ssh/authorized_keys",
            "command=\"/usr/local/bin/backup --once\" ssh-ed25519 AAAAC3Nza laptop\n",
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].tool, "ssh");
        assert_eq!(facts[0].command.as_deref(), Some("/usr/local/bin/backup --once"));
        assert_eq!(facts[0].name, "key laptop");
        assert_eq!(facts[0].id, "ssh:authorized_keys:0");
    }

    #[test]
    fn a_plain_key_is_not_this_collectors_business() {
        let facts = authorized_keys(
            "/home/user/.ssh/authorized_keys",
            "ssh-ed25519 AAAAC3Nza laptop\n# a comment\n\n",
        );
        assert!(facts.is_empty(), "a key with no option cannot start a program");
    }

    #[test]
    fn several_options_are_read_and_the_key_comment_still_lands_on_the_end() {
        let facts = authorized_keys(
            "/home/user/.ssh/authorized_keys",
            "no-port-forwarding,command=\"sh -c 'id'\",environment=\"A=b\" ssh-rsa AAAAB3 work\n",
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].command.as_deref(), Some("sh -c 'id'"));
        assert_eq!(facts[0].name, "key work");
    }

    #[test]
    fn an_environment_only_line_is_reported_as_an_environment() {
        let facts = authorized_keys(
            "/home/user/.ssh/authorized_keys",
            "environment=\"PATH=/tmp/bin\" ssh-ed25519 AAAAC3Nza odd\n",
        );
        assert_eq!(facts.len(), 1);
        assert!(
            facts[0]
                .command
                .as_deref()
                .is_some_and(|command| command.starts_with("environment:")),
            "{:?}",
            facts[0].command
        );
    }

    #[test]
    fn an_rc_file_is_one_fact_that_says_how_much_it_runs() {
        let facts = rc("/home/user/.ssh/rc", "#!/bin/sh\nexport FOO=1\n\n");
        assert_eq!(facts.len(), 1);
        assert!(
            facts[0]
                .command
                .as_deref()
                .is_some_and(|text| text.contains("2 line"))
        );
        assert!(rc("/home/user/.ssh/rc", "  \n\n").is_empty());
    }

    #[test]
    fn a_client_config_reports_only_the_directives_that_run_a_program() {
        // The shape this machine's own configuration has: names and files, no commands.
        let plain = "Host work\n  HostName example.invalid\n  User user\n  IdentityFile ~/.ssh/id\n";
        assert!(config("/home/user/.ssh/config", plain).is_empty());

        let running = "Host jump\n  ProxyCommand ssh -W %h:%p bastion\nHost *\n  LocalCommand echo hi\n";
        let facts = config("/home/user/.ssh/config", running);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].name, "ProxyCommand for jump");
        assert_eq!(facts[0].command.as_deref(), Some("ssh -W %h:%p bastion"));
        assert_eq!(facts[1].name, "LocalCommand for *");
    }
}
