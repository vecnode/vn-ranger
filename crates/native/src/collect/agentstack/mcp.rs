//! MCP client configurations.
//!
//! An MCP client's configuration lists servers, and a server entry is a command: the client
//! starts that program when it starts, and the model talks to it. That is the same shape as
//! a startup entry, in a file that a person edits by hand and the client trusts.
//!
//! The paths below are the ones the clients themselves document. A file that is not there
//! contributes nothing; the collector's status says which files it looked for, so "no MCP
//! server" and "no MCP client" stay distinguishable.

use std::path::{Path, PathBuf};

use vnr_core::AgentFact;

/// The configuration files an MCP client is known to read.
#[must_use]
pub fn candidates(home: &Path) -> Vec<PathBuf> {
    let mut paths = vec![
        home.join(".cursor").join("mcp.json"),
        home.join(".config")
            .join("claude")
            .join("claude_desktop_config.json"),
    ];
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let appdata = PathBuf::from(appdata);
        paths.push(appdata.join("Claude").join("claude_desktop_config.json"));
        paths.push(appdata.join("Code").join("User").join("mcp.json"));
    }
    paths
}

/// One server entry per fact, with the command it names.
#[must_use]
pub fn read(path: &str, text: &str) -> Vec<AgentFact> {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        // A configuration that is not JSON is not a configuration this build can read, and
        // guessing at half of it would invent a fact.
        return Vec::new();
    };
    let Some(servers) = document.get("mcpServers").and_then(|value| value.as_object()) else {
        return Vec::new();
    };
    let mut facts = Vec::new();
    for (name, server) in servers {
        let command = server
            .get("command")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        let arguments: Vec<&str> = server
            .get("args")
            .and_then(|value| value.as_array())
            .map(|arguments| arguments.iter().filter_map(|value| value.as_str()).collect())
            .unwrap_or_default();
        let line = match (&command, arguments.is_empty()) {
            (Some(command), false) => Some(format!("{command} {}", arguments.join(" "))),
            (Some(command), true) => Some(command.clone()),
            // A server with a URL rather than a command starts nothing locally.
            (None, _) => None,
        };
        facts.push(AgentFact {
            id: format!("mcp:{name}"),
            tool: "mcp".to_owned(),
            name: name.clone(),
            path: path.to_owned(),
            command: line,
            capabilities: Vec::new(),
            hash: None,
        });
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape a client writes. Constructed rather than captured: there is no MCP client
    /// configuration on the machine this was written on, which is the capture the module's
    /// absent file represents.
    const CONFIGURATION: &str = r#"{
      "mcpServers": {
        "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
        "remote": { "url": "https://example.invalid/mcp" }
      }
    }"#;

    #[test]
    fn a_server_with_a_command_is_a_fact_and_one_with_a_url_is_only_listed() {
        let facts = read("/home/user/.cursor/mcp.json", CONFIGURATION);
        assert_eq!(facts.len(), 2);
        let filesystem = facts.iter().find(|fact| fact.name == "filesystem").unwrap();
        assert_eq!(filesystem.tool, "mcp");
        assert_eq!(
            filesystem.command.as_deref(),
            Some("npx -y @modelcontextprotocol/server-filesystem /tmp")
        );
        let remote = facts.iter().find(|fact| fact.name == "remote").unwrap();
        assert_eq!(remote.command, None, "a URL starts nothing locally");
        assert_eq!(
            filesystem.path, "/home/user/.cursor/mcp.json",
            "the fact names the file it came from"
        );
        assert_eq!(filesystem.id, "mcp:filesystem");
    }

    #[test]
    fn a_file_that_is_not_a_server_list_produces_nothing() {
        assert!(read("p", "not json").is_empty());
        assert!(read("p", "{\"other\": 1}").is_empty());
        assert!(read("p", "{\"mcpServers\": []}").is_empty());
    }

    #[test]
    fn the_candidate_paths_are_the_ones_the_clients_document() {
        let paths = candidates(Path::new("/home/user"));
        let rendered: Vec<String> = paths.iter().map(|path| path.display().to_string()).collect();
        assert!(
            rendered
                .iter()
                .any(|path| path.ends_with(".cursor/mcp.json") || path.ends_with(".cursor\\mcp.json"))
        );
        assert!(rendered.iter().any(|path| path.contains("claude")));
        assert!(!rendered.iter().any(|path| path.contains("known_hosts")));
    }
}
