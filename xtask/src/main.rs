//! `cargo xtask` — the checks CI runs, and the two promises a script can enforce.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The profile CI uses: the same code, with dependencies unoptimised so a check is
/// minutes rather than a coffee break.
const CI_PROFILE: &str = "ci";

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "ci".to_owned());
    let result = match command.as_str() {
        "ci" => ci(),
        "fmt-fix" => run(&["fmt", "--all"]),
        "lint" => lint(),
        "test" => test(),
        "check" => run(&["check", "--workspace", "--all-targets", "--profile", CI_PROFILE]),
        "no-network" => no_network(),
        "language" => language(),
        "version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(format!(
            "unknown xtask `{other}`; try ci, fmt-fix, lint, test, check, no-network, language or version"
        )),
    };
    if let Err(error) = result {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}

fn ci() -> Result<(), String> {
    run(&["fmt", "--all", "--check"])?;
    no_network()?;
    language()?;
    lint()?;
    test()
}

fn lint() -> Result<(), String> {
    run(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--profile",
        CI_PROFILE,
        "--",
        "-D",
        "warnings",
    ])
}

/// The tests live in the pure core, the native collectors, the interface's own decisions
/// and these checks. The shell has no tests yet, so it is type-checked rather than linked
/// into an empty test binary; linking wgpu for zero tests is the slowest useful thing CI
/// can do.
fn test() -> Result<(), String> {
    run(&[
        "test",
        "--package",
        "vnr-core",
        "--package",
        "vnr-native",
        "--package",
        "vnr-ui",
        "--package",
        "xtask",
        "--all-targets",
        "--profile",
        CI_PROFILE,
    ])?;
    run(&[
        "check",
        "--package",
        "vn-ranger",
        "--all-targets",
        "--profile",
        CI_PROFILE,
    ])
}

fn run(arguments: &[&str]) -> Result<(), String> {
    let root = workspace_root()?;
    let status = Command::new("cargo")
        .args(arguments)
        .current_dir(&root)
        .status()
        .map_err(|error| format!("could not start cargo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo {} failed", arguments.join(" ")))
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask has no parent directory".to_owned())
}

/// The v0.x promise is that ranger has no network code. A paragraph cannot enforce
/// that; this check can.
fn no_network() -> Result<(), String> {
    let root = workspace_root()?;
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|error| format!("could not read Cargo.lock: {error}"))?;
    let banned = [
        "reqwest",
        "ureq",
        "hyper",
        "h2",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "socket2",
        "openssl",
        "native-tls",
    ];
    let mut problems = Vec::new();
    for line in lock.lines() {
        let Some(name) = line.trim().strip_prefix("name = \"") else {
            continue;
        };
        let Some(name) = name.strip_suffix('"') else {
            continue;
        };
        if banned.contains(&name) {
            problems.push(format!("Cargo.lock contains `{name}`"));
        }
    }
    let mut files = Vec::new();
    walk(&root.join("crates"), &mut files);
    walk(&root.join("apps"), &mut files);
    for file in files {
        if file.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (index, line) in body.lines().enumerate() {
            if line.contains("TcpStream")
                || line.contains("TcpListener")
                || line.contains("UdpSocket")
                || line.contains("socket2::")
            {
                problems.push(format!(
                    "{}:{} looks like network code",
                    file.display(),
                    index + 1
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) == Some("target") {
                continue;
            }
            walk(&path, files);
        } else {
            files.push(path);
        }
    }
}

/// Words the product must not use, each with the sentence that replaces it.
///
/// The table is `docs/PLAN.md` §5.5. This check exists because a language audit done by
/// reading is an audit that stops being done; the words below are the ones that turn a
/// fact into a verdict, and a verdict is what ranger refuses to sell.
const BANNED_WORDS: [(&str, &str); 3] = [
    (
        "fix",
        "quarantine, restore, remove the startup entry, open the folder",
    ),
    ("infected", "an unexplained startup item"),
    ("virus", "a binary that matches a rule"),
];

/// Phrases the product must not use, because they make a claim about a whole machine.
const BANNED_PHRASES: [(&str, &str); 2] = [
    ("pc is clean", "no unexplained startup items in this check"),
    ("threat score", "the findings, with their evidence"),
];

/// The §5.5 language audit, as a check rather than a reading.
///
/// It reads the string literals in the interface and the shell — what a person actually
/// sees — and leaves comments and identifiers alone, because a comment that says "fix a
/// bug" is not a product claim.
fn language() -> Result<(), String> {
    let root = workspace_root()?;
    let mut files = Vec::new();
    walk(&root.join("crates").join("ui").join("src"), &mut files);
    walk(&root.join("apps").join("vn-ranger").join("src"), &mut files);
    let mut problems = Vec::new();
    for file in files {
        if file.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&file) else {
            continue;
        };

        for literal in string_literals(&body) {
            for problem in banned_in(&literal) {
                problems.push(format!(
                    "{}: {} — use {}",
                    file.display(),
                    problem,
                    fix_for(problem.trim_matches('"'))
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        problems.sort();
        problems.dedup();
        Err(format!("the language audit failed:\n{}", problems.join("\n")))
    }
}

/// The replacement sentence for a word or phrase.
fn fix_for(found: &str) -> &'static str {
    for (word, replacement) in BANNED_WORDS {
        if found.eq_ignore_ascii_case(word) {
            return replacement;
        }
    }
    for (phrase, replacement) in BANNED_PHRASES {
        if found.eq_ignore_ascii_case(phrase) {
            return replacement;
        }
    }
    "a fact, not a verdict"
}

/// Every banned word or phrase in one piece of user-facing text.
fn banned_in(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut found = Vec::new();
    for token in lower.split(|character: char| !character.is_alphanumeric()) {
        for (word, _) in BANNED_WORDS {
            if token == word
                || token == format!("{word}s")
                || token == format!("{word}ed")
                || token == format!("{word}ing")
            {
                found.push(format!("\"{token}\""));
            }
        }
    }
    for (phrase, _) in BANNED_PHRASES {
        if lower.contains(phrase) {
            found.push(format!("\"{phrase}\""));
        }
    }
    found
}

/// The string literals in a Rust source file, roughly and honestly.
///
/// A real parser would be a dependency; the check only has to be good enough that a person
/// who writes "your PC is clean" in a label cannot get it merged.
fn string_literals(body: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut inside = false;
    let mut escaped = false;
    for character in body.chars() {
        if inside {
            if escaped {
                current.push(character);
                escaped = false;
                continue;
            }
            match character {
                '\\' => escaped = true,
                '"' => {
                    literals.push(std::mem::take(&mut current));
                    inside = false;
                }
                _ => current.push(character),
            }
        } else if character == '"' {
            inside = true;
        }
    }
    literals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_the_product_must_not_use_are_caught() {
        assert!(banned_in("Quarantine this file").is_empty());
        assert!(!banned_in("Fix the finding").is_empty());
        assert!(!banned_in("This file is infected").is_empty());
        assert!(!banned_in("your PC is clean").is_empty());
        assert!(!banned_in("threat score: 87").is_empty());
    }

    #[test]
    fn words_that_merely_contain_a_banned_one_are_left_alone() {
        for fine in [
            "the prefix of the path",
            "a fixture for the parser",
            "suffix",
            "the fixings",
            "infections are out of scope", // not a product claim
        ] {
            assert!(banned_in(fine).is_empty(), "{fine:?} must not trip the audit");
        }
    }

    #[test]
    fn every_replacement_is_a_sentence_a_person_can_use() {
        for (word, replacement) in BANNED_WORDS {
            assert!(!fix_for(word).is_empty());
            assert_ne!(replacement, word);
        }
        for (phrase, _) in BANNED_PHRASES {
            assert!(!fix_for(phrase).is_empty());
        }
    }

    #[test]
    fn literals_are_found_and_code_is_not() {
        let body = r#"let label = "Quarantine"; // a comment is not a literal
            let other = "found \"quoted\" text";
            fn fix_a_bug() {}"#;
        let literals = string_literals(body);
        assert!(literals.iter().any(|literal| literal == "Quarantine"));
        assert!(
            literals
                .iter()
                .any(|literal| literal.contains("found \"quoted\" text"))
        );
        assert!(!literals.iter().any(|literal| literal.contains("fn fix_a_bug")));
    }
}
