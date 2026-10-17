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
        "version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(format!(
            "unknown xtask `{other}`; try ci, fmt-fix, lint, test, check, no-network or version"
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

/// The tests live in the pure core and the native collectors. The interface and the
/// shell have no tests yet, so they are type-checked rather than linked into an empty
/// test binary; linking wgpu for zero tests is the slowest useful thing CI can do.
fn test() -> Result<(), String> {
    run(&[
        "test",
        "--package",
        "vnr-core",
        "--package",
        "vnr-native",
        "--all-targets",
        "--profile",
        CI_PROFILE,
    ])?;
    run(&[
        "check",
        "--package",
        "vnr-ui",
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
