//! The Linux surfaces that load code before anything a person clicks.
//!
//! Four files decide what the loader and the kernel do behind every program on the machine:
//! `/etc/ld.so.preload` names libraries the dynamic loader maps into *every* process,
//! `modprobe.d` can replace a kernel module's load with a command, a `udev` rule can run a
//! program on a device event, and a shell startup file runs on every login.
//!
//! Each reader takes the file's text and returns what it says; the walk that finds the files
//! is in the module above. That split is what lets a captured file from a real machine stand
//! in for the machine, which is how these parsers are tested on Windows.
//!
//! A line that names a library is a fact with the file that named it. None of this is a
//! verdict: `ld.so.preload` is empty on a healthy machine, and a `udev` rule that runs a
//! vendor helper is ordinary.

use vnr_core::{AutorunFact, AutorunKind, AutorunScope, SignatureStatus};

/// One line of `ld.so.preload`, which is one library mapped into every process.
///
/// The file is normally absent, and an empty file is the same as absent: a line here is worth
/// knowing about because there is no reason for one on a machine nobody has tampered with.
#[must_use]
pub(crate) fn preload(path: &str, text: &str) -> Vec<AutorunFact> {
    let mut facts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        facts.push(fact(
            format!("preload:{line}"),
            format!("Preloaded library {}", base_name(line)),
            line.to_owned(),
            path.to_owned(),
            AutorunKind::Preload,
        ));
        let _ = index;
    }
    facts
}

/// `install <module> <command>` lines in `modprobe.d`, which replace a module's load with a
/// program of the author's choosing.
#[must_use]
pub(crate) fn modprobe(path: &str, text: &str) -> Vec<AutorunFact> {
    let mut facts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("install ") else {
            continue;
        };
        let (module, command) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if command.trim().is_empty() {
            continue;
        }
        facts.push(fact(
            format!("modprobe:{}:{index}", module.trim()),
            format!("Module {} is installed by a command", module.trim()),
            command.trim().to_owned(),
            path.to_owned(),
            AutorunKind::KernelModule,
        ));
    }
    facts
}

/// `RUN+=` and `PROGRAM=` in a `udev` rule, which run a program on a device event.
#[must_use]
pub(crate) fn udev(path: &str, text: &str) -> Vec<AutorunFact> {
    let mut facts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for key in ["RUN+=", "PROGRAM="] {
            let Some(at) = line.find(key) else {
                continue;
            };
            let value = line[at + key.len()..].trim().trim_matches('"');
            if value.is_empty() {
                continue;
            }
            facts.push(fact(
                format!("udev:{}:{index}:{key}", base_name(path)),
                format!("udev rule {key}{}", base_name(path)),
                value.to_owned(),
                path.to_owned(),
                AutorunKind::UdevRule,
            ));
        }
    }
    facts
}

/// A shell startup file: it runs on every login, so the file is the fact.
///
/// The content is not read for commands; a script can do anything, and picking one line out
/// of it would be a guess. What matters is that a file in this position exists and who owns
/// it, and the finding carries `command` as the file itself.
#[must_use]
pub(crate) fn shell_startup(path: &str, text: &str) -> Vec<AutorunFact> {
    let body = text.trim();
    // An empty file, or one that is nothing but comments, cannot do anything.
    let meaningful = body
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !line.starts_with('#'));
    if !meaningful {
        return Vec::new();
    }
    vec![fact(
        format!("shell:{path}"),
        format!("Shell startup file {}", base_name(path)),
        path.to_owned(),
        path.to_owned(),
        AutorunKind::ShellStartup,
    )]
}

fn fact(id: String, name: String, command: String, location: String, kind: AutorunKind) -> AutorunFact {
    let exe =
        crate::collect::unixutil::executable_from_command(&command).map(|path| path.display().to_string());
    AutorunFact {
        id,
        name,
        command,
        location,
        kind,
        // A preloaded library, a module hook and a login script belong to the machine; a file
        // in a person's home belongs to that person. The caller says which by the path, and
        // this is the default for the system files it reads.
        scope: AutorunScope::System,
        enabled: true,
        exe,
        sha256: None,
        hidden: false,
        signature: SignatureStatus::NotChecked,
    }
}

fn base_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("linux")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
    }

    #[test]
    fn the_captured_udev_rule_names_the_program_it_runs() {
        let facts = udev("udev/50-apport.rules", &fixture("udev/50-apport.rules"));
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].kind, AutorunKind::UdevRule);
        assert!(
            facts[0]
                .command
                .starts_with("/usr/share/apport/iwlwifi_error_dump"),
            "{}",
            facts[0].command
        );
        assert_eq!(facts[0].location, "udev/50-apport.rules");
    }

    #[test]
    fn the_captured_profile_scripts_are_facts_and_an_empty_one_is_not() {
        let facts = shell_startup(
            "/etc/profile.d/apps-bin-path.sh",
            &fixture("profile.d/apps-bin-path.sh"),
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].kind, AutorunKind::ShellStartup);
        assert_eq!(facts[0].command, "/etc/profile.d/apps-bin-path.sh");
        assert!(shell_startup("/etc/profile.d/empty.sh", "# nothing\n\n").is_empty());
    }

    #[test]
    fn the_captured_crontab_is_read_by_the_cron_reader_not_this_one() {
        // The capture is here so the module's tests read every file it kept, and to record
        // that this machine has no `install` line and no preload file.
        let crontab = fixture("crontab");
        assert!(modprobe("/etc/modprobe.d/crontab", &crontab).is_empty());
        assert!(preload("/etc/ld.so.preload", "# empty\n").is_empty());
    }

    #[test]
    fn the_captured_blacklist_file_has_no_install_line_which_is_the_ordinary_case() {
        let facts = modprobe(
            "/etc/modprobe.d/blacklist.conf",
            &fixture("modprobe.d/blacklist.conf"),
        );
        assert!(facts.is_empty(), "{facts:?}");
    }

    #[test]
    fn an_install_line_is_read_with_its_module_and_its_command() {
        let facts = modprobe(
            "/etc/modprobe.d/acme.conf",
            "install acme /usr/local/bin/acme-loader --quiet\nblacklist floppy\n",
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].name, "Module acme is installed by a command");
        assert_eq!(facts[0].command, "/usr/local/bin/acme-loader --quiet");
        assert_eq!(facts[0].kind, AutorunKind::KernelModule);
    }

    #[test]
    fn a_preload_line_is_one_library_and_a_comment_is_not() {
        let facts = preload(
            "/etc/ld.so.preload",
            "/usr/local/lib/libacme.so.1\n# a comment\n\n",
        );
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].command, "/usr/local/lib/libacme.so.1");
        assert_eq!(facts[0].name, "Preloaded library libacme.so.1");
        assert_eq!(facts[0].kind, AutorunKind::Preload);
        assert!(preload("/etc/ld.so.preload", "").is_empty());
    }
}
