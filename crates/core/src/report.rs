//! A Markdown report a person can read without the interface.

use std::fmt::Write as _;

use crate::model::{AutorunFact, ListenerFact, ProcessFact, Snapshot};
use crate::rules::Finding;

const TABLE_LIMIT: usize = 60;
const FINDING_LIMIT: usize = 40;

/// Render a snapshot as a Markdown report, with the findings the rules produced.
#[must_use]
pub fn to_markdown(snapshot: &Snapshot, findings: &[Finding]) -> String {
    let counts = snapshot.counts();
    let mut out = String::new();
    out.push_str("# vn-ranger report\n\n");
    let _ = writeln!(
        out,
        "Generated {} on {} {} ({}).",
        crate::time::format_utc(snapshot.taken_at_unix),
        clean(&snapshot.host.os),
        clean(&snapshot.host.version),
        clean(&snapshot.host.arch)
    );
    if let Some(hostname) = &snapshot.host.hostname {
        let _ = writeln!(out, "Host: `{}`.", clean(hostname));
    }
    let _ = writeln!(
        out,
        "Elevated scan: {}. Collection time: {} ms.",
        if snapshot.elevated { "yes" } else { "no" },
        snapshot.duration_ms
    );
    let _ = writeln!(
        out,
        "\n**{} processes · {} startup items · {} listeners · {} packages.**\n",
        counts.processes, counts.autoruns, counts.listeners, counts.packages
    );

    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str(
            "No rule fired on this scan. That is a statement about the facts ranger could read, not a verdict that the machine is clean.\n\n",
        );
    } else {
        let _ = writeln!(out, "{} finding(s).\n", findings.len());
        for finding in findings.iter().take(FINDING_LIMIT) {
            let _ = writeln!(
                out,
                "### {} — {}\n",
                finding.severity.label(),
                clean(finding.title)
            );
            let _ = writeln!(
                out,
                "- Rule: `{}` · Confidence: {}\n- Subject: {}",
                finding.rule_id,
                finding.confidence.label(),
                clean(&finding.subject_label)
            );
            for line in &finding.evidence {
                let _ = writeln!(out, "  - {}", clean(line));
            }
            let _ = writeln!(
                out,
                "\nWhy: {}\n\nLikely benign: {}\n\nWhat to do: {}\n",
                clean(finding.why),
                clean(finding.benign),
                clean(finding.remediation)
            );
        }
        if findings.len() > FINDING_LIMIT {
            let _ = writeln!(out, "… and {} more finding(s).\n", findings.len() - FINDING_LIMIT);
        }
    }

    out.push_str("## What was checked\n\n");
    out.push_str("| Collector | Result | Items | Why not complete |\n|---|---|---:|---|\n");
    for status in &snapshot.collectors {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            cell(&status.label),
            status.state.label(),
            status.items,
            cell(status.reason.as_deref().unwrap_or("—"))
        );
    }
    out.push('\n');

    out.push_str("## Signature database\n\n");
    let _ = writeln!(
        out,
        "Loaded: **{}** signature(s) ({}) · rejected lines: {} · matches: **{}**.\n",
        snapshot.signatures.loaded,
        if snapshot.signatures.algorithms.is_empty() {
            "none".to_owned()
        } else {
            snapshot.signatures.algorithms.join(", ")
        },
        snapshot.signatures.rejected,
        snapshot.signatures.matches.len()
    );
    if !snapshot.signatures.matches.is_empty() {
        out.push_str("| Signature | Algorithm | File | Subject |\n|---|---|---|---|\n");
        for hit in &snapshot.signatures.matches {
            let _ = writeln!(
                out,
                "| {} | {} | `{}` | {} |",
                cell(&hit.name),
                hit.algorithm,
                cell(&hit.path),
                cell(&hit.subject)
            );
        }
        out.push('\n');
    }
    for note in &snapshot.signatures.notes {
        let _ = writeln!(out, "- {}\n", cell(note));
    }
    out.push('\n');

    if !snapshot.autoruns.is_empty() {
        out.push_str("## Startup items\n\n");
        out.push_str("| Name | Kind | Scope | Enabled | Path | Location |\n|---|---|---|---|---|---|\n");
        for autorun in snapshot.autoruns.iter().take(TABLE_LIMIT) {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | `{}` | {} |",
                cell(&autorun.name),
                autorun.kind.label(),
                autorun.scope.label(),
                if autorun.enabled { "yes" } else { "no" },
                cell(autorun.exe.as_deref().unwrap_or("—")),
                cell(&autorun.location)
            );
        }
        more(&mut out, snapshot.autoruns.len());
    }

    if !snapshot.listeners.is_empty() {
        out.push_str("## Listening sockets\n\n");
        out.push_str("| Protocol | Address | Port | Process | PID | Public |\n|---|---|---:|---|---:|---|\n");
        for listener in snapshot.listeners.iter().take(TABLE_LIMIT) {
            let _ = writeln!(
                out,
                "| {} | `{}` | {} | {} | {} | {} |",
                listener.protocol.label(),
                cell(&listener.address),
                listener.port,
                cell(listener.process.as_deref().unwrap_or("—")),
                listener.pid.map_or_else(|| "—".to_owned(), |pid| pid.to_string()),
                if listener.public { "yes" } else { "no" }
            );
        }
        more(&mut out, snapshot.listeners.len());
    }

    if !snapshot.processes.is_empty() {
        out.push_str("## Processes\n\n");
        out.push_str("| PID | Name | User | Started | Path |\n|---:|---|---|---|---|\n");
        for process in snapshot.processes.iter().take(TABLE_LIMIT) {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | `{}` |",
                process.pid,
                cell(&process.name),
                cell(process.user.as_deref().unwrap_or("—")),
                process
                    .started_at_unix
                    .map_or_else(|| "—".to_owned(), crate::time::format_utc),
                cell(process.exe.as_deref().unwrap_or("—"))
            );
        }
        more(&mut out, snapshot.processes.len());
    }

    if !snapshot.packages.is_empty() {
        out.push_str("## Packages\n\n");
        out.push_str("| Name | Version | Publisher | Source |\n|---|---|---|---|\n");
        for package in snapshot.packages.iter().take(TABLE_LIMIT) {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                cell(&package.name),
                cell(package.version.as_deref().unwrap_or("—")),
                cell(package.publisher.as_deref().unwrap_or("—")),
                cell(&package.source)
            );
        }
        more(&mut out, snapshot.packages.len());
    }

    out.push_str("---\n\n");
    out.push_str(
        "This is an inventory, not a verdict. It lists what ranger could see at the \
         moment of the scan; a fact that is absent does not mean it was not there. \
         No data left this machine.\n",
    );
    out
}

fn more(out: &mut String, total: usize) {
    if total > TABLE_LIMIT {
        let _ = writeln!(
            out,
            "\n_{} more in the JSON export._\n",
            total.saturating_sub(TABLE_LIMIT)
        );
    } else {
        out.push('\n');
    }
}

fn cell(value: &str) -> String {
    clean(value).replace('|', "\\|")
}

fn clean(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .replace('`', "'")
        .trim()
        .to_owned()
}

/// A one-line description of a startup item, for interfaces that need a summary.
#[must_use]
pub fn describe_autorun(autorun: &AutorunFact) -> String {
    format!(
        "{} · {} · {}",
        autorun.kind.label(),
        autorun.scope.label(),
        autorun.exe.as_deref().unwrap_or(autorun.command.as_str())
    )
}

/// A one-line description of a listener.
#[must_use]
pub fn describe_listener(listener: &ListenerFact) -> String {
    format!(
        "{}:{} · {}",
        listener.address,
        listener.port,
        listener.process.as_deref().unwrap_or("unknown process")
    )
}

/// A one-line description of a process.
#[must_use]
pub fn describe_process(process: &ProcessFact) -> String {
    format!(
        "{} · pid {} · {}",
        process.name,
        process.pid,
        process.exe.as_deref().unwrap_or("path not visible")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CollectorStatus, Host, SignatureReport};
    use crate::rules::{Confidence, Severity};

    #[test]
    fn a_finding_appears_in_the_report_with_its_evidence() {
        let snapshot = Snapshot::empty(Host::default(), false);
        let finding = Finding {
            rule_id: "startup.temp-path",
            title: "A startup item runs from a temporary folder",
            severity: Severity::Attention,
            confidence: Confidence::Observed,
            subject: "autorun:x".to_owned(),
            subject_label: "X".to_owned(),
            evidence: vec!["Executable: C:\\Temp\\x.exe".to_owned()],
            why: "Temporary folders are cleaned up.",
            benign: "An installer registered a helper.",
            remediation: "Check the file's publisher.",
        };
        let report = to_markdown(&snapshot, &[finding]);
        assert!(report.contains("## Findings"));
        assert!(report.contains("startup.temp-path"));
        assert!(report.contains("An installer registered a helper."));
        assert!(report.contains("Executable: C:\\Temp\\x.exe"));
    }

    #[test]
    fn report_contains_the_counts_and_escapes_pipes() {
        let mut snapshot = Snapshot::empty(
            Host {
                os: "linux".into(),
                version: "test".into(),
                arch: "x86_64".into(),
                hostname: Some("box".into()),
            },
            false,
        );
        snapshot.taken_at_unix = 1_000_000_000;
        snapshot
            .collectors
            .push(CollectorStatus::ok("test", "Test collector", 0));
        snapshot.signatures = SignatureReport::default();
        snapshot.processes.push(ProcessFact {
            pid: 1,
            parent: None,
            name: "a|b".into(),
            exe: None,
            command: None,
            user: None,
            started_at_unix: None,
        });
        let report = to_markdown(&snapshot, &[]);
        assert!(report.contains("1 processes"));
        assert!(report.contains("a\\|b"));
        assert!(report.contains("2001-09-09"));
        assert!(report.contains("No data left this machine"));
    }
}
