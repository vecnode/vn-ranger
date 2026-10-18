//! The pack that ships, evaluated against facts.
//!
//! Every other pack test uses a fixture written for the test. This one reads
//! `packs/ranger.core.json` — the bytes `include_str!` puts in the binary — and checks that
//! a rule in the shipped catalogue actually fires on the fact it was written for, and stays
//! quiet on the same fact when it is ordinary. A rule that cannot be shown to fire is a
//! comment.

use crate::model::{AgentFact, AutorunFact, AutorunKind, AutorunScope, Host, SignatureStatus, Snapshot};
use crate::pack::Pack;
use crate::pack::evaluate::{Places, evaluate};
use crate::rules::{Severity, builtin_ids};

/// The pack that travels with the build.
const SHIPPED: &str = include_str!("../../../../packs/ranger.core.json");

fn shipped() -> Pack {
    crate::pack::parse(SHIPPED, builtin_ids()).expect("the shipped pack is valid")
}

fn service_dll(name: &str, path: &str) -> AutorunFact {
    AutorunFact {
        id: format!("service-dll:HKLM:64:{name}"),
        name: name.to_owned(),
        command: path.to_owned(),
        location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}\Parameters\ServiceDll (64-bit)"),
        kind: AutorunKind::Service,
        scope: AutorunScope::System,
        enabled: true,
        hidden: false,
        exe: Some(path.to_owned()),
        sha256: None,
        signature: SignatureStatus::NotChecked,
    }
}

fn snapshot(autoruns: Vec<AutorunFact>) -> Snapshot {
    let mut snapshot = Snapshot::empty(Host::default(), false);
    snapshot.autoruns = autoruns;
    snapshot
}

/// The places a normal machine resolves, with the user's folders where they really are.
fn places() -> Places {
    Places::new()
        .with("PROGRAMDATA", r"C:\ProgramData")
        .with("LOCALAPPDATA", r"C:\Users\user\AppData\Local")
        .with("APPDATA", r"C:\Users\user\AppData\Roaming")
        .with("TEMP", r"C:\Users\user\AppData\Local\Temp")
}

#[test]
fn the_shipped_pack_loads_and_holds_the_rules_the_release_notes_claim() {
    let pack = shipped();
    assert_eq!(pack.header.id, "ranger.core");
    assert!(pack.rules.len() >= 6, "{} rules", pack.rules.len());
    for rule in &pack.rules {
        assert!(!rule.benign.trim().is_empty(), "{} has no benign", rule.id);
        assert!(
            !rule.why.trim().is_empty(),
            "{} has no reason a person can read",
            rule.id
        );
    }
}

#[test]
fn a_service_dll_under_a_user_writable_folder_fires() {
    let pack = shipped();
    let facts = snapshot(vec![service_dll(
        "AcmeHelper",
        r"C:\Users\user\AppData\Local\Temp\acme.dll",
    )]);
    let findings = evaluate(&pack, &facts, &places());
    let fired = findings
        .iter()
        .find(|finding| finding.rule_id == "startup.service-dll-user-writable")
        .expect("the shipped rule fires on a service DLL in a temporary folder");
    assert_eq!(fired.severity, Severity::Attention);
    assert_eq!(fired.technique.as_deref(), Some("T1543.003"));
    assert_eq!(fired.subject, "service-dll:HKLM:64:AcmeHelper");
    assert!(
        fired
            .evidence
            .iter()
            .any(|line| line.contains("AppData\\Local\\Temp")),
        "the evidence names the observed path: {:?}",
        fired.evidence
    );
    assert_eq!(fired.pack.as_deref(), Some("ranger.core 2026.11.1"));
}

#[test]
fn the_same_service_with_its_dll_in_system32_does_not_fire() {
    let pack = shipped();
    let facts = snapshot(vec![service_dll("wscsvc", r"C:\Windows\System32\wscsvc.dll")]);
    let findings = evaluate(&pack, &facts, &places());
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "startup.service-dll-user-writable"),
        "an installed service must not fire: {findings:?}"
    );
}

#[test]
fn a_startup_entry_in_a_temporary_folder_under_the_user_scope_fires() {
    let pack = shipped();
    let mut entry = service_dll("Acme", r"C:\Users\user\AppData\Local\Temp\acme.exe");
    entry.kind = AutorunKind::RunKey;
    entry.scope = AutorunScope::User;
    entry.id = "run:HKCU:64:Acme".to_owned();
    let findings = evaluate(&pack, &snapshot(vec![entry]), &places());
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "startup.under-temp"),
        "the temporary-folder rule resolves the place and fires: {findings:?}"
    );
}

#[test]
fn a_place_this_machine_cannot_name_makes_the_rule_stay_quiet() {
    let pack = shipped();
    let facts = snapshot(vec![service_dll(
        "AcmeHelper",
        r"C:\Users\user\AppData\Local\Temp\acme.dll",
    )]);
    // No place resolved: a rule about {PROGRAMDATA} cannot claim anything about a path.
    let findings = evaluate(&pack, &facts, &Places::new());
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "startup.service-dll-user-writable"),
        "an unresolved place must not fire: {findings:?}"
    );
}

/// One loader rule, the kind it is about, a path it should fire on and one it should not.
const LOADERS: [(&str, AutorunKind, &str, &str); 5] = [
    (
        "startup.service-dll-user-writable",
        AutorunKind::Service,
        r"C:\Users\user\AppData\Local\Temp\acme.dll",
        r"C:\Windows\System32\wscsvc.dll",
    ),
    (
        "startup.netsh-helper-user-writable",
        AutorunKind::NetshHelper,
        r"C:\Users\user\AppData\Roaming\acme\netsh.dll",
        r"C:\Windows\System32\ifmon.dll",
    ),
    (
        "startup.print-monitor-user-writable",
        AutorunKind::PrintMonitor,
        r"C:\ProgramData\Acme\monitor\acme.dll",
        r"C:\Windows\System32\localspl.dll",
    ),
    (
        "startup.time-provider-user-writable",
        AutorunKind::TimeProvider,
        r"C:\Users\user\AppData\Local\Temp\w32time.dll",
        r"C:\Windows\System32\w32time.dll",
    ),
    (
        "startup.screensaver-user-writable",
        AutorunKind::Screensaver,
        r"C:\Users\user\AppData\Local\acme.scr",
        r"C:\Windows\System32\scrnsave.scr",
    ),
];

fn loader(kind: AutorunKind, path: &str) -> AutorunFact {
    let mut fact = service_dll("Acme", path);
    fact.kind = kind;
    fact.id = format!("{}:test:{}", kind.id(), "one");
    fact
}

#[test]
fn every_loader_rule_fires_on_its_folder_and_stays_quiet_on_an_installed_one() {
    let pack = shipped();
    for (rule_id, kind, written, installed) in LOADERS {
        let fires = evaluate(&pack, &snapshot(vec![loader(kind, written)]), &places());
        assert!(
            fires.iter().any(|finding| finding.rule_id == rule_id),
            "{rule_id} did not fire on {written}"
        );
        let quiet = evaluate(&pack, &snapshot(vec![loader(kind, installed)]), &places());
        assert!(
            quiet.iter().all(|finding| finding.rule_id != rule_id),
            "{rule_id} fired on an installed {installed}"
        );
    }
}

#[test]
fn a_loader_rule_names_the_kind_it_is_about_so_one_loader_cannot_be_read_as_another() {
    let pack = shipped();
    // A netsh helper in a temporary folder is not a service, and the service rule must not
    // claim it: the kind predicate is what keeps the six rules apart.
    let findings = evaluate(
        &pack,
        &snapshot(vec![loader(
            AutorunKind::NetshHelper,
            r"C:\Users\user\AppData\Local\Temp\acme.dll",
        )]),
        &places(),
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "startup.netsh-helper-user-writable")
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "startup.service-dll-user-writable"),
        "a netsh helper is not a service: {findings:?}"
    );
}
#[test]
fn a_hidden_task_running_from_a_user_writable_folder_fires_and_a_visible_one_does_not() {
    let pack = shipped();
    let hidden = |hidden: bool| {
        let mut fact = loader(
            AutorunKind::ScheduledTask,
            r"C:\Users\user\AppData\Local\Acme\updater.exe",
        );
        fact.hidden = hidden;
        fact
    };
    let fires = evaluate(&pack, &snapshot(vec![hidden(true)]), &places());
    let finding = fires
        .iter()
        .find(|finding| finding.rule_id == "task.hidden-user-writable")
        .expect("a hidden task in a user-writable folder fires");
    assert_eq!(finding.severity, Severity::Attention);
    assert_eq!(finding.technique.as_deref(), Some("T1053.005"));

    let quiet = evaluate(&pack, &snapshot(vec![hidden(false)]), &places());
    assert!(
        quiet
            .iter()
            .all(|finding| finding.rule_id != "task.hidden-user-writable"),
        "a visible task is not this rule's business: {quiet:?}"
    );
}

#[test]
fn every_rule_in_the_shipped_pack_names_a_technique_and_a_benign_explanation() {
    let pack = shipped();
    for rule in &pack.rules {
        assert!(rule.technique.is_some(), "{} names no technique", rule.id);
        assert!(!rule.benign.trim().is_empty(), "{} has no benign", rule.id);
        assert!(rule.severity != Severity::Attention || !rule.benign.trim().is_empty());
    }
}

fn agent(command: Option<&str>) -> AgentFact {
    AgentFact {
        id: "mcp:filesystem".to_owned(),
        tool: "mcp".to_owned(),
        name: "filesystem".to_owned(),
        path: r"C:\Users\user\.cursor\mcp.json".to_owned(),
        command: command.map(str::to_owned),
    }
}

#[test]
fn a_configuration_that_names_a_command_fires_and_one_that_does_not_stays_quiet() {
    let pack = shipped();
    let mut with = snapshot(Vec::new());
    with.agents.push(agent(Some("npx -y server-filesystem /tmp")));
    let fires = evaluate(&pack, &with, &places());
    let finding = fires
        .iter()
        .find(|finding| finding.rule_id == "agent.config-names-a-command")
        .expect("a configuration that names a command fires");
    assert_eq!(finding.severity, Severity::Notice);
    assert_eq!(finding.technique.as_deref(), Some("T1059"));
    assert_eq!(finding.subject, "mcp:filesystem");
    assert!(
        finding.evidence.iter().any(|line| line.contains("npx -y")),
        "the evidence names the command: {:?}",
        finding.evidence
    );

    let mut without = snapshot(Vec::new());
    without.agents.push(agent(None));
    let quiet = evaluate(&pack, &without, &places());
    assert!(
        quiet
            .iter()
            .all(|finding| finding.rule_id != "agent.config-names-a-command"),
        "a server with a URL and no command starts nothing: {quiet:?}"
    );
}

#[test]
fn the_accessibility_swap_fires_and_a_debugger_for_any_other_program_does_not() {
    let pack = shipped();
    let debugger = |name: &str| {
        let mut fact = loader(AutorunKind::Debugger, r"C:\Windows\System32\cmd.exe");
        fact.name = name.to_owned();
        fact.id = format!("ifeo-debugger:HKLM:64:{name}");
        fact
    };
    let fires = evaluate(&pack, &snapshot(vec![debugger("sethc.exe")]), &places());
    let finding = fires
        .iter()
        .find(|finding| finding.rule_id == "startup.accessibility-swap")
        .expect("a debugger on an accessibility program fires");
    assert_eq!(finding.severity, Severity::Attention);
    assert_eq!(finding.technique.as_deref(), Some("T1546.008"));

    let quiet = evaluate(&pack, &snapshot(vec![debugger("notepad.exe")]), &places());
    assert!(
        quiet
            .iter()
            .all(|finding| finding.rule_id != "startup.accessibility-swap"),
        "an ordinary program is not this rule's business: {quiet:?}"
    );
}
