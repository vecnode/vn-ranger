//! The pack that ships, evaluated against facts.
//!
//! Every other pack test uses a fixture written for the test. This one reads
//! `packs/ranger.core.json` — the bytes `include_str!` puts in the binary — and checks that
//! a rule in the shipped catalogue actually fires on the fact it was written for, and stays
//! quiet on the same fact when it is ordinary. A rule that cannot be shown to fire is a
//! comment.

use crate::model::{AutorunFact, AutorunKind, AutorunScope, Host, SignatureStatus, Snapshot};
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
