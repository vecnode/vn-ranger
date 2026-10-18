//! What the Sigma importer takes, refuses, and counts.

use super::*;

const POWERSHELL: &str = "\
title: Encoded PowerShell
id: 6f3a1c11
description: PowerShell running with an encoded command.
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
falsepositives:
  - Administrator scripts
  - Some installers
tags:
  - attack.t1059.001
";

#[test]
fn a_mapped_rule_becomes_a_pack_rule_with_its_technique_and_its_benign_explanation() {
    let import = import(POWERSHELL).unwrap();
    assert!(import.skipped.is_empty(), "{:?}", import.skipped);
    assert_eq!(import.rules.len(), 1);
    let rule = &import.rules[0];
    assert_eq!(rule.id, "sigma.encoded-powershell");
    assert_eq!(rule.severity, Severity::Attention);
    assert_eq!(rule.confidence, Confidence::Possible);
    assert_eq!(rule.technique.as_deref(), Some("T1059.001"));
    assert!(rule.benign.contains("Administrator scripts"), "{}", rule.benign);
    assert_eq!(rule.matches.all.len(), 2);
    assert_eq!(rule.matches.all[0].field, "path");
    assert_eq!(rule.matches.all[0].operator, crate::pack::Operator::Suffix);
    assert_eq!(rule.matches.all[1].field, "command");
    assert_eq!(rule.matches.all[1].operator, crate::pack::Operator::Contains);
}

#[test]
fn the_imported_pack_passes_the_product_s_own_validator_once_it_is_written() {
    let import = import(POWERSHELL).unwrap();
    let pack = import.pack("imported.powershell", "1.0.0");
    let text = serde_json::to_string(&pack_as_json(&pack)).unwrap();
    let parsed = crate::pack::parse(&text, crate::rules::builtin_ids())
        .expect("a pack the importer wrote is a pack the reader accepts");
    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(parsed.rules[0].id, "sigma.encoded-powershell");
}

/// The wire shape, written the way a pack file is: the importer's output has to survive the
/// same reader a hand-written pack goes through.
fn pack_as_json(pack: &Pack) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = pack
        .rules
        .iter()
        .map(|rule| {
            let mut all = Vec::new();
            for predicate in &rule.matches.all {
                all.push(serde_json::json!({
                    "field": predicate.field,
                    "op": predicate.operator.id(),
                    "value": predicate.value,
                }));
            }
            serde_json::json!({
                "id": rule.id,
                "title": rule.title,
                "severity": match rule.severity {
                    Severity::Attention => "attention",
                    Severity::Notice => "notice",
                    Severity::Info => "info",
                },
                "confidence": "possible",
                "technique": rule.technique,
                "match": {
                    "subject": "process",
                    "all": all,
                },
                "why": rule.why,
                "benign": rule.benign,
                "remediation": rule.remediation,
            })
        })
        .collect();
    serde_json::json!({
        "schema": schema(),
        "pack": {
            "id": pack.header.id,
            "version": pack.header.version,
            "title": pack.header.title,
        },
        "rules": rules,
    })
}

#[test]
fn an_unmapped_field_is_skipped_with_the_field_named() {
    let text = "\
title: Registry run key
detection:
  selection:
    TargetObject|contains: '\\CurrentVersion\\Run'
  condition: selection
falsepositives:
  - Installers
";
    let import = import(text).unwrap();
    assert!(import.rules.is_empty());
    assert_eq!(import.skipped.len(), 1);
    assert!(
        import.skipped[0].reason.contains("TargetObject"),
        "{}",
        import.skipped[0].reason
    );
}

#[test]
fn a_rule_without_false_positives_is_skipped_rather_than_shipped_without_a_benign_explanation() {
    let text = "\
title: No benign
detection:
  selection:
    Image|endswith: '\\x.exe'
  condition: selection
";
    let import = import(text).unwrap();
    assert!(import.rules.is_empty());
    assert!(import.skipped[0].reason.contains("falsepositives"));
}

#[test]
fn a_regular_expression_is_refused_by_name() {
    let text = "\
title: Regex
detection:
  selection:
    CommandLine|re: '.*-enc.*'
  condition: selection
falsepositives:
  - None
";
    let import = import(text).unwrap();
    assert!(import.rules.is_empty());
    assert!(import.skipped[0].reason.contains("regular expression"));
}

#[test]
fn a_compound_condition_is_counted_with_the_condition_in_the_reason() {
    let text = "\
title: Two selections
detection:
  selection_a:
    Image|endswith: '\\a.exe'
  selection_b:
    Image|endswith: '\\b.exe'
  condition: selection_a and selection_b
falsepositives:
  - None
";
    let import = import(text).unwrap();
    assert!(import.rules.is_empty());
    assert!(
        import.skipped[0].reason.contains("selection_a and selection_b"),
        "{}",
        import.skipped[0].reason
    );
}

#[test]
fn a_severity_is_capped_at_attention_and_the_lowest_levels_are_info() {
    for (level, expected) in [
        ("critical", Severity::Attention),
        ("high", Severity::Attention),
        ("medium", Severity::Notice),
        ("low", Severity::Info),
        ("informational", Severity::Info),
    ] {
        assert_eq!(severity(Some(level)), expected, "{level}");
    }
}

#[test]
fn a_rule_id_is_stable_and_lower_case() {
    assert_eq!(rule_id("Encoded PowerShell", 0), "sigma.encoded-powershell");
    assert_eq!(rule_id("Encoded PowerShell", 1), "sigma.encoded-powershell-2");
    assert!(valid_id(&rule_id("!!!", 0)), "even a title with no letters");
}

#[test]
fn a_document_that_is_not_yaml_is_an_error_rather_than_an_empty_pack() {
    assert!(import("").is_err());
    assert!(import("title: &anchor\n").is_err());
}
