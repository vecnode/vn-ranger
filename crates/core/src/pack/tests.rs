//! The validator's tests: one per promise, one per limit.
//!
//! The pack in [`GOOD`] is the one in `docs/PLAN.md` §6.11, so the documentation and the
//! parser are checked against the same bytes.

use super::*;

/// The pack from the plan, which is the shape a real one takes.
const GOOD: &str = r#"{
  "schema": 1,
  "pack": { "id": "ranger.core", "version": "2026.11.1", "title": "Ranger core detections" },
  "rules": [
    {
      "id": "startup.msix-package-root",
      "title": "A startup entry under a packaged app's local cache",
      "severity": "attention",
      "confidence": "likely",
      "technique": "T1547.001",
      "match": {
        "subject": "startup",
        "all": [
          { "field": "path", "op": "under", "value": "{LOCALAPPDATA}\\Packages\\" },
          { "field": "scope", "op": "eq", "value": "user" }
        ]
      },
      "why": "A package's cache is not a place an installer registers a login item.",
      "benign": "An application that registers its own updater at first launch.",
      "remediation": "Quarantine the binary, then remove the startup entry."
    }
  ]
}"#;

const RULE: &str = r#"{"id":"a.b","title":"t","severity":"info","confidence":"likely","match":{"subject":"startup","all":[{"field":"path","op":"exists"}]},"why":"w","benign":"b","remediation":"r"}"#;

fn rejects(text: &str) -> Vec<Reject> {
    parse(text, &[]).expect_err("the pack must be refused")
}

fn problems(text: &str) -> Vec<String> {
    rejects(text).into_iter().map(|reject| reject.problem).collect()
}

fn one_problem(text: &str) -> String {
    let all = problems(text);
    assert_eq!(all.len(), 1, "expected one refusal, got {all:?}");
    all.into_iter().next().unwrap()
}

#[test]
fn the_pack_in_the_plan_parses() {
    let pack = parse(GOOD, &["builtin.hash.example"]).expect("the documented pack is valid");
    assert_eq!(pack.header.id, "ranger.core");
    assert_eq!(pack.rules.len(), 1);
    let rule = &pack.rules[0];
    assert_eq!(rule.id, "startup.msix-package-root");
    assert_eq!(rule.severity, Severity::Attention);
    assert_eq!(rule.confidence, Confidence::Likely);
    assert_eq!(rule.matches.len(), 2);
    assert_eq!(rule.matches.subject, Some(Subject::Startup));
    assert_eq!(rule.matches.all[0].operator, Operator::Under);
    assert_eq!(rule.technique.as_deref(), Some("T1547.001"));
}

#[test]
fn a_pack_with_the_wrong_schema_is_refused() {
    let text = GOOD.replace("\"schema\": 1", "\"schema\": 2");
    assert!(one_problem(&text).contains("schema"));
}

#[test]
fn an_unknown_field_is_a_load_error_rather_than_a_rule_that_never_fires() {
    let text = GOOD.replace("\"field\": \"scope\"", "\"field\": \"registry_hive\"");
    let problem = one_problem(&text);
    assert!(problem.contains("registry_hive"), "{problem}");
    assert!(problem.contains("startup"), "it says which subject: {problem}");
}

#[test]
fn an_unknown_operator_is_refused() {
    let text = GOOD.replace("\"op\": \"under\"", "\"op\": \"regex\"");
    let problem = one_problem(&text);
    assert!(problem.contains("regex"), "{problem}");
    assert!(problem.contains("glob"), "it lists what is allowed: {problem}");
}

#[test]
fn a_rule_without_a_benign_explanation_is_not_a_finding() {
    let text = GOOD.replace(
        "\"benign\": \"An application that registers its own updater at first launch.\"",
        "\"benign\": \"  \"",
    );
    assert!(one_problem(&text).contains("benign"));
}

#[test]
fn urgent_cannot_come_from_a_pack() {
    let text = GOOD.replace("\"severity\": \"attention\"", "\"severity\": \"urgent\"");
    let problem = one_problem(&text);
    assert!(problem.contains("urgent"), "{problem}");
    assert!(problem.contains("ceiling"), "{problem}");
}

#[test]
fn a_rule_id_must_be_lowercase_and_dotted() {
    for bad in ["startup", "Startup.Thing", "a..b", "a_b.c", ".leading"] {
        let text = GOOD.replace("startup.msix-package-root", bad);
        assert!(!problems(&text).is_empty(), "{bad} must be refused as an id");
    }
    for good in ["a.b", "ranger.core", "startup.msix-package-root", "x1.y-2"] {
        assert!(valid_id(good), "{good} is a valid id");
    }
}

#[test]
fn a_technique_id_has_a_shape() {
    for good in ["T1547", "T1547.001"] {
        assert!(valid_technique(good), "{good}");
    }
    for bad in ["1547", "T154", "T1547.1", "T15470", "T1547.0001", "t1547"] {
        assert!(!valid_technique(bad), "{bad} must not pass for a technique");
    }
}

#[test]
fn two_rules_may_not_share_an_id_and_a_pack_may_not_shadow_a_builtin() {
    let duplicate = RULE.replace("\"a.b\"", "\"startup.msix-package-root\"");
    let twice = GOOD.replace("\"rules\": [", &format!("\"rules\": [ {duplicate},"));
    assert!(
        problems(&twice).iter().any(|problem| problem.contains("twice")),
        "a duplicate id makes a suppression ambiguous"
    );
    let shadow = parse(GOOD, &["startup.msix-package-root"]);
    assert!(shadow.is_err(), "a pack may not shadow a built-in");
}

#[test]
fn the_rule_limit_is_enforced_before_anything_is_evaluated() {
    let many = format!(
        "{{\"schema\":1,\"pack\":{{\"id\":\"p.q\",\"version\":\"1\",\"title\":\"t\"}},\"rules\":[{}]}}",
        vec![RULE; MAX_RULES + 1].join(",")
    );
    assert!(
        problems(&many).iter().any(|problem| problem.contains("512")),
        "the rule count is a load error"
    );
}

#[test]
fn the_predicate_and_string_limits_are_enforced() {
    let predicates = vec![r#"{"field":"path","op":"exists"}"#; MAX_PREDICATES + 1].join(",");
    let long = GOOD.replace(
        "{ \"field\": \"scope\", \"op\": \"eq\", \"value\": \"user\" }",
        &format!("{{\"field\":\"scope\",\"op\":\"eq\",\"value\":\"user\"}},{predicates}"),
    );
    assert!(
        problems(&long)
            .iter()
            .any(|problem| problem.contains("predicates")),
        "a rule may not hold more predicates than the limit"
    );

    let big = "x".repeat(MAX_STRING + 1);
    let wide = GOOD.replace(
        "\"why\": \"A package's cache is not a place an installer registers a login item.\"",
        &format!("\"why\": \"{big}\""),
    );
    assert!(
        problems(&wide).iter().any(|problem| problem.contains("4096")),
        "the string limit is a load error"
    );
}

#[test]
fn a_pack_over_two_megabytes_is_refused_before_it_is_parsed() {
    let huge = " ".repeat(MAX_BYTES + 1);
    let reject = rejects(&huge).into_iter().next().unwrap();
    assert!(reject.problem.contains("2097152"), "{}", reject.problem);
}

#[test]
fn a_predicate_needs_exactly_the_value_its_operator_takes() {
    let missing = GOOD.replace(
        "{ \"field\": \"scope\", \"op\": \"eq\", \"value\": \"user\" }",
        "{ \"field\": \"scope\", \"op\": \"eq\" }",
    );
    assert!(one_problem(&missing).contains("needs a value"));

    let extra = GOOD.replace(
        "{ \"field\": \"scope\", \"op\": \"eq\", \"value\": \"user\" }",
        "{ \"field\": \"scope\", \"op\": \"exists\", \"value\": \"user\" }",
    );
    assert!(one_problem(&extra).contains("takes no value"));
}

#[test]
fn a_refusal_can_be_found_in_the_file() {
    let text = GOOD.replace("\"field\": \"scope\"", "\"field\": \"nope\"");
    let reject = rejects(&text).into_iter().next().unwrap();
    assert_eq!(reject.rule.as_deref(), Some("startup.msix-package-root"));
    let line = reject.line.expect("a semantic refusal still names its line");
    assert!(
        text.lines().nth(line.saturating_sub(1)).is_some(),
        "the line is inside the file"
    );
    assert!(reject.to_string().contains("at line"), "{reject}");
}

#[test]
fn a_pack_that_is_not_json_says_where_it_stopped() {
    let reject = rejects("{\"schema\": 1,}").into_iter().next().unwrap();
    assert!(reject.line.is_some(), "the parser knows the line");
    assert!(reject.problem.contains("JSON"), "{}", reject.problem);
}

#[test]
fn a_pack_with_no_rules_is_refused() {
    let text = "{\"schema\":1,\"pack\":{\"id\":\"p.q\",\"version\":\"1\",\"title\":\"t\"},\"rules\":[]}";
    assert!(one_problem(text).contains("no rules"));
}

#[test]
fn the_vocabulary_is_closed() {
    assert_eq!(Operator::from_id("regex"), None);
    assert_eq!(Subject::from_id("registry"), None);
    for operator in Operator::ALL {
        assert_eq!(
            Operator::from_id(operator.id()),
            Some(operator),
            "{} round-trips",
            operator.id()
        );
    }
    assert!(Subject::ALL.iter().all(|subject| !subject.fields().is_empty()));
    assert!(!Operator::Exists.takes_value() && Operator::Eq.takes_value());
}
