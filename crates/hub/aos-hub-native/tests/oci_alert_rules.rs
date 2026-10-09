//! Contract checks for the deployable low-cardinality OCI alert rules.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RuleFile {
    groups: Vec<RuleGroup>,
}

#[derive(Debug, Deserialize)]
struct RuleGroup {
    name: String,
    rules: Vec<AlertRule>,
}

#[derive(Debug, Deserialize)]
struct AlertRule {
    alert: String,
    expr: String,
    #[serde(rename = "for")]
    duration: String,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
}

#[test]
fn oci_alert_rules_are_parseable_complete_and_low_cardinality() {
    let source = include_str!("../monitoring/oci-alerts.rules.yml");
    let parsed: RuleFile = serde_json::from_str(source).expect(
        "the checked Prometheus rule file uses the JSON subset of YAML for parser coverage",
    );
    assert_eq!(parsed.groups.len(), 1);
    let group = &parsed.groups[0];
    assert_eq!(group.name, "aos-hub-oci");

    let expected = BTreeMap::from([
        (
            "AosHubOciConditionalDeleteFailed",
            "aos_hub_oci_gc_failed_actions > 0",
        ),
        (
            "AosHubOciDigestMismatch",
            "aos_hub_oci_digest_mismatches > 0",
        ),
        (
            "AosHubOciGcPlanningBlocked",
            "aos_hub_oci_gc_blockers > 0",
        ),
        (
            "AosHubOciInventoryStale",
            "aos_hub_oci_gc_stale_inventories > 0 or aos_hub_oci_inventory_age_seconds{stat=\"max\"} > 900",
        ),
        (
            "AosHubOciPlacementLoss",
            "aos_hub_oci_placements{health=\"unhealthy\"} > 0",
        ),
        (
            "AosHubOciPublicationStuck",
            "aos_hub_oci_publications{state=\"stuck\"} > 0",
        ),
    ]);
    let actual = group
        .rules
        .iter()
        .map(|rule| (rule.alert.as_str(), rule.expr.as_str()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual, expected);

    for rule in &group.rules {
        assert!(rule.expr.starts_with("aos_hub_oci_"), "{}", rule.alert);
        assert!(!rule.duration.is_empty(), "{}", rule.alert);
        assert_eq!(
            rule.labels
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["component", "severity"]),
            "{}",
            rule.alert
        );
        assert_eq!(
            rule.labels.get("component").map(String::as_str),
            Some("aos-hub-oci")
        );
        assert!(rule.annotations.contains_key("summary"), "{}", rule.alert);
        assert!(
            rule.annotations.contains_key("description"),
            "{}",
            rule.alert
        );
        for forbidden in ["registry=", "repository=", "digest=", "actor=", "run_id="] {
            assert!(
                !rule.expr.contains(forbidden),
                "{}: {forbidden}",
                rule.alert
            );
        }
    }
}
