//! Checks T-OBS-13 event-kind catalog freezing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    ContentHash, EVENT_KIND_CATALOG_VERSION, SchedulerEventLogClass, event_kind_catalog,
    event_kind_catalog_canonical_bytes, event_kind_catalog_canonical_material,
    event_kind_catalog_class, event_kind_catalog_dependency_map, event_kind_catalog_entry,
};

const EXPECTED_CATALOG_HASH: &str =
    "50c440576c24fb6b5a10359c231fb551e7b63e7b7f26ae231fd9f421db0aa139";

#[test]
fn event_kind_catalog_is_versioned_sorted_and_single_source_for_classes() {
    assert_eq!(EVENT_KIND_CATALOG_VERSION, 7);

    let mut kinds = BTreeSet::new();
    let mut previous = "";
    for entry in event_kind_catalog() {
        assert!(
            previous < entry.kind(),
            "catalog kinds must be sorted and unique: {previous:?}, {:?}",
            entry.kind()
        );
        previous = entry.kind();
        assert!(kinds.insert(entry.kind()));
        assert_eq!(event_kind_catalog_class(entry.kind()), Some(entry.class()));
        assert_sorted_unique(entry.sources());
        assert_sorted_unique(entry.attributes());
        assert_eq!(entry.canonical_bytes(), entry.canonical_line().into_bytes());
    }
}

#[test]
fn event_kind_catalog_contains_rfc_19_7_required_kinds() {
    for (kind, class) in [
        ("state_transition", SchedulerEventLogClass::Causal),
        ("signal_transition", SchedulerEventLogClass::Causal),
        ("signal_sample", SchedulerEventLogClass::Causal),
        ("signal_state_transition", SchedulerEventLogClass::Causal),
        ("binding_activation", SchedulerEventLogClass::Causal),
        ("binding_deactivation", SchedulerEventLogClass::Causal),
        ("campaign_selection", SchedulerEventLogClass::Causal),
        ("fault_opportunity", SchedulerEventLogClass::Causal),
        ("effect_choice", SchedulerEventLogClass::Causal),
        ("effect_combined", SchedulerEventLogClass::Causal),
        ("effect_applied", SchedulerEventLogClass::Causal),
        ("effect_committed", SchedulerEventLogClass::Causal),
        ("effect_rejected", SchedulerEventLogClass::Causal),
        ("network_profile", SchedulerEventLogClass::Causal),
        ("association_transition", SchedulerEventLogClass::Causal),
        ("trace_alignment", SchedulerEventLogClass::Causal),
        ("event_activated", SchedulerEventLogClass::Causal),
        ("trigger_fired", SchedulerEventLogClass::Causal),
        ("node_started", SchedulerEventLogClass::Causal),
        ("node_crashed", SchedulerEventLogClass::Causal),
        ("node_completed", SchedulerEventLogClass::Causal),
        ("timer_armed", SchedulerEventLogClass::Causal),
        ("timer_fired", SchedulerEventLogClass::Causal),
        ("timer_cancelled", SchedulerEventLogClass::Causal),
        ("message_delivered", SchedulerEventLogClass::Causal),
        ("message_dropped", SchedulerEventLogClass::Causal),
        ("assertion_evaluated", SchedulerEventLogClass::Causal),
        ("assertion_state_changed", SchedulerEventLogClass::Causal),
        ("savepoint", SchedulerEventLogClass::Causal),
        ("fork", SchedulerEventLogClass::Causal),
        ("tick", SchedulerEventLogClass::Causal),
        ("diagnostic", SchedulerEventLogClass::Observational),
        ("coverage", SchedulerEventLogClass::Observational),
        ("assertion_proximity", SchedulerEventLogClass::Observational),
        ("guest_marker", SchedulerEventLogClass::Observational),
        (
            "guest_measurement_begin",
            SchedulerEventLogClass::Observational,
        ),
        (
            "guest_measurement_end",
            SchedulerEventLogClass::Observational,
        ),
        ("guest_metric_sample", SchedulerEventLogClass::Observational),
        (
            "guest_semantic_marker",
            SchedulerEventLogClass::Observational,
        ),
    ] {
        let entry = event_kind_catalog_entry(kind)
            .unwrap_or_else(|| panic!("catalog should contain RFC kind {kind}"));
        assert_eq!(entry.class(), class, "{kind}");
    }
}

#[test]
fn event_kind_catalog_records_structural_dependency_map() {
    let dependencies = event_kind_catalog_dependency_map()
        .iter()
        .map(|dependency| (dependency.consumer(), dependency.kinds()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        dependencies
            .get("0016-08-observability-measurement-debugging")
            .copied()
            .unwrap_or(&[]),
        &[
            "guest_measurement_begin",
            "guest_measurement_end",
            "guest_metric_sample",
            "guest_semantic_marker",
        ]
    );
    assert_eq!(
        dependencies
            .get("0012-05-recording-replay-observability")
            .copied()
            .unwrap_or(&[]),
        &[
            "association_transition",
            "binding_activation",
            "binding_deactivation",
            "effect_applied",
            "effect_choice",
            "effect_combined",
            "effect_committed",
            "effect_rejected",
            "fault_opportunity",
            "network_profile",
            "signal_sample",
            "signal_state_transition",
            "signal_transition",
            "trace_alignment",
        ]
    );
    assert_eq!(
        dependencies
            .get("18-assertions-properties")
            .copied()
            .unwrap_or(&[]),
        &[
            "assertion_evaluated",
            "assertion_proximity",
            "assertion_state_changed",
            "guest_marker",
        ]
    );
    assert_eq!(
        dependencies
            .get("20-session-control-plane")
            .copied()
            .unwrap_or(&[]),
        &["*"]
    );
    assert_eq!(dependencies.get("21-api").copied().unwrap_or(&[]), &["*"]);
    assert_eq!(
        dependencies
            .get("22-advanced-features")
            .copied()
            .unwrap_or(&[]),
        &["assertion_proximity", "coverage"]
    );
    assert_eq!(
        dependencies
            .get("24-determinism-harness-testing")
            .copied()
            .unwrap_or(&[]),
        causal_kinds().as_slice()
    );
}

#[test]
fn event_kind_catalog_dependencies_resolve_to_catalog_entries() {
    for dependency in event_kind_catalog_dependency_map() {
        for kind in dependency.kinds() {
            if *kind == "*" {
                continue;
            }
            assert!(
                event_kind_catalog_entry(kind).is_some(),
                "{} dependency kind {kind} must resolve through the catalog",
                dependency.consumer()
            );
        }
    }
}

#[test]
fn event_kind_catalog_canonical_serialization_matches_golden_vector() {
    let material = event_kind_catalog_canonical_material();
    let bytes = event_kind_catalog_canonical_bytes();
    assert_eq!(bytes, material.as_bytes());
    assert_eq!(
        ContentHash::from_bytes(&bytes).to_hex(),
        EXPECTED_CATALOG_HASH
    );
}

fn assert_sorted_unique(values: &[&str]) {
    let mut previous = "";
    for value in values {
        assert!(
            previous < *value,
            "catalog values must be sorted and unique: {previous:?}, {value:?}"
        );
        previous = value;
    }
}

fn causal_kinds() -> Vec<&'static str> {
    event_kind_catalog()
        .iter()
        .filter(|entry| entry.class() == SchedulerEventLogClass::Causal)
        .map(|entry| entry.kind())
        .collect()
}
