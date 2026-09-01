//! Checks T-OBS-13 event-kind catalog freezing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    ContentHash, EVENT_KIND_CATALOG_VERSION, EventClass, event_kind_catalog,
    event_kind_catalog_canonical_bytes, event_kind_catalog_canonical_material,
    event_kind_catalog_class, event_kind_catalog_dependency_map, event_kind_catalog_entry,
};

const EXPECTED_CATALOG_HASH: &str =
    "256a2fbe140895c90d7ec8fa600902fd1247617c13074e2a736abbde481d4ae8";

#[test]
fn event_kind_catalog_is_versioned_sorted_and_single_source_for_classes() {
    assert_eq!(EVENT_KIND_CATALOG_VERSION, 5);

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
        ("state_transition", EventClass::Causal),
        ("signal_transition", EventClass::Causal),
        ("signal_sample", EventClass::Causal),
        ("signal_state_transition", EventClass::Causal),
        ("binding_activation", EventClass::Causal),
        ("binding_deactivation", EventClass::Causal),
        ("fault_opportunity", EventClass::Causal),
        ("effect_choice", EventClass::Causal),
        ("effect_combined", EventClass::Causal),
        ("effect_applied", EventClass::Causal),
        ("effect_committed", EventClass::Causal),
        ("effect_rejected", EventClass::Causal),
        ("network_profile", EventClass::Causal),
        ("association_transition", EventClass::Causal),
        ("trace_alignment", EventClass::Causal),
        ("event_activated", EventClass::Causal),
        ("trigger_fired", EventClass::Causal),
        ("node_started", EventClass::Causal),
        ("node_crashed", EventClass::Causal),
        ("node_completed", EventClass::Causal),
        ("timer_armed", EventClass::Causal),
        ("timer_fired", EventClass::Causal),
        ("timer_cancelled", EventClass::Causal),
        ("message_delivered", EventClass::Causal),
        ("message_dropped", EventClass::Causal),
        ("assertion_evaluated", EventClass::Causal),
        ("assertion_state_changed", EventClass::Causal),
        ("savepoint", EventClass::Causal),
        ("fork", EventClass::Causal),
        ("tick", EventClass::Causal),
        ("diagnostic", EventClass::Observational),
        ("coverage", EventClass::Observational),
        ("assertion_proximity", EventClass::Observational),
        ("guest_marker", EventClass::Observational),
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
        .filter(|entry| entry.class() == EventClass::Causal)
        .map(|entry| entry.kind())
        .collect()
}
