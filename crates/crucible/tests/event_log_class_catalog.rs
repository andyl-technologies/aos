//! Checks the T-OBS-4 event-kind class catalog lint.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, Decision, EventClass,
    EventDiagnosticPayload, EventLevel, GuestAssertionDetail, GuestAssertionKind,
    GuestAssertionMarker, Icount, NodeId, ObservableEvent, RngDecision, RngStreamId,
    SchedulerEventLogPayload, VirtualTime,
};

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn rng_decision(name: &str, value: u64) -> SchedulerEventLogPayload {
    SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(name),
        value,
    }))
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

#[test]
fn event_class_is_derived_from_payload_kind_catalog() {
    let causal = crucible::test_support::condition_payload_entry_for_test(
        0,
        time(0),
        rng_decision("class-catalog-causal", 9),
    );
    let observational = crucible::test_support::condition_payload_entry_for_test(
        1,
        time(1),
        SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
            "catalog.diagnostic",
            EventLevel::Info,
            BTreeMap::new(),
        )),
    );

    assert_eq!(causal.event_payload().kind(), "rng_draw");
    assert_eq!(causal.class(), EventClass::Causal);
    assert!(causal.class_matches_catalog());
    assert_eq!(observational.event_payload().kind(), "diagnostic");
    assert_eq!(observational.class(), EventClass::Observational);
    assert!(observational.class_matches_catalog());
}

#[test]
fn assertion_and_guest_marker_kinds_follow_rfc_catalog_classes() {
    let assertion_state = ObservableEvent::assertion_state_changed(
        time(3),
        assertion_id("catalog-assertion"),
        AssertionPhase::Satisfied,
    );
    let assertion_entry =
        crucible::test_support::condition_observation_entry_for_test(0, &assertion_state);
    assert_eq!(
        assertion_entry.event_payload().kind(),
        "assertion_state_changed"
    );
    assert_eq!(
        assertion_entry.event_payload().string("id"),
        Some("catalog-assertion")
    );
    assert_eq!(
        assertion_entry.event_payload().string("new_state"),
        Some("Satisfied")
    );
    assert_eq!(assertion_entry.class(), EventClass::Causal);
    assert!(assertion_entry.class_matches_catalog());

    let assertion_evaluated = ObservableEvent::assertion_evaluated(
        time(4),
        assertion_id("catalog-evaluated"),
        AssertionQuantifierKind::Sometimes,
        true,
        "catalog assertion evaluated",
        vec![GuestAssertionDetail::new("case", "catalog")],
    );
    let evaluated_entry =
        crucible::test_support::condition_observation_entry_for_test(1, &assertion_evaluated);
    assert_eq!(
        evaluated_entry.event_payload().kind(),
        "assertion_evaluated"
    );
    assert_eq!(
        evaluated_entry.event_payload().string("id"),
        Some("catalog-evaluated")
    );
    assert_eq!(
        evaluated_entry.event_payload().string("flavor"),
        Some("Sometimes")
    );
    assert_eq!(
        evaluated_entry.event_payload().bool("condition"),
        Some(true)
    );
    assert_eq!(evaluated_entry.class(), EventClass::Causal);
    assert!(evaluated_entry.class_matches_catalog());

    let assertion_marker = GuestAssertionMarker::new(
        assertion_id("guest-marker-catalog"),
        "guest marker catalog",
        GuestAssertionKind::Reachable,
        true,
        true,
        vec![GuestAssertionDetail::new("case", "catalog")],
        "guest.rs:7",
    );
    let guest_marker =
        ObservableEvent::guest_assertion_marker(icount(7), node("guest"), assertion_marker);
    let guest_marker_entry =
        crucible::test_support::condition_observation_entry_for_test(2, &guest_marker);
    assert_eq!(guest_marker_entry.event_payload().kind(), "guest_marker");
    assert_eq!(
        guest_marker_entry.event_payload().string("marker_kind"),
        Some("assert")
    );
    assert_eq!(
        guest_marker_entry.event_payload().string("assertion"),
        Some("guest-marker-catalog")
    );
    assert_eq!(
        guest_marker_entry.event_payload().bool("condition"),
        Some(true)
    );
    assert_eq!(
        guest_marker_entry.event_payload().u64("details_len"),
        Some(1)
    );
    assert_eq!(
        guest_marker_entry.event_payload().string("detail.0.key"),
        Some("case")
    );
    assert_eq!(guest_marker_entry.class(), EventClass::Observational);
    assert!(guest_marker_entry.class_matches_catalog());
}
