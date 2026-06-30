//! Checks the T-OBS-4 event-kind class catalog lint.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crucible::{
    Decision, EventClass, EventDiagnosticPayload, EventLevel, RngDecision, RngStreamId,
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
