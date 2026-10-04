//! Exercises strict validation of original typed guest read brackets and returns.

use super::*;
use crucible::NodeId;
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlanError, SelectablePlanPendingRequest,
};
use crucible_protocol::{SelectableRegister, SelectionRequest};

fn register_readiness(plan: &mut SelectableCatalogPlan) {
    let registration = SelectableRegister::new(
        1,
        super::super::READINESS_SELECTABLE_ID,
        vec![1],
        vec![1],
        vec![String::from("readiness")],
    )
    .expect("original guest registration");
    plan.apply_registration(&registration)
        .expect("declared readiness selectable");
    plan.apply_freeze().expect("original setup freeze");
}

fn pending_barrier(sequence: u64, instance: &str) -> SelectablePlanPendingRequest {
    let request = SelectionRequest::new(
        sequence,
        super::super::READINESS_SELECTABLE_ID,
        instance,
        None,
        128,
    )
    .expect("original barrier reply capacity");
    SelectablePlanPendingRequest::new(request, 100, 5000, 0, 0x1000)
}

#[test]
fn clock_profile_accepts_three_original_barriers_then_refuses_fourth_atomically() {
    let mut plan = selectable_catalog_plan(true).expect("clock profile");
    register_readiness(&mut plan);

    for (sequence, instance) in [(2, "boot"), (3, "clock-0"), (4, "clock-1")] {
        plan.apply_pending_request(pending_barrier(sequence, instance))
            .expect("every original guest barrier fits the finite profile");
        let reply = SelectionReply::rejected(
            sequence,
            SelectionReplyStatus::Unavailable,
            [0; 32],
            [0; 32],
        )
        .expect("original typed unavailable reply");
        plan.apply_completed_reply(&reply)
            .expect("exact reply completion counts once");
    }

    assert_eq!(plan.continuation().total_completed_requests(), 3);
    assert_eq!(
        plan.continuation().last_completed_request_sequence(),
        Some(4)
    );
    let completed = plan.encode().expect("completed canonical plan");
    assert_eq!(
        SelectableCatalogPlan::decode(&completed).expect("canonical round trip"),
        plan
    );
    assert!(matches!(
        plan.apply_pending_request(pending_barrier(5, "extra")),
        Err(SelectableCatalogPlanError::RequestLimitExceeded {
            field: "total_requests",
            actual: 4,
            maximum: 3,
        })
    ));
    assert_eq!(plan.encode().expect("refused plan"), completed);
}

#[test]
fn default_profile_preserves_original_cold_plan_and_refuses_second_barrier() {
    let declaration = SelectablePlanDeclaration::new(
        "flight.ready",
        vec![1],
        vec![1],
        vec![String::from("readiness")],
        SelectablePlanPresence::Required,
    )
    .expect("original declaration");
    let original = SelectableCatalogPlan::new(
        SelectablePlanLimits::new(1, 1, 1).expect("original finite limits"),
        vec![declaration],
        SelectablePlanContinuation::cold(),
    )
    .expect("original cold plan");
    let mut plan = selectable_catalog_plan(false).expect("default profile");
    let clock = selectable_catalog_plan(true).expect("clock profile");

    assert_eq!(
        plan.encode().expect("default plan"),
        original.encode().expect("original plan")
    );
    assert_eq!(clock.declarations(), original.declarations());
    assert_eq!(clock.continuation(), original.continuation());
    assert_eq!(clock.limits().declarations(), 1);
    assert_eq!(clock.limits().requests_per_selectable(), 3);
    assert_eq!(clock.limits().total_requests(), 3);

    register_readiness(&mut plan);
    plan.apply_pending_request(pending_barrier(2, "boot"))
        .expect("original boot barrier");
    let reply = SelectionReply::rejected(2, SelectionReplyStatus::Unavailable, [0; 32], [0; 32])
        .expect("original typed unavailable reply");
    plan.apply_completed_reply(&reply).expect("boot completion");
    let completed = plan.encode().expect("completed default plan");

    assert!(matches!(
        plan.apply_pending_request(pending_barrier(3, "clock-0")),
        Err(SelectableCatalogPlanError::RequestLimitExceeded {
            field: "total_requests",
            actual: 2,
            maximum: 1,
        })
    ));
    assert_eq!(plan.encode().expect("refused default plan"), completed);
}

fn detail(key: &str, value: GuestMeasurementValue) -> GuestSemanticMarkerDetail {
    GuestSemanticMarkerDetail {
        key: key.into(),
        value,
    }
}

fn event(
    ps: u64,
    marker: &str,
    instance: &str,
    details: Vec<GuestSemanticMarkerDetail>,
) -> ObservableEvent {
    ObservableEvent::guest_semantic_marker(
        Icount { retired: ps },
        NodeId {
            name: super::super::FLIGHT_NODE_ID.into(),
        },
        marker,
        instance,
        details,
    )
}

fn batch(index: u64) -> Vec<ObservableEvent> {
    let mut events = Vec::new();
    for (position, clock) in CLOCKS.into_iter().enumerate() {
        let instance = format!("{index}-{clock}");
        let ps = 1000 + index * 1000 + position as u64 * 100;
        let unit = match clock {
            "tsc" => "cycles",
            "gettimeofday" => "microseconds",
            _ => "nanoseconds",
        };
        events.push(event(
            ps,
            BEFORE,
            &instance,
            vec![detail("cpu", GuestMeasurementValue::Unsigned(0))],
        ));
        events.push(event(
            ps + 10,
            AFTER,
            &instance,
            vec![
                detail("cpu", GuestMeasurementValue::Unsigned(0)),
                detail("fraction", GuestMeasurementValue::Signed(0)),
                detail(
                    "seconds",
                    GuestMeasurementValue::Signed(if clock == "tsc" {
                        0
                    } else {
                        100 + index as i64
                    }),
                ),
                detail("unit", GuestMeasurementValue::Enumerated(unit.into())),
                detail(
                    "value",
                    GuestMeasurementValue::Unsigned(if clock == "tsc" { 5 + index * 4 } else { 0 }),
                ),
            ],
        ));
    }
    events
}

#[test]
fn original_read_bracket_accepts_tsc_interval_without_using_later_marker_as_read_time() {
    let first = validate_batch(&batch(0), 0).expect("original bracket");
    assert_eq!(
        (first[3].before_ps, first[3].after_ps, first[3].value),
        (1300, 1310, 5)
    );
    assert_ne!(first[3].after_ps, first[3].value * 250);

    let mut reads = first;
    reads.extend(validate_batch(&batch(1), 1).expect("second bracket"));
    validate_forward_returns(&reads).expect("authorized wake advances returned clocks");
}

#[test]
fn wrong_node_missing_repeated_reversed_and_extra_original_events_refuse() {
    let original = batch(0);
    let mut cases = Vec::new();
    cases.push(original[..7].to_vec());
    let mut extra = original.clone();
    extra.push(original[7].clone());
    cases.push(extra);
    let mut repeated = original.clone();
    repeated[1] = repeated[0].clone();
    cases.push(repeated);
    let mut reversed = original.clone();
    reversed.swap(0, 1);
    cases.push(reversed);
    let mut foreign = original;
    foreign[0] = ObservableEvent::guest_semantic_marker(
        Icount { retired: 1000 },
        NodeId {
            name: "foreign-node".into(),
        },
        BEFORE,
        "0-realtime",
        vec![detail("cpu", GuestMeasurementValue::Unsigned(0))],
    );
    cases.push(foreign);

    for events in cases {
        assert!(validate_batch(&events, 0).is_err());
    }
}

#[test]
fn out_of_bracket_tsc_and_scaled_overflow_refuse_without_fitting_an_offset() {
    for value in [4, 6, u64::MAX] {
        let mut events = batch(0);
        events[7] = event(
            1310,
            AFTER,
            "0-tsc",
            vec![
                detail("cpu", GuestMeasurementValue::Unsigned(0)),
                detail("fraction", GuestMeasurementValue::Signed(0)),
                detail("seconds", GuestMeasurementValue::Signed(0)),
                detail("unit", GuestMeasurementValue::Enumerated("cycles".into())),
                detail("value", GuestMeasurementValue::Unsigned(value)),
            ],
        );
        assert!(validate_batch(&events, 0).is_err());
    }
}

#[test]
fn linux_return_schema_normalization_cpu_and_units_refuse() {
    let good = batch(0);
    for (field, replacement) in [
        (0, detail("cpu", GuestMeasurementValue::Unsigned(1))),
        (
            1,
            detail("fraction", GuestMeasurementValue::Signed(1_000_000_000)),
        ),
        (1, detail("fraction", GuestMeasurementValue::Signed(-1))),
        (2, detail("seconds", GuestMeasurementValue::Unsigned(100))),
        (
            3,
            detail("unit", GuestMeasurementValue::Enumerated("cycles".into())),
        ),
        (4, detail("value", GuestMeasurementValue::Unsigned(1))),
    ] {
        let mut events = good.clone();
        let ObservableEventPayload::GuestSemanticMarker { details, .. } = events[1].payload()
        else {
            panic!("fixture marker")
        };
        let mut details = details.clone();
        details[field] = replacement;
        events[1] = event(1010, AFTER, "0-realtime", details);
        assert!(validate_batch(&events, 0).is_err());
    }
}

#[test]
fn host_delay_comparison_uses_original_return_tuples_and_all_read_coordinates() {
    let first = validate_batch(&batch(0), 0).expect("first batch");
    let second = validate_batch(&batch(1), 1).expect("second batch");
    let mut reads = first;
    reads.extend(second);
    let reference = RunEvidence {
        pid: 100,
        reads,
        boundaries: Vec::new(),
        idle_ps: 1800,
        idle_raw: 30,
        wake_ps: 2000,
        timer_generation: 1,
        events: retained(&batch(0)),
    };
    let mut hostile = reference.clone();
    hostile.pid = 200;
    compare(&reference, &hostile).expect("original equal returns and coordinates");
    hostile.reads[0].fraction += 1;
    assert!(compare(&reference, &hostile).is_err());
    hostile = reference.clone();
    hostile.pid = 200;
    hostile.reads[0].before_ps += 1;
    assert!(compare(&reference, &hostile).is_err());
    hostile = reference.clone();
    hostile.pid = 200;
    hostile.events.pop();
    assert!(compare(&reference, &hostile).is_err());

    let mut unchanged = reference.reads;
    unchanged[4].seconds = unchanged[0].seconds;
    assert!(validate_forward_returns(&unchanged).is_err());
}

#[test]
fn mode_is_default_off_and_requires_original_ownership_admission() {
    use std::ffi::OsStr;
    assert!(!mode(None, None).expect("default off"));
    assert!(!mode(None, Some(OsStr::new("0"))).expect("existing default mode"));
    assert!(mode(Some(OsStr::new("1")), Some(OsStr::new("1"))).expect("explicit mode"));
    for value in ["", "0", "2", "01"] {
        assert!(mode(Some(OsStr::new(value)), Some(OsStr::new("1"))).is_err());
    }
    assert!(mode(Some(OsStr::new("1")), None).is_err());
}
