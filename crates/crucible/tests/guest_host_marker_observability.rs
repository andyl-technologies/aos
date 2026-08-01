//! Checks T-GHC-9 marker event-log observability and fingerprint neutrality.

#![cfg(feature = "test-double")]
#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AdvanceOutcome, Backend, BackendInput, Decision, EventClass, EventLog, EventLogIcountStamp,
    EventSource, ExecutionFingerprint, ExecutionHorizon, Icount, NodeId, ObservableEventPayload,
    RngDecision, RngStreamId, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SimBackend, VirtualTime, compare_event_log_determinism,
    event_log_causal_projection, observable_event_from_whitebox_marker_payload,
};
use crucible_protocol::{
    WhiteboxAssertionMarkerBody, WhiteboxAssertionMarkerFlavor, WhiteboxCoverageMarkerBody,
    WhiteboxEventMarkerBody, WhiteboxLifecycleMarkerEvent, WhiteboxMarkerDetail,
    WhiteboxMarkerPayload, WhiteboxRandomRequestBody,
};

#[test]
fn whitebox_marker_payloads_append_as_observational_icount_stamped_entries() {
    let marker_node = node("db-0");
    let marker_payloads = observational_marker_payloads();
    let entries = marker_payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            marker_entry(
                index as u64,
                40 + index as u64,
                marker_node.clone(),
                payload,
            )
        })
        .collect::<Vec<_>>();

    for (index, entry) in entries.iter().enumerate() {
        let expected_icount = icount(40 + index as u64);

        assert_eq!(entry.class(), EventClass::Observational);
        assert_eq!(entry.time().virtual_time, time(expected_icount.retired));
        assert_eq!(
            entry.time().icount,
            EventLogIcountStamp {
                node: Some(marker_node.clone()),
                icount: expected_icount,
            }
        );
        assert!(matches!(
            entry.source(),
            EventSource::Guest { node } if node == &marker_node
        ));
        assert!(entry.has_valid_content_hash());
        assert!(matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(
                ObservableEventPayload::GuestMarker { .. }
                    | ObservableEventPayload::GuestAssertionMarker { .. }
                    | ObservableEventPayload::CoverageMarker { .. }
            )
        ));
    }

    let append = append_event_log(entries.clone());
    assert_eq!(append, entries);
    assert!(event_log_causal_projection(&append).is_empty());

    let random_request = WhiteboxMarkerPayload::RandomRequest(WhiteboxRandomRequestBody {
        request_id: 7,
        width_bytes: 4,
        stream_tag: String::from("rng"),
    });
    assert_eq!(
        observable_event_from_whitebox_marker_payload(icount(44), marker_node, &random_request),
        None
    );
}

#[test]
fn whitebox_marker_entries_do_not_move_determinism_or_backend_fingerprint() {
    let baseline = run_material(
        vec![
            rng_entry(0, 10, "marker-neutrality", 17),
            boundary_entry(1, 20),
        ],
        17,
        b"workload",
    );
    let marked = run_material(
        vec![
            rng_entry(0, 10, "marker-neutrality", 17),
            marker_entry(1, 11, node("db-0"), &coverage_payload("hot-path")),
            marker_entry(2, 12, node("db-0"), &event_payload("guest.note")),
            boundary_entry(3, 20),
        ],
        17,
        b"workload",
    );
    let differently_marked = run_material(
        vec![
            marker_entry(0, 9, node("db-0"), &lifecycle_payload()),
            rng_entry(1, 10, "marker-neutrality", 17),
            boundary_entry(2, 20),
            marker_entry(3, 21, node("db-0"), &assertion_payload("guest.ready")),
        ],
        17,
        b"workload",
    );

    assert_eq!(baseline, marked);
    assert_eq!(marked, differently_marked);

    let changed_decision = run_material(
        vec![
            rng_entry(0, 10, "marker-neutrality", 19),
            boundary_entry(1, 20),
        ],
        19,
        b"workload",
    );
    assert_ne!(
        baseline, changed_decision,
        "causal schedule changes must still move the determinism projection"
    );
    assert_ne!(baseline.schedule, changed_decision.schedule);
    assert_ne!(
        baseline.causal_event_log_fingerprint,
        changed_decision.causal_event_log_fingerprint
    );

    let changed_workload = run_material(
        vec![
            rng_entry(0, 10, "marker-neutrality", 17),
            boundary_entry(1, 20),
        ],
        17,
        b"changed-workload",
    );
    assert_ne!(
        baseline, changed_workload,
        "backend input changes must still move the backend fingerprint"
    );
    assert_ne!(
        baseline.backend_fingerprint,
        changed_workload.backend_fingerprint
    );

    let baseline_log = append_event_log(vec![
        rng_entry(0, 10, "marker-neutrality", 17),
        boundary_entry(1, 20),
    ]);
    let marked_log = append_event_log(vec![
        rng_entry(0, 10, "marker-neutrality", 17),
        marker_entry(1, 11, node("db-0"), &coverage_payload("hot-path")),
        marker_entry(2, 12, node("db-0"), &event_payload("guest.note")),
        boundary_entry(3, 20),
    ]);
    let differently_marked_log = append_event_log(vec![
        marker_entry(0, 9, node("db-0"), &lifecycle_payload()),
        rng_entry(1, 10, "marker-neutrality", 17),
        boundary_entry(2, 20),
        marker_entry(3, 21, node("db-0"), &assertion_payload("guest.ready")),
    ]);

    let marked_comparison = compare_event_log_determinism(&baseline_log, &marked_log);
    let differently_marked_comparison =
        compare_event_log_determinism(&marked_log, &differently_marked_log);

    assert!(marked_comparison.passes());
    assert!(differently_marked_comparison.passes());
    assert_eq!(
        marked_comparison.expected().canonical_bytes(),
        marked_comparison.reproduced().canonical_bytes()
    );
    assert_eq!(
        differently_marked_comparison.expected().content_hash(),
        differently_marked_comparison.reproduced().content_hash()
    );
}

fn append_event_log(entries: Vec<SchedulerEventLogEntry>) -> Vec<SchedulerEventLogEntry> {
    let append = EventLog::new()
        .append_entries(entries)
        .expect("marker observability test entries should append");
    append.entries
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunMaterial {
    schedule: Vec<Decision>,
    causal_event_log_fingerprint: crucible::ContentHash,
    backend_fingerprint: ExecutionFingerprint,
}

fn run_material(
    event_log_entries: Vec<SchedulerEventLogEntry>,
    rng_value: u64,
    workload: &[u8],
) -> RunMaterial {
    let schedule = vec![Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("marker-neutrality"),
        value: rng_value,
    })];
    let event_log = append_event_log(event_log_entries);
    let causal_event_log_fingerprint = event_log_causal_projection(&event_log).content_hash();

    let mut backend = SimBackend::new();
    backend
        .deliver_input(BackendInput {
            node: node("db-0"),
            payload: workload.to_vec(),
        })
        .expect("deterministic backend input should deliver");
    assert_eq!(
        backend.advance_to_horizon(ExecutionHorizon {
            icount: icount(4096),
        }),
        Ok(AdvanceOutcome::ReachedHorizon)
    );
    backend
        .fingerprint()
        .map(|backend_fingerprint| RunMaterial {
            schedule,
            causal_event_log_fingerprint,
            backend_fingerprint,
        })
        .expect("deterministic backend fingerprint should read")
}

fn marker_entry(
    sequence: u64,
    marker_icount: u64,
    node: NodeId,
    payload: &WhiteboxMarkerPayload,
) -> SchedulerEventLogEntry {
    let event = observable_event_from_whitebox_marker_payload(icount(marker_icount), node, payload)
        .expect("observational marker payload should map to an event-log observation");
    crucible::test_support::condition_observation_entry_for_test(sequence, &event)
}

fn rng_entry(sequence: u64, ticks: u64, stream: &str, value: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name(stream),
            value,
        })),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn observational_marker_payloads() -> Vec<WhiteboxMarkerPayload> {
    vec![
        assertion_payload("guest.ready"),
        lifecycle_payload(),
        event_payload("guest.note"),
        coverage_payload("hot-path"),
    ]
}

fn assertion_payload(id: &str) -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Assertion(WhiteboxAssertionMarkerBody {
        flavor: WhiteboxAssertionMarkerFlavor::Reachable,
        condition: true,
        must_hit: true,
        id: id.to_owned(),
        message: String::from("guest reached ready point"),
        location: String::from("guest.rs:7"),
        details: vec![WhiteboxMarkerDetail::new("phase", "setup")],
    })
}

fn lifecycle_payload() -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Lifecycle(WhiteboxLifecycleMarkerEvent::SetupComplete)
}

fn event_payload(name: &str) -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Event(WhiteboxEventMarkerBody {
        name: name.to_owned(),
        details: Vec::new(),
    })
}

fn coverage_payload(point: &str) -> WhiteboxMarkerPayload {
    WhiteboxMarkerPayload::Coverage(WhiteboxCoverageMarkerBody {
        point: point.to_owned(),
    })
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
