//! Checks T-SCHED-19 EMIT event-log entries and STEP frontier advancement.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ContentHash, Decision, EventEvaluationKind, EventKey, ExactLocalEvent, FaultId,
    FaultRateBasisPoints, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    RngStreamId, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerEventLogClass,
    SchedulerEventLogPayload, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerResolveFaultChoice, SchedulerScenarioNode, SchedulingNodeKind, Shift, SimDuration,
    SimInstant, SingleScheduler, VirtualTime, check_scheduler_liveness,
};

#[test]
fn emit_appends_resolved_happenings_before_decisions_with_dense_content_hashes() {
    let consumer = scheduler_node("consumer", SchedulingNodeKind::Vm);
    let frame_producer = scheduler_node("producer", SchedulingNodeKind::Vm);
    let fault_producer = scheduler_node("fault-link", SchedulingNodeKind::Network);
    let stream = RngStreamId::for_link("fault-link/loss");
    let fault = FaultId {
        name: String::from("link-loss"),
    };
    let frame = backend_event(4, &consumer, &frame_producer, 1, b"frame");
    let probabilistic =
        probabilistic_fault_event(4, &consumer, &fault_producer, 2, &fault, &stream, 0);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "emit-step-entry-order",
        shift(0),
        8,
        SimInstant { nanos: 30 },
        vec![scenario_node("consumer", 0, finite_lookahead(12))],
        vec![probabilistic.clone(), frame.clone()],
    );
    let mut scheduler = SingleScheduler::new(scenario.clone()).expect("scenario should build");
    let mut replay = SingleScheduler::new(scenario).expect("replay scenario should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should emit event-log entries");
    let replay_outcome = replay
        .drive_quantum(QuantumRequest {
            configuration: replay.configuration().clone(),
            control: Vec::new(),
        })
        .expect("replay should emit event-log entries");

    assert_eq!(outcome.frontier, VirtualTime { ticks: 4 });
    assert_eq!(
        outcome.resolved_events,
        vec![probabilistic.clone(), frame.clone()]
    );
    assert_eq!(outcome.event_log_entries, replay_outcome.event_log_entries);
    assert_eq!(outcome.event_log_offset, replay_outcome.event_log_offset);
    assert!(outcome.event_log_offset.appended_segment.is_some());
    assert_eq!(outcome.event_log_offset.events, 6);
    assert!(outcome.event_log_offset.bytes > 0);
    assert!(!outcome.event_log_segment_bytes.is_empty());
    assert_eq!(
        outcome.event_log_segment_hash,
        Some(ContentHash::from_bytes(&outcome.event_log_segment_bytes))
    );
    assert_eq!(
        outcome.event_log_offset.appended_segment,
        outcome.event_log_segment_hash
    );
    assert_eq!(
        scheduler.condition_event_log_prefix().point().kind(),
        EventEvaluationKind::QuantumBoundary
    );
    assert_eq!(
        scheduler.condition_event_log_prefix().point().at(),
        VirtualTime { ticks: 4 }
    );
    assert_eq!(
        outcome.event_log_offset.bytes,
        outcome.event_log_segment_bytes.len() as u64
    );

    let sequences = outcome
        .event_log_entries
        .iter()
        .map(|entry| entry.sequence())
        .collect::<Vec<_>>();
    assert_eq!(sequences, vec![0, 1, 2, 3, 4, 5]);
    assert!(
        outcome
            .event_log_entries
            .iter()
            .all(|entry| entry.class() == SchedulerEventLogClass::Causal
                && entry.content_hash() != Default::default())
    );

    assert!(matches!(
        outcome.event_log_entries[0].payload(),
        SchedulerEventLogPayload::ResolvedHappening(event) if event == &probabilistic
    ));
    assert!(matches!(
        outcome.event_log_entries[1].payload(),
        SchedulerEventLogPayload::ResolvedHappening(event) if event == &frame
    ));
    assert!(matches!(
        outcome.event_log_entries[2].payload(),
        SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(order))
            if order.order == vec![event_key(&probabilistic), event_key(&frame)]
    ));
    assert!(matches!(
        outcome.event_log_entries[3].payload(),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(draw)) if draw.stream == stream
    ));
    assert!(matches!(
        outcome.event_log_entries[4].payload(),
        SchedulerEventLogPayload::Decision(Decision::FaultFires(recorded))
            if recorded.fault == fault && !recorded.fired
    ));
    assert!(matches!(
        outcome.event_log_entries[5].payload(),
        SchedulerEventLogPayload::EvaluationBoundary(
            crucible::SchedulerEvaluationBoundaryKind::Quantum
        )
    ));
}

#[test]
fn step_advances_schedule_and_event_log_prefix_across_quanta() {
    let node_a = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let node_b = scheduler_node("node-b", SchedulingNodeKind::Vm);
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "emit-step-prefix-advance",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node("node-a", 0, finite_lookahead(10)),
            scenario_node("node-b", 0, finite_lookahead(10)),
        ],
        vec![
            backend_event(6, &node_b, &node_a, 2, b"b"),
            backend_event(3, &node_a, &node_b, 1, b"a"),
        ],
    ))
    .expect("scenario should build");

    let first = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("first quantum should emit");
    let second = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("second quantum should emit");

    assert_eq!(first.event_log_entries.len(), 3);
    assert_eq!(second.event_log_entries.len(), 3);
    assert_eq!(first.event_log_offset.events, 3);
    assert_eq!(second.event_log_entries[0].sequence(), 3);
    assert_eq!(second.event_log_offset.events, 6);
    assert!(second.event_log_offset.bytes > first.event_log_offset.bytes);
    assert_ne!(
        second.event_log_offset.prefix,
        first.event_log_offset.prefix
    );
    assert_eq!(
        scheduler.configuration().schedule.decisions().len(),
        first.decisions.len() + second.decisions.len()
    );
}

#[test]
fn liveness_report_includes_deterministic_event_log_hashes() {
    let first = check_scheduler_liveness(report_scenario()).expect("first run should terminate");
    let second = check_scheduler_liveness(report_scenario()).expect("second run should terminate");

    assert_eq!(first, second);
    assert_eq!(first.resolved_events, 2);
    assert_eq!(first.event_log_entries, 8);
    assert_eq!(first.event_log_entry_hashes.len(), 8);
    assert_eq!(first.event_log_offset.events, 8);
    assert!(first.event_log_offset.bytes > 0);
}

#[test]
fn no_progress_quantum_does_not_append_polling_boundary_entries() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "emit-step-no-progress-poll",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        Vec::new(),
        Vec::new(),
    ))
    .expect("empty scheduler scenario should build");

    let first = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("first no-progress quantum should return");
    let second = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("second no-progress quantum should return");

    assert!(first.event_log_entries.is_empty());
    assert!(second.event_log_entries.is_empty());
    assert_eq!(first.event_log_offset.events, 0);
    assert_eq!(second.event_log_offset.events, 0);
    assert!(first.event_log_segment_hash.is_none());
    assert!(second.event_log_segment_hash.is_none());
}

fn report_scenario() -> SchedulerLivenessScenario {
    let node_a = scheduler_node("node-a", SchedulingNodeKind::Vm);
    let node_b = scheduler_node("node-b", SchedulingNodeKind::Vm);
    SchedulerLivenessScenario::from_canonical_material(
        "emit-step-report",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![
            scenario_node("node-a", 0, finite_lookahead(10)),
            scenario_node("node-b", 0, finite_lookahead(10)),
        ],
        vec![
            backend_event(6, &node_b, &node_a, 2, b"b"),
            backend_event(3, &node_a, &node_b, 1, b"a"),
        ],
    )
}

fn event_key(event: &ScheduledEvent) -> EventKey {
    EventKey::new(
        event.key.virtual_time(),
        event.key.consumer().clone(),
        event.key.producer().clone(),
        event.key.sequence(),
    )
}

fn backend_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    payload: &[u8],
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::BackendInput(BackendInput {
            node: consumer.node.clone(),
            payload: payload.to_vec(),
        }),
    }
}

fn probabilistic_fault_event(
    virtual_time: u64,
    consumer: &SchedulerNodeId,
    producer: &SchedulerNodeId,
    sequence: u64,
    fault: &FaultId,
    stream: &RngStreamId,
    rate_basis_points: u32,
) -> ScheduledEvent {
    ScheduledEvent {
        key: ScheduledEventKey::from_parts(
            VirtualTime {
                ticks: virtual_time,
            },
            consumer.clone(),
            producer.clone(),
            sequence,
        ),
        payload: ScheduledEventPayload::ProbabilisticFault(SchedulerResolveFaultChoice {
            fault: fault.clone(),
            stream: stream.clone(),
            rate: FaultRateBasisPoints::from_basis_points(rate_basis_points)
                .expect("test rate should be valid"),
        }),
    }
}

fn scenario_node(
    name: &str,
    counter: u64,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity: SchedulerNodeActivity::Runnable,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
    }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
