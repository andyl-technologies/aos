//! Checks T-SCHED-25 bounded scheduler concurrency.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConcurrentQuantumLoop, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId,
    QuantumLoop, QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerConcurrentRunCandidate, SchedulerError, SchedulerLivenessScenario,
    SchedulerLookaheadEdge, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler, VirtualTime,
};

#[test]
fn concurrent_run_set_is_bounded_by_workers_and_horizons() {
    let producer = scheduler_node("producer");
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let gamma = scheduler_node("gamma");
    let scenario = base_scenario(
        "concurrent-run-set-bounded",
        vec![
            scenario_node("alpha", 0, SchedulerNodeActivity::Runnable),
            scenario_node("beta", 0, SchedulerNodeActivity::Runnable),
            scenario_node("gamma", 0, SchedulerNodeActivity::Runnable),
        ],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![
        edge(&producer, &alpha, 8),
        edge(&producer, &beta, 8),
        edge(&producer, &gamma, 8),
    ]);
    let scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let run_set = scheduler
        .concurrent_run_set(2)
        .expect("run set should be available");

    assert_eq!(run_set.max_host_workers, 2);
    assert_eq!(
        run_set.candidates,
        vec![
            concurrent_candidate(&alpha, 0, 8, 8),
            concurrent_candidate(&beta, 0, 8, 8),
        ]
    );
}

#[test]
fn concurrent_run_set_excludes_skewed_peers_from_same_round() {
    let producer = scheduler_node("producer");
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let scenario = base_scenario(
        "concurrent-run-set-skewed-peer",
        vec![
            scenario_node("alpha", 0, SchedulerNodeActivity::Runnable),
            scenario_node("beta", 4, SchedulerNodeActivity::Runnable),
        ],
        Vec::new(),
    )
    .with_effective_topology_edges(vec![edge(&producer, &alpha, 5), edge(&producer, &beta, 5)]);
    let scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let run_set = scheduler
        .concurrent_run_set(2)
        .expect("run set should be available");

    assert_eq!(
        run_set.candidates,
        vec![concurrent_candidate(&alpha, 0, 5, 5)]
    );
}

#[test]
fn concurrent_run_set_rejects_zero_workers() {
    let scenario = base_scenario(
        "concurrent-run-set-zero-workers",
        vec![scenario_node("alpha", 0, SchedulerNodeActivity::Runnable)],
        Vec::new(),
    );
    let scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let error = scheduler
        .concurrent_run_set(0)
        .expect_err("zero workers must be rejected");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("max_host_workers"));
}

#[test]
fn concurrent_round_serializes_resolve_emit_bit_identically_to_serial() {
    let producer = scheduler_node("producer");
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let scenario = base_scenario(
        "concurrent-round-bit-identical",
        vec![
            scenario_node("alpha", 0, SchedulerNodeActivity::Runnable),
            scenario_node("beta", 0, SchedulerNodeActivity::Runnable),
        ],
        vec![
            backend_event(5, &alpha, &producer, 0, b"alpha-input"),
            backend_event(5, &beta, &producer, 0, b"beta-input"),
        ],
    )
    .with_effective_topology_edges(vec![edge(&producer, &alpha, 5), edge(&producer, &beta, 5)]);

    let mut serial = SingleScheduler::new(scenario.clone()).expect("scenario should build");
    let serial_first = drive_one_quantum(&mut serial);
    let serial_second = drive_one_quantum(&mut serial);
    let serial_frontiers = vec![serial_first.frontier, serial_second.frontier];
    let serial_hashes = event_hashes([&serial_first, &serial_second]);
    let serial_configuration = serial.configuration().clone();
    let serial_frontier = serial.frontier();
    let serial_offset = serial.event_log_offset();

    let mut concurrent = SingleScheduler::new(scenario).expect("scenario should build");
    let concurrent_round = concurrent
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: concurrent.configuration().clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect("concurrent round should drive");
    let concurrent_hashes = event_hashes(concurrent_round.outcomes.iter());
    let concurrent_frontiers = concurrent_round
        .outcomes
        .iter()
        .map(|outcome| outcome.frontier)
        .collect::<Vec<_>>();

    assert_eq!(concurrent_round.run_set.candidates.len(), 2);
    assert_eq!(concurrent_round.run_set.candidates[0].node, alpha);
    assert_eq!(concurrent_round.run_set.candidates[1].node, beta);
    assert_eq!(concurrent_frontiers, serial_frontiers);
    assert_eq!(concurrent_hashes, serial_hashes);
    assert_eq!(concurrent.configuration(), &serial_configuration);
    assert_eq!(concurrent.frontier(), serial_frontier);
    assert_eq!(concurrent.event_log_offset(), serial_offset);
}

fn base_scenario(
    material: &str,
    nodes: Vec<SchedulerScenarioNode>,
    pending_events: Vec<ScheduledEvent>,
) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        shift(0),
        8,
        instant(40),
        nodes,
        pending_events,
    )
}

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum")
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

fn edge(from: &SchedulerNodeId, to: &SchedulerNodeId, latency_ns: u64) -> SchedulerLookaheadEdge {
    SchedulerLookaheadEdge::new(from.clone(), to.clone(), duration(latency_ns))
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

fn concurrent_candidate(
    node: &SchedulerNodeId,
    current_time: u64,
    target_time: u64,
    max_advance_icount: u64,
) -> SchedulerConcurrentRunCandidate {
    SchedulerConcurrentRunCandidate {
        node: node.clone(),
        current_time: instant(current_time),
        target_time: instant(target_time),
        max_advance_icount,
    }
}

fn event_hashes<'a>(
    outcomes: impl IntoIterator<Item = &'a crucible::QuantumOutcome>,
) -> Vec<crucible::ContentHash> {
    outcomes
        .into_iter()
        .flat_map(|outcome| {
            outcome
                .event_log_entries
                .iter()
                .map(|entry| entry.content_hash())
        })
        .collect()
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn instant(nanos: u64) -> SimInstant {
    SimInstant { nanos }
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
