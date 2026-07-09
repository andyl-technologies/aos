//! Checks T-SCHED-20 horizon virtual-time to icount ceiling conversion.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, Icount, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerError,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulingNodeKind, SharedTimeline, Shift, SimDuration, SimInstant, SingleScheduler,
    VirtualTime,
};

#[test]
fn shared_timeline_converts_horizon_with_time4_ceil_map() {
    let timeline = SharedTimeline::new(shift(4)).expect("timeline should accept fixed shift");

    assert_eq!(
        timeline.max_advance_icount_for_horizon(SimInstant { nanos: 64 }),
        Ok(Icount { retired: 4 })
    );
    assert_eq!(
        timeline.max_advance_icount_for_horizon(SimInstant { nanos: 65 }),
        Ok(Icount { retired: 5 })
    );
    assert_eq!(
        timeline.max_advance_icount_for_horizon(SimInstant { nanos: 79 }),
        Ok(Icount { retired: 5 })
    );
}

#[test]
fn exact_horizon_publishes_ceil_icount_not_floor_or_virtual_time() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-exact-horizon",
        shift(2),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(40),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 5 },
            },
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(publication.target_time, SimInstant { nanos: 5 });
    assert_eq!(publication.icount_shift, shift(2));
    assert_eq!(publication.current_icount, NodeCounter { ticks: 0 });
    assert_eq!(publication.max_advance_icount, 2);
    assert_ne!(
        publication.max_advance_icount,
        publication.target_time.nanos
    );
    assert_eq!(outcome.frontier, VirtualTime { ticks: 8 });
}

#[test]
fn network_horizon_ceiling_uses_fixed_shift_not_raw_virtual_nanoseconds() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-network-horizon",
        shift(3),
        8,
        SimInstant { nanos: 80 },
        vec![scenario_node(
            "runner",
            2,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(16),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(publication.target_time, SimInstant { nanos: 32 });
    assert_eq!(publication.icount_shift, shift(3));
    assert_eq!(publication.current_icount, NodeCounter { ticks: 2 });
    assert_eq!(publication.max_advance_icount, 4);
    assert_ne!(
        publication.max_advance_icount,
        publication.target_time.nanos
    );
    assert_eq!(outcome.frontier, VirtualTime { ticks: 32 });
}

#[test]
fn unaligned_conservative_horizon_rejects_ceil_overshoot() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-network-overshoot",
        shift(3),
        8,
        SimInstant { nanos: 80 },
        vec![scenario_node(
            "runner",
            2,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(10),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("unaligned conservative horizon must not be rounded past");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("icount ceiling overshoot"));
}

#[test]
fn exact_horizon_equal_to_network_cap_rejects_conservative_overshoot() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-exact-equals-network",
        shift(2),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(5),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 5 },
            },
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("exact horizon must not round past an equal conservative cap");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("icount ceiling overshoot"));
}

#[test]
fn exact_horizon_rejects_ceil_over_later_network_cap() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-exact-crosses-network",
        shift(3),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(7),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 5 },
            },
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("exact horizon must not round past a later conservative cap");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("network_cap_at=7"));
}

#[test]
fn exact_horizon_rejects_ceil_over_future_cross_node_dependency() {
    let consumer = scheduler_node("runner");
    let producer = scheduler_node("peer");
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-exact-crosses-dependency",
        shift(3),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(40),
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 5 },
            },
        )],
        vec![backend_event(7, &consumer, &producer, 1, b"frame")],
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("exact horizon must not round past an unresolved dependency");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("dependency_at=7"));
}

#[test]
fn idle_wake_equal_to_time_limit_rejects_ceil_overshoot() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-idle-time-limit",
        shift(2),
        8,
        SimInstant { nanos: 9 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 9 },
            },
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("idle wake must not round past an equal time-limit cap");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("target_at=9"));
}

#[test]
fn idle_wake_equal_to_rendezvous_rejects_ceil_overshoot() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-idle-rendezvous",
        shift(2),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 9 },
            },
        )],
        Vec::new(),
    )
    .with_rendezvous_interval(SimDuration { nanos: 9 })
    .expect("rendezvous interval should be valid");
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("idle wake must not round past an equal rendezvous cap");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("target_at=9"));
}

#[test]
fn idle_wake_horizon_uses_same_fixed_shift_ceiling_conversion() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-idle-wake",
        shift(2),
        8,
        SimInstant { nanos: 40 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 9 },
            },
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(outcome.advanced_node, Some(scheduler_node("idle")));
    assert_eq!(publication.target_time, SimInstant { nanos: 9 });
    assert_eq!(publication.icount_shift, shift(2));
    assert_eq!(publication.max_advance_icount, 3);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 12 });
}

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum")
}

fn only_publication(scheduler: &SingleScheduler) -> &crucible::SchedulerRunCeilingPublication {
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    &scheduler.run_ceiling_publications()[0]
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event,
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

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}
