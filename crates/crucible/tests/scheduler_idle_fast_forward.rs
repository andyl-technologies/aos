//! Checks the T-SCHED-15 idle fast-forward projection.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerEffectiveClockSource, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerScenarioNode, SchedulerTerminal, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, SingleScheduler, VirtualTime, check_scheduler_liveness,
};

#[test]
fn idle_fast_forward_jumps_to_exact_timer_wake_without_schedule_decision() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-fast-forward-timer",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 23 },
            },
        )],
        Vec::new(),
    );

    let report = check_scheduler_liveness(scenario).expect("idle timer wake should fast-forward");

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.frontier, VirtualTime { ticks: 23 });
    assert_eq!(
        report.advanced_nodes,
        vec![scheduler_node("idle", SchedulingNodeKind::Vm)]
    );
    assert!(report.final_configuration.schedule.is_empty());
}

#[test]
fn idle_effective_clock_uses_wake_time_and_does_not_constrain_peer_behind_it() {
    let runner = scheduler_node("runner", SchedulingNodeKind::Vm);
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "idle-effective-clock-peer",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![
            scenario_node(
                "idle",
                0,
                SchedulerNodeActivity::Idle,
                finite_lookahead(1),
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 100 },
                },
            ),
            scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(4),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");

    let clocks = scheduler
        .effective_clocks()
        .expect("effective clocks should compute");
    let idle_clock = clocks
        .iter()
        .find(|clock| clock.node == scheduler_node("idle", SchedulingNodeKind::Vm))
        .expect("idle clock should be present");

    assert_eq!(idle_clock.current_time, SimInstant { nanos: 0 });
    assert_eq!(idle_clock.effective_time, SimInstant { nanos: 100 });
    assert_eq!(idle_clock.source, SchedulerEffectiveClockSource::IdleWake);

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("peer behind idle wake should advance");

    assert_eq!(outcome.advanced_node, Some(runner));
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(
        scheduler.run_ceiling_publications()[0].max_advance_icount,
        4
    );
}

#[test]
fn idle_fast_forward_uses_earliest_pending_delivery_as_wake() {
    let consumer = scheduler_node("idle", SchedulingNodeKind::Vm);
    let producer = scheduler_node("peer", SchedulingNodeKind::Vm);
    let due = backend_event(17, &consumer, &producer, 1, b"wake");
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-fast-forward-pending-delivery",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![due.clone()],
    );

    let report =
        check_scheduler_liveness(scenario).expect("idle pending delivery should fast-forward");

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.frontier, VirtualTime { ticks: 17 });
    assert_eq!(report.resolved_events, 1);
}

#[test]
fn idle_fast_forward_clamps_exact_wake_to_time_limit() {
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "idle-fast-forward-limit",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![scenario_node(
            "idle",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::TimerDeadline {
                virtual_time: SimInstant { nanos: 100 },
            },
        )],
        Vec::new(),
    );

    let report = check_scheduler_liveness(scenario).expect("idle wake should clamp to limit");

    assert_eq!(report.terminal, SchedulerTerminal::TimeLimitReached);
    assert_eq!(report.frontier, VirtualTime { ticks: 64 });
}

#[test]
fn idle_without_wake_keeps_current_effective_clock_and_produces_no_advance() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "idle-fast-forward-no-wake",
        shift(0),
        8,
        SimInstant { nanos: 64 },
        vec![scenario_node(
            "idle",
            7,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let clocks = scheduler
        .effective_clocks()
        .expect("effective clocks should compute");

    assert_eq!(clocks.len(), 1);
    assert_eq!(clocks[0].current_time, SimInstant { nanos: 7 });
    assert_eq!(clocks[0].effective_time, SimInstant { nanos: 7 });
    assert_eq!(clocks[0].source, SchedulerEffectiveClockSource::Current);

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("idle no-wake quantum should drive");

    assert_eq!(outcome.advanced_node, None);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 7 });
}

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
    exact_local_event: ExactLocalEvent,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name, SchedulingNodeKind::Vm),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event,
    }
}

fn scheduler_node(name: &str, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind,
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
