//! Checks T-SCHED-20 horizon virtual-time to icount conversion.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConcurrentQuantumLoop, ExactLocalEvent, Icount, NetworkLookahead, NodeCounter,
    NodeId, NodeTimeMapping, QuantumLoop, QuantumRequest, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerError, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, SharedTimeline, Shift, SimDuration,
    SimInstant, SingleScheduler, TimeConversionError, VirtualTime,
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
fn anchored_floor_projection_contains_targets_on_both_sides_of_anchor() {
    let mapping = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: 1_000 },
        anchor_time: SimInstant { nanos: 50_000 },
    };

    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant { nanos: 49_999 }, shift(7)),
        Ok(NodeCounter { ticks: 999 })
    );
    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant { nanos: 50_000 }, shift(7)),
        Ok(NodeCounter { ticks: 1_000 })
    );
    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant { nanos: 50_127 }, shift(7)),
        Ok(NodeCounter { ticks: 1_000 })
    );
    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant { nanos: 50_128 }, shift(7)),
        Ok(NodeCounter { ticks: 1_001 })
    );
}

#[test]
fn anchored_floor_projection_accepts_exact_lower_bound() {
    let mapping = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: 2 },
        anchor_time: SimInstant { nanos: 256 },
    };

    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant { nanos: 128 }, shift(7)),
        Ok(NodeCounter { ticks: 1 })
    );
    assert_eq!(
        mapping.logical_time(NodeCounter { ticks: 1 }, shift(7)),
        Ok(SimInstant { nanos: 128 })
    );
}

#[test]
fn anchored_floor_projection_rejects_unrepresentable_lower_boundary() {
    let mapping = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: 1 },
        anchor_time: SimInstant { nanos: 1 },
    };

    assert_eq!(
        mapping.counter_for_logical_time_floor(SimInstant::EPOCH, shift(7)),
        Err(TimeConversionError::VirtualTimeOverflow {
            icount: Icount { retired: 0 },
            shift: shift(7),
        })
    );
}

#[test]
fn anchored_floor_projection_rejects_counter_add_and_subtract_overflow() {
    let add_overflow = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: u64::MAX },
        anchor_time: SimInstant::EPOCH,
    };
    let subtract_overflow = NodeTimeMapping {
        anchor_counter: NodeCounter { ticks: 0 },
        anchor_time: SimInstant { nanos: 128 },
    };

    assert_eq!(
        add_overflow.counter_for_logical_time_floor(SimInstant { nanos: 128 }, shift(7)),
        Err(TimeConversionError::VirtualTimeOverflow {
            icount: Icount { retired: u64::MAX },
            shift: shift(7),
        })
    );
    assert_eq!(
        subtract_overflow.counter_for_logical_time_floor(SimInstant::EPOCH, shift(7)),
        Err(TimeConversionError::VirtualTimeOverflow {
            icount: Icount { retired: 0 },
            shift: shift(7),
        })
    );
}

#[test]
fn anchored_floor_projection_rejects_invalid_shift() {
    let invalid = Shift { bits: 64 };

    assert_eq!(
        NodeTimeMapping::IDENTITY.counter_for_logical_time_floor(SimInstant { nanos: 1 }, invalid),
        Err(TimeConversionError::InvalidShift { shift: invalid })
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
fn unaligned_conservative_horizon_publishes_safe_floor_ceiling() {
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

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(publication.current_icount, NodeCounter { ticks: 2 });
    assert_eq!(publication.target_time, SimInstant { nanos: 26 });
    assert_eq!(publication.max_advance_icount, 3);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 24 });
    assert!(outcome.frontier.ticks <= publication.target_time.nanos);
}

#[test]
fn exact_horizon_equal_to_network_cap_waits_for_a_safe_ceil_window() {
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

    let first = drive_one_quantum(&mut scheduler);
    let first_publication = &scheduler.run_ceiling_publications()[0];

    assert_eq!(first_publication.target_time, SimInstant { nanos: 5 });
    assert_eq!(first_publication.max_advance_icount, 1);
    assert_eq!(first.frontier, VirtualTime { ticks: 4 });

    let second = drive_one_quantum(&mut scheduler);
    let second_publication = &scheduler.run_ceiling_publications()[1];

    assert_eq!(second_publication.target_time, SimInstant { nanos: 5 });
    assert_eq!(second_publication.max_advance_icount, 2);
    assert_eq!(second.frontier, VirtualTime { ticks: 8 });
    assert!(second.frontier.ticks <= 9, "the later network cap is 9 ns");
}

#[test]
fn production_shift_seven_network_ceiling_respects_nonzero_ready_anchor() {
    let runner = scheduler_node("curl");
    let ready_counter = NodeCounter { ticks: 9_000_000 };
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-production-network-window",
        shift(7),
        8,
        SimInstant { nanos: 100_000_000 },
        vec![scenario_node(
            "curl",
            ready_counter.ticks,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(4_500_000),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    )
    .with_ready_point_counter(runner, ready_counter);
    let mut scheduler = SingleScheduler::new(scenario).expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(publication.current_icount, ready_counter);
    assert_eq!(publication.target_time, SimInstant { nanos: 4_500_000 });
    assert_eq!(publication.max_advance_icount, 9_035_156);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 4_499_968 });
    assert!(outcome.frontier.ticks <= publication.target_time.nanos);
}

#[test]
fn sub_tick_global_minimum_rejects_before_a_later_node_can_advance() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-sub-tick-global-minimum",
        shift(7),
        8,
        SimInstant { nanos: 1_000 },
        vec![
            scenario_node(
                "blocked",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(1),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "later",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(256),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("the global minimum has no safe counter tick");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert_eq!(scheduler.run_ceiling_publications(), &[]);
    assert_eq!(
        scheduler.scheduler_counter_for_node(&NodeId {
            name: String::from("later"),
        }),
        Ok(NodeCounter { ticks: 0 })
    );
    assert!(error.to_string().contains(
        "target_at_ns=1 projected_target_ns=0 source_counter_ticks=0 \
             source_logical_ns=0 target_counter_ticks=0 anchor_counter_ticks=0 \
             anchor_logical_ns=0 shift_bits=7 nanos_per_counter_tick=128 \
             rounding=conservative_floor"
    ));
}

#[test]
fn later_sub_tick_window_does_not_block_an_earlier_exact_event() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-sub-tick-after-exact-event",
        shift(7),
        8,
        SimInstant { nanos: 1_000 },
        vec![
            scenario_node(
                "sub-tick-later",
                1,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(1),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "exact-first",
                0,
                SchedulerNodeActivity::Runnable,
                NetworkLookahead::Infinite,
                ExactLocalEvent::TimerDeadline {
                    virtual_time: SimInstant { nanos: 64 },
                },
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(outcome.advanced_node, Some(scheduler_node("exact-first")));
    assert_eq!(publication.target_time, SimInstant { nanos: 64 });
    assert_eq!(publication.max_advance_icount, 1);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 128 });
    assert_eq!(
        scheduler.scheduler_counter_for_node(&NodeId {
            name: String::from("sub-tick-later"),
        }),
        Ok(NodeCounter { ticks: 1 })
    );
}

#[test]
fn equal_minimum_defers_sub_tick_candidate_for_advanceable_peer() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-equal-minimum-sub-tick",
        shift(7),
        8,
        SimInstant { nanos: 100_000_000 },
        vec![
            scenario_node(
                "a-sub-tick",
                35_156,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(32),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "b-advanceable",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(4_500_000),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);
    let publication = only_publication(&scheduler);

    assert_eq!(outcome.advanced_node, Some(scheduler_node("b-advanceable")));
    assert_eq!(publication.target_time, SimInstant { nanos: 4_500_000 });
    assert_eq!(publication.max_advance_icount, 35_156);
    assert_eq!(outcome.frontier, VirtualTime { ticks: 4_499_968 });
    assert_eq!(
        scheduler.scheduler_counter_for_node(&NodeId {
            name: String::from("a-sub-tick"),
        }),
        Ok(NodeCounter { ticks: 35_156 })
    );
}

#[test]
fn concurrent_equal_minimum_defers_sub_tick_candidate_for_advanceable_peer() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "icount-ceiling-concurrent-equal-minimum-sub-tick",
        shift(7),
        8,
        SimInstant { nanos: 100_000_000 },
        vec![
            scenario_node(
                "a-sub-tick",
                35_156,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(32),
                ExactLocalEvent::NoArmedTimer,
            ),
            scenario_node(
                "b-advanceable",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(4_500_000),
                ExactLocalEvent::NoArmedTimer,
            ),
        ],
        Vec::new(),
    ))
    .expect("scenario should build");

    let round = scheduler
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            },
            usize::MAX,
        )
        .expect("concurrent scheduler should drive the advanceable peer");

    assert_eq!(round.run_set.candidates.len(), 1);
    assert_eq!(
        round.run_set.candidates[0].node,
        scheduler_node("b-advanceable")
    );
    assert_eq!(round.run_set.candidates[0].max_advance_icount, 35_156);
    assert_eq!(round.outcomes.len(), 1);
    assert_eq!(
        round.outcomes[0].advanced_node,
        Some(scheduler_node("b-advanceable"))
    );
    assert_eq!(round.outcomes[0].frontier, VirtualTime { ticks: 4_499_968 });
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(
        scheduler.scheduler_counter_for_node(&NodeId {
            name: String::from("a-sub-tick"),
        }),
        Ok(NodeCounter { ticks: 35_156 })
    );
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
    assert!(error.to_string().contains("network_cap_at_ns=7"));
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
    assert!(error.to_string().contains("dependency_at_ns=7"));
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

    let first = drive_one_quantum(&mut scheduler);

    assert_eq!(first.frontier, VirtualTime { ticks: 8 });

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("the remaining sub-tick window must not fabricate progress");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("target_at_ns=9"));
    assert!(error.to_string().contains("rounding=conservative_floor"));
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

    let first = drive_one_quantum(&mut scheduler);

    assert_eq!(first.frontier, VirtualTime { ticks: 8 });

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("the remaining sub-tick window must not fabricate progress");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("target_at_ns=9"));
    assert!(error.to_string().contains("rounding=conservative_floor"));
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
