//! Checks T-SCHED-29 scheduler-side preemption RESOLVE.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConcurrentQuantumLoop, Decision, EventKey, ExactLocalEvent, Icount, IrqVector,
    NetworkLookahead, NodeCounter, NodeId, PreemptionDecision, PreemptionKind, QuantumLoop,
    QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload, SchedulerError,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId, SchedulerQuiescenceBlocker,
    SchedulerScenarioNode, SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler,
    VcpuId, VirtualTime,
};

#[test]
fn preemption_within_window_records_decision_and_application_in_total_order() {
    let runner = scheduler_node("runner");
    let producer = scheduler_node("producer");
    let preemption = interrupt_preemption("runner", 4, 32);
    let event = backend_event(8, &runner, &producer, 0, b"input");
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-in-window",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(10),
            )],
            vec![event.clone()],
        )
        .with_preemption_request(preemption.clone()),
    )
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(runner));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 8 });
    assert_eq!(
        outcome.decisions,
        vec![
            Decision::Preemption(preemption.clone()),
            Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 8 },
                order: vec![event_key(&event)],
            }),
        ]
    );
    assert_eq!(
        outcome
            .event_log_entries
            .iter()
            .map(|entry| entry.at())
            .collect::<Vec<_>>(),
        vec![
            VirtualTime { ticks: 4 },
            VirtualTime { ticks: 8 },
            VirtualTime { ticks: 8 },
            VirtualTime { ticks: 8 },
        ]
    );
    assert!(matches!(
        outcome.event_log_entries[0].payload(),
        crucible::SchedulerEventLogPayload::Decision(Decision::Preemption(decision))
            if decision == &preemption
    ));
    assert_eq!(scheduler.preemption_applications().len(), 1);
    let application = &scheduler.preemption_applications()[0];
    assert_eq!(application.sequence, 0);
    assert_eq!(application.quantum, 0);
    assert_eq!(application.decision, preemption);
    assert_eq!(application.deadline_icount, Icount { retired: 0 });
    assert_eq!(application.horizon_icount, Icount { retired: 8 });
    assert_eq!(application.ceiling, scheduler.run_ceiling_publications()[0]);
}

#[test]
fn preemption_at_authorized_ceiling_is_allowed() {
    let preemption = interrupt_preemption("runner", 6, 33);
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-at-ceiling",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(6),
            )],
            Vec::new(),
        )
        .with_preemption_request(preemption.clone()),
    )
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.frontier, VirtualTime { ticks: 6 });
    assert_eq!(outcome.decisions, vec![Decision::Preemption(preemption)]);
    assert_eq!(scheduler.preemption_applications().len(), 1);
}

#[test]
fn preemption_waits_for_vm_node_not_same_named_subnode() {
    let preemption = interrupt_preemption("guest", 4, 34);
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-vm-only",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![
                SchedulerScenarioNode {
                    id: SchedulerNodeId {
                        node: NodeId {
                            name: String::from("guest"),
                        },
                        kind: SchedulingNodeKind::Disk,
                    },
                    counter: NodeCounter { ticks: 0 },
                    activity: SchedulerNodeActivity::Runnable,
                    network_lookahead: finite_lookahead(2),
                    exact_local_event: ExactLocalEvent::NoArmedTimer,
                },
                scenario_node(
                    "guest",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(5),
                ),
            ],
            Vec::new(),
        )
        .with_preemption_request(preemption.clone()),
    )
    .expect("scenario should build");

    let disk = drive_one_quantum(&mut scheduler);

    assert_eq!(
        disk.advanced_node,
        Some(SchedulerNodeId {
            node: NodeId {
                name: String::from("guest"),
            },
            kind: SchedulingNodeKind::Disk,
        })
    );
    assert!(disk.decisions.is_empty());
    assert!(scheduler.preemption_applications().is_empty());
    let vm = drive_one_quantum(&mut scheduler);

    assert_eq!(vm.advanced_node, Some(scheduler_node("guest")));
    assert_eq!(vm.decisions, vec![Decision::Preemption(preemption)]);
    assert_eq!(scheduler.preemption_applications().len(), 1);
}

#[test]
fn preemption_past_authorized_ceiling_fails_without_application() {
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-past-ceiling",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(6),
            )],
            Vec::new(),
        )
        .with_preemption_request(interrupt_preemption("runner", 7, 34)),
    )
    .expect("scenario should build");
    let before_configuration = scheduler.configuration().clone();
    let before_frontier = scheduler.frontier();

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("preemption past ceiling must fail");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("outside authorized window"));
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.frontier(), before_frontier);
    assert!(scheduler.preemption_applications().is_empty());
}

#[test]
fn preemption_before_deadline_fails_without_application() {
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-before-deadline",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                5,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(5),
            )],
            Vec::new(),
        )
        .with_preemption_request(interrupt_preemption("runner", 4, 35)),
    )
    .expect("scenario should build");
    let before_configuration = scheduler.configuration().clone();
    let before_frontier = scheduler.frontier();

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("preemption before deadline must fail");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("deadline=5"));
    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.frontier(), before_frontier);
    assert!(scheduler.preemption_applications().is_empty());
}

#[test]
fn multiple_preemptions_for_one_run_fail_before_advance() {
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-one-command-per-run",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(12),
            )],
            Vec::new(),
        )
        .with_preemption_request(interrupt_preemption("runner", 2, 38))
        .with_preemption_request(interrupt_preemption("runner", 10, 39)),
    )
    .expect("scenario should build");
    let before_configuration = scheduler.configuration().clone();
    let before_frontier = scheduler.frontier();

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("multiple preemptions in one RUN cannot be globally ordered");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("multiple explorer preemptions"));
    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.frontier(), before_frontier);
    assert!(scheduler.preemption_applications().is_empty());
}

#[test]
fn concurrent_preemption_validation_is_all_or_nothing() {
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-concurrent-all-or-nothing",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![
                scenario_node(
                    "alpha",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(6),
                ),
                scenario_node(
                    "beta",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(6),
                ),
            ],
            Vec::new(),
        )
        .with_preemption_request(interrupt_preemption("alpha", 3, 38))
        .with_preemption_request(interrupt_preemption("beta", 7, 39)),
    )
    .expect("scenario should build");
    let before_configuration = scheduler.configuration().clone();
    let before_frontier = scheduler.frontier();

    let error = scheduler
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect_err("invalid concurrent preemption should fail before any selected run commits");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("outside authorized window"));
    assert_eq!(scheduler.run_ceiling_publications().len(), 2);
    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.frontier(), before_frontier);
    assert!(scheduler.preemption_applications().is_empty());
}

#[test]
fn concurrent_multiple_preemptions_for_one_run_fail_before_any_commit() {
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-concurrent-multiple-one-run",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![
                scenario_node(
                    "alpha",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(12),
                ),
                scenario_node(
                    "beta",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(12),
                ),
            ],
            Vec::new(),
        )
        .with_preemption_request(interrupt_preemption("alpha", 2, 40))
        .with_preemption_request(interrupt_preemption("alpha", 10, 41))
        .with_preemption_request(interrupt_preemption("beta", 5, 42)),
    )
    .expect("scenario should build");
    let before_configuration = scheduler.configuration().clone();
    let before_frontier = scheduler.frontier();

    let error = scheduler
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect_err("multiple preemptions for one concurrent RUN should fail before commits");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("multiple explorer preemptions"));
    assert_eq!(scheduler.run_ceiling_publications().len(), 2);
    assert_eq!(scheduler.configuration(), &before_configuration);
    assert_eq!(scheduler.frontier(), before_frontier);
    assert!(scheduler.preemption_applications().is_empty());
}

#[test]
fn concurrent_preemptions_record_in_commanded_time_order() {
    let alpha = interrupt_preemption("alpha", 5, 40);
    let beta = interrupt_preemption("beta", 2, 41);
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-concurrent-total-order",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![
                scenario_node(
                    "alpha",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(6),
                ),
                scenario_node(
                    "beta",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(6),
                ),
            ],
            Vec::new(),
        )
        .with_preemption_request(alpha.clone())
        .with_preemption_request(beta.clone()),
    )
    .expect("scenario should build");

    let round = scheduler
        .drive_concurrent_quantum(
            QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            },
            2,
        )
        .expect("concurrent preemption round should drive");

    assert_eq!(round.run_set.candidates[0].node, scheduler_node("alpha"));
    assert_eq!(round.run_set.candidates[1].node, scheduler_node("beta"));
    assert_eq!(
        round.outcomes[0].advanced_node,
        Some(scheduler_node("beta"))
    );
    assert_eq!(
        round.outcomes[1].advanced_node,
        Some(scheduler_node("alpha"))
    );
    assert_eq!(
        scheduler.configuration().schedule.decisions(),
        &[
            Decision::Preemption(beta.clone()),
            Decision::Preemption(alpha.clone()),
        ]
    );
    assert_eq!(
        scheduler
            .preemption_applications()
            .iter()
            .map(|application| application.decision.clone())
            .collect::<Vec<_>>(),
        vec![beta.clone(), alpha.clone()]
    );
    assert_eq!(
        round
            .outcomes
            .iter()
            .flat_map(|outcome| outcome.event_log_entries.iter())
            .map(|entry| entry.at())
            .collect::<Vec<_>>(),
        vec![
            VirtualTime { ticks: 2 },
            VirtualTime { ticks: 6 },
            VirtualTime { ticks: 5 },
            VirtualTime { ticks: 6 },
        ]
    );
}

#[test]
fn pending_preemption_blocks_quiescence_until_applied() {
    let preemption = interrupt_preemption("runner", 1, 36);
    let scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "preemption-resolve-quiescence",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
            )],
            Vec::new(),
        )
        .with_preemption_request(preemption.clone()),
    )
    .expect("scenario should build");

    let quiescence = scheduler
        .quiescence()
        .expect("quiescence should compute with pending preemption");

    assert_eq!(
        quiescence.blockers,
        vec![SchedulerQuiescenceBlocker::PendingPreemption {
            decision: preemption
        }]
    );
}

#[test]
fn preemption_requests_participate_in_configuration_identity() {
    let base = SchedulerLivenessScenario::from_canonical_material(
        "preemption-resolve-identity",
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(6),
        )],
        Vec::new(),
    );
    let first = base
        .clone()
        .with_preemption_request(interrupt_preemption("runner", 3, 37));
    let second = base.with_preemption_request(interrupt_preemption("runner", 4, 37));

    assert_ne!(first.configuration, second.configuration);
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
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
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

fn interrupt_preemption(node: &str, at: u64, irq: u32) -> PreemptionDecision {
    PreemptionDecision {
        node: NodeId {
            name: node.to_owned(),
        },
        at: Icount { retired: at },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: irq },
        },
    }
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

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
}
