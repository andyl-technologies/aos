//! Checks T-SCHED-28 scheduler RR subdivision inside RUN.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    BackendInput, ConcurrentQuantumLoop, ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId,
    QuantumLoop, QuantumRequest, ScheduledEvent, ScheduledEventKey, ScheduledEventPayload,
    SchedulerError, SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerRunSubdivisionPolicy, SchedulerRunSubdivisionSlice, SchedulerScenarioNode,
    SchedulingNodeKind, Shift, SimDuration, SimInstant, SingleScheduler, VcpuId, VirtualTime,
    scheduler_rr_run_subdivision,
};

#[test]
fn multi_vcpu_run_subdivision_uses_fixed_quantum_and_ascending_rotation() {
    let node = scheduler_node("runner");
    let policy = SchedulerRunSubdivisionPolicy::new(node.clone(), 3, 4)
        .expect("RR subdivision policy should be valid");
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "rr-subdivision-multi-vcpu",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                2,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(12),
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        )
        .with_run_subdivision_policy(policy.clone()),
    )
    .expect("scenario should build");

    let outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(outcome.advanced_node, Some(node));
    assert_eq!(outcome.frontier, VirtualTime { ticks: 14 });
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(scheduler.run_subdivision_records().len(), 1);
    let ceiling = &scheduler.run_ceiling_publications()[0];
    let record = &scheduler.run_subdivision_records()[0];
    assert_eq!(record.sequence, 0);
    assert_eq!(record.quantum, 0);
    assert_eq!(record.policy, policy);
    assert_eq!(&record.ceiling, ceiling);
    assert_eq!(
        record.slices,
        vec![
            slice(0, 2, 4),
            slice(1, 4, 8),
            slice(2, 8, 12),
            slice(0, 12, 14),
        ]
    );
}

#[test]
fn concurrent_rr_subdivision_records_one_completed_record_per_outcome() {
    let alpha = scheduler_node("alpha");
    let beta = scheduler_node("beta");
    let alpha_policy = SchedulerRunSubdivisionPolicy::new(alpha.clone(), 2, 3)
        .expect("alpha RR subdivision policy should be valid");
    let beta_policy = SchedulerRunSubdivisionPolicy::new(beta.clone(), 3, 2)
        .expect("beta RR subdivision policy should be valid");
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "rr-subdivision-concurrent",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![
                scenario_node(
                    "alpha",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(6),
                    ExactLocalEvent::NoArmedTimer,
                ),
                scenario_node(
                    "beta",
                    0,
                    SchedulerNodeActivity::Runnable,
                    finite_lookahead(6),
                    ExactLocalEvent::NoArmedTimer,
                ),
            ],
            Vec::new(),
        )
        .with_run_subdivision_policy(beta_policy.clone())
        .with_run_subdivision_policy(alpha_policy.clone()),
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
        .expect("concurrent quantum should drive");

    assert_eq!(round.run_set.candidates.len(), 2);
    assert_eq!(round.outcomes.len(), 2);
    assert_eq!(round.outcomes[0].advanced_node, Some(alpha.clone()));
    assert_eq!(round.outcomes[0].frontier, VirtualTime { ticks: 0 });
    assert_eq!(round.outcomes[1].advanced_node, Some(beta.clone()));
    assert_eq!(round.outcomes[1].frontier, VirtualTime { ticks: 6 });
    assert_eq!(scheduler.run_ceiling_publications().len(), 2);
    assert_eq!(scheduler.run_subdivision_records().len(), 2);
    assert_eq!(
        scheduler.run_subdivision_records()[0].ceiling,
        scheduler.run_ceiling_publications()[0]
    );
    assert_eq!(
        scheduler.run_subdivision_records()[1].ceiling,
        scheduler.run_ceiling_publications()[1]
    );
    assert_eq!(scheduler.run_subdivision_records()[0].policy, alpha_policy);
    assert_eq!(scheduler.run_subdivision_records()[0].quantum, 0);
    assert_eq!(
        scheduler.run_subdivision_records()[0].slices,
        vec![slice(0, 0, 3), slice(1, 3, 6)]
    );
    assert_eq!(scheduler.run_subdivision_records()[1].policy, beta_policy);
    assert_eq!(scheduler.run_subdivision_records()[1].quantum, 0);
    assert_eq!(
        scheduler.run_subdivision_records()[1].slices,
        vec![slice(0, 0, 2), slice(1, 2, 4), slice(2, 4, 6)]
    );
}

#[test]
fn failed_resolve_after_run_plan_records_no_rr_subdivision() {
    let runner = scheduler_node("runner");
    let producer = scheduler_node("producer");
    let mut invalid_event = backend_event(5, &runner, &producer, 0, b"wrong-target");
    if let ScheduledEventPayload::BackendInput(input) = &mut invalid_event.payload {
        input.node = NodeId {
            name: String::from("wrong-target"),
        };
    }
    let policy = SchedulerRunSubdivisionPolicy::new(runner, 2, 3)
        .expect("RR subdivision policy should be valid");
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "rr-subdivision-failed-resolve",
            shift(0),
            8,
            SimInstant { nanos: 20 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(5),
                ExactLocalEvent::NoArmedTimer,
            )],
            vec![invalid_event],
        )
        .with_run_subdivision_policy(policy),
    )
    .expect("scenario should build");

    let error = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect_err("invalid due event should fail during RESOLVE");

    assert!(matches!(error, SchedulerError::BoundaryViolation { .. }));
    assert!(error.to_string().contains("backend input key consumer"));
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert!(scheduler.run_subdivision_records().is_empty());
}

#[test]
fn single_vcpu_subdivision_consumes_whole_budget() {
    let slices = scheduler_rr_run_subdivision(NodeCounter { ticks: 3 }, 11, 1, 4)
        .expect("single-vCPU RR subdivision should be valid");

    assert_eq!(slices, vec![slice(0, 3, 11)]);
}

#[test]
fn run_subdivision_policy_does_not_publish_extra_ceilings() {
    let policy = SchedulerRunSubdivisionPolicy::new(scheduler_node("runner"), 2, 3)
        .expect("RR subdivision policy should be valid");
    let mut scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "rr-subdivision-one-node-ceiling",
            shift(0),
            8,
            SimInstant { nanos: 16 },
            vec![scenario_node(
                "runner",
                0,
                SchedulerNodeActivity::Runnable,
                finite_lookahead(9),
                ExactLocalEvent::NoArmedTimer,
            )],
            Vec::new(),
        )
        .with_run_subdivision_policy(policy),
    )
    .expect("scenario should build");

    let _outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(scheduler.run_subdivision_records().len(), 1);
    assert_eq!(
        scheduler.run_subdivision_records()[0].ceiling,
        scheduler.run_ceiling_publications()[0]
    );
}

#[test]
fn invalid_rr_policy_rejects_zero_quantum_or_vcpus() {
    let zero_vcpus = SchedulerRunSubdivisionPolicy::new(scheduler_node("runner"), 0, 4)
        .expect_err("zero vCPUs should be rejected");
    let zero_quantum = SchedulerRunSubdivisionPolicy::new(scheduler_node("runner"), 2, 0)
        .expect_err("zero RR quantum should be rejected");

    assert!(matches!(
        zero_vcpus,
        SchedulerError::BoundaryViolation { message } if message.contains("vCPU count")
    ));
    assert!(matches!(
        zero_quantum,
        SchedulerError::BoundaryViolation { message } if message.contains("quantum")
    ));
}

#[test]
fn node_without_run_subdivision_policy_records_no_rr_slices() {
    let mut scheduler = SingleScheduler::new(SchedulerLivenessScenario::from_canonical_material(
        "rr-subdivision-no-policy",
        shift(0),
        8,
        SimInstant { nanos: 16 },
        vec![scenario_node(
            "runner",
            0,
            SchedulerNodeActivity::Runnable,
            finite_lookahead(5),
            ExactLocalEvent::NoArmedTimer,
        )],
        Vec::new(),
    ))
    .expect("scenario should build");

    let _outcome = drive_one_quantum(&mut scheduler);

    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert!(scheduler.run_subdivision_records().is_empty());
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

fn shift(bits: u8) -> Shift {
    Shift::new(bits).expect("test shift should be valid")
}

fn finite_lookahead(nanos: u64) -> NetworkLookahead {
    NetworkLookahead::Finite(SimDuration { nanos })
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

fn slice(vcpu: u32, start: u64, end: u64) -> SchedulerRunSubdivisionSlice {
    SchedulerRunSubdivisionSlice {
        vcpu: VcpuId { index: vcpu },
        start_icount: NodeCounter { ticks: start },
        end_icount: NodeCounter { ticks: end },
    }
}
