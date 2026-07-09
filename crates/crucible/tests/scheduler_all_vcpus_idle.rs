//! Checks T-SCHED-30 all-vCPUs-idle quiescence.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ExactLocalEvent, NetworkLookahead, NodeCounter, NodeId, QuantumLoop, QuantumRequest,
    SchedulerEffectiveClockSource, SchedulerError, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerNodeVcpuIdleSnapshot,
    SchedulerQuiescenceBlocker, SchedulerRunSubdivisionPolicy, SchedulerScenarioNode,
    SchedulerTerminal, SchedulerVcpuIdleState, SchedulingNodeKind, Shift, SimDuration, SimInstant,
    SingleScheduler, VcpuId, VirtualTime, check_scheduler_liveness,
};

#[test]
fn all_vcpus_halted_without_timer_or_input_are_quiescent() {
    let scheduler = scheduler_with_snapshot(vcpu_snapshot(
        "guest",
        vec![halted_vcpu(0), halted_vcpu(1), halted_vcpu(2)],
    ));

    let quiescence = scheduler
        .quiescence()
        .expect("all-vCPUs-idle quiescence should compute");

    assert!(quiescence.is_quiescent());
    assert_eq!(quiescence.blockers, Vec::new());
}

#[test]
fn active_vcpu_prevents_idle_and_uses_one_node_level_projection() {
    let node = scheduler_node("guest");
    let mut scheduler = scheduler_with_snapshot(vcpu_snapshot(
        "guest",
        vec![halted_vcpu(0), active_vcpu(1), halted_vcpu(2)],
    ));

    let quiescence = scheduler
        .quiescence()
        .expect("active-vCPU quiescence should compute");

    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::ActiveVcpu {
                node: node.clone(),
                vcpu: VcpuId { index: 1 },
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::RunnableNode { node: node.clone() })
    );

    let outcome = scheduler
        .drive_quantum(request(&scheduler))
        .expect("active vCPU should make the node runnable");

    assert_eq!(outcome.advanced_node, Some(node.clone()));
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(scheduler.run_ceiling_publications()[0].node, node);
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        SimInstant { nanos: 8 }
    );
}

#[test]
fn pending_vcpu_input_prevents_idle_even_when_all_vcpus_are_halted() {
    let node = scheduler_node("guest");
    let mut state = halted_vcpu(1);
    state.pending_input = true;
    let scheduler = scheduler_with_snapshot(vcpu_snapshot("guest", vec![halted_vcpu(0), state]));

    let quiescence = scheduler
        .quiescence()
        .expect("pending-input quiescence should compute");

    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingVcpuInput {
                node: node.clone(),
                vcpu: VcpuId { index: 1 },
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::RunnableNode { node })
    );
}

#[test]
fn node_idle_wake_uses_minimum_vcpu_deadline_and_clears_due_timer() {
    let node = scheduler_node("guest");
    let mut scheduler = scheduler_with_snapshot(vcpu_snapshot(
        "guest",
        vec![timer_vcpu(0, 15), timer_vcpu(1, 7), halted_vcpu(2)],
    ));

    let clocks = scheduler
        .effective_clocks()
        .expect("effective clocks should compute");
    assert_eq!(clocks.len(), 1);
    assert_eq!(clocks[0].node, node.clone());
    assert_eq!(clocks[0].source, SchedulerEffectiveClockSource::IdleWake);
    assert_eq!(clocks[0].effective_time, SimInstant { nanos: 7 });

    let outcome = scheduler
        .drive_quantum(request(&scheduler))
        .expect("minimum vCPU deadline should fast-forward the node");

    assert_eq!(outcome.advanced_node, Some(node.clone()));
    assert_eq!(scheduler.frontier(), VirtualTime { ticks: 7 });
    assert_eq!(scheduler.run_ceiling_publications().len(), 1);
    assert_eq!(scheduler.run_ceiling_publications()[0].node, node.clone());
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        SimInstant { nanos: 7 }
    );

    let quiescence = scheduler
        .quiescence()
        .expect("post-wake quiescence should compute");
    assert!(
        !quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingVcpuTimer {
                node: node.clone(),
                vcpu: VcpuId { index: 1 },
                deadline: SimInstant { nanos: 7 },
            })
    );
    assert!(
        quiescence
            .blockers
            .contains(&SchedulerQuiescenceBlocker::PendingVcpuTimer {
                node,
                vcpu: VcpuId { index: 0 },
                deadline: SimInstant { nanos: 15 },
            })
    );
}

#[test]
fn liveness_drains_all_vcpu_deadlines_before_terminal_quiescence() {
    let scenario = base_scenario("all-vcpu-deadlines-drain")
        .with_vcpu_idle_snapshot(vcpu_snapshot(
            "guest",
            vec![timer_vcpu(0, 15), timer_vcpu(1, 7), halted_vcpu(2)],
        ))
        .expect("vCPU snapshot should be valid");

    let report =
        check_scheduler_liveness(scenario).expect("vCPU idle deadlines should not deadlock");

    assert_eq!(report.terminal, SchedulerTerminal::Quiescent);
    assert_eq!(report.frontier, VirtualTime { ticks: 15 });
    assert_eq!(
        report.advanced_nodes,
        vec![scheduler_node("guest"), scheduler_node("guest")]
    );
}

#[test]
fn vcpu_idle_snapshot_rejects_duplicate_vcpu_indices() {
    let error = SchedulerNodeVcpuIdleSnapshot::new(
        scheduler_node("guest"),
        2,
        vec![halted_vcpu(0), timer_vcpu(0, 8)],
    )
    .expect_err("duplicate vCPU indices should fail");

    assert!(
        matches!(error, SchedulerError::BoundaryViolation { message } if message.contains("contiguous vCPUs"))
    );
}

#[test]
fn vcpu_idle_snapshot_rejects_missing_vcpu_coverage() {
    let error =
        SchedulerNodeVcpuIdleSnapshot::new(scheduler_node("guest"), 2, vec![halted_vcpu(0)])
            .expect_err("missing vCPU coverage should fail");

    assert!(
        matches!(error, SchedulerError::BoundaryViolation { message } if message.contains("must cover all 2 vCPUs"))
    );
}

#[test]
fn vcpu_idle_snapshot_count_must_match_rr_subdivision_policy() {
    let scenario = base_scenario("vcpu-idle-rr-policy-count")
        .with_vcpu_idle_snapshot(vcpu_snapshot("guest", vec![halted_vcpu(0), halted_vcpu(1)]))
        .expect("vCPU snapshot should be valid")
        .with_run_subdivision_policy(
            SchedulerRunSubdivisionPolicy::new(scheduler_node("guest"), 3, 4)
                .expect("RR policy should be valid"),
        );

    let error = SingleScheduler::new(scenario).expect_err("mismatched vCPU counts should fail");

    assert!(
        matches!(error, SchedulerError::BoundaryViolation { message } if message.contains("does not match RR policy"))
    );
}

#[test]
fn vcpu_idle_snapshot_participates_in_configuration_identity() {
    let base = base_scenario("vcpu-idle-identity");
    let first = base
        .clone()
        .with_vcpu_idle_snapshot(vcpu_snapshot(
            "guest",
            vec![timer_vcpu(0, 7), halted_vcpu(1)],
        ))
        .expect("first vCPU snapshot should be valid");
    let second = base
        .with_vcpu_idle_snapshot(vcpu_snapshot(
            "guest",
            vec![timer_vcpu(0, 8), halted_vcpu(1)],
        ))
        .expect("second vCPU snapshot should be valid");

    assert_ne!(
        first.canonical_configuration().def.id(),
        second.canonical_configuration().def.id()
    );
}

fn scheduler_with_snapshot(snapshot: SchedulerNodeVcpuIdleSnapshot) -> SingleScheduler {
    SingleScheduler::new(
        base_scenario("all-vcpus-idle-focused")
            .with_vcpu_idle_snapshot(snapshot)
            .expect("vCPU snapshot should be valid"),
    )
    .expect("scheduler should build")
}

fn base_scenario(material: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        shift(0),
        16,
        SimInstant { nanos: 64 },
        vec![SchedulerScenarioNode {
            id: scheduler_node("guest"),
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Idle,
            network_lookahead: NetworkLookahead::Finite(SimDuration { nanos: 8 }),
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
}

fn vcpu_snapshot(name: &str, vcpus: Vec<SchedulerVcpuIdleState>) -> SchedulerNodeVcpuIdleSnapshot {
    let vcpu_count = vcpus
        .len()
        .try_into()
        .expect("test vCPU count should fit in u32");
    SchedulerNodeVcpuIdleSnapshot::new(scheduler_node(name), vcpu_count, vcpus)
        .expect("vCPU snapshot should be valid")
}

fn halted_vcpu(index: u32) -> SchedulerVcpuIdleState {
    SchedulerVcpuIdleState {
        vcpu: VcpuId { index },
        halted: true,
        next_deadline: None,
        pending_input: false,
    }
}

fn active_vcpu(index: u32) -> SchedulerVcpuIdleState {
    SchedulerVcpuIdleState {
        halted: false,
        ..halted_vcpu(index)
    }
}

fn timer_vcpu(index: u32, deadline: u64) -> SchedulerVcpuIdleState {
    SchedulerVcpuIdleState {
        next_deadline: Some(SimInstant { nanos: deadline }),
        ..halted_vcpu(index)
    }
}

fn request(scheduler: &SingleScheduler) -> QuantumRequest {
    QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
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
