//! Genuine scheduler admission and retained fixed-T input handoff regressions.

use super::*;

#[path = "run_admission/semantic_horizon.rs"]
mod semantic_horizon;

#[path = "run_admission/input_boundary.rs"]
mod input_boundary;

fn runnable(name: &str) -> SchedulerScenarioNode {
    test_scenario_node(
        name,
        0,
        SchedulerNodeActivity::Runnable,
        NetworkLookahead::Infinite,
        ExactLocalEvent::NoArmedTimer,
    )
}

fn prepare(scheduler: &SingleScheduler) -> PreparedHostConcurrentQuantum {
    scheduler
        .prepare_host_concurrent_quantum_limited(
            QuantumRequest {
                configuration: scheduler.configuration().clone(),
                control: Vec::new(),
            },
            usize::MAX,
        )
        .expect("actual scheduler PICK should seal a RUN")
}

#[test]
fn final_preemption_clip_seals_actual_publication_and_semantic_horizon() {
    let mut scheduler = test_scheduler(vec![runnable("a")], Vec::new());
    let command = PreemptionDecision {
        node: NodeId {
            name: String::from("a"),
        },
        at: SimInstant { ticks: 20 },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    };
    scheduler.preemption_requests.push(command.clone());

    let prepared = prepare(&scheduler);
    let run = &prepared.runs[0];

    assert_eq!(run.plan.target_counter, 20);
    assert_eq!(run.admission.dispatch_horizon().icount.retired, 20);
    assert_eq!(run.admission.semantic_horizon().icount.retired, 20);
    assert_eq!(prepared.next.ceiling_publications[0], run.plan.ceiling);
    assert_eq!(run.preemptions[0].decision, command);
    assert_eq!(run.admission.control_token().get(), 1);
}

#[test]
fn complete_inventory_projects_actual_ready_point_mapping() {
    let consumer = scheduler_node("a", SchedulingNodeKind::Vm);
    let producer = scheduler_node("b", SchedulingNodeKind::Network);
    let scenario = SchedulerLivenessScenario::from_canonical_material(
        "rebased-inventory",
        16,
        SimInstant { ticks: 64 },
        vec![test_scenario_node(
            "a",
            100,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Infinite,
            ExactLocalEvent::NoArmedTimer,
        )],
        vec![event(20, &consumer, &producer, 0, b"input")],
    )
    .with_ready_point_counter(consumer, NodeCounter { ticks: 100 });
    let scheduler = SingleScheduler::new(scenario).expect("rebased scenario builds");

    let prepared = prepare(&scheduler);

    assert_eq!(
        prepared.runs[0].admission.input_inventory().next_input(),
        Some(NodeCounter { ticks: 120 })
    );
    assert_eq!(
        prepared.runs[0].admission.dispatch_horizon().icount.retired,
        120
    );
}

#[test]
fn unregistered_publication_and_stale_device_cache_cannot_mint_absence() {
    let scheduler = test_scheduler(vec![runnable("a")], Vec::new());
    let mut prepared = prepare(&scheduler);
    let run = &prepared.runs[0];
    let mut forged = run.plan.clone();
    forged.ceiling.sequence = 30;
    assert!(
        prepared
            .next
            .seal_prepared_run(&forged, 64, None, None)
            .is_err()
    );

    prepared.next = prepared
        .next
        .with_device_sub_node(disk_with_reads("a", "disk", &[(1, 8)]));
    let error = prepared
        .next
        .seal_prepared_run(&run.plan, 64, None, None)
        .expect_err("uncounted live device cannot certify known absence");
    assert!(error.to_string().contains("stale device horizons"));
}

#[test]
fn catchup_cap_preserves_natural_command_horizon_and_committed_prefix_remints() {
    let mut scheduler = test_scheduler(vec![runnable("a")], Vec::new());
    scheduler.preemption_requests.push(PreemptionDecision {
        node: NodeId {
            name: String::from("a"),
        },
        at: SimInstant { ticks: 30 },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    });
    let first = scheduler
        .prepare_host_catchup_run(0, SimInstant { ticks: 10 })
        .expect("catchup plans")
        .expect("runnable source has RUN");
    assert_eq!(first.admission.dispatch_horizon().icount.retired, 10);
    assert_eq!(first.admission.semantic_horizon().icount.retired, 30);
    let original = first.admission.clone();

    scheduler
        .commit_prepared_host_run(first.clone(), 10, &[], Vec::new(), Vec::new())
        .expect("model physical receipt commits");
    let next = scheduler
        .prepare_host_catchup_run_after(&first, SimInstant { ticks: 20 })
        .expect("exact pending command retains natural authority")
        .expect("next RUN");

    assert_eq!(next.admission.semantic_horizon().icount.retired, 30);
    assert_ne!(next.admission.control_token(), original.control_token());
    assert_ne!(next.admission.context(), original.context());
    assert_eq!(original.dispatch_horizon().icount.retired, 10);
}

#[test]
fn genuine_control_and_branch_caps_are_not_queued_service_inputs() {
    let mut scheduler = test_scheduler(vec![runnable("a")], Vec::new());
    scheduler
        .set_branch_frontier_cap(VirtualTime { ticks: 25 })
        .expect("branch cap installs");
    scheduler
        .set_signal_fault_wakeup(Some(20))
        .expect("actual control cap installs");

    let prepared = prepare(&scheduler);

    assert_eq!(
        prepared.runs[0].admission.dispatch_horizon().icount.retired,
        20
    );
    assert_eq!(
        prepared.runs[0].admission.input_inventory().next_input(),
        None
    );
}

#[test]
fn queued_control_refuses_inventory_seal_until_actual_boundary_drain() {
    let prepared = prepare(&test_scheduler(vec![runnable("a")], Vec::new()));
    let run = &prepared.runs[0];
    let mut frontier = prepared.next.clone();
    frontier.queue_control(ControlOperation {
        sequence: 7,
        kind: ControlOperationKind::Query,
    });

    let error = frontier
        .seal_prepared_run(&run.plan, 64, None, None)
        .expect_err("unadmitted controls are not known absence");

    assert!(error.to_string().contains("unadmitted control"));
}

#[test]
fn replacement_command_does_not_reuse_an_immutable_run_owner() {
    let mut frontier = test_scheduler(vec![runnable("a")], Vec::new());
    let mut command = PreemptionDecision {
        node: NodeId {
            name: String::from("a"),
        },
        at: SimInstant { ticks: 30 },
        kind: PreemptionKind::VcpuSwitch {
            from_vcpu: VcpuId { index: 0 },
            to_vcpu: VcpuId { index: 1 },
        },
    };
    frontier.preemption_requests.push(command.clone());
    let first = prepare(&frontier);
    let old = first.runs[0].admission.clone();
    frontier = first.next;
    command.kind = PreemptionKind::VcpuSwitch {
        from_vcpu: VcpuId { index: 1 },
        to_vcpu: VcpuId { index: 0 },
    };
    frontier.preemption_requests[0] = command.clone();
    let next = prepare(&frontier);

    let reminted = next
        .next
        .seal_prepared_run(&next.runs[0].plan, 64, Some(&command), Some(&old))
        .expect("actual replacement has its own authenticated RUN");

    assert_ne!(old.control_token(), reminted.control_token());
    assert_ne!(old.context(), reminted.context());
    assert_eq!(old.semantic_horizon().icount.retired, 30);
}
