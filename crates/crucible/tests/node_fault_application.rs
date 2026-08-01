//! Checks T-FAULT-7 node timing fault application on VM scheduler nodes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    CombinedNodeFaults, Decision, ExactLocalEvent, FaultSlowdownFactorBasisPoints, Icount,
    IrqVector, NetworkLookahead, NodeCounter, NodeId, PreemptionDecision, PreemptionKind,
    QuantumLoop, QuantumRequest, SchedulerEventLogPayload, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift,
    SimDuration, SimInstant, SimOffset, SingleScheduler, VcpuId, VirtualTime,
    apply_combined_node_timing_faults_to_scheduler, node_timing_faults_from_combined_node,
};
use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore};

#[test]
fn slow_projection_anchors_at_activation_without_rewinding_time() {
    let slow = slowdown(20_000);
    let faults = CombinedNodeFaults {
        slow_factor: Some(slow),
        ..CombinedNodeFaults::default()
    };
    let timing = node_timing_faults_from_combined_node(
        &faults,
        NodeCounter { ticks: 100 },
        SimInstant { nanos: 100 },
    );

    let projection = ok(timing.project(NodeCounter { ticks: 120 }, Shift { bits: 0 }));
    assert_eq!(projection.unfaulted_time, SimInstant { nanos: 120 });
    assert_eq!(
        projection.faulted_time,
        SimInstant { nanos: 110 },
        "2x slow advances scheduler time by one tick for every two retired instructions"
    );
    assert_eq!(projection.guest_visible_time, SimInstant { nanos: 110 });
    assert_eq!(
        ok(timing
            .counter_for_faulted_virtual_time_ceil(SimInstant { nanos: 110 }, Shift { bits: 0 })),
        NodeCounter { ticks: 120 }
    );
    assert_eq!(
        ok(timing
            .counter_for_faulted_virtual_time_ceil(SimInstant { nanos: 111 }, Shift { bits: 0 })),
        NodeCounter { ticks: 122 },
        "ceil conversion keeps RUN ceilings at or after the slowed target time"
    );
}

#[test]
fn slow_fault_stretches_scheduler_run_ceiling_without_changing_counters() {
    let node = node_id("vm-a");
    let mut scheduler = ok(SingleScheduler::new(single_vm_scenario(
        "node-slow-run-ceiling",
        &node,
        10,
        40,
    )));
    let faults = CombinedNodeFaults {
        slow_factor: Some(slowdown(20_000)),
        ..CombinedNodeFaults::default()
    };

    let timing = ok(apply_combined_node_timing_faults_to_scheduler(
        &mut scheduler,
        &node,
        &faults,
    ));
    assert_eq!(timing.anchor_counter, NodeCounter { ticks: 10 });
    assert_eq!(timing.anchor_time, SimInstant { nanos: 10 });

    let outcome = drive_scheduler(&mut scheduler);
    assert_eq!(outcome.frontier.ticks, 20);
    let ceiling = scheduler
        .run_ceiling_publications()
        .first()
        .unwrap_or_else(|| panic!("RUN ceiling should be published"));
    assert_eq!(ceiling.current_icount, NodeCounter { ticks: 10 });
    assert_eq!(
        ceiling.max_advance_icount, 30,
        "the VM retires twenty more instructions to advance ten slowed virtual ticks"
    );
    assert_eq!(ceiling.target_time, SimInstant { nanos: 20 });

    let projection = ok(scheduler.node_timing_projection(&node));
    assert_eq!(projection.counter, NodeCounter { ticks: 30 });
    assert_eq!(projection.unfaulted_time, SimInstant { nanos: 30 });
    assert_eq!(projection.faulted_time, SimInstant { nanos: 20 });
}

#[test]
fn clock_skew_offsets_guest_time_without_moving_scheduler_axis() {
    let node = node_id("vm-a");
    let mut scheduler = ok(SingleScheduler::new(single_vm_scenario(
        "node-clock-skew",
        &node,
        40,
        80,
    )));
    let faults = CombinedNodeFaults {
        clock_skew: SimOffset { nanos: 7 },
        ..CombinedNodeFaults::default()
    };

    let timing = ok(apply_combined_node_timing_faults_to_scheduler(
        &mut scheduler,
        &node,
        &faults,
    ));
    assert_eq!(timing.anchor_counter, NodeCounter { ticks: 40 });
    assert_eq!(timing.anchor_time, SimInstant { nanos: 40 });

    let projection = ok(scheduler.node_timing_projection(&node));
    assert_eq!(projection.faulted_time, SimInstant { nanos: 40 });
    assert_eq!(projection.guest_visible_time, SimInstant { nanos: 47 });
    assert_eq!(
        ok(scheduler.guest_visible_time_for_node(&node)),
        SimInstant { nanos: 47 }
    );

    let clocks = ok(scheduler.effective_clocks());
    assert_eq!(clocks[0].current_time, SimInstant { nanos: 40 });
    assert_eq!(
        clocks[0].effective_time,
        SimInstant { nanos: 40 },
        "guest-visible skew is not a scheduler horizon or ordering input"
    );

    let _ = drive_scheduler(&mut scheduler);
    let ceiling = scheduler
        .run_ceiling_publications()
        .first()
        .unwrap_or_else(|| panic!("RUN ceiling should be published"));
    assert_eq!(
        ceiling.max_advance_icount, 50,
        "clock skew alone must not alter the icount ceiling"
    );
}

#[test]
fn slowed_preemption_event_time_uses_faulted_virtual_projection() {
    let node = node_id("vm-a");
    let preemption = PreemptionDecision {
        node: node.clone(),
        at: Icount { retired: 20 },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 33 },
        },
    };
    let mut scheduler = ok(SingleScheduler::new(
        single_vm_scenario("node-slow-preemption-time", &node, 10, 40)
            .with_preemption_request(preemption.clone()),
    ));
    let faults = CombinedNodeFaults {
        slow_factor: Some(slowdown(20_000)),
        ..CombinedNodeFaults::default()
    };
    let _ = ok(apply_combined_node_timing_faults_to_scheduler(
        &mut scheduler,
        &node,
        &faults,
    ));

    let outcome = drive_scheduler(&mut scheduler);

    assert_eq!(
        outcome
            .event_log_entries
            .iter()
            .map(|entry| entry.at())
            .collect::<Vec<_>>(),
        vec![VirtualTime { ticks: 15 }, VirtualTime { ticks: 20 }],
        "the preemption event is logged at the slowed projection of icount 20"
    );
    assert!(matches!(
        outcome.event_log_entries[0].payload(),
        SchedulerEventLogPayload::Decision(Decision::Preemption(decision))
            if decision == &preemption
    ));
    let application = scheduler
        .preemption_applications()
        .first()
        .unwrap_or_else(|| panic!("preemption should be recorded"));
    assert_eq!(application.virtual_time, SimInstant { nanos: 15 });
}

#[test]
fn slowed_device_completion_event_key_uses_faulted_virtual_projection() {
    let node = node_id("vm-a");
    let mut scenario = single_vm_scenario("node-slow-device-completion-time", &node, 10, 600);
    scenario.nodes[0].network_lookahead = NetworkLookahead::Infinite;
    let mut scheduler = ok(SingleScheduler::new(scenario));
    scheduler = scheduler.with_device_sub_node(block_sub_node(&node, "disk-a", 10, 8));
    let faults = CombinedNodeFaults {
        slow_factor: Some(slowdown(20_000)),
        ..CombinedNodeFaults::default()
    };
    let _ = ok(apply_combined_node_timing_faults_to_scheduler(
        &mut scheduler,
        &node,
        &faults,
    ));

    let outcome = drive_scheduler(&mut scheduler);

    assert_eq!(
        scheduler.run_ceiling_publications()[0].max_advance_icount,
        1018,
        "the VM still retires to the device's exact raw delivery icount"
    );
    assert_eq!(
        scheduler.run_ceiling_publications()[0].target_time,
        SimInstant { nanos: 514 },
        "the exact I/O horizon is projected through the active slow map"
    );
    assert_eq!(outcome.resolved_events.len(), 1);
    assert_eq!(
        outcome.resolved_events[0].key.virtual_time(),
        VirtualTime { ticks: 514 },
        "the resolved I/O event key uses the slowed scheduler time, not raw icount 1018"
    );
    assert_eq!(
        outcome
            .event_log_entries
            .first()
            .unwrap_or_else(|| panic!("I/O completion should be logged"))
            .at(),
        VirtualTime { ticks: 514 }
    );
}

fn single_vm_scenario(
    material: &str,
    node: &NodeId,
    counter: u64,
    time_limit: u64,
) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        material,
        Shift { bits: 0 },
        4,
        SimInstant { nanos: time_limit },
        vec![SchedulerScenarioNode {
            id: scheduler_node(node),
            counter: NodeCounter { ticks: counter },
            activity: SchedulerNodeActivity::Runnable,
            network_lookahead: NetworkLookahead::Finite(SimDuration { nanos: 10 }),
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
}

fn scheduler_node(node: &NodeId) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node.clone(),
        kind: SchedulingNodeKind::Vm,
    }
}

fn block_sub_node(
    target: &NodeId,
    device_name: &str,
    request_icount: u64,
    count: u32,
) -> crucible::DeviceSchedulingSubNode {
    let core = ok(IoCore::new(0, 1, 16, 16));
    let block = BlockDevice::new(
        core,
        BaseImage::new(vec![0x5a; 4096]),
        BlockLatency::default(),
    );
    let device_id = crucible::DeviceId {
        name: device_name.to_owned(),
    };
    let mut sub_node = crucible::DeviceSchedulingSubNode::new(
        SchedulerNodeId {
            node: NodeId {
                name: device_name.to_owned(),
            },
            kind: SchedulingNodeKind::Disk,
        },
        target.clone(),
        device_id,
        block,
        crucible::Seed::from_u64(0x0d15_c0de),
    );
    ok(sub_node.submit(request_icount, &BlockRequest::read(1, 0, count)));
    sub_node
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn slowdown(basis_points: u32) -> FaultSlowdownFactorBasisPoints {
    FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid slowdown factor: {error}"))
}

fn drive_scheduler(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    let request = QuantumRequest {
        configuration: scheduler.configuration().clone(),
        control: Vec::new(),
    };
    ok(scheduler.drive_quantum(request))
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}
