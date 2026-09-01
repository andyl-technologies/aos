//! Owned lifecycle work and release barrier tests.

use super::*;

#[test]
fn lifecycle_work_transfer_preserves_buffers_and_holds_barrier_until_release_completion() {
    let action = lifecycle_action(NodeLifecycleTransition::Reset, NodeBootPolicy::Immediate);
    let event = lifecycle_event(&action);
    let node = NodeId {
        name: String::from("node-a"),
    };
    let decision = node_lifecycle_decision(
        &node,
        action.id(),
        &event,
        0,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("lifecycle evidence should authenticate: {error}"))
    .unwrap_or_else(|| panic!("lifecycle evidence should produce a decision"));
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let mut nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"lifecycle-work-transfer"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    runtime.pending_node_lifecycle.push(decision);
    runtime.pending_node_boot.push(node);
    let decision_storage = runtime.pending_node_lifecycle.as_ptr();
    let boot_storage = runtime.pending_node_boot.as_ptr();

    let work = runtime
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("lifecycle work should transfer: {error}"));

    assert_eq!(work.decisions().as_ptr(), decision_storage);
    assert_eq!(work.boot_requests().as_ptr(), boot_storage);
    assert!(runtime.pending_node_lifecycle.is_empty());
    assert!(runtime.pending_node_boot.is_empty());
    assert_barrier(&mut runtime, &mut nodes);
    assert!(matches!(
        runtime.take_node_lifecycle_work(),
        Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork)
    ));
    let release = runtime
        .acknowledge_node_lifecycle_work(work)
        .unwrap_or_else(|_| panic!("owned lifecycle work should acknowledge"));
    assert_barrier(&mut runtime, &mut nodes);
    runtime
        .complete_node_lifecycle_release(release)
        .unwrap_or_else(|_| panic!("owned lifecycle release should complete"));
    runtime
        .checkpoint(&mut nodes)
        .unwrap_or_else(|error| panic!("completed lifecycle ownership should checkpoint: {error}"));
    runtime
        .evaluate_boundary(test_coordinate(), 0, &mut nodes)
        .unwrap_or_else(|error| panic!("completed lifecycle ownership should evaluate: {error}"));
    runtime
        .set_boundary_snapshot(SignalBoundarySnapshot::default())
        .unwrap_or_else(|error| panic!("completed lifecycle ownership should mutate: {error}"));
    let empty = runtime
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("empty lifecycle work should transfer: {error}"));
    let empty_release = runtime
        .acknowledge_node_lifecycle_work(empty)
        .unwrap_or_else(|_| panic!("empty lifecycle work should acknowledge"));
    runtime
        .complete_node_lifecycle_release(empty_release)
        .unwrap_or_else(|_| panic!("empty lifecycle release should complete"));
}

fn assert_barrier(runtime: &mut ProductionFaultRuntime, nodes: &mut QemuNodeSet) {
    assert!(matches!(
        runtime.checkpoint(nodes),
        Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork)
    ));
    assert!(matches!(
        runtime.evaluate_boundary(test_coordinate(), 0, nodes),
        Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork)
    ));
    assert!(matches!(
        runtime.set_boundary_snapshot(SignalBoundarySnapshot::default()),
        Err(ProductionFaultRuntimeError::PendingNodeLifecycleWork)
    ));
}

const fn test_coordinate() -> FaultCoordinate {
    FaultCoordinate {
        virtual_nanos: 0,
        retired_instructions: None,
    }
}

#[test]
fn lifecycle_owners_are_bound_to_the_creating_runtime_instance() {
    let node = NodeId {
        name: String::from("node-a"),
    };
    assert_cross_runtime_rejection(runtime_with_boot(&node), runtime_with_boot(&node));

    let original = runtime_with_boot(&node);
    let transactional_clone = original
        .try_clone()
        .unwrap_or_else(|error| panic!("runtime should clone before work transfer: {error}"));
    assert_cross_runtime_rejection(original, transactional_clone);
}

fn runtime_with_boot(node: &NodeId) -> ProductionFaultRuntime {
    let plan = FaultSignalPlan::new(Vec::new(), Vec::new(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("empty test plan should be valid: {error}"));
    let nodes = QemuNodeSet::new();
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        None,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"lifecycle-owner-instance"),
        test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("empty runtime should initialize: {error}"));
    runtime.pending_node_boot.push(node.clone());
    runtime
}

fn assert_cross_runtime_rejection(
    mut first: ProductionFaultRuntime,
    mut second: ProductionFaultRuntime,
) {
    let first_work = first
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("first work should transfer: {error}"));
    let second_work = second
        .take_node_lifecycle_work()
        .unwrap_or_else(|error| panic!("second work should transfer: {error}"));
    let second_work = match first.acknowledge_node_lifecycle_work(second_work) {
        Ok(_release) => panic!("a foreign work owner must be rejected"),
        Err(work) => work,
    };
    let first_release = first
        .acknowledge_node_lifecycle_work(first_work)
        .unwrap_or_else(|_| panic!("the creating runtime should acknowledge its work"));
    let second_release = second
        .acknowledge_node_lifecycle_work(second_work)
        .unwrap_or_else(|_| panic!("the creating runtime should acknowledge its work"));
    let second_release = match first.complete_node_lifecycle_release(second_release) {
        Ok(()) => panic!("a foreign release owner must be rejected"),
        Err(release) => release,
    };
    first
        .complete_node_lifecycle_release(first_release)
        .unwrap_or_else(|_| panic!("the creating runtime should complete its release"));
    second
        .complete_node_lifecycle_release(second_release)
        .unwrap_or_else(|_| panic!("the creating runtime should complete its release"));
}
