use super::*;

#[test]
fn empty_backend_world_captures_complete_process_neutral_continuation() {
    let source = super::super::runtime::tests::nonterminal_signal_replay_scenario();
    let mut lifecycle = super::super::runtime::tests::production_loop_without_backends(&source);
    for vm in source.world().vm_nodes() {
        lifecycle.node_generations.insert(vm.id.clone(), 1);
        lifecycle
            .node_service_states
            .insert(vm.id.clone(), ProductionNodeServiceState::PermanentlyFailed);
    }

    let continuation = lifecycle
        .capture_hot_fork_world_continuation()
        .unwrap_or_else(|error| panic!("process-neutral continuation should capture: {error}"));

    assert_eq!(continuation.configuration().def, source.scenario_def());
    assert_eq!(
        continuation
            .scheduler()
            .configuration_for(&source.scenario_def()),
        Ok(continuation.configuration().clone())
    );
    assert_eq!(continuation.nodes().len(), source.world().vm_nodes().len());
    assert!(continuation.nodes().iter().all(|node| {
        node.generation() == 1
            && node.service_state() == ProductionVmHotForkNodeServiceState::PermanentlyFailed
            && node.physical_time().is_none()
            && node.process().is_none()
    }));
    assert_eq!(
        continuation.fault_checkpoint_identity(),
        continuation.fault_checkpoint.id()
    );
    continuation
        .validate_complete_internal_state()
        .unwrap_or_else(|error| panic!("captured continuation should remain complete: {error}"));
}

#[test]
fn hot_fork_capture_rejects_unresolved_lifecycle_ownership() {
    let source = super::super::runtime::tests::nonterminal_signal_replay_scenario();
    let mut lifecycle = super::super::runtime::tests::production_loop_without_backends(&source);
    lifecycle.node_lease_cleanup_failed = true;

    let error = lifecycle
        .capture_hot_fork_world_continuation()
        .err()
        .unwrap_or_else(|| panic!("unresolved lifecycle ownership should fail closed"));

    assert!(
        error
            .to_string()
            .contains("unresolved process-lifecycle ownership")
    );
}

#[test]
fn hot_fork_continuation_rejects_a_cross_node_generation_map() {
    let source = super::super::runtime::tests::nonterminal_signal_replay_scenario();
    let mut lifecycle = super::super::runtime::tests::production_loop_without_backends(&source);
    for vm in source.world().vm_nodes() {
        lifecycle.node_generations.insert(vm.id.clone(), 1);
        lifecycle
            .node_service_states
            .insert(vm.id.clone(), ProductionNodeServiceState::PermanentlyFailed);
    }
    let mut continuation = lifecycle
        .capture_hot_fork_world_continuation()
        .unwrap_or_else(|error| panic!("process-neutral continuation should capture: {error}"));
    let first = continuation
        .nodes
        .first()
        .unwrap_or_else(|| panic!("fixture should contain a World node"))
        .node
        .clone();
    continuation.node_generations.remove(&first);
    continuation.node_generations.insert(
        NodeId {
            name: String::from("foreign-hot-fork-node"),
        },
        1,
    );

    let error = continuation
        .validate_complete_internal_state()
        .err()
        .unwrap_or_else(|| panic!("cross-node continuation should fail closed"));

    assert!(error.to_string().contains("node continuation is incomplete"));
}
