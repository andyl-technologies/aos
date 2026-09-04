use super::*;

fn permanently_failed_continuation() -> (ScenarioDefForm, ProductionVmHotForkWorldContinuation) {
    let source = super::super::runtime::tests::nonterminal_signal_replay_scenario();
    let mut lifecycle = super::super::runtime::tests::production_loop_without_backends(&source);
    for vm in source.world().vm_nodes() {
        lifecycle.node_generations.insert(vm.id.clone(), 1);
        lifecycle
            .node_service_states
            .insert(vm.id.clone(), ProductionNodeServiceState::PermanentlyFailed);
        lifecycle.immutable_root_images.insert(
            vm.id.clone(),
            ContentHash::from_bytes(vm.id.name.as_bytes()),
        );
    }
    let continuation = lifecycle
        .capture_hot_fork_world_continuation()
        .unwrap_or_else(|error| panic!("process-neutral continuation should capture: {error}"));
    (source, continuation)
}

#[test]
fn empty_backend_world_captures_complete_process_neutral_continuation() {
    let (source, continuation) = permanently_failed_continuation();

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
    let (_source, mut continuation) = permanently_failed_continuation();
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

    assert!(
        error
            .to_string()
            .contains("node continuation is incomplete")
    );
}

#[test]
fn hot_fork_adoption_inventory_requires_the_exact_next_generation() {
    let (_source, mut continuation) = permanently_failed_continuation();
    let boundary = continuation
        .nodes
        .first_mut()
        .unwrap_or_else(|| panic!("fixture should contain a World node"));
    let node = boundary.node.clone();
    boundary.generation = 7;
    boundary.service_state = ProductionVmHotForkNodeServiceState::Running;
    boundary.physical_time = Some(VirtualTime { ticks: 41 });
    boundary.process = Some(QemuProcessIdentity {
        process_id: 123,
        start_time_ticks: 456,
        executable: PathBuf::from("qemu-system-test"),
    });
    continuation.node_generations.insert(node.clone(), 7);
    continuation
        .node_service_states
        .insert(node.clone(), ProductionNodeServiceState::Running);

    let accepted = BTreeMap::from([(node.clone(), 8)]);
    let HotForkAdoptionInventory {
        expected_times,
        node_generations: generations,
    } = validate_hot_fork_adoption_inventory(&continuation, &accepted)
        .unwrap_or_else(|error| panic!("exact next generation should validate: {error}"));
    assert_eq!(expected_times.get(&node), Some(&VirtualTime { ticks: 41 }));
    assert_eq!(generations.get(&node), Some(&8));

    let stale = BTreeMap::from([(node, 7)]);
    let error = validate_hot_fork_adoption_inventory(&continuation, &stale)
        .err()
        .unwrap_or_else(|| panic!("source generation must not be adopted as its child"));
    assert!(error.to_string().contains("expected 8"));
}

#[test]
fn hot_fork_adoption_inventory_rejects_missing_and_foreign_children() {
    let (_source, mut continuation) = permanently_failed_continuation();
    let boundary = continuation
        .nodes
        .first_mut()
        .unwrap_or_else(|| panic!("fixture should contain a World node"));
    let node = boundary.node.clone();
    boundary.service_state = ProductionVmHotForkNodeServiceState::Running;
    boundary.physical_time = Some(VirtualTime { ticks: 1 });
    boundary.process = Some(QemuProcessIdentity {
        process_id: 123,
        start_time_ticks: 456,
        executable: PathBuf::from("qemu-system-test"),
    });
    continuation
        .node_service_states
        .insert(node, ProductionNodeServiceState::Running);

    let missing = validate_hot_fork_adoption_inventory(&continuation, &BTreeMap::new())
        .err()
        .unwrap_or_else(|| panic!("missing running child should fail closed"));
    assert!(missing.to_string().contains("has no adopted child"));

    let foreign = BTreeMap::from([(
        NodeId {
            name: String::from("foreign-hot-fork-node"),
        },
        2,
    )]);
    let foreign = validate_hot_fork_adoption_inventory(&continuation, &foreign)
        .err()
        .unwrap_or_else(|| panic!("foreign child should fail closed"));
    assert!(
        foreign.to_string().contains("has no adopted child")
            || foreign
                .to_string()
                .contains("differs from the running-node set")
    );
}

#[test]
fn hot_fork_adoption_inventory_rejects_powered_off_nodes() {
    let (_source, mut continuation) = permanently_failed_continuation();
    let boundary = continuation
        .nodes
        .first_mut()
        .unwrap_or_else(|| panic!("fixture should contain a World node"));
    let node = boundary.node.clone();
    boundary.service_state = ProductionVmHotForkNodeServiceState::PoweredOff;
    continuation
        .node_service_states
        .insert(node, ProductionNodeServiceState::PoweredOff);

    let error = validate_hot_fork_adoption_inventory(&continuation, &BTreeMap::new())
        .err()
        .unwrap_or_else(|| panic!("powered-off adoption should fail closed"));
    assert!(
        error
            .to_string()
            .contains("does not yet support powered-off")
    );
}

#[test]
fn hot_fork_restore_replaces_only_the_durable_run_root() {
    let (_source, continuation) = permanently_failed_continuation();
    let expected_roots = continuation.immutable_root_images.clone();
    let generations = continuation.node_generations.clone();

    let ProductionVmHotForkRestoreParts {
        config,
        checkpoint,
        immutable_root_images: roots,
        block_bindings: blocks,
        ninep_bindings: ninep,
    } = continuation.into_restore_parts(generations.clone(), "child-run-state");

    assert_eq!(config.run_state_root(), Path::new("child-run-state"));
    assert_eq!(checkpoint.node_generations, generations);
    assert_eq!(roots, expected_roots);
    assert!(blocks.is_empty());
    assert!(ninep.is_empty());
}
