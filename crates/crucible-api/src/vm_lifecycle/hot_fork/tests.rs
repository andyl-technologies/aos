//! Tests exact host-world continuation capture and atomic hot-fork installation.

use super::*;

struct RetainedOwnershipLease {
    identity: ProductionVmNodeGeneration,
    _ownership: std::sync::Arc<()>,
}

impl ProductionVmNodeLease for RetainedOwnershipLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

fn permanently_failed_loop() -> (ScenarioDefForm, ProductionVmLifecycleLoop) {
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
    (source, lifecycle)
}

fn permanently_failed_continuation() -> (ScenarioDefForm, ProductionVmHotForkWorldContinuation) {
    let (source, mut lifecycle) = permanently_failed_loop();
    let continuation = lifecycle
        .capture_hot_fork_world_continuation()
        .unwrap_or_else(|error| panic!("process-neutral continuation should capture: {error}"));
    (source, continuation)
}

#[test]
fn committed_lifecycle_history_does_not_block_hot_fork_capture() {
    let (_source, mut lifecycle) = permanently_failed_loop();
    lifecycle.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Committed;
    lifecycle.lifecycle_journal.transaction = 1;

    let continuation = lifecycle
        .capture_hot_fork_world_continuation()
        .unwrap_or_else(|error| panic!("completed lifecycle should permit capture: {error}"));
    continuation
        .validate_complete_internal_state()
        .unwrap_or_else(|error| panic!("completed capture should remain valid: {error}"));
}

#[test]
fn unfinished_lifecycle_phases_block_hot_fork_capture() {
    for phase in [
        ProductionLifecycleJournalPhase::Intent,
        ProductionLifecycleJournalPhase::Prepared,
        ProductionLifecycleJournalPhase::ExitsReaped,
        ProductionLifecycleJournalPhase::Quarantined,
    ] {
        let (_source, mut lifecycle) = permanently_failed_loop();
        lifecycle.lifecycle_journal.phase = phase;
        lifecycle.lifecycle_journal.transaction = 1;

        assert!(lifecycle.capture_hot_fork_world_continuation().is_err());
    }
}

#[test]
fn committed_lifecycle_with_a_staged_process_still_blocks_hot_fork_capture() {
    let (_source, mut lifecycle) = permanently_failed_loop();
    lifecycle.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Committed;
    lifecycle.lifecycle_journal.transaction = 1;
    lifecycle.run_manifest.staged_processes = BTreeMap::from([(
        String::from("staged-node"),
        QemuProcessIdentity {
            process_id: 123,
            start_time_ticks: 456,
            executable: PathBuf::from("qemu-system-test"),
        },
    )])
    .into();

    assert!(lifecycle.capture_hot_fork_world_continuation().is_err());
}

#[test]
fn committed_lifecycle_with_a_live_journal_owner_still_blocks_hot_fork_capture() {
    let (_source, mut lifecycle) = permanently_failed_loop();
    lifecycle.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Committed;
    lifecycle.lifecycle_journal.transaction = 1;
    lifecycle
        .lifecycle_journal
        .nodes
        .push(ProductionLifecycleJournalNode {
            node: String::from("unsettled-node"),
            current_process: QemuProcessIdentity {
                process_id: 123,
                start_time_ticks: 456,
                executable: PathBuf::from("qemu-system-test"),
            },
            replacement_process: None,
            current_generation: 1,
            next_generation: 2,
            transition: String::from("power_off"),
            action_sha256: String::new(),
            evidence_sha256: String::new(),
            expected_exit_code: None,
        });

    assert!(lifecycle.capture_hot_fork_world_continuation().is_err());
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
fn permanently_failed_world_prepares_without_source_processes() {
    let (source, lifecycle) = permanently_failed_loop();
    let source_world = lifecycle
        .prepare_hot_fork_source_world()
        .unwrap_or_else(|error| panic!("permanently failed world should prepare: {error}"));

    assert_eq!(source_world.prepared_nodes().len(), 0);
    assert_eq!(
        source_world.continuation().nodes().len(),
        source.world().vm_nodes().len()
    );
    assert!(source_world.continuation().nodes().iter().all(|boundary| {
        boundary.service_state() == ProductionVmHotForkNodeServiceState::PermanentlyFailed
    }));

    let recovered = source_world
        .recover()
        .unwrap_or_else(|error| panic!("empty source world should recover: {error}"));
    assert_eq!(recovered.inner.backend().len(), 0);
}

#[test]
fn retained_service_state_without_process_authority_fails_before_preparation() {
    let (_source, mut lifecycle) = permanently_failed_loop();
    let node = lifecycle
        .source
        .world()
        .vm_nodes()
        .first()
        .unwrap_or_else(|| panic!("fixture should contain a World node"))
        .id
        .clone();
    lifecycle
        .node_service_states
        .insert(node, ProductionNodeServiceState::PoweredOff);

    let failure = lifecycle
        .prepare_hot_fork_source_world()
        .err()
        .unwrap_or_else(|| panic!("retained state without QEMU authority must fail closed"));

    assert!(failure.unreconciled_nodes().is_empty());
    assert!(failure.rollback_diagnostics().is_empty());
    let recovered = failure
        .into_recovered_lifecycle()
        .unwrap_or_else(|error| panic!("preparation did not mutate the lifecycle: {error}"));
    assert_eq!(recovered.inner.backend().len(), 0);
}

#[test]
fn dropping_unreconciled_preparation_failure_quarantines_its_lifecycle_owner() {
    let (_source, mut lifecycle) = permanently_failed_loop();
    let node = lifecycle
        .source
        .world()
        .vm_nodes()
        .first()
        .unwrap_or_else(|| panic!("fixture should contain a World node"))
        .id
        .clone();
    let ownership = std::sync::Arc::new(());
    let retained_ownership = std::sync::Arc::downgrade(&ownership);
    lifecycle.node_leases.insert(
        node.clone(),
        Box::new(RetainedOwnershipLease {
            identity: ProductionVmNodeGeneration::new(node.clone(), 1)
                .unwrap_or_else(|error| panic!("test generation should be valid: {error}")),
            _ownership: ownership,
        }),
    );
    let failure = ProductionVmHotForkSourceWorldPreparationFailure::new(
        lifecycle,
        "injected unresolved retained source",
        vec![node],
    );

    drop(failure);

    assert!(retained_ownership.upgrade().is_some());
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
fn powered_off_continuation_requires_the_retained_process_boundary() {
    let (_source, mut continuation) = permanently_failed_continuation();
    let boundary = &mut continuation.nodes[0];
    let node = boundary.node.clone();
    boundary.service_state = ProductionVmHotForkNodeServiceState::PoweredOff;
    continuation
        .node_service_states
        .insert(node, ProductionNodeServiceState::PoweredOff);

    assert!(continuation.validate_complete_internal_state().is_err());
    continuation.nodes[0].physical_time = Some(VirtualTime { ticks: 41 });
    assert!(continuation.validate_complete_internal_state().is_err());
    continuation.nodes[0].process = Some(QemuProcessIdentity {
        process_id: 123,
        start_time_ticks: 456,
        executable: PathBuf::from("qemu-system-test"),
    });
    continuation
        .validate_complete_internal_state()
        .unwrap_or_else(|error| panic!("retained powered-off boundary should validate: {error}"));
}

#[test]
fn powered_off_capture_does_not_silently_omit_a_missing_backend() {
    let source = super::super::runtime::tests::nonterminal_signal_replay_scenario();
    let mut lifecycle = super::super::runtime::tests::production_loop_without_backends(&source);
    for vm in source.world().vm_nodes() {
        lifecycle.node_generations.insert(vm.id.clone(), 1);
        lifecycle
            .node_service_states
            .insert(vm.id.clone(), ProductionNodeServiceState::PoweredOff);
    }

    assert!(lifecycle.hot_fork_node_boundaries().is_err());
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
