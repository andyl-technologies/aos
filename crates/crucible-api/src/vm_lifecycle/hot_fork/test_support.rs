//! Focused construction support for cross-crate production hot-fork tests.

use std::error::Error;

use super::*;

struct TestNodeLease {
    identity: ProductionVmNodeGeneration,
}

impl ProductionVmNodeLease for TestNodeLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

/// Builds one prepared production source world around a scripted live QEMU node.
///
/// Every other VM in the built-in scenario is represented as permanently
/// failed, so the returned world owns exactly one retained QEMU source while
/// still exercising the complete production lifecycle and source preparation.
///
/// # Errors
///
/// Returns a diagnostic when the built-in scenario, lifecycle state, source
/// ownership, or retained-template preparation cannot be constructed.
pub fn prepared_hot_fork_source_world_for_test(
    source_node: QemuNode,
) -> Result<
    (
        NodeId,
        ProductionVmNodeGeneration,
        ProductionVmHotForkSourceWorld,
    ),
    Box<dyn Error>,
> {
    let source = crucible::crash_restart_scenario()?.scenario;
    let mut lifecycle = lifecycle_without_backends(&source)?;
    let retained_node = source
        .world()
        .vm_nodes()
        .first()
        .map(|vm| vm.id.clone())
        .ok_or_else(|| std::io::Error::other("built-in scenario has no VM node"))?;

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

    let generation = ProductionVmNodeGeneration::new(retained_node.clone(), 1)?;
    let node_directory = lifecycle
        ._run_directory
        .path()
        .join("retained-hot-fork-source");
    lifecycle.launch_configs.insert(
        retained_node.clone(),
        ProductionLiveNodeStepGateConfig::new_with_root_image(
            "qemu",
            "plugin",
            "kernel",
            "root",
            &node_directory,
        ),
    );
    lifecycle
        .node_run_directories
        .insert(retained_node.clone(), node_directory);
    lifecycle.node_leases.insert(
        retained_node.clone(),
        Box::new(TestNodeLease {
            identity: generation.clone(),
        }),
    );
    lifecycle
        .node_service_states
        .insert(retained_node.clone(), ProductionNodeServiceState::Running);
    lifecycle
        .inner
        .backend_mut()
        .insert(retained_node.clone(), source_node);

    let source_world = lifecycle
        .prepare_hot_fork_source_world()
        .map_err(|error| -> Box<dyn Error> { Box::new(error) })?;
    Ok((retained_node, generation, source_world))
}

fn lifecycle_without_backends(
    source: &ScenarioDefForm,
) -> Result<ProductionVmLifecycleLoop, Box<dyn Error>> {
    let scenario = source.scenario_def();
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        Shift::new(0)?,
        4,
        SimInstant { nanos: 4 },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let mut scheduler = SingleScheduler::new(runtime_scenario)?;
    scheduler.attach_world_network_links(source.world())?;
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())?
        .into_event_graph();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state");
    let nodes = ProductionNodeSet::new();
    let artifacts = (!source.plan().fault_signals().programs().is_empty()).then(|| {
        let store: Arc<dyn crucible::model::DagStore> =
            Arc::new(crucible::model::MemoryDagStore::new());
        Arc::new(crucible::model::OwnedDagSignalArtifactProvider::new(store))
            as Arc<dyn crucible::model::SignalArtifactProvider>
    });
    let fault_runtime = ProductionFaultRuntime::new(
        source.plan().fault_signals().clone(),
        artifacts,
        SignalBoundarySnapshot::default(),
        scenario.id(),
        crucible::model::production_host_fault_adapter_manifests()?,
        &nodes,
    )?;
    let fault_runtime = Arc::new(std::sync::Mutex::new(fault_runtime));
    let fault_evaluation_cursor = Arc::new(std::sync::Mutex::new(
        ProductionFaultEvaluationCursor::default(),
    ));
    let storage_fault_observations = Arc::new(std::sync::Mutex::new(
        storage_faults::ProductionFaultObservationJournal::default(),
    ));
    let interceptor = ProductionFaultNetworkInterceptor::with_shared_runtime(
        Arc::clone(&fault_runtime),
        Arc::clone(&fault_evaluation_cursor),
        Arc::clone(&storage_fault_observations),
        source.plan().fault_signals().resource_limits(),
        source.world().fault_topology().clone(),
        source.world().links().to_vec(),
    );
    let run_directory = ProductionRunDirectory::temporary()?;

    let mut lifecycle = ProductionVmLifecycleLoop {
        inner: BackendQuantumLoop::with_network_output_interceptor(scheduler, nodes, interceptor),
        trigger_graph,
        trigger_state: EventGraphState::default(),
        trigger_world: source.world().clone(),
        assertion_evaluator: HostAssertionEvaluator::new(source.properties())
            .with_world_white_box_policies(source.world()),
        assertion_oracle: BlackBoxHostOracle,
        terminal_verdict: None,
        checkpoint_terminal_cause: None,
        initial_lifecycle_observations_pending: true,
        branch: None,
        signal_fault_branches: VecDeque::new(),
        promote_signal_fault_campaign_choices: false,
        launch_configs: BTreeMap::new(),
        block_bindings: BTreeMap::new(),
        ninep_bindings: BTreeMap::new(),
        block_devices: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        storage_fault_observations,
        fault_runtime,
        fault_evaluation_cursor,
        fault_replay_installed: false,
        fault_search_overrides_installed: false,
        icount_shift: 0,
        node_indexes: BTreeMap::new(),
        node_run_directories: BTreeMap::new(),
        immutable_root_images: BTreeMap::new(),
        node_generations: BTreeMap::new(),
        node_leases: BTreeMap::new(),
        node_lease_cleanup_failed: false,
        node_service_states: BTreeMap::new(),
        lifecycle_journal: ProductionLifecycleJournal {
            version: 1,
            transaction: 0,
            phase: ProductionLifecycleJournalPhase::Idle,
            nodes: Vec::new().into(),
            completed_exits: Vec::new().into(),
        },
        lifecycle_persistence: LifecycleStatePersistence::new(run_directory.path())?,
        run_manifest: ProductionRunManifest {
            version: 2,
            scenario: scenario.id().to_hex(),
            owner: linux_process_identity(std::process::id())?
                .ok_or_else(|| std::io::Error::other("test process has no Linux identity"))?,
            processes: process_owners::ProductionProcessOwners::new(),
            staged_processes: process_owners::ProductionProcessOwners::new(),
            clean_shutdown: false,
            recovered_after_host_exit: false,
        },
        scenario,
        source: source.clone(),
        config,
        checkpoint_targets: BTreeMap::new(),
        recorded_controls: Vec::new(),
        signal_artifact_objects: BTreeMap::new(),
        debug_backend_paths: BTreeMap::new(),
        debug_gateway: None,
        debug_attach: None,
        debug_gateway_teardown_required: false,
        indeterminate_debug_candidate: None,
        debug_runtime_evidence: Vec::new(),
        node_launcher: Box::new(PackagedProductionVmNodeLauncher),
        _run_directory: run_directory,
    };
    lifecycle.reserve_lifecycle_state_encoding(
        source.plan().fault_signals().resource_limits(),
        0,
        0,
    )?;
    Ok(lifecycle)
}
