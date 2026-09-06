//! Focused construction support for cross-crate production hot-fork tests.

use super::*;

std::thread_local! {
    static COMPLETED_ADOPTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Resets the current test thread's completed hot-fork adoption count.
pub fn reset_hot_fork_adoption_count_for_test() {
    COMPLETED_ADOPTIONS.set(0);
}

/// Returns the current test thread's completed hot-fork adoption count.
#[must_use]
pub fn hot_fork_adoption_count_for_test() -> usize {
    COMPLETED_ADOPTIONS.get()
}

pub(crate) fn record_hot_fork_adoption_for_test() {
    COMPLETED_ADOPTIONS.set(COMPLETED_ADOPTIONS.get().saturating_add(1));
}

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
/// Returns [`LifecycleApiError::LoopFactory`] when the built-in scenario,
/// scheduler, fault runtime, process identity, lifecycle state, source
/// ownership, or retained-template preparation cannot be constructed.
pub fn prepared_hot_fork_source_world_for_test(
    source_node: QemuNode,
) -> Result<
    (
        NodeId,
        ProductionVmNodeGeneration,
        ProductionVmHotForkSourceWorld,
    ),
    LifecycleApiError,
> {
    let (mut nodes, source_world) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])?;
    let (node, generation) = nodes
        .pop()
        .ok_or_else(|| loop_factory_error("single-node source fixture lost its retained node"))?;
    Ok((node, generation, source_world))
}

/// Builds one prepared production source world around scripted live QEMU nodes.
///
/// The built-in scenario's first `source_nodes.len()` VMs are running retained
/// sources. Every remaining VM is represented as permanently failed.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the built-in scenario has
/// too few VM nodes or any source-world boundary cannot be constructed.
pub fn prepared_multi_node_hot_fork_source_world_for_test(
    source_nodes: Vec<QemuNode>,
) -> Result<
    (
        Vec<(NodeId, ProductionVmNodeGeneration)>,
        ProductionVmHotForkSourceWorld,
    ),
    LifecycleApiError,
> {
    let source = crucible::crash_restart_scenario()
        .map_err(|error| test_support_error("construct built-in scenario", error))?
        .scenario;
    let mut lifecycle = lifecycle_without_backends(&source)?;
    if source_nodes.is_empty() || source_nodes.len() > source.world().vm_nodes().len() {
        return Err(loop_factory_error(
            "scripted source count is outside the built-in scenario World",
        ));
    }

    for vm in source.world().vm_nodes() {
        let root_image = &lifecycle.config.guest_assets[&vm.arch].root_image;
        let root_image = std::fs::File::open(root_image)
            .map_err(|error| test_support_error("open scripted root image", error))?;
        let root_image_hash = ContentHash::from_reader(root_image)
            .map_err(|error| test_support_error("hash scripted root image", error))?;
        lifecycle.node_generations.insert(vm.id.clone(), 1);
        lifecycle
            .node_service_states
            .insert(vm.id.clone(), ProductionNodeServiceState::PermanentlyFailed);
        lifecycle
            .immutable_root_images
            .insert(vm.id.clone(), root_image_hash);
    }

    let mut retained = Vec::with_capacity(source_nodes.len());
    for (index, (vm, source_node)) in source
        .world()
        .vm_nodes()
        .iter()
        .zip(source_nodes)
        .enumerate()
    {
        let retained_node = vm.id.clone();
        let generation = ProductionVmNodeGeneration::new(retained_node.clone(), 1)?;
        let node_directory = lifecycle
            ._run_directory
            .path()
            .join(format!("retained-hot-fork-source-{index}"));
        let assets = &lifecycle.config.guest_assets[&vm.arch];
        lifecycle.launch_configs.insert(
            retained_node.clone(),
            ProductionLiveNodeStepGateConfig::new_with_root_image(
                &lifecycle.config.executable,
                &lifecycle.config.plugin,
                &assets.kernel,
                &assets.root_image,
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
        retained.push((retained_node, generation));
    }

    let source_world = lifecycle
        .prepare_hot_fork_source_world()
        .map_err(|error| test_support_error("prepare scripted hot-fork source world", error))?;
    Ok((retained, source_world))
}

fn lifecycle_without_backends(
    source: &ScenarioDefForm,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
    let scenario = source.scenario_def();
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        Shift::new(0).map_err(|error| test_support_error("construct test time shift", error))?,
        4,
        SimInstant { nanos: 4 },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let mut scheduler = SingleScheduler::new(runtime_scenario)
        .map_err(|error| test_support_error("construct test scheduler", error))?;
    scheduler
        .attach_world_network_links(source.world())
        .map_err(|error| test_support_error("attach test World links", error))?;
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .map_err(|error| test_support_error("lower test trigger graph", error))?
        .into_event_graph();
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
        crucible::model::production_host_fault_adapter_manifests()
            .map_err(|error| test_support_error("construct test fault manifests", error))?,
        &nodes,
    )
    .map_err(|error| test_support_error("construct test fault runtime", error))?;
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
    let run_directory = ProductionRunDirectory::temporary()
        .map_err(|error| test_support_error("construct temporary test run directory", error))?;
    let test_assets = run_directory.path().join("assets");
    std::fs::create_dir(&test_assets)
        .map_err(|error| test_support_error("create scripted test assets", error))?;
    let qemu = test_assets.join("qemu");
    let plugin = test_assets.join("plugin");
    let kernel = test_assets.join("kernel");
    let root = test_assets.join("root");
    for path in [&qemu, &plugin, &kernel, &root] {
        std::fs::write(path, path.as_os_str().as_encoded_bytes())
            .map_err(|error| test_support_error("write scripted test asset", error))?;
    }
    let config = ProductionVmLifecycleConfig::new(
        qemu,
        plugin,
        kernel,
        root,
        run_directory.path().join("restored-runs"),
    );

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
        lifecycle_persistence: LifecycleStatePersistence::new(run_directory.path())
            .map_err(|error| test_support_error("construct test lifecycle persistence", error))?,
        run_manifest: ProductionRunManifest {
            version: 2,
            scenario: scenario.id().to_hex(),
            owner: linux_process_identity(std::process::id())
                .map_err(|error| test_support_error("identify test process", error))?
                .ok_or_else(|| loop_factory_error("test process has no Linux identity"))?,
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
    lifecycle
        .reserve_lifecycle_state_encoding(source.plan().fault_signals().resource_limits(), 0, 0)
        .map_err(|error| test_support_error("reserve test lifecycle encoding", error))?;
    Ok(lifecycle)
}

fn test_support_error(
    operation: &'static str,
    source: impl std::fmt::Display,
) -> LifecycleApiError {
    loop_factory_error(format!("{operation}: {source}"))
}
