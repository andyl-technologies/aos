//! Production runtime evidence and initial-boundary regression tests.

use super::*;

fn hash(domain: &str) -> ContentHash {
    ContentHash::from_canonical_material("debug-runtime-evidence-test", domain)
}

fn node() -> NodeId {
    NodeId {
        name: String::from("vm-a"),
    }
}

struct FailingFinishLauncher {
    finish_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl ProductionVmNodeLauncher for FailingFinishLauncher {
    fn launch(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
    ) -> Result<QemuNode, LifecycleApiError> {
        Err(loop_factory_error("test launcher does not spawn"))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error("test launcher does not admit replay"))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        self.finish_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(loop_factory_error("test launcher retained quarantine"))
    }
}

#[test]
fn recorded_control_boundary_waits_until_every_node_reaches_the_exact_time() {
    let node_a = node();
    let node_b = NodeId {
        name: String::from("vm-b"),
    };
    let expected = BTreeMap::from([
        (node_a.clone(), VirtualTime { ticks: 17 }),
        (node_b.clone(), VirtualTime { ticks: 23 }),
    ]);

    assert_eq!(
        classify_recorded_control_boundary(
            &expected,
            &BTreeMap::from([
                (node_a.clone(), VirtualTime { ticks: 16 }),
                (node_b.clone(), VirtualTime { ticks: 23 }),
            ]),
        ),
        RecordedControlBoundary::Pending
    );
    assert_eq!(
        classify_recorded_control_boundary(&expected, &expected),
        RecordedControlBoundary::Ready
    );
    assert_eq!(
        classify_recorded_control_boundary(
            &expected,
            &BTreeMap::from([
                (node_a.clone(), VirtualTime { ticks: 18 }),
                (node_b, VirtualTime { ticks: 22 }),
            ]),
        ),
        RecordedControlBoundary::Bypassed
    );
    assert_eq!(
        classify_recorded_control_boundary(
            &expected,
            &BTreeMap::from([(node_a, VirtualTime { ticks: 17 })]),
        ),
        RecordedControlBoundary::Bypassed
    );
}

fn initially_violated_scenario() -> ScenarioDefForm {
    let base = crucible::crash_restart_scenario()
        .unwrap_or_else(|error| panic!("built-in scenario should validate: {error}"))
        .scenario;
    let world = base.world().clone();
    let assertion_id = crucible::AssertionId::from_name("db-0-must-remain-crashed");
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef {
            id: assertion_id.clone(),
            message: String::from("db-0 must remain crashed"),
            property: crucible::Property::Always {
                predicate: crucible::Predicate::node_state(
                    NodeId {
                        name: String::from("db-0"),
                    },
                    NodeLifecycle::Crashed,
                ),
            },
        }],
    )
    .unwrap_or_else(|error| panic!("test assertions should validate: {error}"));
    let assertion_ids = vec![assertion_id.clone()];
    let graph = EventGraph::builder()
        .event("fail-on-initial-violation")
        .when(crucible::Predicate::assertion_state(
            assertion_id,
            AssertionPhase::Violated,
        ))
        .action(Action::fail("db-0 did not remain crashed"))
        .build_with_assertions_for_world(assertion_ids.clone(), &world)
        .unwrap_or_else(|error| panic!("test trigger should validate: {error}"));
    let plan =
        crucible::Plan::from_event_graph_with_assertions_for_world(&world, assertion_ids, graph)
            .unwrap_or_else(|error| panic!("test plan should validate: {error}"));
    ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &plan,
        &properties,
        Seed::from_u64(7),
        0,
    )
    .unwrap_or_else(|error| panic!("test scenario should validate: {error}"))
}

#[test]
fn durable_run_state_allows_concurrent_sessions_for_one_scenario() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (first, _, _) = production_run_directory(&scenario, &config)
        .unwrap_or_else(|error| panic!("first run owner should acquire: {error}"));
    let (second, _, _) = production_run_directory(&scenario, &config)
        .unwrap_or_else(|error| panic!("concurrent session should acquire: {error}"));
    assert_ne!(first.path(), second.path());
}

#[test]
fn durable_run_state_recovers_an_unfinished_run_before_reuse() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (first, mut first_manifest, _) = production_run_directory(&scenario, &config)
        .unwrap_or_else(|error| panic!("first run should build: {error}"));
    let first_path = first.path().to_path_buf();
    first_manifest.owner.process_id = u32::MAX;
    persist_atomic_json(&first_path.join("run-manifest.json"), &first_manifest)
        .unwrap_or_else(|error| panic!("dead owner fixture should persist: {error}"));
    drop(first);

    let (second, _, _) = production_run_directory(&scenario, &config)
        .unwrap_or_else(|error| panic!("recovered run should build: {error}"));
    assert_ne!(first_path, second.path());
    let recovered: ProductionRunManifest = decode_run_json(&first_path.join("run-manifest.json"))
        .unwrap_or_else(|error| panic!("recovered manifest should decode: {error}"));
    assert!(recovered.clean_shutdown);
    assert!(recovered.recovered_after_host_exit);
    let journal: ProductionLifecycleJournal =
        decode_run_json(&first_path.join("lifecycle-journal.json"))
            .unwrap_or_else(|error| panic!("recovered journal should decode: {error}"));
    assert!(matches!(
        journal.phase,
        ProductionLifecycleJournalPhase::Quarantined
    ));
}

#[test]
fn durable_run_state_recovers_every_incomplete_transaction_phase() {
    for phase in [
        ProductionLifecycleJournalPhase::Intent,
        ProductionLifecycleJournalPhase::Prepared,
        ProductionLifecycleJournalPhase::ExitsReaped,
    ] {
        let root = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("run-state root should build: {error}"));
        let source = initially_violated_scenario();
        let scenario = source.scenario_def();
        let config =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
        let (first, mut manifest, mut journal) = production_run_directory(&scenario, &config)
            .unwrap_or_else(|error| panic!("first run should build: {error}"));
        let first_path = first.path().to_path_buf();
        manifest.owner.process_id = u32::MAX;
        persist_atomic_json(&first_path.join("run-manifest.json"), &manifest)
            .unwrap_or_else(|error| panic!("dead owner fixture should persist: {error}"));
        journal.phase = phase;
        journal.transaction = 17;
        persist_atomic_json(&first_path.join("lifecycle-journal.json"), &journal)
            .unwrap_or_else(|error| panic!("crash-point journal should persist: {error}"));
        drop(first);

        let (_second, _, _) = production_run_directory(&scenario, &config)
            .unwrap_or_else(|error| panic!("incomplete transaction should recover: {error}"));
        let recovered: ProductionLifecycleJournal =
            decode_run_json(&first_path.join("lifecycle-journal.json"))
                .unwrap_or_else(|error| panic!("recovered journal should decode: {error}"));
        assert_eq!(recovered.transaction, 17);
        assert!(matches!(
            recovered.phase,
            ProductionLifecycleJournalPhase::Quarantined
        ));
    }
}

#[test]
fn durable_run_state_fails_closed_on_a_corrupt_journal() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (first, _, _) = production_run_directory(&scenario, &config)
        .unwrap_or_else(|error| panic!("first run should build: {error}"));
    let journal = first.path().join("lifecycle-journal.json");
    drop(first);
    fs::write(&journal, b"not-json")
        .unwrap_or_else(|error| panic!("corrupt journal fixture should write: {error}"));

    let error = production_run_directory(&scenario, &config)
        .err()
        .unwrap_or_else(|| panic!("corrupt journal should fail closed"));
    assert!(
        error
            .to_string()
            .contains("invalid prior lifecycle journal")
    );
}

#[test]
fn durable_run_state_fails_closed_on_a_corrupt_manifest() {
    let root =
        tempfile::tempdir().unwrap_or_else(|error| panic!("run-state root should build: {error}"));
    let source = initially_violated_scenario();
    let scenario = source.scenario_def();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", root.path());
    let (first, _, _) = production_run_directory(&scenario, &config)
        .unwrap_or_else(|error| panic!("first run should build: {error}"));
    let manifest = first.path().join("run-manifest.json");
    drop(first);
    fs::write(&manifest, b"not-json")
        .unwrap_or_else(|error| panic!("corrupt manifest fixture should write: {error}"));

    let error = production_run_directory(&scenario, &config)
        .err()
        .unwrap_or_else(|| panic!("corrupt manifest should fail closed"));
    assert!(error.to_string().contains("invalid prior run manifest"));
}

fn production_loop_without_backends(source: &ScenarioDefForm) -> ProductionVmLifecycleLoop {
    let scenario = source.scenario_def();
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        Shift::new(0).unwrap_or_else(|error| panic!("zero shift should validate: {error}")),
        4,
        SimInstant { nanos: 4 },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let mut scheduler = SingleScheduler::new(runtime_scenario)
        .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    scheduler
        .attach_world_network_links(source.world())
        .unwrap_or_else(|error| panic!("test world links should attach: {error}"));
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .unwrap_or_else(|error| panic!("test trigger plan should lower: {error}"))
        .into_event_graph();
    let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state");
    let nodes = ProductionNodeSet::new();
    let fault_runtime = ProductionFaultRuntime::new(
        source.plan().fault_signals().clone(),
        None,
        SignalBoundarySnapshot::default(),
        scenario.id(),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
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
        source.world().fault_topology().clone(),
        source.world().links().to_vec(),
    );

    ProductionVmLifecycleLoop {
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
        node_generations: BTreeMap::new(),
        node_service_states: BTreeMap::new(),
        lifecycle_journal: ProductionLifecycleJournal {
            version: 1,
            transaction: 0,
            phase: ProductionLifecycleJournalPhase::Idle,
            nodes: Vec::new(),
            completed_exits: Vec::new(),
        },
        run_manifest: ProductionRunManifest {
            version: 2,
            scenario: scenario.id().to_hex(),
            owner: linux_process_identity(std::process::id())
                .unwrap_or_else(|error| panic!("test process identity should read: {error}"))
                .unwrap_or_else(|| panic!("test process should have a Linux identity")),
            processes: BTreeMap::new(),
            staged_processes: BTreeMap::new(),
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
        _run_directory: ProductionRunDirectory::temporary()
            .unwrap_or_else(|error| panic!("test run directory should build: {error}")),
    }
}

#[test]
fn lifecycle_reports_launch_authority_cleanup_after_backend_shutdown() {
    let source = initially_violated_scenario();
    let finish_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut lifecycle = production_loop_without_backends(&source);
    lifecycle.node_launcher = Box::new(FailingFinishLauncher {
        finish_calls: Arc::clone(&finish_calls),
    });

    let error = QuantumLoop::shutdown(&mut lifecycle)
        .err()
        .unwrap_or_else(|| panic!("failed launch-authority cleanup must reject shutdown"));

    assert!(
        error
            .to_string()
            .contains("test launcher retained quarantine")
    );
    assert_eq!(finish_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn production_guest_assets_are_kept_per_architecture() {
    let config = ProductionVmLifecycleConfig::new(
        "qemu-system-x86_64",
        "plugin",
        "x86-kernel",
        "x86-root",
        "run-state",
    )
    .with_kernel_cmdline_prefix("console=ttyS0")
    .with_guest_assets(
        VmArchitecture::Aarch64,
        "arm-kernel",
        "arm-root",
        Some(String::from("console=ttyAMA0")),
    );

    let x86 = config
        .guest_assets
        .get(&VmArchitecture::X86_64)
        .unwrap_or_else(|| panic!("x86_64 assets should remain configured"));
    assert_eq!(x86.kernel, PathBuf::from("x86-kernel"));
    assert_eq!(x86.root_image, PathBuf::from("x86-root"));
    assert_eq!(x86.kernel_cmdline_prefix, None);

    let arm = config
        .guest_assets
        .get(&VmArchitecture::Aarch64)
        .unwrap_or_else(|| panic!("AArch64 assets should be configured"));
    assert_eq!(arm.kernel, PathBuf::from("arm-kernel"));
    assert_eq!(arm.root_image, PathBuf::from("arm-root"));
    assert_eq!(
        arm.kernel_cmdline_prefix.as_deref(),
        Some("console=ttyAMA0")
    );
}

#[test]
fn production_native_aarch64_assets_do_not_create_an_x86_fallback() {
    let config = ProductionVmLifecycleConfig::new_for_guest_architecture(
        "qemu-system-aarch64",
        "plugin",
        VmArchitecture::Aarch64,
        "arm-kernel",
        "arm-root",
        "run-state",
    );

    assert!(!config.guest_assets.contains_key(&VmArchitecture::X86_64));
    let arm = config
        .guest_assets
        .get(&VmArchitecture::Aarch64)
        .unwrap_or_else(|| panic!("native AArch64 assets should be configured"));
    assert_eq!(arm.kernel, PathBuf::from("arm-kernel"));
    assert_eq!(arm.root_image, PathBuf::from("arm-root"));
}

#[test]
fn architecture_override_does_not_inherit_the_native_kernel_cmdline() {
    let config =
        ProductionVmLifecycleConfig::new("qemu", "plugin", "x86-kernel", "x86-root", "run-state")
            .with_kernel_cmdline_prefix("console=ttyS0")
            .with_guest_assets(VmArchitecture::Aarch64, "arm-kernel", "arm-root", None);

    let x86 = config
        .guest_assets
        .get(&VmArchitecture::X86_64)
        .unwrap_or_else(|| panic!("native x86 assets should be configured"));
    let arm = config
        .guest_assets
        .get(&VmArchitecture::Aarch64)
        .unwrap_or_else(|| panic!("AArch64 assets should be configured"));

    assert_eq!(
        production_kernel_cmdline_prefix(&config, VmArchitecture::X86_64, x86),
        Some("console=ttyS0")
    );
    assert_eq!(
        production_kernel_cmdline_prefix(&config, VmArchitecture::Aarch64, arm),
        None
    );
}

fn graph_runtime(configuration: ContentHash, reduced_state: ContentHash) -> RuntimeState {
    RuntimeState {
        id: reduced_state,
        configuration,
        node_blobs: BTreeMap::new(),
        node_icounts: BTreeMap::new(),
        scheduler: SchedulerState::default(),
        event_log: EventLogOffset::default(),
    }
}

fn evidence(configuration: ContentHash) -> ProductionVmDebugRuntimeEvidence {
    ProductionVmDebugRuntimeEvidence {
        configuration,
        event_log: EventLogOffset::new(hash("event-log"), 3, 7),
        scheduler: SchedulerState::default(),
        node_icounts: BTreeMap::from([(node(), Icount { retired: 41 })]),
        node_times: BTreeMap::from([(node(), VirtualTime { ticks: 17 })]),
        fingerprints: BTreeMap::new(),
        graph_runtimes: Vec::new(),
        runtime: None,
    }
}

fn bound_evidence(
    configuration: ContentHash,
    reduced_state: ContentHash,
    frontier: u64,
    retired: u64,
    events: u64,
) -> ProductionVmDebugRuntimeEvidence {
    let graph = graph_runtime(configuration, reduced_state);
    let mut sample = evidence(configuration);
    sample.event_log = EventLogOffset::new(hash(&format!("event-log-{events}")), events, events);
    sample.node_icounts = BTreeMap::from([(node(), Icount { retired })]);
    sample.node_times = BTreeMap::from([(node(), VirtualTime { ticks: frontier })]);
    sample.graph_runtimes.push(graph.clone());
    sample.runtime = Some(sample.bind_graph_runtime(&graph));
    sample
}

#[test]
fn virtual_time_coordinate_selects_the_latest_boundary_not_after_the_target() {
    let source = initially_violated_scenario();
    let mut lifecycle = production_loop_without_backends(&source);
    let configuration = hash("configuration");
    let reduced_state = hash("reduced-state");
    let graph = graph_runtime(configuration, reduced_state);
    lifecycle.debug_runtime_evidence = vec![
        bound_evidence(configuration, reduced_state, 10, 11, 1),
        bound_evidence(configuration, reduced_state, 20, 21, 2),
        bound_evidence(configuration, reduced_state, 100, 101, 3),
    ];

    let resolved = lifecycle
        .resolve_recorded_debug_coordinate_runtime_evidence(
            &crucible::DebugCoordinate::virtual_time(VirtualTime { ticks: 20 }),
            &graph,
        )
        .unwrap_or_else(|error| panic!("virtual-time evidence should resolve: {error}"));

    assert_eq!(
        resolved.node_icounts.get(&node()),
        Some(&Icount { retired: 21 })
    );
}

#[test]
fn node_icount_coordinate_does_not_alias_a_later_same_configuration_boundary() {
    let source = initially_violated_scenario();
    let mut lifecycle = production_loop_without_backends(&source);
    let configuration = hash("configuration");
    let reduced_state = hash("reduced-state");
    let graph = graph_runtime(configuration, reduced_state);
    lifecycle.debug_runtime_evidence = vec![
        bound_evidence(configuration, reduced_state, 10, 11, 1),
        bound_evidence(configuration, reduced_state, 20, 21, 2),
        bound_evidence(configuration, reduced_state, 100, 101, 3),
    ];

    let resolved = lifecycle
        .resolve_recorded_debug_coordinate_runtime_evidence(
            &crucible::DebugCoordinate::node_icount(node(), Icount { retired: 21 }),
            &graph,
        )
        .unwrap_or_else(|error| panic!("node-icount evidence should resolve: {error}"));

    assert_eq!(
        resolved.node_icounts.get(&node()),
        Some(&Icount { retired: 21 })
    );
}

#[test]
fn production_lifecycle_emits_initial_started_state_for_every_vm() {
    let scenario = crucible::happy_path_scenario()
        .unwrap_or_else(|error| panic!("built-in scenario should validate: {error}"))
        .scenario;
    let at = VirtualTime { ticks: 17 };

    let events = initial_node_state_events(&scenario, at);

    assert_eq!(events.len(), scenario.world().vm_nodes().len());
    for (event, node) in events.iter().zip(scenario.world().vm_nodes()) {
        assert!(
            event.at() == at
                && matches!(
                    event.payload(),
                    crucible::ObservableEventPayload::NodeState {
                        node: observed,
                        state: NodeLifecycle::Started,
                    } if observed == &node.id
                ),
            "initial lifecycle observations must preserve canonical world order"
        );
    }
}

#[cfg(test)]
mod initial_terminal_boundary {
    use super::*;

    #[test]
    fn initial_terminal_assertion_returns_without_advancing_a_backend() {
        let source = initially_violated_scenario();
        let mut lifecycle = production_loop_without_backends(&source);
        let configuration = lifecycle.inner.loop_impl().configuration().clone();
        let frontier = lifecycle.inner.loop_impl().frontier();

        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("initial terminal boundary should settle: {error}"));

        assert_eq!(outcome.configuration, configuration);
        assert_eq!(outcome.frontier, frontier);
        assert_eq!(outcome.advanced_node, None);
        assert!(outcome.resolved_events.is_empty());
        assert!(outcome.decisions.is_empty());
        assert_eq!(outcome.event_log_entries.len(), 6);
        for (entry, node) in outcome.event_log_entries[..3]
            .iter()
            .zip(source.world().vm_nodes())
        {
            assert!(matches!(
                entry.payload(),
                crucible::SchedulerEventLogPayload::Observable(
                    crucible::ObservableEventPayload::NodeState {
                        node: observed,
                        state: NodeLifecycle::Started,
                    }
                ) if observed == &node.id
            ));
        }
        assert!(matches!(
            outcome.event_log_entries[3].payload(),
            crucible::SchedulerEventLogPayload::Observable(
                crucible::ObservableEventPayload::AssertionStateChanged {
                    state: AssertionPhase::Violated,
                    ..
                }
            )
        ));
        assert!(matches!(
            outcome.event_log_entries[4].payload(),
            crucible::SchedulerEventLogPayload::TriggerFired(_)
        ));
        assert!(matches!(
            outcome.event_log_entries[5].payload(),
            crucible::SchedulerEventLogPayload::TriggerActionApplied(_)
        ));
        assert!(matches!(
            lifecycle.take_terminal_verdict(),
            Some(QuantumTerminalVerdict::Failed(violations))
                if violations == vec![String::from("db-0 did not remain crashed")]
        ));
    }
}

#[test]
fn production_debug_evidence_hydrates_only_backend_owned_runtime_fields() {
    let configuration = hash("configuration");
    let reduced_state = hash("reduced-state");
    let mut graph = graph_runtime(configuration, reduced_state);
    graph
        .node_blobs
        .insert(node(), crucible::NodeBlobRef::baked(hash("blob")));
    graph.node_icounts.insert(node(), Icount { retired: 5 });
    let evidence = evidence(configuration);

    if let Err(error) = evidence.validate_graph_runtime(configuration, reduced_state, &graph) {
        panic!("complete graph identity should validate: {error}");
    }
    let bound = evidence.bind_graph_runtime(&graph);
    assert_eq!(bound.id, graph.id);
    assert_eq!(bound.node_blobs, graph.node_blobs);
    assert_eq!(bound.event_log, evidence.event_log);
    assert_eq!(bound.node_icounts, evidence.node_icounts);
}

#[test]
fn production_debug_evidence_rejects_forged_or_partial_graph_identity() {
    let configuration = hash("configuration");
    let reduced_state = hash("reduced-state");
    let evidence = evidence(configuration);
    let mut forged = graph_runtime(configuration, hash("forged-state"));
    assert!(
        evidence
            .validate_graph_runtime(configuration, reduced_state, &forged)
            .is_err()
    );

    forged.id = reduced_state;
    forged.node_icounts.insert(node(), Icount { retired: 5 });
    assert!(
        evidence
            .validate_graph_runtime(configuration, reduced_state, &forged)
            .is_err()
    );
}

#[test]
fn production_debug_evidence_matches_a_runtime_bound_at_a_later_boundary() {
    let configuration = hash("configuration");
    let reduced_state = hash("reduced-state");
    let earlier = evidence(configuration);
    let mut later = evidence(configuration);
    later.event_log = EventLogOffset::new(hash("later-event-log"), 9, 17);
    later.node_icounts = BTreeMap::from([(node(), Icount { retired: 97 })]);

    let mut graph = graph_runtime(configuration, reduced_state);
    graph
        .node_blobs
        .insert(node(), crucible::NodeBlobRef::baked(hash("blob")));
    graph.node_icounts.insert(node(), Icount { retired: 5 });
    let later_bound = later.bind_graph_runtime(&graph);

    assert!(earlier.matches_graph_runtime(&later_bound));
    assert!(later.matches_graph_runtime(&later_bound));
}

#[test]
fn production_debug_evidence_restores_the_recorded_scheduler_frontier() {
    let configuration = hash("configuration");
    let mut recorded = evidence(configuration);
    recorded.node_times.insert(
        NodeId {
            name: String::from("node-b"),
        },
        VirtualTime { ticks: 23 },
    );

    assert_eq!(
        recorded.scheduler_frontier(VirtualTime { ticks: 99 }),
        VirtualTime { ticks: 17 }
    );

    recorded.node_times.clear();
    assert_eq!(
        recorded.scheduler_frontier(VirtualTime { ticks: 99 }),
        VirtualTime { ticks: 99 }
    );
}
