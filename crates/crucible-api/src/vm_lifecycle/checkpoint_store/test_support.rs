//! Production exact-checkpoint codec fixtures for cross-crate integration tests.

use super::*;

/// Authenticated production checkpoint codec material for integration tests.
///
/// The fixture represents a zero-progress scheduler boundary and uses placeholder
/// overlay and VMState bytes. It can exercise closure encoding, transfer, and
/// authentication, but it cannot launch or restore a QEMU process.
pub struct AuthenticatedProductionCheckpointCodecFixture {
    source: ScenarioDefForm,
    configuration: Configuration,
    closure: ProductionExactCheckpointClosure,
}

impl AuthenticatedProductionCheckpointCodecFixture {
    /// Returns the typed scenario source that authenticates the checkpoint.
    #[must_use]
    pub const fn source(&self) -> &ScenarioDefForm {
        &self.source
    }

    /// Returns the modeled configuration captured by the checkpoint.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the portable production closure with authenticated replay-oracle metadata.
    #[must_use]
    pub const fn closure(&self) -> &ProductionExactCheckpointClosure {
        &self.closure
    }
}

/// Builds a one-node production checkpoint codec fixture at scheduler genesis.
///
/// The fixture uses the real production manifest, scheduler, sparse-artifact,
/// fault-runtime, portable-closure, and replay-oracle authentication paths. Its
/// placeholder overlay and VMState bytes are deliberately not launchable. It
/// neither advances a scheduler nor restores QEMU and is available only through
/// the `test-support` feature.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when fixture construction or durable closure
/// publication under `run_state_root` fails.
pub fn build_authenticated_production_checkpoint_codec_fixture(
    run_state_root: &Path,
) -> Result<AuthenticatedProductionCheckpointCodecFixture, LifecycleApiError> {
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: node.clone(),
        arch: VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: Icount { retired: 0 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .map_err(|error| fixture_error("build checkpoint world", error))?;
    let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        Seed::from_u64(0x4f52_4143),
        0,
    )
    .map_err(|error| fixture_error("build checkpoint scenario", error))?;
    let scenario = source.scenario_def();
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        Shift::new(0).map_err(|error| fixture_error("build zero shift", error))?,
        4,
        SimInstant { nanos: 4 },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let scheduler = SingleScheduler::new(runtime_scenario)
        .map_err(|error| fixture_error("build checkpoint scheduler", error))?;
    let scheduler_checkpoint = scheduler
        .checkpoint()
        .map_err(|error| fixture_error("capture scheduler continuation", error))?;

    let nodes = ProductionNodeSet::new();
    let host_manifests = crucible::model::production_host_fault_adapter_manifests()
        .map_err(|error| fixture_error("build host fault manifests", error))?;
    let fault_runtime = ProductionFaultRuntime::new(
        source.plan().fault_signals().clone(),
        None,
        SignalBoundarySnapshot::default(),
        scenario.id(),
        host_manifests,
        &nodes,
    )
    .map_err(|error| fixture_error("build fault runtime", error))?;
    let fault_checkpoint = fault_runtime
        .checkpoint(&mut ProductionNodeSet::new())
        .map_err(|error| fixture_error("capture fault runtime", error))?
        .with_unvalidated_test_node(
            source.plan().fault_signals(),
            node.clone(),
            ContentHash::from_bytes(b"integration checkpoint fingerprint"),
        )
        .map_err(|error| fixture_error("bind node fingerprint", error))?;

    let configuration = Configuration {
        def: scenario.clone(),
        schedule: Schedule::empty(),
    };
    let modeled_checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime { ticks: 0 },
        BTreeMap::from([(node.clone(), Icount { retired: 0 })]),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .map_err(|error| fixture_error("build modeled checkpoint", error))?;
    let runtime_hash = ContentHash::from_bytes(b"matching integration runtime");
    let snapshot = ExactSnapshotHandle::diskless(
        modeled_checkpoint,
        QemuReplayOracleValidation::Match { runtime_hash },
    )
    .map_err(|error| fixture_error("build exact snapshot", error))?;

    fs::create_dir_all(run_state_root)
        .map_err(|error| loop_factory_error(format!("create checkpoint fixture root: {error}")))?;
    let overlay = run_state_root.join("fixture-overlay.qcow2");
    let vmstate = run_state_root.join("fixture-vmstate.bin");
    fs::write(&overlay, b"overlay fixture")
        .map_err(|error| loop_factory_error(format!("write fixture overlay: {error}")))?;
    fs::write(&vmstate, b"vmstate fixture")
        .map_err(|error| loop_factory_error(format!("write fixture VMState: {error}")))?;
    let overlay_artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
        &overlay,
        &run_state_root.join("fixture-overlay-chunks"),
        "root overlay fixture",
        0,
        source.plan().fault_signals().resource_limits(),
        &mut || Ok(()),
    )
    .map_err(|error| fixture_error("stage sparse overlay", error))?;
    let vmstate_artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(vmstate.clone()),
        identity: hash_file(&vmstate)
            .map_err(|error| loop_factory_error(format!("hash fixture VMState: {error}")))?,
        length: fs::metadata(&vmstate)
            .map_err(|error| loop_factory_error(format!("inspect fixture VMState: {error}")))?
            .len(),
        chunks: Vec::new(),
        sparse: false,
        extents: Vec::new(),
    };
    let manifest_identity =
        exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
            configuration: configuration.id(),
            immutable_backing: Some(ContentHash::from_bytes(b"immutable backing")),
            node: &node,
            counter: 0,
            scheduler_time: VirtualTime { ticks: 0 },
            snapshot: snapshot.id(),
            fault_identity: fault_checkpoint.id(),
            overlay: overlay_artifact.identity,
            vmstate: vmstate_artifact.identity,
        });
    let mut checkpoint = ProductionVmExactCheckpointSet {
        identity: ContentHash::default(),
        configuration: configuration.clone(),
        scheduler: scheduler_checkpoint,
        event_log_objects: BTreeMap::new(),
        signal_artifact_objects: BTreeMap::new(),
        trigger_state: EventGraphState::default(),
        assertion_state: HostAssertionEvaluator::new(source.properties()).checkpoint(),
        terminal_verdict: None,
        terminal_cause: None,
        initial_lifecycle_observations_pending: true,
        branch: None,
        recorded_controls: Vec::new(),
        selectable_catalog_plans: BTreeMap::new(),
        fault_checkpoint: Some(fault_checkpoint),
        targets: BTreeMap::from([(
            node.clone(),
            ProductionVmExactCheckpointTarget {
                configuration: configuration.clone(),
                immutable_backing: Some(ContentHash::from_bytes(b"immutable backing")),
                counter: 0,
                scheduler_time: VirtualTime { ticks: 0 },
                snapshot,
                overlay_artifact,
                vmstate_artifact,
                manifest_identity,
            },
        )]),
        node_generations: BTreeMap::from([(node.clone(), 1)]),
        node_service_states: BTreeMap::from([(node, ProductionNodeServiceState::Running)]),
    };
    let prepared = prepare_exact_checkpoint_set_with_boundary(
        run_state_root,
        scenario.id(),
        source.plan().fault_signals().resource_limits(),
        &mut checkpoint,
        &mut || Ok(()),
    )
    .map_err(|error| fixture_error("prepare fixture checkpoint", error))?;
    let identity = prepared.identity();
    prepared
        .publish()
        .map_err(|error| fixture_error("publish fixture checkpoint", error))?;
    let closure = open_exact_checkpoint_closure(run_state_root, &source, identity)?;
    let basis = authenticate_portable_exact_checkpoint_resume_basis(&source, &closure)?;
    if !basis.replay_oracle_ready() {
        return Err(loop_factory_error(
            "fixture production checkpoint metadata is not replay-oracle ready",
        ));
    }

    Ok(AuthenticatedProductionCheckpointCodecFixture {
        source,
        configuration,
        closure,
    })
}

fn fixture_error(role: &str, error: impl std::fmt::Debug) -> LifecycleApiError {
    loop_factory_error(format!("{role}: {error:?}"))
}
