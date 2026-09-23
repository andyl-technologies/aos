//! Production exact-checkpoint codec fixtures for cross-crate integration tests.

use super::*;
use std::io::SeekFrom;

const STREAMING_FIXTURE_BUFFER_BYTES: usize = 64 * 1024;
const STREAMING_FIXTURE_OVERLAY_BYTES: u64 = 20 * ARTIFACT_CHUNK_BYTES_U64 + 137;
const STREAMING_FIXTURE_VMSTATE_BYTES: u64 = 3 * ARTIFACT_CHUNK_BYTES_U64 + 257;

/// Authenticated production checkpoint codec material for integration tests.
///
/// The fixture represents a zero-progress scheduler boundary and uses placeholder
/// overlay and VMState bytes. It can exercise closure encoding, transfer, and
/// authentication, but it cannot launch or restore a QEMU process.
pub struct AuthenticatedProductionCheckpointCodecFixture {
    source: ScenarioDefForm,
    configuration: Configuration,
    closure: ProductionExactCheckpointClosure,
    overlay_bytes: u64,
    vmstate_bytes: u64,
}

/// Authenticated v9 closure containing a direct RAM base and one delta.
pub struct AuthenticatedProductionExactRamCodecFixture {
    source: ScenarioDefForm,
    configuration: Configuration,
    closure: ProductionExactCheckpointClosure,
    parent_closure: ContentHash,
    layer_identities: Vec<QmpCheckpointIdentity>,
}

impl AuthenticatedProductionExactRamCodecFixture {
    /// Returns the scenario source that authenticates both retained closures.
    #[must_use]
    pub const fn source(&self) -> &ScenarioDefForm {
        &self.source
    }

    /// Returns the modeled configuration captured by the fixture.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the final self-contained direct-plus-delta closure.
    #[must_use]
    pub const fn closure(&self) -> &ProductionExactCheckpointClosure {
        &self.closure
    }

    /// Returns the retained direct closure named as delta provenance.
    #[must_use]
    pub const fn parent_closure(&self) -> ContentHash {
        self.parent_closure
    }

    /// Returns QEMU checkpoint identities in direct-then-delta order.
    #[must_use]
    pub fn layer_identities(&self) -> &[QmpCheckpointIdentity] {
        &self.layer_identities
    }
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

    /// Returns the sparse overlay's logical length.
    #[must_use]
    pub const fn overlay_bytes(&self) -> u64 {
        self.overlay_bytes
    }

    /// Returns the dense VMState artifact's logical length.
    #[must_use]
    pub const fn vmstate_bytes(&self) -> u64 {
        self.vmstate_bytes
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
    build_production_checkpoint_codec_fixture(run_state_root, FixtureArtifactShape::Placeholder)
}

/// Builds a multi-chunk production checkpoint fixture for streaming gates.
///
/// The dense VMState spans distinct native chunks. The sparse overlay contains
/// two distant allocated extents, so stored bytes remain below its logical
/// length. The authenticated placeholder bytes cannot launch QEMU.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when fixture construction or durable closure
/// publication under `run_state_root` fails.
pub fn build_streaming_production_checkpoint_codec_fixture(
    run_state_root: &Path,
) -> Result<AuthenticatedProductionCheckpointCodecFixture, LifecycleApiError> {
    build_production_checkpoint_codec_fixture(run_state_root, FixtureArtifactShape::Streaming)
}

/// Builds a v9 closure with a retained direct RAM base and one delta layer.
///
/// The fixture passes through the production staging, manifest, publication,
/// open, and resume-basis paths. Its compact CRUCRAM placeholders model the
/// storage protocol and are deliberately not accepted as native QEMU state.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when either closure cannot be staged,
/// published, reopened, or authenticated.
pub fn build_exact_ram_production_checkpoint_codec_fixture(
    run_state_root: &Path,
) -> Result<AuthenticatedProductionExactRamCodecFixture, LifecycleApiError> {
    build_exact_ram_production_checkpoint_codec_fixture_inner(run_state_root)
}

fn build_exact_ram_production_checkpoint_codec_fixture_inner(
    run_state_root: &Path,
) -> Result<AuthenticatedProductionExactRamCodecFixture, LifecycleApiError> {
    let base = build_production_checkpoint_codec_fixture(
        run_state_root,
        FixtureArtifactShape::Placeholder,
    )?;
    let source = base.source().clone();
    let configuration = base.configuration().clone();
    let scenario = source.scenario_def();
    let limits = source.plan().fault_signals().resource_limits();
    let mut checkpoint = load_exact_checkpoint_set(
        run_state_root,
        &scenario,
        &source,
        base.closure().identity(),
    )?;
    let node = source
        .world()
        .vm_nodes()
        .first()
        .map(|node| node.id.clone())
        .ok_or_else(|| loop_factory_error("exact RAM fixture scenario has no VM node"))?;
    let (direct_layer, device_sha256, device_artifact) = checkpoint
        .targets
        .get(&node)
        .and_then(|target| {
            target.native_exact_ram().and_then(|exact_ram| {
                exact_ram.layers.first().cloned().map(|layer| {
                    (
                        layer,
                        exact_ram.device_content_sha256,
                        exact_ram.device_artifact.clone(),
                    )
                })
            })
        })
        .ok_or_else(|| loop_factory_error("fixture direct RAM layer disappeared"))?;
    let parent_closure = base.closure().identity();
    let direct_identity: QmpCheckpointIdentity = direct_layer.identity.into();
    let topology = direct_layer.topology;

    let delta_path = run_state_root.join("fixture-delta.crucram");
    fs::write(&delta_path, b"CRUCRAM1 fixture changed RAM extent")
        .map_err(|error| loop_factory_error(format!("write delta RAM fixture: {error}")))?;
    let delta_artifact = stage_checkpoint_artifact_chunks_with_boundary(
        &delta_path,
        &run_state_root.join("fixture-delta-chunks"),
        "delta RAM fixture",
        direct_layer.artifact.length,
        limits,
        &mut || Ok(()),
    )
    .map_err(|error| fixture_error("stage delta RAM fixture", error))?;
    let delta_sha256 = hash_exact_checkpoint_file_sha256_with_boundary(&delta_path, &mut || Ok(()))
        .map_err(|error| fixture_error("hash delta RAM fixture", error))?;

    let delta_identity = exact_ram_fixture_qmp_identity(&checkpoint, &node)?;
    let delta_layer = ProductionExactRamLayer {
        kind: ProductionExactRamKind::Delta,
        identity: delta_identity.into(),
        parent: Some(direct_identity.into()),
        topology,
        ram_regions: 1,
        ram_records: 1,
        content_sha256: delta_sha256,
        artifact: delta_artifact,
    };
    let delta = ProductionExactRamCheckpoint::new(
        Some(parent_closure),
        device_sha256,
        device_artifact,
        vec![direct_layer, delta_layer],
    )
    .map_err(|error| fixture_error("build delta RAM checkpoint", error))?;
    bind_exact_ram_fixture_target(&mut checkpoint, &node, delta, limits)?;
    let prepared = prepare_exact_checkpoint_set_with_boundary(
        run_state_root,
        scenario.id(),
        limits,
        &mut checkpoint,
        &mut || Ok(()),
    )
    .map_err(|error| fixture_error("prepare delta RAM fixture", error))?;
    let identity = prepared.identity();
    prepared
        .publish()
        .map_err(|error| fixture_error("publish delta RAM fixture", error))?;
    let closure = open_exact_checkpoint_closure(run_state_root, &source, identity)?;
    Ok(AuthenticatedProductionExactRamCodecFixture {
        source,
        configuration,
        closure,
        parent_closure,
        layer_identities: vec![direct_identity, delta_identity],
    })
}

fn exact_ram_fixture_qmp_identity(
    checkpoint: &ProductionVmExactCheckpointSet,
    node: &NodeId,
) -> Result<QmpCheckpointIdentity, LifecycleApiError> {
    let target = checkpoint
        .targets
        .get(node)
        .ok_or_else(|| loop_factory_error("exact RAM fixture target disappeared"))?;
    let fault_identity = checkpoint
        .fault_checkpoint
        .as_ref()
        .ok_or_else(|| loop_factory_error("exact RAM fixture has no fault continuation"))?
        .id();
    exact_ram_checkpoint_qmp_identity(ExactRamCheckpointQmpIdentityBasis {
        configuration: &checkpoint.configuration,
        immutable_backing: target.immutable_backing,
        node,
        counter: target.counter,
        scheduler_time: target.scheduler_time,
        checkpoint: target.snapshot.checkpoint(),
        fault_identity,
        scheduler: &checkpoint.scheduler,
    })
    .map_err(|error| loop_factory_error(error.to_string()))
}

fn bind_exact_ram_fixture_target(
    checkpoint: &mut ProductionVmExactCheckpointSet,
    node: &NodeId,
    exact_ram: ProductionExactRamCheckpoint,
    limits: FaultResourceLimits,
) -> Result<(), LifecycleApiError> {
    let fault_checkpoint = checkpoint
        .fault_checkpoint
        .as_ref()
        .ok_or_else(|| loop_factory_error("fixture fault continuation disappeared"))?;
    let fault_identity = exact_checkpoint_fault_object_identity(fault_checkpoint, limits)?;
    let target = checkpoint
        .targets
        .get_mut(node)
        .ok_or_else(|| loop_factory_error("fixture target disappeared"))?;
    let ProductionVmExactCheckpointMaterialization::Native {
        overlay_artifact,
        exact_ram: target_exact_ram,
        manifest_identity,
    } = &mut target.materialization
    else {
        return Err(loop_factory_error(
            "fixture target lost native materialization",
        ));
    };
    *manifest_identity = exact_ram_checkpoint_target_manifest_identity(
        ExactCheckpointTargetManifestBasis {
            configuration: target.configuration.id(),
            immutable_backing: target.immutable_backing,
            node,
            counter: target.counter,
            scheduler_time: target.scheduler_time,
            snapshot: exact_checkpoint_snapshot_object_identity(&target.snapshot, limits)?,
            fault_identity,
            overlay: overlay_artifact.identity,
            device_state: exact_ram.device_artifact.identity,
        },
        &exact_ram,
    );
    **target_exact_ram = exact_ram;
    Ok(())
}

fn bind_direct_ram_fixture_target(
    run_state_root: &Path,
    checkpoint: &mut ProductionVmExactCheckpointSet,
    node: &NodeId,
    limits: FaultResourceLimits,
) -> Result<(), LifecycleApiError> {
    let direct_path = run_state_root.join("fixture-direct.crucram");
    fs::write(&direct_path, b"CRUCRAM1 fixture direct RAM base")
        .map_err(|error| loop_factory_error(format!("write direct RAM fixture: {error}")))?;
    let direct_artifact = stage_checkpoint_artifact_chunks_with_boundary(
        &direct_path,
        &run_state_root.join("fixture-direct-chunks"),
        "direct RAM fixture",
        0,
        limits,
        &mut || Ok(()),
    )
    .map_err(|error| fixture_error("stage direct RAM fixture", error))?;
    let direct_sha256 =
        hash_exact_checkpoint_file_sha256_with_boundary(&direct_path, &mut || Ok(()))
            .map_err(|error| fixture_error("hash direct RAM fixture", error))?;
    let device_path = run_state_root.join("fixture-vmstate.bin");
    let device_sha256 =
        hash_exact_checkpoint_file_sha256_with_boundary(&device_path, &mut || Ok(()))
            .map_err(|error| fixture_error("hash device-state fixture", error))?;
    let direct_identity = exact_ram_fixture_qmp_identity(checkpoint, node)?;
    let direct_layer = ProductionExactRamLayer {
        kind: ProductionExactRamKind::Direct,
        identity: direct_identity.into(),
        parent: None,
        topology: ContentHash::from_bytes(b"fixture RAMBlock topology"),
        ram_regions: 1,
        ram_records: 1,
        content_sha256: direct_sha256,
        artifact: direct_artifact,
    };
    let device_artifact = checkpoint
        .targets
        .get(node)
        .and_then(ProductionVmExactCheckpointTarget::native_exact_ram)
        .ok_or_else(|| loop_factory_error("fixture direct target disappeared"))?
        .device_artifact
        .clone();
    let direct =
        ProductionExactRamCheckpoint::new(None, device_sha256, device_artifact, vec![direct_layer])
            .map_err(|error| fixture_error("build direct RAM checkpoint", error))?;

    bind_exact_ram_fixture_target(checkpoint, node, direct, limits)
}

#[derive(Clone, Copy)]
enum FixtureArtifactShape {
    Placeholder,
    Streaming,
}

fn build_production_checkpoint_codec_fixture(
    run_state_root: &Path,
    artifact_shape: FixtureArtifactShape,
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
        white_box: crucible::WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .map_err(|error| fixture_error("build checkpoint world", error))?;
    let properties = crucible::Properties::from_assertions_for_world(
        &world,
        vec![crucible::AssertionDef::guest_unreachable(
            crucible::AssertionId::from_name("no-split-brain"),
            "the fixed checkpoint fixture retains its property boundary",
        )],
    )
    .map_err(|error| fixture_error("build checkpoint properties", error))?;
    let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &crucible::Plan::empty(),
        &properties,
        Seed::from_u64(0x4f52_4143),
        0,
    )
    .map_err(|error| fixture_error("build checkpoint scenario", error))?;
    let recovery = crucible::campaign::SelectableDeclaration::new(
        "product.recovery",
        crucible::campaign::ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        crucible::campaign::ChoiceDomain::Boolean(
            crucible::campaign::BooleanDomain::new(1)
                .map_err(|error| fixture_error("build checkpoint selectable domain", error))?,
        ),
        crucible::campaign::ChoiceValue::Boolean(false),
        crucible::campaign::ChoiceClassContext::new(BTreeSet::new())
            .map_err(|error| fixture_error("build checkpoint selectable class", error))?,
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .map_err(|error| fixture_error("build checkpoint selectable declaration", error))?;
    let selectables = crucible::ScenarioSelectables::new(
        &world,
        crucible::ScenarioSelectableLimits::new(4, 8, 16, 32)
            .map_err(|error| fixture_error("build checkpoint selectable limits", error))?,
        vec![recovery],
    )
    .map_err(|error| fixture_error("build checkpoint scenario selectables", error))?;
    let source = source
        .with_selectables(selectables)
        .map_err(|error| fixture_error("attach checkpoint scenario selectables", error))?;
    let fixture_nodes = vec![node.clone()];
    let scenario = source.scenario_def();
    let configuration = Configuration {
        def: scenario.clone(),
        schedule: Schedule::empty(),
    };
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

    let nodes = QemuNodeSet::new();
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
        .checkpoint(&mut QemuNodeSet::new())
        .map_err(|error| fixture_error("capture fault runtime", error))?
        .with_unvalidated_test_node(
            source.plan().fault_signals(),
            node,
            ContentHash::from_bytes(b"integration checkpoint fingerprint"),
        )
        .map_err(|error| fixture_error("bind node fingerprint", error))?;

    let parent_configuration = if configuration.schedule.is_empty() {
        None
    } else {
        let parent_length = configuration.schedule.len().saturating_sub(1);
        let parent_schedule = configuration
            .schedule
            .prefix(parent_length)
            .map_err(|error| fixture_error("derive checkpoint parent schedule", error))?;
        Some(Configuration {
            def: scenario.clone(),
            schedule: parent_schedule,
        })
    };
    let modeled_checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        parent_configuration.as_ref(),
        VirtualTime { ticks: 0 },
        fixture_nodes
            .iter()
            .cloned()
            .map(|node| (node, Icount { retired: 0 }))
            .collect(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .map_err(|error| fixture_error("build modeled checkpoint", error))?;
    let snapshot = ExactSnapshotHandle::diskless(modeled_checkpoint)
        .map_err(|error| fixture_error("build exact snapshot", error))?;

    fs::create_dir_all(run_state_root)
        .map_err(|error| loop_factory_error(format!("create checkpoint fixture root: {error}")))?;
    let overlay = run_state_root.join("fixture-overlay.qcow2");
    let vmstate = run_state_root.join("fixture-vmstate.bin");
    write_fixture_artifacts(&overlay, &vmstate, artifact_shape)?;
    let overlay_bytes = fs::metadata(&overlay)
        .map_err(|error| loop_factory_error(format!("inspect fixture overlay: {error}")))?
        .len();
    let vmstate_bytes = fs::metadata(&vmstate)
        .map_err(|error| loop_factory_error(format!("inspect fixture VMState: {error}")))?
        .len();
    let overlay_artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
        &File::open(&overlay).map_err(|error| fixture_error("open fixture overlay", error))?,
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
    let bootstrap_identity = ProductionExactCheckpointIdentity {
        checkpoint: ContentHash::from_bytes(b"fixture checkpoint"),
        target: ContentHash::from_bytes(b"fixture target"),
        frontier: ContentHash::from_bytes(b"fixture frontier"),
    };
    let bootstrap_exact_ram = ProductionExactRamCheckpoint::new(
        None,
        hash_exact_checkpoint_file_sha256_with_boundary(&vmstate, &mut || Ok(()))
            .map_err(|error| fixture_error("hash fixture device state", error))?,
        vmstate_artifact.clone(),
        vec![ProductionExactRamLayer {
            kind: ProductionExactRamKind::Direct,
            identity: bootstrap_identity,
            parent: None,
            topology: ContentHash::from_bytes(b"fixture bootstrap topology"),
            ram_regions: 1,
            ram_records: 1,
            content_sha256: hash_exact_checkpoint_file_sha256_with_boundary(&vmstate, &mut || {
                Ok(())
            })
            .map_err(|error| fixture_error("hash fixture bootstrap RAM", error))?,
            artifact: vmstate_artifact,
        }],
    )
    .map_err(|error| fixture_error("build bootstrap exact RAM", error))?;
    let mut selectable_catalog_plans = BTreeMap::new();
    for node in &fixture_nodes {
        let declarations = source
            .selectables()
            .guest_declarations(node)
            .map(|declaration| {
                crucible_protocol::selectable_catalog_plan::SelectablePlanDeclaration::new(
                    declaration.name(),
                    declaration.domain().canonical_bytes(),
                    declaration.default().canonical_bytes(),
                    declaration.semantic_tags().iter().cloned().collect(),
                    if declaration.required() {
                        crucible_protocol::selectable_catalog_plan::SelectablePlanPresence::Required
                    } else {
                        crucible_protocol::selectable_catalog_plan::SelectablePlanPresence::Optional
                    },
                )
                .map_err(|error| fixture_error("build selectable declaration", error))
            })
            .collect::<Result<Vec<_>, LifecycleApiError>>()?;
        if declarations.is_empty() {
            continue;
        }

        let source_limits = source.selectables().limits();
        let limits = crucible_protocol::selectable_catalog_plan::SelectablePlanLimits::new(
            source_limits.declarations_per_node() as usize,
            source_limits.requests_per_selectable(),
            source_limits.requests_per_node(),
        )
        .map_err(|error| fixture_error("build selectable limits", error))?;
        let continuation = if configuration == Configuration::genesis(configuration.def.clone()) {
            crucible_protocol::selectable_catalog_plan::SelectablePlanContinuation::cold()
        } else {
            let registered = declarations
                .iter()
                .map(|declaration| declaration.registration().selectable_id().to_owned())
                .collect::<BTreeSet<_>>();
            let last_registration_sequence = u64::try_from(registered.len())
                .map_err(|error| fixture_error("count frozen selectable registrations", error))?;
            crucible_protocol::selectable_catalog_plan::SelectablePlanContinuation::new(
                crucible_protocol::selectable_catalog_plan::SelectablePlanPhase::Frozen,
                registered,
                Some(last_registration_sequence),
                BTreeMap::new(),
                None,
                None,
            )
            .map_err(|error| fixture_error("build frozen selectable continuation", error))?
        };
        let plan = crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::new(
            limits,
            declarations,
            continuation,
        )
        .map_err(|error| fixture_error("build selectable catalog plan", error))?;
        selectable_catalog_plans.insert(node.clone(), plan);
    }

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
        selectable_catalog_plans,
        fault_checkpoint: Some(fault_checkpoint),
        targets: fixture_nodes
            .iter()
            .cloned()
            .map(|node| {
                (
                    node,
                    ProductionVmExactCheckpointTarget {
                        configuration: Arc::new(configuration.clone()),
                        immutable_backing: ContentHash::from_bytes(b"immutable backing"),
                        counter: 0,
                        scheduler_time: VirtualTime { ticks: 0 },
                        snapshot: snapshot.clone(),
                        materialization: ProductionVmExactCheckpointMaterialization::Native {
                            overlay_artifact: overlay_artifact.clone(),
                            exact_ram: Box::new(bootstrap_exact_ram.clone()),
                            manifest_identity: ContentHash::default(),
                        },
                    },
                )
            })
            .collect(),
        failed_host_io: BTreeMap::new(),
        node_generations: fixture_nodes
            .iter()
            .cloned()
            .map(|node| (node, 1))
            .collect(),
        node_service_states: fixture_nodes
            .iter()
            .cloned()
            .map(|node| (node, ProductionNodeServiceState::Running))
            .collect(),
        repository_restore: None,
    };
    for node in &fixture_nodes {
        bind_direct_ram_fixture_target(
            run_state_root,
            &mut checkpoint,
            node,
            source.plan().fault_signals().resource_limits(),
        )?;
    }
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
    Ok(AuthenticatedProductionCheckpointCodecFixture {
        source,
        configuration,
        closure,
        overlay_bytes,
        vmstate_bytes,
    })
}

fn write_fixture_artifacts(
    overlay: &Path,
    vmstate: &Path,
    shape: FixtureArtifactShape,
) -> Result<(), LifecycleApiError> {
    match shape {
        FixtureArtifactShape::Placeholder => {
            fs::write(overlay, b"overlay fixture")
                .map_err(|error| loop_factory_error(format!("write fixture overlay: {error}")))?;
            fs::write(vmstate, b"vmstate fixture")
                .map_err(|error| loop_factory_error(format!("write fixture VMState: {error}")))?;
        }
        FixtureArtifactShape::Streaming => {
            write_sparse_fixture(overlay)?;
            write_dense_fixture(vmstate)?;
        }
    }
    Ok(())
}

fn write_sparse_fixture(path: &Path) -> Result<(), LifecycleApiError> {
    let mut file = File::create(path)
        .map_err(|error| loop_factory_error(format!("create sparse fixture overlay: {error}")))?;
    file.set_len(STREAMING_FIXTURE_OVERLAY_BYTES)
        .map_err(|error| loop_factory_error(format!("size sparse fixture overlay: {error}")))?;
    let mut buffer = vec![0_u8; STREAMING_FIXTURE_BUFFER_BYTES];

    fill_fixture_buffer(&mut buffer, 0x35);
    file.seek(SeekFrom::Start(8 * 1024))
        .and_then(|_| file.write_all(&buffer))
        .map_err(|error| {
            loop_factory_error(format!("write first sparse fixture extent: {error}"))
        })?;

    fill_fixture_buffer(&mut buffer, 0xa7);
    let final_extent = STREAMING_FIXTURE_OVERLAY_BYTES
        .checked_sub(u64::try_from(buffer.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| loop_factory_error("sparse fixture overlay length underflow"))?;
    file.seek(SeekFrom::Start(final_extent))
        .and_then(|_| file.write_all(&buffer))
        .map_err(|error| {
            loop_factory_error(format!("write final sparse fixture extent: {error}"))
        })?;
    file.sync_all()
        .map_err(|error| loop_factory_error(format!("sync sparse fixture overlay: {error}")))
}

fn write_dense_fixture(path: &Path) -> Result<(), LifecycleApiError> {
    let mut file = File::create(path)
        .map_err(|error| loop_factory_error(format!("create dense fixture VMState: {error}")))?;
    let mut buffer = vec![0_u8; STREAMING_FIXTURE_BUFFER_BYTES];
    let mut written = 0_u64;
    let mut block = 0_u64;
    while written < STREAMING_FIXTURE_VMSTATE_BYTES {
        fill_fixture_buffer(&mut buffer, block as u8);
        let remaining = STREAMING_FIXTURE_VMSTATE_BYTES - written;
        let count = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        file.write_all(&buffer[..count])
            .map_err(|error| loop_factory_error(format!("write dense fixture VMState: {error}")))?;
        written = written
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| loop_factory_error("dense fixture VMState length overflow"))?;
        block = block.saturating_add(1);
    }
    file.sync_all()
        .map_err(|error| loop_factory_error(format!("sync dense fixture VMState: {error}")))
}

fn fill_fixture_buffer(buffer: &mut [u8], block: u8) {
    for (offset, byte) in buffer.iter_mut().enumerate() {
        *byte = (offset as u8).wrapping_mul(31).wrapping_add(block);
    }
}

fn fixture_error(role: &str, error: impl std::fmt::Debug) -> LifecycleApiError {
    loop_factory_error(format!("{role}: {error:?}"))
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture assertions identify the violated invariant.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn streaming_fixture_has_distinct_dense_chunks_and_sparse_extents() {
        let root = tempfile::tempdir().expect("streaming fixture root");
        let fixture = build_streaming_production_checkpoint_codec_fixture(root.path())
            .expect("authenticated streaming fixture");

        assert_eq!(fixture.overlay_bytes(), STREAMING_FIXTURE_OVERLAY_BYTES);
        assert_eq!(fixture.vmstate_bytes(), STREAMING_FIXTURE_VMSTATE_BYTES);

        let objects = fixture.closure().objects();
        let full_chunks = objects
            .iter()
            .filter(|object| object.length() == ARTIFACT_CHUNK_BYTES_U64)
            .count();
        assert!(full_chunks >= 5, "expected dense and sparse full chunks");
        assert!(
            objects.windows(2).all(|pair| pair[0] != pair[1]),
            "portable inventory must contain distinct identities"
        );

        let stored_bytes = objects.iter().map(|object| object.length()).sum::<u64>();
        assert!(
            stored_bytes < fixture.overlay_bytes() + fixture.vmstate_bytes(),
            "sparse fixture must store less than its logical artifact bytes"
        );
    }
}
