//! Unit tests for durable exact-checkpoint closure storage.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use super::{ExactSnapshotHandle as Snapshot, *};

fn wire_string(value: &str) -> decode::FallibleString {
    decode::FallibleString::new(String::from(value))
}

fn stream_artifact(
    artifact: &ProductionCheckpointArtifact,
    role: &str,
) -> Result<Vec<u8>, LifecycleApiError> {
    let mut bytes = Vec::new();
    stream_checkpoint_artifact_with_boundary(artifact, &mut bytes, role, &mut || Ok(()))?;
    Ok(bytes)
}

fn manifest() -> ClosureManifest {
    ClosureManifest {
        format_version: MANIFEST_VERSION,
        scenario: ContentHash::default(),
        configuration: ContentHash::default(),
        schedule: ContentHash::default(),
        frontier: 0,
        scheduler: ContentHash::default(),
        event_log_segments: Vec::new(),
        signal_artifacts: Vec::new(),
        trigger_state: ContentHash::default(),
        assertion_state: ContentHash::default(),
        lifecycle_state: ContentHash::default(),
        fault_checkpoint: ContentHash::default(),
        targets: Vec::new(),
        failed_host_io: Vec::new(),
        node_generations: Vec::new(),
        node_service_states: Vec::new(),
        identity: ContentHash::default(),
    }
}

fn target(node: &str) -> TargetManifest {
    let chunk = ContentHash::from_bytes(b"artifact");
    let overlay_extents = vec![ArtifactExtent {
        start_chunk: 0,
        chunks: vec![chunk],
    }];
    let overlay = ArtifactManifest {
        identity: sparse_artifact_identity(8, &overlay_extents)
            .expect("derive sparse artifact fixture identity"),
        length: 8,
        chunks: Vec::new(),
        sparse: true,
        extents: overlay_extents,
    };
    let device = ArtifactManifest {
        identity: ContentHash::from_bytes(b"artifact"),
        length: 8,
        chunks: vec![chunk],
        sparse: false,
        extents: Vec::new(),
    };
    TargetManifest {
        node: wire_string(node),
        immutable_backing: ContentHash::from_bytes(b"immutable backing"),
        counter: 0,
        scheduler_time: 0,
        snapshot: ContentHash::from_bytes(node.as_bytes()),
        overlay,
        exact_ram: ExactRamManifest {
            parent_closure: None,
            device_content_sha256: ContentHash::from_bytes(b"device sha256"),
            device: device.clone(),
            layers: vec![ExactRamLayerManifest {
                kind: ProductionExactRamKind::Direct,
                identity: ProductionExactCheckpointIdentity {
                    checkpoint: ContentHash::from_bytes(b"checkpoint"),
                    target: ContentHash::from_bytes(node.as_bytes()),
                    frontier: ContentHash::from_bytes(b"frontier"),
                },
                parent: None,
                topology: ContentHash::from_bytes(b"topology"),
                ram_regions: 1,
                ram_records: 1,
                content_sha256: ContentHash::from_bytes(b"ram sha256"),
                artifact: device,
            }],
        },
        manifest_identity: ContentHash::default(),
    }
}

fn failed_host_io(node: &str) -> FailedHostIoManifest {
    FailedHostIoManifest {
        node: wire_string(node),
        execution_binding: ContentHash::from_canonical_material(
            "crucible.test.failed-host-io-binding.v1",
            node,
        ),
        checkpoint: ContentHash::from_canonical_material(
            "crucible.test.failed-host-io-checkpoint.v1",
            node,
        ),
        fingerprint_at: 41,
        fingerprint: ContentHash::from_canonical_material(
            "crucible.test.failed-node-fingerprint.v1",
            node,
        ),
    }
}

fn build_one_node_raw_checkpoint(
    run_state_root: &Path,
    selectable_continuation: Option<
        crucible_protocol::selectable_catalog_plan::SelectablePlanContinuation,
    >,
) -> (
    ScenarioDefForm,
    ProductionVmExactCheckpointSet,
    NodeId,
    ContentHash,
) {
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
        white_box: if selectable_continuation.is_some() {
            crucible::WhiteBoxPolicy::Enabled
        } else {
            crucible::WhiteBoxPolicy::Disabled
        },
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("build one-node checkpoint world");
    let mut source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        Seed::from_u64(0x4f52_4143),
        0,
    )
    .expect("build one-node checkpoint scenario");
    let selectable_plan = if let Some(continuation) = selectable_continuation {
        use crucible_protocol::selectable_catalog_plan::{
            SelectableCatalogPlan, SelectablePlanDeclaration, SelectablePlanLimits,
            SelectablePlanPresence,
        };

        let domain = crucible::campaign::ChoiceDomain::Boolean(
            crucible::campaign::BooleanDomain::new(1).expect("build selectable Boolean domain"),
        );
        let default = crucible::campaign::ChoiceValue::Boolean(false);
        let recovery = crucible::campaign::SelectableDeclaration::new(
            "checkpoint.recovery",
            crucible::campaign::ChoiceSource::Guest {
                node: node.name.clone(),
                protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
            },
            domain.clone(),
            default.clone(),
            crucible::campaign::ChoiceClassContext::new(BTreeSet::new())
                .expect("build selectable choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("build scenario selectable declaration");
        let retry = crucible::campaign::SelectableDeclaration::new(
            "checkpoint.retry",
            crucible::campaign::ChoiceSource::Guest {
                node: node.name.clone(),
                protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
            },
            domain.clone(),
            crucible::campaign::ChoiceValue::Boolean(true),
            crucible::campaign::ChoiceClassContext::new(BTreeSet::new())
                .expect("build selectable choice class"),
            BTreeSet::new(),
            true,
        )
        .expect("build second scenario selectable declaration");
        let limits = crucible::ScenarioSelectableLimits::new(2, 2, 1, 2)
            .expect("build scenario selectable limits");
        let selectables = crucible::ScenarioSelectables::new(&world, limits, vec![recovery, retry])
            .expect("build scenario selectables");
        source = source
            .with_selectables(selectables)
            .expect("attach scenario selectables");

        let declarations = vec![
            SelectablePlanDeclaration::new(
                "checkpoint.recovery",
                domain.canonical_bytes(),
                default.canonical_bytes(),
                Vec::new(),
                SelectablePlanPresence::Required,
            )
            .expect("build checkpoint selectable declaration"),
            SelectablePlanDeclaration::new(
                "checkpoint.retry",
                domain.canonical_bytes(),
                crucible::campaign::ChoiceValue::Boolean(true).canonical_bytes(),
                Vec::new(),
                SelectablePlanPresence::Required,
            )
            .expect("build second checkpoint selectable declaration"),
        ];
        Some(
            SelectableCatalogPlan::new(
                SelectablePlanLimits::new(2, 1, 2).expect("build checkpoint selectable limits"),
                declarations,
                continuation,
            )
            .expect("build checkpoint selectable plan"),
        )
    } else {
        None
    };
    let scenario = source.scenario_def();
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        Shift::new(0).expect("zero shift validates"),
        4,
        SimInstant { nanos: 4 },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let scheduler = SingleScheduler::new(runtime_scenario).expect("build one-node scheduler");
    let scheduler_checkpoint = scheduler
        .checkpoint()
        .expect("checkpoint one-node scheduler");

    let nodes = QemuNodeSet::new();
    let fault_runtime = ProductionFaultRuntime::new(
        source.plan().fault_signals().clone(),
        None,
        SignalBoundarySnapshot::default(),
        scenario.id(),
        super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .expect("build inert one-node fault runtime");
    let fault_checkpoint = fault_runtime
        .checkpoint(&mut QemuNodeSet::new())
        .expect("checkpoint inert fault runtime")
        .with_unvalidated_test_node(
            source.plan().fault_signals(),
            node.clone(),
            ContentHash::from_bytes(b"one-node execution fingerprint"),
        )
        .expect("bind synthetic node fingerprint");

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
    .expect("build one-node modeled checkpoint");
    let snapshot =
        Snapshot::diskless(modeled_checkpoint).expect("build raw one-node QEMU snapshot");
    let snapshot_identity = snapshot.id();

    let overlay = run_state_root.join("raw-overlay.qcow2");
    let device_state = run_state_root.join("device-state.bin");
    let ram = run_state_root.join("exact-ram.bin");
    fs::write(&overlay, b"overlay fixture").expect("write overlay fixture");
    fs::write(&device_state, b"device-state fixture").expect("write device-state fixture");
    fs::write(&ram, b"exact RAM fixture").expect("write exact RAM fixture");
    let overlay_artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
        &File::open(&overlay).expect("open overlay fixture"),
        &overlay,
        &run_state_root.join("raw-overlay-chunks"),
        "root overlay fixture",
        0,
        source.plan().fault_signals().resource_limits(),
        &mut || Ok(()),
    )
    .expect("stage sparse overlay fixture");
    let device_artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(device_state.clone()),
        identity: hash_file(&device_state).expect("hash device-state fixture"),
        length: fs::metadata(&device_state)
            .expect("inspect device-state fixture")
            .len(),
        chunks: Vec::new(),
        sparse: false,
        extents: Vec::new(),
    };
    let ram_artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(ram.clone()),
        identity: hash_file(&ram).expect("hash exact RAM fixture"),
        length: fs::metadata(&ram).expect("inspect exact RAM fixture").len(),
        chunks: Vec::new(),
        sparse: false,
        extents: Vec::new(),
    };
    let qmp_identity = exact_ram_checkpoint_qmp_identity(ExactRamCheckpointQmpIdentityBasis {
        configuration: &configuration,
        immutable_backing: ContentHash::from_bytes(b"immutable backing"),
        node: &node,
        counter: 0,
        scheduler_time: VirtualTime { ticks: 0 },
        checkpoint: snapshot.checkpoint(),
        fault_identity: fault_checkpoint.id(),
        scheduler: &scheduler_checkpoint,
    })
    .expect("derive exact RAM QMP identity");
    let exact_ram = ProductionExactRamCheckpoint::new(
        None,
        hash_exact_checkpoint_file_sha256_with_boundary(&device_state, &mut || Ok(()))
            .expect("hash device-state fixture with SHA-256"),
        device_artifact,
        vec![ProductionExactRamLayer {
            kind: ProductionExactRamKind::Direct,
            identity: qmp_identity.into(),
            parent: None,
            topology: ContentHash::from_bytes(b"fixture topology"),
            ram_regions: 1,
            ram_records: 1,
            content_sha256: hash_exact_checkpoint_file_sha256_with_boundary(&ram, &mut || Ok(()))
                .expect("hash exact RAM fixture with SHA-256"),
            artifact: ram_artifact,
        }],
    )
    .expect("build exact RAM fixture");
    let manifest_identity = exact_ram_checkpoint_target_manifest_identity(
        ExactCheckpointTargetManifestBasis {
            configuration: configuration.id(),
            immutable_backing: ContentHash::from_bytes(b"immutable backing"),
            node: &node,
            counter: 0,
            scheduler_time: VirtualTime { ticks: 0 },
            snapshot: exact_checkpoint_snapshot_object_identity(
                &snapshot,
                source.plan().fault_signals().resource_limits(),
            )
            .expect("derive stored snapshot identity"),
            fault_identity: exact_checkpoint_fault_object_identity(
                &fault_checkpoint,
                source.plan().fault_signals().resource_limits(),
            )
            .expect("derive stored fault continuation identity"),
            overlay: overlay_artifact.identity,
            device_state: exact_ram.device_artifact.identity,
        },
        &exact_ram,
    );
    let checkpoint = ProductionVmExactCheckpointSet {
        identity: ContentHash::default(),
        configuration,
        scheduler: Arc::new(scheduler_checkpoint),
        event_log_objects: Arc::new(BTreeMap::new()),
        signal_artifact_objects: Arc::new(BTreeMap::new()),
        trigger_state: EventGraphState::default(),
        assertion_state: HostAssertionEvaluator::new(source.properties()).checkpoint(),
        terminal_verdict: None,
        terminal_cause: None,
        initial_lifecycle_observations_pending: true,
        branch: None,
        recorded_controls: Vec::new(),
        selectable_catalog_plans: selectable_plan
            .map(|plan| BTreeMap::from([(node.clone(), plan)]))
            .unwrap_or_default(),
        fault_checkpoint: Some(fault_checkpoint),
        targets: BTreeMap::from([(
            node.clone(),
            ProductionVmExactCheckpointTarget {
                configuration: Arc::new(Configuration {
                    def: scenario,
                    schedule: Schedule::empty(),
                }),
                immutable_backing: ContentHash::from_bytes(b"immutable backing"),
                counter: 0,
                scheduler_time: VirtualTime { ticks: 0 },
                snapshot,
                materialization: ProductionVmExactCheckpointMaterialization::Native {
                    overlay_artifact,
                    exact_ram: Box::new(exact_ram),
                    manifest_identity,
                },
            },
        )]),
        failed_host_io: BTreeMap::new(),
        node_generations: BTreeMap::from([(node.clone(), 1)]),
        node_service_states: BTreeMap::from([(node.clone(), ProductionNodeServiceState::Running)]),
        repository_restore: None,
    };
    (source, checkpoint, node, snapshot_identity)
}

fn publish_one_node_raw_checkpoint(
    run_state_root: &Path,
) -> (ScenarioDefForm, ContentHash, NodeId, ContentHash) {
    let (source, mut checkpoint, node, snapshot_identity) =
        build_one_node_raw_checkpoint(run_state_root, None);
    let prepared = prepare_exact_checkpoint_set(
        run_state_root,
        source.scenario_def().id(),
        source.plan().fault_signals().resource_limits(),
        &mut checkpoint,
    )
    .expect("prepare one-node production checkpoint");
    let identity = prepared.identity();
    prepared
        .publish()
        .expect("publish one-node production checkpoint");
    (source, identity, node, snapshot_identity)
}

#[cfg(feature = "test-support")]
#[test]
fn baked_snapshot_catalog_exposes_only_authenticated_modeled_snapshots() {
    let root = tempfile::tempdir().expect("create baked snapshot catalog store");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(root.path())
        .expect("build authenticated baked snapshot fixture");
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let closure = Arc::new(fixture.closure().clone());

    let catalog = closure
        .baked_snapshot_catalog_with_boundary(&mut || Ok(()))
        .expect("authenticate baked snapshot catalog");
    assert_eq!(catalog.nodes().collect::<Vec<_>>(), vec![&node]);
    assert_eq!(catalog.len(), 1);
    assert!(!catalog.is_empty());
    assert_eq!(
        catalog
            .open_snapshot(&node, &mut || Ok(()))
            .expect("open authenticated modeled snapshot")
            .checkpoint()
            .configuration,
        fixture.configuration().id()
    );
    assert!(
        catalog
            .open_snapshot(
                &NodeId {
                    name: String::from("foreign"),
                },
                &mut || Ok(())
            )
            .is_err()
    );
}

#[cfg(feature = "test-support")]
#[test]
fn materialized_baked_snapshots_survive_native_catalog_retirement() {
    let root = tempfile::tempdir().expect("create baked snapshot retirement store");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(root.path())
        .expect("build authenticated baked snapshot fixture");
    let closure = Arc::new(fixture.closure().clone());
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let snapshots = closure
        .baked_snapshot_catalog_with_boundary(&mut || Ok(()))
        .expect("authenticate baked snapshot catalog")
        .materialize_with_boundary(&mut || Ok(()))
        .expect("materialize authenticated baked snapshots");

    retire_production_exact_checkpoint_catalog(&closure.native_retirement())
        .expect("retire the native baked catalog");
    assert_eq!(snapshots.nodes().collect::<Vec<_>>(), vec![&node]);
    assert_eq!(
        snapshots
            .snapshot(&node)
            .expect("retained baked snapshot")
            .checkpoint()
            .configuration,
        fixture.configuration().id()
    );
    assert!(
        closure
            .baked_snapshot_catalog_with_boundary(&mut || Ok(()))
            .is_err()
    );
}

#[test]
fn cold_genesis_catalog_checkpoint_round_trips_only_at_initial_boundary() {
    std::thread::Builder::new()
        .name(String::from("cold-genesis-selectable-checkpoint"))
        .stack_size(32 * 1024 * 1024)
        .spawn(run_cold_genesis_catalog_checkpoint_test)
        .expect("spawn cold-genesis selectable checkpoint test")
        .join()
        .expect("cold-genesis selectable checkpoint test should not panic");
}

fn run_cold_genesis_catalog_checkpoint_test() {
    use crucible_protocol::selectable_catalog_plan::{
        SelectablePlanContinuation, SelectablePlanPhase,
    };

    let store = tempfile::tempdir().expect("create cold-genesis checkpoint store");
    let (source, mut checkpoint, node, _) =
        build_one_node_raw_checkpoint(store.path(), Some(SelectablePlanContinuation::cold()));
    let expected_plan = checkpoint
        .selectable_catalog_plans
        .get(&node)
        .expect("cold selectable plan should exist")
        .clone();
    let prepared = prepare_exact_checkpoint_set(
        store.path(),
        source.scenario_def().id(),
        source.plan().fault_signals().resource_limits(),
        &mut checkpoint,
    )
    .expect("prepare cold-genesis selectable checkpoint");
    let identity = prepared.identity();
    prepared
        .publish()
        .expect("publish cold-genesis selectable checkpoint");

    let restored =
        load_exact_checkpoint_set(store.path(), &source.scenario_def(), &source, identity)
            .expect("load cold-genesis selectable checkpoint");
    assert_eq!(
        restored.selectable_catalog_plans.get(&node),
        Some(&expected_plan)
    );
    open_exact_checkpoint_closure(store.path(), &source, identity)
        .expect("open cold-genesis selectable checkpoint closure")
        .validate_complete()
        .expect("authenticate complete cold-genesis selectable checkpoint closure");

    let partial_store = tempfile::tempdir().expect("create partial-registration checkpoint store");
    let partial = SelectablePlanContinuation::new(
        SelectablePlanPhase::Registering,
        BTreeSet::from([String::from("checkpoint.recovery")]),
        Some(1),
        BTreeMap::new(),
        None,
        None,
    )
    .expect("build partial selectable continuation");
    let (partial_source, mut partial_checkpoint, _, _) =
        build_one_node_raw_checkpoint(partial_store.path(), Some(partial));
    let error = prepare_exact_checkpoint_set(
        partial_store.path(),
        partial_source.scenario_def().id(),
        partial_source.plan().fault_signals().resource_limits(),
        &mut partial_checkpoint,
    )
    .err()
    .expect("partial selectable registration must fail checkpoint preparation");
    let PersistExactCheckpointError::Unpublished(source) = error else {
        panic!("partial catalog rejection must precede publication");
    };
    assert!(source.to_string().contains(
        "selectable catalogs are neither frozen nor pristine pre-execution cold-genesis continuations"
    ));

    let progressed_store = tempfile::tempdir().expect("create progressed checkpoint store");
    let (progressed_source, mut progressed_checkpoint, _, _) = build_one_node_raw_checkpoint(
        progressed_store.path(),
        Some(SelectablePlanContinuation::cold()),
    );
    progressed_checkpoint.initial_lifecycle_observations_pending = false;
    let error = prepare_exact_checkpoint_set(
        progressed_store.path(),
        progressed_source.scenario_def().id(),
        progressed_source.plan().fault_signals().resource_limits(),
        &mut progressed_checkpoint,
    )
    .err()
    .expect("progressed cold catalog must fail checkpoint preparation");
    assert!(matches!(error, PersistExactCheckpointError::Unpublished(_)));
}

fn regular_file_count(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                regular_file_count(&entry.path())
            } else {
                usize::from(entry.file_type().is_ok_and(|kind| kind.is_file()))
            }
        })
        .sum()
}

#[test]
fn native_checkpoint_retirement_is_crash_safe_and_idempotent() {
    let root = tempfile::tempdir().expect("create native retirement store");
    let (source, identity, _, _) = publish_one_node_raw_checkpoint(root.path());
    let scenario = source.scenario_def().id();
    let closure = open_exact_checkpoint_closure(root.path(), &source, identity)
        .expect("open native closure before retirement");
    let retirement = closure.native_retirement();
    let scenario_directory = root.path().join(scenario.to_hex());

    let first = retire_production_exact_checkpoint_catalog(&retirement)
        .expect("retire native checkpoint catalog");
    assert_eq!(first.scenario(), scenario);
    assert!(first.retired());
    assert!(!scenario_directory.exists());

    let second =
        retire_production_exact_checkpoint_catalog(&retirement).expect("repeat native retirement");
    assert_eq!(second.scenario(), scenario);
    assert!(!second.retired());
}

#[test]
fn native_checkpoint_retirement_recovers_renamed_generation() {
    let root = tempfile::tempdir().expect("create interrupted native retirement store");
    let (source, identity, _, _) = publish_one_node_raw_checkpoint(root.path());
    let scenario = source.scenario_def().id();
    let closure = open_exact_checkpoint_closure(root.path(), &source, identity)
        .expect("open native closure before interrupted retirement");
    let retirement = closure.native_retirement();
    let scenario_name = scenario.to_hex();
    let active = root.path().join(&scenario_name);
    let retired = root
        .path()
        .join(format!(".retired-checkpoint-catalog-{scenario_name}"));
    fs::rename(&active, &retired).expect("simulate durable catalog rename");
    File::open(root.path())
        .and_then(|directory| directory.sync_all())
        .expect("sync simulated rename");

    let report = retire_production_exact_checkpoint_catalog(&retirement)
        .expect("finish interrupted retirement");
    assert!(!report.retired());
    assert!(!active.exists());
    assert!(!retired.exists());
}

#[test]
fn closure_manifest_round_trip_is_canonical() {
    let mut original = manifest();
    original.targets = vec![target("a"), target("b")];
    original.node_generations = vec![(wire_string("a"), 1), (wire_string("b"), 2)];
    original.node_service_states = vec![(wire_string("a"), 1), (wire_string("b"), 2)];

    let bytes = encode_manifest(&original).expect("encode canonical closure manifest");
    let decoded = decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default())
        .expect("decode canonical closure manifest");

    assert_eq!(
        encode_manifest(&decoded).expect("re-encode canonical closure manifest"),
        bytes
    );
}

#[test]
fn failed_node_fingerprint_fields_bind_the_v9_closure_identity() {
    let mut original = manifest();
    original.failed_host_io.push(failed_host_io("vm-a"));
    let identity = closure_identity(&original).expect("derive failed-node closure identity");

    let mut changed_time = original.clone();
    changed_time.failed_host_io[0].fingerprint_at += 1;
    assert_ne!(
        closure_identity(&changed_time).expect("derive changed-time closure identity"),
        identity
    );

    let mut changed_fingerprint = original;
    changed_fingerprint.failed_host_io[0].fingerprint =
        ContentHash::from_bytes(b"changed terminal fingerprint");
    assert_ne!(
        closure_identity(&changed_fingerprint)
            .expect("derive changed-fingerprint closure identity"),
        identity
    );
}

#[test]
fn manifest_rejects_duplicate_failed_node_owners() {
    let failed = failed_host_io("vm-a");
    let mut duplicate = manifest();
    duplicate.failed_host_io = vec![failed.clone(), failed];
    let bytes = encode_manifest(&duplicate).expect("encode duplicate failed-node manifest");

    assert!(decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default()).is_err());
}

#[test]
fn checkpoint_set_rejects_missing_failed_node_authority() {
    let root = tempfile::tempdir().expect("create failed-node checkpoint fixture root");
    let (source, mut checkpoint, node, _) = build_one_node_raw_checkpoint(root.path(), None);
    checkpoint
        .node_service_states
        .insert(node, ProductionNodeServiceState::PermanentlyFailed);

    let error = validate_checkpoint_set(source.scenario_def().id(), &checkpoint)
        .expect_err("failed node without retained authority must fail closed");
    assert!(error.to_string().contains("owner partition is incomplete"));
}

#[test]
fn checkpoint_set_rejects_wrong_failed_node_fingerprint_owner() {
    let root = tempfile::tempdir().expect("create failed-node checkpoint fixture root");
    let (source, mut checkpoint, node, _) = build_one_node_raw_checkpoint(root.path(), None);
    checkpoint.targets.remove(&node);
    checkpoint
        .node_service_states
        .insert(node.clone(), ProductionNodeServiceState::PermanentlyFailed);
    checkpoint.failed_host_io.insert(
        node,
        ProductionFailedNodeState {
            host_io: QemuHostIoCheckpoint::without_devices(ContentHash::from_bytes(
                b"wrong-owner failed-node host binding",
            )),
            fingerprint: FingerprintSample {
                node: NodeId {
                    name: String::from("foreign-node"),
                },
                at: VirtualTime { ticks: 73 },
                fingerprint: ExecutionFingerprint {
                    hash: ContentHash::from_bytes(b"wrong-owner failed-node fingerprint"),
                },
            },
        },
    );

    let error = validate_checkpoint_set(source.scenario_def().id(), &checkpoint)
        .expect_err("a retained fingerprint must name its failed-node owner");
    assert!(
        error
            .to_string()
            .contains("fingerprint owner is inconsistent")
    );
}

#[test]
fn failed_node_authority_round_trips_through_the_v9_closure() {
    let root = tempfile::tempdir().expect("create failed-node checkpoint store");
    let (source, mut checkpoint, node, _) = build_one_node_raw_checkpoint(root.path(), None);
    checkpoint.targets.remove(&node);
    checkpoint
        .node_service_states
        .insert(node.clone(), ProductionNodeServiceState::PermanentlyFailed);
    let expected = ProductionFailedNodeState::new(
        &node,
        QemuHostIoCheckpoint::without_devices(ContentHash::from_bytes(
            b"durable failed-node host binding",
        )),
        FingerprintSample {
            node: node.clone(),
            at: VirtualTime { ticks: 73 },
            fingerprint: ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"durable failed-node fingerprint"),
            },
        },
    )
    .expect("construct failed-node authority");
    checkpoint
        .failed_host_io
        .insert(node.clone(), expected.clone());
    let fault_runtime = ProductionFaultRuntime::new(
        source.plan().fault_signals().clone(),
        None,
        SignalBoundarySnapshot::default(),
        source.scenario_def().id(),
        super::super::fault_implementation::test_host_manifests(),
        &QemuNodeSet::new(),
    )
    .expect("build failed-node fault runtime");
    checkpoint.fault_checkpoint = Some(
        fault_runtime
            .checkpoint(&mut QemuNodeSet::new())
            .expect("checkpoint failed-node fault runtime"),
    );

    let prepared = prepare_exact_checkpoint_set(
        root.path(),
        source.scenario_def().id(),
        source.plan().fault_signals().resource_limits(),
        &mut checkpoint,
    )
    .expect("prepare failed-node checkpoint");
    let identity = prepared.identity();
    prepared.publish().expect("publish failed-node checkpoint");
    let restored =
        load_exact_checkpoint_set(root.path(), &source.scenario_def(), &source, identity)
            .expect("load failed-node checkpoint");

    assert_eq!(restored.failed_host_io.get(&node), Some(&expected));
    assert!(restored.targets.is_empty());
}

#[test]
fn target_manifest_identity_authenticates_immutable_backing() {
    let node = NodeId {
        name: String::from("vm-a"),
    };
    let basis = |immutable_backing| ExactCheckpointTargetManifestBasis {
        configuration: ContentHash::from_bytes(b"configuration"),
        immutable_backing,
        node: &node,
        counter: 17,
        scheduler_time: VirtualTime { ticks: 23 },
        snapshot: ContentHash::from_bytes(b"snapshot"),
        fault_identity: ContentHash::from_bytes(b"fault"),
        overlay: ContentHash::from_bytes(b"overlay"),
        device_state: ContentHash::from_bytes(b"device state"),
    };

    let first =
        exact_checkpoint_target_manifest_identity(basis(ContentHash::from_bytes(b"first backing")));
    let second = exact_checkpoint_target_manifest_identity(basis(ContentHash::from_bytes(
        b"second backing",
    )));

    assert_ne!(first, second);
}

#[test]
fn closure_manifest_allows_content_deduplication_between_distinct_nodes() {
    let mut shared = manifest();
    let first = target("a");
    let mut second = target("b");
    second.snapshot = first.snapshot;
    shared.targets = vec![first, second];
    shared.identity = closure_identity(&shared).expect("derive shared-content identity");
    let bytes = encode_manifest(&shared).expect("encode shared-content manifest");
    let decoded = decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default())
        .expect("distinct nodes may share immutable snapshot content");
    assert!(decoded == shared);
    assert_eq!(
        encode_manifest(&decoded).expect("re-encode manifest"),
        bytes
    );

    shared.targets[1].node = wire_string("a");
    let bytes = encode_manifest(&shared).expect("encode duplicate-node manifest");
    assert!(decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default()).is_err());
}

#[test]
fn shared_snapshot_content_does_not_authorize_a_foreign_node_target() {
    std::thread::Builder::new()
        .name(String::from("checkpoint-target-ownership"))
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let store = tempfile::tempdir().expect("create checkpoint store");
            let (source, identity, node, _) = publish_one_node_raw_checkpoint(store.path());
            let restored =
                load_exact_checkpoint_set(store.path(), &source.scenario_def(), &source, identity)
                    .expect("load authentic checkpoint");
            let target = restored.targets.get(&node).expect("find target");
            let fault_checkpoint = restored
                .fault_checkpoint
                .as_ref()
                .expect("find fault state");
            let limits = source.plan().fault_signals().resource_limits();
            let fault = exact_checkpoint_fault_object_identity(fault_checkpoint, limits)
                .expect("derive stored fault continuation identity");
            let snapshot = exact_checkpoint_snapshot_object_identity(&target.snapshot, limits)
                .expect("derive stored snapshot identity");
            validate_exact_checkpoint_target(&node, target, fault, snapshot)
                .expect("original node owns the snapshot and artifacts");
            let foreign = NodeId {
                name: String::from("foreign-node"),
            };
            let error = validate_exact_checkpoint_target(&foreign, target, fault, snapshot)
                .expect_err("identical content does not transfer node ownership");
            assert!(error.to_string().contains("failed manifest authentication"));
        })
        .expect("spawn large-stack ownership test")
        .join()
        .expect("ownership test should not panic");
}

#[test]
fn closure_manifest_rejects_unsorted_or_trailing_records() {
    let mut unsorted = manifest();
    unsorted.targets = vec![target("b"), target("a")];
    let bytes = encode_manifest(&unsorted).expect("encode fixture");
    assert!(decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default()).is_err());

    let mut trailing = encode_manifest(&manifest()).expect("encode fixture");
    trailing.push(0);
    assert!(
        decode::decode_manifest_with_limits(&trailing, FaultResourceLimits::default()).is_err()
    );
}

#[test]
fn current_manifest_requires_sparse_overlay_and_dense_device_state() {
    let mut dense_overlay = manifest();
    let mut dense_target = target("a");
    dense_target.overlay = dense_target.exact_ram.device.clone();
    dense_overlay.targets.push(dense_target);
    let bytes = encode_manifest(&dense_overlay).expect("encode dense-overlay fixture");
    assert!(decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default()).is_err());

    let mut sparse_device_state = manifest();
    let mut sparse_target = target("a");
    sparse_target.exact_ram.device = sparse_target.overlay.clone();
    sparse_device_state.targets.push(sparse_target);
    let bytes = encode_manifest(&sparse_device_state).expect("encode sparse-VMState fixture");
    assert!(decode::decode_manifest_with_limits(&bytes, FaultResourceLimits::default()).is_err());
}

#[test]
fn closure_identity_excludes_only_its_identity_field() {
    let mut original = manifest();
    let identity = closure_identity(&original).expect("derive closure identity");
    original.identity = ContentHash::from_bytes(b"ignored identity field");
    assert_eq!(
        closure_identity(&original).expect("derive closure identity again"),
        identity
    );
    original.frontier = 1;
    assert_ne!(
        closure_identity(&original).expect("derive changed closure identity"),
        identity
    );
}

#[test]
fn portable_closure_inventory_streams_only_authenticated_manifest_objects() {
    let root = tempfile::tempdir().expect("create portable closure root");
    let source = crucible::happy_path_scenario()
        .expect("build portable closure scenario")
        .scenario;
    let scenario = source.scenario_def().id();
    let bytes = b"deduplicated portable checkpoint object";
    let object_identity = ContentHash::from_bytes(bytes);
    let mut manifest = manifest();
    manifest.scenario = scenario;
    manifest.configuration = ContentHash::from_bytes(b"portable configuration");
    manifest.schedule = object_identity;
    manifest.scheduler = object_identity;
    manifest.trigger_state = object_identity;
    manifest.assertion_state = object_identity;
    manifest.lifecycle_state = object_identity;
    manifest.fault_checkpoint = object_identity;
    manifest.identity = closure_identity(&manifest).expect("derive portable closure identity");

    let object_directory = object_parent(root.path(), scenario);
    fs::create_dir_all(&object_directory).expect("create portable object directory");
    persist_object(&object_directory, object_identity, bytes).expect("persist portable object");
    let publication = closure_parent(root.path(), scenario).join(manifest.identity.to_hex());
    fs::create_dir_all(&publication).expect("create portable publication directory");
    fs::write(
        publication.join(MANIFEST_FILE),
        encode_manifest(&manifest).expect("encode portable manifest"),
    )
    .expect("write portable manifest");

    let closure = open_exact_checkpoint_closure(root.path(), &source, manifest.identity)
        .expect("open portable checkpoint closure");
    assert_eq!(closure.identity(), manifest.identity);
    assert_eq!(closure.scenario(), scenario);
    assert_eq!(closure.configuration(), manifest.configuration);
    assert_eq!(closure.objects().len(), 1);
    assert_eq!(closure.objects()[0].identity(), object_identity);
    assert_eq!(
        closure.objects()[0].length(),
        u64::try_from(bytes.len()).expect("fixture length fits")
    );

    fs::write(object_path(&object_directory, object_identity), b"changed")
        .expect("replace portable object fixture");
    assert!(closure.open_object(object_identity).is_err());
}

#[test]
fn portable_object_read_observes_cancellation_between_bounded_chunks() {
    let root = tempfile::tempdir().expect("create cancellable portable closure root");
    let source = crucible::happy_path_scenario()
        .expect("build cancellable portable closure scenario")
        .scenario;
    let scenario = source.scenario_def().id();
    let bytes = vec![0x5a; io::MAX_BOUNDED_READ_CHUNK_BYTES * 2 + 1];
    let object_identity = ContentHash::from_bytes(&bytes);
    let mut manifest = manifest();
    manifest.scenario = scenario;
    manifest.configuration = ContentHash::from_bytes(b"cancellable portable configuration");
    manifest.schedule = object_identity;
    manifest.scheduler = object_identity;
    manifest.trigger_state = object_identity;
    manifest.assertion_state = object_identity;
    manifest.lifecycle_state = object_identity;
    manifest.fault_checkpoint = object_identity;
    manifest.identity = closure_identity(&manifest).expect("derive cancellable closure identity");

    let object_directory = object_parent(root.path(), scenario);
    fs::create_dir_all(&object_directory).expect("create cancellable object directory");
    persist_object(&object_directory, object_identity, &bytes)
        .expect("persist multi-chunk portable object");
    let publication = closure_parent(root.path(), scenario).join(manifest.identity.to_hex());
    fs::create_dir_all(&publication).expect("create cancellable publication directory");
    fs::write(
        publication.join(MANIFEST_FILE),
        encode_manifest(&manifest).expect("encode cancellable manifest"),
    )
    .expect("write cancellable manifest");

    let closure = open_exact_checkpoint_closure(root.path(), &source, manifest.identity)
        .expect("open cancellable portable closure");
    let mut boundary_count = 0_u8;
    let error = replay::read_portable_object(
        &closure,
        object_identity,
        u64::try_from(bytes.len()).expect("fixture length fits"),
        "cancellation fixture",
        &mut || {
            boundary_count += 1;
            if boundary_count == 5 {
                return Err(LifecycleApiError::LoopFactory {
                    message: String::from("canceled during second snapshot chunk"),
                });
            }
            Ok(())
        },
    )
    .expect_err("mid-stream cancellation must stop the portable object read");

    assert_eq!(boundary_count, 5);
    assert!(
        error
            .to_string()
            .contains("canceled during second snapshot chunk")
    );
}

#[test]
fn content_store_deduplicates_equal_objects() {
    let directory = tempfile::tempdir().expect("create object directory");
    let bytes = b"same object";
    let identity = ContentHash::from_bytes(bytes);

    persist_object(directory.path(), identity, bytes).expect("persist first object");
    persist_object(directory.path(), identity, bytes).expect("reuse equal object");
    let dag_store = LocalDagStore::new(directory.path());
    assert_eq!(
        dag_store
            .get(&identity)
            .expect("read exact object as DAG object"),
        bytes
    );
    assert!(!directory.path().join(identity.to_hex()).exists());
}

#[test]
fn concurrent_equal_object_publishers_converge_atomically() {
    let directory = std::sync::Arc::new(tempfile::tempdir().expect("create object directory"));
    let bytes = b"concurrent object".to_vec();
    let identity = ContentHash::from_bytes(&bytes);
    let publishers = (0..8)
        .map(|_| {
            let directory = std::sync::Arc::clone(&directory);
            let bytes = bytes.clone();
            std::thread::spawn(move || persist_object(directory.path(), identity, &bytes))
        })
        .collect::<Vec<_>>();

    for publisher in publishers {
        publisher
            .join()
            .expect("publisher thread should not panic")
            .expect("equal publisher should converge");
    }
    validate_file_hash(&object_path(directory.path(), identity), identity)
        .expect("published object should authenticate");
}

#[cfg(target_os = "linux")]
#[test]
fn file_artifact_stream_authenticates_sparse_file_contents() {
    let root = tempfile::tempdir().expect("create sparse materialization fixture");
    let source = root.path().join("source");
    let length = 16 * 1024 * 1024_u64;
    let mut source_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .expect("create sparse source");
    source_file.write_all(b"head").expect("write sparse head");
    source_file
        .seek(SeekFrom::Start(length - 4))
        .expect("seek sparse tail");
    source_file.write_all(b"tail").expect("write sparse tail");
    source_file.sync_all().expect("flush sparse source");
    drop(source_file);

    let identity = hash_file(&source).expect("hash sparse source");
    let artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(source.clone()),
        identity,
        length,
        chunks: Vec::new(),
        sparse: false,
        extents: Vec::new(),
    };
    let streamed = stream_artifact(&artifact, "sparse test").expect("stream sparse source");
    assert_eq!(streamed.len(), length as usize);
    assert_eq!(&streamed[..4], b"head");
    assert!(
        streamed[4..streamed.len() - 4]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(&streamed[streamed.len() - 4..], b"tail");
    assert_eq!(ContentHash::from_bytes(&streamed), identity);

    let mut changed = OpenOptions::new()
        .write(true)
        .open(source)
        .expect("reopen sparse source");
    changed.write_all(b"fail").expect("change sparse source");
    changed.sync_all().expect("flush changed sparse source");
    assert!(stream_artifact(&artifact, "changed sparse test").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn chunked_artifact_stream_recreates_sparse_zero_extents() {
    let root = tempfile::tempdir().expect("create sparse chunk fixture");
    let source = root.path().join("source");
    let object_directory = root.path().join("objects");
    fs::create_dir(&object_directory).expect("create object directory");
    let length = 16 * 1024 * 1024_u64;
    let mut source_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .expect("create sparse source");
    source_file.write_all(b"head").expect("write sparse head");
    source_file
        .seek(SeekFrom::Start(length - 4))
        .expect("seek sparse tail");
    source_file.write_all(b"tail").expect("write sparse tail");
    source_file.sync_all().expect("flush sparse source");
    drop(source_file);

    let identity = hash_file(&source).expect("hash sparse source");
    let source_artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(source),
        identity,
        length,
        chunks: Vec::new(),
        sparse: false,
        extents: Vec::new(),
    };
    let manifest = artifact_manifest(&source_artifact).expect("derive sparse chunk manifest");
    persist_chunked_artifact(&object_directory, &manifest, &source_artifact)
        .expect("persist sparse chunks");
    let chunked = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::ChunkStore(object_directory),
        identity,
        length,
        chunks: manifest.chunks,
        sparse: manifest.sparse,
        extents: manifest.extents,
    };
    let streamed = stream_artifact(&chunked, "sparse chunk test").expect("stream sparse chunks");
    assert_eq!(streamed.len(), length as usize);
    assert_eq!(&streamed[..4], b"head");
    assert!(
        streamed[4..streamed.len() - 4]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(&streamed[streamed.len() - 4..], b"tail");
    assert_eq!(ContentHash::from_bytes(&streamed), identity);
}

#[test]
fn chunk_store_deduplicates_and_streams_complete_artifacts() {
    let root = tempfile::tempdir().expect("create chunk-store fixture");
    let source = root.path().join("source");
    let object_directory = root.path().join("objects");
    fs::create_dir(&object_directory).expect("create object directory");
    let mut bytes = vec![0x5a; ARTIFACT_CHUNK_BYTES];
    bytes.extend_from_slice(b"tail");
    fs::write(&source, &bytes).expect("write source artifact");
    let artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(source),
        identity: ContentHash::from_bytes(&bytes),
        length: u64::try_from(bytes.len()).expect("fixture length fits"),
        chunks: Vec::new(),
        sparse: false,
        extents: Vec::new(),
    };
    let manifest = artifact_manifest(&artifact).expect("derive chunk manifest");

    persist_chunked_artifact(&object_directory, &manifest, &artifact)
        .expect("persist first artifact");
    persist_chunked_artifact(&object_directory, &manifest, &artifact)
        .expect("deduplicate second artifact");
    let stored_count = fs::read_dir(&object_directory)
        .expect("read object directory")
        .map(|entry| {
            fs::read_dir(entry.expect("read object prefix entry").path())
                .expect("read object prefix directory")
                .count()
        })
        .sum::<usize>();
    assert_eq!(stored_count, 2);

    let chunked = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.clone()),
        identity: manifest.identity,
        length: manifest.length,
        chunks: manifest.chunks.clone(),
        sparse: manifest.sparse,
        extents: manifest.extents.clone(),
    };
    let mut streamed = Vec::new();
    stream_checkpoint_artifact_with_boundary(&chunked, &mut streamed, "test", &mut || Ok(()))
        .expect("stream authenticated chunked artifact");
    assert_eq!(streamed, bytes);

    let first_chunk = object_path(&object_directory, manifest.chunks[0]);
    fs::write(&first_chunk, vec![0; ARTIFACT_CHUNK_BYTES]).expect("corrupt first checkpoint chunk");
    let mut rejected_stream = Vec::new();
    assert!(
        stream_checkpoint_artifact_with_boundary(
            &chunked,
            &mut rejected_stream,
            "corrupt test",
            &mut || Ok(()),
        )
        .is_err()
    );
    fs::write(&first_chunk, &bytes[..ARTIFACT_CHUNK_BYTES])
        .expect("restore first checkpoint chunk");

    let last_chunk = object_path(
        &object_directory,
        *manifest.chunks.last().expect("fixture has a tail chunk"),
    );
    fs::remove_file(last_chunk).expect("remove tail checkpoint chunk");
    assert!(stream_artifact(&chunked, "missing tail test").is_err());
}

#[test]
fn paused_artifact_staging_writes_only_deduplicated_chunks() {
    let root = tempfile::tempdir().expect("create direct chunk-staging fixture");
    let source = root.path().join("active-overlay.qcow2");
    let object_directory = root.path().join("staged-objects");
    let repeated = vec![0x6d; ARTIFACT_CHUNK_BYTES];
    let mut bytes = repeated.clone();
    bytes.extend_from_slice(&repeated);
    bytes.extend_from_slice(b"tail");
    fs::write(&source, &bytes).expect("write active overlay fixture");

    let artifact = stage_checkpoint_artifact_chunks_with_boundary(
        &source,
        &object_directory,
        "root overlay",
        0,
        FaultResourceLimits::compiled_maximum(),
        &mut || Ok(()),
    )
    .expect("stage paused overlay directly into chunks");

    assert_eq!(artifact.identity, ContentHash::from_bytes(&bytes));
    assert_eq!(artifact.length, bytes.len() as u64);
    assert_eq!(artifact.chunks.len(), 3);
    assert_eq!(artifact.chunks[0], artifact.chunks[1]);
    assert!(matches!(
        artifact.source,
        ProductionCheckpointArtifactSource::RetainedChunkStore(ref lease)
            if lease.directory == object_directory
    ));
    assert!(!object_directory.join("active-overlay.qcow2").exists());

    let stored_count = fs::read_dir(&object_directory)
        .expect("read staged object directory")
        .map(|entry| {
            fs::read_dir(entry.expect("read staged object prefix").path())
                .expect("read staged object prefix directory")
                .count()
        })
        .sum::<usize>();
    assert_eq!(stored_count, 2);

    assert_eq!(
        stream_artifact(&artifact, "direct chunk staging").expect("stream directly staged chunks"),
        bytes
    );
}

#[cfg(target_os = "linux")]
#[test]
fn captured_artifact_publication_reads_the_pinned_inode_after_path_replacement() {
    let root = tempfile::tempdir().expect("create pinned capture fixture");
    let source = root.path().join("captured-ram.bin");
    let displaced = root.path().join("displaced-ram.bin");
    let object_directory = root.path().join("staged-objects");
    let captured_bytes = b"bytes written through the admitted capture descriptor";
    let replacement_bytes = b"attacker-controlled pathname replacement";
    fs::write(&source, captured_bytes).expect("write captured inode");
    let mut captured_file = File::open(&source).expect("pin captured inode");

    fs::rename(&source, &displaced).expect("move captured pathname");
    fs::write(&source, replacement_bytes).expect("replace captured pathname");

    let observed_sha256 = hash_exact_checkpoint_open_file_sha256_with_boundary(
        &mut captured_file,
        &source,
        &mut || Ok(()),
    )
    .expect("hash pinned capture descriptor");
    let artifact = stage_open_checkpoint_artifact_chunks_with_boundary(
        &mut captured_file,
        &source,
        &object_directory,
        "exact RAM",
        0,
        FaultResourceLimits::compiled_maximum(),
        &mut || Ok(()),
    )
    .expect("publish pinned capture descriptor");

    let mut expected_sha256 = Sha256::new();
    expected_sha256.update(captured_bytes);
    let mut expected_sha256_bytes = [0_u8; 32];
    expected_sha256_bytes.copy_from_slice(&expected_sha256.finalize());
    assert_eq!(
        observed_sha256,
        ContentHash {
            bytes: expected_sha256_bytes,
        }
    );
    assert_eq!(artifact.identity, ContentHash::from_bytes(captured_bytes));
    assert_eq!(
        stream_artifact(&artifact, "pinned exact RAM").expect("stream pinned artifact"),
        captured_bytes
    );
    assert_eq!(
        fs::read(source).expect("read replacement pathname"),
        replacement_bytes
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sparse_overlay_staging_persists_only_changed_chunks_and_reconstructs_holes() {
    let root = tempfile::tempdir().expect("create sparse staging fixture");
    let source = root.path().join("active-overlay.qcow2");
    let object_directory = root.path().join("staged-objects");
    let length = 64 * 1024 * 1024_u64;
    let mut source_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .expect("create sparse overlay");
    source_file
        .write_all(b"changed-head")
        .expect("write changed head");
    source_file
        .seek(SeekFrom::Start(length - 12))
        .expect("seek changed tail");
    source_file
        .write_all(b"changed-tail")
        .expect("write changed tail");
    source_file.sync_all().expect("flush sparse overlay");
    drop(source_file);

    let artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
        &File::open(&source).expect("open sparse overlay"),
        &source,
        &object_directory,
        "root overlay",
        0,
        FaultResourceLimits::compiled_maximum(),
        &mut || Ok(()),
    )
    .expect("stage sparse overlay extents");
    assert!(artifact.sparse);
    assert!(artifact.chunks.is_empty());
    assert_eq!(artifact.extents.len(), 2);
    assert_eq!(artifact.extents[0].start_chunk, 0);
    assert_eq!(artifact.extents[1].start_chunk, 15);
    assert_eq!(
        artifact
            .extents
            .iter()
            .map(|extent| extent.chunks.len())
            .sum::<usize>(),
        2
    );
    assert_eq!(regular_file_count(&object_directory), 2);

    let mut streamed = Vec::new();
    stream_checkpoint_artifact_with_boundary(
        &artifact,
        &mut streamed,
        "sparse staged overlay",
        &mut || Ok(()),
    )
    .expect("stream sparse staged overlay");
    assert_eq!(
        streamed.len(),
        usize::try_from(length).expect("fixture length fits")
    );
    assert_eq!(&streamed[..12], b"changed-head");
    assert!(
        streamed[12..streamed.len() - 12]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(&streamed[streamed.len() - 12..], b"changed-tail");

    let first = artifact.extents[0].chunks[0];
    fs::write(
        object_path(&object_directory, first),
        vec![0x5a; ARTIFACT_CHUNK_BYTES],
    )
    .expect("corrupt sparse extent object");
    assert!(validate_chunked_artifact(&object_directory, &artifact).is_err());
    assert!(stream_artifact(&artifact, "corrupt sparse overlay").is_err());
    fs::remove_file(object_path(&object_directory, first)).expect("remove sparse extent object");
    assert!(validate_chunked_artifact(&object_directory, &artifact).is_err());
    assert!(stream_artifact(&artifact, "missing sparse overlay").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn all_zero_sparse_overlay_has_no_stored_chunks() {
    let root = tempfile::tempdir().expect("create all-zero sparse fixture");
    let source = root.path().join("zero-overlay.qcow2");
    let object_directory = root.path().join("staged-objects");
    let length = 8 * 1024 * 1024_u64;
    let source_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .expect("create all-zero sparse overlay");
    source_file
        .set_len(length)
        .expect("size all-zero sparse overlay");
    source_file
        .sync_all()
        .expect("flush all-zero sparse overlay");
    drop(source_file);

    let artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
        &File::open(&source).expect("open all-zero overlay"),
        &source,
        &object_directory,
        "all-zero root overlay",
        0,
        FaultResourceLimits::compiled_maximum(),
        &mut || Ok(()),
    )
    .expect("stage all-zero sparse overlay");
    assert!(artifact.sparse);
    assert!(artifact.extents.is_empty());
    assert_eq!(regular_file_count(&object_directory), 0);
    validate_chunked_artifact(&object_directory, &artifact)
        .expect("authenticate all-zero sparse overlay");

    let mut streamed = Vec::new();
    stream_checkpoint_artifact_with_boundary(
        &artifact,
        &mut streamed,
        "all-zero sparse overlay",
        &mut || Ok(()),
    )
    .expect("stream all-zero sparse overlay");
    assert_eq!(
        streamed.len(),
        usize::try_from(length).expect("fixture length fits")
    );
    assert!(streamed.iter().all(|byte| *byte == 0));
}

#[test]
fn sparse_manifest_rejects_noncanonical_extent_geometry() {
    let chunk = ContentHash::from_bytes(b"chunk");
    let mut invalid = target("a").overlay;
    invalid.length = 3 * ARTIFACT_CHUNK_BYTES_U64;
    invalid.extents = vec![
        ArtifactExtent {
            start_chunk: 0,
            chunks: vec![chunk],
        },
        ArtifactExtent {
            start_chunk: 1,
            chunks: vec![chunk],
        },
    ];
    assert!(validate_sparse_artifact_shape(&invalid).is_err());

    invalid.extents[1].start_chunk = 0;
    assert!(validate_sparse_artifact_shape(&invalid).is_err());

    invalid.extents = vec![ArtifactExtent {
        start_chunk: 3,
        chunks: vec![chunk],
    }];
    assert!(validate_sparse_artifact_shape(&invalid).is_err());

    invalid.extents = vec![ArtifactExtent {
        start_chunk: 0,
        chunks: Vec::new(),
    }];
    assert!(validate_sparse_artifact_shape(&invalid).is_err());
}

#[test]
fn paused_artifact_staging_rejects_length_before_writing_chunks() {
    let root = tempfile::tempdir().expect("create chunk-staging limit fixture");
    let source = root.path().join("active-vmstate.qcow2");
    let object_directory = root.path().join("staged-objects");
    fs::write(&source, b"over-limit").expect("write over-limit artifact fixture");

    let error = stage_checkpoint_artifact_chunks_with_boundary(
        &source,
        &object_directory,
        "VMState",
        0,
        FaultResourceLimits {
            fat_checkpoint_bytes: 4,
            ..FaultResourceLimits::default()
        },
        &mut || Ok(()),
    )
    .expect_err("over-limit artifact must be rejected");

    assert!(matches!(
        error,
        SchedulerError::ResourceLimit {
            field: "fat_checkpoint_bytes",
            current: 0,
            requested: 10,
            configured: 4,
            ..
        }
    ));
    assert!(!object_directory.exists());
}

#[test]
fn lifecycle_wire_restores_terminal_branch_and_controls() {
    let scenario = crucible::happy_path_scenario()
        .expect("build lifecycle wire scenario")
        .scenario
        .scenario_def();
    let schedule = Schedule::empty().to_compact_binary();
    let selectable_plan = {
        use crucible_protocol::selectable_catalog_plan::{
            SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
            SelectablePlanLimits, SelectablePlanPendingRequest, SelectablePlanPhase,
            SelectablePlanPresence,
        };
        let declaration = SelectablePlanDeclaration::new(
            "network.policy",
            vec![1, 2],
            vec![1],
            vec!["network".to_owned()],
            SelectablePlanPresence::Required,
        )
        .expect("build selectable declaration");
        let pending = SelectablePlanPendingRequest::new(
            crucible_protocol::SelectionRequest::new(9, "network.policy", "epoch/1", None, 128)
                .expect("build pending request"),
            700,
            2,
            0x8000,
        );
        let continuation = SelectablePlanContinuation::new(
            SelectablePlanPhase::Frozen,
            BTreeSet::from(["network.policy".to_owned()]),
            Some(4),
            BTreeMap::new(),
            None,
            Some(pending),
        )
        .expect("build selectable continuation");
        SelectableCatalogPlan::new(
            SelectablePlanLimits::new(1, 8, 8).expect("build selectable limits"),
            vec![declaration],
            continuation,
        )
        .expect("build selectable plan")
    };
    let wire = LifecycleWire {
        terminal: Some(TerminalWire::Failed(vec![wire_string("failed")])),
        terminal_cause: Some(TerminalCauseWire::Failed(vec![wire_string("failed")])),
        initial_lifecycle_observations_pending: false,
        branch: Some(BranchWire {
            base_schedule: schedule.clone(),
            frontier: 7,
            seed: Some(Seed::from_u64(9).bytes()),
        }),
        recorded_controls: vec![RecordedControlWire {
            configuration_schedule: schedule,
            node_times: Vec::new(),
            control: vec![ControlOperation {
                sequence: 1,
                kind: crucible::ControlOperationKind::Snapshot,
            }],
        }],
        selectable_catalog_plans: vec![SelectableCatalogWire {
            node: wire_string("vm-0"),
            plan: selectable_plan.encode().expect("encode selectable plan"),
        }],
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&wire, &mut bytes).expect("encode lifecycle fixture");

    let decoded = decode_lifecycle(&bytes, &scenario, FaultResourceLimits::default())
        .expect("decode lifecycle fixture");

    assert_eq!(
        decoded.terminal,
        Some(QuantumTerminalVerdict::Failed(vec![String::from("failed")]))
    );
    assert!(!decoded.initial_lifecycle_observations_pending);
    assert_eq!(
        decoded.terminal_cause,
        Some(CheckpointTerminalCause::Failed(vec![String::from(
            "failed"
        )]))
    );
    let branch = decoded.branch.expect("branch should restore");
    assert_eq!(branch.frontier, VirtualTime { ticks: 7 });
    assert_eq!(branch.seed, Some(Seed::from_u64(9)));
    assert_eq!(decoded.recorded_controls.len(), 1);
    assert_eq!(
        decoded.selectable_catalog_plans.get(&NodeId {
            name: String::from("vm-0")
        }),
        Some(&selectable_plan)
    );
    assert_eq!(decoded.recorded_controls[0].control[0].sequence, 1);
}

#[cfg(feature = "test-support")]
#[test]
fn v9_exact_ram_fixture_retains_the_complete_layer_chain() {
    let source_root = tempfile::tempdir().expect("create exact RAM source store");
    let fixture = build_exact_ram_production_checkpoint_codec_fixture(source_root.path())
        .expect("build exact RAM closure fixture");
    assert_ne!(fixture.parent_closure(), fixture.closure().identity());
    let parent = load_exact_ram_checkpoint_parent(
        source_root.path(),
        fixture.source(),
        &NodeId {
            name: String::from("vm-a"),
        },
        fixture.parent_closure(),
        fixture.layer_identities()[0],
    )
    .expect("load authoritative exact RAM parent");
    assert_eq!(parent.layers.len(), 1);
    fixture
        .closure()
        .validate_complete()
        .expect("validate exact RAM closure");
}

#[cfg(feature = "test-support")]
fn rewrite_exact_ram_fixture_manifest(
    run_state_root: &Path,
    fixture: &AuthenticatedProductionExactRamCodecFixture,
    mutate: impl FnOnce(&mut ExactRamManifest),
) -> ContentHash {
    let _restored = load_exact_checkpoint_set(
        run_state_root,
        &fixture.source().scenario_def(),
        fixture.source(),
        fixture.closure().identity(),
    )
    .expect("load exact RAM fixture before mutation");
    let mut manifest = decode::decode_manifest_with_limits(
        fixture.closure().manifest(),
        fixture.source().plan().fault_signals().resource_limits(),
    )
    .expect("decode exact RAM fixture manifest");
    let configuration = manifest.configuration;
    let target = manifest.targets.first_mut().expect("find fixture target");
    let node = NodeId {
        name: target.node.to_string(),
    };
    let fault_identity = manifest.fault_checkpoint;
    let exact_ram = &mut target.exact_ram;
    mutate(exact_ram);
    let checkpoint = production_exact_ram_from_manifest(exact_ram.clone(), PathBuf::new())
        .expect("rebuild mutated exact RAM metadata");
    target.manifest_identity = exact_ram_checkpoint_target_manifest_identity(
        ExactCheckpointTargetManifestBasis {
            configuration,
            immutable_backing: target.immutable_backing,
            node: &node,
            counter: target.counter,
            scheduler_time: VirtualTime {
                ticks: target.scheduler_time,
            },
            snapshot: target.snapshot,
            fault_identity,
            overlay: target.overlay.identity,
            device_state: target.exact_ram.device.identity,
        },
        &checkpoint,
    );
    manifest.identity = closure_identity(&manifest).expect("derive mutated closure identity");
    let bytes = encode_manifest(&manifest).expect("encode mutated exact RAM manifest");
    let scenario = fixture.source().scenario_def().id();
    let original =
        closure_parent(run_state_root, scenario).join(fixture.closure().identity().to_hex());
    let destination = closure_parent(run_state_root, scenario).join(manifest.identity.to_hex());
    fs::rename(&original, &destination).expect("rename mutated exact RAM closure");
    fs::write(destination.join(MANIFEST_FILE), bytes).expect("replace mutated exact RAM manifest");
    manifest.identity
}

#[cfg(feature = "test-support")]
#[test]
fn v9_exact_ram_loader_derives_the_qmp_identity_from_authenticated_state() {
    let store = tempfile::tempdir().expect("create exact RAM store");
    let fixture = build_exact_ram_production_checkpoint_codec_fixture(store.path())
        .expect("build exact RAM closure fixture");
    let identity = rewrite_exact_ram_fixture_manifest(store.path(), &fixture, |exact_ram| {
        exact_ram
            .layers
            .last_mut()
            .expect("find final RAM layer")
            .identity
            .frontier = ContentHash::from_bytes(b"forged exact RAM frontier");
    });

    let error = load_exact_checkpoint_set(
        store.path(),
        &fixture.source().scenario_def(),
        fixture.source(),
        identity,
    )
    .expect_err("self-consistent manifest hashes cannot forge a QMP frontier");
    assert!(error.to_string().contains("QMP identity authentication"));
}

#[cfg(feature = "test-support")]
#[test]
fn v9_exact_ram_loader_authenticates_declared_sha256_digests() {
    for role in ["device", "RAM layer"] {
        let store = tempfile::tempdir().expect("create exact RAM store");
        let fixture = build_exact_ram_production_checkpoint_codec_fixture(store.path())
            .expect("build exact RAM closure fixture");
        let identity = rewrite_exact_ram_fixture_manifest(store.path(), &fixture, |exact_ram| {
            if role == "device" {
                exact_ram.device_content_sha256 = ContentHash::from_bytes(b"forged device SHA-256");
            } else {
                exact_ram.layers[0].content_sha256 = ContentHash::from_bytes(b"forged RAM SHA-256");
            }
        });

        let error = load_exact_checkpoint_set(
            store.path(),
            &fixture.source().scenario_def(),
            fixture.source(),
            identity,
        )
        .expect_err("self-consistent manifest hashes cannot forge artifact SHA-256");
        assert!(error.to_string().contains("failed SHA-256 authentication"));
    }
}
