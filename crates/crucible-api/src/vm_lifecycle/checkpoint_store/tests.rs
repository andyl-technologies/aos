//! Unit tests for durable exact-checkpoint closure storage.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use super::*;

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt as _;

fn manifest() -> ClosureManifest {
    ClosureManifest {
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
        node_generations: Vec::new(),
        node_service_states: Vec::new(),
        identity: ContentHash::default(),
    }
}

fn target(node: &str) -> TargetManifest {
    let artifact = ArtifactManifest {
        identity: ContentHash::from_bytes(b"artifact"),
        length: 8,
        chunks: vec![ContentHash::from_bytes(b"artifact")],
    };
    TargetManifest {
        node: String::from(node),
        counter: 0,
        scheduler_time: 0,
        snapshot: ContentHash::from_bytes(node.as_bytes()),
        overlay: artifact.clone(),
        vmstate: artifact,
        manifest_identity: ContentHash::default(),
    }
}

struct MemoryPortable {
    identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest: Vec<u8>,
    objects: Vec<ProductionExactCheckpointObject>,
    bodies: BTreeMap<ContentHash, Vec<u8>>,
}

impl ProductionExactCheckpointSource for MemoryPortable {
    fn identity(&self) -> ContentHash {
        self.identity
    }

    fn scenario(&self) -> ContentHash {
        self.scenario
    }

    fn configuration(&self) -> ContentHash {
        self.configuration
    }

    fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    fn objects(&self) -> &[ProductionExactCheckpointObject] {
        &self.objects
    }

    fn open_object(
        &self,
        identity: ContentHash,
    ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
        let bytes = self
            .bodies
            .get(&identity)
            .ok_or_else(|| loop_factory_error("memory portable object is absent"))?
            .clone();
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }
}

fn snapshot_portable(mut manifest: ClosureManifest, snapshot: &QemuVmSnapshot) -> MemoryPortable {
    let bytes = snapshot
        .to_canonical_bytes()
        .expect("encode production snapshot fixture");
    let object = ContentHash::from_bytes(&bytes);
    manifest.targets[0].snapshot = object;
    let configuration = manifest.configuration;
    let fault_checkpoint = manifest.fault_checkpoint;
    let target = &mut manifest.targets[0];
    let node = NodeId {
        name: target.node.clone(),
    };
    target.manifest_identity =
        exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
            configuration,
            node: &node,
            counter: target.counter,
            scheduler_time: VirtualTime {
                ticks: target.scheduler_time,
            },
            snapshot: snapshot.id(),
            fault_identity: fault_checkpoint,
            overlay: target.overlay.identity,
            vmstate: target.vmstate.identity,
        });
    manifest.identity = closure_identity(&manifest).expect("derive snapshot closure identity");
    MemoryPortable {
        identity: manifest.identity,
        scenario: manifest.scenario,
        configuration: manifest.configuration,
        manifest: encode_manifest(&manifest).expect("encode snapshot closure fixture"),
        objects: vec![ProductionExactCheckpointObject::new(
            object,
            u64::try_from(bytes.len()).expect("snapshot fixture length fits"),
        )],
        bodies: BTreeMap::from([(object, bytes)]),
    }
}

fn refresh_target_manifest_identities(manifest: &mut ClosureManifest) {
    let configuration = manifest.configuration;
    let fault_checkpoint = manifest.fault_checkpoint;
    for target in &mut manifest.targets {
        let node = NodeId {
            name: target.node.clone(),
        };
        target.manifest_identity =
            exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                configuration,
                node: &node,
                counter: target.counter,
                scheduler_time: VirtualTime {
                    ticks: target.scheduler_time,
                },
                snapshot: target.snapshot,
                fault_identity: fault_checkpoint,
                overlay: target.overlay.identity,
                vmstate: target.vmstate.identity,
            });
    }
}

fn publish_one_node_raw_checkpoint(
    run_state_root: &Path,
) -> (ScenarioDefForm, ContentHash, NodeId, ContentHash) {
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
    .expect("build one-node checkpoint world");
    let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::empty(),
        Seed::from_u64(0x4f52_4143),
        0,
    )
    .expect("build one-node checkpoint scenario");
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

    let nodes = ProductionNodeSet::new();
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
        .checkpoint(&mut ProductionNodeSet::new())
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
    let snapshot = QemuVmSnapshot::diskless(modeled_checkpoint, QemuReplayOracleValidation::NotRun)
        .expect("build raw one-node QEMU snapshot");
    let snapshot_identity = snapshot.id();

    let overlay = run_state_root.join("raw-overlay.qcow2");
    let vmstate = run_state_root.join("raw-vmstate.bin");
    fs::write(&overlay, b"overlay fixture").expect("write overlay fixture");
    fs::write(&vmstate, b"vmstate fixture").expect("write VMState fixture");
    let overlay_artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(overlay.clone()),
        identity: hash_file(&overlay).expect("hash overlay fixture"),
        length: fs::metadata(&overlay)
            .expect("inspect overlay fixture")
            .len(),
        chunks: Vec::new(),
    };
    let vmstate_artifact = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(vmstate.clone()),
        identity: hash_file(&vmstate).expect("hash VMState fixture"),
        length: fs::metadata(&vmstate)
            .expect("inspect VMState fixture")
            .len(),
        chunks: Vec::new(),
    };
    let manifest_identity =
        exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
            configuration: configuration.id(),
            node: &node,
            counter: 0,
            scheduler_time: VirtualTime { ticks: 0 },
            snapshot: snapshot_identity,
            fault_identity: fault_checkpoint.id(),
            overlay: overlay_artifact.identity,
            vmstate: vmstate_artifact.identity,
        });
    let mut checkpoint = ProductionVmExactCheckpointSet {
        identity: ContentHash::default(),
        configuration,
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
        fault_checkpoint: Some(fault_checkpoint),
        targets: BTreeMap::from([(
            node.clone(),
            ProductionVmExactCheckpointTarget {
                configuration: Configuration {
                    def: scenario,
                    schedule: Schedule::empty(),
                },
                counter: 0,
                scheduler_time: VirtualTime { ticks: 0 },
                snapshot,
                overlay_artifact,
                vmstate_artifact,
                manifest_identity,
            },
        )]),
        node_generations: BTreeMap::from([(node.clone(), 1)]),
        node_service_states: BTreeMap::from([(node.clone(), ProductionNodeServiceState::Running)]),
    };
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
fn closure_manifest_round_trip_is_canonical() {
    let mut original = manifest();
    original.targets = vec![target("a"), target("b")];
    original.node_generations = vec![(String::from("a"), 1), (String::from("b"), 2)];
    original.node_service_states = vec![(String::from("a"), 1), (String::from("b"), 2)];

    let bytes = encode_manifest(&original).expect("encode canonical closure manifest");
    let decoded = decode_manifest(&bytes).expect("decode canonical closure manifest");

    assert_eq!(
        encode_manifest(&decoded).expect("re-encode canonical closure manifest"),
        bytes
    );
}

#[test]
fn closure_manifest_rejects_unsorted_or_trailing_records() {
    let mut unsorted = manifest();
    unsorted.targets = vec![target("b"), target("a")];
    let bytes = encode_manifest(&unsorted).expect("encode fixture");
    assert!(decode_manifest(&bytes).is_err());

    let mut trailing = encode_manifest(&manifest()).expect("encode fixture");
    trailing.push(0);
    assert!(decode_manifest(&trailing).is_err());
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
fn replay_oracle_manifest_promotion_changes_only_target_snapshots() {
    let mut source = manifest();
    source.targets = vec![target("a"), target("b")];
    refresh_target_manifest_identities(&mut source);
    source.identity = closure_identity(&source).expect("derive raw closure identity");
    let mut promoted = source.clone();
    promoted.targets[0].snapshot = ContentHash::from_bytes(b"promoted-a");
    promoted.targets[1].snapshot = ContentHash::from_bytes(b"promoted-b");
    refresh_target_manifest_identities(&mut promoted);
    promoted.identity = closure_identity(&promoted).expect("derive promoted closure identity");

    validate_replay_oracle_manifest_basis(&source, &promoted)
        .expect("snapshot-only promotion should preserve the production basis");

    let mut changed_artifact = promoted.clone();
    changed_artifact.targets[0].overlay.length += 1;
    assert!(validate_replay_oracle_manifest_basis(&source, &changed_artifact).is_err());

    let unchanged = source.clone();
    assert!(validate_replay_oracle_manifest_basis(&source, &unchanged).is_err());

    let mut missing_target = promoted;
    missing_target.targets.pop();
    assert!(validate_replay_oracle_manifest_basis(&source, &missing_target).is_err());
}

#[test]
fn replay_oracle_source_pair_is_bound_to_every_exact_snapshot() {
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.production-replay-oracle-pair",
        "scenario",
    );
    let configuration = Configuration::genesis(scenario.clone());
    let checkpoint = Checkpoint::from_recorded_configuration(
        &configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("build replay-oracle checkpoint fixture");
    let raw = QemuVmSnapshot::diskless(checkpoint.clone(), QemuReplayOracleValidation::NotRun)
        .expect("build raw production snapshot");
    let runtime_hash = ContentHash::from_bytes(b"matching production runtime");
    let promoted = QemuVmSnapshot::diskless(
        checkpoint,
        QemuReplayOracleValidation::Match { runtime_hash },
    )
    .expect("build promoted production snapshot");
    let mut basis = manifest();
    basis.scenario = scenario.id();
    basis.configuration = configuration.id();
    basis.targets = vec![target("vm-a")];
    let source = snapshot_portable(basis.clone(), &raw);
    let promoted = snapshot_portable(basis, &promoted);

    authenticate_replay_oracle_source_pair(
        &source,
        &promoted,
        FaultResourceLimits::default(),
        ContentHash::default(),
        &mut || Ok(()),
    )
    .expect("exact raw-to-match source pair should authenticate");

    let foreign_configuration = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.production-replay-oracle-pair",
        "foreign",
    ));
    let foreign_checkpoint = Checkpoint::from_recorded_configuration(
        &foreign_configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("build foreign checkpoint fixture");
    let foreign = QemuVmSnapshot::diskless(
        foreign_checkpoint,
        QemuReplayOracleValidation::Match { runtime_hash },
    )
    .expect("build foreign promoted snapshot");
    let foreign = snapshot_portable(
        decode::decode_manifest_with_limits(source.manifest(), FaultResourceLimits::default())
            .expect("decode source manifest fixture"),
        &foreign,
    );
    assert!(
        authenticate_replay_oracle_source_pair(
            &source,
            &foreign,
            FaultResourceLimits::default(),
            ContentHash::default(),
            &mut || Ok(()),
        )
        .is_err()
    );
}

#[test]
fn production_replay_oracle_promotion_is_no_write_and_restart_authenticatable() {
    std::thread::Builder::new()
        .name(String::from("production-replay-oracle-promotion"))
        .stack_size(32 * 1024 * 1024)
        .spawn(run_production_replay_oracle_promotion_test)
        .expect("spawn large-stack production promotion test")
        .join()
        .expect("production promotion test should not panic");
}

fn run_production_replay_oracle_promotion_test() {
    let source_store = tempfile::tempdir().expect("create raw production store");
    let (source, raw_identity, node, raw_snapshot) =
        publish_one_node_raw_checkpoint(source_store.path());
    let raw = open_exact_checkpoint_closure(source_store.path(), &source, raw_identity)
        .expect("open raw production closure");
    raw.validate_complete()
        .expect("raw production closure should authenticate");
    let catalog_source = Arc::new(raw.clone());
    let catalog = catalog_source
        .replay_oracle_catalog()
        .expect("authenticate random-access replay catalog");
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog.nodes().collect::<Vec<_>>(), vec![&node]);
    let catalog_target = catalog
        .open_target(&node)
        .expect("open exact catalog target");
    assert_eq!(catalog_target.snapshot().id(), raw_snapshot);
    assert!(
        catalog
            .open_target(&NodeId {
                name: String::from("foreign-node"),
            })
            .is_err()
    );
    drop(catalog);
    drop(catalog_source);
    let mut replay_targets = raw
        .replay_oracle_targets()
        .expect("authenticate raw production replay targets");
    assert_eq!(replay_targets.remaining(), 1);
    let replay_target = replay_targets
        .next_target()
        .expect("stream raw production replay target")
        .expect("one raw production replay target");
    assert_eq!(replay_target.node(), &node);
    assert_eq!(replay_target.snapshot().id(), raw_snapshot);
    let mut overlay = Vec::new();
    let mut boundary_calls = 0_u64;
    {
        let mut boundary = || {
            boundary_calls += 1;
            Ok(())
        };
        replay_target
            .overlay()
            .stream_into_with_boundary(&mut overlay, &mut boundary)
            .expect("stream authenticated replay overlay");
    }
    assert!(boundary_calls >= 4);
    assert_eq!(
        u64::try_from(overlay.len()).expect("overlay length"),
        replay_target.overlay().length()
    );
    assert_eq!(
        ContentHash::from_bytes(&overlay),
        replay_target.overlay().identity()
    );
    let mut vmstate = Vec::new();
    replay_target
        .vmstate()
        .stream_into(&mut vmstate)
        .expect("stream authenticated replay VMState");
    assert_eq!(
        u64::try_from(vmstate.len()).expect("VMState length"),
        replay_target.vmstate().length()
    );
    assert_eq!(
        ContentHash::from_bytes(&vmstate),
        replay_target.vmstate().identity()
    );
    assert_eq!(replay_targets.remaining(), 0);
    assert!(
        replay_targets
            .next_target()
            .expect("finish raw production replay targets")
            .is_none()
    );
    let mut retry_targets = raw
        .replay_oracle_targets()
        .expect("authenticate retryable raw production targets");
    assert!(
        retry_targets
            .next_target_with_boundary(&mut || {
                Err(LifecycleApiError::LoopFactory {
                    message: String::from("injected target boundary failure"),
                })
            })
            .is_err()
    );
    assert_eq!(retry_targets.remaining(), 1);
    assert_eq!(
        retry_targets
            .next_target()
            .expect("retry the same production target")
            .expect("retried production target")
            .node(),
        &node,
    );
    assert!(
        !raw.authenticate_resume_basis()
            .expect("raw production resume basis")
            .replay_oracle_ready(),
        "a newly captured NotRun root must not be resume eligible",
    );
    let rejected_destination = tempfile::tempdir().expect("create rejected resume store");
    let scenario = source.scenario_def().id();
    let rejected_objects = object_parent(rejected_destination.path(), scenario);
    let rejected_publication =
        closure_parent(rejected_destination.path(), scenario).join(raw_identity.to_hex());
    let error = match install_exact_checkpoint_closure_with_boundary_and_admission(
        rejected_destination.path(),
        &source,
        &raw,
        &mut || Ok(()),
        &mut |basis| {
            if basis.replay_oracle_ready() {
                Ok(())
            } else {
                Err(LifecycleApiError::LoopFactory {
                    message: String::from("raw replay-oracle root is not resume ready"),
                })
            }
        },
    ) {
        Ok(_) => panic!("raw root admission must reject before native publication"),
        Err(error) => error,
    };
    assert!(matches!(error, LifecycleApiError::LoopFactory { .. }));
    assert!(!rejected_objects.exists());
    assert!(!rejected_publication.exists());
    let files_before = regular_file_count(source_store.path());
    let checks = BTreeMap::from([(
        node.clone(),
        QemuReplayOracleCheck::from_unvalidated_test_result(
            raw_snapshot,
            QemuReplayOracleValidation::Match {
                runtime_hash: ContentHash::from_bytes(b"matching production runtime"),
            },
        ),
    )]);

    let promotion = raw
        .prepare_replay_oracle_promotion(&checks)
        .expect("prepare source-bound production promotion");
    assert_eq!(promotion.source(), raw_identity);
    assert_ne!(promotion.promoted(), raw_identity);
    assert_eq!(regular_file_count(source_store.path()), files_before);

    let promoted_store = tempfile::tempdir().expect("create promoted production store");
    let promoted_identity = promotion.promoted();
    install_exact_checkpoint_closure(promoted_store.path(), &source, &promotion)
        .expect("install promoted production closure");
    let promoted = open_exact_checkpoint_closure(promoted_store.path(), &source, promoted_identity)
        .expect("open promoted production closure");
    assert!(
        promoted
            .authenticate_resume_basis()
            .expect("promoted production resume basis")
            .replay_oracle_ready(),
        "the exact source-bound Match replacement must be resume eligible",
    );
    let mut promoted_targets = promoted
        .replay_oracle_targets()
        .expect("authenticate promoted production replay targets");
    assert!(
        promoted_targets.next_target().is_err(),
        "a promoted snapshot must not be exposed as a raw comparison source",
    );
    raw.authenticate_replay_oracle_promotion(&promoted)
        .expect("restart validation should authenticate the exact root pair");
    authenticate_portable_exact_checkpoint_replay_oracle_promotion(&source, &raw, &promoted)
        .expect("portable restart validator should authenticate the exact root pair");

    let foreign_check = BTreeMap::from([(
        node,
        QemuReplayOracleCheck::from_unvalidated_test_result(
            ContentHash::from_bytes(b"foreign source snapshot"),
            QemuReplayOracleValidation::Match {
                runtime_hash: ContentHash::from_bytes(b"matching production runtime"),
            },
        ),
    )]);
    assert!(raw.prepare_replay_oracle_promotion(&foreign_check).is_err());
    assert_eq!(regular_file_count(source_store.path()), files_before);
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
    let object_length = u64::try_from(bytes.len()).expect("fixture length fits");
    assert_eq!(closure.objects()[0].length(), object_length);
    let mut copied = Vec::new();
    assert_eq!(
        closure
            .copy_object_to(object_identity, &mut copied)
            .expect("stream portable object"),
        object_length
    );
    assert_eq!(copied, bytes);
    assert!(
        closure
            .copy_object_to(ContentHash::from_bytes(b"unlisted"), &mut Vec::new())
            .is_err()
    );

    fs::write(object_path(&object_directory, object_identity), b"changed")
        .expect("replace portable object fixture");
    assert!(
        closure
            .copy_object_to(object_identity, &mut Vec::new())
            .is_err()
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
fn file_artifact_materialization_streams_and_preserves_sparse_zero_extents() {
    let root = tempfile::tempdir().expect("create sparse materialization fixture");
    let source = root.path().join("source");
    let restored = root.path().join("restored");
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
    };
    materialize_checkpoint_artifact(&artifact, &restored, "sparse test")
        .expect("materialize sparse source");

    assert_eq!(hash_file(&restored).expect("hash sparse result"), identity);
    let metadata = fs::metadata(&restored).expect("inspect sparse result");
    assert_eq!(metadata.len(), length);
    assert!(metadata.blocks().saturating_mul(512) < length);

    fs::remove_file(&restored).expect("remove sparse result");
    let mut changed = OpenOptions::new()
        .write(true)
        .open(source)
        .expect("reopen sparse source");
    changed.write_all(b"fail").expect("change sparse source");
    changed.sync_all().expect("flush changed sparse source");
    assert!(materialize_checkpoint_artifact(&artifact, &restored, "changed sparse test").is_err());
    assert!(!restored.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn chunked_artifact_materialization_recreates_sparse_zero_extents() {
    let root = tempfile::tempdir().expect("create sparse chunk fixture");
    let source = root.path().join("source");
    let restored = root.path().join("restored");
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
    };
    let manifest = artifact_manifest(&source_artifact).expect("derive sparse chunk manifest");
    persist_chunked_artifact(&object_directory, &manifest, &source_artifact)
        .expect("persist sparse chunks");
    let chunked = ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::ChunkStore(object_directory),
        identity,
        length,
        chunks: manifest.chunks,
    };
    materialize_checkpoint_artifact(&chunked, &restored, "sparse chunk test")
        .expect("materialize sparse chunks");

    assert_eq!(hash_file(&restored).expect("hash sparse result"), identity);
    let metadata = fs::metadata(&restored).expect("inspect sparse result");
    assert_eq!(metadata.len(), length);
    assert!(metadata.blocks().saturating_mul(512) < length);
}

#[test]
fn chunk_store_deduplicates_and_materializes_complete_artifacts() {
    let root = tempfile::tempdir().expect("create chunk-store fixture");
    let source = root.path().join("source");
    let restored = root.path().join("restored");
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
    };
    let mut streamed = Vec::new();
    ProductionVmNodeCheckpointArtifact {
        artifact: &chunked,
        role: "test",
    }
    .stream_into(&mut streamed)
    .expect("stream authenticated chunked artifact");
    assert_eq!(streamed, bytes);
    materialize_checkpoint_artifact(&chunked, &restored, "test")
        .expect("materialize chunked artifact");
    assert_eq!(fs::read(&restored).expect("read restored artifact"), bytes);

    let first_chunk = object_path(&object_directory, manifest.chunks[0]);
    fs::write(&first_chunk, vec![0; ARTIFACT_CHUNK_BYTES]).expect("corrupt first checkpoint chunk");
    let mut rejected_stream = Vec::new();
    assert!(
        ProductionVmNodeCheckpointArtifact {
            artifact: &chunked,
            role: "corrupt test",
        }
        .stream_into(&mut rejected_stream)
        .is_err()
    );
    fs::remove_file(&restored).expect("remove prior materialization");
    assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
    assert!(!restored.exists());
    fs::write(&first_chunk, &bytes[..ARTIFACT_CHUNK_BYTES])
        .expect("restore first checkpoint chunk");

    let last_chunk = object_path(
        &object_directory,
        *manifest.chunks.last().expect("fixture has a tail chunk"),
    );
    fs::remove_file(last_chunk).expect("remove tail checkpoint chunk");
    assert!(!restored.exists());
    assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
    assert!(!restored.exists());
}

#[test]
fn lifecycle_wire_restores_terminal_branch_and_controls() {
    let scenario = crucible::happy_path_scenario()
        .expect("build lifecycle wire scenario")
        .scenario
        .scenario_def();
    let schedule = Schedule::empty().to_compact_binary();
    let wire = LifecycleWire {
        terminal: Some(TerminalWire::Failed(vec![String::from("failed")])),
        terminal_cause: Some(TerminalCauseWire::Failed(vec![String::from("failed")])),
        initial_lifecycle_observations_pending: false,
        branch: Some(BranchWire {
            base_schedule: schedule.clone(),
            frontier: 7,
            decisions: Vec::new(),
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
    assert_eq!(decoded.recorded_controls[0].control[0].sequence, 1);
}
