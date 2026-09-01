//! Durable checkpoint-store unit tests.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use super::*;

fn wire_string(value: &str) -> decode::FallibleString {
    decode::FallibleString::new(String::from(value))
}

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
        node: wire_string(node),
        counter: 0,
        scheduler_time: 0,
        snapshot: ContentHash::from_bytes(node.as_bytes()),
        overlay: artifact.clone(),
        vmstate: artifact,
        manifest_identity: ContentHash::default(),
    }
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
    materialize_checkpoint_artifact(&chunked, &restored, "test")
        .expect("materialize chunked artifact");
    assert_eq!(fs::read(&restored).expect("read restored artifact"), bytes);

    let first_chunk = object_path(&object_directory, manifest.chunks[0]);
    fs::write(&first_chunk, vec![0; ARTIFACT_CHUNK_BYTES]).expect("corrupt first checkpoint chunk");
    fs::remove_file(&restored).expect("remove prior materialization");
    assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
    fs::write(&first_chunk, &bytes[..ARTIFACT_CHUNK_BYTES])
        .expect("restore first checkpoint chunk");

    let last_chunk = object_path(
        &object_directory,
        *manifest.chunks.last().expect("fixture has a tail chunk"),
    );
    fs::remove_file(last_chunk).expect("remove tail checkpoint chunk");
    assert!(!restored.exists());
    assert!(materialize_checkpoint_artifact(&chunked, &restored, "test").is_err());
}

#[test]
fn lifecycle_wire_restores_terminal_branch_and_controls() {
    let scenario = crucible::happy_path_scenario()
        .expect("build lifecycle wire scenario")
        .scenario
        .scenario_def();
    let schedule = Schedule::empty().to_compact_binary();
    let wire = LifecycleWire {
        terminal: Some(TerminalWire::Failed(vec![wire_string("failed")])),
        terminal_cause: Some(TerminalCauseWire::Failed(vec![wire_string("failed")])),
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
