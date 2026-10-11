//! Genuine ordinary observed worker with a adverse transport between source and storage.

use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::canonical;

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_adverse_transport_worker_preserves_original_fault_draws_correlation_and_storage_bytes() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "storage-observed",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        factory::measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let base = vec![0xab; 4096];
    let definition = crucible::node_adapters::FaultedLinkDefinition {
        version: 1,
        seed: 77.into(),
        stream: id("storage/requests"),
        source_node: 17,
        latency_ps: 1000.into(),
        floor_ps: 1000.into(),
        loss: crucible::node_adapters::FaultProbability {
            numerator: 0.into(),
            denominator: 1.into(),
        },
        duplicate: crucible::node_adapters::FaultProbability {
            numerator: 1.into(),
            denominator: 1.into(),
        },
        duplicate_gap_ps: 100.into(),
        corrupt: crucible::node_adapters::FaultProbability {
            numerator: 0.into(),
            denominator: 1.into(),
        },
        corruption_bits: 0,
    };
    let program = canonical::canonical_json(&serde_json::to_value(&definition).unwrap()).unwrap();
    let program_ref = canonical::content_ref(&program, "application/octet-stream").unwrap();
    let program_path = temporary.path().join("adverse-program");
    std::fs::write(&program_path, &program).unwrap();
    let script = ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![
            ScriptedRequest {
                time_ps: 10,
                payload: BlockRequest::write(101, 0, vec![7, 8, 9]).encode().unwrap(),
            },
            ScriptedRequest {
                time_ps: 50_000,
                payload: BlockRequest::read(102, 0, 3).encode().unwrap(),
            },
        ],
    )
    .unwrap()
    .script_bytes()
    .unwrap();
    let base_ref = canonical::content_ref(&base, "application/octet-stream").unwrap();
    let script_ref = canonical::content_ref(&script, "application/octet-stream").unwrap();
    let base_path = temporary.path().join("base");
    let script_path = temporary.path().join("script");
    std::fs::write(&base_path, &base).unwrap();
    std::fs::write(&script_path, &script).unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(program_path, program_ref.clone()),
            InstalledIoArtifact::path(base_path.clone(), base_ref.clone()),
            InstalledIoArtifact::path(script_path, script_ref.clone()),
        ])
        .unwrap();
    let selected = vec![
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: base_ref,
                    source_node: 7,
                    read_ns: 1.into(),
                    write_ns: 1.into(),
                    flush_ns: 1.into(),
                    get_length_ns: 1.into(),
                    per_byte_ns: 1.into(),
                },
            },
        },
        InstalledNodeSelection {
            node: id("link"),
            owner: id("link-owner"),
            kind: InstalledNodeKind::HostFaultedLink {
                profile: factory::InstalledFaultedLinkProfile {
                    program: program_ref,
                    producer: id("source"),
                    consumer: id("disk"),
                },
            },
        },
        InstalledNodeSelection {
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script_ref,
                    consumer: id("link"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selected).unwrap();
    assert_eq!(scenario.world.connections.len(), 2);
    let execution = ExecutionId::from_bytes([72; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            NodeRunConfiguration {
                horizon_ps: 200_000.into(),
                maximum_rounds: 128.into(),
                ..configuration()
            },
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let planned = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            planned.scenario(),
            planned.payload_schema(),
            planned.payload().to_vec(),
        )
        .unwrap();
    let configured = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configured.scenario(),
            configured.scenario_artifact(),
            configured.configuration(),
            configured.payload_schema(),
            configured.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    assert!(request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker
        .submit("native-storage", &request, &admission)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => break result,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual storage world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(
            Instant::now() < deadline,
            "actual storage world stayed blocked"
        );
        // Yield between polls of the same original execution; its deadline stays unchanged.
        std::thread::yield_now();
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let outgoing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut responses = Vec::new();
    for event in outgoing["events"].as_array().unwrap() {
        let outcome: crucible::node_contract::OperationOutcome =
            serde_json::from_value(event.clone()).unwrap();
        if outcome.node != id("disk") {
            continue;
        }
        for publication in &outcome.scheduling.as_ref().unwrap().publications {
            assert!(publication.evaluation.is_some());
            assert_eq!(publication.causal_parents.len(), 1);
            publication
                .payload
                .verify(&publication.payload_bytes)
                .unwrap();
            responses.push(BlockResponse::decode(&publication.payload_bytes).unwrap());
        }
    }
    assert_eq!(responses.len(), 4);
    assert_eq!(responses[0].request_id, 101);
    assert_eq!(responses[1].request_id, 101);
    assert_eq!(responses[2].request_id, 102);
    assert_eq!(responses[3].request_id, 102);
    assert_eq!(responses[2].data, vec![7, 8, 9]);
    assert_eq!(responses[3].data, vec![7, 8, 9]);
    assert_eq!(std::fs::read(base_path).unwrap(), base);
    assert_eq!(
        worker
            .submit("native-storage", &request, &admission)
            .unwrap(),
        ObservedAttemptState::Completed(result)
    );
}
