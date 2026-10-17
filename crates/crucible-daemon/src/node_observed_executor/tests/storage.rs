//! Genuine finite public request sources feeding captured native storage models.

use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::canonical;

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_scripted_block_requests_preserve_correlation_bytes_and_source_provenance() {
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
            node: id("source"),
            owner: id("source-owner"),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: script_ref,
                    consumer: id("disk"),
                },
            },
        },
    ];
    let scenario = catalog.scenario(&selected).unwrap();
    assert_eq!(scenario.world.connections.len(), 1);
    let execution = ExecutionId::from_bytes([72; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            NodeRunConfiguration {
                horizon_ps: 200_000.into(),
                maximum_rounds: 32.into(),
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
        std::thread::sleep(Duration::from_millis(1));
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
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].request_id, 101);
    assert_eq!(responses[1].request_id, 102);
    assert_eq!(responses[1].data, vec![7, 8, 9]);
    assert_eq!(std::fs::read(base_path).unwrap(), base);
    assert_eq!(
        worker
            .submit("native-storage", &request, &admission)
            .unwrap(),
        ObservedAttemptState::Completed(result)
    );
}
