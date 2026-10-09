//! Actual executor/cache compatibility witnesses, without new native replay claims.

use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind, ScriptedSource};
use crucible_campaign::observed_node_attempt::ObservedAttemptResult;
use crucible_cas::content_store::{ContentId, RefName};
use crucible_device::{BlockRequest, BlockResponse};
use crucible_node_contract::{Bytes, canonical};

fn service(
    temporary: &tempfile::TempDir,
    repository: Arc<CampaignRepository>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    artifacts: Vec<InstalledIoArtifact>,
) -> NodeObservationService {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    NodeObservationService::start(
        NodeObservationServiceConfig {
            expected_device: factory::measure_executable(&executable).unwrap(),
            device_executable: executable,
            installed_artifacts: artifacts,
            socket_parent: temporary.path().to_owned(),
            control_timeout: Duration::from_secs(5),
            maximum_worlds: 2,
            maximum_pending_requests: 4,
        },
        repository,
        blobs,
        refs,
    )
    .unwrap()
}

fn complete(service: &NodeObservationService, execution: ExecutionId) -> ObservedAttemptResult {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match service.state(execution).unwrap() {
            ObservedAttemptState::Completed(result) => return result,
            ObservedAttemptState::Reserved(_) => {}
            ObservedAttemptState::Quarantined { reason, .. } => panic!("native world: {reason}"),
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn retire(service: NodeObservationService) {
    let retention = service.retention_owner();
    drop(service);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !retention.is_retired() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn namespace(refs: &dyn MutableRefBackend, name: &str) -> Vec<(String, ContentId)> {
    let namespace = RefName::new(name).unwrap();
    let page = refs.scan_refs(&namespace, None, 256).unwrap();
    assert!(page.next_after().is_none());
    page.entries()
        .iter()
        .map(|entry| (entry.name().as_str().into(), entry.target()))
        .collect()
}

fn execution_text(execution: ExecutionId) -> String {
    execution
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn request(
    selected: Vec<InstalledNodeSelection>,
    scenario: Vec<u8>,
    configuration: Vec<u8>,
    result: &ObservedAttemptResult,
) -> NodeCacheReuseRequest {
    NodeCacheReuseRequest {
        format: "crucible.node-cache-reuse".into(),
        version: 1,
        source_execution: execution_text(result.request().execution()),
        expected_cache_key: Some(node_cache_key(result).to_hex()),
        selections: selected,
        scenario: Bytes::new(scenario),
        configuration: Bytes::new(configuration),
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the source-built companion"]
fn actual_source_block_cache_survives_retirement_and_source_removal_without_dispatch() {
    let temporary = tempfile::tempdir().unwrap();
    let blob_root = temporary.path().join("blobs");
    let blobs: Arc<dyn ImmutableBlobBackend> =
        Arc::new(DirectoryBlobBackend::new("cache-source", blob_root.clone()));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
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
    let selected = vec![
        InstalledNodeSelection {
            node: id("disk"),
            owner: id("disk-owner"),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: base_ref.clone(),
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
                    script: script_ref.clone(),
                    consumer: id("disk"),
                },
            },
        },
    ];
    let original = service(
        &temporary,
        repository.clone(),
        blobs.clone(),
        refs.clone(),
        vec![
            InstalledIoArtifact::path(base_path.clone(), base_ref.clone()),
            InstalledIoArtifact::path(script_path.clone(), script_ref.clone()),
        ],
    );
    let scenario = original.compile(selected.clone()).unwrap();
    let configuration = canonical::canonical_json(
        &serde_json::to_value(NodeRunConfiguration {
            horizon_ps: 200_000.into(),
            maximum_rounds: 32.into(),
            ..configuration()
        })
        .unwrap(),
    )
    .unwrap();
    let execution = ExecutionId::from_bytes([91; 16]).unwrap();
    original
        .submit(
            "cache-storage".into(),
            execution,
            selected.clone(),
            scenario.clone(),
            configuration.clone(),
        )
        .unwrap();
    let result = complete(&original, execution);
    assert!(result.request().capabilities().roster().is_repeatable());
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let events: serde_json::Value = serde_json::from_slice(
        &blobs
            .read(result.outgoing(), None)
            .unwrap()
            .read_all(16 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let responses: Vec<BlockResponse> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            serde_json::from_value::<crucible::node_contract::OperationOutcome>(event.clone())
                .unwrap()
        })
        .filter(|outcome| outcome.node == id("disk"))
        .flat_map(|outcome| outcome.scheduling.unwrap().publications)
        .map(|publication| BlockResponse::decode(&publication.payload_bytes).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1].request_id, 102);
    assert_eq!(responses[1].data, vec![7, 8, 9]);
    assert_eq!(std::fs::read(&base_path).unwrap(), base);
    retire(original);
    std::fs::remove_file(&base_path).unwrap();
    std::fs::remove_file(&script_path).unwrap();

    let before_activation = namespace(refs.as_ref(), "node-world-activations");
    let before_reservations = namespace(refs.as_ref(), "observed-execution-reservations");
    let before_ledger = namespace(refs.as_ref(), "observed-attempt-ledgers");
    let restarted = service(
        &temporary,
        repository.clone(),
        blobs.clone(),
        refs.clone(),
        vec![
            InstalledIoArtifact::archive_only(base_ref),
            InstalledIoArtifact::archive_only(script_ref),
        ],
    );
    // ArchiveOnly cannot freshly compile or allocate a replacement storage world.
    assert!(restarted.compile(selected.clone()).is_err());
    let request = request(selected, scenario, configuration, &result);
    let wire =
        crate::node_control::NodeControlRequest::cache_reuse("operator/cache", request.clone())
            .unwrap();
    assert_eq!(wire.version, 6);
    assert_eq!(
        serde_json::to_value(&wire).unwrap()["command"]["operation"],
        "cache_reuse"
    );
    for version in [1, 2, 3, 4, 5, 7] {
        let mut wrong_edition = wire.clone();
        wrong_edition.version = version;
        let error = crate::node_control::request_node_control(
            &temporary.path().join("unallocated-endpoint.sock"),
            &wrong_edition,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            crate::node_control::NodeControlError::Refused(_)
        ));
    }
    let receipt = restarted.reuse_cache(request.clone()).unwrap();
    assert_eq!(receipt.result.as_slice(), result.canonical_bytes());
    assert_eq!(receipt.source_execution, execution_text(execution));
    assert_eq!(
        receipt.original_result,
        result.id().unwrap().content_id().encode()
    );
    assert_eq!(restarted.reuse_cache(request.clone()).unwrap(), receipt);
    assert_eq!(
        namespace(refs.as_ref(), "node-world-activations"),
        before_activation
    );
    assert_eq!(
        namespace(refs.as_ref(), "observed-execution-reservations"),
        before_reservations
    );
    assert_eq!(
        namespace(refs.as_ref(), "observed-attempt-ledgers"),
        before_ledger
    );

    let mut wrong_configuration = request.clone();
    let mut configuration =
        NodeRunConfiguration::from_json(request.configuration.as_slice()).unwrap();
    configuration.horizon_ps = 200_001.into();
    wrong_configuration.configuration = Bytes::new(
        canonical::canonical_json(&serde_json::to_value(configuration).unwrap()).unwrap(),
    );
    assert!(restarted.reuse_cache(wrong_configuration).is_err());
    let mut wrong_backend = request.clone();
    wrong_backend.selections[0].kind = InstalledNodeKind::HostClock;
    assert!(restarted.reuse_cache(wrong_backend).is_err());
    let mut wrong_model = request.clone();
    let InstalledNodeKind::HostIo {
        profile: InstalledHostIoProfile::Block { read_ns, .. },
    } = &mut wrong_model.selections[0].kind
    else {
        panic!("storage fixture")
    };
    *read_ns = 2.into();
    assert!(restarted.reuse_cache(wrong_model).is_err());
    let mut wrong_identity = request.clone();
    wrong_identity.expected_cache_key = Some("00".repeat(32));
    assert!(restarted.reuse_cache(wrong_identity).is_err());
    let id = result.evidence();
    let encoded = id.encode();
    let digest = encoded.rsplit('.').next().unwrap();
    let evidence_path = blob_root.join("objects").join(&digest[..2]).join(encoded);
    std::fs::write(evidence_path, b"corrupt original native proof closure").unwrap();
    assert!(restarted.reuse_cache(request).is_err());
    assert_eq!(
        namespace(refs.as_ref(), "node-world-activations"),
        before_activation
    );
    assert_eq!(
        namespace(refs.as_ref(), "observed-execution-reservations"),
        before_reservations
    );
    retire(restarted);
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the source-built companion"]
fn actual_mixed_nondeterministic_world_refuses_cache_before_replacement_allocation() {
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "cache-physical",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let service = service(&temporary, repository, blobs, refs.clone(), vec![]);
    let selected = selections();
    let scenario = service.compile(selected.clone()).unwrap();
    let configuration =
        canonical::canonical_json(&serde_json::to_value(configuration()).unwrap()).unwrap();
    let execution = ExecutionId::from_bytes([92; 16]).unwrap();
    service
        .submit(
            "cache-nondeterministic".into(),
            execution,
            selected.clone(),
            scenario.clone(),
            configuration.clone(),
        )
        .unwrap();
    let result = complete(&service, execution);
    assert!(!result.request().capabilities().roster().is_repeatable());
    let before = namespace(refs.as_ref(), "node-world-activations");
    let refusal = service
        .reuse_cache(request(selected, scenario, configuration, &result))
        .unwrap_err();
    assert!(refusal.to_string().contains("nondeterministic owner"));
    assert_eq!(namespace(refs.as_ref(), "node-world-activations"), before);
    assert_eq!(
        service.state(execution).unwrap(),
        ObservedAttemptState::Completed(result)
    );
    retire(service);
}
