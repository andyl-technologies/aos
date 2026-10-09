//! Actual byte delivery across controlled native windows and an exact host link.

use super::*;

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_native_linked_world_preserves_payloads_and_never_outruns_input() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "connected-observed",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let expected = factory::measure_executable(&executable).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable,
        expected,
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let selected = vec![
        InstalledNodeSelection {
            node: id("consumer"),
            owner: id("consumer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
                closed_ingress: false,
            },
        },
        InstalledNodeSelection {
            node: id("link"),
            owner: id("link-owner"),
            kind: InstalledNodeKind::HostNetLink {
                producer: id("producer"),
                consumer: id("consumer"),
                source_node: 7,
                latency_ps: U64::new(5),
                floor_ps: U64::new(5),
            },
        },
        InstalledNodeSelection {
            node: id("producer"),
            owner: id("producer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
                closed_ingress: true,
            },
        },
    ];
    let scenario = catalog.scenario(&selected).unwrap();
    assert_eq!(scenario.world.connections.len(), 2);
    let configuration = NodeRunConfiguration {
        horizon_ps: U64::new(150),
        maximum_rounds: U64::new(32),
        ..configuration()
    };
    let execution = ExecutionId::from_bytes([71; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            configuration,
            execution,
            blobs.clone(),
            refs,
        )
        .unwrap();
    let scenario = backend.scenario_artifact();
    repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .unwrap();
    let configuration = backend.configuration_artifact();
    repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .unwrap();
    let request = backend.request(execution).unwrap();
    assert!(!request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker
        .submit("native-connected", &request, &admission)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => break result,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual connected native world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(
            Instant::now() < deadline,
            "connected native execution remained blocked"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    let bytes = blobs
        .read(result.incoming(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let ingress: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let cuts = ingress["events"].as_array().unwrap();
    let consumer = cuts
        .iter()
        .filter(|event| event["node"] == "consumer")
        .collect::<Vec<_>>();
    assert_eq!(consumer.len(), 3);
    assert!(consumer[0]["deliveries"].as_array().unwrap().is_empty());
    let deliveries = consumer[2]["deliveries"].as_array().unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0]["delivery"]["time_ps"], "100");
    assert_eq!(deliveries[0]["publication"]["time_ps"], "55");
    let payloads = consumer[2]["payloads"].as_array().unwrap();
    assert_eq!(payloads.len(), 1);
    let payload: crucible::node_scheduling::InputPayload =
        serde_json::from_value(payloads[0].clone()).unwrap();
    payload.reference.verify(&payload.bytes).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&payload.bytes).unwrap();
    assert_eq!(original["bytes_processed"], "0");
    let bytes = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let outgoing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let outcomes: Vec<crucible::node_contract::OperationOutcome> = outgoing["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| serde_json::from_value(event.clone()).unwrap())
        .collect();
    let final_consumer = outcomes
        .iter()
        .filter(|outcome| outcome.node == id("consumer"))
        .next_back()
        .unwrap();
    let publication = &final_consumer.scheduling.as_ref().unwrap().publications[0];
    assert_eq!(publication.publication.time_ps, U64::new(150));
    assert!(publication.evaluation.is_none());
    assert_eq!(publication.causal_parents.len(), 1);
    assert_eq!(publication.causal_parents[0].time_ps, U64::new(100));
    let processed: serde_json::Value = serde_json::from_slice(&publication.payload_bytes).unwrap();
    assert_eq!(
        processed["bytes_processed"],
        payload.bytes.len().to_string()
    );
    let expected_checksum = payload.bytes.iter().fold(0u64, |value, byte| {
        value.wrapping_mul(257).wrapping_add(u64::from(*byte))
    });
    assert_eq!(processed["checksum"], expected_checksum.to_string());
    assert_eq!(
        worker
            .submit("native-connected", &request, &admission)
            .unwrap(),
        ObservedAttemptState::Completed(result)
    );
}
