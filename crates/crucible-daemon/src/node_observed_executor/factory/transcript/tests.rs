//! Actual installed linked-source recording and original source retirement.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::time::Instant;

use crucible::node_adapters::transcript::{TranscriptAction, TranscriptArchive};
use crucible_campaign::{
    CampaignRepository,
    observed_node_attempt::{ObservedAttemptState, ObservedAttemptWorker},
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_recording_refusal_keeps_complete_reserved_native_world_until_reclaimed() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        1,
    )
    .unwrap();
    let selections = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("clock-owner"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("device"),
            owner: id("device-owner"),
            kind: InstalledNodeKind::ReferenceDevice {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(50),
        maximum_rounds: U64::new(8),
    };

    let result = catalog.prepare_recorded_world(
        &selections,
        scenario,
        &configuration,
        ExecutionId::from_bytes([92; 16]).unwrap(),
        TranscriptLimits {
            maximum_records: U64::new(8),
            maximum_record_bytes: U64::new(32),
            maximum_total_bytes: U64::new(32),
        },
    );
    let error = match result {
        Ok(_) => panic!("impossible source capture reservation was admitted"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, NodeObservedError::Native(cause) if cause == "CaptureLimit"),
        "actual source refusal: {error}"
    );
    assert_eq!(catalog.custody().reserved_worlds(), 1);
    assert_eq!(catalog.custody().retained_worlds(), 1);

    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let deadline = Instant::now() + Duration::from_secs(10);
    while catalog.custody().reserved_worlds() != 0 {
        if let std::task::Poll::Ready(Err(error)) = catalog.custody().poll_reclamation(&mut context)
        {
            panic!("retained native source reclamation failed: {error:?}");
        }
        assert!(
            Instant::now() < deadline,
            "refused native world remains alive"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(catalog.custody().retained_worlds(), 0);
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_direct_native_source_records_complete_original_inputs_before_retirement() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "installed-recording",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let selections = vec![
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
            node: id("producer"),
            owner: id("producer-owner"),
            kind: InstalledNodeKind::ReferenceNativeLinked {
                quantum_ps: U64::new(50),
                host_budget_ns: U64::new(20_000_000),
                closed_ingress: true,
            },
        },
    ];
    let scenario = catalog.scenario(&selections).unwrap();
    let run_configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(150),
        maximum_rounds: U64::new(32),
    };
    let execution = ExecutionId::from_bytes([91; 16]).unwrap();
    let InstalledRecordedWorld {
        prepared,
        recording,
    } = catalog
        .prepare_recorded_world(
            &selections,
            scenario.clone(),
            &run_configuration,
            execution,
            TranscriptLimits {
                maximum_records: U64::new(128),
                maximum_record_bytes: U64::new(1024 * 1024),
                maximum_total_bytes: U64::new(16 * 1024 * 1024),
            },
        )
        .unwrap();
    let context =
        super::super::super::backend::input_context_bytes(&scenario, &run_configuration).unwrap();
    let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
    assert!(
        blobs
            .put_if_absent(inputs, &BlobHandle::from_bytes(context))
            .unwrap()
            .is_durable()
    );
    let publisher = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs.clone(),
        RefName::new("node-world-activations/recording".to_owned()).unwrap(),
    )
    .unwrap();
    let backend = NodeObservedBackend::from_prepared(
        prepared,
        run_configuration.clone(),
        Box::new(publisher),
        blobs,
        inputs,
        execution,
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
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();
    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    worker
        .submit("installed-recording", &request, &admission)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(_) => break,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual recorded native world quarantined: {reason}");
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(Instant::now() < deadline, "native recording stalled");
        std::thread::sleep(Duration::from_millis(1));
    }

    let archive = TranscriptArchive::open(
        temporary.path().join("transcripts"),
        TranscriptLimits {
            maximum_records: U64::new(128),
            maximum_record_bytes: U64::new(1024 * 1024),
            maximum_total_bytes: U64::new(16 * 1024 * 1024),
        },
    )
    .unwrap();
    let recorded = recording.persist(&archive).unwrap();
    assert_eq!(recorded.len(), 2);
    let consumer = recorded.get(&id("consumer")).unwrap();
    assert_eq!(
        consumer.transcript().origin.repeatability,
        crucible_node_contract::Repeatability::Nondeterministic
    );
    assert!(
        consumer
            .transcript()
            .records
            .iter()
            .any(|record| record.request.action == TranscriptAction::StageInput)
    );
    assert!(
        consumer
            .transcript()
            .records
            .iter()
            .any(|record| !record.evidence.is_empty())
    );
    for source in recorded.values() {
        for record in &source.transcript().records {
            let response: serde_json::Value =
                serde_json::from_slice(&record.response_bytes).unwrap();
            let required = match response["kind"].as_str() {
                Some("observation") => {
                    let observation: crucible::node_scheduling::NativeSchedulingObservation =
                        serde_json::from_value(response["value"].clone()).unwrap();
                    let mut references = vec![observation.proof_ref];
                    references.extend(observation.bounds.into_iter().map(|bound| bound.proof_ref));
                    if let Some(progress) = observation.input_progress {
                        references.push(progress.proof_ref);
                    }
                    references
                }
                Some("input") => {
                    let acknowledgement: crucible::node_scheduling::NativeInputAcknowledgement =
                        serde_json::from_value(response["value"].clone()).unwrap();
                    vec![acknowledgement.proof_ref]
                }
                _ => Vec::new(),
            };
            for reference in required {
                let original = record
                    .evidence
                    .iter()
                    .find(|object| object.reference == reference)
                    .expect("native observe/stage proof body must survive source retirement");
                original.reference.verify(&original.bytes).unwrap();
            }
        }
    }

    for source in recorded.values() {
        let origin = &source.transcript().origin;
        let binding = origin
            .context
            .iter()
            .find(|object| object.reference == origin.source_binding)
            .unwrap();
        let binding: crucible_node_contract::NodeBinding =
            serde_json::from_slice(&binding.bytes).unwrap();
        let enrollment = origin
            .context
            .iter()
            .find(|object| object.reference == binding.authority.host_receipt)
            .expect("actual original enrolled receipt bytes must survive retirement");
        enrollment.reference.verify(&enrollment.bytes).unwrap();
        let manifest = origin
            .context
            .iter()
            .find(|object| object.reference.media_type == context_fragments::FRAGMENT_MEDIA_TYPE)
            .expect("the complete original source context exceeds one portable byte array");
        let original = context_fragments::reconstruct_source_object(
            manifest,
            &origin.context,
            64 * 1024 * 1024,
        )
        .unwrap();
        assert!(original.bytes.len() > 65_536);
        assert_eq!(
            original.reference.media_type,
            "application/vnd.crucible.installed-reference-recording-context+json"
        );
    }

    drop(worker);
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let deadline = Instant::now() + Duration::from_secs(10);
    while catalog.custody().reserved_worlds() != 0 {
        if let std::task::Poll::Ready(Err(error)) = catalog.custody().poll_reclamation(&mut context)
        {
            panic!("original native reclamation failed: {error:?}");
        }
        assert!(
            Instant::now() < deadline,
            "original native source remains alive"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(catalog);
    for source in recorded.values() {
        let reloaded = archive.load(source.reference()).unwrap();
        assert_eq!(reloaded.bytes(), source.bytes());
        assert_eq!(
            reloaded.transcript().origin.attempt,
            id(&format!("observed/{}", execution_text(execution)))
        );
    }
}
