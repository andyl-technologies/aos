//! Exercises actual source-built native owners through durable observed storage.

use super::*;
use crate::node_scenario::{NodeRunConfiguration, NodeScenario};
use crucible_campaign::{
    CampaignRepository, ExecutionId,
    observed_node_attempt::{ObservedAttemptOutcome, ObservedAttemptState, ObservedAttemptWorker},
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, ObjectKind,
};
use crucible_node_contract::{Id, U64};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn selections() -> Vec<InstalledNodeSelection> {
    vec![
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
    ]
}

fn configuration() -> NodeRunConfiguration {
    NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(100),
        maximum_rounds: U64::new(8),
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_mixed_clock_and_reference_child_publish_observed_provenance_without_reexecution() {
    let executable = PathBuf::from(
        std::env::var("CRUCIBLE_REFERENCE_DEVICE")
            .expect("set CRUCIBLE_REFERENCE_DEVICE to the source-built companion"),
    );
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "native-observed",
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
    let selected = selections();
    let authored = catalog.scenario(&selected).unwrap();
    let bytes = authored.canonical_bytes().unwrap();
    let scenario = NodeScenario::from_json(&bytes).unwrap();
    assert_eq!(bytes, scenario.canonical_bytes().unwrap());
    let execution = ExecutionId::from_bytes([31; 16]).unwrap();
    let backend = catalog
        .prepare(
            &selected,
            scenario,
            configuration(),
            execution,
            blobs.clone(),
            refs.clone(),
        )
        .unwrap();
    let scenario = backend.scenario_artifact();
    let scenario_id = repository
        .publish_scenario_artifact(
            scenario.scenario(),
            scenario.payload_schema(),
            scenario.payload().to_vec(),
        )
        .unwrap();
    assert_eq!(scenario_id, scenario.id().unwrap());
    let configuration = backend.configuration_artifact();
    let configuration_id = repository
        .publish_configuration_artifact(
            configuration.scenario(),
            configuration.scenario_artifact(),
            configuration.configuration(),
            configuration.payload_schema(),
            configuration.payload().to_vec(),
        )
        .unwrap();
    assert_eq!(configuration_id, configuration.id().unwrap());
    let request = backend.request(execution).unwrap();
    assert!(!request.capabilities().roster().is_repeatable());
    assert_eq!(request.capabilities().roster().owners().len(), 2);
    let admission = backend.admission().clone();
    let mut worker = ObservedAttemptWorker::new(repository.clone(), backend, 1).unwrap();

    let _gc = repository.acquire_gc_exclusion_guard().unwrap();
    assert!(matches!(
        worker.submit("native-mixed", &request, &admission).unwrap(),
        ObservedAttemptState::Reserved(_)
    ));
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(result) => break result,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("actual native world quarantined: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(
            Instant::now() < deadline,
            "actual native world did not complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    };

    assert_eq!(result.outcome(), ObservedAttemptOutcome::Completed);
    assert_eq!(result.request(), &request);
    assert_eq!(result.incoming().kind(), ObjectKind::Trace);
    assert_eq!(result.outgoing().kind(), ObjectKind::Trace);
    let outgoing = blobs
        .read(result.outgoing(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&outgoing).unwrap();
    assert_eq!(events["events"].as_array().unwrap().len(), 3);
    assert_ne!(result.evidence(), request.inputs());
    let copied = blobs
        .read(result.evidence(), None)
        .unwrap()
        .read_all(16 * 1024 * 1024)
        .unwrap();
    let evidence: serde_json::Value = serde_json::from_slice(&copied).unwrap();
    let evidence = evidence["events"].as_array().unwrap();
    assert_eq!(evidence.len(), 3);
    for event in evidence {
        let objects = event["objects"].as_array().unwrap();
        assert!(
            !objects.is_empty(),
            "actual native receipt body was not retained"
        );
        for object in objects {
            let reference: crucible_node_contract::ContentRef =
                serde_json::from_value(object["reference"].clone()).unwrap();
            let bytes: crucible_node_contract::Bytes =
                serde_json::from_value(object["bytes"].clone()).unwrap();
            reference.verify(bytes.as_slice()).unwrap();
        }
    }
    assert_eq!(
        repository
            .load_observed_result(result.id().unwrap())
            .unwrap(),
        result
    );
    assert_eq!(
        worker.submit("native-mixed", &request, &admission).unwrap(),
        ObservedAttemptState::Completed(result.clone())
    );
    assert_eq!(
        worker.poll(execution).unwrap(),
        ObservedAttemptState::Completed(result)
    );
}

#[test]
fn node_configuration_strictly_rejects_unknown_editions_and_unbounded_rounds() {
    for bytes in [br#"{"format":"crucible.node-run-configuration","version":2,"horizon_ps":"100","maximum_rounds":"1"}"#.as_slice(),
        br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"100","maximum_rounds":"0"}"#,
        br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"100","maximum_rounds":"1","qemu":true}"#] {
        assert!(NodeRunConfiguration::from_json(bytes).is_err());
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn owning_actor_completes_original_world_and_authenticates_idempotent_retries() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "native-actor",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let expected = factory::measure_executable(&executable).unwrap();
    let catalog = InstalledNodeCatalog::new(
        executable.clone(),
        expected.clone(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let selected = selections();
    let scenario = catalog
        .scenario(&selected)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let configuration = serde_json::to_vec(&configuration()).unwrap();
    let execution = ExecutionId::from_bytes([32; 16]).unwrap();
    let service = NodeObservationService::start(
        NodeObservationServiceConfig {
            device_executable: executable,
            expected_device: expected,
            socket_parent: temporary.path().to_owned(),
            control_timeout: Duration::from_secs(5),
            maximum_worlds: 2,
            maximum_pending_requests: 4,
        },
        repository.clone(),
        blobs,
        refs,
    )
    .unwrap();

    service
        .submit(
            "native-actor".into(),
            execution,
            selected.clone(),
            scenario.clone(),
            configuration.clone(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let completed = loop {
        let state = service.state(execution).unwrap();
        if matches!(state, ObservedAttemptState::Completed(_)) {
            break state;
        }
        assert!(
            matches!(state, ObservedAttemptState::Reserved(_)),
            "unexpected native actor state: {state:?}"
        );
        assert!(Instant::now() < deadline, "native actor did not complete");
        std::thread::sleep(Duration::from_millis(1));
    };

    assert_eq!(
        service
            .submit(
                "native-actor".into(),
                execution,
                selected.clone(),
                scenario.clone(),
                configuration
            )
            .unwrap(),
        completed
    );
    let changed = br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"200","maximum_rounds":"8"}"#.to_vec();
    assert!(
        service
            .submit(
                "native-actor".into(),
                execution,
                selected,
                scenario,
                changed
            )
            .is_err()
    );
    assert_eq!(
        repository.observed_execution_state(execution).unwrap(),
        Some(completed)
    );
    let retention = service.retention_owner();
    drop(service);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !retention.is_retired() {
        assert!(
            Instant::now() < deadline,
            "native actor failed to retire after channel disconnection"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(retention.retention_roots().unwrap().is_empty());
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn dropping_submission_handle_keeps_independent_gc_owner_until_original_native_containment() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "native-drop",
        temporary.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let expected = factory::measure_executable(&executable).unwrap();
    let catalog = InstalledNodeCatalog::new(
        executable.clone(),
        expected.clone(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let selected = selections();
    let scenario = catalog
        .scenario(&selected)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let execution = ExecutionId::from_bytes([33; 16]).unwrap();
    let service = NodeObservationService::start(
        NodeObservationServiceConfig {
            device_executable: executable,
            expected_device: expected,
            socket_parent: temporary.path().to_owned(),
            control_timeout: Duration::from_secs(5),
            maximum_worlds: 2,
            maximum_pending_requests: 4,
        },
        repository.clone(),
        blobs,
        refs,
    )
    .unwrap();
    let retention = service.retention_owner();
    service
        .submit(
            "native-drop".into(),
            execution,
            selected,
            scenario,
            serde_json::to_vec(&configuration()).unwrap(),
        )
        .unwrap();
    drop(service);

    let deadline = Instant::now() + Duration::from_secs(20);
    while !retention.is_retired() {
        assert!(
            Instant::now() < deadline,
            "cleanup owner was lost with submission borrower"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(matches!(
        repository.observed_execution_state(execution).unwrap(),
        Some(ObservedAttemptState::Quarantined { .. })
    ));
    assert!(retention.retention_roots().unwrap().is_empty());
}

#[test]
fn activation_publisher_refuses_nondurable_ref_authority_before_native_activation() {
    use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend, RefName, StoreError};
    let publisher = StoredWorldActivationPublisher::new(
        Arc::new(MemoryBlobBackend::new("not-durable", 1024)),
        Arc::new(MemoryRefBackend::new()),
        RefName::new("node-world-activations/fixture").unwrap(),
    );
    assert!(matches!(publisher, Err(StoreError::Incompatible)));
}

#[path = "tests/connected.rs"]
mod connected;
