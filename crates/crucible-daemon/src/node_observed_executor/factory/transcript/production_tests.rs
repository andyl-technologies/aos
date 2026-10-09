//! Actual installed conditional replay through the ordinary observation worker.
//!
//! The native recording test calls this only after original native reclamation
//! and deletion of its signed transcript archive namespace.

// crucible-lint: allow panic-shortcut -- The real observation worker must retain its original native source and durable outcome.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "production_faults.rs"]
mod faults;

pub(super) use faults::drive_store_failures;

use crate::supervision::ProcessDeadline;
use crucible_campaign::{
    CampaignRepository,
    executor_node_capabilities::NodeMaterializationStrategy,
    observed_node_attempt::{
        ConditionalReplayScope, ObservedAttemptAdmission, ObservedAttemptBackend,
        ObservedAttemptRequest, ObservedAttemptState, ObservedAttemptWorker,
    },
};

use super::*;

pub(super) fn drive_original_recipe(
    prepared: InstalledConditionalReplay,
    execution: ExecutionId,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    repository: Arc<CampaignRepository>,
) -> crucible_campaign::CampaignHash {
    assert_eq!(
        prepared.world.graph.world_repeatability(),
        crucible_node_contract::Repeatability::Nondeterministic
    );
    let context = super::super::super::backend::input_context_bytes(
        &prepared.world.scenario,
        &prepared.configuration,
    )
    .unwrap();
    let inputs = ContentId::for_bytes(ObjectKind::Trace, 1, &context);
    assert!(
        blobs
            .put_if_absent(inputs, &BlobHandle::from_bytes(context))
            .unwrap()
            .is_durable()
    );
    let publisher = StoredWorldActivationPublisher::new(
        blobs.clone(),
        refs,
        RefName::new(format!(
            "node-world-activations/production-original-replay-{}",
            execution_text(execution)
        ))
        .unwrap(),
    )
    .unwrap();
    let mut backend =
        NodeObservedBackend::from_conditional_replay(prepared, publisher, blobs, inputs, execution)
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
    assert!(request.conditional_scope().is_some());
    assert!(
        crucible_campaign::observed_node_attempt::ObservedAttemptRequest::new(
            execution,
            request.capabilities().clone(),
            request.inputs(),
        )
        .is_err()
    );
    assert_eq!(
        crucible_campaign::observed_node_attempt::ObservedAttemptRequest::from_canonical_bytes(
            &request.canonical_bytes(),
        )
        .unwrap(),
        request
    );
    assert_eq!(
        request.capabilities().materialization(),
        &std::collections::BTreeSet::from([
            NodeMaterializationStrategy::ConditionalTranscriptReplay
        ])
    );
    assert!(!request.capabilities().roster().is_repeatable());
    let admission = backend.admission().clone();
    let original = request.conditional_scope().unwrap();
    let changed = ConditionalReplayScope::new(
        original.original_world(),
        crucible_campaign::CampaignHash::parse(&"ff".repeat(32)).unwrap(),
        original.sources().clone(),
    )
    .unwrap();
    let counterfeit = ObservedAttemptRequest::conditional_replay(
        execution,
        request.capabilities().clone(),
        request.inputs(),
        changed,
    )
    .unwrap();
    // The public declaration is valid data; the installed recipe still refuses
    // its changed context before durable dispatch or any response consumption.
    assert!(backend.validate_realization(&counterfeit).is_err());
    assert!(
        admission
            .authenticate(
                &counterfeit,
                backend.scenario_artifact(),
                backend.configuration_artifact(),
            )
            .is_err()
    );

    let mut worker = ObservedAttemptWorker::new(repository, backend, 1).unwrap();
    worker
        .submit("installed-original-replay", &request, &admission)
        .unwrap();
    let deadline = ProcessDeadline::after(Duration::from_secs(10)).unwrap();
    loop {
        match worker.poll(execution).unwrap() {
            ObservedAttemptState::Completed(_) => break,
            ObservedAttemptState::Quarantined { reason, .. } => {
                panic!("installed original replay was contained: {reason}")
            }
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(!deadline.expired(), "installed original replay stalled");
    }
    request.plan_digest()
}

/// Supplies original signed source custody to the real owning service fixture.
pub(super) struct ServiceReplayFixture {
    pub(super) archive: crucible::node_adapters::transcript::TranscriptArchive,
    pub(super) sources: BTreeMap<Id, ContentRef>,
    pub(super) executable: PathBuf,
    pub(super) private_root: PathBuf,
    pub(super) configuration: NodeRunConfiguration,
    pub(super) repository: Arc<CampaignRepository>,
    pub(super) blobs: Arc<dyn ImmutableBlobBackend>,
    pub(super) refs: Arc<dyn MutableRefBackend>,
}

pub(super) fn drive_service_original(fixture: ServiceReplayFixture) {
    use super::super::super::{NodeObservationService, NodeObservationServiceConfig};

    let ServiceReplayFixture {
        archive,
        sources,
        executable,
        private_root,
        configuration,
        repository,
        blobs,
        refs,
    } = fixture;
    let service = NodeObservationService::start_with_transcript_archive(
        NodeObservationServiceConfig {
            installed_artifacts: Vec::new(),
            expected_device: measure_executable(&executable).unwrap(),
            device_executable: executable,
            socket_parent: private_root,
            control_timeout: Duration::from_secs(5),
            maximum_worlds: 2,
            maximum_pending_requests: 2,
        },
        archive,
        repository,
        blobs,
        refs,
    )
    .unwrap();
    let retention = service.retention_owner();
    let execution = ExecutionId::from_bytes([101; 16]).unwrap();
    let mut changed = configuration.clone();
    changed.horizon_ps = U64::new(100);
    assert!(
        service
            .submit_conditional_replay(
                "service-conditional-original".into(),
                execution,
                sources.clone(),
                canonical::canonical_json(&serde_json::to_value(&changed).unwrap()).unwrap(),
            )
            .is_err()
    );
    assert!(service.state(execution).is_err());

    let bytes = canonical::canonical_json(&serde_json::to_value(&configuration).unwrap()).unwrap();
    let original = service
        .submit_conditional_replay(
            "service-conditional-original".into(),
            execution,
            sources.clone(),
            bytes.clone(),
        )
        .unwrap();
    assert!(original.request().conditional_scope().is_some());
    assert!(!original.request().capabilities().roster().is_repeatable());
    let retry = service.submit_conditional_replay(
        "service-conditional-original".into(),
        execution,
        sources.clone(),
        bytes.clone(),
    );
    // A current owner returns its cached original state. If the worker already
    // retired, historical state is readable but cannot allocate a new cursor.
    if let Ok(retry) = retry {
        assert_eq!(retry.request(), original.request());
    }
    let deadline = ProcessDeadline::after(Duration::from_secs(10)).unwrap();
    loop {
        match service.state(execution).unwrap() {
            ObservedAttemptState::Completed(result) => {
                assert_eq!(result.request(), original.request());
                break;
            }
            ObservedAttemptState::Quarantined { reason, .. } => panic!("{reason}"),
            ObservedAttemptState::Reserved(_) => {}
        }
        assert!(!deadline.expired(), "conditional owning actor stalled");
        deadline.pause(Duration::from_millis(1));
    }
    drop(service);
    while !retention.is_retired() {
        assert!(
            !deadline.expired(),
            "conditional owning actor abandoned custody"
        );
        deadline.pause(Duration::from_millis(1));
    }
    assert!(retention.retention_roots().unwrap().is_empty());
}
