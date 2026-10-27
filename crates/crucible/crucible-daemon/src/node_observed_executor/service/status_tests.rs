//! Checks original durable status while an actor command deliberately remains unconsumed.
//!
//! Synthetic campaign envelopes exercise lookup and publication consistency only;
//! they grant no native provider, prepared owner or backend qualification.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Synthetic original-ledger and queued-command assertions deliberately panic on mismatch.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_campaign::{
    CampaignCodecError, CampaignHash, ConfigurationArtifact, ConfigurationId, ScenarioArtifact,
    ScenarioDefId,
    executor_node_capabilities::{
        ExecutorNodeCapabilities, ExecutorNodeRoster, NodeExecutionGuarantee,
        NodeMaterializationStrategy, OwnerImplementationBinding,
    },
    observed_node_attempt::{
        ObservedAttemptAdmission, ObservedAttemptOutcome, ObservedAttemptRequest,
        ObservedAttemptResult, ObservedExecutionPermit, ObservedReservation,
    },
};
use crucible_store::content_store::{
    BlobHandle, DirectoryBlobBackend, DirectoryRefBackend, ObjectKind,
};

struct Fixture {
    service: NodeObservationService,
    receiver: Receiver<Command>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    request: ObservedAttemptRequest,
    permit: ObservedExecutionPermit,
    _directory: tempfile::TempDir,
}

struct ModelAdmission;

impl ObservedAttemptAdmission for ModelAdmission {
    fn authenticate(
        &self,
        request: &ObservedAttemptRequest,
        scenario: &ScenarioArtifact,
        configuration: &ConfigurationArtifact,
    ) -> Result<(), CampaignCodecError> {
        if request.capabilities().roster().scenario() != scenario.id()?
            || request.capabilities().roster().configuration() != configuration.id()?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "synthetic original artifact mismatch",
            });
        }
        Ok(())
    }
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "original-status-model",
            directory.path().join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let hash = |body: &[u8]| CampaignHash::derive("crucible.status-model.v1", body);
        let scenario = ScenarioDefId::from_hash(hash(b"scenario"));
        let scenario_id = repository
            .publish_scenario_artifact(scenario, 1, b"synthetic-source".to_vec())
            .unwrap();
        let configuration_id = repository
            .publish_configuration_artifact(
                scenario,
                scenario_id,
                ConfigurationId::from_hash(hash(b"configuration")),
                1,
                b"synthetic-configuration".to_vec(),
            )
            .unwrap();
        let owner = OwnerImplementationBinding::new(
            "synthetic-status-owner".into(),
            hash(b"no-native-profile"),
            BTreeSet::from(["model".into()]),
            NodeExecutionGuarantee::Nondeterministic,
        )
        .unwrap();
        let roster = ExecutorNodeRoster::new(
            scenario_id,
            configuration_id,
            hash(b"model-only-graph"),
            BTreeMap::from([("owner".into(), owner)]),
        )
        .unwrap();
        let capabilities = ExecutorNodeCapabilities::new(
            roster,
            BTreeSet::from([NodeMaterializationStrategy::FreshExecution]),
        )
        .unwrap();
        let inputs = put(&*blobs, b"synthetic-inputs");
        let request = ObservedAttemptRequest::new(
            ExecutionId::from_bytes([0x92; 16]).unwrap(),
            capabilities,
            inputs,
        )
        .unwrap();
        let ObservedReservation::Fresh(permit) = repository
            .reserve_observed_attempt("status-model", &request, &ModelAdmission)
            .unwrap()
        else {
            panic!("synthetic original did not reserve");
        };

        let (commands, receiver) = mpsc::sync_channel(1);
        let service = NodeObservationService {
            complete_scene_submitted: AtomicBool::new(false),
            repository,
            commands,
            stopping: Arc::new(AtomicBool::new(false)),
            roots: Arc::new(Mutex::new(BTreeSet::new())),
            retired: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "test-support")]
            funded_templates:
                crate::node_observed_executor::service::funded_template_observation::channel().1,
            preparations: None,
            capabilities: CapabilityPreparationLedger::new(blobs.clone(), refs.clone()).unwrap(),
            debug: DebugLedger::new(blobs.clone(), refs.clone()).unwrap(),
            preserving_debug: debug_preserving::Ledger::new(blobs.clone(), refs.clone()).unwrap(),
            root_preparations: RootPreparationLedger::new(blobs.clone(), refs).unwrap(),
        };
        let (reply, _response) = mpsc::sync_channel(1);
        service
            .send(Command::Compile {
                selections: Vec::new(),
                reply,
            })
            .unwrap();
        Self {
            service,
            receiver,
            blobs,
            request,
            permit,
            _directory: directory,
        }
    }

    fn require_unconsumed_command(&self) {
        assert!(matches!(
            self.receiver.try_recv().unwrap(),
            Command::Compile { .. }
        ));
        assert!(matches!(
            self.receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
}

fn put(blobs: &dyn ImmutableBlobBackend, bytes: &[u8]) -> ContentId {
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    blobs
        .put_if_absent(identity, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    identity
}

#[test]
fn reserved_and_quarantined_original_status_bypass_a_full_actor_queue() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.service.state(fixture.request.execution()).unwrap(),
        ObservedAttemptState::Reserved(fixture.request.clone())
    );

    let original = fixture
        .service
        .repository
        .quarantine_observed_attempt("status-model", &fixture.request, "original-model-refusal")
        .unwrap();
    assert_eq!(
        fixture.service.state(fixture.request.execution()).unwrap(),
        original
    );
    assert_eq!(
        fixture.service.state(fixture.request.execution()).unwrap(),
        original
    );
    fixture.require_unconsumed_command();
}

#[test]
fn completed_original_status_reads_current_publication_without_actor_polling() {
    let fixture = Fixture::new();
    let result = ObservedAttemptResult::new(
        fixture.request.clone(),
        put(&*fixture.blobs, b"incoming"),
        put(&*fixture.blobs, b"outgoing"),
        put(&*fixture.blobs, b"evidence"),
        ObservedAttemptOutcome::Completed,
    )
    .unwrap();
    fixture
        .service
        .repository
        .publish_observed_result(&fixture.permit, &result)
        .unwrap();

    assert_eq!(
        fixture.service.state(fixture.request.execution()).unwrap(),
        ObservedAttemptState::Completed(result)
    );
    fixture.require_unconsumed_command();
}

#[test]
fn complete_scene_submission_retries_bypass_an_unresolved_actor_command() {
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.service.prepare_complete_scene(),
        Err(NodeObservationServiceError::Capacity)
    ));
    assert!(
        !fixture
            .service
            .complete_scene_submitted
            .load(Ordering::Acquire)
    );
    fixture.require_unconsumed_command();

    let service = Arc::new(fixture.service);
    let original_service = Arc::clone(&service);
    let original = thread::spawn(move || original_service.prepare_complete_scene());
    let Command::CompleteScenePrepare { reply } = fixture
        .receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
    else {
        panic!("original preparation command missing");
    };

    // Withhold the original result, modeling an actor occupied by preparation.
    // A duplicate submission must refuse without consulting the actor queue.
    let retry_service = Arc::clone(&service);
    let (retry_reply, retry_result) = mpsc::sync_channel(1);
    let retry = thread::spawn(move || {
        retry_reply
            .send(retry_service.prepare_complete_scene())
            .unwrap();
    });
    let result = retry_result.recv_timeout(Duration::from_secs(1));
    reply
        .send(Err(refused("original model preparation refusal")))
        .unwrap();
    let queue_empty = matches!(fixture.receiver.try_recv(), Err(mpsc::TryRecvError::Empty));
    drop(fixture.receiver);
    retry.join().unwrap();

    assert!(matches!(
        result.unwrap(),
        Err(NodeObservationServiceError::Refused(_))
    ));
    assert!(queue_empty);
    assert!(matches!(
        original.join().unwrap(),
        Err(NodeObservationServiceError::Refused(_))
    ));
    assert!(matches!(
        service.prepare_complete_scene(),
        Err(NodeObservationServiceError::Refused(_))
    ));
}

#[test]
fn lost_complete_scene_reply_keeps_original_submission_spent() {
    let fixture = Fixture::new();
    fixture.require_unconsumed_command();
    let service = Arc::new(fixture.service);
    let original_service = Arc::clone(&service);
    let original = thread::spawn(move || original_service.prepare_complete_scene());
    let Command::CompleteScenePrepare { reply } = fixture
        .receiver
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
    else {
        panic!("original preparation command missing");
    };
    drop(reply);

    assert!(matches!(
        original.join().unwrap(),
        Err(NodeObservationServiceError::Unavailable)
    ));
    assert!(matches!(
        service.prepare_complete_scene(),
        Err(NodeObservationServiceError::Refused(_))
    ));
    assert!(matches!(
        fixture.receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    service.stopping.store(true, Ordering::Release);
    assert!(matches!(
        service.prepare_complete_scene(),
        Err(NodeObservationServiceError::Unavailable)
    ));
}
