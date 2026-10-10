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
use crucible_cas::content_store::{
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
            repository,
            commands,
            stopping: Arc::new(AtomicBool::new(false)),
            roots: Arc::new(Mutex::new(BTreeSet::new())),
            retired: Arc::new(AtomicBool::new(false)),
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
