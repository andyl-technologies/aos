//! Contract tests for observed identities, retry ownership and evidence publication.
//!
//! Fixture adapters exercise host transaction semantics only. They do not qualify
//! any native provider, transcript replay, clock pacing or exact state capture.

// crucible-lint: allow panic-shortcut -- These observed node attempt tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible_cas::content_store::{
    BlobHandle, ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, MutableRefBackend,
};

use super::*;
use crate::executor_node_capabilities::{
    ExecutorNodeRoster, NodeExecutionGuarantee, NodeMaterializationStrategy,
    OwnerImplementationBinding,
};
use crate::{
    CampaignRecordKind, CampaignRepository, ConfigurationArtifact, ConfigurationId, ObjectEnvelope,
    ScenarioArtifact, ScenarioDefId,
};

fn hash(bytes: &[u8]) -> CampaignHash {
    CampaignHash::derive("crucible.observed-contract-test.v1", bytes)
}

fn execution(value: u8) -> ExecutionId {
    ExecutionId::from_bytes([value; 16]).unwrap()
}

struct Fixture {
    repository: Arc<CampaignRepository>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    request: ObservedAttemptRequest,
}

impl Fixture {
    fn memory() -> Self {
        Self::new(
            Arc::new(MemoryBlobBackend::new("observed-fixture", 16 * 1024 * 1024)),
            Arc::new(MemoryRefBackend::new()),
        )
    }

    fn new(blobs: Arc<dyn ImmutableBlobBackend>, refs: Arc<dyn MutableRefBackend>) -> Self {
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let scenario = ScenarioArtifact::new(
            ScenarioDefId::from_hash(hash(b"scenario")),
            1,
            b"verified-scenario-fixture".to_vec(),
        )
        .unwrap();
        let configuration = ConfigurationArtifact::new(
            scenario.scenario(),
            scenario.id().unwrap(),
            ConfigurationId::from_hash(hash(b"configuration")),
            1,
            b"verified-configuration-fixture".to_vec(),
        )
        .unwrap();
        let scenario_envelope = ObjectEnvelope::for_record(
            CampaignRecordKind::ScenarioArtifact,
            BTreeSet::new(),
            scenario.canonical_bytes(),
        )
        .unwrap();
        let configuration_envelope = ObjectEnvelope::for_record(
            CampaignRecordKind::ConfigurationArtifact,
            crate::object::content_children(configuration.content_children()).unwrap(),
            configuration.canonical_bytes(),
        )
        .unwrap();
        for envelope in [scenario_envelope, configuration_envelope] {
            blobs
                .put_if_absent(
                    envelope.content_id(),
                    &BlobHandle::from_bytes(envelope.canonical_bytes()),
                )
                .unwrap();
        }
        let inputs = put_leaf(&*blobs, ObjectKind::Trace, b"complete-input-fixture");
        let owner = OwnerImplementationBinding::new(
            "fixture-nondeterministic-provider".to_owned(),
            hash(b"complete-provider-profile"),
            BTreeSet::from(["machine".to_owned()]),
            NodeExecutionGuarantee::Nondeterministic,
        )
        .unwrap();
        let roster = ExecutorNodeRoster::new(
            scenario.id().unwrap(),
            configuration.id().unwrap(),
            hash(b"admitted-complete-graph"),
            BTreeMap::from([("execution-owner".to_owned(), owner)]),
        )
        .unwrap();
        let capabilities = ExecutorNodeCapabilities::new(
            roster,
            BTreeSet::from([NodeMaterializationStrategy::FreshExecution]),
        )
        .unwrap();
        let request = ObservedAttemptRequest::new(execution(1), capabilities, inputs).unwrap();
        Self {
            repository,
            blobs,
            refs,
            request,
        }
    }

    fn result(&self, request: &ObservedAttemptRequest, retain: bool) -> ObservedAttemptResult {
        let incoming = ContentId::for_bytes(ObjectKind::Trace, 1, b"actual-incoming");
        let outgoing = ContentId::for_bytes(ObjectKind::Trace, 1, b"actual-outgoing");
        let evidence = ContentId::for_bytes(ObjectKind::Trace, 1, b"actual-evidence");
        if retain {
            self.retain_result();
        }
        ObservedAttemptResult::new(
            request.clone(),
            incoming,
            outgoing,
            evidence,
            ObservedAttemptOutcome::Completed,
        )
        .unwrap()
    }

    fn retain_result(&self) {
        for bytes in [
            b"actual-incoming".as_slice(),
            b"actual-outgoing",
            b"actual-evidence",
        ] {
            put_leaf(&*self.blobs, ObjectKind::Trace, bytes);
        }
    }
}

fn put_leaf(blobs: &dyn ImmutableBlobBackend, kind: ObjectKind, bytes: &[u8]) -> ContentId {
    let id = ContentId::for_bytes(kind, 1, bytes);
    blobs
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    id
}

struct FixtureAdmission(bool);

impl ObservedAttemptAdmission for FixtureAdmission {
    fn authenticate(
        &self,
        request: &ObservedAttemptRequest,
        scenario: &ScenarioArtifact,
        configuration: &ConfigurationArtifact,
    ) -> Result<(), CampaignCodecError> {
        assert_eq!(
            request.capabilities().roster().scenario(),
            scenario.id().unwrap()
        );
        assert_eq!(
            request.capabilities().roster().configuration(),
            configuration.id().unwrap()
        );
        if self.0 {
            Ok(())
        } else {
            Err(CampaignCodecError::InvalidValue {
                reason: "fixture graph not authenticated",
            })
        }
    }
}

struct FixtureBackend {
    repository: Arc<CampaignRepository>,
    result: ObservedAttemptResult,
    starts: usize,
    polls: usize,
    fail_start: bool,
    fail_poll: bool,
    panic_start: bool,
    panic_poll: bool,
    panic_contain: bool,
    containments: usize,
    containment_pending: bool,
}

impl FixtureBackend {
    fn new(fixture: &Fixture, result: ObservedAttemptResult) -> Self {
        Self {
            repository: fixture.repository.clone(),
            result,
            starts: 0,
            polls: 0,
            fail_start: false,
            fail_poll: false,
            panic_start: false,
            panic_poll: false,
            panic_contain: false,
            containments: 0,
            containment_pending: false,
        }
    }
}

impl ObservedAttemptBackend for FixtureBackend {
    type Error = std::io::Error;

    fn contain(&mut self, _execution: ExecutionId) -> Result<bool, Self::Error> {
        self.containments += 1;
        if self.panic_contain {
            self.panic_contain = false;
            panic!("native containment callback failed");
        }
        if self.containment_pending {
            self.containment_pending = false;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn validate_realization(
        &mut self,
        request: &ObservedAttemptRequest,
    ) -> Result<(), Self::Error> {
        assert_eq!(request.capabilities(), self.result.request().capabilities());
        Ok(())
    }

    fn start(&mut self, request: &ObservedAttemptRequest) -> Result<(), Self::Error> {
        assert_eq!(
            self.repository
                .observed_attempt_state("world", request.execution())
                .unwrap(),
            Some(ObservedAttemptState::Reserved(request.clone()))
        );
        self.starts += 1;
        if self.panic_start {
            panic!("native startup callback failed");
        }
        if self.fail_start {
            Err(std::io::Error::other("uncertain startup"))
        } else {
            Ok(())
        }
    }

    fn poll(
        &mut self,
        execution: ExecutionId,
    ) -> Result<Option<ObservedAttemptResult>, Self::Error> {
        assert_eq!(execution, self.result.request().execution());
        self.polls += 1;
        if self.panic_poll {
            panic!("native poll callback failed");
        }
        if self.fail_poll {
            Err(std::io::Error::other("uncertain completion"))
        } else {
            Ok(Some(self.result.clone()))
        }
    }
}

#[test]
fn independent_observation_identity_does_not_collapse_into_planned_configuration() {
    let fixture = Fixture::memory();
    let second = ObservedAttemptRequest::new(
        execution(2),
        fixture.request.capabilities().clone(),
        fixture.request.inputs(),
    )
    .unwrap();

    assert_eq!(fixture.request.plan_digest(), second.plan_digest());
    assert_ne!(fixture.request.digest(), second.digest());
    assert_ne!(
        fixture.result(&fixture.request, true).id().unwrap(),
        fixture.result(&second, true).id().unwrap()
    );
    assert!(!fixture.request.capabilities().roster().is_repeatable());
}

#[test]
fn strict_observed_formats_refuse_version_aliases_and_trailing_bytes() {
    let fixture = Fixture::memory();
    let result = fixture.result(&fixture.request, true);
    assert_eq!(
        ObservedAttemptRequest::from_canonical_bytes(&fixture.request.canonical_bytes()).unwrap(),
        fixture.request
    );
    assert_eq!(
        ObservedAttemptResult::from_canonical_bytes(&result.canonical_bytes()).unwrap(),
        result
    );

    let mut unsupported = fixture.request.canonical_bytes();
    unsupported[0..4].copy_from_slice(&2_u32.to_le_bytes());
    assert!(ObservedAttemptRequest::from_canonical_bytes(&unsupported).is_err());
    let mut trailing = result.canonical_bytes();
    trailing.push(0);
    assert!(ObservedAttemptResult::from_canonical_bytes(&trailing).is_err());
    assert!(
        ObjectEnvelope::from_canonical_bytes(&result.envelope().unwrap().canonical_bytes())
            .is_err()
    );
}

#[test]
fn failed_admission_publishes_no_dispatch_and_nonce_reuse_refuses() {
    let fixture = Fixture::memory();
    assert!(
        fixture
            .repository
            .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(false))
            .is_err()
    );
    assert!(
        fixture
            .repository
            .observed_attempt_state("world", fixture.request.execution())
            .unwrap()
            .is_none()
    );

    assert!(matches!(
        fixture
            .repository
            .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true))
            .unwrap(),
        ObservedReservation::Fresh(_)
    ));
    let different_inputs = put_leaf(&*fixture.blobs, ObjectKind::Trace, b"different-inputs");
    let reused = ObservedAttemptRequest::new(
        fixture.request.execution(),
        fixture.request.capabilities().clone(),
        different_inputs,
    )
    .unwrap();
    assert!(
        fixture
            .repository
            .reserve_observed_attempt("world", &reused, &FixtureAdmission(true))
            .is_err()
    );
    assert!(matches!(
        fixture
            .repository
            .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true))
            .unwrap(),
        ObservedReservation::Existing(ObservedAttemptState::Reserved(_))
    ));
    assert!(
        fixture
            .repository
            .reserve_observed_attempt("nested/world", &fixture.request, &FixtureAdmission(true))
            .is_err()
    );
    assert!(
        fixture
            .repository
            .reserve_observed_attempt("other-world", &fixture.request, &FixtureAdmission(true))
            .is_err()
    );
}

#[test]
fn partial_global_nonce_reservation_cannot_mint_a_recovered_dispatch_permit() {
    use crucible_cas::content_store::RefName;
    let fixture = Fixture::memory();
    let reservation = ObservedDispatchReservation {
        ledger: "world".to_owned(),
        request: fixture.request.clone(),
    };
    for envelope in [
        fixture.request.envelope().unwrap(),
        reservation.envelope().unwrap(),
    ] {
        let id = envelope.content_id(ObjectKind::CampaignFact);
        fixture
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(envelope.canonical_bytes()))
            .unwrap();
    }
    let name = RefName::new(format!(
        "observed-execution-reservations/{}",
        execution_key(fixture.request.execution()).to_hex()
    ))
    .unwrap();
    fixture
        .refs
        .compare_exchange(
            &name,
            None,
            reservation
                .envelope()
                .unwrap()
                .content_id(ObjectKind::CampaignFact),
        )
        .unwrap();

    let recovered = fixture
        .repository
        .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true))
        .unwrap();
    assert!(matches!(
        recovered,
        ObservedReservation::Existing(ObservedAttemptState::Quarantined { .. })
    ));
}

#[test]
fn observed_cas_closure_retains_provenance_and_profiles_new_schemas() {
    use crucible_cas::content_store::{
        Reconstructibility, RefName, RetentionRole, SensitivityClass, StoreObjectProfiler,
    };
    let fixture = Fixture::memory();
    let result = fixture.result(&fixture.request, true);
    let permit = match fixture
        .repository
        .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true))
        .unwrap()
    {
        ObservedReservation::Fresh(permit) => permit,
        ObservedReservation::Existing(_) => panic!("expected first dispatch permit"),
    };
    fixture
        .repository
        .publish_observed_result(&permit, &result)
        .unwrap();
    assert_eq!(
        fixture
            .repository
            .load_observed_result(result.id().unwrap())
            .unwrap(),
        result
    );
    let head = fixture
        .refs
        .read_ref(&RefName::new("observed-attempt-ledgers/world").unwrap())
        .unwrap()
        .unwrap();
    let closure = fixture
        .repository
        .authenticated_closure_ids([head])
        .unwrap();

    for id in [
        head,
        result.id().unwrap().content_id(),
        fixture.request.content_id().unwrap(),
        fixture.request.inputs(),
        fixture
            .request
            .capabilities()
            .roster()
            .scenario()
            .content_id(),
        fixture
            .request
            .capabilities()
            .roster()
            .configuration()
            .content_id(),
        result.incoming(),
        result.outgoing(),
        result.evidence(),
    ] {
        assert!(closure.contains(&id), "missing retained child {id}");
    }
    let id = result.id().unwrap().content_id();
    let profile = crate::CampaignObjectProfiler
        .derive_profile(id, &fixture.blobs.read(id, None).unwrap())
        .unwrap();
    assert_eq!(profile.sensitivity(), SensitivityClass::Evidence);
    assert_eq!(profile.retention_role(), RetentionRole::Evidence);
    assert_eq!(profile.reconstructibility(), Reconstructibility::Canonical);

    let forged = ContentEnvelope::new(
        "crucible.observed-node-result",
        1,
        BTreeSet::new(),
        result.canonical_bytes(),
    )
    .unwrap();
    let forged_id = forged.content_id(ObjectKind::Observation);
    fixture
        .blobs
        .put_if_absent(forged_id, &BlobHandle::from_bytes(forged.canonical_bytes()))
        .unwrap();
    assert!(
        fixture
            .repository
            .authenticated_closure_ids([forged_id])
            .is_err()
    );
    assert!(
        crate::CampaignObjectProfiler
            .derive_profile(forged_id, &fixture.blobs.read(forged_id, None).unwrap())
            .is_err()
    );
}

#[test]
fn completed_observation_cannot_be_replaced_by_divergent_retry_bytes() {
    let fixture = Fixture::memory();
    let result = fixture.result(&fixture.request, true);
    let permit = match fixture
        .repository
        .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true))
        .unwrap()
    {
        ObservedReservation::Fresh(permit) => permit,
        ObservedReservation::Existing(_) => panic!("expected first dispatch permit"),
    };
    fixture
        .repository
        .publish_observed_result(&permit, &result)
        .unwrap();
    let divergent = ObservedAttemptResult::new(
        fixture.request.clone(),
        result.incoming(),
        result.outgoing(),
        result.evidence(),
        ObservedAttemptOutcome::Failed,
    )
    .unwrap();

    assert!(
        fixture
            .repository
            .publish_observed_result(&permit, &divergent)
            .is_err()
    );
    assert_eq!(
        fixture
            .repository
            .publish_observed_result(&permit, &result)
            .unwrap(),
        result
    );
    assert_eq!(
        fixture
            .repository
            .load_observed_result(result.id().unwrap())
            .unwrap(),
        result
    );
}

#[test]
fn same_planned_world_with_fresh_nonce_starts_an_independent_physical_sample() {
    let fixture = Fixture::memory();
    let second = ObservedAttemptRequest::new(
        execution(2),
        fixture.request.capabilities().clone(),
        fixture.request.inputs(),
    )
    .unwrap();
    let mut observed_ids = BTreeSet::new();
    for request in [&fixture.request, &second] {
        let result = fixture.result(request, true);
        let backend = FixtureBackend::new(&fixture, result);
        let mut worker =
            ObservedAttemptWorker::new(fixture.repository.clone(), backend, 1).unwrap();

        worker
            .submit("world", request, &FixtureAdmission(true))
            .unwrap();
        let ObservedAttemptState::Completed(result) = worker.poll(request.execution()).unwrap()
        else {
            panic!("sample did not complete");
        };
        observed_ids.insert(result.id().unwrap());
        assert_eq!(worker.backend().starts, 1);
        assert_eq!(worker.backend().polls, 1);
    }
    assert_eq!(observed_ids.len(), 2);
}

#[test]
fn result_publication_retries_original_bytes_without_native_reexecution() {
    let fixture = Fixture::memory();
    let result = fixture.result(&fixture.request, false);
    let backend = FixtureBackend::new(&fixture, result.clone());
    let mut worker = ObservedAttemptWorker::new(fixture.repository.clone(), backend, 1).unwrap();

    worker
        .submit("world", &fixture.request, &FixtureAdmission(true))
        .unwrap();
    assert!(worker.poll(fixture.request.execution()).is_err());
    assert_eq!(worker.backend().starts, 1);
    assert_eq!(worker.backend().polls, 1);
    assert_eq!(worker.active_executions(), 1);

    fixture.retain_result();
    assert_eq!(
        worker.poll(fixture.request.execution()).unwrap(),
        ObservedAttemptState::Completed(result.clone())
    );
    assert_eq!(
        worker
            .submit("world", &fixture.request, &FixtureAdmission(true))
            .unwrap(),
        ObservedAttemptState::Completed(result)
    );
    assert_eq!(worker.backend().starts, 1);
    assert_eq!(worker.backend().polls, 1);
    assert_eq!(worker.active_executions(), 0);
    assert!(matches!(
        worker.poll(fixture.request.execution()).unwrap(),
        ObservedAttemptState::Completed(_)
    ));
    assert_eq!(worker.backend().polls, 1);
}

#[test]
fn uncertain_start_and_poll_are_quarantined_without_redispatch() {
    for fail_start in [true, false] {
        let fixture = Fixture::memory();
        let mut backend = FixtureBackend::new(&fixture, fixture.result(&fixture.request, true));
        backend.fail_start = fail_start;
        backend.fail_poll = !fail_start;
        let mut worker =
            ObservedAttemptWorker::new(fixture.repository.clone(), backend, 1).unwrap();

        let submitted = worker.submit("world", &fixture.request, &FixtureAdmission(true));
        if fail_start {
            assert!(submitted.is_err());
        } else {
            submitted.unwrap();
            assert!(worker.poll(fixture.request.execution()).is_err());
        }
        let state = worker
            .submit("world", &fixture.request, &FixtureAdmission(true))
            .unwrap();
        assert!(matches!(state, ObservedAttemptState::Quarantined { .. }));
        assert_eq!(worker.backend().starts, 1);
        assert_eq!(worker.backend().polls, usize::from(!fail_start));
    }
}

#[test]
fn restarted_worker_cannot_reacquire_reserved_dispatch_authority() {
    let fixture = Fixture::memory();
    let result = fixture.result(&fixture.request, true);
    let mut prior = ObservedAttemptWorker::new(
        fixture.repository.clone(),
        FixtureBackend::new(&fixture, result.clone()),
        1,
    )
    .unwrap();
    prior
        .submit("world", &fixture.request, &FixtureAdmission(true))
        .unwrap();
    drop(prior);

    let restarted_repository = Arc::new(CampaignRepository::new(
        fixture.blobs.clone(),
        fixture.refs.clone(),
    ));
    let mut restarted = ObservedAttemptWorker::new(
        restarted_repository,
        FixtureBackend::new(&fixture, result),
        1,
    )
    .unwrap();
    assert!(matches!(
        restarted
            .submit("world", &fixture.request, &FixtureAdmission(true))
            .unwrap(),
        ObservedAttemptState::Reserved(_)
    ));
    assert_eq!(restarted.backend().starts, 0);
    assert_eq!(restarted.backend().polls, 0);
    assert!(matches!(
        restarted.poll(fixture.request.execution()),
        Err(ObservedWorkerError::UnknownExecution)
    ));
}

#[test]
fn cancellation_contains_original_native_world_without_polling_or_restarting_it() {
    let fixture = Fixture::memory();
    let mut backend = FixtureBackend::new(&fixture, fixture.result(&fixture.request, true));
    backend.containment_pending = true;
    let mut worker = ObservedAttemptWorker::new(fixture.repository.clone(), backend, 1).unwrap();
    worker
        .submit("world", &fixture.request, &FixtureAdmission(true))
        .unwrap();

    let state = worker.cancel(fixture.request.execution()).unwrap();

    assert!(
        matches!(state, ObservedAttemptState::Quarantined { ref reason, .. }
        if reason == "executor-cancelled")
    );
    assert_eq!(worker.backend().starts, 1);
    assert_eq!(worker.backend().polls, 0);
    assert_eq!(worker.backend().containments, 1);
    assert_eq!(worker.active_executions(), 1);
    assert_eq!(worker.cancel(fixture.request.execution()).unwrap(), state);
    assert_eq!(worker.backend().starts, 1);
    assert_eq!(worker.backend().polls, 0);
    assert_eq!(worker.backend().containments, 2);
    assert_eq!(worker.active_executions(), 0);
    assert_eq!(worker.cancel(fixture.request.execution()).unwrap(), state);
}

#[test]
fn quarantined_native_ownership_remains_active_until_complete_containment() {
    let fixture = Fixture::memory();
    let mut backend = FixtureBackend::new(&fixture, fixture.result(&fixture.request, true));
    backend.fail_start = true;
    backend.containment_pending = true;
    let mut worker = ObservedAttemptWorker::new(fixture.repository.clone(), backend, 1).unwrap();

    assert!(
        worker
            .submit("world", &fixture.request, &FixtureAdmission(true))
            .is_err()
    );
    assert_eq!(worker.active_executions(), 1);
    assert_eq!(worker.backend().containments, 1);
    let second = ObservedAttemptRequest::new(
        execution(2),
        fixture.request.capabilities().clone(),
        fixture.request.inputs(),
    )
    .unwrap();
    assert!(matches!(
        worker.submit("world", &second, &FixtureAdmission(true)),
        Err(ObservedWorkerError::ContainmentPending)
    ));
    assert!(matches!(
        worker.poll(fixture.request.execution()).unwrap(),
        ObservedAttemptState::Quarantined { .. }
    ));
    assert_eq!(worker.active_executions(), 0);
    assert_eq!(worker.backend().containments, 2);
    assert_eq!(worker.backend().starts, 1);
    assert_eq!(worker.backend().polls, 0);
}

#[test]
fn sqlite_and_directory_reopen_preserve_original_observed_identity() {
    use crucible_cas::content_store::{DirectoryRefBackend, SqliteBlobBackend};
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(
        SqliteBlobBackend::open("observed-persistent", directory.path().join("blobs")).unwrap(),
    );
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let fixture = Fixture::new(blobs, refs);
    let result = fixture.result(&fixture.request, true);
    let permit = match fixture
        .repository
        .reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true))
        .unwrap()
    {
        ObservedReservation::Fresh(permit) => permit,
        ObservedReservation::Existing(_) => panic!("first request did not reserve dispatch"),
    };
    fixture
        .repository
        .publish_observed_result(&permit, &result)
        .unwrap();

    let reopened = CampaignRepository::new(
        Arc::new(
            SqliteBlobBackend::open("observed-persistent", directory.path().join("blobs")).unwrap(),
        ),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    );
    assert_eq!(
        reopened
            .observed_attempt_state("world", fixture.request.execution())
            .unwrap(),
        Some(ObservedAttemptState::Completed(result.clone()))
    );
    assert!(
        matches!(reopened.reserve_observed_attempt("world", &fixture.request, &FixtureAdmission(true)).unwrap(), ObservedReservation::Existing(ObservedAttemptState::Completed(original)) if original.id().unwrap() == result.id().unwrap())
    );
}

#[test]
fn native_callback_unwind_retains_original_permit_for_quarantine_without_redispatch() {
    for at_start in [true, false] {
        let fixture = Fixture::memory();
        let mut backend = FixtureBackend::new(&fixture, fixture.result(&fixture.request, true));
        backend.panic_start = at_start;
        backend.panic_poll = !at_start;
        backend.panic_contain = true;
        let mut worker =
            ObservedAttemptWorker::new(fixture.repository.clone(), backend, 1).unwrap();
        let admission = FixtureAdmission(true);
        if at_start {
            assert!(
                worker
                    .submit("world", &fixture.request, &admission)
                    .is_err()
            );
        } else {
            worker
                .submit("world", &fixture.request, &admission)
                .unwrap();
            assert!(worker.poll(fixture.request.execution()).is_err());
        }
        assert_eq!(worker.active_executions(), 1);
        assert!(worker.poll(fixture.request.execution()).is_err());
        assert_eq!(worker.active_executions(), 1);
        let state = worker.poll(fixture.request.execution()).unwrap();
        assert!(matches!(state, ObservedAttemptState::Quarantined { .. }));
        assert_eq!(worker.active_executions(), 0);
        assert_eq!(worker.backend().starts, 1);
        assert_eq!(worker.backend().polls, usize::from(!at_start));
        assert_eq!(worker.backend().containments, 2);
        worker
            .submit("world", &fixture.request, &admission)
            .unwrap();
        assert_eq!(worker.backend().starts, 1);
    }
}
