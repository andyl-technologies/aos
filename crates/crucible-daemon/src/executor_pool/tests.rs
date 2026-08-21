//! Conformance tests for fixed local executor worker ownership.

#![allow(clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crucible_campaign::{
    AssignmentId, Attempt, AttemptId, AttemptResourceLimits, AttemptStart, BooleanDomain,
    BranchBudget, BranchPath, BranchPathSegment, BranchRequest, BranchRequestCause,
    CampaignCommandId, CampaignControlAction, CampaignExecutorDriver, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignHash, CampaignLineage, CampaignLineageId, CampaignMode,
    CampaignPolicy, CampaignRepository, CampaignSeed, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CandidateSource, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ConfigurationArtifact, ConfigurationId,
    ControlRequest, CoverageProjection, DaemonEpoch, ExactRational, ExecutionRetentionIntent,
    ExecutorCapabilitySet, ExecutorClient, ExecutorCompatibilityProfile, ExecutorControlService,
    ExecutorDescription, ExecutorMaterializationCapability, ExecutorRejection, ExecutorService,
    ExecutorStatusService, ExplorerPolicy, FairnessPolicy, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, MeasurementSet, Observation, ObservationCandidate,
    ProgressiveWideningPolicy, PropertyVerdictSet, Proposal, PuctPolicy, RetentionPolicy,
    ScenarioDefId, SelectableDeclaration, Selection, SelectionOrigin, StopCondition, StopOutcome,
    SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse, WorkerSlotId,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

use super::*;
use crate::{
    AllowAllAttemptAdmission, AttemptAdmissionValidator, AttemptExecutionContext,
    AttemptExecutionInput, AttemptExecutionModel, AttemptWorkResult, AttemptWorkerFailure,
    ExecutorCapacity, MemoryAssignmentLedger, RepositoryAttemptAdmission, RepositoryAttemptWorker,
};

struct BlockingAdmission {
    state: Arc<(Mutex<(bool, bool)>, Condvar)>,
}

impl AttemptAdmissionValidator for BlockingAdmission {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        let (state, changed) = self.state.as_ref();
        let mut state = state.lock().map_err(|_| ExecutorRejection::Unauthorized)?;
        state.0 = true;
        changed.notify_all();
        while !state.1 {
            state = changed
                .wait(state)
                .map_err(|_| ExecutorRejection::Unauthorized)?;
        }
        Ok(())
    }
}

struct SequencedFailureWorker {
    calls: Arc<AtomicUsize>,
}

impl LocalAttemptWorker for SequencedFailureWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        let result = if call == 0 {
            Err(AttemptWorkerFailure::Retryable("retry once"))
        } else {
            Err(AttemptWorkerFailure::Terminal("stop"))
        };
        AttemptWorkResult::new(queued, result)
    }
}

struct BlockingWorker {
    entered: Arc<AtomicUsize>,
}

impl LocalAttemptWorker for BlockingWorker {
    type Error = &'static str;

    fn execute(&mut self, queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        self.entered.store(1, Ordering::Release);
        while !queued.cancellation().is_canceled() {
            thread::sleep(Duration::from_millis(1));
        }
        AttemptWorkResult::new(
            queued,
            Err(AttemptWorkerFailure::Canceled("shutdown cancellation")),
        )
    }
}

struct PanickingWorker;

impl LocalAttemptWorker for PanickingWorker {
    type Error = &'static str;

    fn execute(&mut self, _queued: QueuedAttempt) -> AttemptWorkResult<Self::Error> {
        panic!("intentional worker panic")
    }
}

struct CandidateModel {
    candidate: ObservationCandidate,
    calls: Arc<AtomicUsize>,
}

struct CountingExecutorService<S> {
    inner: S,
    submits: Arc<AtomicUsize>,
    status_reads: Arc<AtomicUsize>,
}

impl<S: ExecutorService> ExecutorService for CountingExecutorService<S> {
    type Error = S::Error;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        self.submits.fetch_add(1, Ordering::AcqRel);
        self.inner.submit_attempt(request)
    }
}

impl<S: ExecutorStatusService> ExecutorStatusService for CountingExecutorService<S> {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        self.status_reads.fetch_add(1, Ordering::AcqRel);
        self.inner.get_attempt_execution(request)
    }
}

impl<S: ExecutorControlService> ExecutorControlService for CountingExecutorService<S> {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        self.inner.checkpoint_attempt_execution(request)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        self.inner.cancel_attempt_execution(request)
    }
}

impl AttemptExecutionModel for CandidateModel {
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        _input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>> {
        assert!(!context.cancellation().is_canceled());
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.candidate.clone())
    }
}

#[test]
fn fixed_pool_requeues_once_then_stops_without_capacity_growth() {
    let epoch = DaemonEpoch::from_bytes([0x31; 16]).expect("epoch");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::clone(&calls),
        }],
    );
    let mut client = ExecutorClient::new(pool.service());
    assert!(matches!(
        client
            .submit_attempt(&request(epoch, 0x41))
            .expect("accepted request")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    wait_until(Duration::from_secs(2), || {
        pool.service()
            .report()
            .is_ok_and(|report| report.active() == 0)
    });
    let report = pool.service().report().expect("pool report");
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(report.executions(), 2);
    assert_eq!(report.retry_requeues(), 1);
    assert_eq!(report.terminal_stops(), 1);
    assert_eq!(report.active(), 0);
    assert_eq!(pool.shutdown_and_join().expect("clean shutdown"), report);
}

#[test]
fn blocking_worker_does_not_block_service_and_shutdown_cancels_it() {
    let epoch = DaemonEpoch::from_bytes([0x32; 16]).expect("epoch");
    let entered = Arc::new(AtomicUsize::new(0));
    let pool = pool(
        epoch,
        vec![BlockingWorker {
            entered: Arc::clone(&entered),
        }],
    );
    let mut service = pool.service();
    let accepted = service
        .submit_attempt(&request(epoch, 0x42))
        .expect("accepted request");
    let SubmitAttemptDisposition::Accepted { .. } = accepted.disposition() else {
        panic!("request should be accepted")
    };
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });

    let started = Instant::now();
    let second = service
        .submit_attempt(&request(epoch, 0x43))
        .expect("bounded capacity response");
    assert!(matches!(
        second.disposition(),
        SubmitAttemptDisposition::Rejected { .. }
    ));
    assert!(started.elapsed() < Duration::from_millis(250));

    pool.request_shutdown();
    let report = pool.shutdown_and_join().expect("shutdown joins worker");
    assert_eq!(report.active(), 0);
    assert_eq!(report.terminal_stops(), 1);
}

#[test]
fn shutdown_drains_accepted_work_that_never_started() {
    let epoch = DaemonEpoch::from_bytes([0x36; 16]).expect("epoch");
    let entered = Arc::new(AtomicUsize::new(0));
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(2, 2, 4096, 8192, 64).expect("two-slot capacity"),
    );
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description_with_slots(epoch, 2))
            .expect("two-slot capability");
    let pool = LocalExecutorWorkerPool::start(
        capability,
        store(),
        vec![BlockingWorker {
            entered: Arc::clone(&entered),
        }],
    )
    .expect("one worker with two admitted slots");
    let mut service = pool.service();
    service
        .submit_attempt(&request(epoch, 0x47))
        .expect("first request");
    wait_until(Duration::from_secs(2), || {
        entered.load(Ordering::Acquire) == 1
    });
    assert!(matches!(
        service
            .submit_attempt(&request(epoch, 0x48))
            .expect("second queued request")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    let before = service.report().expect("pre-shutdown report");
    assert_eq!(before.active(), 2);
    assert_eq!(before.queued(), 1);

    let report = pool.shutdown_and_join().expect("drained shutdown");
    assert_eq!(report.active(), 0);
    assert_eq!(report.queued(), 0);
    assert_eq!(report.executions(), 1);
    assert_eq!(report.terminal_stops(), 2);
}

#[test]
fn worker_panic_fails_closed_and_releases_exact_reservation() {
    let epoch = DaemonEpoch::from_bytes([0x33; 16]).expect("epoch");
    let pool = pool(epoch, vec![PanickingWorker]);
    let mut service = pool.service();
    service
        .submit_attempt(&request(epoch, 0x44))
        .expect("accepted request");
    wait_until(Duration::from_secs(2), || {
        matches!(
            service.submit_attempt(&request(epoch, 0x45)),
            Err(LocalExecutorPoolServiceError::WorkerPanicked)
        )
    });
    wait_until(Duration::from_secs(2), || {
        pool.service
            .shared
            .executor
            .lock()
            .is_ok_and(|executor| executor.supervisor().active_count() == 0)
    });
    assert!(matches!(
        pool.shutdown_and_join(),
        Err(LocalExecutorPoolShutdownError::WorkerPanicked)
    ));
}

#[test]
fn worker_count_is_bounded_by_static_and_supervisor_capacity() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let store = store();
    assert!(matches!(
        LocalExecutorWorkerPool::<MemoryAssignmentLedger, AllowAllAttemptAdmission>::start::<
            SequencedFailureWorker,
        >(capability(epoch), store.clone(), Vec::new()),
        Err(LocalExecutorPoolConfigError::ZeroWorkers)
    ));
    let workers = (0..2)
        .map(|_| SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .collect();
    assert!(matches!(
        LocalExecutorWorkerPool::start(capability(epoch), store, workers),
        Err(LocalExecutorPoolConfigError::WorkerCountExceedsSlots)
    ));
}

#[test]
fn repository_admission_does_not_hold_supervisor_actor_ownership() {
    let epoch = DaemonEpoch::from_bytes([0x35; 16]).expect("epoch");
    let state = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        BlockingAdmission {
            state: Arc::clone(&state),
        },
        epoch,
        capacity(),
    );
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description(epoch)).expect("capability");
    let pool = LocalExecutorWorkerPool::start(
        capability,
        store(),
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    )
    .expect("worker pool");
    let mut submitting = pool.service();
    let submit = thread::spawn(move || submitting.submit_attempt(&request(epoch, 0x46)));

    let (admission_state, changed) = state.as_ref();
    let mut admission_state = admission_state.lock().expect("admission state");
    while !admission_state.0 {
        admission_state = changed.wait(admission_state).expect("admission wake");
    }
    let started = Instant::now();
    assert_eq!(
        pool.service().report().expect("responsive report").active(),
        0
    );
    pool.request_shutdown();
    assert!(started.elapsed() < Duration::from_millis(250));
    admission_state.1 = true;
    changed.notify_all();
    drop(admission_state);

    assert!(matches!(
        submit.join().expect("submit thread"),
        Err(LocalExecutorPoolServiceError::ShuttingDown)
    ));
    let report = pool.shutdown_and_join().expect("clean shutdown");
    assert_eq!(report.active(), 0);
    assert_eq!(report.executions(), 0);
}

#[test]
fn campaign_driver_pool_flight_incorporates_one_execution_without_submit_polling() {
    let blobs = Arc::new(MemoryBlobBackend::new("executor-flight", 64 * 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
    let (lineage, _policy, request, admitted, candidate) =
        campaign_attempt_fixture(&repository, "executor-flight");
    let resume = ControlRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.executor-flight.resume.v1",
            b"resume",
        )),
        expected_snapshot: admitted.new_snapshot,
        action: CampaignControlAction::Resume,
    };
    repository
        .apply_control("executor-flight", &resume)
        .expect("resume campaign");

    let epoch = DaemonEpoch::from_bytes([0x81; 16]).expect("daemon epoch");
    let resources = AttemptResourceLimits::new(2, 512 * 1024 * 1024, 0, 50_000).expect("resources");
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        RepositoryAttemptAdmission::new(Arc::clone(&repository), profile.clone()),
        epoch,
        ExecutorCapacity::new(1, 2, 512 * 1024 * 1024, 0, 50_000).expect("capacity"),
    );
    let capabilities = ExecutorCapabilitySet::new(
        profile,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        1,
        resources,
        BTreeSet::from([CampaignHash::derive(
            "crucible.test.executor-flight.namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    let description = ExecutorDescription::new(epoch, capabilities).expect("description");
    let capability =
        LocalExecutorCapabilityService::new(supervisor, description).expect("capability service");
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = LocalExecutorWorkerPool::start(
        capability,
        CampaignExecutorStore::new(Arc::clone(&repository)),
        vec![RepositoryAttemptWorker::new(
            CampaignExecutorStore::new(Arc::clone(&repository)),
            CandidateModel {
                candidate: candidate.clone(),
                calls: Arc::clone(&calls),
            },
        )],
    )
    .expect("worker pool");
    let submits = Arc::new(AtomicUsize::new(0));
    let status_reads = Arc::new(AtomicUsize::new(0));
    let mut driver = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        ExecutorClient::new(CountingExecutorService {
            inner: pool.service(),
            submits: Arc::clone(&submits),
            status_reads: Arc::clone(&status_reads),
        }),
        epoch,
        1,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
        10_000,
    )
    .expect("campaign executor driver");

    let first = driver
        .step("executor-flight", WorkerSlotId::new(0))
        .expect("submit attempt");
    assert!(matches!(
        first,
        CampaignExecutorStepOutcome::Running {
            attempt,
            newly_accepted: true,
            ..
        } if attempt == admitted.attempt
    ));
    let deadline = Instant::now() + Duration::from_secs(2);
    let incorporated = loop {
        match driver
            .step("executor-flight", WorkerSlotId::new(0))
            .expect("poll execution")
        {
            CampaignExecutorStepOutcome::Running {
                newly_accepted: false,
                ..
            } => {
                assert!(Instant::now() < deadline, "execution did not complete");
                thread::sleep(Duration::from_millis(1));
            }
            CampaignExecutorStepOutcome::Incorporated(result) => break result,
            outcome => panic!("unexpected flight outcome: {outcome:?}"),
        }
    };
    assert_eq!(
        incorporated.observation,
        candidate.observation().id().expect("observation id")
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(submits.load(Ordering::Acquire), 1);
    assert!(status_reads.load(Ordering::Acquire) >= 1);
    assert_eq!(driver.reservation_count(), 0);
    assert_eq!(
        repository
            .project_claimable_attempts("executor-flight", None, 10_000)
            .expect("post-flight projection")
            .attempts(),
        &[]
    );
    drop(driver);
    let report = pool.shutdown_and_join().expect("clean pool shutdown");
    assert_eq!(report.executions(), 1);
    assert_eq!(report.reconciled(), 1);
    assert_eq!(report.active(), 0);

    let restarted = CampaignRepository::new(blobs, refs);
    let head = restarted.head("executor-flight").expect("restart head");
    assert_eq!(head.snapshot_id(), incorporated.new_snapshot);
    assert_eq!(request.stop(), &StopCondition::NextChoice);
}

fn campaign_attempt_fixture(
    repository: &CampaignRepository,
    name: &str,
) -> (
    CampaignLineage,
    CampaignPolicy,
    BranchRequest,
    crucible_campaign::AttemptAdmissionResult,
    ObservationCandidate,
) {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.scenario.v1",
        name.as_bytes(),
    ));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.genesis.v1",
        name.as_bytes(),
    ));
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");
    let created = repository
        .create(name, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.executor-flight",
        ChoiceSource::Workload {
            producer: String::from("executor-flight"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("executor-flight")]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("crucible.test.executor-flight.scheduler.v1", b"s"),
            producer: CampaignHash::derive("crucible.test.executor-flight.producer.v1", b"p"),
        },
        "executor-flight",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let discovered = repository
        .discover_operator_choice_opportunity(
            name,
            created.snapshot_id(),
            genesis_content,
            opportunity.id().expect("opportunity id"),
        )
        .expect("discover opportunity");
    let request = BranchRequest::new(
        opportunity.branch_point_id(genesis),
        genesis_content,
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.executor-flight.branch.v1",
            b"branch",
        ))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request");
    let requested = repository
        .submit_operator_branch_request(name, discovered.new_snapshot, &request)
        .expect("submit branch request");
    let request_head = repository.head(name).expect("request head");
    let proposal = Proposal::new(
        request.branch_point(),
        request.id().expect("request id"),
        request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        None,
        1,
        request_head
            .snapshot()
            .planning_view()
            .id()
            .expect("planning view"),
    )
    .expect("proposal");
    let proposed = repository
        .issue_proposal(name, requested.new_snapshot, &proposal)
        .expect("issue proposal");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )
    .expect("selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])
        .expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id().expect("selection id"),
        },
        path.id().expect("path id"),
        request.stop().clone(),
    )
    .expect("attempt");
    let admitted = repository
        .admit_proposal(
            name,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit proposal");

    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-flight.child.v1",
        name.as_bytes(),
    ));
    let child_artifact =
        ConfigurationArtifact::new(scenario, scenario_content, child, 1, b"child".to_vec())
            .expect("child artifact");
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("properties");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_artifact.id().expect("child artifact id"),
        path.id().expect("path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements.id().expect("measurement id"),
        properties.id().expect("properties id"),
        coverage.id().expect("coverage id"),
        BTreeSet::from([opportunity.id().expect("opportunity id")]),
    )
    .expect("observation");
    let candidate = ObservationCandidate::new(
        child_artifact,
        measurements,
        properties,
        coverage,
        vec![opportunity],
        observation,
    )
    .expect("observation candidate");
    (lineage, policy, request, admitted, candidate)
}

fn pool<W>(
    epoch: DaemonEpoch,
    workers: Vec<W>,
) -> LocalExecutorWorkerPool<MemoryAssignmentLedger, AllowAllAttemptAdmission>
where
    W: LocalAttemptWorker + Send + 'static,
{
    LocalExecutorWorkerPool::start(capability(epoch), store(), workers).expect("worker pool")
}

fn capability(
    epoch: DaemonEpoch,
) -> LocalExecutorCapabilityService<MemoryAssignmentLedger, AllowAllAttemptAdmission> {
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity(),
    );
    LocalExecutorCapabilityService::new(supervisor, description(epoch))
        .expect("matching capability service")
}

fn store() -> CampaignExecutorStore {
    CampaignExecutorStore::new(Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("executor-pool", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    )))
}

fn capacity() -> ExecutorCapacity {
    ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity")
}

fn description(epoch: DaemonEpoch) -> ExecutorDescription {
    description_with_slots(epoch, 1)
}

fn description_with_slots(epoch: DaemonEpoch, maximum_slots: u32) -> ExecutorDescription {
    let compatibility = ExecutorCompatibilityProfile::new(
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("compatibility");
    let capabilities = ExecutorCapabilitySet::new(
        compatibility,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        maximum_slots,
        AttemptResourceLimits::new(2, 4096, 8192, 64).expect("resource ceiling"),
        BTreeSet::from([CampaignHash::derive(
            "crucible.test.executor-pool-namespace.v1",
            b"local",
        )]),
    )
    .expect("capabilities");
    ExecutorDescription::new(epoch, capabilities).expect("description")
}

fn request(epoch: DaemonEpoch, byte: u8) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([byte; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            0x51,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::Discard,
    )
    .expect("request")
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", format!("{byte:02x}").repeat(32))
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(1));
    }
}
