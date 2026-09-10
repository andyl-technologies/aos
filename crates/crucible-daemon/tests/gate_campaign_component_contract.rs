//! Same-campaign direct and split-process component-contract acceptance fixture.

// crucible-lint: allow panic-shortcut -- process fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]
// crucible-lint: allow clippy-disallowed-method -- monotonic time bounds only the child-process protocol wait.
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crucible_campaign::{
    ApplyCampaignCommandRequest, AssignmentId, Attempt, AttemptId, AttemptResourceLimits,
    AttemptStart, BooleanDomain, BranchBudget, BranchPath, BranchPathSegment, BranchPointId,
    BranchRequest, BranchRequestCause, BudgetGrant, CampaignAuthorizationError, CampaignClient,
    CampaignCommandId, CampaignControlAction, CampaignExecutorDriver, CampaignExecutorStepOutcome,
    CampaignExecutorStore, CampaignHash, CampaignLineage, CampaignLineageId, CampaignMode,
    CampaignName, CampaignPolicy, CampaignPrincipal, CampaignPrincipalAuthorizer,
    CampaignRepository, CampaignSeed, CampaignServiceOperation, CandidateSource,
    ChoiceClassContext, ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity,
    ChoiceOpportunityId, ChoiceSource, ChoiceValue, ControlRequest, CoverageProjection,
    CreateCampaignRequest, DaemonEpoch, ExecutionId, ExecutionRetentionIntent,
    ExecutorCapabilityService, ExecutorCapacityReport, ExecutorClient,
    ExecutorCompatibilityProfile, ExecutorControlService, ExecutorDescription,
    ExecutorMaterializationCapability, ExecutorRejection, ExecutorResumeService, ExecutorService,
    ExecutorStatusService, ExplorerPolicy, FairnessPolicy, GetAttemptExecutionDisposition,
    GetAttemptExecutionRequest, GetAttemptExecutionResponse, MeasurementSet, Observation,
    ObservationCandidate, ObservationId, ProgressiveWideningPolicy, PropertyVerdictSet, Proposal,
    PuctPolicy, RepositoryCampaignService, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, RetentionPolicy, SelectableDeclaration, Selection,
    SelectionOrigin, StopCondition, StopOutcome, SubmitAttemptDisposition, SubmitAttemptRequest,
    SubmitAttemptResponse, WatchExecutorCapacityRequest, WorkerSlotId,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use crucible_daemon::{
    encode_crucible_configuration_artifact, serve_loopback_campaign_once,
    serve_loopback_executor_component_connection_with_limits, AssignmentLedgerError,
    AttemptExecutionKey, CrucibleCampaignArtifactStore, DirectoryAssignmentLedger,
    ExecutorCapacity, LocalExecutorCapabilityService, LocalExecutorError, LocalExecutorSupervisor,
    LoopbackCampaignService, LoopbackExecutorService, LoopbackExecutorTimeouts,
    MemoryAssignmentLedger, RepositoryAttemptAdmission,
};

const CAMPAIGN_NAME: &str = "component-contract-flight";
const COORDINATOR_HELPER: &str = "coordinator_process_helper";
const EXECUTOR_HELPER: &str = "executor_process_helper";
const PROCESS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn same_campaign_survives_direct_rpc_and_independent_component_restarts() {
    let directory = tempfile::tempdir().expect("component contract directory");
    let paths = FixturePaths::new(directory.path());
    let fixture = create_direct_campaign_fixture(&paths);
    let campaign_id = fixture.lineage.id().expect("campaign lineage ID");
    let observation_id = fixture
        .candidate
        .observation()
        .id()
        .expect("observation ID");

    let mut coordinator = ProcessGuard::spawn(COORDINATOR_HELPER, &paths, None);
    let rpc_create = coordinator_client(&paths)
        .create_campaign(&fixture.create_request)
        .expect("split-process create replay");
    assert!(rpc_create.replayed());

    let resume_request = ApplyCampaignCommandRequest::new(
        principal(),
        campaign_name(),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: fixture.admitted_snapshot,
            action: CampaignControlAction::Resume,
        },
    )
    .expect("resume request");
    let resumed = coordinator_client(&paths)
        .apply_campaign_command(&resume_request)
        .expect("split-process resume");
    let resumed_replay = coordinator_client(&paths)
        .apply_campaign_command(&resume_request)
        .expect("split-process resume replay");
    assert!(!resumed.replayed());
    assert!(resumed_replay.replayed());
    assert_eq!(resumed_replay.new_snapshot(), resumed.new_snapshot());

    let epoch_one = epoch(0x41);
    let mut executor = ProcessGuard::spawn(EXECUTOR_HELPER, &paths, Some(epoch_one));
    let completed_request = assignment(campaign_id, fixture.attempt, epoch_one, 0x61);
    let (direct_submit, direct_replay) =
        direct_submit_pair(&paths, &fixture.lineage, &completed_request);
    let mut rpc_executor = executor_client(&paths);
    let rpc_submit = rpc_executor
        .submit_attempt(&completed_request)
        .expect("split-process submit");
    let rpc_replay = rpc_executor
        .submit_attempt(&completed_request)
        .expect("split-process submit replay");
    assert_eq!(rpc_submit, direct_submit);
    assert_eq!(rpc_replay, direct_replay);

    let completed_execution = accepted_execution(&rpc_submit);
    assert_eq!(
        executor.command("COMPLETE"),
        format!("COMPLETED {observation_id}")
    );
    let completed_status = rpc_executor
        .get_attempt_execution(
            &GetAttemptExecutionRequest::new(&completed_request, completed_execution)
                .expect("completed status request"),
        )
        .expect("completed status");
    assert_eq!(
        completed_status.disposition(),
        GetAttemptExecutionDisposition::Completed {
            observation: observation_id,
        }
    );

    let completed_recheck = assignment(campaign_id, fixture.attempt, epoch_one, 0x62);
    let completed_response = rpc_executor
        .submit_attempt(&completed_recheck)
        .expect("completed attempt replay through a new assignment");
    assert_eq!(
        completed_response.disposition(),
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observation_id,
        }
    );
    assert_eq!(
        rpc_executor
            .submit_attempt(&completed_recheck)
            .expect("repeat completed assignment"),
        completed_response
    );

    coordinator.kill_and_wait();
    assert_eq!(
        rpc_executor
            .submit_attempt(&completed_recheck)
            .expect("executor remains live across coordinator restart"),
        completed_response
    );
    coordinator = ProcessGuard::spawn(COORDINATOR_HELPER, &paths, None);
    assert_eq!(
        coordinator_client(&paths)
            .apply_campaign_command(&resume_request)
            .expect("coordinator restart resume replay"),
        resumed_replay
    );

    executor.kill_and_wait();
    let campaign_during_executor_restart = coordinator_client(&paths)
        .get_campaign(
            &crucible_campaign::GetCampaignRequest::new(principal(), campaign_name())
                .expect("campaign status request"),
        )
        .expect("coordinator remains live across executor restart");
    assert_eq!(
        campaign_during_executor_restart.snapshot(),
        resumed.new_snapshot()
    );

    let epoch_two = epoch(0x42);
    executor = ProcessGuard::spawn(EXECUTOR_HELPER, &paths, Some(epoch_two));
    let mut restarted_executor = executor_client(&paths);
    let stale_assignment = assignment(campaign_id, fixture.attempt, epoch_one, 0x63);
    assert_eq!(
        restarted_executor
            .submit_attempt(&stale_assignment)
            .expect("stale assignment response")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Unauthorized,
        }
    );
    let conflicting_stale = SubmitAttemptRequest::new(
        stale_assignment.assignment(),
        stale_assignment.daemon_epoch(),
        stale_assignment.lineage(),
        stale_assignment.attempt(),
        AttemptResourceLimits::new(2, 1024, 2048, 32).expect("conflicting resources"),
        stale_assignment.retention(),
    )
    .expect("conflicting stale assignment");
    assert_eq!(
        restarted_executor
            .submit_attempt(&conflicting_stale)
            .expect("conflicting stale assignment response")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::ConflictingAssignment,
        }
    );
    let current_epoch_assignment = assignment(campaign_id, fixture.attempt, epoch_two, 0x64);
    assert_eq!(
        restarted_executor
            .submit_attempt(&current_epoch_assignment)
            .expect("current-epoch completed assignment")
            .disposition(),
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: observation_id,
        }
    );
    assert_eq!(
        restarted_executor
            .submit_attempt(&completed_request)
            .expect("original assignment response after executor restart"),
        rpc_submit
    );
    assert_eq!(
        restarted_executor
            .submit_attempt(&completed_recheck)
            .expect("completed response after executor restart"),
        completed_response
    );
    drop(restarted_executor);
    coordinator.kill_and_wait();
    coordinator = ProcessGuard::spawn(COORDINATOR_HELPER, &paths, Some(epoch_two));
    assert_eq!(coordinator.command("STEP"), "INCORPORATED");

    let campaign_repository = repository(&paths);
    let incorporated_head = campaign_repository
        .head(CAMPAIGN_NAME)
        .expect("incorporated head");
    assert_ne!(incorporated_head.snapshot_id(), resumed.new_snapshot());
    assert_eq!(
        campaign_repository
            .load_observation(observation_id)
            .expect("published observation"),
        fixture.candidate.observation().clone()
    );
    assert!(campaign_repository
        .project_claimable_attempts(CAMPAIGN_NAME, None, 10_000)
        .expect("post-incorporation attempts")
        .attempts()
        .is_empty());
    let visits = campaign_repository
        .project_branch_edge_visits(incorporated_head.snapshot_id(), fixture.branch_point)
        .expect("branch edge visits");
    assert_eq!(visits.parent_visits(), 1);
    assert_eq!(visits.edge_visits().values().copied().sum::<u64>(), 1);

    assert_eq!(coordinator.command("STEP"), "IDLE");
    let incorporated_snapshot = incorporated_head.snapshot_id();
    coordinator.kill_and_wait();
    coordinator = ProcessGuard::spawn(COORDINATOR_HELPER, &paths, Some(epoch_two));
    assert_eq!(coordinator.command("STEP"), "IDLE");
    let restarted_repository = repository(&paths);
    let restarted_head = restarted_repository
        .head(CAMPAIGN_NAME)
        .expect("twice-restarted coordinator head");
    assert_eq!(restarted_head.snapshot_id(), incorporated_snapshot);
    let restarted_visits = restarted_repository
        .project_branch_edge_visits(restarted_head.snapshot_id(), fixture.branch_point)
        .expect("restarted branch edge visits");
    assert_eq!(restarted_visits, visits);

    drop(rpc_executor);
    drop(executor);
    drop(coordinator);
}

#[test]
#[ignore = "spawned by the component-contract process fixture"]
fn coordinator_process_helper() {
    let paths = FixturePaths::from_environment();
    remove_stale_socket(&paths.coordinator_socket);
    let listener = UnixListener::bind(&paths.coordinator_socket).expect("bind coordinator socket");
    let repository = Arc::new(repository(&paths));
    let rpc_repository = Arc::clone(&repository);
    thread::spawn(move || {
        let service =
            RepositoryCampaignService::new(rpc_repository.as_ref(), AllowAllCampaignAccess);
        loop {
            let (mut stream, _) = listener.accept().expect("accept coordinator connection");
            if let Err(error) = serve_loopback_campaign_once(&mut stream, &service) {
                assert!(
                    matches!(
                        error,
                        crucible_daemon::LoopbackCampaignServerError::Protocol(
                            crucible_daemon::LoopbackCampaignProtocolError::ConnectionClosed
                        )
                    ),
                    "coordinator request failed: {error:?}"
                );
            }
        }
    });

    protocol_reply("READY");
    for command in std::io::stdin().lock().lines() {
        match command.expect("coordinator control command").as_str() {
            "STEP" => coordinator_step(Arc::clone(&repository), &paths),
            command => panic!("unknown coordinator command: {command}"),
        }
    }
}

fn coordinator_step(repository: Arc<CampaignRepository>, paths: &FixturePaths) {
    let daemon_epoch = required_epoch();
    let stream = UnixStream::connect(&paths.executor_socket).expect("connect executor for driver");
    let service = LoopbackExecutorService::new(stream).expect("driver executor service");
    let mut driver = CampaignExecutorDriver::new(
        repository,
        ExecutorClient::new(service),
        daemon_epoch,
        1,
        executor_resources(),
        ExecutionRetentionIntent::RetainOnFailure,
        10_000,
    )
    .expect("campaign executor driver");
    let outcome = driver
        .step(CAMPAIGN_NAME, WorkerSlotId::new(0))
        .expect("campaign executor step");
    match outcome {
        CampaignExecutorStepOutcome::Incorporated(_) => protocol_reply("INCORPORATED"),
        CampaignExecutorStepOutcome::Idle { .. }
        | CampaignExecutorStepOutcome::AlreadyResolved { .. } => protocol_reply("IDLE"),
        outcome => panic!("unexpected coordinator step outcome: {outcome:?}"),
    }
}

#[test]
#[ignore = "spawned by the component-contract process fixture"]
fn executor_process_helper() {
    let paths = FixturePaths::from_environment();
    let daemon_epoch = required_epoch();
    let repository = Arc::new(repository(&paths));
    let lineage_id = CampaignLineageId::parse(&required_environment("CRUCIBLE_COMPONENT_LINEAGE"))
        .expect("component lineage ID");
    let lineage = repository
        .load_lineage(lineage_id)
        .expect("component campaign lineage");
    let candidate = observation_candidate(
        repository.as_ref(),
        &lineage,
        required_attempt(&paths),
        required_opportunity(&paths),
    );
    let service = ComponentExecutorService::new(
        &paths,
        Arc::clone(&repository),
        &lineage,
        daemon_epoch,
        candidate,
    );

    remove_stale_socket(&paths.executor_socket);
    let listener = UnixListener::bind(&paths.executor_socket).expect("bind executor socket");
    let rpc_service = service.clone();
    thread::spawn(move || loop {
        let (mut stream, _) = listener.accept().expect("accept executor connection");
        if let Err(error) = serve_loopback_executor_component_connection_with_limits(
            &mut stream,
            &mut rpc_service.clone(),
            LoopbackExecutorTimeouts::default(),
            64,
        ) {
            panic!("executor connection failed: {error:?}");
        }
    });

    protocol_reply("READY");
    for command in std::io::stdin().lock().lines() {
        match command.expect("executor control command").as_str() {
            "COMPLETE" => {
                let observation = service.complete_queued_attempt();
                protocol_reply(&format!("COMPLETED {observation}"));
            }
            command => panic!("unknown executor command: {command}"),
        }
    }
}

#[derive(Clone)]
struct ComponentExecutorService {
    inner: Arc<
        Mutex<
            LocalExecutorCapabilityService<DirectoryAssignmentLedger, RepositoryAttemptAdmission>,
        >,
    >,
    store: CampaignExecutorStore,
    candidate: ObservationCandidate,
}

impl ComponentExecutorService {
    fn new(
        paths: &FixturePaths,
        repository: Arc<CampaignRepository>,
        lineage: &CampaignLineage,
        daemon_epoch: DaemonEpoch,
        candidate: ObservationCandidate,
    ) -> Self {
        let capacity = executor_capacity();
        let profile = ExecutorCompatibilityProfile::from_lineage(lineage);
        let supervisor = LocalExecutorSupervisor::new(
            DirectoryAssignmentLedger::open(&paths.ledger_root).expect("open executor ledger"),
            RepositoryAttemptAdmission::new(Arc::clone(&repository), profile.clone()),
            daemon_epoch,
            capacity,
        );
        let description = executor_description(lineage, profile, daemon_epoch, capacity);
        let service = LocalExecutorCapabilityService::new(supervisor, description)
            .expect("executor capability service");
        Self {
            inner: Arc::new(Mutex::new(service)),
            store: CampaignExecutorStore::new(repository),
            candidate,
        }
    }

    fn complete_queued_attempt(&self) -> ObservationId {
        let observation = self
            .store
            .publish_observation_candidate(&self.candidate)
            .expect("publish semantic observation candidate");
        let mut service = self.inner.lock().expect("executor service lock");
        let queued = service
            .supervisor_mut()
            .next_queued()
            .expect("semantic execution is queued");
        let key = AttemptExecutionKey::for_request(queued.request());
        service
            .supervisor_mut()
            .stage_observation_publication(&queued, observation)
            .expect("stage semantic completion");
        service
            .supervisor_mut()
            .complete_execution(key, queued.execution(), observation)
            .expect("complete semantic execution");
        observation
    }
}

type ExecutorFailure = LocalExecutorError<AssignmentLedgerError>;

impl ExecutorService for ComponentExecutorService {
    type Error = ExecutorFailure;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        ExecutorService::submit_attempt(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorStatusService for ComponentExecutorService {
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        ExecutorStatusService::get_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorControlService for ComponentExecutorService {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &crucible_campaign::CheckpointAttemptExecutionRequest,
    ) -> Result<crucible_campaign::CheckpointAttemptExecutionResponse, Self::Error> {
        ExecutorControlService::checkpoint_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &crucible_campaign::CancelAttemptExecutionRequest,
    ) -> Result<crucible_campaign::CancelAttemptExecutionResponse, Self::Error> {
        ExecutorControlService::cancel_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorResumeService for ComponentExecutorService {
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ExecutorResumeService::resume_attempt_execution(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

impl ExecutorCapabilityService for ComponentExecutorService {
    fn describe_executor(&mut self) -> Result<ExecutorDescription, Self::Error> {
        ExecutorCapabilityService::describe_executor(
            &mut *self.inner.lock().expect("executor service lock"),
        )
    }

    fn watch_capacity(
        &mut self,
        request: &WatchExecutorCapacityRequest,
    ) -> Result<ExecutorCapacityReport, Self::Error> {
        ExecutorCapabilityService::watch_capacity(
            &mut *self.inner.lock().expect("executor service lock"),
            request,
        )
    }
}

struct AllowAllCampaignAccess;

impl CampaignPrincipalAuthorizer for AllowAllCampaignAccess {
    fn authorize_all_campaigns(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }

    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

struct CampaignFixture {
    lineage: CampaignLineage,
    create_request: CreateCampaignRequest,
    admitted_snapshot: crucible_campaign::CampaignSnapshotId,
    attempt: AttemptId,
    branch_point: BranchPointId,
    candidate: ObservationCandidate,
}

fn create_direct_campaign_fixture(paths: &FixturePaths) -> CampaignFixture {
    let repository = Arc::new(repository(paths));
    let scenario = crucible::happy_path_scenario()
        .expect("happy-path scenario")
        .scenario;
    let schedule = crucible::Schedule::empty();
    let artifacts = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
    let scenario_id = artifacts
        .import_scenario(&scenario)
        .expect("import scenario");
    let configuration_id = artifacts
        .import_configuration(&scenario, &schedule)
        .expect("import configuration");
    let stored_scenario = repository
        .load_scenario_artifact(scenario_id)
        .expect("stored scenario");
    let stored_configuration = repository
        .load_configuration_artifact(configuration_id)
        .expect("stored configuration");
    let lineage = CampaignLineage::new(
        stored_scenario.scenario(),
        scenario_id,
        stored_configuration.configuration(),
        configuration_id,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        stored_scenario.payload_schema(),
        stored_configuration.payload_schema(),
    )
    .expect("lineage");
    let create_request = CreateCampaignRequest::new(
        principal(),
        campaign_name(),
        lineage.clone(),
        creation_policy(lineage.scenario()),
    )
    .expect("create request");
    let direct = CampaignClient::new(RepositoryCampaignService::new(
        repository.as_ref(),
        AllowAllCampaignAccess,
    ));
    let created = direct
        .create_campaign(&create_request)
        .expect("direct campaign creation");
    assert!(!created.replayed());
    let direct_replay = direct
        .create_campaign(&create_request)
        .expect("direct campaign creation replay");
    assert!(direct_replay.replayed());
    assert_eq!(direct_replay.snapshot(), created.snapshot());

    let budget_request = ApplyCampaignCommandRequest::new(
        principal(),
        campaign_name(),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("budget")),
            expected_snapshot: created.snapshot(),
            action: CampaignControlAction::GrantBudget(
                BudgetGrant::new(2, 2).expect("campaign budget"),
            ),
        },
    )
    .expect("budget request");
    let budgeted = direct
        .apply_campaign_command(&budget_request)
        .expect("direct budget grant");

    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.component-contract",
        ChoiceSource::Workload {
            producer: String::from("component-contract"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("component-contract")]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish choice domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler"),
            producer: hash("producer"),
        },
        "component-contract",
        None,
    )
    .expect("choice opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish choice opportunity");
    let opportunity_id = opportunity.id().expect("choice opportunity ID");
    let discovered = repository
        .discover_operator_choice_opportunity(
            CAMPAIGN_NAME,
            budgeted.new_snapshot(),
            lineage.genesis_content(),
            opportunity_id,
        )
        .expect("discover operator choice");
    let branch_request = BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity_id,
        domain.id().expect("choice domain ID"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("finite candidate source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("branch"))),
        BranchBudget::new(2, 2).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request");
    let requested = repository
        .submit_operator_branch_request(CAMPAIGN_NAME, discovered.new_snapshot, &branch_request)
        .expect("submit branch request");
    let request_head = repository.head(CAMPAIGN_NAME).expect("branch request head");
    let policy = creation_policy(lineage.scenario());
    let proposal = Proposal::new(
        branch_request.branch_point(),
        branch_request.id().expect("branch request ID"),
        branch_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy ID"),
        None,
        1,
        request_head
            .snapshot()
            .planning_view()
            .id()
            .expect("planning view ID"),
    )
    .expect("proposal");
    let proposed = repository
        .issue_proposal(CAMPAIGN_NAME, requested.new_snapshot, &proposal)
        .expect("issue proposal");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        branch_request.branch_point(),
    )
    .expect("campaign branch selection");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection origin")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(
        branch_request.branch_point(),
        edge,
    )])
    .expect("branch path");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: branch_request.parent(),
            selection: selection.id().expect("selection ID"),
        },
        path.id().expect("path ID"),
        branch_request.stop().clone(),
    )
    .expect("attempt");
    let admitted = repository
        .admit_proposal(
            CAMPAIGN_NAME,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit proposal");
    let candidate = observation_candidate(
        repository.as_ref(),
        &lineage,
        admitted.attempt,
        opportunity_id,
    );

    fs::write(
        &paths.lineage_id,
        lineage.id().expect("lineage ID").to_string(),
    )
    .expect("write lineage ID");
    fs::write(&paths.attempt_id, admitted.attempt.to_string()).expect("write attempt ID");
    fs::write(&paths.opportunity_id, opportunity_id.to_string()).expect("write opportunity ID");

    CampaignFixture {
        lineage,
        create_request,
        admitted_snapshot: admitted.new_snapshot,
        attempt: admitted.attempt,
        branch_point: branch_request.branch_point(),
        candidate,
    }
}

fn observation_candidate(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    attempt_id: AttemptId,
    opportunity_id: ChoiceOpportunityId,
) -> ObservationCandidate {
    let attempt = repository.load_attempt(attempt_id).expect("load attempt");
    let opportunity = repository
        .load_choice_opportunity(opportunity_id)
        .expect("load choice opportunity");
    let declaration = repository
        .load_selectable(opportunity.declaration())
        .expect("load selectable declaration");
    let domain = repository
        .load_choice_domain(opportunity.domain())
        .expect("load choice domain");
    let AttemptStart::Branch { selection, .. } = attempt.start() else {
        panic!("component-contract branch attempt")
    };
    let resolved_selection = repository
        .resolve_selection(selection)
        .expect("resolve branch selection");
    let schedule = crucible::Schedule::from_decisions([crucible::Decision::Selection(
        crucible::SelectionDecision::new(resolved_selection.selection()),
    )]);
    let scenario_artifact = repository
        .load_scenario_artifact(lineage.scenario_content())
        .expect("load scenario artifact");
    let child_artifact = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)
        .expect("encode child configuration artifact");
    let child = child_artifact.configuration();
    let measurements = MeasurementSet::new(BTreeMap::new()).expect("measurements");
    let properties = PropertyVerdictSet::new(BTreeMap::new()).expect("property verdicts");
    let coverage = CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage");
    let observation = Observation::new(
        attempt_id,
        child,
        child_artifact.id().expect("child artifact ID"),
        attempt.path(),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements.id().expect("measurement ID"),
        properties.id().expect("property verdict ID"),
        coverage.id().expect("coverage ID"),
        BTreeSet::from([opportunity_id]),
    )
    .expect("observation");
    ObservationCandidate::new(
        child_artifact,
        measurements,
        properties,
        coverage,
        vec![ChoiceDiscovery::new(declaration, domain, opportunity).expect("choice discovery")],
        observation,
    )
    .expect("observation candidate")
}

fn direct_submit_pair(
    paths: &FixturePaths,
    lineage: &CampaignLineage,
    request: &SubmitAttemptRequest,
) -> (SubmitAttemptResponse, SubmitAttemptResponse) {
    let capacity = executor_capacity();
    let repository = Arc::new(repository(paths));
    let profile = ExecutorCompatibilityProfile::from_lineage(lineage);
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        RepositoryAttemptAdmission::new(repository, profile.clone()),
        request.daemon_epoch(),
        capacity,
    );
    let description = executor_description(lineage, profile, request.daemon_epoch(), capacity);
    let service =
        LocalExecutorCapabilityService::new(supervisor, description).expect("direct executor");
    let mut client = ExecutorClient::new(service);
    let submitted = client.submit_attempt(request).expect("direct submit");
    let replayed = client
        .submit_attempt(request)
        .expect("direct submit replay");
    (submitted, replayed)
}

fn executor_description(
    lineage: &CampaignLineage,
    profile: ExecutorCompatibilityProfile,
    daemon_epoch: DaemonEpoch,
    capacity: ExecutorCapacity,
) -> ExecutorDescription {
    let capabilities = crucible_campaign::ExecutorCapabilitySet::new(
        profile,
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg-v1")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        capacity.maximum_concurrent_executions(),
        executor_resource_ceiling(),
        BTreeSet::from([hash("store-namespace")]),
    )
    .expect("executor capabilities");
    let description =
        ExecutorDescription::new(daemon_epoch, capabilities).expect("executor description");
    assert_eq!(
        description.capabilities().compatibility(),
        &ExecutorCompatibilityProfile::from_lineage(lineage)
    );
    description
}

struct FixturePaths {
    root: PathBuf,
    blobs: PathBuf,
    refs: PathBuf,
    ledger_root: PathBuf,
    coordinator_socket: PathBuf,
    executor_socket: PathBuf,
    lineage_id: PathBuf,
    attempt_id: PathBuf,
    opportunity_id: PathBuf,
}

impl FixturePaths {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            blobs: root.join("blobs"),
            refs: root.join("refs"),
            ledger_root: root.join("ledger"),
            coordinator_socket: root.join("coordinator.sock"),
            executor_socket: root.join("executor.sock"),
            lineage_id: root.join("lineage-id"),
            attempt_id: root.join("attempt-id"),
            opportunity_id: root.join("opportunity-id"),
        }
    }

    fn from_environment() -> Self {
        Self::new(Path::new(&required_environment("CRUCIBLE_COMPONENT_ROOT")))
    }
}

struct ProcessGuard {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    output: Receiver<String>,
    reader: Option<JoinHandle<()>>,
    socket: PathBuf,
}

impl ProcessGuard {
    fn spawn(helper: &str, paths: &FixturePaths, daemon_epoch: Option<DaemonEpoch>) -> Self {
        let socket = if helper == COORDINATOR_HELPER {
            paths.coordinator_socket.clone()
        } else {
            paths.executor_socket.clone()
        };
        remove_stale_socket(&socket);

        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--ignored")
            .arg("--exact")
            .arg(helper)
            .arg("--nocapture")
            .env("CRUCIBLE_COMPONENT_ROOT", &paths.root)
            .env(
                "CRUCIBLE_COMPONENT_LINEAGE",
                fs::read_to_string(&paths.lineage_id).expect("read lineage ID"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(daemon_epoch) = daemon_epoch {
            command.env(
                "CRUCIBLE_COMPONENT_EPOCH",
                encode_hex(&daemon_epoch.as_bytes()),
            );
        }
        let mut child = command.spawn().expect("spawn component process");
        let stdin = child.stdin.take().expect("component control input");
        let stdout = child.stdout.take().expect("component protocol output");
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut guard = Self {
            child: Some(child),
            stdin: Some(stdin),
            output,
            reader: Some(reader),
            socket,
        };
        assert_eq!(guard.read_protocol_reply(), "READY");
        guard
    }

    fn command(&mut self, command: &str) -> String {
        let stdin = self.stdin.as_mut().expect("live component input");
        writeln!(stdin, "{command}").expect("write component command");
        stdin.flush().expect("flush component command");
        self.read_protocol_reply()
    }

    fn read_protocol_reply(&mut self) -> String {
        let deadline = Instant::now() + PROCESS_RESPONSE_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(remaining) {
                Ok(line) if is_protocol_reply(&line) => return line,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    let status = self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait().expect("inspect component process"));
                    panic!("component protocol response timed out; status={status:?}");
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self
                        .child
                        .as_mut()
                        .and_then(|child| child.try_wait().expect("inspect component process"));
                    panic!("component protocol closed before response; status={status:?}");
                }
            }
        }
    }

    fn kill_and_wait(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            if child
                .try_wait()
                .expect("inspect component before cleanup")
                .is_none()
            {
                child.kill().expect("kill component process");
            }
            child.wait().expect("wait for component process");
            remove_stale_socket(&self.socket);
        }
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join component output reader");
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

fn is_protocol_reply(line: &str) -> bool {
    line == "READY" || line == "INCORPORATED" || line == "IDLE" || line.starts_with("COMPLETED ")
}

fn protocol_reply(reply: &str) {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{reply}").expect("write process protocol reply");
    stdout.flush().expect("flush process protocol reply");
}

fn repository(paths: &FixturePaths) -> CampaignRepository {
    CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "component-contract",
            &paths.blobs,
        )),
        Arc::new(DirectoryRefBackend::new(&paths.refs)),
    )
}

fn coordinator_client(paths: &FixturePaths) -> CampaignClient<LoopbackCampaignService> {
    let stream = UnixStream::connect(&paths.coordinator_socket).expect("connect coordinator");
    CampaignClient::new(LoopbackCampaignService::new(stream).expect("coordinator client"))
}

fn executor_client(paths: &FixturePaths) -> ExecutorClient<LoopbackExecutorService> {
    let stream = UnixStream::connect(&paths.executor_socket).expect("connect executor");
    ExecutorClient::new(LoopbackExecutorService::new(stream).expect("executor client"))
}

fn assignment(
    lineage: CampaignLineageId,
    attempt: AttemptId,
    daemon_epoch: DaemonEpoch,
    assignment_byte: u8,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment ID"),
        daemon_epoch,
        lineage,
        attempt,
        executor_resources(),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("assignment request")
}

fn executor_resources() -> AttemptResourceLimits {
    AttemptResourceLimits::new(1, 1024, 2048, 32).expect("executor resources")
}

fn executor_resource_ceiling() -> AttemptResourceLimits {
    AttemptResourceLimits::new(2, 2048, 4096, 64).expect("executor resource ceiling")
}

fn executor_capacity() -> ExecutorCapacity {
    ExecutorCapacity::new(2, 2, 2048, 4096, 64).expect("executor capacity")
}

fn accepted_execution(response: &SubmitAttemptResponse) -> ExecutionId {
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment was not accepted: {:?}", response.disposition())
    };
    execution
}

fn creation_policy(scenario: crucible_campaign::ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("widening constant"),
        crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening");
    CampaignPolicy::new(
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
    .expect("policy")
}

fn campaign_name() -> CampaignName {
    CampaignName::new(CAMPAIGN_NAME).expect("campaign name")
}

fn principal() -> CampaignPrincipal {
    CampaignPrincipal::new("operator:component-contract").expect("campaign principal")
}

fn epoch(byte: u8) -> DaemonEpoch {
    DaemonEpoch::from_bytes([byte; 16]).expect("daemon epoch")
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive(
        "crucible.test.component-contract-process.v1",
        label.as_bytes(),
    )
}

fn required_attempt(paths: &FixturePaths) -> AttemptId {
    AttemptId::parse(&fs::read_to_string(&paths.attempt_id).expect("read attempt ID"))
        .expect("attempt ID")
}

fn required_opportunity(paths: &FixturePaths) -> ChoiceOpportunityId {
    ChoiceOpportunityId::parse(
        &fs::read_to_string(&paths.opportunity_id).expect("read opportunity ID"),
    )
    .expect("choice opportunity ID")
}

fn required_epoch() -> DaemonEpoch {
    DaemonEpoch::from_bytes(
        decode_hex_16(&required_environment("CRUCIBLE_COMPONENT_EPOCH"))
            .expect("executor epoch bytes"),
    )
    .expect("executor epoch")
}

fn required_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn remove_stale_socket(socket: &Path) {
    match fs::remove_file(socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("remove stale socket {}: {error}", socket.display()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_16(value: &str) -> Result<[u8; 16], ()> {
    if value.len() != 32 {
        return Err(());
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| ())?;
    }
    Ok(output)
}
