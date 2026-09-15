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
    AttemptRetentionPolicyBasis, AttemptStart, BooleanDomain, BranchBudget, BranchPath,
    BranchPathSegment, BranchPointId, BranchRequest, BranchRequestCause, BudgetGrant,
    CampaignAuthorizationError, CampaignClient, CampaignCommandId, CampaignControlAction,
    CampaignExecutorDriver, CampaignExecutorStepOutcome, CampaignExecutorStore, CampaignHash,
    CampaignLineage, CampaignLineageId, CampaignMode, CampaignName, CampaignPolicy,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignSeed,
    CampaignServiceOperation, CandidateSource, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDiscovery, ChoiceDomain, ChoiceOpportunity, ChoiceOpportunityId, ChoiceSource,
    ChoiceValue, ControlRequest, CoverageProjection, CreateCampaignRequest, DaemonEpoch,
    ExecutionId, ExecutionRetentionIntent, ExecutorCapabilityService, ExecutorCapacityReport,
    ExecutorClient, ExecutorCompatibilityProfile, ExecutorControlService, ExecutorDescription,
    ExecutorMaterializationCapability, ExecutorRejection, ExecutorResumeService, ExecutorService,
    ExecutorStatusService, ExplorerPolicy, FairnessPolicy,
    FindingExactCheckpointAuthenticationError, FindingExactCheckpointAuthenticator,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    MeasurementSet, Observation, ObservationCandidate, ObservationId, ProgressiveWideningPolicy,
    PropertyVerdictSet, Proposal, PuctPolicy, RepositoryCampaignService,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, RetentionPolicy,
    SelectableDeclaration, Selection, SelectionOrigin, StopCondition, StopOutcome,
    SubmitAttemptDisposition, SubmitAttemptRequest, SubmitAttemptResponse,
    WatchExecutorCapacityRequest, WorkerSlotId,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend,
};

use crucible_daemon::{
    AssignmentLedgerError, AttemptExecutionProduct, AttemptResultStageOutcome, AttemptWorkResult,
    CampaignLoopbackServer, CampaignLoopbackServerConfig, CrucibleCampaignArtifactStore,
    DirectoryAssignmentLedger, ExactCheckpointStore, ExecutorCapacity,
    LocalExecutorCapabilityService, LocalExecutorError, LocalExecutorSupervisor,
    LoopbackCampaignService, LoopbackExecutorService, LoopbackExecutorTimeouts,
    MemoryAssignmentLedger, PreparedAttemptWorkResult, PreparedSemanticAttemptResult,
    RepositoryAttemptAdmission, encode_crucible_configuration_artifact, prepare_attempt_result,
    publish_prepared_attempt_result, reconcile_published_attempt_result,
    serve_loopback_executor_component_connection_with_limits, stage_prepared_attempt_result,
};

#[path = "gate_campaign_component_contract/support.rs"]
mod support;
use support::*;

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
    let retention_basis = repository(&paths)
        .attempt_retention_policy_basis_at(resumed.new_snapshot(), fixture.attempt)
        .expect("attempt retention policy basis");

    let epoch_one = epoch(0x41);
    let mut executor = ProcessGuard::spawn(EXECUTOR_HELPER, &paths, Some(epoch_one));
    let completed_request = assignment(
        campaign_id,
        fixture.attempt,
        epoch_one,
        0x61,
        retention_basis,
    );
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

    let completed_recheck = assignment(
        campaign_id,
        fixture.attempt,
        epoch_one,
        0x62,
        retention_basis,
    );
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
    let stale_assignment = assignment(
        campaign_id,
        fixture.attempt,
        epoch_one,
        0x63,
        retention_basis,
    );
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
        crucible_campaign::AttemptRetentionPolicyDisposition::Required(retention_basis),
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
    let current_epoch_assignment = assignment(
        campaign_id,
        fixture.attempt,
        epoch_two,
        0x64,
        retention_basis,
    );
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
    assert!(
        campaign_repository
            .project_claimable_attempts(CAMPAIGN_NAME, None, 10_000)
            .expect("post-incorporation attempts")
            .attempts()
            .is_empty()
    );
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
    let server = CampaignLoopbackServer::new(
        listener,
        rpc_repository,
        Arc::new(|_credentials| Ok(principal())),
        Arc::new(AllowAllCampaignAccess),
        CampaignLoopbackServerConfig::default(),
    )
    .expect("construct coordinator server");
    thread::spawn(move || {
        server.serve().expect("serve coordinator connections");
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
    thread::spawn(move || {
        loop {
            let (mut stream, _) = listener.accept().expect("accept executor connection");
            if let Err(error) = serve_loopback_executor_component_connection_with_limits(
                &mut stream,
                &mut rpc_service.clone(),
                LoopbackExecutorTimeouts::default(),
                64,
            ) {
                panic!("executor connection failed: {error:?}");
            }
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
