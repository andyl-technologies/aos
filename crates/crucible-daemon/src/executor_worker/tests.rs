//! Conformance tests for bounded worker-to-supervisor reconciliation.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, AttemptStartMode, CampaignHash,
    CampaignLineageId, ConfigurationArtifact, ConfigurationId, DaemonEpoch,
    ExecutionRetentionIntent, ExecutorRejection, ExecutorService, ExecutorStatusService,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, ObservationId, ScenarioArtifact,
    ScenarioDefId, SubmitAttemptDisposition, SubmitAttemptRequest,
};

use super::*;
use crate::{
    AllowAllAttemptAdmission, AssignmentLedger, AttemptExecutionKey, AttemptExecutionOrigin,
    AttemptRuntimeState, ExecutorCapacity, LocalExecutorSupervisor, MemoryAssignmentLedger,
};

#[test]
fn capture_start_validation_requires_the_exact_discovery_artifact() {
    let resolved = configuration_artifact(0x21);
    let resolved_id = resolved.id().expect("resolved configuration artifact ID");
    let requested = configuration_artifact(0x22)
        .id()
        .expect("requested configuration artifact ID");
    let start = ResolvedAttemptStart::Discover {
        configuration: resolved,
    };

    assert_eq!(
        capture_start_validation_reason(
            &start,
            AttemptStartMode::CaptureMaterializedStart {
                configuration: resolved_id,
            },
        )
        .expect("matching capture validation"),
        None
    );
    assert_eq!(
        capture_start_validation_reason(
            &start,
            AttemptStartMode::CaptureMaterializedStart {
                configuration: requested,
            },
        )
        .expect("capture validation"),
        Some("materialized-start capture configuration differs from resolved discovery start")
    );
    assert_eq!(
        capture_start_validation_reason(&start, AttemptStartMode::Execute)
            .expect("ordinary execution validation"),
        None
    );
}

#[test]
fn staged_publication_reconciles_and_releases_capacity() {
    let epoch = DaemonEpoch::from_bytes([0x31; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let request = request(epoch, 0x41);
    supervisor
        .submit_attempt(&request)
        .expect("accept assignment");
    let queued = supervisor.next_queued().expect("queued attempt");
    let observation = observation(0x51);

    assert_eq!(
        supervisor
            .stage_observation_publication(&queued, observation)
            .expect("stage publication root"),
        ObservationPublicationOutcome::Staged
    );
    assert_eq!(supervisor.active_count(), 1);
    assert_eq!(
        supervisor
            .stage_and_reconcile_completion(&queued, observation)
            .expect("complete publication"),
        CompletionOutcome::Completed
    );
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);
}

#[test]
fn operational_worker_failure_requeues_without_growing_the_bounded_queue() {
    let epoch = DaemonEpoch::from_bytes([0x32; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    supervisor
        .submit_attempt(&request(epoch, 0x42))
        .expect("accept assignment");
    assert!(matches!(
        {
            let queued = supervisor.next_queued().expect("queued attempt");
            reconcile_attempt_failure(
                &mut supervisor,
                queued,
                AttemptWorkerFailure::Retryable("temporary materialization failure"),
            )
        },
        Err(AttemptWorkerReconcileError::Worker(
            AttemptWorkerFailure::Retryable("temporary materialization failure")
        ))
    ));
    assert_eq!(supervisor.active_count(), 1);
    assert_eq!(supervisor.queued_count(), 1);
}

#[test]
fn cancellation_keeps_capacity_until_the_worker_acknowledges_exit() {
    let epoch = DaemonEpoch::from_bytes([0x33; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let first_request = request(epoch, 0x43);
    let response = supervisor
        .submit_attempt(&first_request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");
    supervisor
        .cancel_execution(
            AttemptExecutionKey::new(first_request.lineage(), first_request.attempt()),
            execution,
        )
        .expect("cancel running worker");
    assert!(queued.cancellation().is_canceled());
    assert_eq!(supervisor.active_count(), 1);
    let replacement = request(epoch, 0x44);
    assert!(matches!(
        supervisor
            .submit_attempt(&replacement)
            .expect("bounded replacement response")
            .disposition(),
        SubmitAttemptDisposition::Rejected { .. }
    ));

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Canceled::<&'static str>("worker observed cancellation"),
        ),
        Err(AttemptWorkerReconcileError::Stopped {
            cancellation: CancellationOutcome::AlreadyCanceled,
            ..
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);
}

#[test]
fn cancellation_wins_over_a_retryable_worker_failure() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let request = request(epoch, 0x45);
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");
    supervisor
        .cancel_execution(
            AttemptExecutionKey::new(request.lineage(), request.attempt()),
            execution,
        )
        .expect("cancel running worker");

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Retryable("temporary failure after cancellation"),
        ),
        Err(AttemptWorkerReconcileError::Stopped {
            failure: AttemptWorkerFailure::Retryable("temporary failure after cancellation"),
            cancellation: CancellationOutcome::AlreadyCanceled,
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);
}

#[test]
fn terminal_worker_failure_is_durable_without_requeue() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    let request = request(epoch, 0x45);
    let response = supervisor
        .submit_attempt(&request)
        .expect("accept assignment");
    let SubmitAttemptDisposition::Accepted { execution } = response.disposition() else {
        panic!("assignment should be accepted")
    };
    let queued = supervisor.next_queued().expect("queued attempt");

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Terminal("incompatible modeled result"),
        ),
        Err(AttemptWorkerReconcileError::TerminalStopped {
            terminal_failure: TerminalFailureOutcome::Failed,
            failure: AttemptWorkerFailure::Terminal("incompatible modeled result"),
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);

    let status = GetAttemptExecutionRequest::new(&request, execution).expect("status query");
    assert_eq!(
        supervisor
            .get_attempt_execution(&status)
            .expect("terminal status")
            .disposition(),
        GetAttemptExecutionDisposition::TerminalFailure
    );

    let restart_epoch = DaemonEpoch::from_bytes([0x35; 16]).expect("restart epoch");
    let mut restarted = LocalExecutorSupervisor::new(
        supervisor.into_ledger(),
        AllowAllAttemptAdmission,
        restart_epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity"),
    );
    assert_eq!(
        restarted
            .ledger()
            .load_attempt(AttemptExecutionKey::new(
                request.lineage(),
                request.attempt()
            ))
            .expect("load terminal state"),
        Some(AttemptRuntimeState::TerminalFailure {
            execution_basis: request.execution_basis_digest(),
            origin: AttemptExecutionOrigin::Initial,
            daemon_epoch: epoch,
            execution,
        })
    );

    let reassignment = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x46; 16]).expect("reassignment"),
        restart_epoch,
        request.lineage(),
        request.attempt(),
        request.resources(),
        request.retention(),
    )
    .expect("restart assignment");
    assert_eq!(
        restarted
            .submit_attempt(&reassignment)
            .expect("terminal replay response")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::TerminalFailure,
        }
    );
    assert_eq!(restarted.active_count(), 0);
    assert_eq!(restarted.queued_count(), 0);
}

fn supervisor(
    epoch: DaemonEpoch,
) -> LocalExecutorSupervisor<MemoryAssignmentLedger, AllowAllAttemptAdmission> {
    LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity"),
    )
}

fn request(epoch: DaemonEpoch, byte: u8) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([byte; 16]).expect("assignment"),
        epoch,
        CampaignLineageId::parse(&typed_id(
            "crucible.campaign.lineage",
            "campaign-fact",
            byte,
        ))
        .expect("lineage"),
        AttemptId::parse(&typed_id(
            "crucible.campaign.attempt",
            "campaign-fact",
            byte,
        ))
        .expect("attempt"),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("request")
}

fn observation(byte: u8) -> ObservationId {
    ObservationId::parse(&typed_id(
        "crucible.campaign.observation",
        "observation",
        byte,
    ))
    .expect("observation")
}

fn configuration_artifact(byte: u8) -> ConfigurationArtifact {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "crucible.test.executor-worker.capture-scenario.v1",
        &[byte],
    ));
    let scenario_artifact = ScenarioArtifact::new(scenario, 1, vec![byte])
        .expect("scenario artifact")
        .id()
        .expect("scenario artifact ID");
    let configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.executor-worker.capture-configuration.v1",
        &[byte],
    ));
    ConfigurationArtifact::new(scenario, scenario_artifact, configuration, 1, vec![byte])
        .expect("configuration artifact")
}

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", format!("{byte:02x}").repeat(32))
}
