//! Conformance tests for bounded worker-to-supervisor reconciliation.

#![allow(clippy::expect_used)]

use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, CampaignLineageId, DaemonEpoch,
    ExecutionRetentionIntent, ExecutorService, ObservationId, SubmitAttemptDisposition,
    SubmitAttemptRequest,
};

use super::*;
use crate::{
    AllowAllAttemptAdmission, AttemptExecutionKey, ExecutorCapacity, LocalExecutorSupervisor,
    MemoryAssignmentLedger,
};

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
fn terminal_worker_failure_cancels_without_requeue() {
    let epoch = DaemonEpoch::from_bytes([0x34; 16]).expect("epoch");
    let mut supervisor = supervisor(epoch);
    supervisor
        .submit_attempt(&request(epoch, 0x45))
        .expect("accept assignment");
    let queued = supervisor.next_queued().expect("queued attempt");

    assert!(matches!(
        reconcile_attempt_failure(
            &mut supervisor,
            queued,
            AttemptWorkerFailure::Terminal("incompatible modeled result"),
        ),
        Err(AttemptWorkerReconcileError::Stopped {
            cancellation: CancellationOutcome::Canceled,
            ..
        })
    ));
    assert_eq!(supervisor.active_count(), 0);
    assert_eq!(supervisor.queued_count(), 0);
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

fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
    format!("{tag}@{kind}.1.{}", format!("{byte:02x}").repeat(32))
}
