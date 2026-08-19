//! Conformance tests for bounded local executor supervision.

#![allow(clippy::expect_used)]

use std::cell::Cell;

use crucible_campaign::{
    AssignmentId, AttemptId, AttemptResourceLimits, CampaignLineageId, ExecutionRetentionIntent,
    ExecutorClient, SubmitAttemptDisposition,
};

use super::*;
use crate::{DirectoryAssignmentLedger, MemoryAssignmentLedger};

#[test]
fn exact_replay_running_dedup_and_capacity_are_bounded() {
    let epoch = daemon_epoch(0x21);
    let capacity = ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity,
    );
    let mut client = ExecutorClient::new(supervisor);
    let first = request(0x11, 0x31, epoch, resources(1, 2048, 4096));
    let accepted = client
        .submit_attempt(&first)
        .expect("accept first assignment");
    let execution = accepted_execution(&accepted);
    assert_eq!(
        client
            .submit_attempt(&first)
            .expect("exact assignment replay"),
        accepted
    );

    let changed = SubmitAttemptRequest::new(
        first.assignment(),
        epoch,
        first.lineage(),
        first.attempt(),
        resources(2, 2048, 4096),
        first.retention(),
    )
    .expect("changed request");
    assert_eq!(
        client
            .submit_attempt(&changed)
            .expect("assignment conflict")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::ConflictingAssignment
        }
    );

    let duplicate_attempt = request(0x12, 0x31, epoch, resources(1, 2048, 4096));
    assert_eq!(
        client
            .submit_attempt(&duplicate_attempt)
            .expect("running attempt dedup")
            .disposition(),
        SubmitAttemptDisposition::AlreadyRunning { execution }
    );
    let blocked = request(0x13, 0x32, epoch, resources(1, 2048, 4096));
    assert_eq!(
        client
            .submit_attempt(&blocked)
            .expect("bounded backpressure")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Backpressure
        }
    );

    let mut supervisor = client.into_inner();
    assert_eq!(supervisor.active_count(), 1);
    assert_eq!(supervisor.queued_count(), 1);
    let queued = supervisor.next_queued().expect("one queued execution");
    assert_eq!(queued.execution(), execution);
    assert_eq!(queued.request(), &first);
    assert!(supervisor.next_queued().is_none());
    assert_eq!(
        supervisor
            .complete_execution(execution_key(&first), execution, observation(0x71))
            .expect("complete execution"),
        CompletionOutcome::Completed
    );
    assert_eq!(supervisor.active_count(), 0);

    let retry_after_capacity = request(0x14, 0x32, epoch, resources(1, 2048, 4096));
    assert!(matches!(
        supervisor
            .submit_attempt(&retry_after_capacity)
            .expect("capacity released")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
}

#[test]
fn runtime_dedup_is_lineage_scoped_and_requires_an_exact_execution_basis() {
    let epoch = daemon_epoch(0x28);
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(4, 8, 16_384, 32_768, 64).expect("capacity"),
    );
    let first = request_in_lineage(
        0x15,
        0x35,
        0x11,
        epoch,
        resources(1, 2048, 4096),
        ExecutionRetentionIntent::RetainOnFailure,
    );
    let first_execution = accepted_execution(
        &supervisor
            .submit_attempt(&first)
            .expect("accept first lineage"),
    );

    let other_lineage = request_in_lineage(
        0x16,
        0x35,
        0x12,
        epoch,
        first.resources(),
        first.retention(),
    );
    let other_execution = accepted_execution(
        &supervisor
            .submit_attempt(&other_lineage)
            .expect("same attempt is independent in another lineage"),
    );
    assert_ne!(other_execution, first_execution);

    let changed_resources = request_in_lineage(
        0x17,
        0x35,
        0x11,
        epoch,
        resources(2, 2048, 4096),
        first.retention(),
    );
    assert_eq!(
        supervisor
            .submit_attempt(&changed_resources)
            .expect("changed resources are a stable incompatibility")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Incompatible
        }
    );

    let changed_retention = request_in_lineage(
        0x18,
        0x35,
        0x11,
        epoch,
        first.resources(),
        ExecutionRetentionIntent::RetainAlways,
    );
    assert_eq!(
        supervisor
            .submit_attempt(&changed_retention)
            .expect("changed retention is a stable incompatibility")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Incompatible
        }
    );
}

#[test]
fn execution_quanta_are_enforced_as_a_per_execution_capability() {
    let epoch = daemon_epoch(0x29);
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(1, 2, 4096, 8192, 31).expect("capacity"),
    );
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x19; 16]).expect("assignment"),
        epoch,
        lineage(0x11),
        attempt(0x39),
        AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("request");
    assert_eq!(
        supervisor
            .submit_attempt(&request)
            .expect("quanta rejection")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Incompatible
        }
    );
    assert_eq!(supervisor.active_count(), 0);
}

#[test]
fn completion_and_cancellation_races_are_idempotent() {
    let epoch = daemon_epoch(0x22);
    let capacity = ExecutorCapacity::new(2, 4, 8192, 16384, 64).expect("capacity");
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        capacity,
    );
    let completed_request = request(0x21, 0x41, epoch, resources(1, 2048, 4096));
    let completed_response = supervisor
        .submit_attempt(&completed_request)
        .expect("accepted completion fixture");
    let completed_execution = accepted_execution(&completed_response);
    let completed_observation = observation(0x72);
    assert_eq!(
        supervisor
            .complete_execution(
                execution_key(&completed_request),
                completed_execution,
                completed_observation,
            )
            .expect("first completion"),
        CompletionOutcome::Completed
    );
    assert_eq!(
        supervisor
            .complete_execution(
                execution_key(&completed_request),
                completed_execution,
                completed_observation,
            )
            .expect("completion replay"),
        CompletionOutcome::AlreadyCompleted
    );
    assert!(matches!(
        supervisor.complete_execution(
            execution_key(&completed_request),
            completed_execution,
            observation(0x73),
        ),
        Err(LocalExecutorError::ConflictingCompletion)
    ));
    assert_eq!(
        supervisor
            .cancel_execution(execution_key(&completed_request), completed_execution)
            .expect("cancel completed execution"),
        CancellationOutcome::AlreadyCompleted {
            observation: completed_observation
        }
    );
    let completed_retry = request(0x22, 0x41, epoch, resources(1, 2048, 4096));
    assert_eq!(
        supervisor
            .submit_attempt(&completed_retry)
            .expect("completed attempt replay")
            .disposition(),
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: completed_observation
        }
    );

    let canceled_request = request(0x23, 0x42, epoch, resources(1, 2048, 4096));
    let canceled_response = supervisor
        .submit_attempt(&canceled_request)
        .expect("accepted cancellation fixture");
    let canceled_execution = accepted_execution(&canceled_response);
    assert_eq!(
        supervisor
            .cancel_execution(execution_key(&canceled_request), canceled_execution)
            .expect("cancel execution"),
        CancellationOutcome::Canceled
    );
    assert_eq!(supervisor.queued_count(), 0);
    assert_eq!(
        supervisor
            .cancel_execution(execution_key(&canceled_request), canceled_execution)
            .expect("cancel replay"),
        CancellationOutcome::AlreadyCanceled
    );
    assert_eq!(
        supervisor
            .complete_execution(
                execution_key(&canceled_request),
                canceled_execution,
                observation(0x74),
            )
            .expect("late completion"),
        CompletionOutcome::Canceled
    );
    let replacement = request(0x24, 0x42, epoch, resources(1, 2048, 4096));
    assert!(matches!(
        supervisor
            .submit_attempt(&replacement)
            .expect("replacement after cancellation")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
}

#[test]
fn rejection_preflight_is_stable_and_does_not_consume_capacity() {
    let epoch = daemon_epoch(0x23);
    let calls = Cell::new(0_u32);
    let validator = |_: &SubmitAttemptRequest| {
        calls.set(calls.get() + 1);
        Err(ExecutorRejection::UnavailableInput)
    };
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        validator,
        epoch,
        ExecutorCapacity::new(1, 1, 2048, 0, 64).expect("capacity"),
    );
    let unavailable = request(0x31, 0x51, epoch, resources(1, 1024, 0));
    let first = supervisor
        .submit_attempt(&unavailable)
        .expect("unavailable response");
    assert_eq!(
        first.disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::UnavailableInput
        }
    );
    assert_eq!(
        supervisor
            .submit_attempt(&unavailable)
            .expect("stable unavailable replay"),
        first
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(supervisor.active_count(), 0);

    let wrong_epoch = request(0x32, 0x52, daemon_epoch(0x24), resources(1, 1024, 0));
    assert_eq!(
        supervisor
            .submit_attempt(&wrong_epoch)
            .expect("wrong epoch response")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::Unauthorized
        }
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn response_publication_failure_never_abandons_prepared_work() {
    for failure in [PublishFailure::BeforeStore, PublishFailure::AfterStore] {
        let epoch = daemon_epoch(match failure {
            PublishFailure::BeforeStore => 0x25,
            PublishFailure::AfterStore => 0x26,
        });
        let ledger = FailingPublishLedger {
            inner: MemoryAssignmentLedger::default(),
            failure: Some(failure),
        };
        let mut supervisor = LocalExecutorSupervisor::new(
            ledger,
            AllowAllAttemptAdmission,
            epoch,
            ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
        );
        let request = request(0x35, 0x55, epoch, resources(1, 1024, 2048));
        assert!(matches!(
            supervisor.submit_attempt(&request),
            Err(LocalExecutorError::Ledger(InjectedFailure))
        ));
        assert_eq!(supervisor.active_count(), 1);
        let queued = supervisor
            .next_queued()
            .expect("prepared work remains queued");
        assert_eq!(queued.request(), &request);

        let retry = supervisor
            .submit_attempt(&request)
            .expect("retry observes durable or running state");
        match failure {
            PublishFailure::BeforeStore => assert_eq!(
                retry.disposition(),
                SubmitAttemptDisposition::AlreadyRunning {
                    execution: queued.execution()
                }
            ),
            PublishFailure::AfterStore => assert_eq!(
                retry.disposition(),
                SubmitAttemptDisposition::Accepted {
                    execution: queued.execution()
                }
            ),
        }
        assert_eq!(supervisor.active_count(), 1);
        assert!(supervisor.next_queued().is_none());
    }
}

#[test]
fn compare_exchange_failures_reconcile_running_completion_and_cancellation() {
    for failure in [CasFailure::BeforeStore, CasFailure::AfterStore] {
        let epoch = daemon_epoch(match failure {
            CasFailure::BeforeStore => 0x40,
            CasFailure::AfterStore => 0x41,
        });
        let ledger = FailingCasLedger::new(failure, 1);
        let mut supervisor = LocalExecutorSupervisor::new(
            ledger,
            AllowAllAttemptAdmission,
            epoch,
            ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
        );
        let request = request(0x60, 0x70, epoch, resources(1, 1024, 2048));
        assert!(matches!(
            supervisor.submit_attempt(&request),
            Err(LocalExecutorError::Ledger(InjectedFailure))
        ));
        assert_eq!(
            supervisor.active_count(),
            usize::from(matches!(failure, CasFailure::AfterStore))
        );
        let retry = supervisor
            .submit_attempt(&request)
            .expect("running transition retry");
        match failure {
            CasFailure::BeforeStore => {
                assert!(matches!(
                    retry.disposition(),
                    SubmitAttemptDisposition::Accepted { .. }
                ));
            }
            CasFailure::AfterStore => {
                assert!(matches!(
                    retry.disposition(),
                    SubmitAttemptDisposition::AlreadyRunning { .. }
                ));
            }
        }
        assert_eq!(supervisor.active_count(), 1);
    }

    for failure in [CasFailure::BeforeStore, CasFailure::AfterStore] {
        let epoch = daemon_epoch(match failure {
            CasFailure::BeforeStore => 0x42,
            CasFailure::AfterStore => 0x43,
        });
        let ledger = FailingCasLedger::new(failure, 2);
        let mut supervisor = LocalExecutorSupervisor::new(
            ledger,
            AllowAllAttemptAdmission,
            epoch,
            ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
        );
        let request = request(0x61, 0x71, epoch, resources(1, 1024, 2048));
        let execution = accepted_execution(
            &supervisor
                .submit_attempt(&request)
                .expect("completion fixture accepted"),
        );
        let observation = observation(0x78);
        assert!(matches!(
            supervisor.complete_execution(execution_key(&request), execution, observation),
            Err(LocalExecutorError::Ledger(InjectedFailure))
        ));
        assert_eq!(
            supervisor.active_count(),
            usize::from(matches!(failure, CasFailure::BeforeStore))
        );
        assert_eq!(
            supervisor
                .complete_execution(execution_key(&request), execution, observation)
                .expect("completion transition retry"),
            if matches!(failure, CasFailure::BeforeStore) {
                CompletionOutcome::Completed
            } else {
                CompletionOutcome::AlreadyCompleted
            }
        );
        assert_eq!(supervisor.active_count(), 0);
    }

    for failure in [CasFailure::BeforeStore, CasFailure::AfterStore] {
        let epoch = daemon_epoch(match failure {
            CasFailure::BeforeStore => 0x44,
            CasFailure::AfterStore => 0x45,
        });
        let ledger = FailingCasLedger::new(failure, 2);
        let mut supervisor = LocalExecutorSupervisor::new(
            ledger,
            AllowAllAttemptAdmission,
            epoch,
            ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
        );
        let request = request(0x62, 0x72, epoch, resources(1, 1024, 2048));
        let execution = accepted_execution(
            &supervisor
                .submit_attempt(&request)
                .expect("cancellation fixture accepted"),
        );
        assert!(matches!(
            supervisor.cancel_execution(execution_key(&request), execution),
            Err(LocalExecutorError::Ledger(InjectedFailure))
        ));
        assert_eq!(
            supervisor.active_count(),
            usize::from(matches!(failure, CasFailure::BeforeStore))
        );
        assert_eq!(
            supervisor
                .cancel_execution(execution_key(&request), execution)
                .expect("cancellation transition retry"),
            if matches!(failure, CasFailure::BeforeStore) {
                CancellationOutcome::Canceled
            } else {
                CancellationOutcome::AlreadyCanceled
            }
        );
        assert_eq!(supervisor.active_count(), 0);
    }
}

#[test]
fn completion_validation_is_fail_closed_by_default() {
    let epoch = daemon_epoch(0x27);
    let validator = |_: &SubmitAttemptRequest| Ok(());
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        validator,
        epoch,
        ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
    );
    let request = request(0x36, 0x56, epoch, resources(1, 1024, 2048));
    let response = supervisor
        .submit_attempt(&request)
        .expect("accepted execution");
    let execution = accepted_execution(&response);
    assert!(matches!(
        supervisor.complete_execution(execution_key(&request), execution, observation(0x76)),
        Err(LocalExecutorError::CompletionValidation {
            reason: CompletionValidationFailure::Incompatible
        })
    ));
    assert_eq!(supervisor.active_count(), 1);
    assert!(matches!(
        supervisor
            .ledger()
            .load_attempt(execution_key(&request))
            .expect("running state"),
        Some(AttemptRuntimeState::Running { .. })
    ));
}

#[test]
fn durable_completions_are_reauthenticated_or_discarded_before_reuse() {
    let first_epoch = daemon_epoch(0x2a);
    let completed_request = request(0x37, 0x57, first_epoch, resources(1, 1024, 2048));
    let completed_observation = observation(0x77);
    let completed_ledger = |assignment_byte: u8| {
        let request = request(assignment_byte, 0x57, first_epoch, resources(1, 1024, 2048));
        let mut supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            first_epoch,
            ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
        );
        let execution = accepted_execution(
            &supervisor
                .submit_attempt(&request)
                .expect("completion fixture accepted"),
        );
        assert_eq!(
            supervisor
                .complete_execution(execution_key(&request), execution, completed_observation)
                .expect("completion fixture published"),
            CompletionOutcome::Completed
        );
        supervisor.into_ledger()
    };

    let second_epoch = daemon_epoch(0x2b);
    let unavailable_request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x38; 16]).expect("assignment"),
        second_epoch,
        completed_request.lineage(),
        completed_request.attempt(),
        completed_request.resources(),
        completed_request.retention(),
    )
    .expect("unavailable request");
    let mut unavailable = LocalExecutorSupervisor::new(
        completed_ledger(0x37),
        CompletionValidator(Err(CompletionValidationFailure::UnavailableInput)),
        second_epoch,
        ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
    );
    assert_eq!(
        unavailable
            .submit_attempt(&unavailable_request)
            .expect("unavailable completion rejection")
            .disposition(),
        SubmitAttemptDisposition::Rejected {
            reason: ExecutorRejection::UnavailableInput
        }
    );
    assert!(matches!(
        unavailable
            .ledger()
            .load_attempt(execution_key(&unavailable_request))
            .expect("completed acceleration remains"),
        Some(AttemptRuntimeState::Completed { .. })
    ));

    let incompatible_request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x39; 16]).expect("assignment"),
        second_epoch,
        completed_request.lineage(),
        completed_request.attempt(),
        completed_request.resources(),
        completed_request.retention(),
    )
    .expect("incompatible request");
    let mut incompatible = LocalExecutorSupervisor::new(
        completed_ledger(0x3a),
        CompletionValidator(Err(CompletionValidationFailure::Incompatible)),
        second_epoch,
        ExecutorCapacity::new(1, 1, 2048, 4096, 64).expect("capacity"),
    );
    assert!(matches!(
        incompatible
            .submit_attempt(&incompatible_request)
            .expect("invalid acceleration is replaced")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    assert_eq!(incompatible.active_count(), 1);
    assert!(matches!(
        incompatible
            .ledger()
            .load_attempt(execution_key(&incompatible_request))
            .expect("replacement running state"),
        Some(AttemptRuntimeState::Running { .. })
    ));
}

#[test]
fn durable_restart_replaces_stale_running_and_preserves_completion() {
    let directory = tempfile::tempdir().expect("ledger tempdir");
    let first_epoch = daemon_epoch(0x31);
    let capacity = ExecutorCapacity::new(1, 2, 4096, 8192, 64).expect("capacity");
    let attempt_request = request(0x41, 0x61, first_epoch, resources(1, 2048, 4096));
    let first_response = {
        let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open first ledger");
        let mut supervisor =
            LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, first_epoch, capacity);
        supervisor
            .submit_attempt(&attempt_request)
            .expect("first accepted execution")
    };
    let first_execution = accepted_execution(&first_response);

    let second_epoch = daemon_epoch(0x32);
    let replacement_request = request(0x42, 0x61, second_epoch, resources(1, 2048, 4096));
    let completed_observation = observation(0x75);
    {
        let ledger =
            DirectoryAssignmentLedger::open(directory.path()).expect("open restarted ledger");
        let mut supervisor =
            LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, second_epoch, capacity);
        assert_eq!(
            supervisor
                .submit_attempt(&attempt_request)
                .expect("old exact assignment replay"),
            first_response
        );
        let replacement_response = supervisor
            .submit_attempt(&replacement_request)
            .expect("replace stale running execution");
        let replacement_execution = accepted_execution(&replacement_response);
        assert_ne!(replacement_execution, first_execution);
        assert_eq!(
            supervisor
                .complete_execution(
                    execution_key(&replacement_request),
                    replacement_execution,
                    completed_observation,
                )
                .expect("durable completion"),
            CompletionOutcome::Completed
        );
    }

    let third_epoch = daemon_epoch(0x33);
    let completed_request = request(0x43, 0x61, third_epoch, resources(1, 2048, 4096));
    let ledger = DirectoryAssignmentLedger::open(directory.path()).expect("open completed ledger");
    let mut supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, third_epoch, capacity);
    assert_eq!(
        supervisor
            .submit_attempt(&completed_request)
            .expect("completed restart replay")
            .disposition(),
        SubmitAttemptDisposition::AlreadyCompleted {
            observation: completed_observation
        }
    );
    assert_eq!(supervisor.active_count(), 0);
}

#[test]
fn capacity_configuration_rejects_unusable_limits() {
    assert_eq!(
        ExecutorCapacity::new(0, 1, 1, 0, 1),
        Err(ExecutorCapacityError::ZeroConcurrentExecutions)
    );
    assert_eq!(
        ExecutorCapacity::new(1, 0, 1, 0, 1),
        Err(ExecutorCapacityError::ZeroVcpus)
    );
    assert_eq!(
        ExecutorCapacity::new(1, 1, 0, 0, 1),
        Err(ExecutorCapacityError::ZeroResidentBytes)
    );
    assert_eq!(
        ExecutorCapacity::new(1, 1, 1, 0, 0),
        Err(ExecutorCapacityError::ZeroExecutionQuanta)
    );
}

#[derive(Clone, Copy, Debug)]
enum PublishFailure {
    BeforeStore,
    AfterStore,
}

struct CompletionValidator(Result<(), CompletionValidationFailure>);

impl AttemptAdmissionValidator for CompletionValidator {
    fn validate(&self, _request: &SubmitAttemptRequest) -> Result<(), ExecutorRejection> {
        Ok(())
    }

    fn validate_completion(
        &self,
        _request: &SubmitAttemptRequest,
        _observation: ObservationId,
    ) -> Result<(), CompletionValidationFailure> {
        self.0
    }
}

#[derive(Debug)]
struct InjectedFailure;

#[derive(Clone, Copy, Debug)]
enum CasFailure {
    BeforeStore,
    AfterStore,
}

struct FailingCasLedger {
    inner: MemoryAssignmentLedger,
    failure: CasFailure,
    fail_on_call: u32,
    calls: u32,
}

impl FailingCasLedger {
    fn new(failure: CasFailure, fail_on_call: u32) -> Self {
        Self {
            inner: MemoryAssignmentLedger::default(),
            failure,
            fail_on_call,
            calls: 0,
        }
    }
}

impl AssignmentLedger for FailingCasLedger {
    type Error = InjectedFailure;

    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        match self.inner.load_assignment(assignment) {
            Ok(record) => Ok(record),
            Err(never) => match never {},
        }
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        match self.inner.publish_assignment(record) {
            Ok(outcome) => Ok(outcome),
            Err(never) => match never {},
        }
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        match self.inner.load_attempt(key) {
            Ok(state) => Ok(state),
            Err(never) => match never {},
        }
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        self.calls += 1;
        if self.calls == self.fail_on_call {
            if matches!(self.failure, CasFailure::AfterStore) {
                match self.inner.compare_exchange_attempt(key, expected, next) {
                    Ok(_) => {}
                    Err(never) => match never {},
                }
            }
            return Err(InjectedFailure);
        }
        match self.inner.compare_exchange_attempt(key, expected, next) {
            Ok(outcome) => Ok(outcome),
            Err(never) => match never {},
        }
    }
}

struct FailingPublishLedger {
    inner: MemoryAssignmentLedger,
    failure: Option<PublishFailure>,
}

impl AssignmentLedger for FailingPublishLedger {
    type Error = InjectedFailure;

    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        match self.inner.load_assignment(assignment) {
            Ok(record) => Ok(record),
            Err(never) => match never {},
        }
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        match self.failure.take() {
            Some(PublishFailure::BeforeStore) => Err(InjectedFailure),
            Some(PublishFailure::AfterStore) => {
                match self.inner.publish_assignment(record) {
                    Ok(_) => {}
                    Err(never) => match never {},
                }
                Err(InjectedFailure)
            }
            None => match self.inner.publish_assignment(record) {
                Ok(outcome) => Ok(outcome),
                Err(never) => match never {},
            },
        }
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        match self.inner.load_attempt(key) {
            Ok(state) => Ok(state),
            Err(never) => match never {},
        }
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        match self.inner.compare_exchange_attempt(key, expected, next) {
            Ok(outcome) => Ok(outcome),
            Err(never) => match never {},
        }
    }
}

fn accepted_execution(response: &SubmitAttemptResponse) -> ExecutionId {
    match response.disposition() {
        SubmitAttemptDisposition::Accepted { execution } => execution,
        other => panic!("expected accepted execution, got {other:?}"),
    }
}

fn execution_key(request: &SubmitAttemptRequest) -> AttemptExecutionKey {
    AttemptExecutionKey::new(request.lineage(), request.attempt())
}

fn request(
    assignment_byte: u8,
    attempt_byte: u8,
    epoch: DaemonEpoch,
    resources: AttemptResourceLimits,
) -> SubmitAttemptRequest {
    request_in_lineage(
        assignment_byte,
        attempt_byte,
        0x11,
        epoch,
        resources,
        ExecutionRetentionIntent::RetainOnFailure,
    )
}

fn request_in_lineage(
    assignment_byte: u8,
    attempt_byte: u8,
    lineage_byte: u8,
    epoch: DaemonEpoch,
    resources: AttemptResourceLimits,
    retention: ExecutionRetentionIntent,
) -> SubmitAttemptRequest {
    SubmitAttemptRequest::new(
        AssignmentId::from_bytes([assignment_byte; 16]).expect("assignment"),
        epoch,
        lineage(lineage_byte),
        attempt(attempt_byte),
        resources,
        retention,
    )
    .expect("request")
}

fn lineage(byte: u8) -> CampaignLineageId {
    CampaignLineageId::parse(&typed_id(
        "crucible.campaign.lineage",
        "campaign-fact",
        byte,
    ))
    .expect("lineage")
}

fn attempt(byte: u8) -> AttemptId {
    AttemptId::parse(&typed_id(
        "crucible.campaign.attempt",
        "campaign-fact",
        byte,
    ))
    .expect("attempt")
}

fn resources(vcpus: u32, resident: u64, disk: u64) -> AttemptResourceLimits {
    AttemptResourceLimits::new(vcpus, resident, disk, 32).expect("resources")
}

fn daemon_epoch(byte: u8) -> DaemonEpoch {
    DaemonEpoch::from_bytes([byte; 16]).expect("daemon epoch")
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
    format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
