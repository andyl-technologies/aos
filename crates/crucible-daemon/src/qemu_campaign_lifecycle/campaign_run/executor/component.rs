//! Pure executor and checkpoint fixtures without managed execution authority.
//!
//! This module is compiled only for explicit component tests. Its in-memory
//! ledger and detached model contexts cannot be constructed by production runs.

use crate::automatic_finding_runner::{
    CampaignRunFindingExactRetentionSource, FindingExactRetentionSource,
};
use crate::executor_supervisor::{
    AttemptAdmissionValidator, AttemptCheckpointHandoff, ExecutionCheckpointHandoff,
};
use crate::executor_worker::{
    publish_prepared_semantic_attempt_result, validate_prepared_semantic_attempt_result,
};
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionKey,
    AttemptExecutionModel, AttemptExecutionProduct, AttemptResultPreparationError,
    AttemptResultPreparationFailure, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    CheckpointCompletionOutcome, CheckpointHandoffFailure, CheckpointPublicationOutcome,
    CheckpointResultAbortToken, CheckpointResultStageOutcome, ExactCheckpointStore,
    ExactCheckpointStoreError, ExecutionCancellation, ExecutionCheckpointRequest, ExecutorCapacity,
    ExecutorCapacityError, LocalExecutorError, LocalExecutorSupervisor, MemoryAssignmentLedger,
    PreparedAttemptCheckpoint, PreparedAttemptWorkResult, RepositoryAttemptAdmission,
    RepositoryAttemptWorker, abort_checkpoint_result, prepare_attempt_result,
    publish_staged_checkpoint_result, reconcile_published_checkpoint_result,
    stage_prepared_checkpoint_result,
};
use crucible_campaign::{
    AssignmentId, AttemptExecutionScope, AttemptResourceLimits, CampaignExecutorStore,
    CampaignHash, CancelAttemptExecutionDisposition, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, DaemonEpoch,
    ExecutorRejection, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, ObservationId, ResumeAttemptExecutionDisposition,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SubmitAttemptDisposition,
    SubmitAttemptRequest, SubmitAttemptResponse,
};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use super::{SynchronousCampaignExecutorError, reconcile_model};
use crucible_campaign::{ExecutorControlService, ExecutorService, ExecutorStatusService};

type CheckpointCaptureSupervisor =
    LocalExecutorSupervisor<MemoryAssignmentLedger, RepositoryAttemptAdmission>;

struct SynchronousCheckpointCapture {
    supervisor: Arc<Mutex<CheckpointCaptureSupervisor>>,
    checkpoints: Arc<ExactCheckpointStore>,
}

struct SynchronousCheckpointHandoff {
    supervisor: Weak<Mutex<CheckpointCaptureSupervisor>>,
    checkpoints: Arc<ExactCheckpointStore>,
    queued: crate::QueuedAttempt,
}

impl fmt::Debug for SynchronousCheckpointHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SynchronousCheckpointHandoff")
            .field("execution", &self.queued.execution())
            .field("attempt", &self.queued.request().attempt())
            .finish_non_exhaustive()
    }
}

impl AttemptCheckpointHandoff for SynchronousCheckpointHandoff {
    fn prepare_and_stage(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, CheckpointHandoffFailure> {
        let prepared = self
            .checkpoints
            .prepare_attempt_checkpoint_with_cancellation(capture, self.queued.cancellation())
            .map_err(|error| match error {
                ExactCheckpointStoreError::Canceled => CheckpointHandoffFailure::Canceled,
                error if error.is_retryable() => CheckpointHandoffFailure::Retryable,
                _ => CheckpointHandoffFailure::Terminal,
            })?;
        let Some(supervisor) = self.supervisor.upgrade() else {
            return Err(CheckpointHandoffFailure::Terminal);
        };
        let mut supervisor =
            lock_capture_supervisor(&supervisor).map_err(|_| CheckpointHandoffFailure::Terminal)?;
        match supervisor.stage_checkpoint_publication_before_teardown(&self.queued, prepared.root())
        {
            Ok(CheckpointPublicationOutcome::Staged)
            | Ok(CheckpointPublicationOutcome::AlreadyStaged)
            | Ok(CheckpointPublicationOutcome::AlreadyPaused) => Ok(prepared),
            Ok(CheckpointPublicationOutcome::NotCurrent)
                if self.queued.cancellation().is_canceled() =>
            {
                Err(CheckpointHandoffFailure::Canceled)
            }
            Ok(CheckpointPublicationOutcome::NotCurrent) => Err(CheckpointHandoffFailure::Terminal),
            Err(_) => Err(CheckpointHandoffFailure::Terminal),
        }
    }
}

pub(super) struct ComponentExecutionState {
    admission: RepositoryAttemptAdmission,
    daemon_epoch: DaemonEpoch,
    resources: AttemptResourceLimits,
    assignments: BTreeMap<AssignmentId, CampaignHash>,
    completed: BTreeMap<AttemptExecutionKey, ObservationId>,
    checkpoint_capture: Option<SynchronousCheckpointCapture>,
}

/// Borrows the common executor inputs for one component-only submission.
pub(super) struct ComponentExecutorLoans<'a, M> {
    pub(super) worker: &'a mut RepositoryAttemptWorker<M>,
    pub(super) store: &'a CampaignExecutorStore,
    pub(super) exact_retention: &'a dyn FindingExactRetentionSource,
    pub(super) exact_inventory: &'a CampaignRunFindingExactRetentionSource,
    pub(super) cancellation: &'a ExecutionCancellation,
}

impl ComponentExecutionState {
    pub(super) fn new(
        admission: RepositoryAttemptAdmission,
        daemon_epoch: DaemonEpoch,
        resources: AttemptResourceLimits,
    ) -> Self {
        Self {
            admission,
            daemon_epoch,
            resources,
            assignments: BTreeMap::new(),
            completed: BTreeMap::new(),
            checkpoint_capture: None,
        }
    }

    pub(super) fn configure_capture(
        &mut self,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Result<(), ExecutorCapacityError> {
        let capacity = ExecutorCapacity::new(
            1,
            self.resources.maximum_vcpus(),
            self.resources.maximum_resident_bytes(),
            self.resources.maximum_disk_bytes(),
            self.resources.maximum_execution_quanta(),
        )?;
        let supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            self.admission.clone(),
            self.daemon_epoch,
            capacity,
        )
        .with_component_operation_budgets();
        self.checkpoint_capture = Some(SynchronousCheckpointCapture {
            supervisor: Arc::new(Mutex::new(supervisor)),
            checkpoints,
        });
        Ok(())
    }

    pub(super) fn submit<M: AttemptExecutionModel>(
        &mut self,
        loans: ComponentExecutorLoans<'_, M>,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>>
    where
        M::Error: Error + Send + Sync + 'static,
    {
        let ComponentExecutorLoans {
            worker,
            store,
            exact_retention,
            exact_inventory,
            cancellation,
        } = loans;

        if request.execution_scope() != AttemptExecutionScope::Semantic {
            return self.submit_checkpoint_capture(worker, store, exact_inventory, request);
        }
        if request.daemon_epoch() != self.daemon_epoch {
            return SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Unauthorized,
                },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol);
        }
        if request.resources() != self.resources {
            return SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol);
        }
        if request.execution_scope() != AttemptExecutionScope::Semantic {
            return SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol);
        }
        if let Err(reason) = self.admission.validate(request) {
            return SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Rejected { reason },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol);
        }
        let request_digest = request.request_digest();
        if self
            .assignments
            .get(&request.assignment())
            .is_some_and(|retained| retained != &request_digest)
        {
            return SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::ConflictingAssignment,
                },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol);
        }
        self.assignments
            .entry(request.assignment())
            .or_insert(request_digest);

        let key = AttemptExecutionKey::for_request(request);
        if let Some(observation) = self.completed.get(&key).copied() {
            self.admission
                .validate_completion(request, observation)
                .map_err(SynchronousCampaignExecutorError::Completion)?;
            return SubmitAttemptResponse::new(
                request,
                SubmitAttemptDisposition::AlreadyCompleted { observation },
            )
            .map_err(SynchronousCampaignExecutorError::Protocol);
        }
        let input =
            crate::resolve_attempt_execution_input_with_resources(store, key, request.resources())
                .map_err(SynchronousCampaignExecutorError::Repository)?;
        let context = AttemptExecutionContext::new(
            request.resources(),
            request.retention(),
            cancellation.clone(),
            ExecutionCheckpointRequest::default(),
            request.retention_policy(),
        );
        let product = match worker.model_mut().execute(&input, &context) {
            Ok(product) => product,
            Err(failure) => {
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Execution(failure));
            }
        };
        let result = match product {
            AttemptExecutionProduct::PreparedSemantic(result) => Ok(*result),
            AttemptExecutionProduct::ExactCheckpoint(_) => {
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::UnexpectedCheckpoint);
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Preparation(Box::new(
                    AttemptResultPreparationFailure::Result(error),
                )));
            }
        };
        if let Err(error) = validate_prepared_semantic_attempt_result(store, key, &result) {
            reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::Preparation(Box::new(
                error,
            )));
        }
        let observation =
            match publish_prepared_semantic_attempt_result(store, exact_retention, &result) {
                Ok(observation) => observation,
                Err(error) => {
                    reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                    return Err(SynchronousCampaignExecutorError::Publication(error));
                }
            };
        if let Err(reason) = self.admission.validate_completion(request, observation) {
            reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::Completion(reason));
        }
        reconcile_model(
            worker.model_mut(),
            AttemptExecutionDisposition::Observation(observation),
        )?;
        self.completed.insert(key, observation);
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::AlreadyCompleted { observation },
        )
        .map_err(SynchronousCampaignExecutorError::Protocol)
    }
}
impl ComponentExecutionState {
    fn submit_checkpoint_capture<M: AttemptExecutionModel>(
        &mut self,
        worker: &mut RepositoryAttemptWorker<M>,
        store: &CampaignExecutorStore,
        exact_inventory: &CampaignRunFindingExactRetentionSource,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>>
    where
        M::Error: Error + Send + Sync + 'static,
    {
        let capture = self
            .checkpoint_capture
            .as_ref()
            .ok_or(SynchronousCampaignExecutorError::CaptureUnavailable)?;
        let supervisor = Arc::clone(&capture.supervisor);
        let checkpoints = Arc::clone(&capture.checkpoints);
        let response = {
            let mut supervisor = lock_capture_supervisor(&supervisor)
                .map_err(|_| SynchronousCampaignExecutorError::CaptureSupervisorPoisoned)?;
            supervisor
                .submit_attempt(request)
                .map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?
        };
        if !matches!(
            response.disposition(),
            SubmitAttemptDisposition::Accepted { .. }
        ) {
            return Ok(response);
        }

        let mut queued = {
            let mut capture_supervisor = lock_capture_supervisor(&supervisor)
                .map_err(|_| SynchronousCampaignExecutorError::CaptureSupervisorPoisoned)?;
            capture_supervisor
                .next_queued()
                .ok_or(SynchronousCampaignExecutorError::CaptureNotPaused)?
        };
        let handoff = SynchronousCheckpointHandoff {
            supervisor: Arc::downgrade(&supervisor),
            checkpoints: Arc::clone(&checkpoints),
            queued: queued.reconciliation_copy(),
        };
        queued.install_checkpoint_handoff(ExecutionCheckpointHandoff::new(Arc::new(handoff)));

        let work = worker.execute(queued);
        let prepared = match prepare_attempt_result(store, &checkpoints, work) {
            Ok(PreparedAttemptWorkResult::ExactCheckpoint(prepared)) => *prepared,
            Ok(PreparedAttemptWorkResult::Observation(prepared)) => {
                let queued = prepared.queued().reconciliation_copy();
                let cleanup = stop_capture_terminally(&supervisor, &queued);
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                return Err(SynchronousCampaignExecutorError::CaptureUnexpectedSemanticResult);
            }
            Err(AttemptResultPreparationError::Worker { queued, failure }) => {
                let cleanup = stop_capture_after_worker_failure(&supervisor, &queued, &failure);
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                return Err(SynchronousCampaignExecutorError::CaptureExecution(failure));
            }
            Err(AttemptResultPreparationError::Candidate { pending, source }) => {
                let (queued, _) = pending.into_parts();
                let cleanup = stop_capture_terminally(&supervisor, &queued);
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                return Err(SynchronousCampaignExecutorError::CaptureCandidate(source));
            }
            Err(AttemptResultPreparationError::Checkpoint { pending, source }) => {
                let (queued, checkpoint) = pending.into_parts();
                let retirement = checkpoint_result_retirement(checkpoint);
                let cleanup = stop_capture_terminally(&supervisor, &queued);
                let retirement = retire_checkpoint_source(retirement);
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                retirement?;
                return Err(SynchronousCampaignExecutorError::CaptureCheckpoint(*source));
            }
        };

        let checkpoint = prepared.root();
        let staged = match lock_capture_supervisor(&supervisor) {
            Ok(mut capture_supervisor) => {
                stage_prepared_checkpoint_result(&mut capture_supervisor, prepared)
            }
            Err(_) => {
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Prepared(Box::new(prepared)),
                );
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureSupervisorPoisoned);
            }
        };
        let staged = match staged {
            Ok(CheckpointResultStageOutcome::Publish(staged)) => staged,
            Ok(CheckpointResultStageOutcome::Finished {
                prepared,
                outcome: CheckpointPublicationOutcome::AlreadyPaused,
                ..
            }) => {
                let retirement = retire_checkpoint_source(prepared.native_retirement());
                exact_inventory
                    .retain_checkpoint(checkpoint)
                    .map_err(|_| SynchronousCampaignExecutorError::CaptureNotPaused)?;
                reconcile_model(
                    worker.model_mut(),
                    AttemptExecutionDisposition::ExactCheckpoint(checkpoint),
                )?;
                retirement?;
                return Ok(response);
            }
            Ok(CheckpointResultStageOutcome::Finished { prepared, .. }) => {
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Prepared(prepared),
                );
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureNotPaused);
            }
            Err(error) => {
                let source = error.source;
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Prepared(error.prepared),
                );
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureSupervisor(source));
            }
        };
        let published = match publish_staged_checkpoint_result(&checkpoints, *staged) {
            Ok(published) => published,
            Err(error) => {
                let source = error.source;
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Staged(error.staged),
                );
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureCheckpoint(source));
            }
        };
        let completion = match lock_capture_supervisor(&supervisor) {
            Ok(mut capture_supervisor) => {
                reconcile_published_checkpoint_result(&mut capture_supervisor, published)
            }
            Err(_) => {
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Published(Box::new(published)),
                );
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureSupervisorPoisoned);
            }
        };
        match completion {
            Ok(
                CheckpointCompletionOutcome::Paused | CheckpointCompletionOutcome::AlreadyPaused,
            ) => {
                exact_inventory
                    .retain_checkpoint(checkpoint)
                    .map_err(|_| SynchronousCampaignExecutorError::CaptureNotPaused)?;
                reconcile_model(
                    worker.model_mut(),
                    AttemptExecutionDisposition::ExactCheckpoint(checkpoint),
                )?;
                Ok(response)
            }
            Ok(CheckpointCompletionOutcome::NotCurrent) => {
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                Err(SynchronousCampaignExecutorError::CaptureNotPaused)
            }
            Err(error) => {
                let source = error.source;
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Published(error.published),
                );
                reconcile_model(worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                Err(SynchronousCampaignExecutorError::CaptureSupervisor(source))
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CaptureSupervisorPoisoned;

pub(super) fn lock_capture_supervisor<V>(
    supervisor: &Arc<Mutex<LocalExecutorSupervisor<MemoryAssignmentLedger, V>>>,
) -> Result<
    std::sync::MutexGuard<'_, LocalExecutorSupervisor<MemoryAssignmentLedger, V>>,
    CaptureSupervisorPoisoned,
> {
    supervisor.lock().map_err(|_| CaptureSupervisorPoisoned)
}

pub(super) fn lock_capture_supervisor_for_cleanup<V>(
    supervisor: &Arc<Mutex<LocalExecutorSupervisor<MemoryAssignmentLedger, V>>>,
) -> std::sync::MutexGuard<'_, LocalExecutorSupervisor<MemoryAssignmentLedger, V>> {
    // A poisoned owner rejects every new operation. Cleanup alone recovers the
    // retained linear state so native resources can be retired or quarantined.
    supervisor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn stop_capture_after_worker_failure<E>(
    supervisor: &Arc<Mutex<CheckpointCaptureSupervisor>>,
    queued: &crate::QueuedAttempt,
    failure: &AttemptWorkerFailure<E>,
) -> Result<(), LocalExecutorError<Infallible>> {
    let mut supervisor = lock_capture_supervisor_for_cleanup(supervisor);
    match failure {
        AttemptWorkerFailure::Canceled(_) => supervisor
            .stage_and_reconcile_cancellation(queued)
            .map(|_| ()),
        AttemptWorkerFailure::Retryable(_) | AttemptWorkerFailure::Terminal(_) => supervisor
            .stage_and_reconcile_terminal_failure(queued)
            .map(|_| ()),
    }
}

fn stop_capture_terminally(
    supervisor: &Arc<Mutex<CheckpointCaptureSupervisor>>,
    queued: &crate::QueuedAttempt,
) -> Result<(), LocalExecutorError<Infallible>> {
    lock_capture_supervisor_for_cleanup(supervisor)
        .stage_and_reconcile_terminal_failure(queued)
        .map(|_| ())
}

fn abort_checkpoint_capture<E>(
    supervisor: &Arc<Mutex<CheckpointCaptureSupervisor>>,
    token: CheckpointResultAbortToken,
) -> Result<(), SynchronousCampaignExecutorError<E>> {
    let retirement = token.native_retirement();
    let mut supervisor = lock_capture_supervisor_for_cleanup(supervisor);
    let abort = abort_checkpoint_result(&mut supervisor, token)
        .map_err(|error| SynchronousCampaignExecutorError::CaptureAbort(Box::new(error)));
    drop(supervisor);

    let retirement = retire_checkpoint_source(retirement);
    abort.and(retirement)
}

fn checkpoint_result_retirement(
    checkpoint: crate::AttemptCheckpointResult,
) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
    match checkpoint.into_state() {
        crate::exact_checkpoint_store::AttemptCheckpointResultState::Captured(checkpoint) => {
            Some((*checkpoint).into_closure().native_retirement())
        }
        crate::exact_checkpoint_store::AttemptCheckpointResultState::Prepared(checkpoint) => {
            checkpoint.native_retirement()
        }
    }
}

fn retire_checkpoint_source<E>(
    retirement: Option<crucible_api::ProductionExactCheckpointRetirement>,
) -> Result<(), SynchronousCampaignExecutorError<E>> {
    let Some(retirement) = retirement else {
        return Ok(());
    };
    crucible_api::retire_production_exact_checkpoint_catalog(&retirement)
        .map(|_| ())
        .map_err(SynchronousCampaignExecutorError::CaptureNativeRetirement)
}

impl ComponentExecutionState {
    pub(super) fn get_attempt_execution<E>(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, SynchronousCampaignExecutorError<E>> {
        if request.execution_scope() != AttemptExecutionScope::Semantic {
            let capture = self
                .checkpoint_capture
                .as_ref()
                .ok_or(SynchronousCampaignExecutorError::CaptureUnavailable)?;
            return lock_capture_supervisor(&capture.supervisor)
                .map_err(|_| SynchronousCampaignExecutorError::CaptureSupervisorPoisoned)?
                .get_attempt_execution(request)
                .map_err(SynchronousCampaignExecutorError::CaptureSupervisor);
        }
        GetAttemptExecutionResponse::new(request, GetAttemptExecutionDisposition::NotCurrent)
            .map_err(SynchronousCampaignExecutorError::<E>::Protocol)
    }
    pub(super) fn checkpoint_attempt_execution<E>(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, SynchronousCampaignExecutorError<E>> {
        if request.execution_scope() != AttemptExecutionScope::Semantic {
            let capture = self
                .checkpoint_capture
                .as_ref()
                .ok_or(SynchronousCampaignExecutorError::CaptureUnavailable)?;
            return lock_capture_supervisor(&capture.supervisor)
                .map_err(|_| SynchronousCampaignExecutorError::CaptureSupervisorPoisoned)?
                .checkpoint_attempt_execution(request)
                .map_err(SynchronousCampaignExecutorError::CaptureSupervisor);
        }
        CheckpointAttemptExecutionResponse::new(
            request,
            CheckpointAttemptExecutionDisposition::NotCurrent,
        )
        .map_err(SynchronousCampaignExecutorError::<E>::Protocol)
    }
    pub(super) fn cancel_attempt_execution<E>(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, SynchronousCampaignExecutorError<E>> {
        if request.execution_scope() != AttemptExecutionScope::Semantic {
            let capture = self
                .checkpoint_capture
                .as_ref()
                .ok_or(SynchronousCampaignExecutorError::CaptureUnavailable)?;
            return lock_capture_supervisor(&capture.supervisor)
                .map_err(|_| SynchronousCampaignExecutorError::CaptureSupervisorPoisoned)?
                .cancel_attempt_execution(request)
                .map_err(SynchronousCampaignExecutorError::CaptureSupervisor);
        }
        CancelAttemptExecutionResponse::new(request, CancelAttemptExecutionDisposition::NotCurrent)
            .map_err(SynchronousCampaignExecutorError::<E>::Protocol)
    }
    pub(super) fn resume_attempt_execution<E>(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, SynchronousCampaignExecutorError<E>> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(SynchronousCampaignExecutorError::<E>::Protocol)
    }
}
