//! Synchronous planner and executor adapters for one guarded default campaign.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use crate::executor_supervisor::{AttemptCheckpointHandoff, ExecutionCheckpointHandoff};
use crate::executor_worker::{
    publish_prepared_semantic_attempt_result, validate_prepared_semantic_attempt_result,
};
use crate::{
    AttemptAdmissionValidator, AttemptExecutionContext, AttemptExecutionDisposition,
    AttemptExecutionKey, AttemptExecutionModel, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, AttemptFindingRetentionPolicy,
    AttemptResultPreparationError, AttemptResultPreparationFailure,
    AttemptResultPublicationFailure, AttemptWorkerFailure, CapturedAttemptCheckpoint,
    CheckpointCompletionOutcome, CheckpointHandoffFailure, CheckpointPublicationOutcome,
    CheckpointResultAbortError, CheckpointResultAbortToken, CheckpointResultStageOutcome,
    CompletionValidationFailure, ExactCheckpointStore, ExactCheckpointStoreError,
    ExecutionCancellation, ExecutionCheckpointRequest, ExecutorCapacity, ExecutorCapacityError,
    LocalExecutorError, LocalExecutorSupervisor, MemoryAssignmentLedger, PreparedAttemptCheckpoint,
    PreparedAttemptWorkResult, PreparedFindingExactRetention, PreparedSemanticAttemptResult,
    PreparedSemanticResultCodecError, RepositoryAttemptAdmission, RepositoryAttemptWorker,
    RepositoryAttemptWorkerError, abort_checkpoint_result, prepare_attempt_result,
    publish_staged_checkpoint_result, reconcile_published_checkpoint_result,
    stage_prepared_checkpoint_result,
};
use crucible_campaign::{
    AssignmentId, AttemptExecutionScope, AttemptResourceLimits, CampaignCodecError,
    CampaignExecutorStore, CampaignHash, CancelAttemptExecutionDisposition,
    CancelAttemptExecutionRequest, CancelAttemptExecutionResponse,
    CheckpointAttemptExecutionDisposition, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, DaemonEpoch, ExecutorControlService, ExecutorRejection,
    ExecutorResumeService, ExecutorService, ExecutorStatusService, FindingExactPins,
    FindingExactRetention, FindingExactRetentionDisposition, FindingExactRetentionIncomplete,
    GetAttemptExecutionDisposition, GetAttemptExecutionRequest, GetAttemptExecutionResponse,
    ObservationId, PlannerExecutionSupervisor, PlannerRequest, PurePlannerEngine,
    ResumeAttemptExecutionDisposition, ResumeAttemptExecutionRequest,
    ResumeAttemptExecutionResponse, SubmitAttemptDisposition, SubmitAttemptRequest,
    SubmitAttemptResponse, SupervisedPlannerExecution,
};

use super::DEFAULT_RUN_RECONCILIATION_STEPS;

pub(super) struct LocalPlannerMeter;

#[derive(Debug)]
pub(super) enum LocalPlannerMeterError {
    FuelOverflow,
    FuelExceeded,
}

impl fmt::Display for LocalPlannerMeterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FuelOverflow => formatter.write_str("canonical planner measured fuel overflow"),
            Self::FuelExceeded => {
                formatter.write_str("canonical planner measured fuel exceeds request budget")
            }
        }
    }
}

impl Error for LocalPlannerMeterError {}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalFrontierPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalSearchPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalSearchPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalPuctPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalPuctPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

impl PlannerExecutionSupervisor<crucible_campaign::CanonicalBeamPlanner> for LocalPlannerMeter {
    type Error = LocalPlannerMeterError;

    fn execute(
        &mut self,
        engine: &mut crucible_campaign::CanonicalBeamPlanner,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(LocalPlannerMeterError::FuelOverflow)?;
        if measured_fuel > request.invocation().budget().fuel() {
            return Err(LocalPlannerMeterError::FuelExceeded);
        }
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

pub(super) struct SynchronousCampaignExecutor<M> {
    store: CampaignExecutorStore,
    worker: RepositoryAttemptWorker<M>,
    admission: RepositoryAttemptAdmission,
    daemon_epoch: DaemonEpoch,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    assignments: BTreeMap<AssignmentId, CampaignHash>,
    completed: BTreeMap<AttemptExecutionKey, ObservationId>,
    checkpoint_capture: Option<SynchronousCheckpointCapture>,
}

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
            .prepare_attempt_checkpoint_with_cancellation(
                capture.reopenable_copy(),
                self.queued.cancellation(),
            )
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

impl<M> SynchronousCampaignExecutor<M> {
    pub(super) fn new(
        store: CampaignExecutorStore,
        model: M,
        admission: RepositoryAttemptAdmission,
        daemon_epoch: DaemonEpoch,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Self {
        Self {
            worker: RepositoryAttemptWorker::new(store.clone(), model),
            store,
            admission,
            daemon_epoch,
            resources,
            cancellation,
            assignments: BTreeMap::new(),
            completed: BTreeMap::new(),
            checkpoint_capture: None,
        }
    }

    pub(super) fn with_checkpoint_capture(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Result<Self, ExecutorCapacityError> {
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
        );
        self.checkpoint_capture = Some(SynchronousCheckpointCapture {
            supervisor: Arc::new(Mutex::new(supervisor)),
            checkpoints,
        });
        Ok(self)
    }
}

#[derive(Debug)]
pub(super) enum SynchronousCampaignExecutorError<E> {
    Protocol(crucible_campaign::CampaignCodecError),
    Repository(crucible_campaign::CampaignRepositoryError),
    Preparation(AttemptResultPreparationFailure),
    Publication(AttemptResultPublicationFailure),
    Execution(crate::AttemptWorkerFailure<E>),
    Reconciliation(crate::AttemptWorkerFailure<E>),
    Completion(CompletionValidationFailure),
    CaptureUnavailable,
    CaptureSupervisorPoisoned,
    CaptureSupervisor(LocalExecutorError<Infallible>),
    CaptureExecution(AttemptWorkerFailure<RepositoryAttemptWorkerError<E>>),
    CaptureCandidate(AttemptResultPreparationFailure),
    CaptureCheckpoint(ExactCheckpointStoreError),
    CaptureUnexpectedSemanticResult,
    CaptureAbort(Box<CheckpointResultAbortError<LocalExecutorError<Infallible>>>),
    CaptureNativeRetirement {
        source: crucible_api::ProductionExactCheckpointRetirementError,
        _retirement: crucible_api::ProductionExactCheckpointRetirement,
    },
    CaptureNativeCleanupRetained {
        terminal: Vec<(
            crucible_api::ProductionExactCheckpointRetirementError,
            crucible_api::ProductionExactCheckpointRetirement,
        )>,
        quarantined: Vec<crucible_api::ProductionExactCheckpointRetirement>,
    },
    CaptureNotPaused,
    UnexpectedCheckpoint,
    FindingExactRetentionMismatch {
        reason: &'static str,
    },
    ReconciliationLimit,
}

impl<E: fmt::Display> fmt::Display for SynchronousCampaignExecutorError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "executor protocol: {error}"),
            Self::Repository(error) => write!(formatter, "executor repository: {error}"),
            Self::Preparation(error) => write!(formatter, "executor result preflight: {error}"),
            Self::Publication(error) => write!(formatter, "executor result publication: {error}"),
            Self::Execution(error) => write!(formatter, "executor model: {error}"),
            Self::Reconciliation(error) => write!(formatter, "executor reconciliation: {error}"),
            Self::Completion(reason) => {
                write!(formatter, "executor completion validation: {reason:?}")
            }
            Self::CaptureUnavailable => {
                formatter.write_str("executor exact capture store is not configured")
            }
            Self::CaptureSupervisorPoisoned => {
                formatter.write_str("executor exact capture supervisor lock is poisoned")
            }
            Self::CaptureSupervisor(error) => {
                write!(formatter, "executor exact capture supervisor: {error}")
            }
            Self::CaptureExecution(error) => {
                write!(formatter, "executor exact capture worker: {error}")
            }
            Self::CaptureCandidate(error) => {
                write!(
                    formatter,
                    "executor exact capture returned a candidate: {error}"
                )
            }
            Self::CaptureCheckpoint(error) => {
                write!(formatter, "executor exact checkpoint: {error}")
            }
            Self::CaptureUnexpectedSemanticResult => {
                formatter.write_str("executor exact capture returned a semantic observation")
            }
            Self::CaptureAbort(error) => write!(formatter, "executor exact capture abort: {error}"),
            Self::CaptureNativeRetirement { source, .. } => {
                write!(
                    formatter,
                    "executor exact capture source retirement: {source}"
                )
            }
            Self::CaptureNativeCleanupRetained {
                terminal,
                quarantined,
            } => write!(
                formatter,
                "executor retained {} terminal and {} quarantined native checkpoint catalogs",
                terminal.len(),
                quarantined.len()
            ),
            Self::CaptureNotPaused => {
                formatter.write_str("executor exact capture did not reach durable paused state")
            }
            Self::UnexpectedCheckpoint => formatter
                .write_str("standalone default run unexpectedly produced an exact checkpoint"),
            Self::FindingExactRetentionMismatch { reason } => {
                write!(
                    formatter,
                    "executor finding exact-retention mismatch: {reason}"
                )
            }
            Self::ReconciliationLimit => formatter
                .write_str("execution owner reconciliation exceeded its bounded step count"),
        }
    }
}

impl<E> Error for SynchronousCampaignExecutorError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Repository(error) => Some(error),
            Self::Preparation(error) => Some(error),
            Self::Publication(error) => Some(error),
            Self::Execution(error) | Self::Reconciliation(error) => Some(error),
            Self::CaptureSupervisor(error) => Some(error),
            Self::CaptureExecution(error) => Some(error),
            Self::CaptureCandidate(error) => Some(error),
            Self::CaptureCheckpoint(error) => Some(error),
            Self::CaptureAbort(error) => Some(error),
            Self::CaptureNativeRetirement { source, .. } => Some(source),
            Self::CaptureNativeCleanupRetained { terminal, .. } => terminal
                .first()
                .map(|(source, _)| source as &(dyn Error + 'static)),
            Self::Completion(_)
            | Self::CaptureUnavailable
            | Self::CaptureSupervisorPoisoned
            | Self::CaptureUnexpectedSemanticResult
            | Self::CaptureNotPaused
            | Self::UnexpectedCheckpoint
            | Self::FindingExactRetentionMismatch { .. }
            | Self::ReconciliationLimit => None,
        }
    }
}

enum SynchronousSemanticResultError {
    Preparation(PreparedSemanticResultCodecError),
    FindingExactRetentionMismatch(&'static str),
}

fn prepare_synchronous_finding_exact_retention(
    context: &AttemptExecutionContext,
    result: &mut PreparedSemanticAttemptResult,
    retention: PreparedFindingExactRetention,
    checkpoints: Option<&ExactCheckpointStore>,
) -> Result<(), SynchronousSemanticResultError> {
    validate_synchronous_finding_exact_retention(context, result, &retention)?;

    let (basis, exact_pins, authenticated_candidates, disposition, evidence) = match retention {
        PreparedFindingExactRetention::Disabled { basis } => (
            basis,
            FindingExactPins::default(),
            0,
            FindingExactRetentionDisposition::Disabled,
            None,
        ),
        PreparedFindingExactRetention::Incomplete { basis, reason, .. } => (
            basis,
            FindingExactPins::default(),
            0,
            FindingExactRetentionDisposition::Incomplete(reason),
            None,
        ),
        PreparedFindingExactRetention::Captured { basis, checkpoint } => {
            let selected = checkpoints
                .ok_or(FindingExactRetentionIncomplete::DurableStagingFailed)
                .and_then(|checkpoints| {
                    prepare_synchronous_finding_exact_capture(checkpoints, result, checkpoint)
                });
            match selected {
                Ok((pins, candidates, evidence)) => (
                    basis,
                    pins,
                    candidates,
                    FindingExactRetentionDisposition::Complete,
                    Some(evidence),
                ),
                Err(reason) => (
                    basis,
                    FindingExactPins::default(),
                    0,
                    FindingExactRetentionDisposition::Incomplete(reason),
                    None,
                ),
            }
        }
    };
    let exact_retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        authenticated_candidates,
        disposition,
    )
    .map_err(|_| {
        SynchronousSemanticResultError::Preparation(
            PreparedSemanticResultCodecError::Inconsistent {
                component: "synchronous finding exact retention evidence",
            },
        )
    })?;
    let finding = result
        .prepare_bound_finding_exact_retention(exact_pins, exact_retention, evidence)
        .map_err(SynchronousSemanticResultError::Preparation)?;
    result.commit_bound_production_replay_finding(finding);
    Ok(())
}

fn validate_synchronous_finding_exact_retention(
    context: &AttemptExecutionContext,
    result: &PreparedSemanticAttemptResult,
    retention: &PreparedFindingExactRetention,
) -> Result<(), SynchronousSemanticResultError> {
    let policy = context.finding_retention_policy().ok_or(
        SynchronousSemanticResultError::FindingExactRetentionMismatch(
            "finding exact-retention handoff has no authenticated request policy",
        ),
    )?;
    if policy.basis() != retention.basis() {
        return Err(
            SynchronousSemanticResultError::FindingExactRetentionMismatch(
                "finding exact-retention handoff differs from authenticated request policy",
            ),
        );
    }
    let finding = result.finding().ok_or(
        SynchronousSemanticResultError::FindingExactRetentionMismatch(
            "finding exact-retention handoff has no finding",
        ),
    )?;
    if finding.bundle().exact_retention().is_some() {
        return Err(
            SynchronousSemanticResultError::FindingExactRetentionMismatch(
                "finding exact retention was already bound before executor handoff",
            ),
        );
    }

    let disposition_matches = match (policy.retention(), retention) {
        (None, PreparedFindingExactRetention::Incomplete { reason, .. }) => {
            *reason == FindingExactRetentionIncomplete::MissingAuthenticatedPolicyBasis
        }
        (Some(policy), PreparedFindingExactRetention::Disabled { .. }) => !policy.exact_findings(),
        (Some(policy), PreparedFindingExactRetention::Captured { .. }) => policy.exact_findings(),
        (Some(policy), PreparedFindingExactRetention::Incomplete { reason, .. }) => {
            policy.exact_findings()
                && *reason != FindingExactRetentionIncomplete::MissingAuthenticatedPolicyBasis
        }
        (None, _) => false,
    };
    if !disposition_matches {
        return Err(
            SynchronousSemanticResultError::FindingExactRetentionMismatch(
                "finding exact-retention disposition differs from authenticated request policy",
            ),
        );
    }
    Ok(())
}

fn prepare_synchronous_finding_exact_capture(
    checkpoints: &ExactCheckpointStore,
    result: &PreparedSemanticAttemptResult,
    checkpoint: CapturedAttemptCheckpoint,
) -> Result<
    (
        FindingExactPins,
        u32,
        crucible_campaign::FindingExactRetentionEvidence,
    ),
    FindingExactRetentionIncomplete,
> {
    let prepared = checkpoints
        .prepare_attempt_checkpoint(checkpoint)
        .map_err(|_| FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let captured = checkpoints
        .publish_attempt_checkpoint(&prepared)
        .map_err(|_| FindingExactRetentionIncomplete::DurableStagingFailed)?
        .root();
    let finding = result
        .finding()
        .ok_or(FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let scenario = crate::decode_crucible_scenario_artifact(finding.scenario())
        .map_err(|_| FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let configuration = finding.original_configuration().configuration();
    let mut candidates = crate::executor_pool::FindingExactCandidateAccumulator::new(
        checkpoints,
        &scenario,
        configuration,
    );
    candidates.consider(captured);
    let candidates = candidates.finish()?;
    crate::executor_pool::select_finding_exact_retention_from_candidates(
        result,
        captured,
        &candidates,
    )
}

impl<M> ExecutorService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + 'static,
{
    type Error = SynchronousCampaignExecutorError<M::Error>;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        if request.execution_scope() != AttemptExecutionScope::Semantic {
            return self.submit_checkpoint_capture(request);
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
        let input = crate::resolve_attempt_execution_input_with_resources(
            &self.store,
            key,
            request.resources(),
        )
        .map_err(SynchronousCampaignExecutorError::Repository)?;
        let finding_retention = request
            .retention_policy_basis()
            .map(|basis| {
                self.store
                    .validate_attempt_retention_policy_basis(
                        request.lineage(),
                        request.attempt(),
                        basis,
                    )
                    .map(|retention| AttemptFindingRetentionPolicy::new(basis, retention))
            })
            .transpose()
            .map_err(SynchronousCampaignExecutorError::Repository)?;
        let context = AttemptExecutionContext::new(
            request.resources(),
            request.retention(),
            self.cancellation.clone(),
            ExecutionCheckpointRequest::default(),
        )
        .with_finding_retention_policy(finding_retention);
        let execution = self.worker.model_mut().execute(&input, &context);
        complete_checkpoint_cleanup(self.worker.model_mut().take_abandoned_native_checkpoint())?;
        let product = match execution {
            Ok(product) => product,
            Err(failure) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Execution(failure));
            }
        };
        let result = match product {
            AttemptExecutionProduct::Observation(candidate) => {
                PreparedSemanticAttemptResult::new(*candidate, None)
                    .map_err(SynchronousSemanticResultError::Preparation)
            }
            AttemptExecutionProduct::ObservationWithFinding {
                observation,
                finding,
            } => {
                if context.finding_retention_policy().is_some() {
                    Err(
                        SynchronousSemanticResultError::FindingExactRetentionMismatch(
                            "policy-bound finding omitted exact-retention handoff",
                        ),
                    )
                } else {
                    PreparedSemanticAttemptResult::new(*observation, Some(*finding))
                        .map_err(SynchronousSemanticResultError::Preparation)
                }
            }
            AttemptExecutionProduct::PreparedSemantic(result) => {
                if context.finding_retention_policy().is_some() && result.finding().is_some() {
                    Err(
                        SynchronousSemanticResultError::FindingExactRetentionMismatch(
                            "policy-bound finding omitted exact-retention handoff",
                        ),
                    )
                } else {
                    Ok(*result)
                }
            }
            AttemptExecutionProduct::PreparedSemanticWithExactRetention {
                mut result,
                retention,
            } => {
                let retirement = retention
                    .checkpoint()
                    .and_then(CapturedAttemptCheckpoint::native_retirement);
                let checkpoints = self
                    .checkpoint_capture
                    .as_ref()
                    .map(|capture| capture.checkpoints.as_ref());
                let prepared = prepare_synchronous_finding_exact_retention(
                    &context,
                    &mut result,
                    *retention,
                    checkpoints,
                );
                retire_checkpoint_source(retirement)?;
                prepared.map(|()| *result)
            }
            AttemptExecutionProduct::ExactCheckpoint(checkpoint) => {
                retire_checkpoint_source(checkpoint_result_retirement(*checkpoint))?;
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::UnexpectedCheckpoint);
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(SynchronousSemanticResultError::Preparation(error)) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Preparation(
                    AttemptResultPreparationFailure::Result(error),
                ));
            }
            Err(SynchronousSemanticResultError::FindingExactRetentionMismatch(reason)) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(
                    SynchronousCampaignExecutorError::FindingExactRetentionMismatch { reason },
                );
            }
        };
        if let Err(error) = validate_prepared_semantic_attempt_result(&self.store, key, &result) {
            reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::Preparation(error));
        }
        let observation = match publish_prepared_semantic_attempt_result(&self.store, &result) {
            Ok(observation) => observation,
            Err(error) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Publication(error));
            }
        };
        if let Err(reason) = self.admission.validate_completion(request, observation) {
            reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::Completion(reason));
        }
        reconcile_model(
            self.worker.model_mut(),
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

impl<M> SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + 'static,
{
    fn submit_checkpoint_capture(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, SynchronousCampaignExecutorError<M::Error>> {
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

        let work = self.worker.execute(queued);
        let prepared = match prepare_attempt_result(&self.store, &checkpoints, work) {
            Ok(PreparedAttemptWorkResult::ExactCheckpoint(prepared)) => *prepared,
            Ok(PreparedAttemptWorkResult::Observation(prepared)) => {
                let queued = prepared.queued().reconciliation_copy();
                let cleanup = stop_capture_terminally(&supervisor, &queued);
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                return Err(SynchronousCampaignExecutorError::CaptureUnexpectedSemanticResult);
            }
            Err(AttemptResultPreparationError::Worker {
                queued,
                failure,
                retirement,
            }) => {
                let cleanup = stop_capture_after_worker_failure(&supervisor, &queued, &failure);
                let retirement = complete_checkpoint_cleanup(retirement);
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                retirement?;
                return Err(SynchronousCampaignExecutorError::CaptureExecution(failure));
            }
            Err(AttemptResultPreparationError::Candidate { pending, source }) => {
                let (queued, _candidate, retention) = pending.into_parts();
                if let Some(checkpoint) = retention
                    .as_ref()
                    .and_then(crate::PreparedFindingExactRetention::checkpoint)
                {
                    retire_checkpoint_source(checkpoint.native_retirement())?;
                }
                let cleanup = stop_capture_terminally(&supervisor, &queued);
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                return Err(SynchronousCampaignExecutorError::CaptureCandidate(source));
            }
            Err(AttemptResultPreparationError::Checkpoint { pending, source }) => {
                let (queued, checkpoint) = pending.into_parts();
                let retirement = checkpoint_result_retirement(checkpoint);
                let cleanup = stop_capture_terminally(&supervisor, &queued);
                let retirement = retire_checkpoint_source(retirement);
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup.map_err(SynchronousCampaignExecutorError::CaptureSupervisor)?;
                retirement?;
                return Err(SynchronousCampaignExecutorError::CaptureCheckpoint(source));
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
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
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
                reconcile_model(
                    self.worker.model_mut(),
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
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureNotPaused);
            }
            Err(error) => {
                let source = error.source;
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Prepared(error.prepared),
                );
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
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
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
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
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                return Err(SynchronousCampaignExecutorError::CaptureSupervisorPoisoned);
            }
        };
        match completion {
            Ok(
                CheckpointCompletionOutcome::Paused | CheckpointCompletionOutcome::AlreadyPaused,
            ) => {
                reconcile_model(
                    self.worker.model_mut(),
                    AttemptExecutionDisposition::ExactCheckpoint(checkpoint),
                )?;
                Ok(response)
            }
            Ok(CheckpointCompletionOutcome::NotCurrent) => {
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                Err(SynchronousCampaignExecutorError::CaptureNotPaused)
            }
            Err(error) => {
                let source = error.source;
                let cleanup = abort_checkpoint_capture(
                    &supervisor,
                    CheckpointResultAbortToken::Published(error.published),
                );
                reconcile_model(self.worker.model_mut(), AttemptExecutionDisposition::Failed)?;
                cleanup?;
                Err(SynchronousCampaignExecutorError::CaptureSupervisor(source))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CaptureSupervisorPoisoned;

fn lock_capture_supervisor<V>(
    supervisor: &Arc<Mutex<LocalExecutorSupervisor<MemoryAssignmentLedger, V>>>,
) -> Result<
    std::sync::MutexGuard<'_, LocalExecutorSupervisor<MemoryAssignmentLedger, V>>,
    CaptureSupervisorPoisoned,
> {
    supervisor.lock().map_err(|_| CaptureSupervisorPoisoned)
}

fn lock_capture_supervisor_for_cleanup<V>(
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
        crate::exact_checkpoint_store::AttemptCheckpointResultState::Captured(
            CapturedAttemptCheckpoint::SingleNode(_),
        ) => None,
        crate::exact_checkpoint_store::AttemptCheckpointResultState::Captured(
            CapturedAttemptCheckpoint::Production(checkpoint),
        ) => Some(checkpoint.native_retirement()),
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
    match crucible_api::retire_production_exact_checkpoint_catalog(&retirement) {
        Ok(_) => Ok(()),
        Err(source) => Err(SynchronousCampaignExecutorError::CaptureNativeRetirement {
            source,
            _retirement: retirement,
        }),
    }
}

fn complete_checkpoint_cleanup<E>(
    cleanup: Option<crate::NativeCheckpointCleanup>,
) -> Result<(), SynchronousCampaignExecutorError<E>> {
    let Some(cleanup) = cleanup else {
        return Ok(());
    };
    let (retirements, quarantined) = partition_checkpoint_cleanup(cleanup);
    let mut terminal = Vec::new();
    for retirement in retirements {
        if let Err(retained) = retire_checkpoint_once(retirement) {
            terminal.push(retained);
        }
    }
    if terminal.is_empty() && quarantined.is_empty() {
        Ok(())
    } else {
        Err(
            SynchronousCampaignExecutorError::CaptureNativeCleanupRetained {
                terminal,
                quarantined,
            },
        )
    }
}

fn partition_checkpoint_cleanup(
    cleanup: crate::NativeCheckpointCleanup,
) -> (
    Vec<crucible_api::ProductionExactCheckpointRetirement>,
    Vec<crucible_api::ProductionExactCheckpointRetirement>,
) {
    let mut retirements = Vec::new();
    let mut quarantined = Vec::new();
    let mut pending = vec![cleanup];
    while let Some(cleanup) = pending.pop() {
        match cleanup {
            crate::NativeCheckpointCleanup::Retire(retirement) => retirements.push(retirement),
            crate::NativeCheckpointCleanup::Quarantine(retirement) => {
                quarantined.push(retirement);
            }
            crate::NativeCheckpointCleanup::Batch(cleanups) => pending.extend(cleanups),
        }
    }
    (retirements, quarantined)
}

fn retire_checkpoint_once(
    retirement: crucible_api::ProductionExactCheckpointRetirement,
) -> Result<
    (),
    (
        crucible_api::ProductionExactCheckpointRetirementError,
        crucible_api::ProductionExactCheckpointRetirement,
    ),
> {
    match crucible_api::retire_production_exact_checkpoint_catalog(&retirement) {
        Ok(_) => Ok(()),
        Err(error) => Err((error, retirement)),
    }
}

fn reconcile_model<M: AttemptExecutionModel>(
    model: &mut M,
    disposition: AttemptExecutionDisposition,
) -> Result<(), SynchronousCampaignExecutorError<M::Error>>
where
    M::Error: Error + 'static,
{
    for _ in 0..DEFAULT_RUN_RECONCILIATION_STEPS {
        let reconciliation = model.reconcile_execution(disposition);
        complete_checkpoint_cleanup(model.take_abandoned_native_checkpoint())?;
        match reconciliation {
            Ok(AttemptExecutionReconciliationStep::Complete) => return Ok(()),
            Ok(AttemptExecutionReconciliationStep::Progressed) => {}
            Err(error) => {
                return Err(SynchronousCampaignExecutorError::Reconciliation(error));
            }
        }
    }
    Err(SynchronousCampaignExecutorError::ReconciliationLimit)
}

impl<M> ExecutorStatusService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + 'static,
{
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
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
            .map_err(SynchronousCampaignExecutorError::<M::Error>::Protocol)
    }
}

impl<M> ExecutorControlService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + 'static,
{
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
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
        .map_err(SynchronousCampaignExecutorError::<M::Error>::Protocol)
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
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
            .map_err(SynchronousCampaignExecutorError::<M::Error>::Protocol)
    }
}

impl<M> ExecutorResumeService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + 'static,
{
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        ResumeAttemptExecutionResponse::new(request, ResumeAttemptExecutionDisposition::NotCurrent)
            .map_err(SynchronousCampaignExecutorError::<M::Error>::Protocol)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- this regression deliberately poisons the owner lock.
// crucible-lint: allow rust-allow -- the same poison regression uses Rust's explicit panic lint allowance.
#[allow(clippy::expect_used, clippy::panic)]
mod lock_tests {
    use super::*;

    use crate::AllowAllAttemptAdmission;
    use crucible_campaign::{
        AssignmentId, AttemptId, AttemptResourceLimits, AttemptRetentionPolicyBasis,
        CampaignExecutorStore, CampaignLineageId, CampaignRepository, ExactCheckpointId,
        ExecutionRetentionIntent, ExecutorCompatibilityProfile,
    };
    use crucible_cas::content_store::{
        ContentId, DirectoryBlobBackend, MemoryBlobBackend, MemoryRefBackend, ObjectKind,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RetentionRecordingModel {
        product: Option<AttemptExecutionProduct>,
        observed: Arc<Mutex<Option<AttemptFindingRetentionPolicy>>>,
        calls: Arc<AtomicUsize>,
    }

    impl AttemptExecutionModel for RetentionRecordingModel {
        type Error = Infallible;

        fn execute(
            &mut self,
            _input: &crate::AttemptExecutionInput,
            context: &AttemptExecutionContext,
        ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.observed.lock().expect("recorded retention policy") =
                context.finding_retention_policy();
            Ok(self.product.take().expect("recording model executes once"))
        }
    }

    #[test]
    fn synchronous_executor_authenticates_and_carries_finding_retention_policy() {
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "synchronous-retention-positive",
                64 * 1024 * 1024,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let (lineage, _policy, _branch, admitted, candidate) =
            crate::executor_pool::tests::campaign_attempt_fixture(
                &repository,
                "synchronous-retention-positive",
            );
        let basis = repository
            .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
            .expect("retention policy basis");
        let epoch = DaemonEpoch::from_bytes([0x71; 16]).expect("daemon epoch");
        let resources = AttemptResourceLimits::new(1, 4096, 8192, 64).expect("resources");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x72; 16]).expect("assignment"),
            epoch,
            lineage.id().expect("lineage ID"),
            admitted.attempt,
            resources,
            ExecutionRetentionIntent::Discard,
        )
        .expect("submit request")
        .with_retention_policy_basis(basis)
        .expect("policy-bound submit request");
        let observed = Arc::new(Mutex::new(None));
        let calls = Arc::new(AtomicUsize::new(0));
        let model = RetentionRecordingModel {
            product: Some(AttemptExecutionProduct::observation(candidate)),
            observed: Arc::clone(&observed),
            calls: Arc::clone(&calls),
        };
        let mut executor = SynchronousCampaignExecutor::new(
            CampaignExecutorStore::new(Arc::clone(&repository)),
            model,
            RepositoryAttemptAdmission::new(
                Arc::clone(&repository),
                ExecutorCompatibilityProfile::from_lineage(&lineage),
            ),
            epoch,
            resources,
            ExecutionCancellation::default(),
        );

        let response = executor
            .submit_attempt(&request)
            .expect("policy-bound synchronous execution");

        assert!(matches!(
            response.disposition(),
            SubmitAttemptDisposition::AlreadyCompleted { .. }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let recorded = observed
            .lock()
            .expect("recorded retention policy")
            .expect("model received retention policy");
        assert_eq!(recorded.basis(), basis);
        assert!(
            recorded
                .retention()
                .expect("authenticated retention policy")
                .exact_findings()
        );
    }

    #[test]
    fn synchronous_executor_binds_and_publishes_incomplete_exact_retention() {
        let blob_root = tempfile::tempdir().expect("campaign blob root");
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(DirectoryBlobBackend::new(
                "synchronous-retention-publication",
                blob_root.path(),
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let checkpoint = exact_checkpoint_id(b"synchronous-retention-publication-checkpoint");
        let fixture = crate::crucible_artifact::tests::prepared_finding_recovery_fixture(
            &repository,
            "synchronous-retention-publication",
            checkpoint,
        );
        let basis = repository
            .attempt_retention_policy_basis_at(
                repository
                    .head("synchronous-retention-publication")
                    .expect("campaign head")
                    .snapshot_id(),
                fixture.attempt,
            )
            .expect("retention policy basis");
        let reason = FindingExactRetentionIncomplete::MissingSafeBoundaryCapture;
        let handoff = PreparedFindingExactRetention::Incomplete {
            basis,
            reason,
            discarded_checkpoint: None,
        };
        let expected_result = fixture.unbound_result.clone();
        let expected_retention = FindingExactRetention::new(
            basis.snapshot(),
            basis.policy(),
            basis.admission(),
            0,
            FindingExactRetentionDisposition::Incomplete(reason),
        )
        .expect("expected exact retention");
        let expected_finding = expected_result
            .prepare_bound_finding_exact_retention(
                FindingExactPins::default(),
                expected_retention,
                None,
            )
            .expect("expected bound finding");
        let expected_finding_id = expected_finding.id().expect("expected finding ID");
        let epoch = DaemonEpoch::from_bytes([0x75; 16]).expect("daemon epoch");
        let resources = AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x76; 16]).expect("assignment"),
            epoch,
            fixture.lineage.id().expect("lineage ID"),
            fixture.attempt,
            resources,
            ExecutionRetentionIntent::Discard,
        )
        .expect("submit request")
        .with_retention_policy_basis(basis)
        .expect("policy-bound submit request");
        let model = RetentionRecordingModel {
            product: Some(
                AttemptExecutionProduct::prepared_semantic_with_exact_retention(
                    fixture.unbound_result,
                    handoff,
                ),
            ),
            observed: Arc::new(Mutex::new(None)),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut executor = SynchronousCampaignExecutor::new(
            CampaignExecutorStore::new(Arc::clone(&repository)),
            model,
            RepositoryAttemptAdmission::new(
                Arc::clone(&repository),
                ExecutorCompatibilityProfile::from_lineage(&fixture.lineage),
            ),
            epoch,
            resources,
            ExecutionCancellation::default(),
        );

        let response = executor
            .submit_attempt(&request)
            .expect("publish incomplete exact retention");

        assert!(matches!(
            response.disposition(),
            SubmitAttemptDisposition::AlreadyCompleted { .. }
        ));
        let published = repository
            .load_finding_candidate_bundle(expected_finding_id)
            .expect("published finding candidate");
        assert_eq!(
            published
                .exact_retention()
                .expect("published exact retention")
                .disposition(),
            FindingExactRetentionDisposition::Incomplete(reason)
        );
    }

    #[test]
    fn synchronous_executor_rejects_a_handoff_that_disables_enabled_exact_retention() {
        let blob_root = tempfile::tempdir().expect("campaign blob root");
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(DirectoryBlobBackend::new(
                "synchronous-retention-handoff-mismatch",
                blob_root.path(),
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let checkpoint = exact_checkpoint_id(b"synchronous-retention-handoff-mismatch-checkpoint");
        let fixture = crate::crucible_artifact::tests::prepared_finding_recovery_fixture(
            &repository,
            "synchronous-retention-handoff-mismatch",
            checkpoint,
        );
        let basis = repository
            .attempt_retention_policy_basis_at(
                repository
                    .head("synchronous-retention-handoff-mismatch")
                    .expect("campaign head")
                    .snapshot_id(),
                fixture.attempt,
            )
            .expect("retention policy basis");
        let epoch = DaemonEpoch::from_bytes([0x77; 16]).expect("daemon epoch");
        let resources = AttemptResourceLimits::new(1, 1024, 2048, 32).expect("resources");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x78; 16]).expect("assignment"),
            epoch,
            fixture.lineage.id().expect("lineage ID"),
            fixture.attempt,
            resources,
            ExecutionRetentionIntent::Discard,
        )
        .expect("submit request")
        .with_retention_policy_basis(basis)
        .expect("policy-bound submit request");
        let model = RetentionRecordingModel {
            product: Some(
                AttemptExecutionProduct::prepared_semantic_with_exact_retention(
                    fixture.unbound_result,
                    PreparedFindingExactRetention::Disabled { basis },
                ),
            ),
            observed: Arc::new(Mutex::new(None)),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut executor = SynchronousCampaignExecutor::new(
            CampaignExecutorStore::new(Arc::clone(&repository)),
            model,
            RepositoryAttemptAdmission::new(
                Arc::clone(&repository),
                ExecutorCompatibilityProfile::from_lineage(&fixture.lineage),
            ),
            epoch,
            resources,
            ExecutionCancellation::default(),
        );

        let error = executor
            .submit_attempt(&request)
            .expect_err("disabled handoff must not satisfy enabled exact retention");

        assert!(matches!(
            error,
            SynchronousCampaignExecutorError::FindingExactRetentionMismatch { .. }
        ));
    }

    #[test]
    fn synchronous_executor_rejects_a_foreign_finding_retention_policy_basis() {
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "synchronous-retention-negative",
                64 * 1024 * 1024,
            )),
            Arc::new(MemoryRefBackend::new()),
        ));
        let (lineage, _policy, _branch, admitted, candidate) =
            crate::executor_pool::tests::campaign_attempt_fixture(
                &repository,
                "synchronous-retention-negative",
            );
        let basis = repository
            .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
            .expect("retention policy basis");
        let foreign_basis =
            AttemptRetentionPolicyBasis::new(basis.snapshot(), basis.admission(), None);
        let epoch = DaemonEpoch::from_bytes([0x73; 16]).expect("daemon epoch");
        let resources = AttemptResourceLimits::new(1, 4096, 8192, 64).expect("resources");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x74; 16]).expect("assignment"),
            epoch,
            lineage.id().expect("lineage ID"),
            admitted.attempt,
            resources,
            ExecutionRetentionIntent::Discard,
        )
        .expect("submit request")
        .with_retention_policy_basis(foreign_basis)
        .expect("foreign policy-bound request");
        let calls = Arc::new(AtomicUsize::new(0));
        let model = RetentionRecordingModel {
            product: Some(AttemptExecutionProduct::observation(candidate)),
            observed: Arc::new(Mutex::new(None)),
            calls: Arc::clone(&calls),
        };
        let mut executor = SynchronousCampaignExecutor::new(
            CampaignExecutorStore::new(Arc::clone(&repository)),
            model,
            RepositoryAttemptAdmission::new(
                Arc::clone(&repository),
                ExecutorCompatibilityProfile::from_lineage(&lineage),
            ),
            epoch,
            resources,
            ExecutionCancellation::default(),
        );

        let response = executor
            .submit_attempt(&request)
            .expect("foreign policy rejection response");

        assert!(
            matches!(
                response.disposition(),
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                }
            ),
            "{response:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn standalone_mixed_cleanup_retires_safe_catalog_before_retaining_quarantines() {
        let retired_state = tempfile::tempdir().expect("standalone retired state");
        let retired_fixture =
            crucible_api::build_authenticated_production_checkpoint_codec_fixture(
                retired_state.path(),
            )
            .expect("standalone retired fixture");
        let retired = retired_fixture.closure().native_retirement();
        let first_state = tempfile::tempdir().expect("first standalone quarantine state");
        let first_fixture = crucible_api::build_authenticated_production_checkpoint_codec_fixture(
            first_state.path(),
        )
        .expect("first standalone quarantine fixture");
        let first = first_fixture.closure().native_retirement();
        let second_state = tempfile::tempdir().expect("second standalone quarantine state");
        let second_fixture = crucible_api::build_authenticated_production_checkpoint_codec_fixture(
            second_state.path(),
        )
        .expect("second standalone quarantine fixture");
        let second = second_fixture.closure().native_retirement();
        let cleanup = crate::NativeCheckpointCleanup::Batch(vec![
            crate::NativeCheckpointCleanup::Quarantine(first.clone()),
            crate::NativeCheckpointCleanup::Retire(retired.clone()),
            crate::NativeCheckpointCleanup::Quarantine(second.clone()),
        ]);

        let error = complete_checkpoint_cleanup::<Infallible>(Some(cleanup))
            .expect_err("standalone cleanup must surface quarantined catalogs");

        assert!(matches!(
            error,
            SynchronousCampaignExecutorError::CaptureNativeCleanupRetained {
                terminal,
                quarantined,
            } if terminal.is_empty() && quarantined.len() == 2
        ));
        let repeated = crucible_api::retire_production_exact_checkpoint_catalog(&retired)
            .expect("repeat standalone safe retirement");
        assert!(!repeated.retired());
        assert!(
            crucible_api::retire_production_exact_checkpoint_catalog(&first)
                .expect("release first standalone quarantine")
                .retired()
        );
        assert!(
            crucible_api::retire_production_exact_checkpoint_catalog(&second)
                .expect("release second standalone quarantine")
                .retired()
        );
    }

    #[test]
    fn poisoned_capture_owner_rejects_new_work_but_allows_controlled_cleanup() {
        let epoch = DaemonEpoch::from_bytes([0x61; 16]).expect("daemon epoch");
        let capacity = ExecutorCapacity::new(1, 1, 4096, 8192, 64).expect("capacity");
        let resources = AttemptResourceLimits::new(1, 2048, 4096, 32).expect("attempt resources");
        let request = SubmitAttemptRequest::new(
            AssignmentId::from_bytes([0x62; 16]).expect("assignment"),
            epoch,
            stored_id(
                "crucible.campaign.lineage",
                ObjectKind::CampaignFact,
                b"poisoned-capture-lineage",
                CampaignLineageId::parse,
            ),
            stored_id(
                "crucible.campaign.attempt",
                ObjectKind::CampaignFact,
                b"poisoned-capture-attempt",
                AttemptId::parse,
            ),
            resources,
            ExecutionRetentionIntent::RetainOnFailure,
        )
        .expect("submit request");
        let mut supervisor = LocalExecutorSupervisor::new(
            MemoryAssignmentLedger::default(),
            AllowAllAttemptAdmission,
            epoch,
            capacity,
        );
        supervisor
            .submit_attempt(&request)
            .expect("accept capture work before poison");
        let queued = supervisor
            .next_queued()
            .expect("accepted work remains cleanup-owned");
        let owner = Arc::new(Mutex::new(supervisor));
        let poison_target = Arc::clone(&owner);
        let poison = std::thread::spawn(move || {
            let _guard = lock_capture_supervisor_for_cleanup(&poison_target);
            panic!("poison the capture owner");
        })
        .join();

        assert!(poison.is_err());
        assert!(matches!(
            lock_capture_supervisor(&owner),
            Err(CaptureSupervisorPoisoned)
        ));
        let mut cleanup = lock_capture_supervisor_for_cleanup(&owner);
        cleanup
            .stage_and_reconcile_terminal_failure(&queued)
            .expect("cleanup reaches a durable terminal state");
        assert_eq!(cleanup.active_count(), 0);
        assert_eq!(cleanup.queued_count(), 0);
        drop(cleanup);

        assert!(matches!(
            lock_capture_supervisor(&owner),
            Err(CaptureSupervisorPoisoned)
        ));
    }

    fn stored_id<T>(
        tag: &str,
        kind: ObjectKind,
        bytes: &[u8],
        parse: impl FnOnce(&str) -> Result<T, CampaignCodecError>,
    ) -> T {
        let content = ContentId::for_bytes(kind, 1, bytes);
        parse(&format!("{tag}@{content}")).expect("typed stored ID")
    }

    fn exact_checkpoint_id(bytes: &[u8]) -> ExactCheckpointId {
        let content = ContentId::for_bytes(
            ObjectKind::ExactManifest,
            crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
            bytes,
        );
        ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@{content}"
        ))
        .expect("exact checkpoint ID")
    }
}
