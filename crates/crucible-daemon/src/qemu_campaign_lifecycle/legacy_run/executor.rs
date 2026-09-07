//! Synchronous planner and executor adapters for one guarded default campaign.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::{
    AttemptAdmissionValidator, AttemptExecutionContext, AttemptExecutionDisposition,
    AttemptExecutionKey, AttemptExecutionModel, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, CompletionValidationFailure, ExecutionCancellation,
    ExecutionCheckpointRequest, RepositoryAttemptAdmission, resolve_attempt_execution_input,
};
use crucible_campaign::{
    AssignmentId, AttemptResourceLimits, CampaignCodecError, CampaignExecutorStore, CampaignHash,
    CancelAttemptExecutionDisposition, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionDisposition,
    CheckpointAttemptExecutionRequest, CheckpointAttemptExecutionResponse, DaemonEpoch,
    ExecutorControlService, ExecutorRejection, ExecutorResumeService, ExecutorService,
    ExecutorStatusService, GetAttemptExecutionDisposition, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, ObservationId, PlannerExecutionSupervisor, PlannerRequest,
    PurePlannerEngine, ResumeAttemptExecutionDisposition, ResumeAttemptExecutionRequest,
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

pub(super) struct SynchronousCampaignExecutor<M> {
    store: CampaignExecutorStore,
    model: M,
    admission: RepositoryAttemptAdmission,
    daemon_epoch: DaemonEpoch,
    resources: AttemptResourceLimits,
    assignments: BTreeMap<AssignmentId, CampaignHash>,
    completed: BTreeMap<AttemptExecutionKey, ObservationId>,
}

impl<M> SynchronousCampaignExecutor<M> {
    pub(super) const fn new(
        store: CampaignExecutorStore,
        model: M,
        admission: RepositoryAttemptAdmission,
        daemon_epoch: DaemonEpoch,
        resources: AttemptResourceLimits,
    ) -> Self {
        Self {
            store,
            model,
            admission,
            daemon_epoch,
            resources,
            assignments: BTreeMap::new(),
            completed: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub(super) enum SynchronousCampaignExecutorError<E> {
    Protocol(crucible_campaign::CampaignCodecError),
    Repository(crucible_campaign::CampaignRepositoryError),
    Execution(crate::AttemptWorkerFailure<E>),
    Reconciliation(crate::AttemptWorkerFailure<E>),
    Completion(CompletionValidationFailure),
    UnexpectedCheckpoint,
    ReconciliationLimit,
}

impl<E: fmt::Display> fmt::Display for SynchronousCampaignExecutorError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "executor protocol: {error}"),
            Self::Repository(error) => write!(formatter, "executor repository: {error}"),
            Self::Execution(error) => write!(formatter, "executor model: {error}"),
            Self::Reconciliation(error) => write!(formatter, "executor reconciliation: {error}"),
            Self::Completion(reason) => {
                write!(formatter, "executor completion validation: {reason:?}")
            }
            Self::UnexpectedCheckpoint => formatter
                .write_str("standalone default run unexpectedly produced an exact checkpoint"),
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
            Self::Execution(error) | Self::Reconciliation(error) => Some(error),
            Self::Completion(_) | Self::UnexpectedCheckpoint | Self::ReconciliationLimit => None,
        }
    }
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

        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
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
        let input = resolve_attempt_execution_input(&self.store, key)
            .map_err(SynchronousCampaignExecutorError::Repository)?;
        let context = AttemptExecutionContext::new(
            request.resources(),
            request.retention(),
            ExecutionCancellation::default(),
            ExecutionCheckpointRequest::default(),
        );
        let product = match self.model.execute(&input, &context) {
            Ok(product) => product,
            Err(failure) => {
                reconcile_model(&mut self.model, AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Execution(failure));
            }
        };
        let AttemptExecutionProduct::Observation(candidate) = product else {
            reconcile_model(&mut self.model, AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::UnexpectedCheckpoint);
        };
        let observation = match self.store.publish_observation_candidate(&candidate) {
            Ok(observation) => observation,
            Err(error) => {
                reconcile_model(&mut self.model, AttemptExecutionDisposition::Failed)?;
                return Err(SynchronousCampaignExecutorError::Repository(error));
            }
        };
        if let Err(reason) = self.admission.validate_completion(request, observation) {
            reconcile_model(&mut self.model, AttemptExecutionDisposition::Failed)?;
            return Err(SynchronousCampaignExecutorError::Completion(reason));
        }
        reconcile_model(
            &mut self.model,
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

fn reconcile_model<M: AttemptExecutionModel>(
    model: &mut M,
    disposition: AttemptExecutionDisposition,
) -> Result<(), SynchronousCampaignExecutorError<M::Error>>
where
    M::Error: Error + 'static,
{
    for _ in 0..DEFAULT_RUN_RECONCILIATION_STEPS {
        match model.reconcile_execution(disposition) {
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
