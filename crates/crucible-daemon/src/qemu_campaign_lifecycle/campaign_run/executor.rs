//! Admitted campaign execution and canonical local planner accounting.
//!
//! Production requests require the shared executor actor. Explicit component
//! fixtures live in a separately compiled module and grant no physical authority.

use crate::automatic_finding_runner::{
    CampaignRunFindingExactRetentionSource, FindingExactRetentionSource,
};
use crate::executor_worker::{
    publish_prepared_semantic_attempt_result, validate_prepared_semantic_attempt_result,
};
use crate::{
    AttemptExecutionDisposition, AttemptExecutionKey, AttemptExecutionModel,
    AttemptExecutionProduct, AttemptExecutionReconciliationStep, AttemptResultPreparationError,
    AttemptResultPreparationFailure, AttemptResultPublicationFailure, CheckpointCompletionOutcome,
    CheckpointPublicationOutcome, CheckpointResultStageOutcome, ExecutionCancellation,
    PreparedAttemptWorkResult, RepositoryAttemptWorker, RepositoryAttemptWorkerError,
    prepare_attempt_result, publish_staged_checkpoint_result,
    reconcile_published_checkpoint_result, stage_prepared_checkpoint_result,
};
#[cfg(any(test, feature = "test-support"))]
use crate::{
    AttemptWorkerFailure, CheckpointResultAbortError, CompletionValidationFailure,
    ExactCheckpointStore, ExactCheckpointStoreError, ExecutorCapacityError, LocalExecutorError,
    RepositoryAttemptAdmission,
};
use crucible_campaign::PurePlannerEngine;
#[cfg(any(test, feature = "test-support"))]
use crucible_campaign::{AttemptResourceLimits, DaemonEpoch};
use crucible_campaign::{
    CampaignCodecError, CampaignExecutorStore, CancelAttemptExecutionRequest,
    CancelAttemptExecutionResponse, CheckpointAttemptExecutionRequest,
    CheckpointAttemptExecutionResponse, ExecutorControlService, ExecutorResumeService,
    ExecutorService, ExecutorStatusService, GetAttemptExecutionRequest,
    GetAttemptExecutionResponse, ObservationId, PlannerExecutionSupervisor, PlannerRequest,
    ResumeAttemptExecutionRequest, ResumeAttemptExecutionResponse, SubmitAttemptDisposition,
    SubmitAttemptRequest, SubmitAttemptResponse, SupervisedPlannerExecution,
};
#[cfg(any(test, feature = "test-support"))]
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::DEFAULT_RUN_RECONCILIATION_STEPS;
mod admitted;
mod admitted_error;
use admitted_error::AdmittedCampaignError;
#[cfg(any(test, feature = "test-support"))]
mod component;

/// Measures deterministic canonical planning against its explicit work budget.
pub(crate) struct LocalPlannerMeter;

/// Reports fixed canonical planner fuel accounting refusal.
#[derive(Debug)]
pub(crate) enum LocalPlannerMeterError {
    /// The measured request size cannot fit the fuel coordinate.
    FuelOverflow,
    /// Measured work exceeds the explicit request budget.
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
    exact_retention: Arc<dyn FindingExactRetentionSource>,
    exact_inventory: Arc<CampaignRunFindingExactRetentionSource>,
    worker: RepositoryAttemptWorker<M>,
    cancellation: ExecutionCancellation,
    admitted: Option<super::GuardedCampaignOwner>,
    caller_supervisor: Option<crucible_linux_resource::host_supervision::HostOperationSupervisor>,
    #[cfg(any(test, feature = "test-support"))]
    component: Option<component::ComponentExecutionState>,
}

impl<M> SynchronousCampaignExecutor<M> {
    pub(super) fn under_caller(
        mut self,
        supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Self {
        self.caller_supervisor = Some(supervisor.clone());
        self
    }

    pub(super) fn new_admitted(
        store: CampaignExecutorStore,
        exact_retention: Arc<CampaignRunFindingExactRetentionSource>,
        model: M,
        cancellation: ExecutionCancellation,
        owner: super::GuardedCampaignOwner,
    ) -> Self {
        Self {
            worker: RepositoryAttemptWorker::new(store.clone(), model),
            store,
            exact_inventory: Arc::clone(&exact_retention),
            exact_retention,
            cancellation,
            admitted: Some(owner),
            caller_supervisor: None,
            #[cfg(any(test, feature = "test-support"))]
            component: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn new(
        store: CampaignExecutorStore,
        exact_retention: Arc<CampaignRunFindingExactRetentionSource>,
        model: M,
        admission: RepositoryAttemptAdmission,
        daemon_epoch: DaemonEpoch,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Self {
        Self {
            worker: RepositoryAttemptWorker::new(store.clone(), model),
            store,
            exact_inventory: Arc::clone(&exact_retention),
            exact_retention,
            cancellation,
            admitted: None,
            caller_supervisor: None,
            component: Some(component::ComponentExecutionState::new(
                admission,
                daemon_epoch,
                resources,
            )),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn with_checkpoint_capture(
        mut self,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Result<Self, ComponentCaptureConfigurationError> {
        let component = self
            .component
            .as_mut()
            .ok_or(ComponentCaptureConfigurationError::MissingAuthority)?;
        component
            .configure_capture(checkpoints)
            .map_err(ComponentCaptureConfigurationError::Capacity)?;
        Ok(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub(super) enum ComponentCaptureConfigurationError {
    MissingAuthority,
    Capacity(ExecutorCapacityError),
}

#[derive(Debug)]
pub(super) enum SynchronousCampaignExecutorError<E> {
    Admitted(Box<AdmittedCampaignError<E>>),
    AuthorityUnavailable,
    Protocol(crucible_campaign::CampaignCodecError),
    #[cfg(any(test, feature = "test-support"))]
    Repository(crucible_campaign::CampaignRepositoryError),
    Preparation(Box<AttemptResultPreparationFailure>),
    Publication(AttemptResultPublicationFailure),
    Execution(crate::AttemptWorkerFailure<E>),
    Reconciliation(crate::AttemptWorkerFailure<E>),
    #[cfg(any(test, feature = "test-support"))]
    Completion(CompletionValidationFailure),
    #[cfg(any(test, feature = "test-support"))]
    CaptureUnavailable,
    #[cfg(any(test, feature = "test-support"))]
    CaptureSupervisorPoisoned,
    #[cfg(any(test, feature = "test-support"))]
    CaptureSupervisor(LocalExecutorError<Infallible>),
    #[cfg(any(test, feature = "test-support"))]
    CaptureExecution(AttemptWorkerFailure<RepositoryAttemptWorkerError<E>>),
    #[cfg(any(test, feature = "test-support"))]
    CaptureCandidate(Box<AttemptResultPreparationFailure>),
    #[cfg(any(test, feature = "test-support"))]
    CaptureCheckpoint(ExactCheckpointStoreError),
    #[cfg(any(test, feature = "test-support"))]
    CaptureUnexpectedSemanticResult,
    #[cfg(any(test, feature = "test-support"))]
    CaptureAbort(Box<CheckpointResultAbortError<LocalExecutorError<Infallible>>>),
    #[cfg(any(test, feature = "test-support"))]
    CaptureNativeRetirement(crucible_api::ProductionExactCheckpointRetirementError),
    #[cfg(any(test, feature = "test-support"))]
    CaptureNotPaused,
    UnexpectedCheckpoint,
    ReconciliationLimit,
}

impl<E: fmt::Display> fmt::Display for SynchronousCampaignExecutorError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityUnavailable => {
                formatter.write_str("executor has no admitted execution authority")
            }
            Self::Admitted(error) => write!(formatter, "admitted campaign execution: {error}"),
            Self::Protocol(error) => write!(formatter, "executor protocol: {error}"),
            #[cfg(any(test, feature = "test-support"))]
            Self::Repository(error) => write!(formatter, "executor repository: {error}"),
            Self::Preparation(error) => write!(formatter, "executor result preflight: {error}"),
            Self::Publication(error) => write!(formatter, "executor result publication: {error}"),
            Self::Execution(error) => write!(formatter, "executor model: {error}"),
            Self::Reconciliation(error) => write!(formatter, "executor reconciliation: {error}"),
            #[cfg(any(test, feature = "test-support"))]
            Self::Completion(reason) => {
                write!(formatter, "executor completion validation: {reason:?}")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureUnavailable => {
                formatter.write_str("executor exact capture store is not configured")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureSupervisorPoisoned => {
                formatter.write_str("executor exact capture supervisor lock is poisoned")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureSupervisor(error) => {
                write!(formatter, "executor exact capture supervisor: {error}")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureExecution(error) => {
                write!(formatter, "executor exact capture worker: {error}")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureCandidate(error) => {
                write!(
                    formatter,
                    "executor exact capture returned a candidate: {error}"
                )
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureCheckpoint(error) => {
                write!(formatter, "executor exact checkpoint: {error}")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureUnexpectedSemanticResult => {
                formatter.write_str("executor exact capture returned a semantic observation")
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureAbort(error) => write!(formatter, "executor exact capture abort: {error}"),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureNativeRetirement(error) => {
                write!(
                    formatter,
                    "executor exact capture source retirement: {error}"
                )
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureNotPaused => {
                formatter.write_str("executor exact capture did not reach durable paused state")
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
            Self::Admitted(error) => Some(error.as_ref()),
            Self::Protocol(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::Repository(error) => Some(error),
            Self::Preparation(error) => Some(error),
            Self::Publication(error) => Some(error),
            Self::Execution(error) | Self::Reconciliation(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureSupervisor(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureExecution(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureCandidate(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureCheckpoint(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureAbort(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::CaptureNativeRetirement(error) => Some(error),
            #[cfg(any(test, feature = "test-support"))]
            Self::Completion(_)
            | Self::CaptureUnavailable
            | Self::CaptureSupervisorPoisoned
            | Self::CaptureUnexpectedSemanticResult
            | Self::CaptureNotPaused => None,
            Self::AuthorityUnavailable | Self::UnexpectedCheckpoint | Self::ReconciliationLimit => {
                None
            }
        }
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

impl<M> ExecutorService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + Send + Sync + 'static,
{
    type Error = SynchronousCampaignExecutorError<M::Error>;
    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        if let Some(owner) = self.admitted.clone() {
            return self.submit_admitted(&owner, request);
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(component) = self.component.as_mut() {
            return component.submit(
                component::ComponentExecutorLoans {
                    worker: &mut self.worker,
                    store: &self.store,
                    exact_retention: self.exact_retention.as_ref(),
                    exact_inventory: self.exact_inventory.as_ref(),
                    cancellation: &self.cancellation,
                },
                request,
            );
        }
        Err(SynchronousCampaignExecutorError::AuthorityUnavailable)
    }
}
impl<M> ExecutorStatusService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + Send + Sync + 'static,
{
    fn get_attempt_execution(
        &mut self,
        request: &GetAttemptExecutionRequest,
    ) -> Result<GetAttemptExecutionResponse, Self::Error> {
        if let Some(owner) = &self.admitted {
            return owner
                .inner
                .actor
                .with_supervisor(|actor| Ok(actor.get_attempt_execution(request)))
                .map_err(admitted::admitted_error)?
                .map_err(admitted::admitted_error);
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(component) = self.component.as_mut() {
            return component.get_attempt_execution(request);
        }
        Err(SynchronousCampaignExecutorError::AuthorityUnavailable)
    }
}
impl<M> ExecutorControlService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + Send + Sync + 'static,
{
    fn checkpoint_attempt_execution(
        &mut self,
        request: &CheckpointAttemptExecutionRequest,
    ) -> Result<CheckpointAttemptExecutionResponse, Self::Error> {
        if let Some(owner) = &self.admitted {
            return owner
                .inner
                .actor
                .with_supervisor(|actor| Ok(actor.checkpoint_attempt_execution(request)))
                .map_err(admitted::admitted_error)?
                .map_err(admitted::admitted_error);
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(component) = self.component.as_mut() {
            return component.checkpoint_attempt_execution(request);
        }
        Err(SynchronousCampaignExecutorError::AuthorityUnavailable)
    }
    fn cancel_attempt_execution(
        &mut self,
        request: &CancelAttemptExecutionRequest,
    ) -> Result<CancelAttemptExecutionResponse, Self::Error> {
        if let Some(owner) = &self.admitted {
            return owner
                .inner
                .actor
                .with_supervisor(|actor| Ok(actor.cancel_attempt_execution(request)))
                .map_err(admitted::admitted_error)?
                .map_err(admitted::admitted_error);
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(component) = self.component.as_mut() {
            return component.cancel_attempt_execution(request);
        }
        Err(SynchronousCampaignExecutorError::AuthorityUnavailable)
    }
}
impl<M> ExecutorResumeService for SynchronousCampaignExecutor<M>
where
    M: AttemptExecutionModel,
    M::Error: Error + Send + Sync + 'static,
{
    fn resume_attempt_execution(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, Self::Error> {
        if let Some(owner) = &self.admitted {
            return owner
                .inner
                .actor
                .with_supervisor(|actor| Ok(actor.resume_attempt_execution(request)))
                .map_err(admitted::admitted_error)?
                .map_err(admitted::admitted_error);
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(component) = self.component.as_mut() {
            return component.resume_attempt_execution(request);
        }
        Err(SynchronousCampaignExecutorError::AuthorityUnavailable)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- this regression deliberately poisons the owner lock.
// crucible-lint: allow rust-allow -- the same poison regression uses Rust's explicit panic lint allowance.
#[allow(clippy::expect_used, clippy::panic)]
mod lock_tests {
    use super::component::{
        CaptureSupervisorPoisoned, lock_capture_supervisor, lock_capture_supervisor_for_cleanup,
    };
    use super::*;
    use crate::{ExecutorCapacity, LocalExecutorSupervisor, MemoryAssignmentLedger};
    use std::sync::Mutex;

    use crate::executor_supervisor::AllowAllAttemptAdmission;
    use crucible_campaign::{
        AssignmentId, AttemptId, AttemptResourceLimits, CampaignLineageId, CampaignRecordKind,
        ExecutionRetentionIntent,
    };
    use crucible_cas::content_store::{ContentId, ObjectKind};

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
                CampaignRecordKind::Lineage.schema_version(),
                b"poisoned-capture-lineage",
                CampaignLineageId::parse,
            ),
            stored_id(
                "crucible.campaign.attempt",
                ObjectKind::CampaignFact,
                CampaignRecordKind::Attempt.schema_version(),
                b"poisoned-capture-attempt",
                AttemptId::parse,
            ),
            resources,
            ExecutionRetentionIntent::RetainOnFailure,
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
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
        schema_version: u32,
        bytes: &[u8],
        parse: impl FnOnce(&str) -> Result<T, CampaignCodecError>,
    ) -> T {
        let content = ContentId::for_bytes(kind, schema_version, bytes);
        parse(&format!("{tag}@{content}")).expect("typed stored ID")
    }
}
