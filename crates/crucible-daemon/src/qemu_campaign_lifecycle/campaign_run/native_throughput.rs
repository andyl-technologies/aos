//! Native performance probes on the genuine admitted campaign execution path.
//!
//! The adapter changes physical placement observations only. The ordinary
//! modeled driver, canonical planner, original assignment actor, immutable
//! publication, final teardown, and durable completion reconciliation remain
//! the production implementations. It grants no public paging qualification.

use super::*;
use crate::qemu_campaign_driver::{QemuFreshModeledDriver, QemuFreshPendingObservation};
use crate::qemu_campaign_lifecycle::QemuCheckpointChoiceProvenance;
use crate::{
    AttemptExecutionContext, AttemptExecutionProduct, AttemptWorkerFailure,
    CrucibleAttemptExecution, QemuAttemptProductionVmLifecycleError, QemuFreshAttemptDriver,
    QemuFreshAttemptLifecycle, QemuFreshDriveOutcome, QemuFreshExecutionRunnerError,
    QemuFreshStartMaterialization,
};
use crucible::SchedulerEventLogEntry;
use crucible_api::host_operational::HostOperationalError;

/// Observes an actual admitted world before and after modeled guest driving.
pub(crate) trait NativeCampaignProbe: Send + Sync {
    fn before_drive(
        &self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<(), HostOperationalError>;

    fn after_drive(
        &self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<(), HostOperationalError>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeCampaignProbeError {
    #[error("native campaign placement probe failed: {0}")]
    Probe(#[source] HostOperationalError),
    #[error(transparent)]
    Driver(QemuFreshModeledDriverError),
}

type NativeCampaignRunError = GuardedDefaultCampaignRunError<
    QemuFreshExecutionRunnerError<
        QemuObservedFreshAttemptLifecycleFactoryError<QemuAttemptProductionVmLifecycleError>,
        NativeCampaignProbeError,
    >,
>;

/// Runs a normal campaign against its original charged repository and actor.
pub(crate) fn run(
    request: GuardedDefaultCampaignRunRequest,
    probe: Arc<dyn NativeCampaignProbe>,
    cancellation: crate::ExecutionCancellation,
) -> Result<GuardedDefaultCampaignRun, NativeCampaignRunError> {
    let request = request.with_execution_cancellation(cancellation);
    validate_initial_replay(&request)?;
    validate_resume_source(&request)?;
    let owner =
        request
            .execution
            .as_ref()
            .ok_or(GuardedDefaultCampaignRunError::ManagedExecution(
                HostOperationalError::Unavailable,
            ))?;
    let repository = owner.inner.repository.clone();
    let planner = owner.inner.planner.clone();
    let store = CampaignExecutorStore::new(repository.clone());
    let checkpoints = owner.inner.checkpoints.clone();
    let retention = Arc::new(CampaignRunFindingExactRetentionSource::new(
        store,
        checkpoints.clone(),
    ));
    let production = QemuAttemptProductionVmLifecycleFactory::new(
        request.lifecycle.clone(),
        ComposedQemuAttemptResourceGuardFactory::new(owner.inner.host.clone()),
    )
    .with_terminal_checkpoints(checkpoints);
    let (factory, evidence) = QemuObservedFreshAttemptLifecycleFactory::with_evidence(production);
    let runner = QemuFreshExecutionRunner::new(factory, ProbeDriver { probe })
        .with_terminal_exact_retention_source(retention.clone());
    run_guarded_default_campaign_with_repository(
        request, runner, evidence, repository, planner, retention,
    )
}

struct ProbeDriver {
    probe: Arc<dyn NativeCampaignProbe>,
}

fn driver_failure(
    failure: AttemptWorkerFailure<QemuFreshModeledDriverError>,
) -> AttemptWorkerFailure<NativeCampaignProbeError> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(NativeCampaignProbeError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(NativeCampaignProbeError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(NativeCampaignProbeError::Driver(error))
        }
    }
}

impl QemuFreshAttemptDriver for ProbeDriver {
    type Pending = QemuFreshPendingObservation;
    type Error = NativeCampaignProbeError;

    fn terminal_checkpoint_choices(
        &self,
        pending: &Self::Pending,
    ) -> Option<(QemuCheckpointChoiceProvenance, u64)> {
        QemuFreshModeledDriver.terminal_checkpoint_choices(pending)
    }

    fn has_terminal_assertion_failure(&self, pending: &Self::Pending) -> Result<bool, Self::Error> {
        QemuFreshModeledDriver
            .has_terminal_assertion_failure(pending)
            .map_err(NativeCampaignProbeError::Driver)
    }

    fn drive(
        &mut self,
        lifecycle: &mut QemuFreshAttemptLifecycle<'_>,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        materialization: QemuFreshStartMaterialization,
    ) -> Result<QemuFreshDriveOutcome<Self::Pending>, AttemptWorkerFailure<Self::Error>> {
        self.probe
            .before_drive(lifecycle, input, context)
            .map_err(|error| {
                AttemptWorkerFailure::Retryable(NativeCampaignProbeError::Probe(error))
            })?;
        let result = QemuFreshModeledDriver
            .drive(lifecycle, input, context, materialization)
            .map_err(driver_failure);
        // Even failed guest work is observed before the runner's real teardown.
        // A probe failure cannot replace an earlier classified guest failure.
        let observed = self.probe.after_drive(lifecycle, input, context);
        match result {
            Err(error) => Err(error),
            Ok(outcome) => {
                observed.map_err(|error| {
                    AttemptWorkerFailure::Retryable(NativeCampaignProbeError::Probe(error))
                })?;
                Ok(outcome)
            }
        }
    }

    fn seal(
        &mut self,
        pending: Self::Pending,
        events: Vec<SchedulerEventLogEntry>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        QemuFreshModeledDriver
            .seal(pending, events)
            .map_err(driver_failure)
    }

    fn seal_with_trace(
        &mut self,
        pending: Self::Pending,
        events: Vec<SchedulerEventLogEntry>,
        trace: Option<Vec<u8>>,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        QemuFreshModeledDriver
            .seal_with_trace(pending, events, trace)
            .map_err(driver_failure)
    }
}
