//! Selects capture as the final output of the same retained construction core.
//!
//! No Loop is exported and reborrowed for capture. The actual completed body
//! remains in its original Main carrier until Source validation and commit.

use super::*;
use crate::vm_lifecycle::{ProductionVmHotForkSourceWorld, SourcePreparationBoundary};

pub(in crate::qemu_campaign_lifecycle) fn authenticate_resume_contents(
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    basis: QemuExactResumeBasis<'_>,
    context: &AttemptExecutionContext,
) -> Result<
    (
        crate::qemu_campaign_driver::QemuSelectedResumeBoundary,
        crate::vm_lifecycle::ProductionVmExactHotForkSourceBoundary,
    ),
    QemuAttemptProductionVmLifecycleError,
> {
    let QemuExactResumeBasis {
        source,
        initial,
        post_selection,
        ..
    } = basis;

    let boundary = authenticate_attempt_production_resume_boundary(
        checkpoints,
        checkpoint,
        source,
        initial,
        post_selection,
        context.cancellation(),
    )
    .map_err(|error| QemuAttemptProductionVmLifecycleError::CheckpointRestore(Box::new(error)))?;
    let scheduler = boundary.scheduler();
    if scheduler.retained_event_log_base_events() != 0 {
        return Err(QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary);
    }
    let proof = QemuSavepointReplayProof::from_reached_boundary(
        boundary.configuration(),
        scheduler.quanta(),
        scheduler.frontier(),
        scheduler.retained_event_log_entries(),
    )
    .map_err(|_| QemuAttemptProductionVmLifecycleError::InvalidResumeBoundary)?;
    let selected = crate::qemu_campaign_driver::QemuSelectedResumeBoundary::new(
        boundary
            .configuration()
            .try_clone_admitted()
            .map_err(|source| QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(source)))?,
        proof,
    );
    Ok((selected, boundary.into_hot_fork_source()))
}

impl<R> QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    pub(crate) fn capture_fresh_source_world(
        &mut self,
        source: &ScenarioDefForm,
        start: &Configuration,
        context: &AttemptExecutionContext,
    ) -> Result<ProductionVmHotForkSourceWorld, QemuAttemptProductionVmLifecycleError> {
        let prepared = self.selected_prepared_source()?;
        let network = std::mem::take(&mut self.authenticated_network_selections);
        let result = prepared.capture_fresh_source_world(
            &self.config,
            self.terminal_checkpoints.clone(),
            source,
            start,
            context,
            &network,
            &self.continuations,
        );
        if result.is_ok() {
            self.lifecycle_outstanding = true;
        }
        result
    }

    pub(crate) fn capture_exact_source_world(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        requested: &Configuration,
        context: &AttemptExecutionContext,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, QemuAttemptProductionVmLifecycleError> {
        let prepared = self.selected_prepared_source()?;
        let result = prepared.capture_exact_source_world(
            &self.config,
            self.terminal_checkpoints.clone(),
            checkpoints,
            checkpoint,
            basis,
            requested,
            context,
        );
        if matches!(&result, Ok(Some(_))) {
            self.lifecycle_outstanding = true;
        }
        result
    }
}

pub(crate) fn capture_fresh_prepared_source<R>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    config: &ProductionVmLifecycleConfig,
    terminal: Option<Arc<ExactCheckpointStore>>,
    source: &ScenarioDefForm,
    start: &Configuration,
    context: &AttemptExecutionContext,
    network: &[crucible::SelectionDecision],
    continuations: &[crate::qemu_campaign_lifecycle::OwnedQemuAttemptContinuation],
) -> Result<ProductionVmHotForkSourceWorld, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    let scenario = source.scenario_def();
    let result = fresh_prepared_source_with(
        prepared,
        terminal,
        &scenario,
        source,
        context,
        || {
            if let Some(account) = crucible::owned_decode::current_budget() {
                account.check().map_err(|source| {
                    QemuAttemptProductionVmLifecycleError::ModelCopy(Box::new(source))
                })?;
            }
            let replay = crucible::SignalFaultCampaignReplayPlan::empty(start.clone());
            let config = production_lifecycle_config_for_start(
                config,
                source,
                start,
                Some(&replay),
                network,
            )?;
            let config = production_lifecycle_config_for_continuations(config, continuations)?;
            validate_fresh_source_request(&scenario, source, context)?;
            Ok(config)
        },
        |pending| pending.prepare_hot_fork_source_world(SourcePreparationBoundary::Canonical),
    );
    result
}

pub(crate) fn capture_exact_prepared_source<R>(
    prepared: &crate::qemu_lifecycle_launcher::PreparedSourceHandle<R>,
    config: &ProductionVmLifecycleConfig,
    terminal: Option<Arc<ExactCheckpointStore>>,
    checkpoints: &ExactCheckpointStore,
    checkpoint: ExactCheckpointId,
    basis: QemuExactResumeBasis<'_>,
    requested: &Configuration,
    context: &AttemptExecutionContext,
) -> Result<Option<ProductionVmHotForkSourceWorld>, QemuAttemptProductionVmLifecycleError>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    let result = resume_prepared_source_with(
        prepared,
        config,
        terminal,
        checkpoints,
        checkpoint,
        basis,
        context,
        crate::vm_lifecycle::RetainedConstructionExposure::Released,
        || {
            let (selected, production) =
                authenticate_resume_contents(checkpoints, checkpoint, basis, context)?;
            if selected.configuration().id() != requested.id() {
                return Ok(None);
            }
            Ok(Some((selected, production)))
        },
        |pending, (selected, production)| {
            pending.prepare_hot_fork_source_world(SourcePreparationBoundary::Exact {
                requested: requested.id(),
                selected: &selected,
                production: &production,
            })
        },
    );
    result
}
