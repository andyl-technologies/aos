//! Durable replay promotion and fresh ownership for guarded continuations.
//!
//! A caller can continue only a checkpoint produced by this owner's accepted
//! worker and retained in its paused ledger. Replay uses independent Services;
//! publication and selected-root acquisition use the original actor. The final
//! Service has its own physical reservation and deadline, rather than copying
//! the completed source execution's capability.

use super::*;
use crate::paused_checkpoint_promotion::{
    PausedCheckpointPromotionStageOutcome, PreparedPausedCheckpointPromotionRestart,
    prepare_production_paused_checkpoint_promotion_restart,
    publish_staged_paused_checkpoint_promotion, reconcile_published_paused_checkpoint_promotion,
    stage_prepared_paused_checkpoint_promotion,
};
use crate::qemu_baked_genesis::ProductionCheckpointReplayBasis;
use crate::qemu_campaign_lifecycle::GuardedDefaultCampaignRun;
use crate::{
    AttemptExecutionKey, AttemptExecutionRuntimeBasis, CheckpointPromotionCompletionOutcome,
    CheckpointPromotionRestartWork, ComposedQemuAttemptResourceGuardFactory, ExecutionCancellation,
    ProductionBakedGenesisReplayCatalogFactory, QemuAttemptProductionVmLifecycleFactory,
    capture_production_baked_genesis,
};
use crucible_api::ProductionVmLifecycleConfig;
use crucible_campaign::{AttemptExecutionScope, ExactCheckpointId};
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};
use std::error::Error;

/// A promoted root and the fresh charged Service authorized to consume it.
pub(crate) struct GuardedContinuation {
    pub(crate) checkpoint: ExactCheckpointId,
    pub(crate) service: RetainedTemplateService,
}

/// Refusal of an unauthenticated or unsuccessful durable continuation phase.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GuardedContinuationError {
    #[error("guarded continuation refused: {0}")]
    Refused(&'static str),
    #[error("guarded continuation {phase} failed: {source}")]
    Operation {
        phase: &'static str,
        #[source]
        source: Box<dyn Error + Send>,
    },
}

impl GuardedContinuationError {
    fn operation(phase: &'static str, source: impl Error + Send + 'static) -> Self {
        Self::Operation {
            phase,
            source: Box::new(source),
        }
    }
}

impl GuardedCampaignOwner {
    /// Promotes an accepted capture and admits a fresh continuation Service.
    ///
    /// # Errors
    /// Refuses another owner's result, an obsolete campaign head, a nonpaused
    /// or substituted root, failed independent replay, publication or ledger
    /// reconciliation, and unavailable physical Service capacity.
    pub(crate) fn continuation(
        &self,
        run: &GuardedDefaultCampaignRun,
        cancellation: ExecutionCancellation,
        preparation_supervisor: HostOperationSupervisor,
        lifecycle: &Arc<ProductionVmLifecycleConfig>,
    ) -> Result<GuardedContinuation, GuardedContinuationError> {
        let preparation = preparation_supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(|error| GuardedContinuationError::operation("admit preparation", error))?;
        check_preparation(&preparation, &cancellation)?;
        let capture = run
            .resume()
            .and_then(|resume| resume.source_savepoint())
            .or_else(|| run.savepoint())
            .ok_or(GuardedContinuationError::Refused(
                "source capture is absent",
            ))?;
        let head = self
            .inner
            .repository
            .head(run.campaign().as_str())
            .map_err(|error| GuardedContinuationError::operation("authenticate campaign", error))?;
        check_preparation(&preparation, &cancellation)?;
        if head.snapshot_id() != run.final_snapshot() {
            return Err(GuardedContinuationError::Refused(
                "campaign head changed after source capture",
            ));
        }
        let key = AttemptExecutionKey::new_scoped(
            head.snapshot().lineage(),
            capture.attempt(),
            AttemptExecutionScope::SavepointCapture {
                request: capture.request(),
            },
        );
        let recovery = self
            .inner
            .actor
            .with_supervisor(|actor| Ok(actor.paused_checkpoint_promotion_recovery(key)))
            .map_err(|error| GuardedContinuationError::operation("read paused owner", error))?
            .map_err(|error| GuardedContinuationError::operation("read paused ledger", error))?
            .ok_or(GuardedContinuationError::Refused(
                "capture has no durable raw paused owner",
            ))?;
        if recovery.source() != capture.checkpoint() {
            return Err(GuardedContinuationError::Refused(
                "paused root differs from authenticated capture",
            ));
        }

        let store = CampaignExecutorStore::new(Arc::clone(&self.inner.repository));
        check_preparation(&preparation, &cancellation)?;
        let input = crate::resolve_attempt_execution_input_with_resources(
            &store,
            key,
            recovery.promotion_basis().resources(),
        )
        .map_err(|error| GuardedContinuationError::operation("authenticate replay input", error))?;
        check_preparation(&preparation, &cancellation)?;
        let execution = crate::decode_crucible_attempt_execution_with_resources(
            &store,
            &input,
            recovery.promotion_basis().resources(),
        )
        .map_err(|error| GuardedContinuationError::operation("decode replay input", error))?;
        check_preparation(&preparation, &cancellation)?;
        let _input_scope = execution.enter_decode_scope();
        let basis = ProductionCheckpointReplayBasis::new(
            execution.scenario(),
            recovery.promotion_basis().resources(),
            AttemptExecutionRuntimeBasis::new(key, recovery.execution()),
            recovery.promotion_basis().start_mode(),
            recovery.source(),
        )
        .map_err(|error| {
            GuardedContinuationError::operation("copy admitted replay basis", error)
        })?;
        let services = self
            .replay_services()
            .map_err(|error| GuardedContinuationError::operation("open replay allocator", error))?;
        let preparation_services = services
            .clone()
            .with_outer_supervisor(preparation_supervisor);
        let baked = self.capture_continuation_genesis(
            &basis,
            &preparation_services,
            cancellation.clone(),
            lifecycle,
        )?;
        let mut replay = ProductionBakedGenesisReplayCatalogFactory::new(
            [baked],
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        )
        .map_err(|error| GuardedContinuationError::operation("admit replay catalog", error))?
        .with_savepoint_replay_config(lifecycle.try_clone_admitted().map_err(|error| {
            GuardedContinuationError::operation("copy admitted replay lifecycle", error)
        })?)
        .with_replay_services(preparation_services);
        let mut work = CheckpointPromotionRestartWork::Paused(recovery);
        let ready = prepare_production_paused_checkpoint_promotion_restart(
            &store,
            &self.inner.checkpoints,
            &mut work,
            &self
                .inner
                .config
                .lifecycle
                .run_state_root()
                .join("guarded-continuation"),
            cancellation.clone(),
            &mut replay,
        )
        .map_err(|error| GuardedContinuationError::operation("independent replay", error))?;
        let PreparedPausedCheckpointPromotionRestart::Stage(ready) = ready else {
            return Err(GuardedContinuationError::Refused(
                "raw pause did not require replay staging",
            ));
        };
        check_preparation(&preparation, &cancellation)?;
        let staged = self
            .inner
            .actor
            .with_supervisor(|actor| Ok(stage_prepared_paused_checkpoint_promotion(actor, *ready)))
            .map_err(|error| GuardedContinuationError::operation("enter promotion actor", error))?
            .map_err(|error| GuardedContinuationError::operation("stage promotion", error))?;
        let PausedCheckpointPromotionStageOutcome::Publish(staged) = staged else {
            return Err(GuardedContinuationError::Refused(
                "paused source changed before promotion publication",
            ));
        };
        check_preparation(&preparation, &cancellation)?;
        let published =
            publish_staged_paused_checkpoint_promotion(&self.inner.checkpoints, *staged)
                .map_err(|error| GuardedContinuationError::operation("publish promotion", error))?;
        check_preparation(&preparation, &cancellation)?;
        let checkpoint = published.promoted();
        let outcome = self
            .inner
            .actor
            .with_supervisor(|actor| {
                Ok(reconcile_published_paused_checkpoint_promotion(
                    &self.inner.checkpoints,
                    actor,
                    published,
                ))
            })
            .map_err(|error| {
                GuardedContinuationError::operation("enter reconciliation actor", error)
            })?
            .map_err(|error| GuardedContinuationError::operation("reconcile promotion", error))?;
        if !matches!(
            outcome,
            CheckpointPromotionCompletionOutcome::Promoted
                | CheckpointPromotionCompletionOutcome::AlreadyPromoted
        ) {
            return Err(GuardedContinuationError::Refused(
                "promoted root is no longer the paused owner",
            ));
        }

        let mut selected = self
            .inner
            .actor
            .with_supervisor(|actor| {
                Ok(actor.select_reconciled_paused_checkpoint_root(key, checkpoint))
            })
            .map_err(|error| {
                GuardedContinuationError::operation("enter selected-root actor", error)
            })?
            .map_err(|error| GuardedContinuationError::operation("select promoted root", error))?;
        if selected.is_none() {
            return Err(GuardedContinuationError::Refused(
                "promoted root has no selected ledger authority",
            ));
        }
        check_preparation(&preparation, &cancellation)?;
        let service = services
            .start_for_replay_basis(
                &basis,
                Some(checkpoint),
                cancellation.clone(),
                &mut selected,
            )
            .map_err(|error| {
                GuardedContinuationError::operation("admit continuation Service", error)
            })?;
        check_preparation(&preparation, &cancellation)?;
        preparation.complete().map_err(|error| {
            cancellation.cancel();
            GuardedContinuationError::operation("complete preparation", error)
        })?;
        Ok(GuardedContinuation {
            checkpoint,
            service,
        })
    }

    fn capture_continuation_genesis(
        &self,
        basis: &ProductionCheckpointReplayBasis,
        services: &RetainedTemplateServiceFactory,
        cancellation: ExecutionCancellation,
        lifecycle: &Arc<ProductionVmLifecycleConfig>,
    ) -> Result<crate::ProductionBakedGenesisCheckpoint, GuardedContinuationError> {
        let mut selected = None;
        let service = services
            .start_for_replay_basis(basis, None, cancellation, &mut selected)
            .map_err(|error| GuardedContinuationError::operation("admit genesis Service", error))?;
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        );
        let capture =
            capture_production_baked_genesis(&mut factory, basis.source(), service.context());
        // The capture routine tears down its native world before returning.
        // Drop the launch facade too before proving final Service discharge.
        drop(factory);
        let baked = match capture {
            Ok(baked) => baked,
            Err(error) => {
                service.retain_after_unknown_cleanup();
                return Err(GuardedContinuationError::operation(
                    "capture genesis",
                    error,
                ));
            }
        };
        service
            .release_after_world_cleanup()
            .map_err(|error| GuardedContinuationError::operation("reap genesis Service", error))?;
        Ok(baked)
    }
}

fn check_preparation(
    operation: &HostOperationGuard,
    cancellation: &ExecutionCancellation,
) -> Result<(), GuardedContinuationError> {
    if cancellation.is_canceled() {
        return Err(GuardedContinuationError::Refused(
            "preparation was canceled",
        ));
    }
    operation.wait_slice().map(|_| ()).map_err(|error| {
        cancellation.cancel();
        GuardedContinuationError::operation("original preparation allowance", error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::HostOperationBudgets;

    #[test]
    fn terminal_preparation_cap_cancels_native_and_publication_work() {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
            .unwrap_or_else(|error| panic!("admit operational fixture: {error}"));
        let operation = supervisor
            .begin(HostOperationClass::Preparation)
            .unwrap_or_else(|error| panic!("begin preparation fixture: {error}"));
        let cancellation = ExecutionCancellation::default();
        assert!(check_preparation(&operation, &cancellation).is_ok());

        supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel fixture cap: {error}"));
        assert!(check_preparation(&operation, &cancellation).is_err());
        assert!(cancellation.is_canceled());
    }
}
