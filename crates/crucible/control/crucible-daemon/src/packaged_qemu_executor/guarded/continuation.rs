//! Durable replay promotion and fresh ownership for guarded continuations.
//!
//! A caller can continue only a checkpoint produced by this owner's accepted
//! worker and retained in its paused ledger. Replay uses independent Services;
//! publication and selected-root acquisition use the original actor. The final
//! Service has its own physical reservation and deadline, rather than copying
//! the completed source execution's capability.

use super::service_source::GuardedServiceSupervisionFailure;
use super::*;
use crate::ProductionVmLifecycleConfig;
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
    ProductionBakedGenesisReplayCatalogFactory, capture_production_baked_genesis,
};
use crucible_campaign::{AttemptExecutionScope, ExactCheckpointId};
use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};
use std::error::Error;

/// A promoted root and the fresh charged Service authorized to consume it.
pub(crate) struct GuardedContinuation {
    pub(crate) checkpoint: ExactCheckpointId,
    pub(crate) source: GuardedServiceSource,
}

/// Refusal of an unauthenticated or unsuccessful durable continuation phase.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GuardedContinuationError {
    #[error("guarded continuation refused: {0}")]
    Refused(&'static str),
    #[error("guarded continuation preparation refused: {0}")]
    Prepared(#[source] crate::PreparedSourceFailure),
    #[error("guarded continuation Original refused: {0}")]
    Supervision(#[source] GuardedServiceSupervisionFailure),
    #[error(
        "guarded continuation selected-root producer refused: {first}; retained custody: {custody}"
    )]
    Selection {
        #[source]
        first: ContinuationRootSelectionError,
        custody: crate::PreparedSourceFailure,
    },
    #[error("guarded continuation cleanup remains retained: {0}")]
    Retirement(#[source] crate::PreparedSourceRefusal),
    /// Retains the initiating capture cause beside its original Main custody.
    #[error("guarded continuation genesis capture failed: {first}; retained custody: {custody}")]
    GenesisCapture {
        #[source]
        first: Box<
            crate::ProductionBakedGenesisCaptureError<crate::QemuAttemptProductionVmLifecycleError>,
        >,
        custody: crate::PreparedSourceFailure,
    },
    /// Keeps a later receiver-return refusal separate from the capture failure.
    #[error("{first}; genesis projection return also failed: {returned}")]
    ProjectionReturn {
        #[source]
        first: Box<Self>,
        returned: Box<Self>,
    },
    /// Owns negative history even after physical retirement has completed.
    #[error("guarded continuation retirement completed with failures: {0}")]
    Terminal(#[source] Box<crate::ProductionVmConstructionPostBody>),
    #[error("guarded continuation {phase} failed: {source}")]
    Operation {
        phase: &'static str,
        #[source]
        source: Box<dyn Error + Send>,
    },
}

/// Preserves the actual actor-route or selected-ledger producer refusal.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ContinuationRootSelectionError {
    #[error("preparation was canceled")]
    Canceled,
    #[error("enter selected-root actor: {0}")]
    Route(#[source] crucible_control_api::host_operational::HostOperationalError),
    #[error("select promoted root: {0}")]
    Select(#[source] crate::executor_supervisor::LocalExecutorError<crate::AssignmentLedgerError>),
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
        let catalog_original = crucible_engine::owned_decode::current_budget().ok_or(
            GuardedContinuationError::Refused("missing original replay metadata"),
        )?;
        let mut replay = ProductionBakedGenesisReplayCatalogFactory::new(
            [baked],
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
            &catalog_original,
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

        // Select the real ledger root only after the Main owner is durable.
        // A refused projection cannot create a caller-local claim to discard.
        check_preparation(&preparation, &cancellation)?;
        let source = self
            .prepare_service_source(lifecycle.clone())
            .map_err(|first| {
                GuardedContinuationError::operation("prepare continuation Source", first)
            })?;
        let service = source.service_handle();
        match service.with_start(|startup| {
            startup.retain_reconciled_replay_root(checkpoint, || {
                self.inner
                    .actor
                    .with_supervisor(|actor| {
                        Ok(actor.select_reconciled_paused_checkpoint_root(key, checkpoint))
                    })
                    .map_err(ContinuationRootSelectionError::Route)?
                    .map_err(ContinuationRootSelectionError::Select)
            })
        }) {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(first))) => {
                return Err(GuardedContinuationError::Selection {
                    first,
                    custody: source.failure("select promoted root"),
                });
            }
            Ok(Err(_)) => {
                return Err(GuardedContinuationError::Prepared(
                    source.failure("retain promoted root before Service"),
                ));
            }
            Err(first) => {
                return Err(GuardedContinuationError::Prepared(
                    service.failure_with_refusal("borrow promoted-root Main phase", first),
                ));
            }
        }
        // The root already lives in Main across this same caller Original cut.
        // Expiry cannot require restoring a local selection after refusal.
        if cancellation.is_canceled() {
            return Err(GuardedContinuationError::Selection {
                first: ContinuationRootSelectionError::Canceled,
                custody: source.failure("preparation was canceled"),
            });
        }
        if let Err(first) = preparation.wait_slice() {
            cancellation.cancel();
            return Err(GuardedContinuationError::Supervision(
                source.supervision_failure("original preparation allowance", first),
            ));
        }
        source
            .start("admit continuation Service", |start| {
                services.start_for_replay_basis(
                    start,
                    &basis,
                    Some(checkpoint),
                    cancellation.clone(),
                )
            })
            .map_err(GuardedContinuationError::Prepared)?;
        if let Err(first) = preparation.wait_slice() {
            cancellation.cancel();
            return Err(GuardedContinuationError::Supervision(
                source.supervision_failure("check continuation preparation", first),
            ));
        }
        if cancellation.is_canceled() {
            return Err(GuardedContinuationError::Prepared(
                source.failure("continuation caller canceled"),
            ));
        }
        preparation.complete().map_err(|error| {
            cancellation.cancel();
            GuardedContinuationError::Supervision(
                source.supervision_failure("complete continuation preparation", error),
            )
        })?;
        Ok(GuardedContinuation { checkpoint, source })
    }

    fn capture_continuation_genesis(
        &self,
        basis: &ProductionCheckpointReplayBasis,
        services: &RetainedTemplateServiceFactory,
        cancellation: ExecutionCancellation,
        lifecycle: &Arc<ProductionVmLifecycleConfig>,
    ) -> Result<crate::ProductionBakedGenesisCheckpoint, GuardedContinuationError> {
        let mut source = self
            .prepare_service_source(lifecycle.clone())
            .map_err(|first| {
                GuardedContinuationError::operation("prepare genesis Source", first)
            })?;
        source
            .start("admit genesis Service", |start| {
                services.start_for_replay_basis(start, basis, None, cancellation)
            })
            .map_err(GuardedContinuationError::Prepared)?;
        let service = source.service_handle();
        let receiver = service.retain_receiver_in_main().map_err(|first| {
            GuardedContinuationError::Prepared(
                service.failure_with_refusal("retain genesis projection", first),
            )
        })?;
        let captured = source
            .with_ready("borrow genesis context", |service| {
                service.context().clone()
            })
            .map_err(GuardedContinuationError::Prepared)
            .and_then(|context| {
                capture_production_baked_genesis(&mut source.factory, basis.source(), &context)
                    .map_err(|first| GuardedContinuationError::GenesisCapture {
                        first: Box::new(first),
                        custody: source.failure("capture continuation genesis"),
                    })
            });
        // The capture's real World/body cleanup precedes this local alias cut.
        // Always attempt receiver return; its later refusal cannot replace the
        // capture's first cause. Main retains the receiver if return refuses.
        let baked = return_genesis_projection(captured, || {
            receiver.return_after_alias_destruction().map_err(|first| {
                GuardedContinuationError::Prepared(
                    service.failure_with_refusal("return genesis projection", first),
                )
            })
        })?;
        let prepared = source.factory.prepared_source_handle().map_err(|first| {
            GuardedContinuationError::Prepared(
                service.failure_with_refusal("select genesis retirement", first),
            )
        })?;
        let mut retirement = prepared.into_retirement();
        if !retirement
            .retry()
            .map_err(GuardedContinuationError::Retirement)?
        {
            return Err(GuardedContinuationError::Retirement(
                crate::PreparedSourceRefusal::Pending,
            ));
        }
        let terminal = retirement.finish().map_err(|_retained| {
            GuardedContinuationError::Retirement(crate::PreparedSourceRefusal::Pending)
        })?;
        check_genesis_retirement(terminal)?;
        Ok(baked)
    }
}

/// Attempts the actual alias return even when capture has already failed.
fn return_genesis_projection<T>(
    captured: Result<T, GuardedContinuationError>,
    return_projection: impl FnOnce() -> Result<(), GuardedContinuationError>,
) -> Result<T, GuardedContinuationError> {
    match (captured, return_projection()) {
        (Ok(baked), Ok(())) => Ok(baked),
        (Err(first), Ok(())) => Err(first),
        (Ok(_), Err(returned)) => Err(returned),
        (Err(first), Err(returned)) => Err(GuardedContinuationError::ProjectionReturn {
            first: Box::new(first),
            returned: Box::new(returned),
        }),
    }
}

/// Separates factual retirement from the semantic result retained by its body.
fn check_genesis_retirement(
    terminal: crate::ProductionVmConstructionPostBody,
) -> Result<(), GuardedContinuationError> {
    if terminal.first_failure().is_some() {
        return Err(GuardedContinuationError::Terminal(Box::new(terminal)));
    }
    Ok(())
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
    use crucible_host_resources::host_supervision::HostOperationBudgets;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn genesis_projection_return_preserves_both_failures_and_runs_once() {
        #[derive(Debug, thiserror::Error)]
        #[error("owned failure {marker}")]
        struct OwnedFailure {
            marker: usize,
            destroyed: Arc<AtomicUsize>,
        }

        impl Drop for OwnedFailure {
            fn drop(&mut self) {
                self.destroyed.fetch_or(self.marker, Ordering::SeqCst);
            }
        }

        let returns = std::cell::Cell::new(0);
        let destroyed = Arc::new(AtomicUsize::new(0));
        let result = return_genesis_projection::<()>(
            Err(GuardedContinuationError::operation(
                "capture",
                OwnedFailure {
                    marker: 1,
                    destroyed: destroyed.clone(),
                },
            )),
            || {
                returns.set(returns.get() + 1);
                Err(GuardedContinuationError::operation(
                    "receiver",
                    OwnedFailure {
                        marker: 2,
                        destroyed: destroyed.clone(),
                    },
                ))
            },
        );

        assert_eq!(returns.get(), 1);
        assert_eq!(destroyed.load(Ordering::SeqCst), 0);
        let error = result.unwrap_err();
        let initiating = error
            .source()
            .and_then(|first| first.downcast_ref::<Box<GuardedContinuationError>>())
            .unwrap();
        assert!(matches!(
            initiating.as_ref(),
            GuardedContinuationError::Operation {
                phase: "capture",
                ..
            }
        ));
        let GuardedContinuationError::ProjectionReturn { first, returned } = &error else {
            panic!("both capture and receiver failures must remain owned");
        };
        let GuardedContinuationError::Operation {
            source: capture, ..
        } = first.as_ref()
        else {
            panic!("the initiating capture cause must remain typed");
        };
        let GuardedContinuationError::Operation {
            source: receiver, ..
        } = returned.as_ref()
        else {
            panic!("the independent receiver cause must remain typed");
        };
        assert_eq!(capture.downcast_ref::<OwnedFailure>().unwrap().marker, 1);
        assert_eq!(receiver.downcast_ref::<OwnedFailure>().unwrap().marker, 2);

        drop(error);
        assert_eq!(destroyed.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn genesis_retirement_keeps_typed_terminal_failure_history() {
        assert!(
            check_genesis_retirement(crate::ProductionVmConstructionPostBody::history_only())
                .is_ok()
        );
        let mut terminal = crate::ProductionVmConstructionPostBody::history_only();
        terminal
            .retain_constructor_first(crucible_control_api::LifecycleApiError::CleanupRetained)
            .unwrap();
        terminal
            .retain_constructor_first(crucible_control_api::LifecycleApiError::ParentParkHeld)
            .unwrap();

        let error = check_genesis_retirement(terminal).unwrap_err();

        assert!(error.source().is_some());
        let GuardedContinuationError::Terminal(terminal) = error else {
            panic!("the terminal body must remain owned on failure");
        };
        assert!(matches!(
            terminal.first_failure(),
            Some(crate::LifecycleFailureRef::Control(
                crucible_control_api::LifecycleApiError::CleanupRetained
            ))
        ));
        let mut failures = 0;
        terminal.visit_history(|_, _| failures += 1);
        assert_eq!(failures, 2);
    }

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
