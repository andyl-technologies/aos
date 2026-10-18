//! Receiver archive realization through the original guarded capacity actor.
//!
//! Genesis owns its pristine imported input in the same Main before effects.
//! A checked physical-return cut exports that parent-paid input once to replay.

use super::*;
use crate::imported_checkpoint::{
    AuthenticatedImportedCheckpoint, ImportedCheckpointHandoffFailure,
};
use crate::qemu_baked_genesis::{
    ImportedProductionCheckpointReplay, ImportedProductionReplayError,
};

enum ImportedGenesisCaptureFailure {
    Prepared(crate::PreparedSourceFailure),
    Capture(
        crate::ProductionBakedGenesisCaptureError<crate::QemuAttemptProductionVmLifecycleError>,
    ),
}

impl GuardedCampaignOwner {
    /// Consumes one receiver-authenticated archive into a fresh verification World.
    ///
    /// The exact parent input remains Main-owned through independent genesis.
    /// Replay receives that same untouched input only after real genesis body,
    /// controls, World loans and projected aliases have physically returned.
    ///
    /// # Errors
    /// Refuses incompatible backend, admission, authentication, capture or
    /// cleanup. Refusal retains actual input and independent raw return causes;
    /// no source-local execution identity or maintenance authority is copied.
    pub fn begin_imported_checkpoint(
        &self,
        imported: AuthenticatedImportedCheckpoint<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<ImportedProductionCheckpointReplay, ImportedProductionReplayError> {
        let (capsule, owner) = imported.into_start_custody();
        let mut source = self
            .prepare_imported_service_source(capsule)
            .map_err(ImportedProductionReplayError::Preparation)?;
        source
            .start("validate imported genesis input", |start| {
                start.check_imported_receiver(
                    crate::host_operational_registry::operational_identity(
                        self.inner.config.daemon_epoch.as_bytes(),
                    ),
                    &self.inner.checkpoints,
                )
            })
            .map_err(ImportedProductionReplayError::Prepared)?;
        let services = self.replay_services().map_err(|first| {
            let (first, custody) = source
                .admission_failure("select imported genesis Service", first)
                .into_parts();
            match first {
                Some(first) => ImportedProductionReplayError::ServiceAdmission {
                    first,
                    access: custody,
                },
                None => ImportedProductionReplayError::Prepared(custody),
            }
        })?;
        source
            .start("start imported genesis Service", |start| {
                services.start_for_imported_genesis(start, cancellation.clone())
            })
            .map_err(ImportedProductionReplayError::Prepared)?;
        source
            .start("set imported genesis budgets", |start| {
                start.update_imported_genesis_budgets()
            })
            .map_err(ImportedProductionReplayError::Prepared)?;

        let service = source.service_handle();
        let receiver = service.retain_receiver_in_main().map_err(|first| {
            ImportedProductionReplayError::Prepared(
                service.failure_with_refusal("retain imported genesis projections", first),
            )
        })?;
        let captured = (|| {
            let scenario = source
                .start("project imported genesis source", |start| {
                    start.project_imported_genesis_source()
                })
                .map_err(ImportedGenesisCaptureFailure::Prepared)?;
            let context = source
                .with_ready("project imported genesis context", |ready| {
                    ready.context().clone()
                })
                .map_err(ImportedGenesisCaptureFailure::Prepared)?;
            capture_production_baked_genesis(&mut source.factory, &scenario, &context)
                .map_err(ImportedGenesisCaptureFailure::Capture)
        })();
        // Both projected aliases have left scope. Even on access refusal the
        // exact receiver and its acknowledgment remain in this original Main.
        let receiver_return = receiver
            .return_after_alias_destruction()
            .err()
            .map(|first| {
                service.failure_with_refusal("return imported genesis projections", first)
            });
        let baked = match (captured, receiver_return) {
            (Ok(baked), None) => baked,
            (Ok(_baked), Some(first)) => {
                return Err(ImportedProductionReplayError::Prepared(first));
            }
            (Err(ImportedGenesisCaptureFailure::Prepared(first)), None) => {
                return Err(ImportedProductionReplayError::Prepared(first));
            }
            (Err(ImportedGenesisCaptureFailure::Prepared(first)), Some(receiver_return)) => {
                return Err(ImportedProductionReplayError::PreparedReturn {
                    first,
                    receiver_return,
                });
            }
            (Err(ImportedGenesisCaptureFailure::Capture(first)), receiver_return) => {
                return Err(ImportedProductionReplayError::GenesisRetained {
                    first: Box::new(first),
                    custody: source.failure("capture imported genesis"),
                    receiver_return,
                });
            }
        };

        // All catalog/configuration failures occur while the untouched input
        // still lives in genesis Main. After export there is no bare `?` that
        // could drop that input during the next prebirth handoff.
        let catalog_original = crucible_engine::owned_decode::current_budget().ok_or_else(|| {
            ImportedProductionReplayError::Prepared(
                source.failure("retain imported replay catalog account"),
            )
        })?;
        let catalog = ProductionBakedGenesisReplayCatalogFactory::new(
            [baked],
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
            &catalog_original,
        )
        .map_err(|first| ImportedProductionReplayError::CatalogRetained {
            first,
            custody: source.failure("prepare imported replay catalog"),
        })?
        .with_savepoint_replay_config(self.inner.config.lifecycle.clone())
        .with_replay_services(services);

        let mut retirement = service
            .prepared_selector()
            .service_main_handle()
            .into_retirement();
        // An export-pending Service deliberately prevents terminal readiness.
        // Only the following exact World/body/controls/loan journal projection
        // can establish the physical cut, independently of this retry sign.
        let _physical_attempt = retirement.retry();
        let capsule = match service.with_start_after_world_return(|start| {
            start.take_unlaunched_import_after_world_return()
        }) {
            Ok(Ok(capsule)) => capsule,
            Ok(Err(_)) => {
                return Err(ImportedProductionReplayError::Prepared(
                    source.failure("export imported genesis input"),
                ));
            }
            Err(first) => {
                return Err(ImportedProductionReplayError::Prepared(
                    service.failure_with_refusal("prove imported genesis physical return", first),
                ));
            }
        };
        let closing = retirement.retry();
        if !matches!(closing, Ok(true)) {
            let mut failure = ImportedCheckpointHandoffFailure::new(
                capsule,
                source.failure("close imported genesis Service"),
            );
            if let Err(first) = closing {
                failure.retain_retirement_refusal(first);
            }
            return Err(ImportedProductionReplayError::GenesisHandoff(failure));
        }
        match retirement.finish() {
            Ok(terminal) if terminal.first_failure().is_some() => {
                let mut failure = ImportedCheckpointHandoffFailure::new(
                    capsule,
                    source.failure("observe imported genesis terminal history"),
                );
                failure.retain_terminal(terminal);
                return Err(ImportedProductionReplayError::GenesisHandoff(failure));
            }
            Ok(terminal) => drop(terminal),
            Err(_retirement) => {
                return Err(ImportedProductionReplayError::GenesisHandoff(
                    ImportedCheckpointHandoffFailure::new(
                        capsule,
                        source.failure("dispose imported genesis terminal body"),
                    ),
                ));
            }
        }
        catalog.begin_retained_imported_checkpoint(
            &self.inner.checkpoints,
            capsule,
            owner,
            cancellation,
        )
    }
}
