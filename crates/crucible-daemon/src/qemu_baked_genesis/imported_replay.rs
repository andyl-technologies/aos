//! Receiver-owned realization of a completely authenticated imported checkpoint.

use super::*;
use crate::imported_checkpoint::{AuthenticatedImportedCheckpoint, ImportedCheckpointBasis};
use crucible_api::vm_lifecycle::ProductionVmLifecycleLoop;

/// Native receiver lifecycle and its independently charged original Service.
///
/// The receiver repository remains retained until actual process and source
/// cleanup. Dropping an unfinished instance conservatively quarantines its
/// Service reservation; only [`Self::finish`] can discharge proven cleanup.
pub struct ImportedProductionCheckpointReplay {
    lifecycle: Option<ProductionVmLifecycleLoop>,
    service: Option<crate::packaged_qemu_executor::RetainedTemplateService>,
    basis: Option<ImportedCheckpointBasis>,
    archive: crucible_campaign::CampaignArchiveManifestId,
}

impl ImportedProductionCheckpointReplay {
    /// Moves native custody into a debug actor while retaining its Service.
    pub(crate) fn into_debug_lifecycle(
        mut self,
    ) -> Result<
        (
            ProductionVmLifecycleLoop,
            crucible_api::SessionLifetimeRetention,
        ),
        ImportedProductionReplayError,
    > {
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        let retention = crucible_api::SessionLifetimeRetention::new(DebugReplayCustody(
            std::sync::Mutex::new(self),
        ));
        Ok((lifecycle, retention))
    }

    /// Returns the authenticated receiver archive realized by this lifecycle.
    pub fn archive(&self) -> crucible_campaign::CampaignArchiveManifestId {
        self.archive
    }

    /// Returns the original independently admitted receiver operation context.
    ///
    /// # Errors
    /// Refuses a lifecycle whose cleanup authority has already been consumed.
    pub fn context(&self) -> Result<&AttemptExecutionContext, ImportedProductionReplayError> {
        self.service
            .as_ref()
            .map(|service| service.context())
            .ok_or(ImportedProductionReplayError::Unavailable)
    }

    /// Borrows the authenticated native lifecycle for scheduler operations.
    ///
    /// # Errors
    /// Refuses a lifecycle that has already completed physical cleanup.
    pub fn lifecycle_mut(
        &mut self,
    ) -> Result<&mut ProductionVmLifecycleLoop, ImportedProductionReplayError> {
        self.lifecycle
            .as_mut()
            .ok_or(ImportedProductionReplayError::Unavailable)
    }

    /// Reaps the receiver and joins source workers before releasing its Service.
    ///
    /// # Errors
    /// Retains the Service charge when native cleanup or actor release cannot
    /// be proved. An identical successful call is idempotent.
    pub fn finish(&mut self) -> Result<(), ImportedProductionReplayError> {
        if let Some(lifecycle) = self.lifecycle.as_mut() {
            crate::QemuFreshAttemptLifecycleOwner::shutdown(lifecycle)
                .map_err(ImportedProductionReplayError::Cleanup)?;
        }
        // All lifecycle-held descriptors and lazy-source leases close before
        // the full Service vector becomes available to another receiver.
        self.lifecycle = None;
        // Decoded semantic material is part of the receiver's retained
        // metadata, so it also drops before the reservation is discharged.
        self.basis = None;
        if let Some(service) = self.service.as_ref() {
            service.release_after_world_cleanup().map_err(|error| {
                ImportedProductionReplayError::Admission(Box::new(error.into()))
            })?;
        }
        self.service = None;
        Ok(())
    }
}

/// Session retention drops after its native actor and source workers close.
struct DebugReplayCustody(std::sync::Mutex<ImportedProductionCheckpointReplay>);

impl Drop for DebugReplayCustody {
    fn drop(&mut self) {
        if let Ok(replay) = self.0.get_mut() {
            // Failed proof leaves the Service in replay's conservative Drop.
            let _ = replay.finish();
        }
    }
}

impl Drop for ImportedProductionCheckpointReplay {
    fn drop(&mut self) {
        if let Some(service) = self.service.take() {
            service.retain_after_unknown_cleanup();
        }
    }
}

impl
    ProductionBakedGenesisReplayCatalogFactory<
        crate::ComposedQemuAttemptResourceGuardFactory<
            crate::SharedQemuAttemptHostResourceFactory<crate::LinuxQemuAttemptHostResourceFactory>,
        >,
    >
{
    /// Starts one authenticated receiver import under fresh physical authority.
    ///
    /// This uses the packaged factory's real Service allocator and guarded
    /// resource factory. The selection is consumed once. The source's local
    /// execution ledger and original host cap are never copied to the receiver.
    /// This creates a verification world; it does not publish a semantic result
    /// or transfer a source executor's campaign maintenance authority.
    ///
    /// # Errors
    /// Refuses missing configured replay ownership, insufficient complete
    /// capacity, expired authority, or failed exact authentication/native launch.
    /// Uncertain cleanup retains the actual Service reservation.
    pub fn begin_imported_checkpoint(
        &self,
        checkpoints: &crate::ExactCheckpointStore,
        imported: AuthenticatedImportedCheckpoint<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<ImportedProductionCheckpointReplay, ImportedProductionReplayError> {
        let config = self
            .savepoint_replay_config
            .as_ref()
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        let services = self
            .replay_services
            .as_ref()
            .ok_or(ImportedProductionReplayError::Unavailable)?;
        self.require_basis(
            imported.source().world().id,
            imported.source().scenario_def().id(),
        )
        .map_err(ImportedProductionReplayError::Compatibility)?;
        let (service, basis) = services
            .start_for_imported_checkpoint(imported, cancellation)
            .map_err(|error| ImportedProductionReplayError::Admission(Box::new(error)))?;
        let setup = (|| {
            checkpoints
                .require_reuse_backend(&basis.repository.blob_backend())
                .map_err(ImportedProductionReplayError::Store)?;
            let scenario = basis.source.scenario_def();
            QemuAttemptProductionVmLifecycleFactory::new(config.clone(), self.resources.clone())
                .begin_resume(
                    checkpoints,
                    basis.checkpoint,
                    crate::QemuExactResumeBasis::new(
                        &scenario,
                        &basis.source,
                        &basis.configuration,
                        None,
                    ),
                    service.context(),
                )
                .map_err(|error| ImportedProductionReplayError::Launch(Box::new(error)))
        })();
        match setup {
            Ok(lifecycle) => Ok(ImportedProductionCheckpointReplay {
                lifecycle: Some(lifecycle),
                service: Some(service),
                archive: basis.archive,
                basis: Some(basis),
            }),
            Err(error) => {
                drop(basis);
                if service.release_after_world_cleanup().is_err() {
                    service.retain_after_unknown_cleanup();
                }
                Err(error)
            }
        }
    }
}

/// Refusal while realizing a receiver-authenticated imported root.
#[derive(Debug, Error)]
pub enum ImportedProductionReplayError {
    /// The packaged replay factory or terminal lifecycle has no live authority.
    #[error("imported replay authority is unavailable")]
    Unavailable,
    /// The original actor refused Service ownership or cleanup discharge.
    #[error("imported replay Service admission: {0}")]
    Admission(#[source] Box<crate::PackagedQemuExecutorError>),
    /// An independently admitted receiver genesis could not be captured.
    #[error("imported replay genesis capture: {0}")]
    Genesis(
        #[source]
        Box<
            crate::ProductionBakedGenesisCaptureError<crate::QemuAttemptProductionVmLifecycleError>,
        >,
    ),
    /// The independently captured receiver basis could not be admitted.
    #[error("imported replay catalog: {0}")]
    Catalog(#[source] crate::ProductionBakedGenesisReplayCatalogError),
    /// Exact native lifecycle construction refused the selected root.
    #[error("imported replay native launch: {0}")]
    Launch(#[source] Box<crate::QemuAttemptProductionVmLifecycleError>),
    /// Receiver backend authority differs from the authenticated selection.
    #[error("imported replay checkpoint store: {0}")]
    Store(#[source] crate::ExactCheckpointStoreError),
    /// The receiver has no compatible independently captured replay basis.
    #[error("imported replay compatibility: {0}")]
    Compatibility(#[source] QemuVmRealizationError),
    /// Actual native cleanup could not be proved.
    #[error("imported replay cleanup: {0}")]
    Cleanup(#[source] crucible::SchedulerError),
}
