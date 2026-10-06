//! Receiver archive realization through the original guarded capacity actor.

use super::*;
use crate::imported_checkpoint::AuthenticatedImportedCheckpoint;
use crate::qemu_baked_genesis::{
    ImportedProductionCheckpointReplay, ImportedProductionReplayError,
};

impl GuardedCampaignOwner {
    /// Consumes one receiver-authenticated archive into a fresh verification world.
    ///
    /// The receiver repository must share this owner's exact checkpoint backend.
    /// Its original actor reserves each complete Service before native startup.
    /// An independently captured genesis supplies the receiver replay basis;
    /// imported local execution rows are never created. The authentication
    /// owner remains charged through this handoff. This entry does not publish
    /// a semantic result or transfer campaign maintenance authority.
    ///
    /// # Errors
    /// Refuses another backend, insufficient complete resources, original
    /// expiry/cancellation, incompatible native state, or unproven cleanup.
    /// Failed cleanup retains its actual reservation.
    pub fn begin_imported_checkpoint(
        &self,
        imported: AuthenticatedImportedCheckpoint<'_>,
        cancellation: ExecutionCancellation,
    ) -> Result<ImportedProductionCheckpointReplay, ImportedProductionReplayError> {
        self.inner
            .checkpoints
            .require_reuse_backend(&imported.repository().blob_backend())
            .map_err(ImportedProductionReplayError::Store)?;
        let services = self
            .replay_services()
            .map_err(|error| ImportedProductionReplayError::Admission(Box::new(error.into())))?;
        let genesis = services
            .start_for_imported_genesis(&imported, cancellation.clone())
            .map_err(|error| ImportedProductionReplayError::Admission(Box::new(error)))?;
        genesis
            .context()
            .host_operation_supervisor()
            .ok_or(ImportedProductionReplayError::Unavailable)?
            .update_budgets(0, imported.budgets())
            .map_err(|source| {
                ImportedProductionReplayError::Admission(Box::new(
                    PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(source)),
                ))
            })?;
        let mut capture_factory = QemuAttemptProductionVmLifecycleFactory::new(
            self.inner.config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        );
        let captured = capture_production_baked_genesis(
            &mut capture_factory,
            imported.source(),
            genesis.context(),
        );
        drop(capture_factory);
        let baked = match captured {
            Ok(baked) => baked,
            Err(error) => {
                genesis.retain_after_unknown_cleanup();
                return Err(ImportedProductionReplayError::Genesis(Box::new(error)));
            }
        };
        genesis
            .release_after_world_cleanup()
            .map_err(|error| ImportedProductionReplayError::Admission(Box::new(error.into())))?;
        drop(genesis);

        ProductionBakedGenesisReplayCatalogFactory::new(
            [baked],
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        )
        .map_err(ImportedProductionReplayError::Catalog)?
        .with_savepoint_replay_config(self.inner.config.lifecycle.clone())
        .with_replay_services(services)
        .begin_imported_checkpoint(&self.inner.checkpoints, imported, cancellation)
    }
}
