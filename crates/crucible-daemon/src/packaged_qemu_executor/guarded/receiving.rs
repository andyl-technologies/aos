//! Private stopped receiving World and live maintenance-original custody.
//!
//! Archive authentication is consumed once without completing its Transfer.
//! No lifecycle interface or Ready receipt escapes this owner. A separate
//! durable destination/source commit issuer must precede execution exposure.

use super::*;
mod commit;
pub(crate) use commit::GuardedReceivingReady;
pub use commit::{
    GuardedSourceTransferOffer, GuardedSourceTransferOperation, GuardedTransferError,
};

use crate::imported_checkpoint::{
    AuthenticatedImportedCheckpoint, ImportedCheckpointBasis, ImportedCheckpointMaintenance,
};
use crucible_api::ProductionVmStoppedLifecycle;
use crucible_linux_resource::host_supervision::HostSupervisionError;

/// Retains the whole stopped World, source root and original receiver charge.
///
/// This is reconstruction custody, not RestoreReady or execution permission.
/// It exposes no scheduler or native resume operation. Uncertain teardown keeps
/// the full Service charged; authentication cannot become a completed replay.
pub struct ReceivingExecutionPreparation<'owner> {
    lifecycle: Option<ProductionVmStoppedLifecycle>,
    basis: Option<ImportedCheckpointBasis>,
    service: Option<RetainedTemplateService>,
    maintenance: Option<ImportedCheckpointMaintenance<'owner>>,
    destination: Option<GuardedCampaignOwner>,
    possession: Option<crate::campaign_transfer::CampaignArchiveExecutionPossession>,
    journal: Option<crate::assignment_ledger::ReceivingTransferRecord>,
    ready: Option<GuardedReceivingReady>,
    completed: bool,
}

impl ReceivingExecutionPreparation<'_> {
    /// Physically retires the stopped receiver without restoring source rights.
    ///
    /// # Errors
    /// Refuses unproven World cleanup, Service retirement or the final original
    /// cut. A failed original cut is preserved after physical cleanup; it does
    /// not create readiness, a source release, or an accepted destination.
    pub fn abort(&mut self) -> Result<(), ReceivingExecutionPreparationError> {
        if self.completed {
            return Ok(());
        }
        self.abort_journal()
            .map_err(|source| ReceivingExecutionPreparationError::Transfer(Box::new(source)))?;
        if let Some(lifecycle) = self.lifecycle.as_mut() {
            lifecycle
                .shutdown()
                .map_err(ReceivingExecutionPreparationError::Cleanup)?;
        }
        self.lifecycle = None;
        self.basis = None;
        if let Some(service) = self.service.as_ref() {
            service
                .release_after_world_cleanup()
                .map_err(ReceivingExecutionPreparationError::Retirement)?;
        }
        self.service = None;
        self.maintenance
            .as_ref()
            .ok_or(ReceivingExecutionPreparationError::Unavailable)?
            .complete_after_cleanup()
            .map_err(ReceivingExecutionPreparationError::Original)?;
        self.maintenance = None;
        self.destination = None;
        self.possession = None;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ReceivingExecutionPreparation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            // Unknown retirement retains the entire World and its real
            // original/account/root together. Retaining only Service while
            // discarding the stopped scheduler would lose uncertain custody.
            std::mem::forget((
                self.lifecycle.take(),
                self.basis.take(),
                self.service.take(),
                self.maintenance.take(),
                self.destination.take(),
                self.possession.take(),
            ));
        }
    }
}

impl GuardedCampaignOwner {
    /// Reconstructs an authenticated import as an unexposed stopped World.
    ///
    /// The actual destination actor admits its complete Service and uses its
    /// original host allocator, registry and repository. Native Source/W or
    /// whole-floor refusal remains authoritative before any accepting result.
    /// This entry neither issues Ready nor transfers execution ownership.
    ///
    /// # Errors
    /// Refuses another backend, receiver resource limits, original terminal
    /// cuts, incomplete native authority, invalid full checkpoint identity or
    /// failed physical restore. The original initiating cause stays primary.
    pub fn prepare_receiving_execution<'owner>(
        &self,
        imported: AuthenticatedImportedCheckpoint<'owner>,
        cancellation: ExecutionCancellation,
    ) -> Result<ReceivingExecutionPreparation<'owner>, ReceivingExecutionPreparationError> {
        if imported.authentication_owner().host_daemon_epoch()
            != crate::host_operational_registry::operational_identity(
                self.inner.config.daemon_epoch.as_bytes(),
            )
        {
            return Err(ReceivingExecutionPreparationError::Unavailable);
        }
        self.inner
            .checkpoints
            .require_reuse_backend(&imported.repository().blob_backend())
            .map_err(ReceivingExecutionPreparationError::Store)?;
        let services = self
            .replay_services()
            .map_err(ReceivingExecutionPreparationError::Retirement)?;
        let (service, basis, maintenance) = services
            .start_for_maintenance_import(imported, cancellation)
            .map_err(|source| ReceivingExecutionPreparationError::Admission(Box::new(source)))?;
        maintenance
            .check()
            .map_err(ReceivingExecutionPreparationError::Original)?;
        let scenario = basis.source.scenario_def();
        let lifecycle = QemuAttemptProductionVmLifecycleFactory::new(
            self.inner.config.lifecycle.clone(),
            ComposedQemuAttemptResourceGuardFactory::new(self.inner.host.clone()),
        )
        .begin_stopped_transfer(
            &self.inner.checkpoints,
            basis.checkpoint,
            crate::QemuExactResumeBasis::new(&scenario, &basis.source, &basis.configuration, None),
            service.context(),
        )
        .map_err(|source| ReceivingExecutionPreparationError::Restore(Box::new(source)))?;
        // Install complete custody before the final fallible original cut.
        // A failure here closes/quarantines through the owning value's Drop.
        let receiving = ReceivingExecutionPreparation {
            lifecycle: Some(lifecycle),
            basis: Some(basis),
            service: Some(service),
            maintenance: Some(maintenance),
            destination: Some(self.clone()),
            possession: None,
            journal: None,
            ready: None,
            completed: false,
        };
        receiving
            .maintenance
            .as_ref()
            .ok_or(ReceivingExecutionPreparationError::Unavailable)?
            .check()
            .map_err(ReceivingExecutionPreparationError::Original)?;
        Ok(receiving)
    }
}

/// Typed refusal while retaining or physically retiring a stopped receiver.
#[derive(Debug, thiserror::Error)]
pub enum ReceivingExecutionPreparationError {
    /// A durable receiving observation could not be closed safely.
    #[error("receiving execution transfer journal refused")]
    Transfer(#[source] Box<GuardedTransferError>),

    /// Required live preparation custody was already consumed.
    #[error("receiving execution preparation is unavailable")]
    Unavailable,
    /// The live maintenance authentication original refused.
    #[error("receiving execution original refused")]
    Original(#[source] HostSupervisionError),
    /// The actual admitted Service could not be reserved.
    #[error("receiving execution Service admission refused")]
    Admission(#[source] Box<PackagedQemuExecutorError>),
    /// Complete native stopped reconstruction failed.
    #[error("receiving execution stopped restore failed")]
    Restore(#[source] Box<crate::QemuAttemptProductionVmLifecycleError>),
    /// The selected root uses a different receiver storage owner.
    #[error("receiving execution checkpoint storage refused")]
    Store(#[source] crate::ExactCheckpointStoreError),
    /// Native World/worker cleanup could not be proved.
    #[error("receiving execution physical cleanup failed")]
    Cleanup(#[source] crucible::SchedulerError),
    /// The actual destination registry refused Service retirement.
    #[error("receiving execution Service retirement refused")]
    Retirement(#[source] crucible_api::host_operational::HostOperationalError),
}
