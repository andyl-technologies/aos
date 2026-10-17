//! Attaches the original coordinator to the actual prepared pool and contract.
//!
//! Driver identity, epoch, worker capacity and assignment limits come from the
//! retained factory configuration. No listener thread, copied bank, executor
//! owner or later operation is created for this direct component route.

use super::*;
use crucible_campaign::{CampaignExecutorDriver, ExecutionRetentionIntent, ExecutorClient};
use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};

/// Names the exact existing pool alias used by the original coordinator.
pub(crate) type OriginalCampaignExecutorService =
    crate::LocalExecutorPoolService<DirectoryAssignmentLedger, PackagedAttemptAdmission>;

/// Preserves actual direct component attachment and identity refusals.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalCampaignExecutorError {
    /// The same external original refused further work.
    #[error("original campaign interval refused: {0}")]
    Original(#[from] HostSupervisionError),
    /// Actual actor account custody refused before an alias was lent.
    #[error("original campaign accounts refused: {0}")]
    Accounts(#[from] crucible_qemu::OriginalActorAccountError),
    /// The supplied repository differs or the actual assignment contract is absent.
    #[error("original campaign factory binding is unavailable")]
    Binding,
    /// The exact component alias or its saved original refused.
    #[error("original campaign pool refused: {0}")]
    Pool(#[from] crate::LocalExecutorPoolServiceError<crate::AssignmentLedgerError>),
    /// Explicit scan or actual reservation capacity violates the driver contract.
    #[error("original campaign driver refused: {0}")]
    Configuration(#[from] crucible_campaign::CampaignExecutorDriverConfigError),
}

impl PackagedQemuExecutor {
    /// Attaches a direct driver to this factory's exact repository and pool.
    ///
    /// # Errors
    /// Refuses foreign repository, absent assignment limits, actual component
    /// custody or invalid explicit scan. The caller prepays the driver body.
    pub(crate) fn original_campaign_driver(
        &self,
        repository: &Arc<CampaignRepository>,
        original: Arc<HostOperationGuard>,
        retention: ExecutionRetentionIntent,
        scan_limit: usize,
    ) -> Result<
        CampaignExecutorDriver<OriginalCampaignExecutorService>,
        OriginalCampaignExecutorError,
    > {
        original.wait_slice()?;
        if !Arc::ptr_eq(repository, &self.repository_identity) {
            return Err(OriginalCampaignExecutorError::Binding);
        }
        let config = &self.guarded_state.config;
        let limits = config
            .assignment_limits()
            .ok_or(OriginalCampaignExecutorError::Binding)?;
        let service = self.service.original_component(Arc::clone(&original))?;
        let driver = CampaignExecutorDriver::new(
            Arc::clone(repository),
            ExecutorClient::new(service),
            config.guarded_epoch(),
            config.worker_count(),
            limits,
            retention,
            scan_limit,
        )?;
        original.wait_slice()?;
        Ok(driver)
    }

    /// Returns the actual configured slot count for this same direct driver.
    ///
    /// # Errors
    /// Refuses a configured count that cannot fit the campaign slot coordinate.
    pub(crate) fn original_campaign_worker_slots(
        &self,
    ) -> Result<u32, OriginalCampaignExecutorError> {
        u32::try_from(self.guarded_state.config.worker_count())
            .map_err(|_| OriginalCampaignExecutorError::Binding)
    }
}
