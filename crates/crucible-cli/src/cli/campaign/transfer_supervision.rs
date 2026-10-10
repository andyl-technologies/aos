//! Finite original-start supervision for standalone authenticated archive work.
//!
//! Chunk and retry boundaries check cancellation without claiming meaningful
//! progress. One required work unit completes after authenticated inspection or
//! durable archive publication.

use std::time::Duration;

use crucible_api::host_operational::HostOperationClass;
use crucible_daemon::campaign_store_composition::{
    CampaignArchiveBoundaryError, CampaignArchiveHostOperation,
};

use super::*;

/// Retains the original host lifetime through planning, copy and publication.
pub(super) struct StandaloneArchiveOperation {
    operation: CampaignArchiveHostOperation,
}

impl StandaloneArchiveOperation {
    /// Starts one finite standalone infrastructure lifetime.
    ///
    /// # Errors
    /// Rejects zero or unrepresentable lifetimes and unavailable supervision.
    pub(super) fn start(class: HostOperationClass, timeout_ms: u64) -> Result<Self, CliError> {
        let lifetime = Duration::from_millis(timeout_ms);
        let operation = CampaignArchiveHostOperation::start(class, lifetime)
            .map_err(|error| backend_error(format!("transfer supervision failed: {error}")))?;
        Ok(Self { operation })
    }

    pub(super) fn start_with_quota(
        class: HostOperationClass,
        budgets: crucible_api::host_operational::HostOperationBudgets,
        lifetime: Duration,
        resources: crucible_api::host_operational::HostResourceVector,
    ) -> Result<Self, CliError> {
        let operation =
            CampaignArchiveHostOperation::start_with_quota(class, budgets, lifetime, resources)
                .map_err(CliError::ProviderAdmission)?;
        Ok(Self { operation })
    }

    /// Checks every real storage boundary without renewing progress time.
    ///
    /// # Errors
    /// Preserves typed operational cancellation when the original bound expires.
    pub(super) fn boundary(&self) -> Result<(), CampaignArchiveBoundaryError> {
        self.operation.boundary()
    }

    /// Borrows the original authority for a blocking accepted worker.
    pub(super) fn original_operation(&self) -> &CampaignArchiveHostOperation {
        &self.operation
    }

    /// Completes the authenticated archive operation after deadline checks.
    ///
    /// # Errors
    /// Refuses completion if sticky expiration or cancellation won publication.
    pub(super) fn complete(&self) -> Result<(), CliError> {
        self.operation
            .complete()
            .map_err(|error| backend_error(format!("transfer supervision failed: {error}")))
    }
}
