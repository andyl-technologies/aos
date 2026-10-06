//! Original-start finite supervision for standalone archive application work.
//!
//! Chunk boundaries observe cancellation without renewing progress time. One
//! required work unit completes only after authenticated inspection or durable
//! publication; planning, retries and output publication retain the same cap.

use std::time::Duration;

use crucible_linux_resource::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationGuard,
    HostOperationSupervisor, HostSupervisionError,
};

use super::CampaignArchiveBoundaryError;

/// Retains a finite original host lifetime through standalone archive work.
pub struct CampaignArchiveHostOperation {
    supervisor: HostOperationSupervisor,
    operation: HostOperationGuard,
}

impl CampaignArchiveHostOperation {
    /// Starts an original-start cap and one independently bounded operation.
    ///
    /// # Errors
    /// Rejects zero or unrepresentable durations and unavailable supervision.
    pub fn start(
        class: HostOperationClass,
        lifetime: Duration,
    ) -> Result<Self, HostSupervisionError> {
        let budgets = HostOperationBudgets {
            classes: [HostOperationBudget::finite(lifetime);
                crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
        };
        let supervisor = HostOperationSupervisor::new(budgets, Some(lifetime))?;
        let operation = supervisor.begin(class)?;
        Ok(Self {
            supervisor,
            operation,
        })
    }

    /// Borrows the original supervisor for an independently admitted worker.
    pub fn supervisor(&self) -> &HostOperationSupervisor {
        &self.supervisor
    }

    /// Checks a real storage boundary without claiming completed work.
    ///
    /// # Errors
    /// Returns typed cancellation when the immutable lifetime expires or
    /// ownership becomes unavailable. It never substitutes guest bytes.
    pub fn boundary(&self) -> Result<(), CampaignArchiveBoundaryError> {
        self.operation
            .wait_slice()
            .map(|_| ())
            .map_err(|_| CampaignArchiveBoundaryError::Canceled)
    }

    /// Completes authenticated inspection or publication after deadline checks.
    ///
    /// # Errors
    /// Refuses completion if sticky expiration or cancellation won publication.
    pub fn complete(&self) -> Result<(), HostSupervisionError> {
        self.operation.complete()?;
        self.supervisor.complete()
    }
}
