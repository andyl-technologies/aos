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
    operation: HostOperationGuard,
    supervisor: HostOperationSupervisor,
    // Original service controls remain funded until both supervisor aliases close.
    quota: Option<crate::campaign_store_quota::LinuxProjectQuotaBinder>,
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
            operation,
            supervisor,
            quota: None,
        })
    }

    /// Starts archive work with one operator-authored original quota service.
    ///
    /// Supervision and resource controls are admitted before publication. The
    /// archive record starts before service construction or namespace I/O, and
    /// every later phase retains that same original clock and finite capacity.
    ///
    /// # Errors
    /// Refuses invalid budgets or resource limits, original supervision refusal,
    /// or insufficient capacity before any archive namespace is accessed.
    pub fn start_with_quota(
        class: HostOperationClass,
        budgets: HostOperationBudgets,
        lifetime: Duration,
        resources: crucible_linux_resource::ram_policy::HostResourceVector,
    ) -> Result<Self, crate::ProviderServiceAdmissionError> {
        crate::campaign_store_quota::LinuxProjectQuotaBinder::for_archive(
            class, budgets, lifetime, resources,
        )
    }

    pub(crate) fn from_admitted_quota(
        operation: HostOperationGuard,
        supervisor: HostOperationSupervisor,
        quota: crate::campaign_store_quota::LinuxProjectQuotaBinder,
    ) -> Self {
        Self {
            operation,
            supervisor,
            quota: Some(quota),
        }
    }

    /// Binds one operator-installed archive project before its first access.
    ///
    /// The independently authored primary service supplies the namespace and
    /// decode account. Missing quota admission never becomes metadata-only mode.
    ///
    /// # Errors
    /// Preserves original supervision, namespace, quota and account refusals.
    pub fn bind_archive_namespace(
        &self,
        root: &std::path::Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<
        crate::campaign_store_quota::CampaignArchiveNamespace,
        crate::ProviderServiceAdmissionError,
    > {
        self.operation.wait_slice()?;
        let quota =
            self.quota
                .as_ref()
                .ok_or(crucible_cas::content_store::StoreError::Unsupported {
                    capability: "admitted-archive-namespace",
                })?;
        let namespace =
            quota.archive_namespace(root, project_id, maximum_physical_bytes, maximum_inodes)?;
        self.operation.wait_slice()?;
        Ok(namespace)
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
