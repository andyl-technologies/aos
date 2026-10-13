//! Lends the authenticated normal main to its one production executor.

use std::sync::Arc;

use super::{ACTOR, CampaignProcessAdmissionError, CampaignProcessOwner};
use crucible_linux_resource::host_services::process_birth::AuthenticatedNativeSlotPurpose;
use crucible_linux_resource::host_supervision::HostOperationBudgets;
use crucible_linux_resource::ram_policy::HostResourceVector;

impl CampaignProcessOwner {
    /// Checks the immutable deployment selected by this authenticated main.
    ///
    /// # Errors
    /// Refuses ordinary mode or any path that does not resolve to the exact
    /// evaluated deployment. A caller-selected document grants no authority.
    pub fn verify_executor_deployment(
        &self,
        path: &std::path::Path,
    ) -> Result<(), CampaignProcessAdmissionError> {
        let selected = std::fs::canonicalize(path).map_err(CampaignProcessAdmissionError::Io)?;
        if !self.policy.delegated_executor
            || selected != std::path::Path::new(&self.policy.executor_deployment)
        {
            return Err(CampaignProcessAdmissionError::policy(
                "normal executor deployment differs from its immutable main policy",
            ));
        }
        Ok(())
    }

    /// Matches native device access to the exact evaluated child group.
    ///
    /// # Errors
    /// Refuses a child group different from the immutable full-kernel device
    /// policy. Actual device opening and UFFD negotiation still must succeed.
    pub fn verify_executor_fault_group(
        &self,
        group: u32,
    ) -> Result<(), CampaignProcessAdmissionError> {
        if !self.policy.delegated_executor || group != self.policy.userfaultfd_group_id {
            return Err(CampaignProcessAdmissionError::policy(
                "normal executor child group differs from kernel-fault device policy",
            ));
        }
        Ok(())
    }

    pub(crate) fn admit_executor(
        &self,
        bounds: HostResourceVector,
        budgets: HostOperationBudgets,
    ) -> Result<Arc<AuthenticatedNativeSlotPurpose>, CampaignProcessAdmissionError> {
        if !self.policy.delegated_executor {
            return Err(CampaignProcessAdmissionError::policy(
                "normal production executor requires its authored delegated main",
            ));
        }
        ACTOR
            .get()
            .ok_or_else(|| CampaignProcessAdmissionError::policy("normal main is unpublished"))?
            .accounts
            .admit_executor_purpose(bounds, budgets)
            .map_err(CampaignProcessAdmissionError::ExecutorPurpose)
    }
}
