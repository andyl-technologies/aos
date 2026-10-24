//! Lends the authenticated normal main to its one production executor.

use std::sync::Arc;

use super::{ACTOR, CampaignProcessAdmissionError, CampaignProcessOwner};
use crucible_host_resources::host_services::process_birth::AuthenticatedNativeSlotPurpose;
use crucible_host_resources::host_supervision::HostOperationBudgets;
use crucible_host_resources::ram_policy::HostResourceVector;

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
        let actor = ACTOR
            .get()
            .ok_or_else(|| CampaignProcessAdmissionError::policy("normal main is unpublished"))?;
        let executor = actor
            .accounts
            .admit_executor_purpose(bounds, budgets)
            .map_err(CampaignProcessAdmissionError::ExecutorPurpose)?;
        actor.executor.set(Arc::clone(&executor)).map_err(|_| {
            CampaignProcessAdmissionError::policy("normal Main purpose is already installed")
        })?;
        Ok(executor)
    }
}

/// Pins the actual once-admitted Main queue before any Source construction.
///
/// Repeated observation of the same queue is harmless; another Main or queue
/// cannot replace it. The permanent actor keeps failed-constructor custody
/// reachable independently of every weak factory/reservation handoff.
///
/// # Errors
/// Refuses an absent or inactive Main, a different admitted purpose, or another
/// queue already published in this same permanent actor.
pub(crate) fn install_executor_lifecycle_cleanup(
    main: &Arc<AuthenticatedNativeSlotPurpose>,
    queue: Arc<crate::lifecycle_cleanup::LifecycleCleanupQueue>,
) -> Result<(), crucible_qemu_host::QemuVmRealizationError> {
    let actor = ACTOR
        .get()
        .ok_or_else(|| anchor_refusal("normal Main is unpublished"))?;
    actor
        .verify()
        .map_err(|_| anchor_refusal("normal Main is no longer live"))?;
    let admitted = actor
        .executor
        .get()
        .ok_or_else(|| anchor_refusal("normal executor purpose has not been admitted"))?;
    if !Arc::ptr_eq(admitted, main) {
        return Err(anchor_refusal(
            "cleanup queue belongs to another Main purpose",
        ));
    }
    if let Some(current) = actor.lifecycle_cleanup.get() {
        return if Arc::ptr_eq(current, &queue) {
            Ok(())
        } else {
            Err(anchor_refusal("normal Main retains another cleanup queue"))
        };
    }
    actor
        .lifecycle_cleanup
        .set(queue)
        .map_err(|_| anchor_refusal("normal Main cleanup publication raced another queue"))
}

fn anchor_refusal(message: &'static str) -> crucible_qemu_host::QemuVmRealizationError {
    crucible_qemu_host::QemuVmRealizationError::ExecutorUnavailable {
        operation: "retain Main lifecycle cleanup",
        message: String::from(message),
    }
}
