//! Installed selected Cache initialization and borrowed project observations.
//!
//! This shares the existing executor and worker; it neither admits Git nor
//! fills the other project-account dimensions with zero.

use aos_sandbox::cache_residency::{CacheProjectUsageLoanV1, CacheResidentUnavailableV1};
use aos_sandbox_core::ProjectId;

use super::{ProductionController, ProductionEffectExecutor};
use super::publisher_policy_source::PublisherPolicyBootstrapAttemptV1;

impl ProductionEffectExecutor {
    pub(super) fn observe_existing_cache_usage(
        &mut self,
        project: ProjectId,
    ) -> Result<CacheProjectUsageLoanV1<'_>, CacheResidentUnavailableV1> {
        self.cache_mutation.require_completed_or_empty()?;
        if !self.cache_resident_usage.started() {
            self.cache_resident_usage.initialize_once(&mut self.cache_inventory, self.controller_uid)?;
        }
        let owner = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        self.cache_resident_usage.recheck(owner)?;
        owner.observe_project_usage(project).map_err(|_| CacheResidentUnavailableV1)
    }
}

/// Bookends the real executor loan with the same original signed bootstrap.
pub(super) fn selected_bookend(
    controller: &mut ProductionController,
    bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
) -> Result<(), ()> {
    let project = bootstrap.current_cache_project(controller)?;
    let observed = {
        let returned = controller.existing_cache_project_usage_v1(project);
        // Borrowing ends before the Controller policy writer is borrowed again.
        // The checked quantities and actual replay failures stay in its owner.
        match returned {
            Ok(loan) => loan.partitions().is_some(),
            Err(_) => false,
        }
    };
    // The executor has already parked any actual action cause. Even failure
    // receives the independent original policy/time postcheck before return.
    let cache_postcheck = controller.recheck_existing_cache_project_usage_v1();
    let policy_postcheck = bootstrap.current_cache_project(controller);
    if !observed || cache_postcheck.is_err() || policy_postcheck != Ok(project) {
        return Err(());
    }
    Ok(())
}
