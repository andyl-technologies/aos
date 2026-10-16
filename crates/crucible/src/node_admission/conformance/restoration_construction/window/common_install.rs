//! Orders the admitted common scheduler and runtime installation on the same owner.
//!
//! A real installed context and original prospective row precede every clone.
//! The window retains paused coordinator custody before readiness/publication;
//! its installation marker is spent before the real common runtime is mutated.

use super::*;
use crate::node_contract::OriginalLineageRestoration;
use crate::node_scheduling::PreparedSchedulingRestore;

impl CompleteOriginalRestorationWindow {
    pub(crate) fn authenticate_original_common_construction_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let row = self
            .common_construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let coordinator = self
            .coordinator_construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let target = self
            .coordinator_target
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        runtime.authenticate_original_runtime_restoration_installation_construction_data(
            row,
            self.archive.original_runtime_record_data()?,
            &self.archive.original_host_record_data()?.scheduling,
            target,
            self.archive.content(),
            coordinator,
        )?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_member_data(plan, scope)
    }

    pub(crate) fn retain_original_paused_scheduler_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        construct: impl FnOnce() -> Result<PreparedSchedulingRestore, RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_common_construction_data(runtime, plan)?;
        if self.scheduler_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        {
            let mut output = self
                .paused_scheduler
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if output.is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            *output = Some(construct()?);
        }
        self.authenticate_original_common_construction_data(runtime, plan)?;
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn with_original_paused_scheduler_data(
        &self,
        inspect: impl FnOnce(&PreparedSchedulingRestore) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let scheduler = self
            .paused_scheduler
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        inspect(scheduler.as_ref().ok_or(RuntimeError::OwnerUnavailable)?)
    }

    pub(crate) fn duplicate_original_paused_scheduler_for_install_data(
        &self,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
    ) -> Result<PreparedSchedulingRestore, RuntimeError> {
        self.authenticate_original_common_construction_data(runtime, plan)?;
        if self.install_started.replace(true) {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Installation changes real common owners even when a later validation
        // refuses. The next effect requires a fresh whole-owner observation.
        self.whole_observation.require_observation();
        // The legacy consumer performs real fallible currentness and activation
        // checks before it retains an active scheduler. Keep this SAME original
        // owner through that entire interval and after every outcome. Its inert
        // duplicate has a separate pre-Prepare row in the common constructor.
        let scheduler = self
            .paused_scheduler
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        scheduler
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .duplicate_original_retained_for_installation_data(
                self.common_construction
                    .get()
                    .ok_or(RuntimeError::OwnerUnavailable)?
                    .paused_scheduler_duplicate_requested_bytes_data()
                    .min(self.policy.maximum_requested_bytes),
            )
    }

    pub(crate) fn authenticate_original_context_owner_data(
        &self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        context.authenticate_original_installed_window_data(self)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn authenticate_original_publisher_member_data(
        &self,
        plan: &InstalledConformancePlan,
        publisher: &dyn crate::node_contract::ActivationPublisher,
    ) -> Result<(), RuntimeError> {
        self.whole_observation.authenticate_dispatch_data()?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_identity_data(plan, scope)?;
        let member = OriginalRestorationMemberScope {
            plan,
            window: self,
            sources: &self.sources,
            publisher: Some(
                (publisher as *const dyn crate::node_contract::ActivationPublisher).cast::<()>(),
            ),
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        self.authenticate_original_complete_identity_data(plan, scope)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn retain_original_published_world_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        world: &crate::node_contract::WorldActivation,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_common_construction_data(runtime, plan)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.runtime
            .authenticate_world_activation_data(world, &scope.target)?;
        {
            let original = self
                .coordinator_owner
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            original.authenticate_original_publication_data(world)?;
        }
        if let Err(actual) = self.activation_world.set(world.clone()) {
            // A duplicate actual publication handle cannot reset the old phase.
            // No protocol effect or callback has occurred in this constructor.
            if !self
                .activation_world
                .get()
                .is_some_and(|old| old.same_authority(&actual))
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            return Err(RuntimeError::OutstandingObligations);
        }
        self.whole_observation.require_observation();
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    /// Borrows the same fixed coordinator DATA retained before Prepare.
    ///
    /// # Errors
    /// Refuses another creator or absent original quote. This creates no owner,
    /// context, publication claim or authority to issue a storage callback.
    pub fn original_coordinator_construction_data(
        &self,
    ) -> Result<&OriginalRestorationCoordinatorConstructionData, RuntimeError> {
        self.origin()?;
        self.coordinator_construction
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}
