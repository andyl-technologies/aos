//! Retains and whole-admits the actual imported coordinator policy before Prepare.
//!
//! Legacy callers do not select this path. A new17 caller must supply the real
//! signed checkpoint-bearing Source and same original Runtime/target; missing
//! Initial15 sidecar custody refuses instead of inventing a starting ordinal.

use super::*;
use crate::node_contract::OriginalRestoredCoordinator17ConstructionData;

impl CompleteOriginalRestorationWindow {
    /// Retains the actual constructor row before the transaction's whole census.
    ///
    /// This method allocates no bank and grants no runtime action. The caller
    /// must select the explicit new17 profile before any native preparation.
    ///
    /// # Errors
    /// Refuses a foreign plan/Runtime/target, late or repeated selection, absent
    /// verified checkpoint, changed policy or finite requested-byte excess.
    pub(crate) fn retain_restored_coordinator17_construction_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .is_same_original_plan_data(plan)
            || !std::ptr::eq(self.original_activation_slot, target)
            || self.stage.get() != WindowStage::ColdComplete
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.runtime
            .authenticate_runtime_data(runtime, &target.world_binding_hash)?;
        runtime.authenticate_original_restoration_target_data(&self.archive, plan, target)?;
        let row = OriginalRestoredCoordinator17ConstructionData::quote(
            runtime,
            &self.archive,
            target,
            self.policy.maximum_requested_bytes,
        )?;
        self.coordinator17_construction
            .set(row)
            .map_err(|_| RuntimeError::DuplicateOperation)?;
        self.whole_observation.require_observation();
        Ok(())
    }

    pub(crate) fn initialize_restored_coordinator17_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
        world: &crate::node_contract::WorldActivation,
    ) -> Result<(), RuntimeError> {
        let Some(row) = self.coordinator17_construction.get() else {
            return Ok(());
        };
        self.origin()?;
        if !self.install_started.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        runtime.initialize_restored_coordinator17_data(&self.archive, &scope.target, world, row)?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        self.whole_observation.require_observation();
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    /// Installs the same whole-admitted bank before fresh World publication.
    /// No native arm or publication may precede this retained once owner.
    pub(crate) fn initialize_restored_coordinator17_before_activation_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
        target: &crate::node_contract::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let Some(row) = self.coordinator17_construction.get() else {
            return Ok(());
        };
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        if self.install_started.get() || self.activation_world.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.runtime
            .authenticate_runtime_data(runtime, &target.world_binding_hash)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        if &scope.target != target {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.initialize_restored_coordinator17_before_activation_data(
            &self.archive,
            target,
            row,
        )?;
        self.authenticate_original_complete_member_data(plan, scope)?;
        self.whole_observation.require_observation();
        Ok(())
    }
}
