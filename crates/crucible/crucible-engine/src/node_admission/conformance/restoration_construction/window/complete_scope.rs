//! Constructs the retained four-owner proof only through actual owner validators.
//!
//! Native receipts are reauthenticated on their same three runtime-owned nodes.
//! The fourth actual Host2 node then checks the unchanged source common record.
//! Materialized scope is inert until the separate private final-context issuer
//! repeats that conjunction and the whole installed ownership/currentness gate.

use super::*;

impl CompleteOriginalRestorationWindow {
    /// Retains complete scope/proof output after all four actual owners validate.
    ///
    /// The original policy already funds the named scope/context future rows.
    /// This issues no final context, readiness or native activation permission.
    /// A whole-owner requery is mandatory before any later public group action.
    ///
    /// # Errors
    /// Refuses missing real native/Host ownership, changed journals/targets,
    /// repeated construction, failed callbacks, exhausted original credit or
    /// a changed terminal live member. All partial banks remain retained.
    pub fn construct_original_complete_scope(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_complete_declaration_data()?;
        let attempt = super::dispatch::RestorationDispatchAttempt::begin(self)?;
        if self.complete_scope.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.inspect_original_native_group_data(plan, runtime, activation)?;
        {
            let mut slot = self
                .scope_partial
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if slot.is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            *slot = Some(super::scope_owner::OriginalRestorationScopeOwner::empty());
            let owner = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
            owner.construct_fields(&self.archive, activation)?;
            self.inspect_original_host_continuation_data(
                plan,
                runtime,
                activation,
                owner.owner_mappings_data(),
                owner.journals_data(),
            )?;
            let identities = [
                self.native_continuations[0]
                    .get()
                    .ok_or(RuntimeError::InvalidReceipt)?
                    .held_reference,
                self.native_continuations[1]
                    .get()
                    .ok_or(RuntimeError::InvalidReceipt)?
                    .held_reference,
                self.native_continuations[2]
                    .get()
                    .ok_or(RuntimeError::InvalidReceipt)?
                    .held_reference,
            ];
            owner.construct_proof_and_scope(&self.archive, activation, identities)?;
            if owner.retained_storage_data(self.policy.maximum_requested_bytes)?
                > self.final_construction.scope_peak_bytes
            {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        // The mutable proof bank is no longer lent during Source callbacks.
        self.inspect_original_native_group_data(plan, runtime, activation)?;
        {
            let slot = self
                .scope_partial
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let scope = slot
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .scope_data()?;
            self.inspect_original_host_continuation_data(
                plan,
                runtime,
                activation,
                &scope.owners,
                &scope.journals,
            )?;
        }
        self.authenticate_original_runtime_member_current_data(&activation.world_binding_hash)?;
        observation::authenticate_started_stage_data(
            &self.stage,
            WindowStage::TransactionAdmitted,
        )?;
        {
            let mut slot = self
                .scope_partial
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let owner = slot.take().ok_or(RuntimeError::OwnerUnavailable)?;
            if let Err(owner) = self.complete_scope.set(owner) {
                *slot = Some(owner);
                return Err(RuntimeError::DuplicateOperation);
            }
        }
        attempt.complete()?;
        Ok(())
    }
}
