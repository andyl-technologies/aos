//! Authenticates fixed current Capture identities without reopening owner banks.
//!
//! Actual Source and SDK reads hold their own private owner loans. This member
//! check uses only the retained Window/plan/World/scope and verified phases;
//! the independently admitted claim authenticates its row and native read.

use super::*;
use crate::node_contract::OriginalLineageNativeScope;

impl CompleteOriginalRestorationWindow {
    /// Authenticates the same current archive scope and retained admission.
    ///
    /// The runtime pointer is compared only. Its genuine live source is checked
    /// through the Window's retained runtime identity; the scope constructor
    /// separately validates the actual Runtime, activation and Host source.
    /// Writer/checkpoint byte joins and all native owner claims remain required.
    ///
    /// # Errors
    /// Refuses a foreign plan/World/runtime/attempt, pending whole observation,
    /// absent construction or failed/spent capture custody.
    pub(crate) fn authenticate_restored_capture_archive_identity_data(
        &self,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        slot: usize,
        capture_id: &Id,
        runtime: *const NodeRuntime,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_identity_data(plan, scope)?;
        self.runtime
            .authenticate_world_activation_data(world, &scope.target)?;
        if !self.restored_capture_in_flight.get()
            || self.phase_in_flight.get()
            || self.suffix_in_flight.get()
            || !self
                .activation_world
                .get()
                .is_some_and(|actual| actual.same_authority(world))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        if runtime.is_null()
            || attempt.runtime != runtime
            || &attempt.capture_id != capture_id
            || attempt.stage.get() != Stage::Admitted
            || attempt.rows.iter().any(Option::is_none)
            || attempt.checkpoint.object_data().is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Borrows the actual concrete Source after comparing its erased owner.
    ///
    /// This DATA loan grants no read, quote credit or administrative effect.
    ///
    /// # Errors
    /// Refuses foreign Window origin, an unknown selected slot or another Source.
    pub(crate) fn original_restored_capture_source_data(
        &self,
        selected: usize,
        erased: &dyn crate::node_adapters::cnp::CnpSemanticSource,
    ) -> Result<&PacketCompleteSemanticSource, RuntimeError> {
        self.origin()?;
        if self.original_installed_source_index_data(erased)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.sources
            .get(selected)
            .map(Rc::as_ref)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    /// Authenticates the actual current member during a Capture input loan.
    ///
    /// # Errors
    /// Refuses another installed member, plan, World or scope, incomplete first
    /// observation, concurrent suffix work, or absence of retained Capture custody.
    pub(crate) fn authenticate_restored_capture_signing_member_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        scope: &OriginalLineageNativeScope,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_retained_observation_identity_data(
            selected,
            source,
            self.original_complete_scope_proof_identity_data()?,
        )?;
        if !self.restored_capture_in_flight.get()
            || self.suffix_in_flight.get()
            || !self
                .observation_phases
                .iter()
                .all(|phase| phase.is_verified())
            || !self
                .activation_world
                .get()
                .is_some_and(|actual| actual.same_authority(world))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.authenticate_original_complete_identity_data(plan, scope)?;
        self.runtime
            .authenticate_world_activation_data(world, &scope.target)
    }
}
