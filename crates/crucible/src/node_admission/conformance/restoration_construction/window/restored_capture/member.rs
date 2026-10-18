//! Authenticates fixed current Capture identities without reopening owner banks.
//!
//! Actual Source and SDK reads hold their own private owner loans. This member
//! check uses only the retained Window/plan/World/scope and verified phases;
//! the independently admitted claim authenticates its row and native read.

use super::*;
use crate::node_contract::OriginalLineageNativeScope;

impl CompleteOriginalRestorationWindow {
    /// Borrows stored imported-closure geometry before any member starts.
    ///
    /// The actual Scope supplies its retained plan, World, attempt identity and
    /// Runtime comparison pointer. The fixed Source slot and the row's original
    /// Source/request provenance are checked without borrowing a Controller or
    /// read owner. These counts grant neither those loans nor native effects.
    ///
    /// # Errors
    /// Refuses foreign current custody, a pending/failed/advanced attempt, a
    /// started member, failed/reentrant writer, unobserved storage, or absent
    /// admitted geometry.
    pub(crate) fn original_restored_capture_imported_closure_storage_data(
        &self,
        plan: &InstalledConformancePlan,
        world: &WorldActivation,
        slot: usize,
        capture_id: &Id,
        runtime: *const NodeRuntime,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(usize, usize, usize, usize, usize, usize, usize, usize), RuntimeError> {
        self.origin()?;
        let selected = self.original_installed_source_index_data(source)?;
        // Retain the genuine Window plan without allocating an expired-Weak
        // diagnostic, including when a foreign caller supplied another plan.
        let original_plan = crate::node_admission::conformance::InstalledConformancePlan(
            self.plan
                .0
                .upgrade()
                .ok_or(RuntimeError::ForeignAuthority)?,
        );
        if !original_plan.is_same_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_restored_capture_archive_identity_data(
            &original_plan,
            world,
            slot,
            capture_id,
            runtime,
        )?;

        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.pending.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.members.iter().any(|member| member.get() != 0)
            || !matches!(
                attempt.writer_join.get(),
                checkpoint::WriterJoinStage::Waiting | checkpoint::WriterJoinStage::Verified
            )
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let row = attempt
            .rows
            .get(selected)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_source_data(source, &attempt.request_data())?;
        row.requested_bytes_data()?;
        Ok(row.capture_imported_closure_storage_data())
    }

    /// Borrows the actual admitted Source row before the archive writer joins.
    ///
    /// The current Window, Source/read/controller owners, complete checkpoint
    /// record and original bytes must all match the latest admitted attempt.
    /// This observer neither submits a member nor constructs a ticket, claim,
    /// current native read, output bank or native construction allowance. The
    /// effect path independently requires its verified writer join and ticket.
    ///
    /// # Errors
    /// Refuses a stale or foreign owner, unsettled whole observation, another
    /// World/cut/ordinal, incomplete checkpoint, changed Runtime7 record/object,
    /// any submitted member, or failed/reentrant writer or Capture state.
    pub(crate) fn original_restored_capture_preflight_construction_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        world: &WorldActivation,
        record: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        controller: *const CnpController,
        read_owner: *const (),
    ) -> Result<OriginalSourceRestoredCaptureConstructionData, RuntimeError> {
        self.origin()?;
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.whole_observation.authenticate_dispatch_data()?;

        // This private descendant borrows the same defining Weak directly so
        // expiry returns a fixed RuntimeError rather than allocating diagnostic
        // text. Keep its genuine Rc alive across all identity helpers below.
        let plan = crate::node_admission::conformance::InstalledConformancePlan(
            self.plan
                .0
                .upgrade()
                .ok_or(RuntimeError::ForeignAuthority)?,
        );
        self.authenticate_suffix_identity_data(
            selected,
            source,
            read_owner,
            world,
            self.original_complete_scope_proof_identity_data()?,
        )?;

        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if ledger.pending.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let slot = ledger
            .attempts
            .len()
            .checked_sub(1)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.members.iter().any(|member| member.get() != 0)
            || !matches!(
                attempt.writer_join.get(),
                checkpoint::WriterJoinStage::Waiting | checkpoint::WriterJoinStage::Verified
            )
            || record.capture_cut != attempt.cut
            || record.capture_ordinal != attempt.ordinal
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_restored_capture_archive_identity_data(
            &plan,
            world,
            slot,
            &attempt.capture_id,
            attempt.runtime,
        )?;
        attempt
            .checkpoint_inputs
            .authenticate_runtime_inputs_data(record, runtime_object)?;
        attempt.checkpoint.object_for_runtime_data(runtime_object)?;

        let row = attempt
            .rows
            .get(selected)
            .and_then(Option::as_ref)
            .copied()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        row.authenticate_owner_data(source, controller, read_owner, &attempt.request_data())?;
        self.whole_observation.authenticate_dispatch_data()?;
        Ok(row)
    }

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

/// Names the preflight's genuine plan upgrade, borrowed ledger and DATA result.
pub(super) fn counter_scratch_data() -> usize {
    type PlanOwner = Rc<crate::node_admission::conformance::Plan>;
    type ImportedClosureStorage = (usize, usize, usize, usize, usize, usize, usize, usize);
    size_of::<PlanOwner>()
        + size_of::<Option<PlanOwner>>()
        + size_of::<Result<PlanOwner, RuntimeError>>()
        + size_of::<InstalledConformancePlan>()
        + size_of::<Result<InstalledConformancePlan, crate::node_admission::EvidenceError>>()
        + size_of::<std::cell::Ref<'static, Ledger>>()
        + size_of::<Result<std::cell::Ref<'static, Ledger>, std::cell::BorrowError>>()
        + size_of::<Result<&'static Attempt, RuntimeError>>()
        + size_of::<Option<&'static OriginalSourceRestoredCaptureConstructionData>>()
        + size_of::<OriginalSourceRestoredCaptureConstructionData>()
        + size_of::<Result<OriginalSourceRestoredCaptureConstructionData, RuntimeError>>()
        + size_of::<OriginalRestoredCaptureRequestData<'static>>()
        + size_of::<&OriginalLineageRuntimeRecord>()
        + size_of::<&InputPayload>()
        + size_of::<*const CnpController>()
        + size_of::<*const ()>()
        + size_of::<*const NodeRuntime>()
        + size_of::<std::slice::Iter<'static, Cell<u8>>>()
        + size_of::<Option<usize>>()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<&InstalledConformancePlan>()
        + size_of::<&WorldActivation>()
        + size_of::<&Id>()
        + size_of::<ImportedClosureStorage>()
        + size_of::<Result<ImportedClosureStorage, RuntimeError>>()
        + OriginalSourceRestoredCaptureConstructionData::authenticate_source_counter_scratch_data()
        + size_of::<Result<(), RuntimeError>>()
}
