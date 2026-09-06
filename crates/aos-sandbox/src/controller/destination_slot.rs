//! Exposes the controller's signed destination-slot effect lifecycle.

use aos_sandbox_core::RawPairedClockSample;

use super::{ActivatedOperationCompiler, NodeController};
use crate::SingleNodeEffectExecutor;

impl<C, E> NodeController<C, E>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    /// Derives a new materialize, rematerialize, or reap request.
    ///
    /// The protocol body is assembled only from protected logical state,
    /// authenticated inventory, retained canonical specification bytes, and the
    /// supplied current assignment target. No live payload is required, and the
    /// result grants no broker authority.
    ///
    /// # Errors
    ///
    /// Rejects stale reconciliation or assignment authority, missing canonical
    /// state, a non-effect action, or an invalid protocol 1.4 request.
    pub fn prepare_current_destination_slot<T>(
        &mut self,
        reconciliation: crate::CurrentDestinationSlotReconciliationV1,
        target: crate::runtime_scope::CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentDestinationSlotV1, crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::prepare_current(
            self.reconciler.journal_mut(),
            reconciliation,
            target,
            clock,
        )
    }

    /// Rechecks a derived destination-slot request without binding authority.
    ///
    /// # Errors
    ///
    /// Rejects changed logical, inventory, specification, assignment, or
    /// deadline state.
    pub fn recheck_current_destination_slot_preparation<T>(
        &mut self,
        prepared: &crate::PreparedCurrentDestinationSlotV1,
        clock: &mut T,
    ) -> Result<(), crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Binds a separately signed Mount 1.4 plan to the derived slot request.
    ///
    /// # Errors
    ///
    /// Rejects stale preparation, a plan for another assignment or version, an
    /// absent exact semantic grant, invalid signature, or expired authority.
    pub fn bind_current_destination_slot_plan<T>(
        &mut self,
        prepared: crate::PreparedCurrentDestinationSlotV1,
        signed_plan: crate::SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentDestinationSlotDispatchV1, crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::bind_signed_plan(
            self.reconciler.journal_mut(),
            prepared,
            signed_plan,
            clock,
        )
    }

    /// Rechecks a signed destination-slot preparation before durable admission.
    ///
    /// # Errors
    ///
    /// Rejects changed request inputs, signed plan, live assignment, or deadline.
    pub fn recheck_current_destination_slot_dispatch<T>(
        &mut self,
        prepared: &crate::PreparedCurrentDestinationSlotDispatchV1,
        clock: &mut T,
    ) -> Result<(), crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Durably admits an exact signed destination-slot packet before Mount I/O.
    ///
    /// Admission intentionally invalidates the planning inventory snapshot. The
    /// returned live token instead retains current logical and assignment guards.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, an unsafe deadline, request-ID conflict, corrupt
    /// cross-references, capacity exhaustion, or a failed protected commit.
    pub fn admit_current_destination_slot_attempt<T>(
        &mut self,
        prepared: crate::PreparedCurrentDestinationSlotDispatchV1,
        deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<crate::DurableCurrentDestinationSlotAttemptV1, crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::admit_current(
            self.reconciler.journal_mut(),
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Reacquires preparation for an exact broker-reported pending slot effect.
    ///
    /// The original body and deadline come from durable admission. Inventory
    /// must report the matching materializing or reaping operation.
    ///
    /// # Errors
    ///
    /// Rejects missing or completed attempts, non-pending reconciliation, stale
    /// live authority, changed broker correlations, or expired original work.
    pub fn prepare_current_destination_slot_resume<T>(
        &mut self,
        reconciliation: crate::CurrentDestinationSlotReconciliationV1,
        target: crate::runtime_scope::CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<crate::PreparedCurrentDestinationSlotResumeV1, crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::prepare_current_resume(
            self.reconciler.journal_mut(),
            reconciliation,
            target,
            clock,
        )
    }

    /// Rechecks exact pending preparation before its signed plan is rebound.
    ///
    /// # Errors
    ///
    /// Rejects changed inventory, attempt bytes, logical state, or live authority.
    pub fn recheck_current_destination_slot_resume<T>(
        &mut self,
        prepared: &crate::PreparedCurrentDestinationSlotResumeV1,
        clock: &mut T,
    ) -> Result<(), crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Rebinds the exact original signed Mount plan for pending recovery.
    ///
    /// A current ownership-lease renewal may change only the later envelope; the
    /// plan, body, semantic identity, and original deadline remain exact.
    ///
    /// # Errors
    ///
    /// Rejects plan substitution, stale recovery evidence, or invalid authority.
    pub fn bind_current_destination_slot_resume_plan<T>(
        &mut self,
        prepared: crate::PreparedCurrentDestinationSlotResumeV1,
        signed_plan: crate::SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<
        crate::PreparedCurrentDestinationSlotResumeDispatchV1,
        crate::DestinationSlotEffectError,
    >
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::bind_resume_signed_plan(
            self.reconciler.journal_mut(),
            prepared,
            signed_plan,
            clock,
        )
    }

    /// Rechecks signed pending recovery before reconstructing its envelope.
    ///
    /// # Errors
    ///
    /// Rejects any changed plan, attempt, inventory, or live authority input.
    pub fn recheck_current_destination_slot_resume_dispatch<T>(
        &mut self,
        prepared: &crate::PreparedCurrentDestinationSlotResumeDispatchV1,
        clock: &mut T,
    ) -> Result<(), crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        prepared.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Reconstructs a current-lease packet for one durable pending effect.
    ///
    /// # Errors
    ///
    /// Rejects changed immutable bytes, non-monotonic lease authority, stale
    /// inventory, or an elapsed original deadline.
    pub fn resume_current_destination_slot_attempt<T>(
        &mut self,
        prepared: crate::PreparedCurrentDestinationSlotResumeDispatchV1,
        clock: &mut T,
    ) -> Result<crate::DurableCurrentDestinationSlotAttemptV1, crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::resume_current(
            self.reconciler.journal_mut(),
            prepared,
            clock,
        )
    }

    /// Rechecks an admitted or reconstructed slot attempt without dispatching it.
    ///
    /// # Errors
    ///
    /// Rejects stale logical or assignment authority, substituted durable bytes,
    /// changed signed authority, or an elapsed deadline.
    pub fn recheck_current_destination_slot_attempt<T>(
        &mut self,
        attempt: &crate::DurableCurrentDestinationSlotAttemptV1,
        clock: &mut T,
    ) -> Result<(), crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        attempt.recheck(self.reconciler.journal_mut(), clock)
    }

    /// Dispatches a durable destination-slot packet and records exact success.
    ///
    /// The Mount response writer is authenticated through kernel record subjects.
    /// A successful receipt commits before changed logical state can suppress the
    /// returned live completion token.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, service substitution, protocol mismatch, a
    /// non-terminal or cross-resource result, conflicting replay, or journal failure.
    pub fn dispatch_current_destination_slot_attempt<T>(
        &mut self,
        attempt: crate::DurableCurrentDestinationSlotAttemptV1,
        client: crate::DestinationSlotDispatchClient,
        clock: &mut T,
    ) -> Result<crate::CompletedCurrentDestinationSlotAttemptV1, crate::DestinationSlotEffectError>
    where
        T: FnMut() -> Result<
            RawPairedClockSample,
            crate::ownership_authority::ProtectedOwnershipClockError,
        >,
    {
        crate::destination_slot_effect::dispatch_current(
            self.reconciler.journal_mut(),
            attempt,
            client,
            clock,
        )
    }
}
