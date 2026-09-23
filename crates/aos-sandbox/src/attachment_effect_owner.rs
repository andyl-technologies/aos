//! Joins protected attachment intent with live namespace and Mount evidence.
//!
//! The production effect callback already owns the protected controller journal.
//! This narrow owner lets that callback reuse the attachment state machine and
//! reconciler without granting authority from public projections or durable
//! inventory alone. A mutation still requires a freshly bound namespace target;
//! reconciliation requires an authenticated current-target Mount inventory.

use aos_sandbox_core::{AttachmentId, AttachmentSlotId, OperationId, RawPairedClockSample};

use crate::attachment_reconciliation::{
    self, AttachmentReconciliationError, CurrentAttachmentReconciliationV1,
};
use crate::attachment_slot_state::{
    self, AttachmentSlotMutationV1, AttachmentSlotStateError, CommittedCurrentAttachmentSlotV1,
    DurableAttachmentSlotV1,
};
use crate::attachment_state::{
    self, AttachmentDesiredMutationV1, AttachmentDesiredStateError,
    CommittedCurrentAttachmentDesiredStateV1, DurableAttachmentDesiredStateV1,
};
use crate::destination_slot_effect::{
    self, CompletedCurrentDestinationSlotAttemptV1, DestinationSlotDispatchClient,
    DestinationSlotEffectError, DurableCurrentDestinationSlotAttemptV1,
    PreparedCurrentDestinationSlotDispatchV1, PreparedCurrentDestinationSlotResumeDispatchV1,
    PreparedCurrentDestinationSlotResumeV1, PreparedCurrentDestinationSlotV1,
};
use crate::destination_slot_inventory::{
    self, CurrentDestinationSlotReconciliationV1, DestinationSlotInventoryClient,
    DurableDestinationSlotInventorySnapshotV1,
};
use crate::mount_attempt::{CurrentMountInventoryReconciliationV1, MountAttemptError};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{
    self, CurrentAssignmentTarget, CurrentNamespaceTarget, CurrentRuntimeScopeError,
    CurrentRuntimeScopePolicy, NamespaceTargetError, NamespaceTargetOutcome,
    RuntimeGenerationError, RuntimeScopeClient, RuntimeScopeHolder,
};
use crate::{Journal, JournalError, SignedBrokerPlan};

/// Reports failure to bind a fresh Host observation to protected namespace authority.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedAttachmentTargetErrorV1 {
    /// Protected journal custody was unavailable or unhealthy.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Current holder, signed authority, or Host payload observation failed.
    #[error(transparent)]
    Runtime(#[from] CurrentRuntimeScopeError),
    /// The observed execution changed or its audit history failed.
    #[error(transparent)]
    Generation(#[from] RuntimeGenerationError),
    /// The signed namespace target changed or needs an assignment successor.
    #[error(transparent)]
    Target(#[from] NamespaceTargetError),
}

/// Borrows protected controller custody for one attachment effect step.
pub struct ProtectedAttachmentEffectOwnerV1<'journal> {
    journal: &'journal mut Journal,
}

impl<'journal> ProtectedAttachmentEffectOwnerV1<'journal> {
    /// Opens the attachment effect seam against protected controller custody.
    ///
    /// # Errors
    ///
    /// Rejects an unhealthy journal or one without protected-open provenance.
    pub fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        journal.ensure_protected_authority()?;
        Ok(Self { journal })
    }

    /// Binds a fresh authenticated Host observation to its signed namespace target.
    ///
    /// Trusted deployment supplies the holder selector, single-use Host channel,
    /// pinned verification policy, and paired clock. The journal selects and
    /// rechecks actual current authority. A returned advancement proposal is
    /// inert until a signed assignment successor is published and a new Host
    /// observation is acquired.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, missing or changed authority, a failed Host
    /// observation, invalid audit history, or stale namespace allocation.
    pub fn observe_current_target<T>(
        &mut self,
        holder: RuntimeScopeHolder,
        client: RuntimeScopeClient,
        policy: CurrentRuntimeScopePolicy,
        clock: &mut T,
    ) -> Result<NamespaceTargetOutcome, ProtectedAttachmentTargetErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        let scope =
            runtime_scope::acquire_current_runtime(self.journal, holder, client, policy, clock)?;
        let generation =
            runtime_scope::CurrentRuntimeGeneration::track(scope, self.journal, clock)?;
        Ok(CurrentNamespaceTarget::bind(
            generation,
            self.journal,
            clock,
        )?)
    }

    /// Loads the current desired generation, including a release tombstone.
    ///
    /// This is readback, not live namespace or Mount authority.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy custody and invalid attachment history.
    pub fn current(
        &self,
        attachment_id: AttachmentId,
    ) -> Result<Option<DurableAttachmentDesiredStateV1>, AttachmentDesiredStateError> {
        self.journal.ensure_protected_authority()?;
        attachment_state::get(self.journal, attachment_id)
    }

    /// Loads the exact current destination-slot binding, including a tombstone.
    ///
    /// This structural readback cannot prove a live Mount-owned descriptor.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody or invalid slot history.
    pub fn current_slot(
        &self,
        slot_id: AttachmentSlotId,
    ) -> Result<Option<DurableAttachmentSlotV1>, AttachmentSlotStateError> {
        self.journal.ensure_protected_authority()?;
        attachment_slot_state::get_current(self.journal, slot_id)
    }

    /// Commits a destination slot declared by the current signed sandbox spec.
    ///
    /// The existing slot state machine derives its binding from the fresh
    /// namespace target and compare-and-swaps the exact operation. This only
    /// records the logical slot; Mount must separately materialize and confirm
    /// its physical destination before an attachment can use it.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale target authority, undeclared slots,
    /// conflicting history, or failed durability.
    pub fn commit_current_slot<T>(
        &mut self,
        target: CurrentNamespaceTarget,
        mutation: AttachmentSlotMutationV1,
        clock: &mut T,
    ) -> Result<CommittedCurrentAttachmentSlotV1, AttachmentSlotStateError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        attachment_slot_state::commit_current(self.journal, target, mutation, clock)
    }

    /// Records one complete, freshly queried Mount destination-slot inventory.
    ///
    /// The snapshot is observation evidence; it cannot authorize a materialize
    /// or reap effect without current signed assignment authority.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, unauthenticated or malformed broker state,
    /// stale controller state, and failed durability.
    pub fn record_slot_inventory(
        &mut self,
        client: DestinationSlotInventoryClient,
    ) -> Result<DurableDestinationSlotInventorySnapshotV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        destination_slot_inventory::record_snapshot(self.journal, client)
    }

    /// Classifies an exact current logical slot against a retained Mount query.
    ///
    /// The classification is nonauthorizing. Effect preparation must recheck
    /// the slot, inventory, and current signed assignment.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, changed slot or inventory state, invalid
    /// Mount correlation, or malformed protected history.
    pub fn reconcile_current_slot(
        &mut self,
        slot: DurableAttachmentSlotV1,
        snapshot: DurableDestinationSlotInventorySnapshotV1,
    ) -> Result<CurrentDestinationSlotReconciliationV1, MountAttemptError> {
        self.journal.ensure_protected_authority()?;
        destination_slot_inventory::reconcile_current(self.journal, slot, snapshot)
    }

    /// Prepares a signed-plan candidate for exact slot materialization or reap.
    ///
    /// The prepared request cannot be dispatched until a separately signed
    /// Mount plan is bound and a protected attempt is durably admitted.
    ///
    /// # Errors
    ///
    /// Rejects stale slot, inventory, or signed assignment authority, an
    /// action without a new effect, invalid request semantics, or expired time.
    pub fn prepare_current_slot_effect<T>(
        &mut self,
        reconciliation: CurrentDestinationSlotReconciliationV1,
        target: CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::prepare_current(self.journal, reconciliation, target, clock)
    }

    /// Rebinds a pending slot effect to its original protected attempt bytes.
    ///
    /// Recovery cannot substitute a newly signed plan or current inventory for
    /// the original request; the existing state machine checks every durable
    /// correlation before returning a resumable candidate.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed attempts, stale slot or assignment authority,
    /// invalid original request bytes, and expired time.
    pub fn prepare_current_slot_resume<T>(
        &mut self,
        reconciliation: CurrentDestinationSlotReconciliationV1,
        target: CurrentAssignmentTarget,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotResumeV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::prepare_current_resume(self.journal, reconciliation, target, clock)
    }

    /// Binds a separately signed Mount plan to exact new slot-effect semantics.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale assignment or inventory, a plan
    /// signed outside current authority, or a grant that differs from the
    /// prepared request.
    pub fn bind_current_slot_plan<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotV1,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotDispatchV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::bind_signed_plan(self.journal, prepared, signed_plan, clock)
    }

    /// Binds the exact original signed Mount plan to a recovered slot attempt.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, or a plan whose digest or
    /// semantics differ from the original durable attempt.
    pub fn bind_current_slot_resume_plan<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotResumeV1,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentDestinationSlotResumeDispatchV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::bind_resume_signed_plan(self.journal, prepared, signed_plan, clock)
    }

    /// Durably admits an exact signed slot effect before any Mount I/O.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, a deadline outside the
    /// retained lease, conflicting attempts, or failed durability.
    pub fn admit_current_slot_effect<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotDispatchV1,
        deadline_boottime_nanoseconds: u64,
        clock: &mut T,
    ) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::admit_current(
            self.journal,
            prepared,
            deadline_boottime_nanoseconds,
            clock,
        )
    }

    /// Reopens the original durable slot attempt under current authority.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, a changed attempt or
    /// original plan, and an elapsed protected deadline.
    pub fn resume_current_slot_effect<T>(
        &mut self,
        prepared: PreparedCurrentDestinationSlotResumeDispatchV1,
        clock: &mut T,
    ) -> Result<DurableCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::resume_current(self.journal, prepared, clock)
    }

    /// Dispatches a durable slot attempt through an authenticated Mount channel.
    ///
    /// Success records the exact Mount receipt. A later fresh signed inventory
    /// must still confirm physical Ready before an attachment may proceed.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale authority, broker or channel
    /// failure, a mismatched receipt, and failed completion durability.
    pub fn dispatch_current_slot_effect<T>(
        &mut self,
        attempt: DurableCurrentDestinationSlotAttemptV1,
        client: DestinationSlotDispatchClient,
        clock: &mut T,
    ) -> Result<CompletedCurrentDestinationSlotAttemptV1, DestinationSlotEffectError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        destination_slot_effect::dispatch_current(self.journal, attempt, client, clock)
    }

    /// Loads the exact historical generation committed by an operation.
    ///
    /// A successor can replace the current public projection before an older
    /// operation's effect receipt is recovered. The operation index retains its
    /// original desired bytes without making them current again.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy custody and invalid attachment history.
    pub fn operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<DurableAttachmentDesiredStateV1>, AttachmentDesiredStateError> {
        self.journal.ensure_protected_authority()?;
        attachment_state::get_operation(self.journal, operation_id)
    }

    /// Commits an exact desired generation under a live namespace target.
    ///
    /// The existing state machine checks the target before and after the
    /// commit, including source revision, destination slot, and predecessor
    /// fences. A successful return records intent only; Mount remains separate.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale live authority, invalid intent or
    /// predecessors, conflicting slot or source state, and failed durability.
    pub fn commit_current<T>(
        &mut self,
        target: CurrentNamespaceTarget,
        mutation: AttachmentDesiredMutationV1,
        clock: &mut T,
    ) -> Result<CommittedCurrentAttachmentDesiredStateV1, AttachmentDesiredStateError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal.ensure_protected_authority()?;
        attachment_state::commit_current(self.journal, target, mutation, clock)
    }

    /// Plans the next step from exact desired state and fresh Mount inventory.
    ///
    /// The result is nonauthorizing. A later broker effect must use the
    /// existing guarded Mount preparation and dispatch path.
    ///
    /// # Errors
    ///
    /// Rejects unprotected custody, stale namespace or inventory evidence,
    /// changed desired state, invalid history, or failed clock sampling.
    pub fn reconcile_current<T>(
        &mut self,
        desired: DurableAttachmentDesiredStateV1,
        inventory: CurrentMountInventoryReconciliationV1,
        clock: &mut T,
    ) -> Result<CurrentAttachmentReconciliationV1, AttachmentReconciliationError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.journal
            .ensure_protected_authority()
            .map_err(AttachmentDesiredStateError::from)?;
        attachment_reconciliation::reconcile_current(self.journal, desired, inventory, clock)
    }
}
