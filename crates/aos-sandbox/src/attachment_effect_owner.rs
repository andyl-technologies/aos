//! Joins protected attachment intent with live namespace and Mount evidence.
//!
//! The production effect callback already owns the protected controller journal.
//! This narrow owner lets that callback reuse the attachment state machine and
//! reconciler without granting authority from public projections or durable
//! inventory alone. A mutation still requires a freshly bound namespace target;
//! reconciliation requires an authenticated current-target Mount inventory.

use aos_sandbox_core::{AttachmentId, OperationId, RawPairedClockSample};

use crate::attachment_reconciliation::{
    self, AttachmentReconciliationError, CurrentAttachmentReconciliationV1,
};
use crate::attachment_state::{
    self, AttachmentDesiredMutationV1, AttachmentDesiredStateError,
    CommittedCurrentAttachmentDesiredStateV1, DurableAttachmentDesiredStateV1,
};
use crate::mount_attempt::CurrentMountInventoryReconciliationV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::CurrentNamespaceTarget;
use crate::{Journal, JournalError};

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
