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
use crate::attachment_slot_state::{self, AttachmentSlotStateError, DurableAttachmentSlotV1};
use crate::attachment_state::{
    self, AttachmentDesiredMutationV1, AttachmentDesiredStateError,
    CommittedCurrentAttachmentDesiredStateV1, DurableAttachmentDesiredStateV1,
};
use crate::mount_attempt::CurrentMountInventoryReconciliationV1;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{
    self, CurrentNamespaceTarget, CurrentRuntimeScopeError, CurrentRuntimeScopePolicy,
    NamespaceTargetError, NamespaceTargetOutcome, RuntimeGenerationError, RuntimeScopeClient,
    RuntimeScopeHolder,
};
use crate::{Journal, JournalError};

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
