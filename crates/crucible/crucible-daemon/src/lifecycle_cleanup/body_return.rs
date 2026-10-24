//! Retains one original external-body destination before the body is exported.
//!
//! The destination owns the same token Box and an existing queue reference.
//! Its private construction validates the immutable index, occupied epoch and
//! exclusive return latch. Delivery consumes that witness and cannot select a
//! different role, run cleanup or allocate an owner.

use super::*;

/// Owns the original reserved destination of one externally held body.
///
/// This value moves inside its actual lifecycle. It is not cloneable and grants
/// no cleanup authority. The original queue reference lasts only until custody
/// delivery; the stored body never retains this strong edge back to its queue.
#[must_use = "the original body must return through its own destination"]
pub struct SourceBodyReturn {
    queue: Arc<LifecycleCleanupQueue>,
    index: usize,
    epoch: u64,
    reservation: Box<reservation::CleanupReservation>,
}

impl SourceBodyReturn {
    pub(super) fn new(
        queue: Arc<LifecycleCleanupQueue>,
        index: usize,
        epoch: u64,
        reservation: Box<reservation::CleanupReservation>,
    ) -> Self {
        Self {
            queue,
            index,
            epoch,
            reservation,
        }
    }

    /// Accepts the same body into its exclusively reserved original cell.
    ///
    /// The pre-export constructor and unique token establish a vacant matching
    /// destination. Its retained report reference prevents epoch reuse, and the
    /// queue never resizes its slot vector. Only fixed control metadata is
    /// touched while locked. Poison preserves custody and quarantine together.
    pub(crate) fn deliver(
        self,
        owner: Box<
            dyn ProductionVmCleanupOwner<
                    Failure = crate::ProductionVmConstructionCleanupError,
                    PostBody = ProductionVmConstructionPostBody,
                >,
        >,
    ) -> Box<
        dyn ProductionVmCleanupHandoff<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = ProductionVmConstructionPostBody,
            >,
    > {
        let Self {
            queue,
            index,
            epoch: _,
            reservation,
        } = self;
        let slot = &queue.slots[index];
        let (mut cell, poisoned) = match slot.cell.lock() {
            Ok(cell) => (cell, false),
            Err(poison) => (poison.into_inner(), true),
        };
        // The sole token was moved into this witness before body export. No
        // other publisher can consume it, and the driver cannot close an
        // outstanding external destination. This assignment replaces no owner.
        cell.owner = Some(owner);
        cell.handoff = true;
        slot.external_return_reserved
            .store(false, Ordering::Release);
        if poisoned {
            crate::ProductionVmConstructionCleanupError::retain_first(
                &mut cell.first_failure,
                crate::ProductionVmConstructionCleanupError::Poisoned,
            );
        }
        slot.request_retirement();
        let _published = slot
            .phase
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |phase| {
                Some(
                    if poisoned || phase == CleanupPhase::DestructionRefused as u8 {
                        CleanupPhase::DestructionRefused as u8
                    } else {
                        CleanupPhase::Queued as u8
                    },
                )
            });
        drop(cell);
        // The same token becomes the receipt. Its existing pin stays live;
        // no new receipt Box is allocated, and the strong queue edge ends
        // outside the control mutex after canonical acceptance.
        drop(queue);
        reservation
    }

    /// Restores the same token while its body remains in exclusive Main custody.
    ///
    /// This pure pre-export cancellation is used only when the final transfer
    /// was not committed. It creates neither cleanup nor physical-return proof.
    pub(crate) fn cancel_unexported(
        self,
    ) -> Box<
        dyn ProductionVmCleanupReservation<
                Failure = crate::ProductionVmConstructionCleanupError,
                PostBody = ProductionVmConstructionPostBody,
                ReturnDestination = SourceBodyReturn,
            >,
    > {
        let Self {
            queue,
            index,
            epoch: _,
            mut reservation,
        } = self;
        let slot = &queue.slots[index];
        slot.external_return_reserved
            .store(false, Ordering::Release);
        reservation.cancel_return_registration(slot);
        drop(queue);
        reservation
    }

    /// Cancels only an export still held by its physically cleaned Main body.
    ///
    /// This is not a return proof. The owning carrier must still be destroyed
    /// before controls close. The caller holds the actual body exclusively;
    /// no external facade ever receives this cancellation operation.
    pub(crate) fn cancel_for_owned_body(self) {
        let slot = &self.queue.slots[self.index];
        slot.external_return_reserved
            .store(false, Ordering::Release);
        // Returning the original pin performs only atomic metadata work. The
        // canonical body-destruction journal still bars every physical refund.
        drop(self);
    }

    pub(crate) fn matches_input_return(&self, input: &ServiceInputReturn) -> bool {
        Arc::ptr_eq(&self.queue, &input.queue)
            && self.index == input.index
            && self.epoch == input.epoch
    }

    pub(crate) fn matches_selector(&self, selector: &PreparedSourceSelector) -> bool {
        Weak::ptr_eq(&Arc::downgrade(&self.queue), &selector.key.queue)
            && self.index == selector.key.index
            && self.epoch == selector.key.epoch
    }
}

impl std::fmt::Debug for SourceBodyReturn {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceBodyReturn")
            .field("index", &self.index)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}
