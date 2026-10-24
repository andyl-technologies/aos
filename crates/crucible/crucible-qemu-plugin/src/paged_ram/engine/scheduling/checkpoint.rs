//! Holds accepted placement work while a checkpoint detaches its native mailbox.
//!
//! A request closes the actual queue before detachment. Only a matched native
//! callback can issue detached evidence under its actual native proof root.
//! Retained work is not applied policy or an empty-work proof. Final disposition
//! must re-enqueue that same work before reopening admission.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::paged_ram::controller::{CheckpointWorkAdmission, HeldCheckpointWork};

#[derive(Clone, Copy, PartialEq, Eq)]
struct HeldPlacement {
    transaction: u64,
    policy_generation: Option<u64>,
    detached: bool,
}

/// Keeps one requested or detached checkpoint cut in the actual placement queue.
#[derive(Default)]
pub(in crate::paged_ram::engine) struct PlacementCapture {
    issued_transaction: u64,
    held: Option<HeldPlacement>,
    completed_receipt: Option<QueuedPlacement>,
    disposition_uncertain: bool,
    held_work: Option<HeldCheckpointWork>,
    mailbox_restored: bool,
    native_mailbox: Option<crate::runtime::NativeMailbox>,
    native_restore_attempted: bool,
    local_work_released: bool,
}

/// Names the mailbox cut observed from the authentic native proof owner.
///
/// Production construction follows only the native v2 tuple check while State
/// and the actual placement queue are held; ordinary cancellation never issues it.
pub(super) struct DetachedCheckpointMailbox {
    transaction: u64,
}

impl PlacementCapture {
    pub(in crate::paged_ram::engine) fn is_held(&self) -> bool {
        self.held.is_some()
    }

    pub(super) fn require_open(&self) -> Result<(), RamError> {
        if self.is_held() {
            return Err(RamError::Invariant(
                "checkpoint retains placement admission",
            ));
        }
        Ok(())
    }
}

impl PlacementQueue {
    fn checkpoint_receipt_generation(&self) -> Option<u64> {
        self.receipt
            .as_ref()
            .or(self.capture.completed_receipt.as_ref())
            .map(|receipt| receipt.generation)
    }

    pub(super) fn require_dispatch(&self) -> Result<(), RamError> {
        if self.capture.held.is_some_and(|held| held.detached) {
            return Err(RamError::Invariant("checkpoint detached placement mailbox"));
        }
        Ok(())
    }

    pub(super) fn finish_receipt(
        &mut self,
        generation: u64,
        publish: impl FnOnce() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        self.require_dispatch()?;
        if self.capture.disposition_uncertain {
            return Err(RamError::Invariant(
                "checkpoint placement disposition uncertain",
            ));
        }
        if self.capture.is_held() {
            let Some(receipt) = self.receipt.as_ref() else {
                return Ok(());
            };
            if receipt.generation != generation {
                return Ok(());
            }
            if let Err(error) = receipt.operation.complete() {
                self.capture.disposition_uncertain = true;
                return Err(error.into());
            }
            if let Err(error) = publish() {
                self.capture.disposition_uncertain = true;
                return Err(error);
            }
            // A callback admitted before the request may finish. Its terminal
            // receipt remains owned until native disposition; no capacity or
            // empty-work proof follows from removing it from dispatch.
            self.capture.completed_receipt = self.receipt.take();
            Ok(())
        } else {
            finish_queued_receipt(&mut self.receipt, Some(generation), publish)
        }
    }

    fn retain_checkpoint_work(
        &mut self,
        admission: &mut CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        self.held_checkpoint(transaction)?;
        if self.capture.held_work.is_some() {
            return Ok(());
        }
        let Some(receipt) = self.receipt.as_ref() else {
            return Ok(());
        };
        let loan = receipt
            .operation
            .clone()
            .retain_checkpoint_work(admission)?;
        // Save the actual operation alias before any later readiness predicate
        // can refuse. It remains unfinished, even while native detach is pending.
        self.capture.held_work = Some(loan);
        Ok(())
    }

    fn check_checkpoint_work(
        &self,
        admission: &CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        self.held_checkpoint(transaction)?;
        if let Some(loan) = self.capture.held_work.as_ref() {
            loan.check(admission)
        } else {
            // An absent receipt allows no scalar unfinished-work subtraction.
            admission.check_settled()
        }
    }

    fn request_checkpoint(&mut self, transaction: u64) -> Result<(), RamError> {
        let policy_generation = self.checkpoint_receipt_generation();
        if let Some(held) = self.capture.held {
            if held.transaction == transaction && held.policy_generation == policy_generation {
                return Ok(());
            }
            return Err(RamError::Invariant(
                "checkpoint placement hold already retained",
            ));
        }
        if transaction == 0 || transaction <= self.capture.issued_transaction {
            return Err(RamError::Invariant(
                "checkpoint placement transaction is stale",
            ));
        }

        self.capture.issued_transaction = transaction;
        self.capture.held = Some(HeldPlacement {
            transaction,
            policy_generation,
            detached: false,
        });
        Ok(())
    }

    fn held_checkpoint(&self, transaction: u64) -> Result<HeldPlacement, RamError> {
        self.capture
            .held
            .filter(|held| {
                held.transaction == transaction
                    && held.policy_generation == self.checkpoint_receipt_generation()
            })
            .ok_or(RamError::Invariant("checkpoint placement identity changed"))
    }

    fn record_detached(&mut self, mailbox: &DetachedCheckpointMailbox) -> Result<(), RamError> {
        let mut held = self.held_checkpoint(mailbox.transaction)?;
        if self.capture.mailbox_restored {
            return Err(RamError::Invariant("checkpoint mailbox already restored"));
        }
        if self.dispatching {
            return Err(RamError::Invariant(
                "checkpoint placement dispatch still active",
            ));
        }
        held.detached = true;
        self.capture.held = Some(held);
        Ok(())
    }

    fn check_detached(&self, transaction: u64) -> Result<(), RamError> {
        if self.capture.mailbox_restored {
            return Err(RamError::Invariant("checkpoint mailbox already restored"));
        }
        if self.capture.disposition_uncertain {
            return Err(RamError::Invariant(
                "checkpoint placement disposition uncertain",
            ));
        }
        if !self.held_checkpoint(transaction)?.detached {
            return Err(RamError::Invariant(
                "checkpoint placement mailbox not detached",
            ));
        }
        Ok(())
    }

    fn release_checkpoint_work(
        &mut self,
        admission: &CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        self.held_checkpoint(transaction)?;
        if !self.capture.mailbox_restored {
            return Err(RamError::Invariant("checkpoint mailbox restoration absent"));
        }
        let loan = self
            .capture
            .held_work
            .as_mut()
            .ok_or(RamError::Invariant("checkpoint work loan absent"))?;
        loan.release_after_restore(admission)?;
        self.capture.held_work.take();
        self.capture.held = None;
        self.capture.completed_receipt.take();
        self.capture.mailbox_restored = false;
        Ok(())
    }

    fn release_checkpoint(
        &mut self,
        transaction: u64,
        restore_mailbox: impl FnOnce() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        self.held_checkpoint(transaction)?;
        if self.capture.disposition_uncertain {
            return Err(RamError::Invariant(
                "checkpoint placement disposition uncertain",
            ));
        }
        if self.capture.mailbox_restored {
            // Final policy/work disposition may have refused after restoration.
            // Never restore or signal the accepted native tuple a second time.
            return Ok(());
        }
        self.check_detached(transaction)?;
        if self.receipt.is_some() {
            // No operation completion or policy acknowledgement occurs here.
            // A failed or ambiguous re-enqueue retains this same gate and work.
            if let Err(error) = restore_mailbox() {
                self.capture.disposition_uncertain = true;
                return Err(error);
            }
        }
        self.capture.mailbox_restored = true;
        if self.capture.held_work.is_none() {
            self.capture.held = None;
            self.capture.completed_receipt.take();
            self.capture.mailbox_restored = false;
        }
        Ok(())
    }
}

impl PausedPagingOwner {
    /// Closes the actual queue and retains its unfinished receipt under policy custody.
    ///
    /// # Errors
    /// Refuses busy custody, a changed transaction or a foreign operation loan.
    /// Native detachment remains a separate authenticated invocation effect.
    pub(crate) fn request_checkpoint_work(
        &self,
        admission: &mut CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        queue.request_checkpoint(transaction)?;
        queue.retain_checkpoint_work(admission, transaction)
    }

    /// Detaches under the same policy and queue locks that closed admission.
    ///
    /// # Errors
    /// Refuses active dispatch, changed custody or the genuine native tuple cut.
    /// A retained native result survives any later dispatch/census refusal.
    pub(crate) fn detach_checkpoint_native(
        &self,
        admission: &mut CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        queue.held_checkpoint(transaction)?;
        if queue.dispatching {
            return Err(RamError::Invariant(
                "checkpoint placement dispatch still active",
            ));
        }
        if queue.capture.native_mailbox.is_none() {
            let queued = queue.receipt.is_some();
            let callback =
                queued.then_some(queued_placement as extern "C" fn(*mut c_void) -> c_int);
            let opaque = if queued {
                (self as *const Self).cast_mut().cast()
            } else {
                std::ptr::null_mut()
            };
            let mailbox = admission.with_native_root(|root| root.detach(callback, opaque))?;
            queue.capture.native_mailbox = Some(mailbox);
        }
        let mailbox = queue
            .capture
            .native_mailbox
            .as_ref()
            .ok_or(RamError::Invariant("checkpoint native mailbox absent"))?;
        let evidence = DetachedCheckpointMailbox {
            transaction: mailbox.transaction(),
        };
        queue.record_detached(&evidence)?;
        queue.check_checkpoint_work(admission, transaction)
    }

    /// Restores the genuine accepted tuple before callback return or policy open.
    ///
    /// # Errors
    /// Refuses changed/uncertain custody or the actual native restoration. Every
    /// attempt is journaled before the call; negative results cannot authorize a
    /// second physical restoration. Even EMPTY consumes its native journal.
    pub(crate) fn restore_checkpoint_native(
        &self,
        admission: &mut CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        queue.held_checkpoint(transaction)?;
        if queue.capture.mailbox_restored {
            return Ok(());
        }
        queue.check_detached(transaction)?;
        if queue.capture.native_restore_attempted {
            return Err(RamError::Invariant(
                "checkpoint native restore disposition retained",
            ));
        }
        queue.capture.native_restore_attempted = true;
        let mailbox = queue
            .capture
            .native_mailbox
            .as_ref()
            .ok_or(RamError::Invariant("checkpoint native mailbox absent"))?;
        if let Err(cause) = admission.with_native_root(|root| root.restore(mailbox)) {
            queue.capture.disposition_uncertain = true;
            return Err(cause);
        }
        // Restoration does not dispose the same-registry unfinished work loan,
        // fault pause, page vector or native producer exclusion.
        queue.capture.mailbox_restored = true;
        Ok(())
    }

    /// Returns only the held receipt loan, keeping queue admission closed.
    ///
    /// # Errors
    /// Refuses unrestored/uncertain custody or unrelated work. Empty queues have
    /// no caller-supplied subtraction; their actual registry must be settled.
    pub(crate) fn dispose_checkpoint_native_work(
        &self,
        admission: &CheckpointWorkAdmission<'_>,
        disposition: &crate::runtime::LocalDisposition<'_>,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        let transaction = disposition.transaction();
        queue.held_checkpoint(transaction)?;
        if queue.capture.local_work_released {
            return Ok(());
        }
        if !queue.capture.mailbox_restored {
            if !queue.capture.native_restore_attempted
                || queue
                    .capture
                    .native_mailbox
                    .as_ref()
                    .is_none_or(|mailbox| mailbox.transaction() != transaction)
            {
                return Err(RamError::Invariant(
                    "checkpoint native restore disposition retained",
                ));
            }
            // The SAME root's live LOCAL journal proves physical restoration,
            // callback return and independent post. A prior negative status may
            // have followed restoration; this observation reconciles custody
            // without repeating the effect or replacing its initiating cause.
            queue.capture.mailbox_restored = true;
            queue.capture.disposition_uncertain = false;
        }
        if queue.capture.disposition_uncertain {
            return Err(RamError::Invariant(
                "checkpoint placement disposition uncertain",
            ));
        }
        if let Some(loan) = queue.capture.held_work.as_mut() {
            loan.release_after_restore(admission)?;
        } else {
            admission.check_settled()?;
        }
        queue.capture.held_work.take();
        queue.capture.local_work_released = true;
        Ok(())
    }

    /// Reopens the queue only after real native retirement and final root return.
    ///
    /// # Errors
    /// Refuses incomplete local disposition without discarding any retained body.
    pub(crate) fn finish_checkpoint_native(
        &self,
        transaction: u64,
        finish: impl FnOnce() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        queue.held_checkpoint(transaction)?;
        if queue.capture.disposition_uncertain
            || !queue.capture.local_work_released
            || !queue.capture.mailbox_restored
        {
            return Err(RamError::Invariant(
                "checkpoint local work disposition incomplete",
            ));
        }
        // Obtain every fallible queue lock before final root acknowledgment.
        // The closure retains State and this queue through native observer end.
        finish()?;
        queue.capture.native_mailbox.take();
        queue.capture.completed_receipt.take();
        queue.capture.held = None;
        queue.capture.mailbox_restored = false;
        queue.capture.native_restore_attempted = false;
        queue.capture.local_work_released = false;
        Ok(())
    }

    // Exercises the actual receipt admission without resolving a native mailbox.
    // Neither this fixture entry nor its queued operation can issue capture Ready.
    #[cfg(test)]
    pub(in crate::paged_ram) fn admit_checkpoint_work_for_test(
        &self,
        generation: u64,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        queue.capture.require_open()?;
        prepare_placement_receipt(&mut queue, self.operations.as_ref(), generation)?;
        queue.request_checkpoint(transaction)
    }

    #[cfg(test)]
    pub(in crate::paged_ram) fn detach_checkpoint_work_for_test(
        &self,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        queue.record_detached(&DetachedCheckpointMailbox { transaction })
    }

    #[cfg(test)]
    pub(in crate::paged_ram) fn abandon_checkpoint_work_for_test(&self) {
        let mut queue = self.queued_operation.lock().unwrap();
        drop(queue.capture.held_work.take());
    }

    #[cfg(test)]
    pub(in crate::paged_ram) fn restore_checkpoint_work_for_test(
        &self,
        transaction: u64,
        restore: impl FnOnce() -> Result<(), RamError>,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .lock()
            .map_err(|_| RamError::Invariant("placement queue unavailable"))?;
        if !queue.capture.mailbox_restored {
            queue.record_detached(&DetachedCheckpointMailbox { transaction })?;
        }
        queue.release_checkpoint(transaction, restore)
    }

    /// Classifies actual retained placement work under the matching policy guard.
    ///
    /// # Errors
    /// Refuses busy custody, active dispatch, another held identity, unrelated
    /// unfinished work or uncertainty. This issues no native mailbox evidence.
    pub(crate) fn check_checkpoint_work(
        &self,
        admission: &mut CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        if !queue.capture.is_held() {
            return admission.check_settled();
        }
        if queue.dispatching {
            return Err(RamError::Invariant(
                "checkpoint placement dispatch still active",
            ));
        }
        queue.check_detached(transaction)?;
        queue.retain_checkpoint_work(admission, transaction)?;
        queue.check_checkpoint_work(admission, transaction)
    }

    /// Disposes the work loan only after the same native mailbox was restored.
    ///
    /// # Errors
    /// Refuses busy custody, absent restoration or unrelated/uncertain work.
    /// Refusal retains the work loan and queue admission gate.
    pub(crate) fn release_checkpoint_work(
        &self,
        admission: &CheckpointWorkAdmission<'_>,
        transaction: u64,
    ) -> Result<(), RamError> {
        let mut queue = self
            .queued_operation
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint placement ownership busy"))?;
        if !queue.capture.is_held() {
            return admission.check_settled();
        }
        queue.release_checkpoint_work(admission, transaction)
    }
}

// Dropping a held transaction never reopens admission or releases its retained
// receipt. Only final native acknowledgment under State can dispose these gates.

#[cfg(test)]
mod tests;
