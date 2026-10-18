//! Pins an occupied role while an outside report owns its actual heap leaves.
//!
//! The closed bit and reference count share one atomic word. Closing an empty
//! count races registration at that same word, so a role cannot become Free
//! while a concurrent report registers. Epoch checking follows acquisition;
//! the acquired count itself prevents epoch reuse until any mismatch is undone.

use super::*;

pub(super) const CLOSED: usize = 1usize << (usize::BITS - 1);
const MAX_REFERENCES: usize = CLOSED - 1;

/// Registers a nonissuing role pin without borrowing a callback-held mutex.
pub(super) fn register(slot: &CleanupSlot, epoch: u64) -> bool {
    if slot
        .report_references
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
            (state < MAX_REFERENCES).then(|| state + 1)
        })
        .is_err()
    {
        return false;
    }
    let actual_epoch = slot.epoch.load(Ordering::Acquire);
    if actual_epoch != epoch || slot.is(CleanupPhase::Free) || slot.is(CleanupPhase::Reserving) {
        // A stale selector may briefly pin an occupied newer header. It gains
        // no operation or projection, and returns only that acquired count.
        release(slot, actual_epoch, false);
        return false;
    }
    true
}

/// Returns only an actually registered pin after its outside leaves are gone.
pub(super) fn release(slot: &CleanupSlot, epoch: u64, terminal_disposed: bool) {
    if slot.epoch.load(Ordering::Acquire) != epoch {
        slot.publish(CleanupPhase::DestructionRefused);
        return;
    }
    if terminal_disposed {
        if !slot.claim(CleanupPhase::TerminalOwned, CleanupPhase::TerminalDisposing) {
            slot.publish(CleanupPhase::DestructionRefused);
            return;
        }
        slot.terminal_disposed.store(true, Ordering::Release);
    }
    let returned =
        slot.report_references
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state > 0 && state < CLOSED).then(|| state - 1)
            });
    match returned {
        Ok(1)
            if slot.terminal_disposed.load(Ordering::Acquire)
                && slot.is(CleanupPhase::TerminalDisposing) =>
        {
            if slot
                .report_references
                .compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.completed_epoch.store(epoch, Ordering::Release);
                slot.publish(CleanupPhase::Free);
            }
        }
        Ok(_) => {}
        Err(_) => slot.publish(CleanupPhase::DestructionRefused),
    }
}
