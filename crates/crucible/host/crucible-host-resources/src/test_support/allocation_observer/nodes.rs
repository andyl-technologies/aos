//! Tracks the original Memory namespace's64 reusable live-node identities.
//!
//! The existing process-wide roster registry owns synchronization. This module
//! only updates the original caller's fixed atomics; it cannot inspect storage,
//! allocate authority, invoke callbacks or replace an original counter.

use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::AllocationRosterOutcome;

/// Borrows the original counters for one finite Memory node lifetime witness.
///
/// All references identify caller-owned static counters. They carry neither
/// allocation ownership nor resource admission. The caller resets these objects
/// before capture and keeps real node owners until their physical closes.
pub struct MemoryNodeCounters {
    /// The original64 reusable live identities, cleared by each physical close.
    pub addresses: &'static [AtomicUsize; 64],
    /// The original successful544/640-byte request counter.
    pub allocations: &'static AtomicUsize,
    /// The original matched physical-close counter.
    pub deallocations: &'static AtomicUsize,
    /// The original live-slot or scalar-count overflow flag.
    pub overflow: &'static AtomicBool,
    /// The original flag that remains true only if all closes precede N refund.
    pub funded: &'static AtomicBool,
    /// The original N-loan Drop flag sampled immediately before physical free.
    pub namespace_closed: &'static AtomicBool,
}

/// Retains complete observation status separately from original funding samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryNodeReport {
    /// Complete excludes lock refusal, overflow and unclosed original live slots.
    pub outcome: AllocationRosterOutcome,
    /// The original successful selected-request count, including live overflow.
    pub allocations: usize,
    /// The original matched physical-close count.
    pub deallocations: usize,
    /// The number of original live slots left at action completion.
    pub live: usize,
    /// The original overflow flag; true invalidates the witness.
    pub overflow: bool,
    /// The original funded-at-every-close result; false is a negative witness.
    pub funded: bool,
}

impl MemoryNodeCounters {
    pub(super) fn is_empty(&self) -> bool {
        self.addresses
            .iter()
            .all(|entry| entry.load(Ordering::SeqCst) == 0)
            && self.allocations.load(Ordering::SeqCst) == 0
            && self.deallocations.load(Ordering::SeqCst) == 0
            && !self.overflow.load(Ordering::SeqCst)
    }

    pub(super) fn is_live(&self, address: usize) -> bool {
        address != 0
            && self
                .addresses
                .iter()
                .any(|entry| entry.load(Ordering::SeqCst) == address)
    }

    fn increment(&self, counter: &AtomicUsize) {
        if counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .is_err()
        {
            self.overflow.store(true, Ordering::SeqCst);
        }
    }

    pub(super) fn record_allocation(&self, address: usize, layout: Layout, reallocation: bool) {
        if reallocation {
            self.overflow.store(true, Ordering::SeqCst);
            return;
        }
        if !matches!(layout.size(), 544 | 640) || layout.align() != 8 {
            return;
        }
        self.increment(self.allocations);
        if !self.addresses.iter().any(|entry| {
            entry
                .compare_exchange(0, address, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        }) {
            self.overflow.store(true, Ordering::SeqCst);
        }
    }

    pub(super) fn claim_before_free(&self, address: usize) -> bool {
        if !self.addresses.iter().any(|entry| {
            entry
                .compare_exchange(address, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        }) {
            return false;
        }
        self.increment(self.deallocations);
        if self.namespace_closed.load(Ordering::SeqCst) {
            self.funded.store(false, Ordering::SeqCst);
        }
        true
    }

    pub(super) fn report(&self, mut outcome: AllocationRosterOutcome) -> MemoryNodeReport {
        let allocations = self.allocations.load(Ordering::SeqCst);
        let deallocations = self.deallocations.load(Ordering::SeqCst);
        let live = self
            .addresses
            .iter()
            .filter(|entry| entry.load(Ordering::SeqCst) != 0)
            .count();
        let overflow = self.overflow.load(Ordering::SeqCst);
        if outcome == AllocationRosterOutcome::Complete
            && (overflow || live != 0 || allocations != deallocations)
        {
            outcome = AllocationRosterOutcome::Unavailable;
        }
        MemoryNodeReport {
            outcome,
            allocations,
            deallocations,
            live,
            overflow,
            funded: self.funded.load(Ordering::SeqCst),
        }
    }
}
