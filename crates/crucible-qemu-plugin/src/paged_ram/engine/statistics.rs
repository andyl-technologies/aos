//! Counts completed host paging operations independently of guest state.

use super::*;

#[derive(Default)]
pub(super) struct PagingCounters {
    pub(super) missing_installs: AtomicU64,
    pub(super) successful_missing_read_installs: AtomicU64,
    pub(super) successful_missing_write_installs: AtomicU64,
    pub(super) write_transitions: AtomicU64,
    pub(super) preserved_writes: AtomicU64,
    pub(super) preserved_reads: AtomicU64,
    pub(super) physical_discards: AtomicU64,
    pub(super) prefetched_pages: AtomicU64,
}

/// Reports completed operational transitions; no field enters guest evidence.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct PagingStatistics {
    /// Successful fault-driven authenticated UFFD copies.
    pub(crate) missing_installs: u64,
    /// Authenticated copies triggered by a missing read fault.
    pub(crate) successful_missing_read_installs: u64,
    /// Authenticated copies triggered by a missing write fault.
    pub(crate) successful_missing_write_installs: u64,
    /// Successful first-write ownership transitions.
    pub(crate) write_transitions: u64,
    /// Successful authenticated writes into reserved disk slots.
    pub(crate) preserved_writes: u64,
    /// Successful authenticated disk slot reads.
    pub(crate) preserved_reads: u64,
    /// Successful physical page removals from stable guest mappings.
    pub(crate) physical_discards: u64,
    /// Successful explicit authenticated prefetch copies.
    pub(crate) prefetched_pages: u64,
}

impl PagingCounters {
    pub(super) fn snapshot(&self) -> PagingStatistics {
        PagingStatistics {
            missing_installs: self.missing_installs.load(Ordering::Acquire),
            successful_missing_read_installs: self
                .successful_missing_read_installs
                .load(Ordering::Acquire),
            successful_missing_write_installs: self
                .successful_missing_write_installs
                .load(Ordering::Acquire),
            write_transitions: self.write_transitions.load(Ordering::Acquire),
            preserved_writes: self.preserved_writes.load(Ordering::Acquire),
            preserved_reads: self.preserved_reads.load(Ordering::Acquire),
            physical_discards: self.physical_discards.load(Ordering::Acquire),
            prefetched_pages: self.prefetched_pages.load(Ordering::Acquire),
        }
    }
}

pub(super) fn count_completed(counter: &AtomicU64) -> Result<(), RamError> {
    count_bulk_completed(counter, 1)
}

pub(super) fn count_bulk_completed(counter: &AtomicU64, amount: u64) -> Result<(), RamError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_add(amount)
        })
        .map_err(|_| RamError::Invariant("operational paging counter exhausted"))?;
    Ok(())
}
