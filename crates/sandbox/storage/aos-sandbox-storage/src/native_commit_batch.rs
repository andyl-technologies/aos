//! Finite nonauthorizing result slots for actual prepaid startup appends.
//!
//! State retirement and workspace materialization share this simple reservoir.
//! It contains no payer, role, key or append exception. Each domain prepays its
//! real typed forecast before allocating slots and keeps its semantic checks.

use aos_sandbox_controller_domain::journal::StorageStateNativeCommitAttemptV1;
use aos_sandbox_controller_domain::{Journal, JournalTransaction};
#[cfg(test)]
use aos_sandbox_controller_domain::{CommitResult, JournalError};

#[derive(Debug, thiserror::Error)]
#[error("Storage startup append result slots are closed")]
struct BatchClosed;

pub(crate) struct StorageNativeCommitBatchV1 {
    slots: Vec<StorageStateNativeCommitAttemptV1>,
    allocation: Option<Result<(), std::collections::TryReserveError>>,
    next: usize,
    failed: bool,
    closed: bool,
}

impl StorageNativeCommitBatchV1 {
    pub(crate) const fn new() -> Self {
        Self { slots: Vec::new(), allocation: None, next: 0, failed: false, closed: false }
    }

    pub(crate) fn prepare_once_v1(&mut self, slots: usize) -> Result<(), ()> {
        if self.allocation.is_some() || self.closed {
            self.closed = true;
            return Err(());
        }
        self.allocation = Some(self.slots.try_reserve_exact(slots));
        if !matches!(self.allocation, Some(Ok(()))) {
            self.failed = true;
            return Err(());
        }
        self.slots.extend((0..slots).map(|_| StorageStateNativeCommitAttemptV1::new()));
        Ok(())
    }

    /// Extends the same paid reservoir without replacing attempted originals.
    pub(crate) fn ensure_available_v1(&mut self, slots: usize) -> Result<(), ()> {
        if self.failed || self.closed || !matches!(self.allocation, Some(Ok(()))) {
            self.closed = true;
            return Err(());
        }
        let available = self.slots.len().saturating_sub(self.next);
        let additional = slots.saturating_sub(available);
        if additional == 0 {
            return Ok(());
        }
        self.allocation = Some(self.slots.try_reserve_exact(additional));
        if !matches!(self.allocation, Some(Ok(()))) {
            self.failed = true;
            return Err(());
        }
        self.slots.extend((0..additional).map(|_| StorageStateNativeCommitAttemptV1::new()));
        Ok(())
    }

    pub(crate) fn slot_capacity_bytes_v1(&self, slots: usize) -> Option<usize> {
        let available = self.slots.len().checked_sub(self.next)?;
        self.slots.len().checked_add(slots.saturating_sub(available))?
            .checked_mul(std::mem::size_of::<StorageStateNativeCommitAttemptV1>())
    }

    pub(crate) fn commit_once_v1(
        &mut self,
        journal: &mut Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), ()> {
        if self.failed || self.closed || self.next == self.slots.len() {
            self.closed = true;
            return Err(());
        }
        let slot = &mut self.slots[self.next];
        self.next += 1;
        if slot.commit_once_v1(journal, transaction).is_err() {
            self.failed = true;
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.allocation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.slots.iter().find_map(StorageStateNativeCommitAttemptV1::failure))
            .or_else(|| self.closed.then_some(&BatchClosed as &dyn std::error::Error))
    }

    #[cfg(test)]
    pub(crate) fn native_result_v1(&self, index: usize) -> Option<&Result<CommitResult, JournalError>> {
        self.slots.get(index)?.native_result_v1()
    }

    #[cfg(test)]
    pub(crate) const fn attempted_count_v1(&self) -> usize {
        self.next
    }
}
