//! Classifies actual admitted work separately from live operation-body capacity.
//!
//! Entry is ordered by the controller State gate. Successful real completion
//! removes unfinished work; dropping an admitted unfinished operation records
//! permanent uncertainty before releasing its census. That taint has no reset
//! or status-based refund. Native capture still needs independent worker, mailbox,
//! original and whole source/page fences. This census cannot issue those proofs.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::ram_error::RamError;

mod held;
pub(crate) use held::{CheckpointWorkAdmission, HeldCheckpointWork};

/// Retains both capacity and actual-work disposition in the same shared control.
#[derive(Default)]
pub(in crate::paged_ram::controller) struct OperationRegistry {
    /// Counts retained body slots, independently of whether their work completed.
    pub(in crate::paged_ram::controller) capacity: AtomicUsize,
    // This census is internal work evidence, never a caller-supplied allowance.
    pub(in crate::paged_ram::controller) unfinished: AtomicUsize,
    uncertain: AtomicBool,
    held: Mutex<Option<held::HeldWorkRecord>>,
}

impl OperationRegistry {
    /// Records one real entry while controller State still orders admission.
    pub(in crate::paged_ram::controller) fn start(&self) {
        self.unfinished.fetch_add(1, Ordering::AcqRel);
    }

    /// Records successful completion or a conservatively abandoned work body.
    pub(in crate::paged_ram::controller) fn finish(&self, uncertain: bool) {
        if uncertain {
            self.uncertain.store(true, Ordering::Release);
        }
        // A checker first observes this release, then the uncertainty bit. It
        // cannot mistake a concurrently abandoned final body for settled work.
        self.unfinished.fetch_sub(1, Ordering::AcqRel);
    }

    /// Checks actual completed or proven pre-effect-refused work disposition.
    ///
    /// # Errors
    /// Refuses live work or retained uncertainty even when body capacity is zero.
    pub(in crate::paged_ram::controller) fn check_settled(&self) -> Result<(), RamError> {
        if self
            .held
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint work custody busy"))?
            .is_some()
        {
            return Err(RamError::Invariant("checkpoint work loan remains retained"));
        }
        if self.unfinished.load(Ordering::Acquire) != 0 {
            return Err(RamError::Invariant("checkpoint prior work remains live"));
        }
        if self.uncertain.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "checkpoint prior work disposition uncertain",
            ));
        }
        Ok(())
    }
}

/// Retains the performance call that runs after releasing controller State.
///
/// The fixed receipt is stack-owned, aliases the same registry and cannot reopen
/// a capture. Unwind, an error or forgotten disposition permanently prevents the
/// census from certifying settlement; no destructor claims successful work.
pub(in crate::paged_ram::controller) struct PerformanceDispatch {
    registry: Arc<OperationRegistry>,
    settled: bool,
}

impl PerformanceDispatch {
    /// Enters the same fixed-capacity registry before leaving controller State.
    ///
    /// # Errors
    /// Refuses exhausted operation body capacity without admitting performance.
    pub(in crate::paged_ram::controller) fn begin(
        registry: Arc<OperationRegistry>,
    ) -> Result<Self, RamError> {
        registry
            .capacity
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < super::super::MAX_OPERATIONS).then_some(count + 1)
            })
            .map_err(|_| RamError::Invariant("RAM operation slots exhausted"))?;
        registry.start();
        Ok(Self {
            registry,
            settled: false,
        })
    }

    /// Records the actual dispatch's successful return before its body is freed.
    pub(in crate::paged_ram::controller) fn settle(&mut self) {
        if !self.settled {
            self.registry.finish(false);
            self.settled = true;
        }
    }
}

impl Drop for PerformanceDispatch {
    fn drop(&mut self) {
        if !self.settled {
            self.registry.finish(true);
        }
        self.registry.capacity.fetch_sub(1, Ordering::AcqRel);
    }
}
