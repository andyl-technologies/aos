//! Linearizes pure final ownership transfer against irreversible retirement.
//!
//! The gate supplies no native authority. A commit covers only the reviewed
//! final no-IO moves while the original prepared Box is exclusively borrowed.
//! Once admitted, its owning result is returned unchanged; a later retirement
//! request closes later work instead of retroactively dropping that result.

use super::*;

const OPEN: u8 = 0;
const COMMITTING: u8 = 1;
const RETIRING: u8 = 2;
const COMMITTING_RETIRING: u8 = COMMITTING | RETIRING;

pub(super) struct WorkGate {
    state: AtomicU8,
}

struct Commit<'a> {
    gate: &'a WorkGate,
    requested: &'a AtomicBool,
}

impl WorkGate {
    pub(super) const fn new() -> Self {
        Self {
            state: AtomicU8::new(OPEN),
        }
    }

    pub(super) fn reset_before_publication(&self) {
        self.state.store(OPEN, Ordering::Release);
    }

    pub(super) fn request_retirement(&self, requested: &AtomicBool) {
        // Retirement and commit admission share this atomic word. Setting the
        // bit during an admitted move cannot be overwritten by guard Drop.
        self.state.fetch_or(RETIRING, Ordering::AcqRel);
        requested.store(true, Ordering::Release);
    }

    pub(super) fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPEN
    }

    fn commit<'a>(&'a self, requested: &'a AtomicBool) -> Option<Commit<'a>> {
        if requested.load(Ordering::Acquire)
            || self
                .state
                .compare_exchange(OPEN, COMMITTING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        Some(Commit {
            gate: self,
            requested,
        })
    }
}

impl Drop for Commit<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.gate.request_retirement(self.requested);
        }
        match self.gate.state.compare_exchange(
            COMMITTING,
            OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(COMMITTING_RETIRING) => {
                let _closed = self.gate.state.compare_exchange(
                    COMMITTING_RETIRING,
                    RETIRING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            Err(_) => self.gate.request_retirement(self.requested),
        }
    }
}

impl CleanupSlot {
    pub(super) fn work_is_open(&self) -> bool {
        self.work_gate.is_open() && !self.retirement_requested.load(Ordering::Acquire)
    }

    pub(super) fn request_retirement(&self) {
        self.work_gate
            .request_retirement(&self.retirement_requested);
    }
}

impl prepared_service::ServiceMainHandle {
    /// Admits only a fixed pure final owner transfer under the prepared borrow.
    ///
    /// Every fallible validation must precede this call. The callback moves
    /// existing fields only: no native work, IO, user callback or destructor.
    /// A refused gate never invokes it, preserving the same Main-owned body.
    pub(crate) fn commit_work<R>(
        &self,
        apply: impl FnOnce() -> R,
    ) -> Result<R, ServiceMainPreclaimError> {
        let queue = self.key.containing_queue()?;
        let slot = queue
            .slots
            .get(self.key.index)
            .ok_or(ServiceMainPreclaimError::Role(
                "prepared commit role is absent",
            ))?;
        if slot.epoch.load(Ordering::Acquire) != self.key.epoch || !slot.is(CleanupPhase::Reserved)
        {
            return Err(ServiceMainPreclaimError::Role(
                "prepared commit epoch is stale",
            ));
        }
        let _commit = slot.work_gate.commit(&slot.retirement_requested).ok_or(
            ServiceMainPreclaimError::Role("prepared owner transfer entered retirement"),
        )?;
        Ok(apply())
    }
}

#[cfg(test)]
#[path = "work_gate/tests.rs"]
mod tests;
