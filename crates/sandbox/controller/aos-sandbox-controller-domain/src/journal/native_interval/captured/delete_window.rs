//! Bounds only a genuine Delete inventory owner's temporary append interval.
//!
//! This private storage has no DATA constructor exposed outside Journal. The
//! actual C17 owner must prepay its whole finite request/terminal schedule and
//! retain the same Session and Source cut before installing it. Canonical
//! preparation, write, publish and independent posts remain the sole engines.

use std::error::Error;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::journal::JournalError;

pub(in crate::journal) struct DeleteSessionAppendWindowV1 {
    entered_primary: AtomicBool,
    active_primary: AtomicBool,
    budget: Mutex<WindowBudget>,
    refusal: OnceLock<WindowRefusal>,
}

struct WindowBudget {
    encoded_remaining: u64,
    transactions_remaining: u8,
    admitted_preparations: u8,
    positive_completions: u8,
}

#[derive(Debug, thiserror::Error)]
enum WindowRefusal {
    #[error("Delete inventory append has no entered primary interval")]
    NoPrimary,
    #[error("Delete inventory append overlaps another primary interval")]
    Overlap,
    #[error("Delete inventory append budget is concurrently borrowed")]
    Concurrent,
    #[error("Delete inventory append exceeds its prepaid finite schedule")]
    Budget,
    #[error("Delete inventory append lacks its actual admitted positive publication")]
    Publication,
}

impl DeleteSessionAppendWindowV1 {
    // This must be called only by the private genuine pending-fence factory,
    // after same-C17 complete admission. The two actual native transactions
    // are the fresh signed request installation and its authenticated terminal.
    pub(in crate::journal) fn new_prepaid_v1(encoded: u64) -> Self {
        Self {
            entered_primary: AtomicBool::new(false),
            active_primary: AtomicBool::new(false),
            budget: Mutex::new(WindowBudget {
                encoded_remaining: encoded,
                transactions_remaining: 2,
                admitted_preparations: 0,
                positive_completions: 0,
            }),
            refusal: OnceLock::new(),
        }
    }

    pub(in crate::journal) fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(2 * std::mem::size_of::<usize>())
    }

    pub(in crate::journal) fn open_primary_once_v1(&self) -> Result<(), JournalError> {
        if self.refusal.get().is_some() { return Err(JournalError::ProtectedBoundary); }
        if self.entered_primary.swap(true, Ordering::SeqCst) {
            return self.refuse(WindowRefusal::Overlap);
        }
        if self.active_primary.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return self.refuse(WindowRefusal::Overlap);
        }
        Ok(())
    }

    // The enclosing native after is separately prepaid and remains owed even
    // when primary entry failed. Closing this latch performs no native work.
    pub(in crate::journal) fn close_primary_v1(&self) {
        self.active_primary.store(false, Ordering::SeqCst);
    }

    pub(super) fn admit_encoded_once(&self, encoded: u64) -> Result<(), JournalError> {
        if self.refusal.get().is_some() { return Err(JournalError::ProtectedBoundary); }
        if !self.active_primary.load(Ordering::SeqCst) {
            return self.refuse(WindowRefusal::NoPrimary);
        }
        let mut budget = match self.budget.try_lock() {
            Ok(budget) => budget,
            Err(_) => return self.refuse(WindowRefusal::Concurrent),
        };
        let Some(remaining) = budget.encoded_remaining.checked_sub(encoded) else {
            return self.refuse(WindowRefusal::Budget);
        };
        if encoded == 0 || budget.transactions_remaining == 0 {
            return self.refuse(WindowRefusal::Budget);
        }
        // Consume before the existing owned stage copies or encodes anything.
        // Neither failed preparation nor later local disposal refunds it.
        budget.encoded_remaining = remaining;
        budget.transactions_remaining -= 1;
        budget.admitted_preparations += 1;
        Ok(())
    }

    // Called only by the SAME captured native post's positive disposal,
    // after actual stage publication and its independent after have succeeded.
    pub(super) fn complete_positive_append_v1(&self) -> Result<(), JournalError> {
        if self.refusal.get().is_some() { return Err(JournalError::ProtectedBoundary); }
        if !self.active_primary.load(Ordering::SeqCst) {
            return self.refuse(WindowRefusal::NoPrimary);
        }
        let mut budget = match self.budget.try_lock() {
            Ok(budget) => budget,
            Err(_) => return self.refuse(WindowRefusal::Concurrent),
        };
        if budget.positive_completions >= budget.admitted_preparations
            || budget.positive_completions >= 2 {
            return self.refuse(WindowRefusal::Publication);
        }
        budget.positive_completions += 1;
        Ok(())
    }

    pub(in crate::journal) fn is_exhausted_inactive_v1(&self) -> bool {
        if self.refusal.get().is_some() || self.active_primary.load(Ordering::SeqCst) { return false; }
        self.budget.try_lock().is_ok_and(|budget|
            budget.transactions_remaining == 0 && budget.admitted_preparations == 2
                && budget.positive_completions == 2)
    }

    pub(in crate::journal) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.refusal.get().map(|cause| cause as _)
    }

    fn refuse(&self, cause: WindowRefusal) -> Result<(), JournalError> {
        // The real original refusal remains resident and cannot be replaced by
        // a later callback, post or restored input. No native result is cloned.
        let _ = self.refusal.set(cause);
        Err(JournalError::ProtectedBoundary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_publication_cannot_retire_or_reenter_a_closed_interval() {
        // This is only the finite mechanical control, not a financial original.
        let window = DeleteSessionAppendWindowV1::new_prepaid_v1(100);
        window.open_primary_once_v1().unwrap();
        window.admit_encoded_once(40).unwrap();
        window.complete_positive_append_v1().unwrap();
        window.admit_encoded_once(40).unwrap();
        window.close_primary_v1();

        assert!(!window.is_exhausted_inactive_v1());
        assert!(window.open_primary_once_v1().is_err());
        assert!(window.complete_positive_append_v1().is_err());
        assert!(!window.is_exhausted_inactive_v1());
    }

    #[test]
    fn both_admitted_positive_publications_finish_before_the_single_close() {
        let window = DeleteSessionAppendWindowV1::new_prepaid_v1(100);
        window.open_primary_once_v1().unwrap();
        window.admit_encoded_once(40).unwrap();
        window.complete_positive_append_v1().unwrap();
        window.admit_encoded_once(40).unwrap();
        window.complete_positive_append_v1().unwrap();

        assert!(!window.is_exhausted_inactive_v1());
        window.close_primary_v1();
        assert!(window.is_exhausted_inactive_v1());
    }

    #[test]
    fn unadmitted_publication_keeps_its_original_refusal_and_blocks_retirement() {
        let window = DeleteSessionAppendWindowV1::new_prepaid_v1(100);
        window.open_primary_once_v1().unwrap();
        window.complete_positive_append_v1().unwrap_err();
        let first = std::ptr::from_ref(window.failure().unwrap());

        assert!(window.admit_encoded_once(40).is_err());
        assert_eq!(std::ptr::from_ref(window.failure().unwrap()), first);
        window.close_primary_v1();
        assert!(!window.is_exhausted_inactive_v1());
    }
}
