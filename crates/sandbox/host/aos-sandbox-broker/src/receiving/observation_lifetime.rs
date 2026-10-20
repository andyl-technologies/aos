//! Shares the original observer closure state without admitting an observation.
//!
//! A role creates this DATA only inside its own entered, paid original and
//! retains its native/currentness conjunction. An independently constructed
//! lifetime cannot match that original, fund work or grant a receiving stage.
//! Clones share only closure and allocation identity, never an account.

use std::sync::Arc;

/// Shares monotone closure DATA for one actual role-owned observation interval.
#[derive(Clone)]
pub struct ObservationLifetimeV1(Arc<std::sync::atomic::AtomicBool>);

impl ObservationLifetimeV1 {
    /// Creates an open DATA lifetime without observing or admitting any role.
    #[must_use]
    pub fn begin() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(false)))
    }

    /// Reports whether this shared interval has not been closed.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.0.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Closes this actual interval and every clone permanently.
    pub fn close(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Compares the existing shared allocation as nonauthorizing identity DATA.
    #[must_use]
    pub fn same_original(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_the_original_closes_its_clone_but_cannot_identify_another_interval() {
        let original = ObservationLifetimeV1::begin();
        let shared = original.clone();
        let independent = ObservationLifetimeV1::begin();

        original.close();

        assert!(!original.is_open());
        assert!(!shared.is_open());
        assert!(original.same_original(&shared));
        assert!(!original.same_original(&independent));
        assert!(independent.is_open());
    }
}
