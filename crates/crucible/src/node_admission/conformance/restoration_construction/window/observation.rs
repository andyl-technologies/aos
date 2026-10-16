//! Requires a real whole-owner observation between retained group transitions.
//!
//! This private sequencing gate grants no storage or transaction authority. Only
//! the installed window's successful complete policy/storage/member observation
//! clears it; neither verified transport receipts nor a caller's phase label do.

use super::*;

pub(super) struct OriginalRestorationWholeObservation {
    pending: Cell<bool>,
}

impl OriginalRestorationWholeObservation {
    pub(super) fn new_pending() -> Self {
        Self {
            pending: Cell::new(true),
        }
    }

    pub(super) fn require_observation(&self) {
        self.pending.set(true);
    }

    pub(super) fn authenticate_dispatch_data(&self) -> Result<(), RuntimeError> {
        if self.pending.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn complete_observation(&self) {
        self.pending.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_and_each_completed_group_require_a_new_whole_observation() {
        let observation = OriginalRestorationWholeObservation::new_pending();
        assert!(matches!(
            observation.authenticate_dispatch_data(),
            Err(RuntimeError::OutstandingObligations)
        ));

        observation.complete_observation();
        assert!(observation.authenticate_dispatch_data().is_ok());
        for _phase in [
            OriginalRestorationTransactionPhase::Prepare,
            OriginalRestorationTransactionPhase::Inputs,
            OriginalRestorationTransactionPhase::Commit,
        ] {
            observation.require_observation();
            assert!(matches!(
                observation.authenticate_dispatch_data(),
                Err(RuntimeError::OutstandingObligations)
            ));
            // Inspecting the same pending boundary never consumes or clears it.
            assert!(matches!(
                observation.authenticate_dispatch_data(),
                Err(RuntimeError::OutstandingObligations)
            ));
            observation.complete_observation();
            assert!(observation.authenticate_dispatch_data().is_ok());
        }
    }
}
