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

// A swallowed reentrant error must never reopen a failed window at an outer
// success tail. The exact in-progress stage is checked after the final callback.
pub(super) fn authenticate_started_stage_data(
    stage: &Cell<WindowStage>,
    expected: WindowStage,
) -> Result<(), RuntimeError> {
    if stage.get() != expected {
        return Err(RuntimeError::OutstandingObligations);
    }
    Ok(())
}

// Each concrete caller names its actual payload type. Both the defining borrow
// Result and the mapped RuntimeError Result remain explicit logical views.
pub(in crate::node_admission::conformance::restoration_construction) fn owner_loan_result_counter_scratch_data<
    T: 'static,
>() -> usize {
    size_of::<Result<std::cell::Ref<'static, T>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::Ref<'static, T>, RuntimeError>>()
        + size_of::<Result<std::cell::RefMut<'static, T>, std::cell::BorrowMutError>>()
        + size_of::<Result<std::cell::RefMut<'static, T>, RuntimeError>>()
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

    #[test]
    fn swallowed_reentrant_failure_cannot_complete_an_outer_started_stage() {
        for started in [
            WindowStage::ColdStarted,
            WindowStage::TransactionStarted,
            WindowStage::TransactionChecking,
            WindowStage::TransactionAdmitted,
        ] {
            let stage = Cell::new(started);
            assert!(authenticate_started_stage_data(&stage, started).is_ok());

            // An inner invalid public transition marks this actual shared gate
            // failed even if the callback swallows its returned error.
            stage.set(WindowStage::Failed);
            assert!(matches!(
                authenticate_started_stage_data(&stage, started),
                Err(RuntimeError::OutstandingObligations)
            ));
            assert!(matches!(stage.get(), WindowStage::Failed));
        }
    }
}
