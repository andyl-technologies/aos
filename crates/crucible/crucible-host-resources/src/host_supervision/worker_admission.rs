//! Checks the existing unlent Main Preparation before worker-body admission.
//!
//! Main enters this guard once before constructing its native pool. This narrow
//! observation refuses contention instead of blocking admission, and refuses
//! borrowed phases before touching their published state. It issues no work.

use super::*;

impl HostOperationGuard {
    /// Checks the same initial Preparation without entering or waiting.
    ///
    /// # Errors
    /// Refuses synchronization contention, delegated or physically lent guards,
    /// another class, and the actual retained operation's cancellation/expiry.
    pub(crate) fn try_verify_unlent_preparation(&self) -> Result<(), HostSupervisionError> {
        #[cfg(feature = "private-measurement-domain")]
        if self.original_preparation.is_some() {
            return Err(HostSupervisionError::Unavailable);
        }

        let shared = &self.supervisor.shared;
        if shared.budget_owner != 0 {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let mut state = shared
            .state
            .try_lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let mut outer = shared
            .outer
            .try_lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let operation = state
            .operations
            .get(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;
        if operation.class != HostOperationClass::Preparation {
            return Err(HostSupervisionError::InvalidBudget);
        }
        // Admission cannot call an arbitrary physical publisher while holding
        // these locks. Actual Main worker bodies precede every Source borrower.
        if operation.action_subscribers.is_some() || outer.action_subscribers.is_some() {
            return Err(HostSupervisionError::Unavailable);
        }

        #[cfg(feature = "private-measurement-domain")]
        self.supervisor
            .require_measurement_interval(&mut state, &mut outer)?;
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        let decision = evaluate_operation_decision(&mut state, self.id, self.supervisor.elapsed())?;
        outer.state = state.cap_state;
        if state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        if decision.state == HostOperationState::Completed {
            return Ok(());
        }
        decision.require_running(self.id)
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- these mechanism guards test their real mutexes and same-operation state; no authenticated Main or Source is constructed.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn contended_admission_keeps_the_same_operation_and_original_owner() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        let shared = Arc::clone(&supervisor.shared);
        let id = original.id;

        let held = shared.state.lock().unwrap();
        assert!(matches!(
            original.try_verify_unlent_preparation(),
            Err(HostSupervisionError::Unavailable)
        ));
        assert_eq!(held.operations.len(), 1);
        assert_eq!(held.operations[&id].state, HostOperationState::Running);
        drop(held);

        let held = shared.outer.lock().unwrap();
        assert!(matches!(
            original.try_verify_unlent_preparation(),
            Err(HostSupervisionError::Unavailable)
        ));
        drop(held);

        original.try_verify_unlent_preparation().unwrap();
        assert!(Arc::ptr_eq(&shared, &original.supervisor.shared));
        assert_eq!(original.id, id);
        assert_eq!(shared.state.lock().unwrap().operations.len(), 1);
        original.complete().unwrap();
        original.try_verify_unlent_preparation().unwrap();
        assert_eq!(
            original.status().unwrap().state,
            HostOperationState::Completed
        );
    }

    #[test]
    fn admission_preserves_actual_cancellation_and_rejects_an_unrelated_class() {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
        supervisor.cancel().unwrap();
        let first = original.try_verify_unlent_preparation().unwrap_err();
        let ordinary = original.wait_slice().unwrap_err();
        assert_eq!(first, ordinary);
        assert!(matches!(first, HostSupervisionError::Terminal { .. }));

        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let page_in = supervisor.begin(HostOperationClass::PageIn).unwrap();
        assert!(matches!(
            page_in.try_verify_unlent_preparation(),
            Err(HostSupervisionError::InvalidBudget)
        ));
        page_in.wait_slice().unwrap();
        assert_eq!(supervisor.shared.state.lock().unwrap().operations.len(), 1);

        let child = supervisor
            .new_budget_owner(HostOperationBudgets::default())
            .unwrap();
        let child_preparation = child.begin(HostOperationClass::Preparation).unwrap();
        assert!(matches!(
            child_preparation.try_verify_unlent_preparation(),
            Err(HostSupervisionError::InvalidBudget)
        ));
        child_preparation.wait_slice().unwrap();
    }
}
