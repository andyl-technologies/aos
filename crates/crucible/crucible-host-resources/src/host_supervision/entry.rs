//! Enters actual operations within the supervisor's paid record inventory.
//!
//! Ordinary and reserved Cleanup entry share policy, containing invocation,
//! identity and capacity checks. A reservation starts no interval; the actual
//! insertion captures its first start and consumes its one occupied record.

use super::*;

impl HostOperationSupervisor {
    /// Begins one bounded operation under the current live class policy.
    ///
    /// # Errors
    ///
    /// Returns an error for terminal execution, an unbounded infrastructure
    /// phase, exhausted operation capacity, or uncertain synchronization.
    pub fn begin(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        self.begin_work(class, 1)
    }

    /// Begins one operation with an explicit required-work inventory.
    ///
    /// # Errors
    ///
    /// Returns the same ownership, finite-bound, and capacity errors as
    /// [`Self::begin`], and refuses an empty work inventory.
    pub fn begin_work(
        &self,
        class: HostOperationClass,
        required_work_units: u64,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        self.begin_admitted(
            class,
            required_work_units,
            class == HostOperationClass::Cleanup,
        )
    }

    /// Begins an independent control exchange using reserved operation records.
    ///
    /// Setup retains its live class budget and original outer cap. Cleanup
    /// retains its finite class budget, including after outer-cap expiry.
    /// Work saturation cannot consume the two reserved control records.
    ///
    /// # Errors
    ///
    /// Refuses classes other than setup and cleanup, a terminal setup owner,
    /// exhausted control records, invalid bounds, or uncertain synchronization.
    pub fn begin_control(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        if !matches!(
            class,
            HostOperationClass::Setup | HostOperationClass::Cleanup
        ) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        self.begin_admitted(class, 1, true)
    }

    fn begin_admitted(
        &self,
        class: HostOperationClass,
        required_work_units: u64,
        control: bool,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        self.begin_admitted_with_reservation(class, required_work_units, control, None)
    }

    pub(super) fn begin_admitted_with_reservation(
        &self,
        class: HostOperationClass,
        required_work_units: u64,
        control: bool,
        reserved_id: Option<u64>,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        if required_work_units == 0 {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let mut state = self.lock()?;
        let elapsed = self.elapsed();
        refresh_cap(&mut state, elapsed);
        #[cfg(feature = "private-measurement-domain")]
        if self
            .shared
            .measurement_clock
            .is_some_and(|clock| elapsed >= clock.span())
        {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        if class != HostOperationClass::Cleanup && state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        state
            .budgets
            .get(class)
            .validate(class, state.cap_allowance.is_some())?;
        let work_operations = state
            .operations
            .values()
            .filter(|operation| !operation.control)
            .count();
        let occupied = state
            .operations
            .len()
            .checked_add(state.reserved_controls)
            .ok_or(HostSupervisionError::CapacityExhausted)?;
        if occupied > MAX_HOST_OPERATIONS
            || (reserved_id.is_none() && occupied == MAX_HOST_OPERATIONS)
            || (!control && work_operations >= MAX_HOST_WORK_OPERATIONS)
        {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        let id = if let Some(id) = reserved_id {
            if class != HostOperationClass::Cleanup
                || !control
                || state.reserved_controls == 0
                || state.operations.contains_key(&id)
            {
                return Err(HostSupervisionError::Unavailable);
            }
            state.reserved_controls -= 1;
            id
        } else {
            let id = state
                .next_operation
                .checked_add(1)
                .ok_or(HostSupervisionError::IdentityExhausted)?;
            state.next_operation = id;
            id
        };
        let revision = state.policy_revision;
        state.operations.insert(
            id,
            Operation {
                class,
                control,
                deferred_cleanup_reserved: false,
                started: elapsed,
                last_progress: elapsed,
                started_revision: revision,
                completed: 0,
                required: required_work_units,
                state: HostOperationState::Running,
                startup_cancellation: None,
                guard_live: true,
                action_subscribers: None,
            },
        );
        Ok(HostOperationGuard {
            supervisor: self.clone(),
            id,
            #[cfg(feature = "private-measurement-domain")]
            original_preparation: None,
        })
    }
}
