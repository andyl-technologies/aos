//! Reserves genuine Cleanup control custody before Quantum effects begin.
//!
//! Reservation occupies one record in the same retained supervisor without
//! entering Cleanup or starting its interval. Once-only entry later consults
//! Cleanup and its enclosing authenticated invocation, independently of Work.
//! This local capability supplies no native recipient or wire-format authority.

use super::*;

/// Retains a once-only Cleanup record reserved by an actual Quantum operation.
///
/// The containing owner must fund this inline holder before reservation and
/// retain it through every borrower and uncertain return. The supervisor's
/// existing structural admission covers its bounded operation-record inventory.
/// Reservation creates no native memory, thread or semantic operation grant.
/// A separately negotiated recipient contract is required before native use.
#[derive(Debug)]
#[must_use = "retain reserved Cleanup custody through entry and actual borrower return"]
pub struct HostDeferredCleanupControl {
    supervisor: HostOperationSupervisor,
    id: u64,
    reservation_held: bool,
    ready: bool,
    entry_attempted: bool,
    entry_post_attempted: bool,
    entry_post_returned: bool,
    entry_post_succeeded: bool,
    entered: Option<HostOperationGuard>,
    first_refusal: Option<HostSupervisionError>,
}

impl HostOperationGuard {
    /// Reserves independent Cleanup custody before this Quantum's first effect.
    ///
    /// The supplied prepaid slot receives the actual holder before the
    /// independent Quantum postcheck. A failed post therefore leaves visible
    /// born custody, permanently ineligible for entry. Each Quantum permits
    /// one reservation attempt that actually occupies a record; dropping that
    /// holder does not authorize a replacement reservation for the same Work.
    ///
    /// # Errors
    /// Refuses an occupied output, a noncurrent or non-Quantum operation,
    /// an earlier reservation, invalid Cleanup policy, exhausted identity or
    /// record capacity, uncertain synchronization, or the independent post.
    pub fn reserve_deferred_cleanup_control(
        &self,
        output: &mut Option<HostDeferredCleanupControl>,
    ) -> Result<(), HostSupervisionError> {
        self.reserve_deferred_cleanup_control_with(output, || {})
    }

    fn reserve_deferred_cleanup_control_with(
        &self,
        output: &mut Option<HostDeferredCleanupControl>,
        after_reservation: impl FnOnce(),
    ) -> Result<(), HostSupervisionError> {
        if output.is_some() {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        #[cfg(feature = "private-measurement-domain")]
        self.check_original_preparation()?;

        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        if decision.class != HostOperationClass::Quantum {
            return Err(HostSupervisionError::InvalidBudget);
        }
        if state
            .operations
            .get(&self.id)
            .is_none_or(|operation| operation.deferred_cleanup_reserved)
        {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        state
            .budgets
            .get(HostOperationClass::Cleanup)
            .validate(HostOperationClass::Cleanup, state.cap_allowance.is_some())?;
        state
            .operations
            .len()
            .checked_add(state.reserved_controls)
            .filter(|occupied| *occupied < MAX_HOST_OPERATIONS)
            .ok_or(HostSupervisionError::CapacityExhausted)?;
        let id = state
            .next_operation
            .checked_add(1)
            .ok_or(HostSupervisionError::IdentityExhausted)?;
        let operation = state
            .operations
            .get_mut(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;

        operation.deferred_cleanup_reserved = true;
        state.next_operation = id;
        state.reserved_controls += 1;
        *output = Some(HostDeferredCleanupControl {
            supervisor: self.supervisor.clone(),
            id,
            reservation_held: true,
            ready: false,
            entry_attempted: false,
            entry_post_attempted: false,
            entry_post_returned: false,
            entry_post_succeeded: false,
            entered: None,
            first_refusal: None,
        });
        drop(state);

        after_reservation();
        let post = self.wait_slice();
        if let Some(holder) = output.as_mut() {
            holder.ready = post.is_ok();
            holder.first_refusal = post.err();
        }
        post.map(|_| ())
    }
}

impl HostDeferredCleanupControl {
    /// Reports this holder's inline extent for its actual containing admission.
    pub const fn retained_control_bytes() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Enters this reservation's first and only finite Cleanup interval.
    ///
    /// This checks no Work operation, including after Work or its outer cap
    /// ends. Cleanup still obeys its own live finite class policy and the
    /// authenticated containing invocation. The born guard is retained here
    /// before its independent first post; refusal never restarts entry.
    ///
    /// # Errors
    /// Refuses an unready or previously attempted reservation, invalid policy,
    /// an ended containing invocation, uncertain ownership, or the first post.
    /// A born-negative operation remains retained and observable by identity.
    /// Later entry calls report the retained first refusal without reentry.
    pub fn enter(&mut self) -> Result<&HostOperationGuard, HostSupervisionError> {
        self.enter_with(|| {})
    }

    fn enter_with(
        &mut self,
        after_birth: impl FnOnce(),
    ) -> Result<&HostOperationGuard, HostSupervisionError> {
        if let Some(first) = self.first_refusal {
            return Err(first);
        }
        if !self.ready || self.entry_attempted || !self.reservation_held {
            return Err(HostSupervisionError::Unavailable);
        }
        self.entry_attempted = true;
        let result = self.supervisor.begin_admitted_with_reservation(
            HostOperationClass::Cleanup,
            1,
            true,
            Some(self.id),
        );
        match result {
            Ok(guard) => {
                self.entered = Some(guard);
                self.reservation_held = false;
            }
            Err(first) => {
                self.first_refusal = Some(first);
                return Err(first);
            }
        }
        after_birth();
        self.entry_post_attempted = true;
        let post = self
            .entered
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?
            .wait_slice();
        self.entry_post_returned = true;
        self.entry_post_succeeded = post.is_ok();
        if let Err(first) = post {
            self.first_refusal = Some(first);
            return Err(first);
        }
        self.entered
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)
    }

    /// Borrows an entered guard only after its successful independent first post.
    ///
    /// # Errors
    /// Refuses absent entry, any retained first refusal, or a noncurrent Cleanup.
    /// This does not repeat entry, restart time or query the original Work.
    pub fn current(&self) -> Result<&HostOperationGuard, HostSupervisionError> {
        if let Some(first) = self.first_refusal {
            return Err(first);
        }
        if !self.entry_post_attempted || !self.entry_post_returned || !self.entry_post_succeeded {
            return Err(HostSupervisionError::Unavailable);
        }
        let guard = self
            .entered
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)?;
        guard.wait_slice()?;
        Ok(guard)
    }

    /// Reports actual born operation identity, including after a negative post.
    ///
    /// This copied observation grants no operation or physical-return permission.
    pub fn entered_operation_id(&self) -> Option<u64> {
        self.entered.as_ref().map(|guard| guard.id)
    }

    /// Reports the first retained reservation or entry refusal without polling.
    pub fn first_refusal(&self) -> Option<HostSupervisionError> {
        self.first_refusal
    }
}

impl Drop for HostDeferredCleanupControl {
    fn drop(&mut self) {
        if self.reservation_held
            && let Ok(mut state) = self.supervisor.lock()
            && let Some(remaining) = state.reserved_controls.checked_sub(1)
        {
            state.reserved_controls = remaining;
        }
        // An entered guard follows ordinary borrower-aware Drop: outstanding
        // actual memberships retain its canceled record until physical return.
    }
}

#[cfg(test)]
mod tests;
