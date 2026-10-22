//! Retains a once-delegated Cleanup issuer beneath an actual budget owner.
//!
//! Delegation starts no interval and reserves no operation record. Each later
//! reservation still needs the same owner's real current Quantum, and entry
//! retains the independent Cleanup and containing-invocation constraints.
//! Native assignment, physical funding and wire installation are separate.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Retains one actual supervisor's local future-Cleanup reservation right.
///
/// The containing owner prepays this inline holder before delegation and keeps
/// it through all reservation and borrower returns. It shares the actual
/// supervisor allocation and outer authority without creating a budget owner,
/// native resource child, recipient or exported wire capability. Dropping this
/// holder never permits a replacement delegation for the same budget owner.
#[derive(Debug)]
#[must_use = "retain the actual issuer through its reservations and borrower returns"]
pub struct HostDeferredCleanupIssuer {
    supervisor: HostOperationSupervisor,
    ready: bool,
    first_refusal: Option<HostSupervisionError>,
}

impl HostOperationGuard {
    /// Delegates this setup or preparation's once-only local Cleanup issuer.
    ///
    /// The prepaid output receives the real retained owner before the
    /// independent setup post. Negative born output remains visible and
    /// permanently ineligible to issue reservations. No Cleanup clock,
    /// operation record or future work count is created by delegation.
    ///
    /// # Errors
    /// Refuses occupied output, a noncurrent or wrong-class operation, invalid
    /// Cleanup policy, earlier delegation, uncertain locking or the setup post.
    pub fn delegate_deferred_cleanup_issuer(
        &self,
        output: &mut Option<HostDeferredCleanupIssuer>,
    ) -> Result<(), HostSupervisionError> {
        self.delegate_deferred_cleanup_issuer_with(output, || {})
    }

    fn delegate_deferred_cleanup_issuer_with(
        &self,
        output: &mut Option<HostDeferredCleanupIssuer>,
        after_delegation: impl FnOnce(),
    ) -> Result<(), HostSupervisionError> {
        if output.is_some() {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        #[cfg(feature = "private-measurement-domain")]
        self.check_original_preparation()?;

        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        if !matches!(
            decision.class,
            HostOperationClass::Setup | HostOperationClass::Preparation
        ) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        if state.cleanup_issuer_delegated {
            return Err(HostSupervisionError::BorrowedOperation);
        }
        state
            .budgets
            .get(HostOperationClass::Cleanup)
            .validate(HostOperationClass::Cleanup, state.cap_allowance.is_some())?;

        state.cleanup_issuer_delegated = true;
        *output = Some(HostDeferredCleanupIssuer {
            supervisor: self.supervisor.clone(),
            ready: false,
            first_refusal: None,
        });
        drop(state);

        after_delegation();
        let post = self.wait_slice();
        if let Some(issuer) = output.as_mut() {
            issuer.ready = post.is_ok();
            issuer.first_refusal = post.err();
        }
        post.map(|_| ())
    }
}

impl HostDeferredCleanupIssuer {
    /// Reports the inline holder's extent for the containing real admission.
    pub const fn retained_control_bytes() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Reserves Cleanup only for the same actual owner's current Quantum.
    ///
    /// Actual shared-owner identity is checked before the supplied operation
    /// can reserve anything. Equal cap identities, class policy or outer
    /// ancestry cannot substitute for the exact delegated budget owner. This
    /// never queries the setup operation after its return or starts Cleanup.
    ///
    /// # Errors
    /// Refuses an unready or born-negative issuer, another supervisor, occupied
    /// output, or any genuine Quantum reservation or independent post refusal.
    pub fn reserve(
        &self,
        work: &HostOperationGuard,
        output: &mut Option<HostDeferredCleanupControl>,
    ) -> Result<(), HostSupervisionError> {
        if let Some(first) = self.first_refusal {
            return Err(first);
        }
        if !self.ready || self.supervisor != work.supervisor {
            return Err(HostSupervisionError::Unavailable);
        }
        work.reserve_deferred_cleanup_control(output)
    }

    /// Reports the retained setup post refusal without issuing a reservation.
    pub const fn first_refusal(&self) -> Option<HostSupervisionError> {
        self.first_refusal
    }
}

#[cfg(test)]
mod tests;
