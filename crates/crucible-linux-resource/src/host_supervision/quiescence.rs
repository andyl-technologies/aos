//! Exports the real entered Pause operation without reusing startup authority.
//!
//! The closed phase provider retains the original guard, the authenticated
//! process-contract event and its admission through native relinquishment or
//! containment. These bytes describe that operation; they grant no family,
//! worker, Source or execution-phase permission on their own.
//!
//! ```text
//! 0..8    CRUCPAU1
//! 8..12   schema 1
//! 12..16  basis size 80
//! 16..48  retained cap identity
//! 48..56  entered Quiescence operation identity
//! 56..64  original CLOCK_MONOTONIC start
//! 64..72  conservative absolute end
//! 72..80  intersected responsive poll bound
//! ```

use std::os::fd::OwnedFd;
#[cfg(feature = "private-measurement-domain")]
use std::sync::Arc;

use super::{HostOperationClass, HostOperationGuard, HostSupervisionError};
use crate::host_services::HostServiceLease;

/// Retains a Quiescence admission failure and the Preparation's separate postcut.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("original Pause admission refused: {source}; original postcut: {original_after:?}")]
pub struct OriginalQuiescenceStartError {
    /// First actual admission or original identity refusal.
    #[source]
    pub source: HostSupervisionError,
    /// Independent original refusal after the admission attempt.
    pub original_after: Option<HostSupervisionError>,
}

impl HostOperationGuard {
    /// Enters Quiescence from this exact authenticated whole-family Preparation.
    ///
    /// It uses this owner's current Quiescence policy and existing operation
    /// roster, preserving the same outer cap and private kernel end. No caller
    /// can supply another supervisor, class policy, clock or deadline. The real
    /// provider prepays the operation control before admission and retains this
    /// Preparation alongside the returned operation through physical closure.
    ///
    /// # Errors
    /// Refuses an ordinary or derived roster, a different root operation, an
    /// expired original, or actual Quiescence admission. A failed admission
    /// preserves its first cause independently of the original postcut.
    #[cfg(feature = "private-measurement-domain")]
    pub fn begin_original_quiescence(
        self: &Arc<Self>,
    ) -> Result<Self, OriginalQuiescenceStartError> {
        let admit = || {
            if self.supervisor.shared.measurement_clock.is_none()
                || self.supervisor.shared.budget_owner != 0
                || self.id != 1
                || self.status()?.class != HostOperationClass::Preparation
            {
                return Err(HostSupervisionError::InvalidBudget);
            }
            self.wait_slice()?;
            self.supervisor.begin(HostOperationClass::Quiescence)
        };
        let entered = admit();
        let original_after = self.wait_slice().err();
        match entered {
            Ok(mut operation) => match original_after {
                None => {
                    // This is an alias of the already-admitted original, not
                    // a fresh guard or shared allocation. Every later wait
                    // checks its deadline and the same retained event.
                    operation.original_preparation = Some(Arc::clone(self));
                    Ok(operation)
                }
                Some(source) => Err(OriginalQuiescenceStartError {
                    source,
                    original_after: None,
                }),
            },
            Err(source) => Err(OriginalQuiescenceStartError {
                source,
                original_after,
            }),
        }
    }

    #[cfg(feature = "private-measurement-domain")]
    pub(super) fn check_original_preparation(
        &self,
    ) -> Result<Option<std::time::Duration>, HostSupervisionError> {
        let Some(original) = &self.original_preparation else {
            return Ok(None);
        };
        let remaining = original.wait_slice()?;
        // The subscriber is installed before this operation is used. Until
        // then, admission/export refuses rather than treating absence as live.
        self.check_original_cancellation()?;
        Ok(Some(remaining))
    }

    /// Returns the retained extent for one later Pause cancellation subscriber.
    ///
    /// This measures the existing subscriber layout, not an admitted resource.
    /// The actual phase issuer prepays the descriptor and control body from its
    /// original account before duplicating the same process-contract event.
    #[must_use]
    pub const fn original_quiescence_cancellation_bytes() -> u64 {
        Self::original_setup_cancellation_bytes()
    }

    /// Retains the prepaid existing event for this entered Quiescence operation.
    ///
    /// The closed provider authenticates the descriptor's process-contract
    /// provenance. This method neither creates an event nor begins an operation.
    /// Cancellation and policy amendments conservatively signal the subscriber;
    /// polling never consumes its count. The descriptor closes before its loan.
    ///
    /// # Errors
    /// Refuses another operation class, a terminal guard, signalled or invalid
    /// event, unavailable custody, or a duplicate subscription. Passed custody
    /// is physically released on refusal before its credit is returned.
    pub fn retain_original_quiescence_cancellation(
        &self,
        descriptor: OwnedFd,
        credit: HostServiceLease,
    ) -> Result<(), HostSupervisionError> {
        self.retain_original_cancellation_for(HostOperationClass::Quiescence, descriptor, credit)
    }

    /// Checks the retained Pause event without consuming cancellation.
    ///
    /// # Errors
    /// Refuses a different operation class, absent subscription, original
    /// cancellation or expiry, and unavailable synchronization or descriptor.
    pub fn check_original_quiescence_cancellation(&self) -> Result<(), HostSupervisionError> {
        if self.status()?.class != HostOperationClass::Quiescence {
            return Err(HostSupervisionError::InvalidBudget);
        }
        self.check_original_cancellation()
    }

    /// Waits for this owner's wake within both actual Quiescence slices.
    ///
    /// Both entered subscriptions are checked before and after the bounded
    /// wait. A second owner's shorter slice narrows this wait; it supplies no
    /// replacement clock, timeout, operation or progress credit. The provider
    /// preserves each independent raw postcut alongside an initiating refusal.
    ///
    /// # Errors
    /// Refuses a missing or terminal subscription, a different operation class,
    /// either actual original expiry, or unavailable synchronization.
    #[cfg(feature = "private-measurement-domain")]
    pub fn wait_for_quiescence_change_with(
        &self,
        other: &Self,
    ) -> Result<(), HostSupervisionError> {
        let own = self.check_original_quiescence_cancellation();
        let paired = other.check_original_quiescence_cancellation();
        own.and(paired)?;
        let paired_slice = other.wait_slice()?;
        let original_slice = self.check_original_preparation()?;

        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        let poll = state.budgets.get(decision.class).poll_interval;
        let slice = decision
            .deadline
            .map_or(poll, |deadline| poll.min(deadline.remaining));
        let slice = self.supervisor.bound_measurement_wait(slice)?;
        let slice = original_slice.map_or(slice, |original| original.min(slice));
        let waited = self
            .supervisor
            .shared
            .changed
            .wait_timeout(state, slice.min(paired_slice))
            .map_err(|_| HostSupervisionError::Unavailable)?;
        drop(waited);

        let own = self.check_original_quiescence_cancellation();
        let paired = other.check_original_quiescence_cancellation();
        own.and(paired)
    }

    /// Serializes the same entered finite Pause and retained cancellation basis.
    ///
    /// No timestamp is supplied by the caller. Exports preserve the original
    /// start and immutable total, Preparation and kernel bounds. Existing live
    /// progress policy can advance a progress-limited end; native acquisition
    /// retains its first exported basis rather than importing a renewed one.
    /// The provider keeps the same guard and exclusive Node control until native
    /// obligations close; a copied basis or status cannot replace that owner.
    ///
    /// # Errors
    /// Refuses a different or terminal operation, missing retained event, an
    /// unbounded effective end, and unrepresentable original clock coordinates.
    pub fn serialize_original_quiescence_basis(&self) -> Result<[u8; 80], HostSupervisionError> {
        self.check_original_quiescence_cancellation()?;
        self.serialize_original_operation_basis(HostOperationClass::Quiescence, *b"CRUCPAU1", 1, 80)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_services::HostServiceAllocator;
    use crate::host_supervision::{
        HostOperationBudgets, HostOperationState, HostOperationSupervisor,
    };

    fn event() -> Result<OwnedFd, HostSupervisionError> {
        rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .map_err(|_| HostSupervisionError::Unavailable)
    }

    fn subscribe(
        operation: &HostOperationGuard,
        event: &OwnedFd,
        account: &HostServiceAllocator,
    ) -> Result<(), HostSupervisionError> {
        let credit = account
            .reserve_resources(
                0,
                1,
                HostOperationGuard::original_quiescence_cancellation_bytes(),
            )
            .map_err(|_| HostSupervisionError::CapacityExhausted)?;
        let descriptor = rustix::io::fcntl_dupfd_cloexec(event, 3)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        operation.retain_original_quiescence_cancellation(descriptor, credit)
    }

    fn readable(event: &OwnedFd) -> Result<bool, HostSupervisionError> {
        let mut descriptors = [rustix::event::PollFd::new(
            event,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut descriptors,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|_| HostSupervisionError::Unavailable)?;
        Ok(descriptors[0]
            .revents()
            .contains(rustix::event::PollFlags::IN))
    }

    #[test]
    fn entered_pause_basis_is_stable_and_setup_cannot_replace_it()
    -> Result<(), HostSupervisionError> {
        let owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let pause = owner.begin(HostOperationClass::Quiescence)?;
        let cancellation = event()?;
        let account =
            HostServiceAllocator::new(1, 2, 4096).map_err(|_| HostSupervisionError::Unavailable)?;
        assert!(pause.serialize_original_quiescence_basis().is_err());
        subscribe(&pause, &cancellation, &account)?;

        let first = pause.serialize_original_quiescence_basis()?;
        let second = pause.serialize_original_quiescence_basis()?;
        assert_eq!(first, second);
        assert_eq!(&first[..8], b"CRUCPAU1");
        assert_eq!(&first[8..16], &[0, 0, 0, 1, 0, 0, 0, 80]);
        assert_eq!(pause.status()?.class, HostOperationClass::Quiescence);
        assert!(pause.serialize_original_setup_basis().is_err());

        let setup = owner.begin_control(HostOperationClass::Setup)?;
        assert!(setup.serialize_original_quiescence_basis().is_err());
        assert!(subscribe(&setup, &cancellation, &account).is_err());
        assert!(subscribe(&pause, &cancellation, &account).is_err());
        Ok(())
    }

    #[test]
    fn actual_amendment_signals_pause_and_refuses_its_retained_basis()
    -> Result<(), HostSupervisionError> {
        let owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let pause = owner.begin(HostOperationClass::Quiescence)?;
        let cancellation = event()?;
        let account =
            HostServiceAllocator::new(1, 1, 4096).map_err(|_| HostSupervisionError::Unavailable)?;
        subscribe(&pause, &cancellation, &account)?;
        let before = pause.serialize_original_quiescence_basis()?;
        assert!(!readable(&cancellation)?);

        owner.update_budgets(0, HostOperationBudgets::default())?;

        assert!(readable(&cancellation)?);
        assert!(matches!(
            pause.serialize_original_quiescence_basis(),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ));
        assert!(pause.check_original_quiescence_cancellation().is_err());
        assert!(readable(&cancellation)?);
        assert_ne!(&before[56..64], &before[64..72]);
        assert!(account.reserve_resources(0, 1, 1).is_err());
        drop(pause);
        assert!(account.reserve_resources(0, 1, 1).is_ok());
        Ok(())
    }

    #[test]
    fn cancellation_before_subscription_refuses_without_retaining_credit()
    -> Result<(), HostSupervisionError> {
        let owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let pause = owner.begin(HostOperationClass::Quiescence)?;
        let cancellation = event()?;
        let account =
            HostServiceAllocator::new(1, 1, 4096).map_err(|_| HostSupervisionError::Unavailable)?;
        rustix::io::write(&cancellation, &1_u64.to_ne_bytes())
            .map_err(|_| HostSupervisionError::Unavailable)?;

        assert!(subscribe(&pause, &cancellation, &account).is_err());

        assert!(readable(&cancellation)?);
        assert!(account.reserve_resources(0, 1, 1).is_ok());
        assert!(pause.serialize_original_quiescence_basis().is_err());
        Ok(())
    }
}
