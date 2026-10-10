//! Serializes the already-entered Setup operation for a local native child.
//!
//! The bytes describe the same original clock and conservative deadline; they
//! do not create an operation, refresh progress, or grant resource authority.
//! The actual launch owner retains this guard and authenticates the separate
//! process-contract cancellation role before publishing the sealed carrier.
//!
//! ```text
//! 0..8    CRUCSTP1
//! 8..12   schema 2
//! 12..16  complete startup-record size 128
//! 16..48  existing cap identity
//! 48..56  existing Setup operation identity
//! 56..64  original operation CLOCK_MONOTONIC coordinate
//! 64..72  conservative absolute effective end
//! 72..80  responsive poll bound
//! ```

use std::os::fd::OwnedFd;

use super::{HostOperationClass, HostOperationGuard, HostOperationState, HostSupervisionError};
use crate::host_services::HostServiceLease;

#[derive(Debug)]
pub(super) struct SetupCancellation {
    descriptor: OwnedFd,
    // Physical descriptor destruction precedes the admitted subscription loan.
    _credit: HostServiceLease,
}

impl SetupCancellation {
    pub(super) fn check(&self) -> Result<(), HostSupervisionError> {
        let mut descriptors = [rustix::event::PollFd::new(
            &self.descriptor,
            rustix::event::PollFlags::IN,
        )];
        let ready = rustix::event::poll(
            &mut descriptors,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|_| HostSupervisionError::Unavailable)?;
        if ready == 0 {
            return Ok(());
        }
        if descriptors[0]
            .revents()
            .contains(rustix::event::PollFlags::IN)
        {
            return Err(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
            });
        }
        Err(HostSupervisionError::Unavailable)
    }

    fn revoke(&self) -> Result<(), HostSupervisionError> {
        match rustix::io::write(&self.descriptor, &1_u64.to_ne_bytes()) {
            Ok(8) | Err(rustix::io::Errno::AGAIN) => Ok(()),
            _ => Err(HostSupervisionError::Unavailable),
        }
    }
}

pub(super) fn revoke_setup_operations(shared: &super::Shared) -> Result<(), HostSupervisionError> {
    let (state, mut failure) = match shared.state.lock() {
        Ok(state) => (state, None),
        Err(poisoned) => (
            poisoned.into_inner(),
            Some(HostSupervisionError::Unavailable),
        ),
    };
    for operation in state.operations.values() {
        if operation.state == HostOperationState::Running
            && let Some(cancellation) = &operation.startup_cancellation
        {
            let result = cancellation.revoke();
            if failure.is_none() {
                failure = result.err();
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

impl HostOperationGuard {
    /// Returns the fixed retained extent for an original Setup event subscriber.
    ///
    /// This is layout information, not resource authority. The launch owner
    /// admits these bytes and one descriptor from its existing service account
    /// before duplication; allocator/BTree control peaks remain its obligation.
    #[must_use]
    pub const fn original_setup_cancellation_bytes() -> u64 {
        std::mem::size_of::<Option<SetupCancellation>>() as u64 + HostServiceLease::metadata_bytes()
    }

    /// Retains a prepaid alias of the existing process cancellation event.
    ///
    /// Authenticated launch custody must verify this is the same contract event
    /// and retain its genuine existing account. Later policy/cap mutation signals
    /// this alias conservatively instead of renewing exported immutable time.
    /// This method creates no event, operation, account or native permission.
    ///
    /// # Errors
    /// Refuses another class, terminal/uncertain custody or an existing subscriber.
    /// On refusal, the passed descriptor closes before its external loan.
    pub fn retain_original_setup_cancellation(
        &self,
        descriptor: OwnedFd,
        credit: HostServiceLease,
    ) -> Result<(), HostSupervisionError> {
        self.retain_original_cancellation_for(HostOperationClass::Setup, descriptor, credit)
    }

    pub(super) fn retain_original_cancellation_for(
        &self,
        class: HostOperationClass,
        descriptor: OwnedFd,
        credit: HostServiceLease,
    ) -> Result<(), HostSupervisionError> {
        let cancellation = SetupCancellation {
            descriptor,
            _credit: credit,
        };
        let flags = rustix::fs::fcntl_getfl(&cancellation.descriptor)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if !flags.contains(rustix::fs::OFlags::NONBLOCK) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        cancellation.check()?;
        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        if decision.class != class {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let operation = state
            .operations
            .get_mut(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;
        if operation.startup_cancellation.is_some() {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        operation.startup_cancellation = Some(cancellation);
        Ok(())
    }

    /// Checks the retained original event without consuming its cancellation count.
    ///
    /// # Errors
    /// Refuses revoked, absent, terminal or uncertain startup custody.
    pub fn check_original_setup_cancellation(&self) -> Result<(), HostSupervisionError> {
        self.check_original_cancellation()
    }

    pub(super) fn check_original_cancellation(&self) -> Result<(), HostSupervisionError> {
        let mut state = self.supervisor.lock()?;
        self.supervisor
            .evaluate_decision(&mut state, self.id)?
            .require_running(self.id)?;
        state
            .operations
            .get(&self.id)
            .and_then(|operation| operation.startup_cancellation.as_ref())
            .ok_or(HostSupervisionError::Unavailable)?
            .check()
    }

    /// Serializes the original finite Setup basis for an authenticated local child.
    ///
    /// The caller must retain this same guard until registered acceptance or
    /// physical containment. The returned bytes have no standalone authority;
    /// the closed launch producer must bind the same process contract and put
    /// the complete record in its sealed setup descriptor before child birth.
    ///
    /// # Errors
    /// Refuses another operation class, a terminal or uncertain owner, absent
    /// finite deadline, or unrepresentable shared-kernel coordinates.
    pub fn serialize_original_setup_basis(&self) -> Result<[u8; 80], HostSupervisionError> {
        self.serialize_original_operation_basis(HostOperationClass::Setup, *b"CRUCSTP1", 2, 128)
    }

    pub(super) fn serialize_original_operation_basis(
        &self,
        class: HostOperationClass,
        magic: [u8; 8],
        schema: u32,
        record_size: u32,
    ) -> Result<[u8; 80], HostSupervisionError> {
        #[cfg(feature = "private-measurement-domain")]
        let preparation_limits = if let Some(original) = &self.original_preparation {
            self.check_original_preparation()?;
            let basis = original.serialize_original_operation_basis(
                HostOperationClass::Preparation,
                *b"CRUCPAU1",
                1,
                80,
            )?;
            let end = u64::from_be_bytes(
                basis[64..72]
                    .try_into()
                    .map_err(|_| HostSupervisionError::InvalidBudget)?,
            );
            let poll = u64::from_be_bytes(
                basis[72..80]
                    .try_into()
                    .map_err(|_| HostSupervisionError::InvalidBudget)?,
            );
            Some((end, poll))
        } else {
            None
        };
        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        if decision.class != class {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let operation = state
            .operations
            .get(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;
        let budget = state.budgets.get(class);
        let origin = self.supervisor.shared.original_monotonic_ns;
        #[cfg(feature = "private-measurement-domain")]
        let origin = self
            .supervisor
            .shared
            .measurement_clock
            .map_or(origin, |clock| origin.min(clock.start_ns));
        let started = coordinate(origin, operation.started)?;
        let total_end = budget
            .total_timeout
            .map(|span| {
                operation
                    .started
                    .checked_add(span)
                    .ok_or(HostSupervisionError::InvalidBudget)
            })
            .transpose()?;
        let progress_end = budget
            .progress_timeout
            .map(|span| {
                operation
                    .last_progress
                    .checked_add(span)
                    .ok_or(HostSupervisionError::InvalidBudget)
            })
            .transpose()?;
        let mut end = None;
        for limit in [total_end, progress_end, state.cap_allowance]
            .into_iter()
            .flatten()
        {
            let coordinate = coordinate(origin, limit)?;
            end = Some(end.map_or(coordinate, |current: u64| current.min(coordinate)));
        }
        #[cfg(feature = "private-measurement-domain")]
        if let Some(clock) = self.supervisor.shared.measurement_clock {
            end = Some(end.map_or(clock.end_ns, |current| current.min(clock.end_ns)));
        }
        #[cfg(feature = "private-measurement-domain")]
        if let Some((preparation_end, _)) = preparation_limits {
            end = Some(end.map_or(preparation_end, |current| current.min(preparation_end)));
        }
        let end = end
            .filter(|end| *end > started)
            .ok_or(HostSupervisionError::InvalidBudget)?;
        let poll = u64::try_from(budget.poll_interval.as_nanos())
            .map_err(|_| HostSupervisionError::InvalidBudget)?;
        #[cfg(feature = "private-measurement-domain")]
        let poll = preparation_limits.map_or(poll, |(_, original_poll)| poll.min(original_poll));
        let mut bytes = [0; 80];
        bytes[..8].copy_from_slice(&magic);
        bytes[8..12].copy_from_slice(&schema.to_be_bytes());
        bytes[12..16].copy_from_slice(&record_size.to_be_bytes());
        bytes[16..48].copy_from_slice(&state.cap_id);
        for (offset, value) in [(48, self.id), (56, started), (64, end), (72, poll)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        Ok(bytes)
    }
}

fn coordinate(origin: u64, elapsed: std::time::Duration) -> Result<u64, HostSupervisionError> {
    let elapsed =
        u64::try_from(elapsed.as_nanos()).map_err(|_| HostSupervisionError::InvalidBudget)?;
    origin
        .checked_add(elapsed)
        .ok_or(HostSupervisionError::IdentityExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_supervision::{HostOperationBudgets, HostOperationSupervisor};

    #[test]
    fn same_entered_setup_serializes_without_restarting_its_original_deadline()
    -> Result<(), HostSupervisionError> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let setup = supervisor.begin_control(HostOperationClass::Setup)?;
        let first = setup.serialize_original_setup_basis()?;
        let second = setup.serialize_original_setup_basis()?;
        assert_eq!(first, second);
        assert_ne!(&first[16..48], &[0; 32]);
        assert!(setup.complete().is_ok());
        assert!(setup.serialize_original_setup_basis().is_err());
        Ok(())
    }

    #[test]
    fn common_startup_refuses_another_class_and_actual_cancelled_original()
    -> Result<(), HostSupervisionError> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let preparation = supervisor.begin(HostOperationClass::Preparation)?;
        assert!(matches!(
            preparation.serialize_original_setup_basis(),
            Err(HostSupervisionError::InvalidBudget)
        ));
        let setup = supervisor.begin_control(HostOperationClass::Setup)?;
        supervisor.cancel()?;
        assert!(matches!(
            setup.serialize_original_setup_basis(),
            Err(HostSupervisionError::Terminal { .. })
        ));
        Ok(())
    }

    fn event() -> Result<OwnedFd, HostSupervisionError> {
        rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .map_err(|_| HostSupervisionError::Unavailable)
    }

    fn subscription(
        setup: &HostOperationGuard,
        event: &OwnedFd,
        account: &crate::host_services::HostServiceAllocator,
    ) -> Result<(), HostSupervisionError> {
        let credit = account
            .reserve_resources(
                0,
                1,
                HostOperationGuard::original_setup_cancellation_bytes(),
            )
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let descriptor = rustix::io::fcntl_dupfd_cloexec(event, 3)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        setup.retain_original_setup_cancellation(descriptor, credit)
    }

    fn account(
        descriptors: u64,
    ) -> Result<crate::host_services::HostServiceAllocator, HostSupervisionError> {
        crate::host_services::HostServiceAllocator::new(1, descriptors, 4096)
            .map_err(|_| HostSupervisionError::Unavailable)
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
        .map(|_| {
            descriptors[0]
                .revents()
                .contains(rustix::event::PollFlags::IN)
        })
        .map_err(|_| HostSupervisionError::Unavailable)
    }

    #[test]
    fn registration_during_revocation_cannot_extend_the_original_roster_walk()
    -> Result<(), HostSupervisionError> {
        let root = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let retained = root.new_budget_owner(HostOperationBudgets::default())?;
        let original_last = retained.shared.budget_owner;
        let mut visited = Vec::new();
        let mut newly_registered = Vec::new();
        let mut registration_failure = None;

        root.notify_owners_with_visitor(|id| {
            visited.push(id);
            match root.new_budget_owner(HostOperationBudgets::default()) {
                Ok(owner) => newly_registered.push(owner),
                Err(error) => registration_failure = Some(error),
            }
        })?;

        if let Some(error) = registration_failure {
            return Err(error);
        }
        assert_eq!(visited, [0, original_last]);
        assert_eq!(newly_registered.len(), visited.len());
        assert!(
            newly_registered
                .iter()
                .all(|owner| owner.shared.budget_owner > original_last)
        );
        Ok(())
    }

    #[test]
    fn actual_original_cancel_signals_each_saved_setup_event_without_consuming_it()
    -> Result<(), HostSupervisionError> {
        let root = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let derived = root.new_budget_owner(HostOperationBudgets::default())?;
        let first = root.begin_control(HostOperationClass::Setup)?;
        let second = derived.begin_control(HostOperationClass::Setup)?;
        let first_event = event()?;
        let second_event = event()?;
        let account = account(2)?;
        subscription(&first, &first_event, &account)?;
        subscription(&second, &second_event, &account)?;
        assert!(!readable(&first_event)?);
        assert!(!readable(&second_event)?);

        derived.cancel()?;

        assert!(readable(&first_event)?);
        assert!(readable(&second_event)?);
        assert!(first.check_original_setup_cancellation().is_err());
        assert!(second.complete().is_err());
        assert!(readable(&first_event)?);
        assert!(readable(&second_event)?);
        Ok(())
    }

    #[test]
    fn budget_amendment_revokes_the_exported_setup_without_renewing_its_origin()
    -> Result<(), HostSupervisionError> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let setup = supervisor.begin_control(HostOperationClass::Setup)?;
        let event = event()?;
        subscription(&setup, &event, &account(1)?)?;
        let before = setup.serialize_original_setup_basis()?;

        supervisor.update_budgets(0, HostOperationBudgets::default())?;

        let after = setup.serialize_original_setup_basis()?;
        assert_eq!(&before[48..64], &after[48..64]);
        assert!(readable(&event)?);
        assert!(matches!(
            setup.complete(),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled
            })
        ));
        Ok(())
    }

    #[test]
    fn completed_setup_closes_its_descriptor_and_credit_before_later_amendment()
    -> Result<(), HostSupervisionError> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let setup = supervisor.begin_control(HostOperationClass::Setup)?;
        let event = event()?;
        let account = account(1)?;
        subscription(&setup, &event, &account)?;
        assert!(account.reserve_resources(0, 1, 1).is_err());

        setup.complete()?;

        let available = account
            .reserve_resources(0, 1, 1)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        supervisor.amend_outer_cap(0, Some(std::time::Duration::from_secs(1)))?;
        assert!(!readable(&event)?);
        drop(available);
        Ok(())
    }

    #[test]
    fn simultaneous_saved_setups_keep_separate_existing_operation_subscribers()
    -> Result<(), HostSupervisionError> {
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let first = supervisor.begin_control(HostOperationClass::Setup)?;
        let second = supervisor.begin_control(HostOperationClass::Setup)?;
        let first_event = event()?;
        let second_event = event()?;
        let account = account(2)?;
        subscription(&first, &first_event, &account)?;
        subscription(&second, &second_event, &account)?;
        drop(first);
        let released = account
            .reserve_resources(0, 1, 1)
            .map_err(|_| HostSupervisionError::Unavailable)?;

        supervisor.cancel()?;

        assert!(!readable(&first_event)?);
        assert!(readable(&second_event)?);
        drop(released);
        Ok(())
    }
}
