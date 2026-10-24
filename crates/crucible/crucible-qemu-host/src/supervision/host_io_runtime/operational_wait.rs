//! Live host operation budgets for tokenized shared-memory control waits.

use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

use super::*;

/// Uses a live original-start owner when admitted, with a fixture-only fallback.
pub(crate) enum OperationPollBudget<'a> {
    Borrowed(&'a HostOperationGuard),
    BorrowedCheckpoint(&'a HostOperationGuard),
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    BorrowedPair(&'a HostOperationGuard, &'a HostOperationGuard),
    Supervised(HostOperationGuard),
    #[cfg(any(test, feature = "test-support"))]
    Fixture(HostSupervisionDeadline),
}

impl<'a> OperationPollBudget<'a> {
    /// Identifies the retained two-producer park path without creating a guard.
    pub(crate) fn is_paired_quiescence(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if matches!(self, Self::BorrowedPair(_, _)) {
            return true;
        }
        false
    }

    /// Borrows the actual producing guard set, preserving every class and clock.
    pub(crate) fn action_producers(
        &self,
    ) -> Result<Option<[Option<&HostOperationGuard>; 2]>, QemuAsyncDriverRuntimeError> {
        match self {
            Self::Borrowed(guard) | Self::BorrowedCheckpoint(guard) => {
                Ok(Some([Some(guard), None]))
            }
            Self::Supervised(guard) => Ok(Some([Some(guard), None])),
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::BorrowedPair(actor, family) => Ok(Some([Some(actor), Some(family)])),
            #[cfg(any(test, feature = "test-support"))]
            Self::Fixture(_) => Ok(None),
        }
    }

    /// Borrows the retained checkpoint original and its cancellation subscriber.
    pub(crate) fn borrow_checkpoint_original(
        original: &'a HostOperationGuard,
        operation: &'static str,
    ) -> Result<Self, QemuAsyncDriverRuntimeError> {
        Self::checkpoint_slice(original, operation)?;
        Ok(Self::BorrowedCheckpoint(original))
    }

    fn checkpoint_slice(
        original: &HostOperationGuard,
        operation: &'static str,
    ) -> Result<Duration, QemuAsyncDriverRuntimeError> {
        let check = || {
            original.check_original_quiescence_cancellation()?;
            let slice = original.wait_slice()?;
            original.check_original_quiescence_cancellation()?;
            Ok(slice)
        };
        check().map_err(|source| Self::failure(operation, source))
    }

    /// Borrows the caller's live operation without creating or completing one.
    pub(crate) fn borrow_original(
        original: &'a HostOperationGuard,
        operation: &'static str,
    ) -> Result<Self, QemuAsyncDriverRuntimeError> {
        original
            .wait_slice()
            .map_err(|source| Self::failure(operation, source))?;
        Ok(Self::Borrowed(original))
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn borrow_quiescence_pair(
        actor: &'a HostOperationGuard,
        family: &'a HostOperationGuard,
        operation: &'static str,
    ) -> Result<Self, QemuAsyncDriverRuntimeError> {
        let pair = Self::BorrowedPair(actor, family);
        pair.remaining(operation)?;
        Ok(pair)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn paired_slice(
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
        operation: &'static str,
    ) -> Result<Duration, QemuAsyncDriverRuntimeError> {
        let check = |guard: &HostOperationGuard| {
            guard.check_original_quiescence_cancellation()?;
            let slice = guard.wait_slice()?;
            guard.check_original_quiescence_cancellation()?;
            Ok(slice)
        };
        let actor_slice = check(actor);
        let family_slice = check(family);
        actor_slice
            .and_then(|actor| family_slice.map(|family| actor.min(family)))
            .map_err(|source| Self::failure(operation, source))
    }

    pub(crate) fn begin(
        supervisor: Option<&HostOperationSupervisor>,
        class: HostOperationClass,
        _fixture_timeout: Duration,
        operation: &'static str,
    ) -> Result<Self, QemuAsyncDriverRuntimeError> {
        if let Some(supervisor) = supervisor {
            return supervisor
                .begin(class)
                .map(Self::Supervised)
                .map_err(|source| Self::failure(operation, source));
        }

        #[cfg(any(test, feature = "test-support"))]
        {
            if _fixture_timeout.is_zero() {
                return Err(QemuAsyncDriverRuntimeError::new(
                    operation,
                    "fixture timeout is zero",
                ));
            }
            Ok(Self::Fixture(HostSupervisionDeadline::start(
                _fixture_timeout,
            )))
        }

        #[cfg(not(any(test, feature = "test-support")))]
        {
            Err(QemuAsyncDriverRuntimeError::new(
                operation,
                "operation requires original supervision",
            ))
        }
    }

    pub(crate) fn remaining(
        &self,
        operation: &'static str,
    ) -> Result<Option<Duration>, QemuAsyncDriverRuntimeError> {
        match self {
            Self::BorrowedCheckpoint(guard) => Self::checkpoint_slice(guard, operation).map(Some),
            Self::Borrowed(guard) => guard
                .wait_slice()
                .map(Some)
                .map_err(|source| Self::failure(operation, source)),
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::BorrowedPair(actor, family) => {
                Self::paired_slice(actor, family, operation).map(Some)
            }
            Self::Supervised(guard) => guard
                .wait_slice()
                .map(Some)
                .map_err(|source| Self::failure(operation, source)),
            #[cfg(any(test, feature = "test-support"))]
            Self::Fixture(deadline) => Ok(deadline.remaining()),
        }
    }

    pub(crate) fn wait(
        &self,
        _fixture_poll_interval: Duration,
        operation: &'static str,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match self {
            Self::BorrowedCheckpoint(guard) => {
                Self::checkpoint_slice(guard, operation)?;
                guard
                    .wait_for_change()
                    .map_err(|source| Self::failure(operation, source))?;
                Self::checkpoint_slice(guard, operation).map(|_| ())
            }
            Self::Borrowed(guard) => guard
                .wait_for_change()
                .map_err(|source| Self::failure(operation, source)),
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            Self::BorrowedPair(actor, family) => actor
                .wait_for_quiescence_change_with(family)
                .map_err(|source| Self::failure(operation, source)),
            Self::Supervised(guard) => guard
                .wait_for_change()
                .map_err(|source| Self::failure(operation, source)),
            #[cfg(any(test, feature = "test-support"))]
            Self::Fixture(deadline) => {
                if let Some(remaining) = deadline.remaining() {
                    thread::sleep(_fixture_poll_interval.min(remaining));
                }
                Ok(())
            }
        }
    }

    pub(crate) fn complete(
        &self,
        operation: &'static str,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if let Self::BorrowedCheckpoint(guard) = self {
            Self::checkpoint_slice(guard, operation)?;
        }
        if let Self::Borrowed(guard) = self {
            guard
                .wait_slice()
                .map_err(|source| Self::failure(operation, source))?;
        }
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if let Self::BorrowedPair(actor, family) = self {
            Self::paired_slice(actor, family, operation)?;
        }
        if let Self::Supervised(guard) = self {
            guard
                .complete()
                .map_err(|source| Self::failure(operation, source))?;
        }
        Ok(())
    }

    fn failure(
        operation: &'static str,
        source: crucible_host_resources::host_supervision::HostSupervisionError,
    ) -> QemuAsyncDriverRuntimeError {
        QemuAsyncDriverRuntimeError::operational_supervision(operation, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_host_resources::host_supervision::HostOperationBudgets;

    #[test]
    fn ownerless_fixture_budget_keeps_its_explicit_timeout_without_producers() {
        let budget = OperationPollBudget::begin(
            None,
            HostOperationClass::FingerprintUpdate,
            Duration::from_secs(2),
            "fixture fingerprint",
        )
        .unwrap();

        assert!(matches!(budget, OperationPollBudget::Fixture(_)));
        assert!(budget.action_producers().unwrap().is_none());
        budget.complete("fixture fingerprint").unwrap();
        assert!(
            OperationPollBudget::begin(
                None,
                HostOperationClass::FingerprintUpdate,
                Duration::ZERO,
                "fixture fingerprint",
            )
            .is_err()
        );
    }

    #[test]
    fn refused_supervisor_never_falls_back_to_a_fixture_budget() {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        supervisor.cancel().unwrap();

        let result = OperationPollBudget::begin(
            Some(&supervisor),
            HostOperationClass::FingerprintUpdate,
            Duration::from_secs(2),
            "cancelled fingerprint",
        );

        let error = result.err().unwrap();
        assert_eq!(
            error.operational_supervision_source(),
            Some(
                crucible_host_resources::host_supervision::HostSupervisionError::Terminal {
                    state: crucible_host_resources::host_supervision::HostOperationState::Canceled,
                }
            ),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkpoint_ack_wait_borrows_one_original_and_keeps_subscriber_refusal() {
        use crate::node::checkpoint_original_loan_fixture;
        use crucible_host_resources::host_supervision::HostOperationState;

        let (_owner, original, supervisor, event, _account) = checkpoint_original_loan_fixture();
        let budget = OperationPollBudget::borrow_checkpoint_original(
            original.guard(),
            "checkpoint acknowledgement",
        )
        .unwrap();

        assert!(
            budget
                .remaining("checkpoint acknowledgement")
                .unwrap()
                .is_some()
        );
        budget.complete("checkpoint acknowledgement").unwrap();
        let status = supervisor.operation_statuses().unwrap();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].state, HostOperationState::Running);

        rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();

        assert!(budget.complete("checkpoint acknowledgement").is_err());
        assert!(budget.remaining("checkpoint acknowledgement").is_err());
        assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    }

    #[test]
    fn changed_class_allowance_applies_to_original_wait_start() {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .unwrap_or_else(|error| panic!("admit owner: {error}"));
        let budget = OperationPollBudget::begin(
            Some(&supervisor),
            HostOperationClass::FingerprintUpdate,
            Duration::ZERO,
            "fingerprint",
        )
        .unwrap_or_else(|error| {
            panic!("admit live operation independently of fixture timeout: {error}")
        });
        let (revision, mut budgets) = supervisor
            .budgets()
            .unwrap_or_else(|error| panic!("read policy: {error}"));
        budgets.classes[HostOperationClass::FingerprintUpdate as usize].total_timeout =
            Some(Duration::from_nanos(1));

        supervisor
            .update_budgets(revision, budgets)
            .unwrap_or_else(|error| panic!("reduce original allowance: {error}"));

        assert!(budget.remaining("fingerprint").is_err());
        assert!(budget.complete("fingerprint").is_err());
    }

    #[test]
    fn cancellation_wins_an_already_observed_acknowledgement() {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .unwrap_or_else(|error| panic!("admit owner: {error}"));
        let budget = OperationPollBudget::begin(
            Some(&supervisor),
            HostOperationClass::Quiescence,
            Duration::ZERO,
            "quiescence",
        )
        .unwrap_or_else(|error| panic!("admit live operation: {error}"));

        supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel owner: {error}"));

        assert!(budget.complete("quiescence").is_err());
        assert!(budget.wait(Duration::from_secs(1), "quiescence").is_err());
    }
}
