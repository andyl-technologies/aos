//! Live host operation budgets for tokenized shared-memory control waits.

use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

use super::*;

/// Uses a live original-start owner when admitted, with a fixture-only fallback.
pub(crate) enum OperationPollBudget<'a> {
    Borrowed(&'a HostOperationGuard),
    Supervised(HostOperationGuard),
    Fixture(HostSupervisionDeadline),
}

impl<'a> OperationPollBudget<'a> {
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

    pub(crate) fn begin(
        supervisor: Option<&HostOperationSupervisor>,
        class: HostOperationClass,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<Self, QemuAsyncDriverRuntimeError> {
        if let Some(supervisor) = supervisor {
            return supervisor
                .begin(class)
                .map(Self::Supervised)
                .map_err(|source| Self::failure(operation, source));
        }
        if timeout.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                operation,
                "fixture timeout is zero",
            ));
        }
        Ok(Self::Fixture(HostSupervisionDeadline::start(timeout)))
    }

    pub(crate) fn remaining(
        &self,
        operation: &'static str,
    ) -> Result<Option<Duration>, QemuAsyncDriverRuntimeError> {
        match self {
            Self::Borrowed(guard) => guard
                .wait_slice()
                .map(Some)
                .map_err(|source| Self::failure(operation, source)),
            Self::Supervised(guard) => guard
                .wait_slice()
                .map(Some)
                .map_err(|source| Self::failure(operation, source)),
            Self::Fixture(deadline) => Ok(deadline.remaining()),
        }
    }

    pub(crate) fn wait(
        &self,
        poll_interval: Duration,
        operation: &'static str,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match self {
            Self::Borrowed(guard) => guard
                .wait_for_change()
                .map_err(|source| Self::failure(operation, source)),
            Self::Supervised(guard) => guard
                .wait_for_change()
                .map_err(|source| Self::failure(operation, source)),
            Self::Fixture(deadline) => {
                if let Some(remaining) = deadline.remaining() {
                    thread::sleep(poll_interval.min(remaining));
                }
                Ok(())
            }
        }
    }

    pub(crate) fn complete(
        &self,
        operation: &'static str,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if let Self::Borrowed(guard) = self {
            guard
                .wait_slice()
                .map_err(|source| Self::failure(operation, source))?;
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
        source: crucible_linux_resource::host_supervision::HostSupervisionError,
    ) -> QemuAsyncDriverRuntimeError {
        QemuAsyncDriverRuntimeError::operational_supervision(operation, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::HostOperationBudgets;

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
