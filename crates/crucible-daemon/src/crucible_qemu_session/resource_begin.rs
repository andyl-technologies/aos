//! Keeps bounded resource-begin history separate from selected-root custody.

// SPDX-License-Identifier: Apache-2.0

use crucible_qemu::QemuVmRealizationError;

/// Preserves an initiating resource refusal and its independent rollback cause.
///
/// Both leaves move inline, including any custody they already retain. This
/// report issues no cleanup permission and certifies no physical return. A
/// missing selected claim is not a quarantine observation: only the actual
/// failed rollback constructor records that fact.
#[derive(Debug)]
pub struct QemuAttemptResourceGuardBeginReport {
    first: QemuVmRealizationError,
    cleanup: Option<QemuAttemptResourceGuardCleanupFailure>,
}

/// Moves the raw host cleanup cause and its already-observed quarantine fact.
///
/// This stack report introduces no cleanup operation or containing allocation.
#[derive(Debug)]
pub(crate) struct QemuAttemptResourceGuardCleanupFailure {
    error: QemuVmRealizationError,
}

impl QemuAttemptResourceGuardCleanupFailure {
    pub(crate) fn quarantined(error: QemuVmRealizationError) -> Self {
        Self { error }
    }

    pub(crate) fn into_error(self) -> QemuVmRealizationError {
        self.error
    }
}

impl QemuAttemptResourceGuardBeginReport {
    /// Borrows the unchanged initiating refusal.
    #[must_use]
    pub fn first_error(&self) -> &QemuVmRealizationError {
        &self.first
    }

    /// Borrows the independent rollback refusal, when one actually occurred.
    #[must_use]
    pub fn cleanup_error(&self) -> Option<&QemuVmRealizationError> {
        self.cleanup.as_ref().map(|cleanup| &cleanup.error)
    }

    /// Reports that the actual failed rollback quarantined its host owner.
    #[must_use]
    pub fn was_quarantined(&self) -> bool {
        self.cleanup.is_some()
    }

    pub(super) fn after_rollback(
        first: QemuVmRealizationError,
        cleanup: QemuAttemptResourceGuardCleanupFailure,
    ) -> Self {
        Self {
            first,
            cleanup: Some(cleanup),
        }
    }
}

impl From<QemuVmRealizationError> for QemuAttemptResourceGuardBeginReport {
    fn from(first: QemuVmRealizationError) -> Self {
        Self {
            first,
            cleanup: None,
        }
    }
}

impl std::fmt::Display for QemuAttemptResourceGuardBeginReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.first, formatter)?;
        if let Some(cleanup) = self.cleanup_error() {
            write!(formatter, "; rollback quarantined: {cleanup}")?;
        }
        Ok(())
    }
}

impl std::error::Error for QemuAttemptResourceGuardBeginReport {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.first)
    }
}
