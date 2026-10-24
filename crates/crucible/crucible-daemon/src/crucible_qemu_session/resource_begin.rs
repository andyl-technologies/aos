//! Keeps bounded resource-begin history separate from selected-root custody.

// SPDX-License-Identifier: Apache-2.0

use crucible_qemu_host::QemuVmRealizationError;

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

/// Preserves a guard's actual cleanup cause and independently observed custody.
///
/// This inline report neither admits cleanup nor certifies physical return.
/// An error may retain the original owner without transferring it to quarantine.
/// Reporting policy remains separate from that custody observation: generic
/// composed cleanup historically classifies quarantine as terminal, while the
/// Original route preserves its actual leaf's classification.
#[derive(Debug)]
pub struct QemuAttemptResourceGuardCleanupFailure {
    error: QemuVmRealizationError,
    quarantined: bool,
    terminal_category: bool,
    cause_kind: CleanupCauseKind,
}

#[derive(Debug)]
enum CleanupCauseKind {
    RawLeaf,
    LocalStatus,
}

impl QemuAttemptResourceGuardCleanupFailure {
    /// Retains an actual refusal without asserting a quarantine transfer.
    #[must_use]
    pub fn retained(error: QemuVmRealizationError) -> Self {
        Self {
            error,
            quarantined: false,
            terminal_category: false,
            cause_kind: CleanupCauseKind::RawLeaf,
        }
    }

    /// Records the quarantine transfer performed by the owning cleanup path.
    pub(crate) fn quarantined(error: QemuVmRealizationError) -> Self {
        Self {
            error,
            quarantined: true,
            terminal_category: false,
            cause_kind: CleanupCauseKind::RawLeaf,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn member_status(status: crate::QemuWorldMemberCleanupStatus) -> Self {
        Self {
            error: status.into_realization(),
            quarantined: false,
            terminal_category: false,
            cause_kind: CleanupCauseKind::LocalStatus,
        }
    }

    pub(crate) fn retained_status(operation: &'static str) -> Self {
        Self {
            error: QemuVmRealizationError::CleanupRetained { operation },
            quarantined: false,
            terminal_category: false,
            cause_kind: CleanupCauseKind::LocalStatus,
        }
    }

    pub(crate) fn canceled_status(operation: &'static str) -> Self {
        Self {
            error: QemuVmRealizationError::Canceled { operation },
            quarantined: false,
            terminal_category: false,
            cause_kind: CleanupCauseKind::LocalStatus,
        }
    }

    pub(crate) fn has_raw_cause(&self) -> bool {
        matches!(self.cause_kind, CleanupCauseKind::RawLeaf)
    }

    /// Borrows the unchanged cause, or the existing terminal status on retry.
    #[must_use]
    pub fn error(&self) -> &QemuVmRealizationError {
        &self.error
    }

    /// Observes whether this refusal's owning path transferred to quarantine.
    #[must_use]
    pub const fn was_quarantined(&self) -> bool {
        self.quarantined
    }

    /// Preserves the generic adapter's previous terminal reporting category.
    #[must_use]
    pub const fn reports_terminal_quarantine(&self) -> bool {
        self.terminal_category
    }

    pub(crate) fn after_quarantine(mut self) -> Self {
        self.quarantined = true;
        self
    }

    pub(crate) fn terminal_category(mut self) -> Self {
        self.terminal_category = true;
        self
    }
}

#[cfg(target_os = "linux")]
impl From<crate::QemuWorldMemberCleanupStatus> for QemuAttemptResourceGuardCleanupFailure {
    fn from(status: crate::QemuWorldMemberCleanupStatus) -> Self {
        Self::member_status(status)
    }
}

impl From<QemuVmRealizationError> for QemuAttemptResourceGuardCleanupFailure {
    fn from(error: QemuVmRealizationError) -> Self {
        Self::retained(error)
    }
}

impl std::fmt::Display for QemuAttemptResourceGuardCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.terminal_category {
            write!(
                formatter,
                "release QEMU attempt host resources could not attest process reap; enforcement is quarantined: {}",
                self.error
            )
        } else {
            std::fmt::Display::fmt(&self.error, formatter)
        }
    }
}

impl std::error::Error for QemuAttemptResourceGuardCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
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
        self.cleanup
            .as_ref()
            .is_some_and(|cleanup| cleanup.was_quarantined())
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
