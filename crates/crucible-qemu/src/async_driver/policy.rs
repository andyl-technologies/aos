//! Timeout policy behavior for bounded host-I/O awaits.

use super::*;

impl QemuAsyncDriverPolicy {
    /// Builds a policy from explicit host-I/O timeout budgets.
    #[must_use]
    pub const fn new(
        handshake_timeout: Duration,
        qmp_command_timeout: Duration,
        process_event_timeout: Duration,
        advance_completion_timeout: Duration,
    ) -> Self {
        Self {
            handshake_timeout,
            qmp_command_timeout,
            process_event_timeout,
            advance_completion_timeout,
        }
    }

    /// Returns a small nonzero policy for unit tests.
    #[must_use]
    pub const fn fast_test() -> Self {
        Self::new(
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(4),
        )
    }

    /// Returns the timeout budget for `wait`.
    #[must_use]
    pub const fn timeout_for(self, wait: QemuAsyncWait) -> Duration {
        match wait {
            QemuAsyncWait::Handshake => self.handshake_timeout,
            QemuAsyncWait::QmpCommand => self.qmp_command_timeout,
            QemuAsyncWait::ProcessEvent => self.process_event_timeout,
            QemuAsyncWait::AdvanceCompletion => self.advance_completion_timeout,
        }
    }

    /// Validates that every child await has a nonzero timeout.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverError::UnboundedAwait`] when any timeout is zero.
    pub fn validate(self) -> Result<(), QemuAsyncDriverError> {
        for wait in [
            QemuAsyncWait::Handshake,
            QemuAsyncWait::QmpCommand,
            QemuAsyncWait::ProcessEvent,
            QemuAsyncWait::AdvanceCompletion,
        ] {
            let timeout = self.timeout_for(wait);
            if timeout.is_zero() {
                return Err(QemuAsyncDriverError::UnboundedAwait { wait });
            }
        }
        Ok(())
    }
}
