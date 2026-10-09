//! Retained pidfd guard for the custody process itself.

use aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard as NativeRetainedSelfExecutionGuard;

use crate::BrokerSessionSecurityError;

/// Provides the private currentness operation used by endpoint custody.
pub(crate) trait CurrentSelfExecutionGuard: Send + Sync {
    fn validate_current(&self) -> Result<(), BrokerSessionSecurityError>;
}

/// Retains the loading process's pidfd and stable execution baseline.
pub(crate) struct RetainedSelfExecutionGuard {
    native: NativeRetainedSelfExecutionGuard,
}

impl RetainedSelfExecutionGuard {
    /// Captures and validates the current process through one newly opened pidfd.
    pub(crate) fn capture() -> Result<Self, BrokerSessionSecurityError> {
        let native = NativeRetainedSelfExecutionGuard::capture()
            .map_err(|_| BrokerSessionSecurityError::ExecutionChanged)?;
        Ok(Self { native })
    }

    /// Returns the boot identity pinned by the complete capture sandwich.
    pub(crate) const fn boot_id(&self) -> [u8; 16] {
        self.native.boot_id()
    }
}

impl CurrentSelfExecutionGuard for RetainedSelfExecutionGuard {
    fn validate_current(&self) -> Result<(), BrokerSessionSecurityError> {
        self.native
            .validate_current()
            .map_err(|_| BrokerSessionSecurityError::ExecutionChanged)
    }
}
