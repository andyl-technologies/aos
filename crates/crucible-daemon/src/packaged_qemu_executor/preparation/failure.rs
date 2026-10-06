//! Retains an expired capture's original failure under its admitted metadata loan.
//!
//! Expiration remains the outer operational classification. The cause records
//! the actual launch or capture error without renewing its deadline or losing
//! its typed source. Error storage is destroyed before its original credit.

use super::PackagedQemuExecutorError;
use crucible::owned_decode::DecodeScratch;
use std::error::Error;
use std::fmt;

/// Retains the original capture failure and its admitted owning storage.
pub struct PreparationExpiredCause {
    cause: Box<PackagedQemuExecutorError>,
    _resources: DecodeScratch,
}

impl PreparationExpiredCause {
    /// Returns the original launch, capture, or authentication failure.
    #[must_use]
    pub fn cause(&self) -> &PackagedQemuExecutorError {
        &self.cause
    }
}

impl fmt::Debug for PreparationExpiredCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.cause, formatter)
    }
}

impl fmt::Display for PreparationExpiredCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, formatter)
    }
}

impl Error for PreparationExpiredCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

pub(super) fn finish_capture<T>(
    result: Result<T, PackagedQemuExecutorError>,
    expired: bool,
    resources: DecodeScratch,
) -> Result<T, PackagedQemuExecutorError> {
    if !expired {
        return result;
    }

    let source = result.err().map(|cause| PreparationExpiredCause {
        cause: Box::new(cause),
        _resources: resources,
    });
    Err(PackagedQemuExecutorError::PreparationExpired { source })
}

#[cfg(test)]
#[path = "failure/tests.rs"]
mod tests;
