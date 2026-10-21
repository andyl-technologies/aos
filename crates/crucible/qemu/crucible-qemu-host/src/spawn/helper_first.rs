//! Retains a helper's concrete first error under its own prepaid Main loan.
//!
//! The journal receives the loan before helper effects. Publishing the first
//! error moves that loan into its closed shared body; independent diagnostics
//! cannot outlive its allocation funding. Error-owned heap payloads require
//! separate admission and are not covered by this fixed control extent.

use std::error::Error;
use std::fmt;

use crucible_engine::SharedOperationalCause;
use crucible_host_resources::host_services::process_birth::SourceHostControlLease;

use super::QemuSpawnError;

#[derive(Debug)]
struct HelperCause<Funding> {
    source: QemuSpawnError,
    _funding: Funding,
}

impl<Funding> fmt::Display for HelperCause<Funding> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl<Funding: fmt::Debug> Error for HelperCause<Funding> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Shares a helper's actual first error and its independent Main control loan.
///
/// The final observer frees the shared control before destroying its concrete
/// error and returning the original loan. Cloning grants no helper effect,
/// Source identity, physical-return receipt or continuation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuIssuedHelperFailure {
    first: SharedOperationalCause<HelperCause<SourceHostControlLease>>,
}

impl QemuIssuedHelperFailure {
    pub(crate) fn new(source: QemuSpawnError, funding: SourceHostControlLease) -> Self {
        Self {
            first: SharedOperationalCause::new(HelperCause {
                source,
                _funding: funding,
            }),
        }
    }

    /// Borrows the same concrete first error without detaching its funding.
    #[must_use]
    pub fn source_ref(&self) -> &QemuSpawnError {
        &self.first.source_ref().source
    }
}

impl fmt::Display for QemuIssuedHelperFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source_ref().fmt(formatter)
    }
}

impl Error for QemuIssuedHelperFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source_ref())
    }
}

/// Includes the shared allocation and its final extracted destruction frame.
pub(crate) fn control_peak_bytes() -> Option<u64> {
    SharedOperationalCause::<HelperCause<SourceHostControlLease>>::allocation_bytes()
        .ok()?
        .checked_add(std::mem::size_of::<HelperCause<SourceHostControlLease>>())
        .and_then(|bytes| u64::try_from(bytes).ok())
}

#[cfg(test)]
mod tests;
