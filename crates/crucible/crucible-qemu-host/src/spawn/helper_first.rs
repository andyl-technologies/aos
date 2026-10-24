//! Retains a helper's concrete first error under its own prepaid Main loan.
//!
//! The journal receives the loan and allocates its shared body before helper
//! effects. Publishing the first error initializes that same body; diagnostics
//! cannot outlive its allocation funding. Error-owned heap payloads require
//! separate admission and are not covered by this fixed control extent.

use std::error::Error;
use std::fmt;
use std::sync::OnceLock;

use crucible_engine::SharedOperationalCause;
use crucible_host_resources::host_services::process_birth::SourceHostControlLease;

use super::QemuSpawnError;

#[derive(Debug)]
struct HelperCause<Funding> {
    source: OnceLock<QemuSpawnError>,
    _funding: Funding,
}

impl<Funding> fmt::Display for HelperCause<Funding> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.source.get() {
            Some(source) => source.fmt(formatter),
            None => formatter.write_str("helper failure is not recorded"),
        }
    }
}

impl<Funding: fmt::Debug> Error for HelperCause<Funding> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.get().map(|source| source as _)
    }
}

/// Owns the sole unpublished helper diagnostic before any helper effect.
///
/// Recording consumes this owner. No observer can clone its shared allocation
/// until the concrete first error has been installed in the private body.
pub(crate) struct HelperFirstJournal<
    Funding: fmt::Debug + Send + Sync + 'static = SourceHostControlLease,
> {
    first: SharedOperationalCause<HelperCause<Funding>>,
}

impl<Funding: fmt::Debug + Send + Sync + 'static> HelperFirstJournal<Funding> {
    pub(crate) fn new(funding: Funding) -> Self {
        Self {
            first: SharedOperationalCause::new(HelperCause {
                source: OnceLock::new(),
                _funding: funding,
            }),
        }
    }

    fn record_body(self, source: QemuSpawnError) -> SharedOperationalCause<HelperCause<Funding>> {
        // The linear journal is the only initializer, and no observer exists
        // until this consuming method publishes the completed first error.
        if self.first.source_ref().source.set(source).is_err() {
            unreachable!("a linear unpublished helper journal is recorded once");
        }
        self.first
    }
}

impl HelperFirstJournal {
    pub(crate) fn record(self, source: QemuSpawnError) -> QemuIssuedHelperFailure {
        QemuIssuedHelperFailure {
            first: self.record_body(source),
        }
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
    /// Borrows the same concrete first error without detaching its funding.
    #[must_use]
    pub fn source_ref(&self) -> &QemuSpawnError {
        match self.first.source_ref().source.get() {
            Some(source) => source,
            None => unreachable!("only a recorded helper journal can be published"),
        }
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
