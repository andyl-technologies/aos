//! Linear custody for a first RAM read failure and a distinct provider cleanup.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::content_store::StoreError;
use crate::owned_decode::DecodeScratch;

use super::{RamFailureCause, RamStoreError};

#[derive(Clone)]
pub(super) enum FirstReadCause {
    Boundary(RamFailureCause<RamStoreError>),
    Validation(RamFailureCause<Infallible>),
    ValidationWithProvider(RamReadValidation),
}

impl FirstReadCause {
    pub(super) fn error(&self) -> StoreError {
        match self {
            Self::Boundary(source) => StoreError::RamReadBoundary {
                source: source.clone(),
            },
            Self::Validation(source) => StoreError::RamValidation {
                source: source.clone(),
            },
            Self::ValidationWithProvider(source) => StoreError::RamReadValidation {
                source: source.clone(),
            },
        }
    }

    pub(super) fn matches(&self, error: &StoreError) -> bool {
        match (self, error) {
            (Self::Boundary(first), StoreError::RamReadBoundary { source }) => first == source,
            (Self::Validation(first), StoreError::RamValidation { source }) => first == source,
            (Self::ValidationWithProvider(first), StoreError::RamReadValidation { source }) => {
                first == source
            }
            _ => false,
        }
    }

    fn failure(&self) -> &RamStoreError {
        match self {
            Self::Boundary(source) => source
                .first_boundary()
                .unwrap_or_else(|| source.storage_failure()),
            Self::Validation(source) => source.storage_failure(),
            Self::ValidationWithProvider(source) => source.first_validation(),
        }
    }

    fn boundary(&self) -> Option<&RamStoreError> {
        match self {
            Self::Boundary(source) => source.first_boundary(),
            Self::Validation(_) | Self::ValidationWithProvider(_) => None,
        }
    }
}

/// Shares an original validation failure beside a complete provider outcome.
///
/// Validation remains distinct from an adapter-evidenced boundary refusal.
/// The private carrier uses the operation's existing larger prepayment after
/// provider cleanup has produced its complete result. Clones share that same
/// allocation and its original final-owner custody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RamReadValidation {
    cause: RamFailureCause<RamStoreError>,
}

impl RamReadValidation {
    pub(super) fn new(cause: RamFailureCause<RamStoreError>) -> Self {
        Self { cause }
    }

    /// Borrows the first validation error without treating it as cancellation.
    #[must_use]
    pub fn first_validation(&self) -> &RamStoreError {
        match self.cause.first_error() {
            Some(first) => first,
            None => unreachable!("a validation provider carrier retains its first error"),
        }
    }

    /// Borrows the complete provider failure, including its cleanup outcome.
    #[must_use]
    pub fn storage_failure(&self) -> &RamStoreError {
        self.cause.storage_failure()
    }
}

impl fmt::Display for RamReadValidation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; provider failure: {}",
            self.first_validation(),
            self.storage_failure()
        )
    }
}

impl Error for RamReadValidation {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.first_validation())
    }
}

struct ContinuationBody {
    first: FirstReadCause,
    returned: StoreError,
}

/// Retains a first RAM failure beside a distinct complete provider failure.
///
/// This owner is linear. Its body uses the operation's remaining prepayment;
/// neither creating it nor dropping it renews an expired operation. The first
/// cause remains separately shared with that operation and any earlier caller.
pub struct RamReadContinuation {
    body: Box<ContinuationBody>,
    // Box deallocation precedes the original credit, including payload unwind.
    _credit: DecodeScratch,
}

impl RamReadContinuation {
    pub(super) fn new(first: FirstReadCause, returned: StoreError, credit: DecodeScratch) -> Self {
        Self {
            body: Box::new(ContinuationBody { first, returned }),
            _credit: credit,
        }
    }

    /// Borrows the original RAM cause without discarding its error category.
    #[must_use]
    pub fn first_failure(&self) -> &RamStoreError {
        self.body.first.failure()
    }

    /// Borrows an adapter-evidenced boundary refusal when one was retained.
    #[must_use]
    pub fn first_boundary(&self) -> Option<&RamStoreError> {
        self.body.first.boundary()
    }

    /// Borrows the complete later provider error and its publication outcome.
    #[must_use]
    pub fn returned_failure(&self) -> &StoreError {
        &self.body.returned
    }
}

impl fmt::Debug for RamReadContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RamReadContinuation")
            .field("first", self.first_failure())
            .field("returned", self.returned_failure())
            .finish()
    }
}

impl fmt::Display for RamReadContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; provider cleanup or continuation failure: {}",
            self.first_failure(),
            self.returned_failure()
        )
    }
}

impl Error for RamReadContinuation {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.first_failure())
    }
}
