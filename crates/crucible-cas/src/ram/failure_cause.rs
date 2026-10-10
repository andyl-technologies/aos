//! Prepaid typed RAM failures with shared final-owner resource custody.
//!
//! A carrier retains the first boundary refusal and the complete storage error.
//! Its private shared body never exposes an `Arc` or a weak reference. Every
//! clone consumes its strong reference with `Arc::into_inner`, so the last
//! owner moves the body out before the shared allocation closes and only then
//! releases its original memory credit.

use std::alloc::Layout;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeScratch};

use super::RamStoreError;

/// Reports refusal to prepay a retained RAM failure before storage effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RamFailureAdmission {
    /// The original caller account refused the exact carrier extent.
    Original(DecodeAdmissionError),
    /// The concrete shared carrier layout could not be represented.
    Layout,
}

impl fmt::Display for RamFailureAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Original(source) => source.fmt(formatter),
            Self::Layout => formatter.write_str("RAM failure carrier layout is not representable"),
        }
    }
}

impl Error for RamFailureAdmission {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Original(source) => Some(source),
            Self::Layout => None,
        }
    }
}

struct FailureBody<E> {
    first: Option<E>,
    storage: RamStoreError,
    _credit: DecodeScratch,
}

/// Prepays one exact typed RAM failure body from the borrowed caller account.
///
/// Preparation precedes storage effects and callback invocation. Successful
/// operations drop this linear reservation without allocating a shared body.
#[must_use]
pub struct PreparedRamFailure<E> {
    credit: DecodeScratch,
    marker: PhantomData<fn() -> E>,
}

impl<E> PreparedRamFailure<E> {
    /// Transfers an unused prepayment without allocating a carrier or renewing it.
    pub(super) fn into_credit(self) -> DecodeScratch {
        self.credit
    }

    /// Returns the exact pinned shared allocation extent for this boundary type.
    ///
    /// # Errors
    /// Returns [`RamFailureAdmission::Layout`] if header, body, alignment, or
    /// the resulting byte count cannot be represented.
    pub fn allocation_bytes() -> Result<u64, RamFailureAdmission> {
        let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
            .extend(Layout::new::<FailureBody<E>>())
            .map_err(|_| RamFailureAdmission::Layout)?;
        u64::try_from(layout.pad_to_align().size()).map_err(|_| RamFailureAdmission::Layout)
    }

    /// Admits the complete shared body before effects under original custody.
    ///
    /// # Errors
    /// Returns an earlier account failure, original authority refusal, exhausted
    /// original allowance, or an unrepresentable concrete carrier extent.
    pub fn new(original: &DecodeBudget) -> Result<Self, RamFailureAdmission> {
        original
            .verify_live()
            .map_err(RamFailureAdmission::Original)?;
        let credit = original
            .reserve_scratch_bytes(Self::allocation_bytes()?)
            .map_err(RamFailureAdmission::Original)?;
        Ok(Self {
            credit,
            marker: PhantomData,
        })
    }

    /// Runs one RAM operation while retaining only its first boundary refusal.
    ///
    /// Later requested polls return the same allocation-free canceled marker
    /// without invoking the refused callback again. A direct canceled marker
    /// returns the first error inline; any storage or cleanup wrapper retains
    /// both original failures in this already paid shared carrier.
    ///
    /// # Errors
    /// Refuses the same original account before callbacks or storage effects,
    /// then returns the first boundary refusal or complete retained storage
    /// error. An original preflight refusal precedes callback invocation.
    /// Unexpected success after a boundary refusal is refused; its returned
    /// owner closes before this reservation is released.
    pub fn run<T>(
        self,
        boundary: &mut dyn FnMut() -> Result<(), E>,
        operation: impl FnOnce(
            &mut dyn FnMut() -> Result<(), RamStoreError>,
        ) -> Result<T, RamStoreError>,
    ) -> Result<T, RamOperationFailure<E>> {
        self.credit
            .original_account()
            .verify_live()
            .map_err(RamOperationFailure::Admission)?;

        let mut first = None;
        let result = operation(&mut || {
            if first.is_some() {
                return Err(RamStoreError::Canceled);
            }
            match boundary() {
                Ok(()) => Ok(()),
                Err(error) => {
                    first = Some(error);
                    Err(RamStoreError::Canceled)
                }
            }
        });

        match (first, result) {
            (None, Ok(value)) => Ok(value),
            (Some(first), Ok(value)) => {
                drop(value);
                Err(RamOperationFailure::Boundary(first))
            }
            (Some(first), Err(RamStoreError::Canceled)) => {
                Err(RamOperationFailure::Boundary(first))
            }
            (first, Err(storage)) => {
                Err(RamOperationFailure::Retained(self.retain(first, storage)))
            }
        }
    }

    /// Moves the complete original failures into their already paid shared body.
    ///
    /// Retention does not acquire more credit or recheck liveness. The original
    /// prepayment remains available for an already-produced failure after
    /// cancellation, so cleanup causes cannot be discarded by a later refusal.
    pub fn retain(self, first: Option<E>, storage: RamStoreError) -> RamFailureCause<E> {
        RamFailureCause {
            shared: Some(Arc::new(FailureBody {
                first,
                storage,
                _credit: self.credit,
            })),
        }
    }
}

/// Shares a first boundary refusal and complete RAM failure without deep copies.
///
/// Equality identifies the same retained failure allocation. It has no modeled
/// guest meaning. Cloning neither copies native error buffers nor acquires new
/// resource credit; the final clone releases the complete original custody.
pub struct RamFailureCause<E> {
    shared: Option<Arc<FailureBody<E>>>,
}

impl<E> RamFailureCause<E> {
    /// Borrows the privately tagged first cause without imposing its category.
    pub(super) fn first_error(&self) -> Option<&E> {
        self.body().first.as_ref()
    }

    fn body(&self) -> &FailureBody<E> {
        // A live wrapper always owns its body. Only Drop takes the reference,
        // and neither the taken wrapper nor its private Arc can escape.
        match &self.shared {
            Some(body) => body,
            None => unreachable!("a live RAM failure owns its shared body"),
        }
    }

    /// Borrows the first callback refusal without copying its original custody.
    #[must_use]
    pub fn first_boundary(&self) -> Option<&E> {
        self.body().first.as_ref()
    }

    /// Borrows the complete RAM error, including SQL outcome and cleanup causes.
    #[must_use]
    pub fn storage_failure(&self) -> &RamStoreError {
        &self.body().storage
    }
}

impl<E> Clone for RamFailureCause<E> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<E> Drop for RamFailureCause<E> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            // Ordinary Arc::drop would release the body's credit before its
            // control allocation. Every owner uses into_inner; exactly one
            // extracts the body, after the private implicit Weak has closed.
            drop(Arc::into_inner(shared));
        }
    }
}

impl<E> PartialEq for RamFailureCause<E> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.shared, &other.shared) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl<E> Eq for RamFailureCause<E> {}

impl<E: fmt::Debug> fmt::Debug for RamFailureCause<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RamFailureCause")
            .field("first", &self.body().first)
            .field("storage", &self.body().storage)
            .finish()
    }
}

impl<E: fmt::Display> fmt::Display for RamFailureCause<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(first) = self.first_boundary() {
            write!(formatter, "{first}; RAM cleanup or storage failure: ")?;
        }
        self.storage_failure().fmt(formatter)
    }
}

impl<E: Error + 'static> Error for RamFailureCause<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.first_boundary() {
            Some(first) => Some(first),
            None => Some(self.storage_failure()),
        }
    }
}

/// Preserves a RAM operation's original first refusal and complete storage owner.
#[derive(Debug)]
pub enum RamOperationFailure<E> {
    /// The same original account refused before callbacks or storage effects.
    Admission(DecodeAdmissionError),
    /// The first boundary refusal accompanies only the direct canceled marker.
    Boundary(E),
    /// A storage or cleanup failure retains all original causes and custody.
    Retained(RamFailureCause<E>),
}
