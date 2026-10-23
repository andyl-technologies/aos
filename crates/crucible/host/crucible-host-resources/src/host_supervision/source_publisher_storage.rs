//! Funds standing publisher storage through every strong and weak reference.
//!
//! Typed, standing and action observers share one allocation and its original
//! Source charge. No raw Arc or Weak escapes. Each pointer closes before its
//! funding observer, including after the publisher value has been destroyed.
//! This storage mechanism issues no Source, operation or publication authority.
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{Layout, LayoutError};
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Weak};

use super::{HostActionPublisher, HostSupervisionError, SourceSupervisionPublisher};
use crate::host_services::process_birth::SourceHostControlLease;

/// Retains a prepaid publisher allocation and its actual Source storage charge.
///
/// Every typed and erased observer carries the same charge after its pointer.
/// Cloning allocates nothing and grants no publication or operation authority.
pub struct FundedSourcePublisher<T: ?Sized> {
    value: Arc<T>,
    funding: PublicationFunding,
}

/// Retains publisher allocation storage without prolonging its concrete value.
///
/// A weak observer keeps the complete original allocation price, including the
/// value storage that Arc retains after the final strong observer closes.
pub struct WeakSourcePublisher<T: ?Sized> {
    value: Weak<T>,
    funding: PublicationFunding,
}

struct PublicationFunding {
    shared: Option<Arc<AllocationCharge>>,
}

enum AllocationCharge {
    Source {
        _lease: SourceHostControlLease,
    },
    #[cfg(test)]
    Component {
        _lease: crate::host_services::HostServiceLeasePair,
    },
}

impl<T> FundedSourcePublisher<T> {
    /// Allocates a publisher using its already reserved original storage charge.
    ///
    /// The caller must reserve at least [`Self::allocation_bytes`] before
    /// constructing the value. Physical controls and separately owned payloads
    /// require their own retained charges. This consumes no replacement budget.
    ///
    /// # Errors
    /// Refuses an overflowing allocation recipe or an undersized actual loan
    /// before allocating either shared control. A refused value closes while
    /// the original loan is still held.
    pub fn new(value: T, lease: SourceHostControlLease) -> Result<Self, HostSupervisionError> {
        let validation = Self::allocation_bytes()
            .map_err(|_| HostSupervisionError::InvalidBudget)
            .and_then(|bytes| {
                if lease.covers_metadata(bytes) {
                    Ok(())
                } else {
                    Err(HostSupervisionError::CapacityExhausted)
                }
            });
        Self::construct_after_validation(
            value,
            AllocationCharge::Source { _lease: lease },
            validation,
        )
    }

    /// Prices both shared allocations and the funding constructor's inline body.
    ///
    /// The publisher's own inline constructor and separately allocated payloads
    /// remain the caller's responsibility. The layout follows the pinned Arc
    /// implementation, including complete value storage and both counters.
    ///
    /// # Errors
    /// Returns an error when either aligned allocation or their sum overflows.
    pub fn allocation_bytes() -> Result<usize, LayoutError> {
        let header = Layout::new::<[AtomicUsize; 2]>();
        let (value, _) = header.extend(Layout::new::<T>())?;
        let (funding, _) = header.extend(Layout::new::<AllocationCharge>())?;
        let (both, _) = value.pad_to_align().extend(funding.pad_to_align())?;
        let (complete, _) = both.extend(Layout::new::<AllocationCharge>())?;
        Ok(complete.pad_to_align().size())
    }

    /// Keeps real mechanism charges for allocation-only component controls.
    /// No Source purpose, membership or operation admission is issued.
    #[cfg(test)]
    pub(super) fn component(value: T, lease: crate::host_services::HostServiceLeasePair) -> Self {
        Self::construct(value, AllocationCharge::Component { _lease: lease })
    }

    fn construct_after_validation(
        value: T,
        charge: AllocationCharge,
        validation: Result<(), HostSupervisionError>,
    ) -> Result<Self, HostSupervisionError> {
        if let Err(error) = validation {
            // Ordinary argument destruction would refund the later loan first.
            // A refusal must keep the same credit through actual value close.
            drop(value);
            drop(charge);
            return Err(error);
        }
        Ok(Self::construct(value, charge))
    }

    fn construct(value: T, charge: AllocationCharge) -> Self {
        // Charge exists before either allocation. Its closed owner frees its
        // own header before releasing the original Source loan.
        let funding = PublicationFunding {
            shared: Some(Arc::new(charge)),
        };
        Self {
            value: Arc::new(value),
            funding,
        }
    }

    /// Borrows the same allocation through its standing publication interface.
    pub fn standing(&self) -> FundedSourcePublisher<dyn SourceSupervisionPublisher>
    where
        T: SourceSupervisionPublisher + 'static,
    {
        FundedSourcePublisher {
            value: self.value.clone(),
            funding: self.funding.clone(),
        }
    }

    /// Borrows the same allocation through its action publication interface.
    pub fn action(&self) -> FundedSourcePublisher<dyn HostActionPublisher>
    where
        T: HostActionPublisher + 'static,
    {
        FundedSourcePublisher {
            value: self.value.clone(),
            funding: self.funding.clone(),
        }
    }
}

impl<T: ?Sized> FundedSourcePublisher<T> {
    /// Retains allocation storage while allowing the concrete value to close.
    #[must_use]
    pub fn downgrade(&self) -> WeakSourcePublisher<T> {
        WeakSourcePublisher {
            value: Arc::downgrade(&self.value),
            funding: self.funding.clone(),
        }
    }

    /// Compares actual shared allocations without authenticating their contents.
    #[must_use]
    pub fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.value, &other.value)
    }
}

impl<T: ?Sized> WeakSourcePublisher<T> {
    /// Borrows a still-live value while retaining the same allocation charge.
    ///
    /// This observes physical lifetime only. Callers must independently
    /// authenticate the actual Source and operation before using a publisher.
    #[must_use]
    pub fn upgrade(&self) -> Option<FundedSourcePublisher<T>> {
        self.value.upgrade().map(|value| FundedSourcePublisher {
            value,
            funding: self.funding.clone(),
        })
    }
}

impl<T: ?Sized> Clone for FundedSourcePublisher<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            funding: self.funding.clone(),
        }
    }
}

impl<T: ?Sized> Clone for WeakSourcePublisher<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            funding: self.funding.clone(),
        }
    }
}

impl<T: ?Sized> Deref for FundedSourcePublisher<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: fmt::Debug + ?Sized> fmt::Debug for FundedSourcePublisher<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FundedSourcePublisher")
            .field(&self.value)
            .finish()
    }
}

impl<T: ?Sized> fmt::Debug for WeakSourcePublisher<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WeakSourcePublisher")
            .finish_non_exhaustive()
    }
}

impl Clone for PublicationFunding {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for PublicationFunding {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            // All strong observers use extraction and no funding Weak exists.
            drop(Arc::into_inner(shared));
        }
    }
}

#[cfg(test)]
mod tests;
