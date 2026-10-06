//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Accounts shared live metadata and transient work against an admitted ceiling.

use crate::RamError;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// A shared resource ceiling for persistent nodes, snapshots, and dirty ledgers.
///
/// Clones share one counter. Shared immutable allocations are charged once until
/// their final reference drops; private fork state and temporary work are charged
/// separately. The byte count includes conservative container overhead, not host
/// page residency or a promise that the operating system can satisfy allocation.
#[derive(Clone, Debug)]
pub struct MetadataBudget {
    inner: Arc<BudgetInner>,
}

#[derive(Debug)]
struct BudgetInner {
    limit: u64,
    used: AtomicU64,
}

impl MetadataBudget {
    /// Establishes an admitted metadata byte ceiling, including zero if desired.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                limit: max_bytes,
                used: AtomicU64::new(0),
            }),
        }
    }

    /// Returns the immutable admitted byte ceiling.
    pub fn limit_bytes(&self) -> u64 {
        self.inner.limit
    }

    /// Returns currently charged live allocations and reservations.
    pub fn used_bytes(&self) -> u64 {
        self.inner.used.load(Ordering::Acquire)
    }

    /// Reserves bounded metadata owned by an integrating observer or codec.
    ///
    /// The returned guard releases its charge on drop. Callers reserve before
    /// allocating and retain the guard as long as the corresponding memory is
    /// live. This establishes accounting, not storage or execution authority.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::ResourceLimit`] when the shared ceiling would be
    /// exceeded, or [`RamError::Overflow`] if the byte count cannot be composed.
    pub fn reserve_bytes(&self, bytes: u64) -> Result<MetadataReservation, RamError> {
        let mut used = self.inner.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(bytes).ok_or(RamError::Overflow)?;
            if next > self.inner.limit {
                return Err(RamError::ResourceLimit);
            }
            match self.inner.used.compare_exchange_weak(
                used,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(MetadataReservation {
                        budget: self.clone(),
                        bytes,
                    });
                }
                Err(observed) => used = observed,
            }
        }
    }

    pub(crate) fn reserve(&self, bytes: u64) -> Result<Reservation, RamError> {
        self.reserve_bytes(bytes)
    }
}

/// An owned metadata charge released when its final owner drops the guard.
#[derive(Debug)]
pub struct MetadataReservation {
    budget: MetadataBudget,
    bytes: u64,
}

pub(crate) type Reservation = MetadataReservation;

impl MetadataReservation {
    /// Returns the live byte charge retained by this ownership guard.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn grow(&mut self, bytes: u64) -> Result<(), RamError> {
        let next = self.bytes.checked_add(bytes).ok_or(RamError::Overflow)?;
        let mut additional = self.budget.reserve(bytes)?;
        additional.bytes = 0;
        self.bytes = next;
        Ok(())
    }
}

impl Drop for MetadataReservation {
    fn drop(&mut self) {
        self.budget
            .inner
            .used
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
