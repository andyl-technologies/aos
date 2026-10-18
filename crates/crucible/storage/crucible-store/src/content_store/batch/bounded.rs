//! Fixed-capacity transaction metadata retaining its original allocation loan.

use super::{DecodeBudget, DecodeScratch, StoreError, admission_under, allocation_under};
use std::ops::{Deref, DerefMut};

/// Closes the actual vector before returning its original scratch credit.
pub(crate) struct PrepaidBatchVec<T> {
    values: Vec<T>,
    _credit: DecodeScratch,
}

impl<T> PrepaidBatchVec<T> {
    /// Admits fixed control and element storage before allocating either body.
    ///
    /// # Errors
    /// Refuses overflow, original exhaustion, allocation failure or capacity
    /// beyond the admitted extent. Callers never grow beyond this capacity.
    pub(crate) fn with_capacity(original: &DecodeBudget, count: usize) -> Result<Self, StoreError> {
        let bytes = std::mem::size_of::<T>()
            .checked_mul(count)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(StoreError::Quota)?;
        let credit = original
            .reserve_scratch_bytes(u64::try_from(bytes).map_err(|_| StoreError::Quota)?)
            .map_err(|error| admission_under(original, error))?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|error| allocation_under(original, error))?;
        if values.capacity() > count {
            return Err(StoreError::Quota);
        }
        Ok(Self {
            values,
            _credit: credit,
        })
    }
}

impl<T> Deref for PrepaidBatchVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> DerefMut for PrepaidBatchVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}
