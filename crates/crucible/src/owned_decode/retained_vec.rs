//! Geometric Vec growth with replaceable loans for each physical allocation.
//!
//! The old allocation stays charged through reserve. A successful reserve closes
//! that allocation before replacing its credit; failed later work can therefore
//! retain a grown buffer without retaining all historical buffers as well.

use super::{DecodeAdmissionError, DecodeCustody, require_current_child_budget};

/// Reserves an owned Vec's capacity under the same original authority.
///
/// The caller stores `custody` after the Vec in its owning container. Existing
/// element allocations have their own retained receipts; this accounts only the
/// Vec's element table and its new account's actual bookkeeping.
///
/// # Errors
/// Refuses missing authority, size overflow, original resource exhaustion or
/// allocation failure before publishing a replacement loan.
pub fn grow_retained_vec<T>(
    values: &mut Vec<T>,
    additional: usize,
    custody: &mut DecodeCustody,
) -> Result<(), DecodeAdmissionError> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| DecodeAdmissionError::new(std::fmt::Error))?;
    if required <= values.capacity() {
        return Ok(());
    }
    let capacity = values
        .capacity()
        .checked_mul(2)
        .unwrap_or(required)
        .max(required)
        .max(4);
    let bank = require_current_child_budget()?;
    bank.charge_array::<T>(capacity)?;
    values
        .try_reserve_exact(capacity - values.len())
        .map_err(DecodeAdmissionError::new)?;
    *custody = bank.custody();
    Ok(())
}
