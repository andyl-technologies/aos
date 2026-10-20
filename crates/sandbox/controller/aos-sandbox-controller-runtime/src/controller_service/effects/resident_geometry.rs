//! Compiled fixed destination geometry at the existing startup precharge.
//!
//! These passive widths create no allocation, payer, Source or admission. The
//! actual RuntimeFixed or issue-only original must admit their complete sum
//! before any constructor below can allocate its fixed subslots.

use std::alloc::Layout;
use std::mem::size_of;

// The pointee can coexist with a returned constructor value and its callee's
// staging. Keep all three planes without depending on placement optimization.
// Box handles are already in their parent; these two are constructor carriers.
pub(in crate::controller_service) fn boxed_bytes<T>() -> Option<usize> {
    size_of::<T>().checked_mul(3)?
        .checked_add(size_of::<Box<T>>().checked_mul(2)?)?
        .checked_add(size_of::<Layout>())
}

pub(in crate::controller_service) fn sum_bytes<const N: usize>(
    values: [Option<usize>; N],
) -> Option<usize> {
    values.into_iter().try_fold(0_usize, |total, next| total.checked_add(next?))
}
