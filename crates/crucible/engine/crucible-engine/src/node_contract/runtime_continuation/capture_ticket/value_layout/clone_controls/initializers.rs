//! Names the actual transparent move-initializer constructor windows.
//!
//! MaybeUninit::write calls MaybeUninit::new, ManuallyDrop::new and the pinned
//! transparent MaybeDangling::new. The private latter field/return has exactly
//! its T field's layout by repr(transparent), not by a guessed Rust ABI.

use super::*;

/// Names the actual transparent ManuallyDrop constructor moves.
///
/// # Errors
/// Refuses checked layout arithmetic overflow.
pub(super) fn manually_drop_data<T>() -> Result<MapCloneControlStorageData, RuntimeError> {
    Ok(MapCloneControlStorageData {
        transient_return_bytes: checked_sum!(
            size_of::<T>(),               // ManuallyDrop::new owned value argument
            size_of::<T>(),               // MaybeDangling::new owned value argument
            size_of::<T>(),               // transparent MaybeDangling return
            size_of::<ManuallyDrop<T>>()  // ManuallyDrop::new return
        ),
        declared_counter_scratch_bytes: 0,
    })
}

/// Names nested write initialization moves and its mutable view windows.
///
/// The outer write owned argument remains the defining caller's term.
///
/// # Errors
/// Refuses checked layout arithmetic overflow.
pub(super) fn maybe_uninit_write_data<T>() -> Result<MapCloneControlStorageData, RuntimeError> {
    let inner = manually_drop_data::<T>()?;
    // The outer MaybeUninit::write owned T argument belongs to its caller's
    // existing owning-input row. These are the nested constructor moves.
    Ok(MapCloneControlStorageData {
        transient_return_bytes: checked_sum!(
            size_of::<T>(), // MaybeUninit::new owned val argument
            inner.transient_return_bytes,
            size_of::<std::mem::MaybeUninit<T>>() // MaybeUninit::new return
        ),
        declared_counter_scratch_bytes: checked_sum!(
            size_of::<&mut std::mem::MaybeUninit<T>>(), // write receiver
            size_of::<&mut std::mem::MaybeUninit<T>>(), // assume_init_mut receiver
            size_of::<&mut std::mem::MaybeUninit<T>>(), // nested as_mut_ptr receiver
            size_of::<*mut T>(),                        // as_mut_ptr return
            size_of::<&mut T>(),                        // assume_init_mut return
            size_of::<&mut T>()                         // write return, discarded by the clone loop
        ),
    })
}

/// Names actual initializer query inputs, intermediate and returned rows.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<MapCloneControlStorageData>() // retained inner constructor row
        + size_of::<MapCloneControlStorageData>() // returned initializer row
        + size_of::<Result<MapCloneControlStorageData,RuntimeError>>()
        + size_of::<[usize;2]>() // checked_sum previous/next
}
