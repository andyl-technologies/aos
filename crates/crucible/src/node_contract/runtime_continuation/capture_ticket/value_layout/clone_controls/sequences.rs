//! Defines the closed installation sequence Clone constructor layouts.
//!
//! The caller separately visits real nontrivial child Clone implementations.
//! This supplies Vec/slice/RawVec construction and the actual partial-init
//! guard, or the pinned TrivialClone byte-copy branch for u8/FacetKind. Physical
//! backing, allocator implementation/abort and activation frames stay separate.

use super::*;

/// Names fixed data/result/layout controls before a sequence query.
pub(super) fn counter_scratch_data() -> usize {
    super::initializers::counter_scratch_data()
        + size_of::<MapCloneControlStorageData>() // element write initializer row
        + size_of::<MapCloneControlStorageData>()
        + size_of::<Result<MapCloneControlStorageData, RuntimeError>>()
        + size_of::<[FieldBound; 5]>() // inner/raw/result/allocation-result/drop-guard
        + size_of::<[FieldBound; 3]>() // actual field descriptor argument arrays
        + size_of::<[usize; 6]>() // length/maximum and computed T/S/total/input bytes
        + size_of::<[usize; 2]>() // previous/next checked sum
        + size_of::<bool>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>()
}

fn buffer_view_data<T: 'static>() -> Result<usize, RuntimeError> {
    // vec/mod.rs2058 (as_mut_ptr),3262 (spare_capacity_mut), and Vec's
    // Deref/as_slice path traverse the concrete RawVec/RawVecInner/Unique
    // pointer fields. These helper receivers/returns coexist down the call
    // chain; their final slice/pointer consumer is separately named below.
    Ok(checked_sum!(
        size_of::<&Vec<T>>(),                         // Vec::deref receiver
        size_of::<&Vec<T>>(),                         // Vec::as_slice receiver
        size_of::<&[T]>(),                            // as_slice return
        size_of::<&[T]>(),                            // deref return
        size_of::<&Vec<T>>(),                         // Vec::as_ptr receiver
        size_of::<&()>(),                             // RawVec pointer getter receiver geometry
        size_of::<&()>(),                             // RawVecInner pointer getter receiver
        size_of::<&()>(),                             // Unique::as_ptr receiver
        size_of::<*const T>(),                        // immutable pointer getter return
        size_of::<&mut Vec<T>>(),                     // Vec::spare_capacity_mut receiver
        size_of::<&()>(),                             // spare-capacity RawVec ptr receiver
        size_of::<&()>(),                             // nested RawVecInner pointer receiver
        size_of::<&()>(),                             // nested Unique pointer receiver
        size_of::<*mut T>(),                          // pointer getter return
        size_of::<*mut T>(),                          // pointer.add(len) return
        size_of::<usize>(),                           // len field argument
        size_of::<usize>(),                           // capacity() result
        size_of::<usize>(),                           // capacity-len result
        size_of::<&()>(),                             // RawVec::capacity receiver
        size_of::<&()>(),                             // RawVecInner::capacity receiver
        size_of::<usize>(),                           // Cap::as_inner return
        size_of::<&mut [std::mem::MaybeUninit<T>]>(), // from_raw_parts_mut return
        size_of::<&mut Vec<T>>(),                     // Vec::set_len receiver
        size_of::<usize>(),                           // set_len owned length argument
        size_of::<bool>()                             // ZST/length validity conditions
    ))
}

/// Bounds actual sequence constructors for the closed caller's child family.
///
/// The caller prices nontrivial child Clone methods independently.
///
/// # Errors
/// Refuses incompatible pinned geometry, checked overflow or row exhaustion.
pub(super) fn storage_data<T: 'static>(
    initialized_len: usize,
    trivial_elements: bool,
    maximum: usize,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    require_profile(
        Layout::new::<usize>(),
        Layout::new::<NonNull<u8>>(),
        Layout::new::<BTreeMap<String, serde_json::Value>>(),
    )?;
    // raw_vec/mod.rs73-91: Global is fieldless; Unique is repr(transparent)
    // over NonNull plus a ZST marker (core/ptr/unique.rs36-43); Cap is the
    // pinned transparent usize niche newtype. No private Rust ABI is guessed.
    let inner = FieldBound::record(&[
        FieldBound::of::<NonNull<u8>>(),
        FieldBound::of::<usize>(),
        FieldBound::of::<()>(),
    ])?;
    let raw = FieldBound::record(&[inner, FieldBound::of::<std::marker::PhantomData<T>>()])?;
    let inner_result =
        FieldBound::two_variant(inner, FieldBound::of::<std::collections::TryReserveError>())?;
    let allocation_result =
        FieldBound::two_variant(FieldBound::of::<NonNull<[u8]>>(), FieldBound::of::<()>())?;
    // alloc/slice.rs411-414: private DropGuard has these exact two fields.
    let guard = FieldBound::record(&[FieldBound::of::<&mut Vec<T>>(), FieldBound::of::<usize>()])?;
    let write = super::initializers::maybe_uninit_write_data::<T>()?;
    let transient = checked_sum!(
        if trivial_elements {
            0
        } else {
            initialized_len
                .checked_mul(write.transient_return_bytes)
                .ok_or(RuntimeError::ResourceLimit)?
        },
        size_of::<Vec<T>>(), // Vec::clone return
        size_of::<Vec<T>>(), // slice::to_vec_in return
        size_of::<Vec<T>>(), // ConvertVec::to_vec return
        size_of::<Vec<T>>(), // ConvertVec's actual vec/v local
        size_of::<Vec<T>>(), // Vec::with_capacity_in return
        raw.bytes,           // RawVec::with_capacity_in return
        inner.bytes,         // RawVecInner::with_capacity_in return
        inner_result.bytes,  // try_allocate_in return
        inner.bytes,         // with_capacity_in's Ok(this) pattern
        if initialized_len == 0 || size_of::<T>() == 0 {
            inner.bytes
        } else {
            0
        }, // new_in zero-allocation return
        if trivial_elements {
            0
        } else {
            initialized_len
                .checked_mul(size_of::<T>())
                .ok_or(RuntimeError::ResourceLimit)? // MaybeUninit::write owns each real child Clone output
        }
    );
    let scratch = checked_sum!(
        counter_scratch_data(),
        buffer_view_data::<T>()?,
        if trivial_elements {
            0
        } else {
            write.declared_counter_scratch_bytes
        },
        size_of::<&Vec<T>>(), // Vec Clone receiver
        size_of::<&()>(),     // allocator's borrowed Global receiver
        size_of::<&[T]>(),    // Vec's dereferenced slice / to_vec_in input
        size_of::<&[T]>(),    // ConvertVec::to_vec input
        size_of::<usize>(),   // initialized length local/input
        size_of::<usize>(),   // Vec with_capacity_in capacity
        size_of::<usize>(),   // RawVec with_capacity_in capacity
        size_of::<usize>(),   // RawVecInner with_capacity_in capacity
        size_of::<usize>(),   // try_allocate_in capacity
        size_of::<usize>(),   // source AllocInit two-unit-variant tag bound
        size_of::<Layout>(),  // element Layout argument
        size_of::<Layout>(),  // layout_array returned layout/local
        size_of::<Result<Layout, std::collections::TryReserveError>>(), // layout_array return
        size_of::<Result<Layout, std::alloc::LayoutError>>(), // repeat_packed raw result
        size_of::<usize>(),   // capacity checked multiplication return/input
        size_of::<Option<usize>>(), // checked layout arithmetic
        allocation_result.bytes, // Allocator::allocate typed return
        size_of::<NonNull<[u8]>>(), // allocation Ok ptr local
        size_of::<NonNull<u8>>(), // allocation cast/Unique input
        size_of::<NonNull<u8>>(), // returned Unique field geometry
        size_of::<usize>(),   // Cap::new_unchecked input/return
        size_of::<std::num::NonZeroUsize>(), // zero-branch Alignment input
        size_of::<NonNull<u8>>(), // zero-branch dangling pointer return
        size_of::<&mut Vec<T>>(), // raw pointer/set_len receiver
        size_of::<*mut T>(),  // Vec as_mut_ptr return
        size_of::<*const T>(), // slice as_ptr return
        size_of::<usize>(),   // copied length/set_len argument
        size_of::<()>(),      // pointer-copy/set_len results
        size_of::<bool>(),    // empty/ZST and branch predicates
        if trivial_elements {
            0
        } else {
            checked_sum!(
                guard.bytes,                                                     // DropGuard initializer
                guard.bytes, // guard local retained across child clones
                guard.bytes, // mem::forget's owned guard input
                size_of::<&mut [std::mem::MaybeUninit<T>]>(), // spare_capacity_mut return
                size_of::<&mut [std::mem::MaybeUninit<T>]>(), // slots local
                size_of::<std::slice::Iter<'static, T>>(), // s.iter return
                size_of::<std::iter::Enumerate<std::slice::Iter<'static, T>>>(), // enumerate return
                size_of::<std::iter::Take<std::iter::Enumerate<std::slice::Iter<'static, T>>>>(), // take return / owned loop iterator
                size_of::<Option<(usize, &T)>>(), // Take::next returned item
                size_of::<&mut std::iter::Take<std::iter::Enumerate<std::slice::Iter<'static, T>>>>(
                ),
                size_of::<&mut std::iter::Enumerate<std::slice::Iter<'static, T>>>(),
                size_of::<&mut std::slice::Iter<'static, T>>(),
                size_of::<Option<(usize, &T)>>(), // Enumerate::next intermediate result
                size_of::<Option<&T>>(),          // Iter::next intermediate result
                size_of::<usize>(),               // enumerate's prior count
                size_of::<usize>(),               // enumerate's advanced count
                size_of::<(usize, &T)>(),         // i,b pattern values
                size_of::<usize>(),               // guard.num_init write input
                size_of::<&mut std::mem::MaybeUninit<T>>(), // slots[i] / write receiver
                size_of::<&mut T>()               // write return, discarded
            )
        }
    );
    if transient
        .checked_add(scratch)
        .ok_or(RuntimeError::ResourceLimit)?
        > maximum
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(MapCloneControlStorageData {
        transient_return_bytes: transient,
        declared_counter_scratch_bytes: scratch,
    })
}
