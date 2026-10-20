//! Names actual typed sequence call operands, returns and scalar teardown.

use super::{dispatch, layout};
use std::alloc::{Layout, LayoutError};
use std::collections::TryReserveError;
use std::mem::{ManuallyDrop, align_of, size_of};
use std::ptr::NonNull;
use std::vec::IntoIter;

pub(super) fn new_reserve_transient<T>() -> usize {
    size_of::<Vec<T>>() // Vec::new return
        + size_of::<Vec<T>>() // empty parent-field initializer
        + layout::RAW.0 // RawVec::new return
        + layout::RAW.0 // RawVec::new_in return
        + layout::INNER.0 // RawVecInner::new_in return
        + layout::INNER.0 // RawVecInner initializer
        + size_of::<Result<(), TryReserveError>>() // Vec try_reserve_exact return
        + size_of::<Result<(), TryReserveError>>() // RawVec try_reserve_exact return
        + size_of::<Result<(), TryReserveError>>() // inner try_reserve_exact return
        + size_of::<Result<(), TryReserveError>>() // grow_exact return
        + size_of::<Result<NonNull<[u8]>, TryReserveError>>() // finish_grow return
}

fn reserve_controls<T>() -> usize {
    size_of::<&mut Vec<T>>() // Vec::try_reserve_exact receiver
        + size_of::<usize>() // additional argument
        + size_of::<&mut ()>() // RawVec receiver geometry
        + size_of::<usize>() // RawVec len input
        + size_of::<usize>() // RawVec additional input
        + size_of::<&mut ()>() // RawVecInner receiver geometry
        + size_of::<usize>() // inner len input
        + size_of::<usize>() // inner additional input
        + size_of::<Layout>() // inner element layout
        + size_of::<&()>() // needs_to_grow receiver
        + size_of::<usize>() // needs_to_grow len
        + size_of::<usize>() // needs_to_grow additional
        + size_of::<Layout>() // needs_to_grow element layout
        + size_of::<bool>() // needs_to_grow result
        + size_of::<&()>() // capacity receiver
        + size_of::<usize>() // element size/capacity result
        + size_of::<usize>() // wrapping_sub result
        + size_of::<&()>() // post-reserve needs_to_grow receiver
        + size_of::<usize>() * 3 // post-reserve len/additional/capacity
        + size_of::<Layout>() // post-reserve element layout
        + size_of::<bool>() // post-reserve predicate
        + size_of::<Result<(), TryReserveError>>() * 4
}

pub(super) fn new_reserve_scratch<T>() -> usize {
    reserve_controls::<T>()
        + dispatch::reserve_try_scratch()
        + dispatch::allocation_scratch()
        + size_of::<usize>() // Vec::new len initializer
        + size_of::<()>() // fieldless Global argument
        + size_of::<std::num::NonZeroUsize>() // new_in Alignment input
        + size_of::<NonNull<u8>>() // without_provenance return
        + size_of::<NonNull<u8>>() // Unique initializer geometry
        + size_of::<usize>() // ZERO_CAP field geometry
        + size_of::<&mut ()>() // grow_exact receiver
        + size_of::<usize>() // grow_exact len
        + size_of::<usize>() // grow_exact additional
        + size_of::<Layout>() // grow_exact element layout
        + size_of::<Option<usize>>() // checked_add result
        + size_of::<usize>() // new cap local
        + layout::RESERVE_KIND.0 // capacity-overflow error kind
        + layout::CAPACITY_RESULT.0 // checked capacity Result<usize, Kind>
        + size_of::<TryReserveError>() // converted reserve error
        + size_of::<&()>() // finish_grow receiver
        + size_of::<usize>() // finish_grow cap
        + size_of::<Layout>() // finish_grow element layout
        + size_of::<Layout>() // new_layout local
        + size_of::<Result<Layout, TryReserveError>>() // layout_array result
        + size_of::<Result<Layout, LayoutError>>() // repeat_packed result
        + size_of::<LayoutError>() // map_err closure argument
        + size_of::<Option<usize>>() // checked layout arithmetic
        + size_of::<usize>() // checked layout byte size
        + size_of::<Option<(NonNull<u8>, Layout)>>() // current_memory result
        + size_of::<&()>() // current_memory receiver
        + size_of::<Layout>() // current_memory element layout
        + size_of::<usize>() // old zero capacity
        + size_of::<bool>() // unallocated test; grow branch is not reached
        + size_of::<&()>() // actual Global::allocate receiver
        + size_of::<Layout>() // new allocation layout
        + layout::ALLOCATION_RESULT.0 // memory result
        + size_of::<NonNull<[u8]>>() // allocation Ok memory
        + layout::RESERVE_KIND.0 // allocation-error kind initializer
        + size_of::<TryReserveError>() // allocation-error return
        + size_of::<Result<NonNull<[u8]>, TryReserveError>>()
        + size_of::<NonNull<[u8]>>() // grow_exact ptr local
        + size_of::<&mut ()>() // set_ptr_and_cap receiver
        + size_of::<NonNull<[u8]>>() // set_ptr_and_cap ptr input
        + size_of::<usize>() // set_ptr_and_cap cap input
        + size_of::<NonNull<u8>>() // ptr.cast return
        + size_of::<NonNull<u8>>() // Unique::from input/return geometry
        + size_of::<usize>() // Cap::new_unchecked input
        + size_of::<()>() // set_ptr_and_cap return
        + vec_shell_drop_scratch::<T>()
}

fn mutable_pointer_controls<T>() -> usize {
    size_of::<&mut Vec<T>>() // as_mut_ptr receiver
        + size_of::<&()>() // RawVec pointer getter
        + size_of::<&()>() // RawVecInner pointer getter
        + size_of::<&()>() // Unique pointer getter
        + size_of::<*mut T>() // returned pointer
}

pub(super) fn push_transient<T>() -> usize {
    size_of::<T>() // Vec::push owned input
        + size_of::<T>() // push_mut owned input
        + size_of::<T>() // ptr::write owned input
        + size_of::<T>() // write_via_move intrinsic owned input
        + size_of::<&mut T>() // push_mut returned/discarded reference
}

pub(super) fn push_scratch<T>() -> usize {
    size_of::<&mut Vec<T>>() // push receiver
        + size_of::<&mut Vec<T>>() // push_mut receiver
        + size_of::<usize>() // saved len
        + size_of::<usize>() // capacity result
        + size_of::<&()>() // RawVec::capacity receiver
        + size_of::<&()>() // RawVecInner::capacity receiver
        + size_of::<bool>() // capacity comparison; growth is excluded by caller
        + mutable_pointer_controls::<T>()
        + size_of::<*mut T>() // pointer.add(len)/end local
        + size_of::<*mut T>() // ptr::write destination
        + size_of::<usize>() // pointer offset
        + size_of::<usize>() // advanced length
        + size_of::<&mut T>() // end-to-reference result
        + size_of::<()>() // ptr::write/push return
}

pub(super) fn pop_transient<T>() -> usize {
    size_of::<T>() // read_via_copy intrinsic output
        + size_of::<T>() // ptr::read output
        + size_of::<Option<T>>() // Some initializer
        + size_of::<Option<T>>() // Vec::pop return
}

pub(super) fn pop_scratch<T>() -> usize {
    size_of::<&mut Vec<T>>()
        + size_of::<bool>() // empty comparison
        + size_of::<usize>() * 3 // decremented len/capacity/offset
        + size_of::<&Vec<T>>() // as_ptr receiver
        + size_of::<&()>() // RawVec pointer getter
        + size_of::<&()>() // RawVecInner pointer getter
        + size_of::<&()>() // Unique pointer getter
        + size_of::<*const T>() // pointer return
        + size_of::<*const T>() // pointer.add result/read input
        + size_of::<&Vec<T>>() // capacity receiver
        + size_of::<&()>() // RawVec capacity receiver
        + size_of::<&()>() // RawVecInner capacity receiver
        + size_of::<bool>() // successful-pop capacity assertion
}

pub(super) fn string_transient() -> usize {
    size_of::<String>() // String::new return
        + size_of::<String>() // guarded Value/key initializer
        + size_of::<Result<(), TryReserveError>>() // String reserve return
        + size_of::<std::slice::Iter<'static, u8>>() // Iter::new initializer
        + size_of::<std::slice::Iter<'static, u8>>() // Iter::new return
        + size_of::<std::slice::Iter<'static, u8>>() // extend_from_slice iterator
        + size_of::<std::slice::Iter<'static, u8>>() // SpecExtend owned iterator
}

pub(super) fn string_scratch() -> usize {
    size_of::<&mut String>() // String reserve receiver
        + size_of::<usize>() // String reserve additional
        + size_of::<&mut String>() // String push_str receiver
        + size_of::<&str>() // same source bytes
        + size_of::<&str>() // as_bytes receiver
        + size_of::<&[u8]>() // as_bytes output
        + size_of::<&mut Vec<u8>>() // extend_from_slice receiver
        + size_of::<&[u8]>() // extend_from_slice input
        + size_of::<&[u8]>() // slice::iter receiver
        + size_of::<&mut Vec<u8>>() // SpecExtend receiver
        + size_of::<&std::slice::Iter<'static, u8>>() // Iter::as_slice receiver
        + size_of::<&[u8]>() // Iter::as_slice return/local
        + size_of::<&mut Vec<u8>>() // append_elements receiver
        + size_of::<*const [u8]>() // append_elements input
        + size_of::<usize>() // append_elements count
        + size_of::<usize>() // append_elements saved len
        + size_of::<&mut Vec<u8>>() // Vec::reserve receiver
        + size_of::<usize>() // reserve additional
        + size_of::<&mut ()>() // RawVec reserve receiver
        + size_of::<usize>() * 2 // reserve len/additional
        + size_of::<&mut ()>() // inner reserve receiver
        + size_of::<Layout>() // reserve element layout
        + size_of::<&()>() // needs_to_grow receiver
        + size_of::<usize>() * 3 // len/additional/capacity result
        + size_of::<Layout>() // needs_to_grow element layout
        + size_of::<bool>() // reserved capacity proves false
        + size_of::<*const u8>() // copy source cast
        + mutable_pointer_controls::<u8>()
        + size_of::<*mut u8>() // destination.add(len)
        + size_of::<usize>() // pointer-copy count
        + size_of::<usize>() // updated Vec len
        + size_of::<()>() // copy/extend/push_str returns
        + size_of::<&mut String>() // automatic String field-drop receiver;
    // the exact Vec<u8> field teardown is already in its reserve subrow.
}

// Only after the actual guard has drained deep children, or before any exist.
pub(super) fn vec_shell_drop_scratch<T>() -> usize {
    size_of::<&mut Vec<T>>() // Vec::drop receiver
        + mutable_pointer_controls::<T>()
        + size_of::<*mut [T]>() // zero-length drop_in_place slice
        + size_of::<usize>() // zero initialized length
        + size_of::<()>() // drop_in_place return
        + empty_deallocation_scratch::<T>()
}

fn empty_deallocation_scratch<T>() -> usize {
    size_of::<&mut ()>() // RawVec Drop receiver
        + size_of::<&mut ()>() // RawVecInner deallocate receiver
        + size_of::<Layout>() // actual T element layout
        + size_of::<&()>() // current_memory receiver
        + size_of::<Layout>() // current_memory element layout
        + size_of::<Option<(NonNull<u8>, Layout)>>()
        + size_of::<(NonNull<u8>, Layout)>()
        + size_of::<NonNull<u8>>() // resulting allocation pointer
        + size_of::<Layout>() // resulting allocation layout
        + size_of::<usize>() * 3 // cap/element extent/alloc_size
        + size_of::<std::num::NonZeroUsize>() // unchecked alignment
        + size_of::<bool>() // zero-capacity/zero-layout condition
        + size_of::<&()>() // Global deallocate receiver
        + size_of::<NonNull<u8>>() // deallocate pointer
        + size_of::<Layout>() // deallocate layout
        + size_of::<()>() // deallocation return
        + size_of::<std::marker::PhantomData<T>>() // actual zero-sized marker
        + dispatch::deallocation_scratch()
}

fn into_iter_guard_bound<T>() -> usize {
    size_of::<&mut IntoIter<T>>()
        + (align_of::<&mut IntoIter<T>>() - 1)
        + (align_of::<&mut IntoIter<T>>() - 1)
}

pub(super) fn into_iter_transient<T>() -> usize {
    size_of::<Vec<T>>() // IntoIterator owned input
        + dispatch::vec_manually_drop_new_transient::<T>()
        + size_of::<ManuallyDrop<Vec<T>>>() // actual me local
        + size_of::<IntoIter<T>>() // initializer
        + size_of::<IntoIter<T>>() // returned iterator
        + layout::RAW.0 // RawVec::from_nonnull_in return in dealloc_only
        + layout::RAW.0 // reconstructed RawVec initializer
        + layout::INNER.0 // RawVecInner::from_nonnull_in return
        + layout::INNER.0 // reconstructed RawVecInner initializer
        + into_iter_guard_bound::<T>() // private one-field DropGuard initializer
}

pub(super) fn into_iter_item_transient<T>() -> usize {
    size_of::<T>() // read_via_copy output
        + size_of::<T>() // ptr::read output
        + size_of::<T>() // NonNull::read output
        + size_of::<Option<T>>() // Some initializer
        + size_of::<Option<T>>() // IntoIter::next return
}

pub(super) fn into_iter_scratch<T>() -> usize {
    dispatch::vec_manually_drop_deref_scratch::<T>() // me.allocator()
        + dispatch::vec_manually_drop_deref_scratch::<T>() // me.buf.non_null()
        + dispatch::vec_manually_drop_deref_scratch::<T>() // me.len()
        + dispatch::vec_manually_drop_deref_scratch::<T>() // me.buf.capacity()
        + size_of::<&Vec<T>>() // Vec::allocator receiver
        + size_of::<&Vec<T>>() // Vec::len receiver
        + size_of::<&()>() // Global pointer-read source
        + size_of::<ManuallyDrop<()>>() // alloc local
        + size_of::<NonNull<T>>() // buf local
        + size_of::<*mut T>() // begin pointer
        + size_of::<*const T>() // end pointer
        + size_of::<usize>() * 3 // len/offset/cap local
        + size_of::<&()>() // RawVec non_null receiver
        + size_of::<&()>() // RawVecInner non_null receiver
        + size_of::<&()>() // Unique pointer receiver
        + size_of::<&mut IntoIter<T>>() // next receiver
        + size_of::<NonNull<T>>() // next ptr local
        + size_of::<NonNull<T>>() // old pointer local
        + size_of::<NonNull<T>>() // end non_null! comparator
        + size_of::<NonNull<T>>() // NonNull::read owned receiver
        + size_of::<NonNull<T>>() // advanced pointer
        + size_of::<bool>() // empty/ZST comparison
        + size_of::<*const T>() // end cast
        + size_of::<usize>() // increment offset
        + size_of::<&mut IntoIter<T>>() // IntoIter Drop receiver
        + into_iter_guard_bound::<T>() // DropGuard retained local
        + size_of::<&mut ()>() // private DropGuard::drop receiver geometry
        + size_of::<&mut IntoIter<T>>() // as_raw_mut_slice receiver
        + size_of::<*mut T>() // remaining pointer
        + size_of::<usize>() // remaining len
        + size_of::<*mut [T]>() // remaining slice/drop input (must be empty)
        + size_of::<&mut IntoIter<T>>() // dealloc_only receiver
        + size_of::<&mut ManuallyDrop<()>>() // allocator take receiver
        + size_of::<()>() // taken Global value
        + dispatch::global_manually_drop_scratch()
        + size_of::<NonNull<T>>() // from_nonnull_in argument
        + size_of::<usize>() // original capacity argument
        + size_of::<NonNull<u8>>() // inner pointer cast
        + size_of::<usize>() // Cap constructor input
        + empty_deallocation_scratch::<T>()
}

pub(super) fn access_scratch<T>() -> usize {
    size_of::<&Vec<T>>() // shared Deref/index receiver
        + size_of::<&Vec<T>>() // as_slice receiver
        + size_of::<&[T]>() // Deref/as_slice output
        + size_of::<&[T]>() // slice get/index receiver
        + size_of::<usize>() // usize index
        + size_of::<usize>() // slice length
        + size_of::<bool>() // index bound comparison
        + size_of::<&Vec<T>>() // shared as_ptr receiver
        + size_of::<&()>() // shared RawVec pointer getter
        + size_of::<&()>() // shared RawVecInner pointer getter
        + size_of::<&()>() // shared Unique pointer getter
        + size_of::<*const T>() // shared data pointer
        + size_of::<*const T>() // offset pointer
        + size_of::<&T>() // checked shared reference
        + size_of::<Option<&T>>() // get result
        + size_of::<&T>() // Index result
        + size_of::<&mut Vec<T>>() // DerefMut/IndexMut receiver
        + size_of::<&mut Vec<T>>() // as_mut_slice receiver
        + mutable_pointer_controls::<T>()
        + size_of::<&mut [T]>() // as_mut_slice result
        + size_of::<&mut [T]>() // DerefMut result
        + size_of::<&mut [T]>() // get_mut/index_mut receiver
        + size_of::<usize>() // mutable index
        + size_of::<usize>() // mutable slice length
        + size_of::<bool>() // mutable bound comparison
        + size_of::<*mut T>() // mutable data pointer
        + size_of::<*mut T>() // mutable offset pointer
        + size_of::<&mut T>() // get_unchecked_mut output
        + size_of::<Option<&mut T>>() // get_mut result
        + size_of::<&mut T>() // IndexMut result
        // The actual materializer get_mut(...).ok_or_else adapter, not a
        // differently typed sibling's Result header, remains independently named.
        + size_of::<Result<&mut T, crate::ProviderError>>()
        + dispatch::access_try_scratch::<T>()
        + size_of::<usize>() // actual Vec Index/IndexMut owned operand
}
