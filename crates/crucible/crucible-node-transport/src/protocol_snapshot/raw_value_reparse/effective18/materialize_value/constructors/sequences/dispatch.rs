//! Names selected AOS std dispatch, Try, and transparent wrapper call controls.
//!
//! Allocation rows stop after the real std ABI operands/results. They do not
//! describe backend allocator residency, growth of a nonempty Vec or deep Drop.

use super::layout;
use crate::ProviderError;
use std::alloc::{Layout, LayoutError};
use std::collections::TryReserveError;
use std::convert::Infallible;
use std::mem::{ManuallyDrop, size_of};
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::ptr::NonNull;

// Result::branch consumes the actual Result, creates a residual on Err and
// returns ControlFlow. FromResidual then consumes that residual and converts E
// through the actual identity From<E> before creating the enclosing Result.
fn try_scratch<Output, Return, Error>() -> usize {
    size_of::<Result<Output, Error>>() // branch owned input
        + size_of::<Output>() // Ok binding / Continue operand
        + size_of::<Error>() // Err binding
        + size_of::<Result<Infallible, Error>>() // Err residual initializer
        + size_of::<ControlFlow<Result<Infallible, Error>, Output>>() // initializer
        + size_of::<ControlFlow<Result<Infallible, Error>, Output>>() // branch return
        + size_of::<Result<Infallible, Error>>() // FromResidual owned input
        + size_of::<Error>() // residual Err binding
        + size_of::<Error>() // identity From::from input
        + size_of::<Error>() // identity From::from output
        + size_of::<Result<Return, Error>>() // enclosing Err initializer
        + size_of::<Result<Return, Error>>() // FromResidual return
}

pub(super) fn query_try_scratch() -> usize {
    // Separate actual DATA helper contexts: quote arithmetic, finish's nested
    // arithmetic, and String copy's returned three-axis reserve quotation.
    try_scratch::<usize, [usize; 3], ProviderError>()
        + try_scratch::<usize, [usize; 3], ProviderError>()
        + try_scratch::<[usize; 3], [usize; 3], ProviderError>()
}

pub(super) fn access_try_scratch<T>() -> usize {
    // The actual get_mut(...).ok_or_else(invalid)? in attach_data returns ().
    try_scratch::<&mut T, (), ProviderError>()
}

pub(super) fn reserve_try_scratch() -> usize {
    // These three ? sites have different actual successful operand types.
    try_scratch::<(), (), TryReserveError>() // inner try_reserve_exact -> grow_exact
        + try_scratch::<NonNull<[u8]>, (), TryReserveError>() // grow_exact -> finish_grow
        + try_scratch::<Layout, NonNull<[u8]>, TryReserveError>() // finish_grow -> layout_array
        // grow_exact checked_add().ok_or(CapacityOverflow)? converts the actual
        // unstable TryReserveErrorKind into the public TryReserveError.
        + layout::CAPACITY_RESULT.0 // Result<usize,Kind> branch owned input
        + size_of::<usize>() // successful cap binding
        + layout::RESERVE_KIND.0 // failed Kind binding
        + layout::CAPACITY_RESIDUAL.0 // Err residual initializer
        + layout::CAPACITY_FLOW.0 // ControlFlow initializer
        + layout::CAPACITY_FLOW.0 // branch return
        + layout::CAPACITY_RESIDUAL.0 // FromResidual owned input
        + layout::RESERVE_KIND.0 // FromResidual Err binding
        + layout::RESERVE_KIND.0 // From<Kind> input
        + size_of::<TryReserveError>() // Self { kind } initializer
        + size_of::<TryReserveError>() // From<Kind> return
        + size_of::<Result<(), TryReserveError>>() // enclosing Err initializer
        + size_of::<Result<(), TryReserveError>>() // FromResidual return
        // layout_array's actual repeat_packed(...).map_err(CapacityOverflow.into).
        + size_of::<Result<Layout, LayoutError>>() // map_err owned input
        + size_of::<Layout>() // successful binding
        + size_of::<LayoutError>() // failed binding
        + size_of::<LayoutError>() // closure input
        + size_of::<()>() // actual capture-free closure value
        + layout::RESERVE_KIND.0 // Into::into owned input
        + layout::RESERVE_KIND.0 // nested From<Kind> owned input
        + size_of::<TryReserveError>() // Self { kind } initializer
        + size_of::<TryReserveError>() // From<Kind> return
        + size_of::<TryReserveError>() // Into::into return
        + size_of::<Result<Layout, TryReserveError>>() // map_err result initializer
        + size_of::<Result<Layout, TryReserveError>>() // map_err return
        // finish_grow's actual AllocError { layout, non_exhaustive:() }.into().
        + layout::RESERVE_KIND.0 // Into::into owned input
        + layout::RESERVE_KIND.0 // nested From<Kind> owned input
        + size_of::<TryReserveError>() // Self { kind } initializer
        + size_of::<TryReserveError>() // From<Kind> return
        + size_of::<TryReserveError>() // Into::into return
}

pub(super) fn allocation_scratch() -> usize {
    size_of::<&()>() // Global::alloc_impl receiver
        + size_of::<Layout>() // alloc_impl layout
        + size_of::<bool>() // alloc_impl zeroed=false
        + size_of::<(Layout, bool)>() // const_eval_select ARG tuple
        + size_of::<()>() // alloc_impl_const function item (not executed)
        + size_of::<()>() // alloc_impl_runtime function item
        + layout::ALLOCATION_RESULT.0 // const_eval_select return
        + layout::ALLOCATION_RESULT.0 // alloc_impl return
        + size_of::<Layout>() // alloc_impl_runtime input
        + size_of::<bool>() // runtime zeroed input
        + size_of::<&Layout>() // layout.size receiver
        + size_of::<usize>() // size match binding
        + size_of::<bool>() // nonzero / zeroed branch controls
        + size_of::<Layout>() // alloc(Layout) owned input
        + size_of::<()>() // no-alloc-shim ABI return
        + size_of::<&Layout>() // alloc layout.size receiver
        + size_of::<usize>() // layout.size return
        + size_of::<usize>() // __rust_alloc size input
        + size_of::<&Layout>() // alloc layout.alignment receiver
        + size_of::<NonZeroUsize>() // layout.alignment returned Alignment geometry
        + size_of::<NonZeroUsize>() // repr(usize) Alignment ABI geometry
        + size_of::<*mut u8>() // __rust_alloc returned thin pointer
        + size_of::<*mut u8>() // alloc returned pointer
        + size_of::<*mut u8>() // raw_ptr local / NonNull::new input
        + size_of::<bool>() // pointer null check
        + size_of::<NonNull<u8>>() // unchecked pointer initializer
        + size_of::<*mut u8>() // NonNull::new_unchecked owned input
        + size_of::<NonNull<u8>>() // NonNull::new_unchecked return
        + size_of::<Option<NonNull<u8>>>() // Some/None initializer
        + size_of::<Option<NonNull<u8>>>() // NonNull::new return
        + size_of::<Option<NonNull<u8>>>() // Option::ok_or owned input
        + size_of::<()>() // fieldless AllocError input
        + layout::ALLOCATION_THIN_RESULT.0 // ok_or result initializer
        + layout::ALLOCATION_THIN_RESULT.0 // ok_or return
        + layout::ALLOCATION_THIN_RESULT.0 // Try::branch owned input
        + size_of::<NonNull<u8>>() // successful ptr binding
        + size_of::<()>() // AllocError binding
        + layout::ALLOCATION_RESIDUAL.0 // Err residual initializer
        + layout::ALLOCATION_THIN_FLOW.0 // ControlFlow initializer
        + layout::ALLOCATION_THIN_FLOW.0 // branch return
        + layout::ALLOCATION_RESIDUAL.0 // FromResidual input
        + size_of::<()>() // FromResidual AllocError binding
        + size_of::<()>() // identity From<AllocError> input
        + size_of::<()>() // identity From<AllocError> return
        + layout::ALLOCATION_RESULT.0 // FromResidual fat Err initializer
        + layout::ALLOCATION_RESULT.0 // FromResidual fat result
        + size_of::<NonNull<u8>>() // cast_slice receiver
        + size_of::<usize>() // cast_slice length
        + size_of::<NonNull<u8>>() // slice_from_raw_parts input
        + size_of::<*mut u8>() // as_ptr / ptr::slice_from_raw_parts_mut input
        + size_of::<usize>() // ptr slice length
        + size_of::<*mut [u8]>() // raw slice constructor output
        + size_of::<NonNull<[u8]>>() // NonNull slice initializer
        + size_of::<NonNull<[u8]>>() // cast_slice return
        + layout::ALLOCATION_RESULT.0 // runtime Ok initializer
        + layout::ALLOCATION_RESULT.0 // alloc_impl_runtime return
        // The mutually exclusive size0 arm uses this same cast_slice helper
        // roster above; its independent dangling-pointer producer is named here.
        + size_of::<&Layout>() // Layout::dangling_ptr receiver
        + size_of::<NonZeroUsize>() // Alignment::as_nonzero_usize receiver geometry
        + size_of::<NonZeroUsize>() // as_nonzero_usize return
        + size_of::<NonZeroUsize>() // NonNull::without_provenance input
        + size_of::<NonZeroUsize>() // NonZero::get owned receiver
        + size_of::<usize>() // NonZero::get returned address
        + size_of::<usize>() // ptr::without_provenance_mut input
        + size_of::<*mut u8>() // ptr::without_provenance_mut output
        + size_of::<NonNull<u8>>() // without_provenance returned pointer
        + size_of::<NonNull<u8>>() // dangling_ptr returned pointer
}

pub(super) fn deallocation_scratch() -> usize {
    size_of::<&()>() // Global::deallocate_impl receiver
        + size_of::<NonNull<u8>>() // deallocate_impl pointer
        + size_of::<Layout>() // deallocate_impl layout
        + size_of::<(NonNull<u8>, Layout)>() // const_eval_select ARG tuple
        + size_of::<()>() // const function item (not executed)
        + size_of::<()>() // runtime function item
        + size_of::<()>() // const_eval_select result
        + size_of::<NonNull<u8>>() // runtime pointer input
        + size_of::<Layout>() // runtime layout input
        + size_of::<&Layout>() // runtime layout.size receiver
        + size_of::<usize>() // runtime size
        + size_of::<bool>() // nonzero size test
        + size_of::<NonNull<u8>>() // dealloc_nonnull pointer input
        + size_of::<Layout>() // dealloc_nonnull layout input
        + size_of::<NonNull<u8>>() // __rust_dealloc pointer input
        + size_of::<&Layout>() // ABI layout.size receiver
        + size_of::<usize>() // ABI layout.size return
        + size_of::<usize>() // ABI size input
        + size_of::<&Layout>() // ABI layout.alignment receiver
        + size_of::<NonZeroUsize>() // ABI layout.alignment returned Alignment geometry
        + size_of::<NonZeroUsize>() // repr(usize) Alignment ABI geometry
        + size_of::<()>() // ABI/dealloc_nonnull/runtime/impl returns
}

pub(super) fn vec_manually_drop_new_transient<T>() -> usize {
    size_of::<Vec<T>>() // ManuallyDrop::new actual owned input
        + size_of::<Vec<T>>() // MaybeDangling::new actual owned input
        // Pinned MaybeDangling is repr(transparent) over exactly Vec<T>.
        + size_of::<Vec<T>>() // MaybeDangling(Vec) initializer geometry
        + size_of::<Vec<T>>() // MaybeDangling::new return geometry
        + size_of::<ManuallyDrop<Vec<T>>>() // ManuallyDrop initializer
        + size_of::<ManuallyDrop<Vec<T>>>() // ManuallyDrop::new return
}

pub(super) fn vec_manually_drop_deref_scratch<T>() -> usize {
    size_of::<&ManuallyDrop<Vec<T>>>() // ManuallyDrop::deref receiver
        + size_of::<&Vec<T>>() // &MaybeDangling<Vec<T>> as_ref receiver geometry
        + size_of::<&Vec<T>>() // MaybeDangling::as_ref return
        + size_of::<&Vec<T>>() // ManuallyDrop::deref return
}

pub(super) fn global_manually_drop_scratch() -> usize {
    size_of::<()>() // Global ptr::read return / ManuallyDrop::new input
        + size_of::<()>() // MaybeDangling::new(Global) input
        + size_of::<()>() // MaybeDangling(Global) initializer
        + size_of::<()>() // MaybeDangling::new return
        + size_of::<ManuallyDrop<()>>() // allocator wrapper initializer
        + size_of::<ManuallyDrop<()>>() // allocator wrapper returned value
        + size_of::<&mut ManuallyDrop<()>>() // ManuallyDrop::take receiver
        + size_of::<&()>() // &MaybeDangling<Global> as_ref receiver geometry
        + size_of::<&()>() // MaybeDangling::as_ref return
        + size_of::<*const ()>() // ptr::read(Global) pointer
        + size_of::<()>() // ptr::read / take return
}
