//! Names this producer's actual String/u8-copy constructors and scalar teardown.
//!
//! AOS Rust 1.98.1 String::from(&str), String::clone and validator-reason copy reach
//! the same TrivialClone-u8 slice/Vec allocation chain. Each complete String is
//! rooted and observed before another copy starts, so one chain is admitted at
//! a time. Actual new byte backing remains in the parent's separate R/T quote.
//! Allocator implementation, abort and compiler activation frames are excluded.

use std::alloc::{Layout, LayoutError};
use std::collections::TryReserveError;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;

// These are constant structural upper bounds, never casts or ABI mirrors of
// private Rust types. A record can spend at most align-1 before each field and
// max_align-1 at its end. The enum bound reserves a usize tag and its largest
// payload; niches can only reduce it. The pinned definitions have no repr(align)
// or packed attributes. All descriptions evaluate at compile time, not quote.
const fn record(fields: &[(usize, usize)]) -> (usize, usize) {
    let mut bytes = 0;
    let mut alignment = 1;
    let mut index = 0;
    while index < fields.len() {
        let (size, align) = fields[index];
        bytes += size + align - 1;
        if align > alignment {
            alignment = align;
        }
        index += 1;
    }
    (bytes + alignment - 1, alignment)
}

const fn either(first: (usize, usize), second: (usize, usize)) -> (usize, usize) {
    let bytes = if first.0 > second.0 {
        first.0
    } else {
        second.0
    };
    let alignment = if first.1 > second.1 {
        first.1
    } else {
        second.1
    };
    record(&[
        (size_of::<usize>(), align_of::<usize>()),
        (bytes, alignment),
    ])
}

// AOS 1.98.1 raw_vec/mod.rs73-91: Unique<u8> is transparent over NonNull<u8>
// plus PhantomData;
// Cap is the pinned transparent usize niche newtype, and Global is fieldless.
const INNER: (usize, usize) = record(&[
    (size_of::<NonNull<u8>>(), align_of::<NonNull<u8>>()),
    (size_of::<usize>(), align_of::<usize>()),
    (size_of::<()>(), align_of::<()>()),
]);
const RAW: (usize, usize) = record(&[
    INNER,
    (
        size_of::<std::marker::PhantomData<u8>>(),
        align_of::<std::marker::PhantomData<u8>>(),
    ),
]);
const INNER_RESULT: (usize, usize) = either(
    INNER,
    (size_of::<TryReserveError>(), align_of::<TryReserveError>()),
);
// Allocator::allocate returns Result<NonNull<[u8]>, AllocError>; AllocError is
// fieldless. It is represented structurally to avoid using an unstable API.
const ALLOCATION_RESULT: (usize, usize) = either(
    (size_of::<NonNull<[u8]>>(), align_of::<NonNull<[u8]>>()),
    (size_of::<()>(), align_of::<()>()),
);

// TryReserveErrorKind is CapacityOverflow or AllocError { Layout, () }.
const RESERVE_KIND: (usize, usize) = either(
    (size_of::<()>(), align_of::<()>()),
    record(&[
        (size_of::<Layout>(), align_of::<Layout>()),
        (size_of::<()>(), align_of::<()>()),
    ]),
);

pub(super) const fn transient_data() -> usize {
    size_of::<String>() // String::from or String::clone return
        + size_of::<String>() // str::to_owned return
        + size_of::<String>() // from_utf8_unchecked return/field initializer
        + size_of::<Vec<u8>>() // bytes::to_owned or Vec::clone return
        + size_of::<Vec<u8>>() // slice::to_vec return
        + size_of::<Vec<u8>>() // slice::to_vec_in return
        + size_of::<Vec<u8>>() // ConvertVec::to_vec return
        + size_of::<Vec<u8>>() // ConvertVec's v local
        + size_of::<Vec<u8>>() // Vec::with_capacity_in return
        + RAW.0 // RawVec::with_capacity_in return
        + INNER.0 // RawVecInner::with_capacity_in return
        + INNER_RESULT.0 // try_allocate_in return
        + INNER.0 // with_capacity_in's Ok(this) local
        + INNER.0 // zero-length new_in return
        + INNER.0 // try_allocate_in's successful Self initializer
}

pub(super) const fn counter_data() -> usize {
    size_of::<&str>() // String::from input
        + size_of::<&str>() // str::to_owned receiver
        + size_of::<&str>() // str::as_bytes receiver
        + size_of::<&[u8]>() // str::as_bytes return
        + size_of::<&[u8]>() // slice::to_owned receiver
        + size_of::<&String>() // String::clone receiver
        + size_of::<&Vec<u8>>() // Vec::clone receiver
        + size_of::<&Vec<u8>>() // Vec::allocator receiver
        + size_of::<&()>() // actual Global clone receiver geometry
        + size_of::<&Vec<u8>>() // Vec::deref receiver
        + size_of::<&Vec<u8>>() // Vec::as_slice receiver
        + size_of::<&[u8]>() // Vec::as_slice return
        + size_of::<&[u8]>() // Vec::deref return
        + size_of::<&[u8]>() // slice::to_vec receiver
        + size_of::<&[u8]>() // slice::to_vec_in receiver
        + size_of::<&[u8]>() // ConvertVec::to_vec input
        + size_of::<usize>() // TrivialClone initialized len
        + size_of::<usize>() // Vec::with_capacity_in input
        + size_of::<usize>() // RawVec::with_capacity_in input
        + size_of::<usize>() // RawVecInner::with_capacity_in input
        + size_of::<usize>() // try_allocate_in capacity
        + size_of::<usize>() // AllocInit closed two-unit-variant bound
        + size_of::<Layout>() // element layout input
        + size_of::<Layout>() // layout_array result/local
        + size_of::<Result<Layout, TryReserveError>>()
        + size_of::<Result<Layout, LayoutError>>() // repeat_packed result
        + size_of::<usize>() // checked array extent
        + size_of::<Option<usize>>() // checked layout arithmetic
        + size_of::<&()>() // Global::allocate receiver geometry
        + ALLOCATION_RESULT.0 // allocation result
        + size_of::<NonNull<[u8]>>() // Ok(ptr) local
        + size_of::<NonNull<u8>>() // ptr.cast result
        + size_of::<NonNull<u8>>() // Unique constructor argument
        + size_of::<usize>() // Cap::new_unchecked argument
        + size_of::<std::num::NonZeroUsize>() // zero-branch Alignment argument
        + size_of::<NonNull<u8>>() // zero-branch dangling pointer
        + size_of::<TryReserveError>() // infallible allocation handle_error input
        + RESERVE_KIND.0 // allocation-error kind initializer
        + RESERVE_KIND.0 // handle_error e.kind() return
        + size_of::<Layout>() // allocation-error layout binding
        + size_of::<&[u8]>() // source as_ptr receiver
        + size_of::<*const u8>() // source pointer
        + size_of::<&mut Vec<u8>>() // destination as_mut_ptr receiver
        + size_of::<&()>() // RawVec pointer getter receiver geometry
        + size_of::<&()>() // RawVecInner pointer getter receiver geometry
        + size_of::<&()>() // Unique pointer getter receiver geometry
        + size_of::<*mut u8>() // destination pointer
        + size_of::<usize>() // copy_to_nonoverlapping length
        + size_of::<&mut Vec<u8>>() // Vec::set_len receiver
        + size_of::<usize>() // set_len argument
        + size_of::<()>() // pointer-copy/set_len returns
        + size_of::<bool>() // empty/zero-layout branch predicates
        // u8 selects TrivialClone: no nontrivial child or DropGuard is reached.
        // New Strings eventually drop a scalar Vec<u8>; no recursive Value is
        // introduced. These are the pinned Vec/RawVec field-drop/dealloc calls.
        + size_of::<&mut String>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<*mut [u8]>() // Vec's drop_in_place slice argument
        + size_of::<*mut u8>() // scalar Drop as_mut_ptr/cast_slice input
        + size_of::<&()>() // Drop RawVec pointer getter
        + size_of::<&()>() // Drop RawVecInner pointer getter
        + size_of::<&()>() // Drop Unique pointer getter
        + size_of::<usize>() // Vec element length
        + size_of::<()>() // scalar drop_in_place return
        + size_of::<&mut ()>() // RawVec Drop receiver geometry
        + size_of::<&mut ()>() // RawVecInner deallocate receiver geometry
        + size_of::<Layout>() // u8 element layout
        + size_of::<&()>() // current_memory receiver geometry
        + size_of::<Layout>() // current_memory element layout
        + size_of::<Option<(NonNull<u8>, Layout)>>()
        + size_of::<(NonNull<u8>, Layout)>()
        + size_of::<NonNull<u8>>()
        + size_of::<Layout>() // resulting allocation layout
        + size_of::<usize>() // actual capacity
        + size_of::<usize>() // u8 element byte extent
        + size_of::<usize>() // current_memory alloc_size
        + size_of::<usize>() // layout alignment
        + size_of::<std::num::NonZeroUsize>() // unchecked layout Alignment
        + size_of::<bool>() // current_memory empty predicate
        + size_of::<&()>() // Global::deallocate receiver geometry
        + size_of::<NonNull<u8>>() // deallocate pointer argument
        + size_of::<Layout>() // deallocate layout argument
        + size_of::<usize>() // caller quote's returned fixed byte count
}
