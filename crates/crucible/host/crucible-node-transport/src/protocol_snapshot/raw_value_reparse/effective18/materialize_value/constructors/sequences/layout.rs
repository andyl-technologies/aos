//! Bounds only the actual pinned AOS1.98.1 private sequence fields/results.
//!
//! Descriptions are const-evaluated. They never instantiate a private ABI mirror
//! or dereference a pointer. Per-field and terminal alignment slack bound any
//! field order of the pinned repr(Rust) records; a usize tag bounds two variants.

use std::alloc::Layout;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;

pub(super) const fn record(fields: &[(usize, usize)]) -> (usize, usize) {
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

// Unique<u8> is transparent over NonNull plus a zero-sized marker; Cap is the
// transparent usize niche newtype and Global is a fieldless unit struct.
pub(super) const INNER: (usize, usize) = record(&[
    (size_of::<NonNull<u8>>(), align_of::<NonNull<u8>>()),
    (size_of::<usize>(), align_of::<usize>()),
    (size_of::<()>(), align_of::<()>()),
]);
pub(super) const RAW: (usize, usize) = record(&[
    INNER,
    (
        size_of::<std::marker::PhantomData<u8>>(),
        align_of::<std::marker::PhantomData<u8>>(),
    ),
]);
pub(super) const ALLOCATION_RESULT: (usize, usize) = either(
    (size_of::<NonNull<[u8]>>(), align_of::<NonNull<[u8]>>()),
    (size_of::<()>(), align_of::<()>()),
);
pub(super) const RESERVE_KIND: (usize, usize) = either(
    (size_of::<()>(), align_of::<()>()),
    record(&[
        (size_of::<Layout>(), align_of::<Layout>()),
        (size_of::<()>(), align_of::<()>()),
    ]),
);

// grow_exact checked_add().ok_or(CapacityOverflow) before conversion via ?.
pub(super) const CAPACITY_RESULT: (usize, usize) =
    either((size_of::<usize>(), align_of::<usize>()), RESERVE_KIND);

// AllocError is a fieldless unit type. These are structural descriptions of the
// actual private Result/residual/ControlFlow fields, never instantiated types.
const ALLOC_ERROR: (usize, usize) = (size_of::<()>(), align_of::<()>());
const IMPOSSIBLE: (usize, usize) = (
    size_of::<std::convert::Infallible>(),
    align_of::<std::convert::Infallible>(),
);
const THIN: (usize, usize) = (size_of::<NonNull<u8>>(), align_of::<NonNull<u8>>());
pub(super) const ALLOCATION_THIN_RESULT: (usize, usize) = either(THIN, ALLOC_ERROR);
pub(super) const ALLOCATION_RESIDUAL: (usize, usize) = either(IMPOSSIBLE, ALLOC_ERROR);
pub(super) const ALLOCATION_THIN_FLOW: (usize, usize) = either(ALLOCATION_RESIDUAL, THIN);
pub(super) const CAPACITY_RESIDUAL: (usize, usize) = either(IMPOSSIBLE, RESERVE_KIND);
pub(super) const CAPACITY_FLOW: (usize, usize) =
    either(CAPACITY_RESIDUAL, (size_of::<usize>(), align_of::<usize>()));
