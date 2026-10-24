//! Defines field-backed bounds for the locked String/Value insertion views.
//!
//! Rust1.98.1 node.rs190,771,1754-1779, search.rs33-42, borrow.rs14-17 and
//! navigate.rs103-131 define every private record below. Fields have alignment
//! at most eight for these exact ordinary serde_json String/Value operands.
//! One gap per field plus trailing padding bounds every source-field order.
//! Actual two-variant enums, and their enclosing Option, use the locked rustc
//! tagged/niche rules; a word bounds the source's small discriminant. No private
//! Rust enum is asserted to equal an invented public ABI mirror.
//!
//! These calculations execute at compile time. The caller must reject a changed
//! public profile before using them; source/toolchain upgrades require re-audit.

use serde_json::{Map, Number, Value};
use std::{
    collections::BTreeMap,
    mem::{align_of, size_of},
    ptr::NonNull,
};

pub(super) const WORD: usize = size_of::<usize>();
pub(super) const POINTER: usize = size_of::<NonNull<u8>>();
pub(super) const KEY: usize = size_of::<String>();
pub(super) const VALUE: usize = size_of::<Value>();
const ALIGNMENT: usize = 8;

/// Bounds every possible field order for this pinned, at-most-eight alignment.
const fn record(fields: &[usize]) -> usize {
    let mut total = 0usize;
    let mut index = 0;
    while index < fields.len() {
        total = match total.checked_add(fields[index]) {
            Some(value) => value,
            None => return usize::MAX,
        };
        index += 1;
    }
    let gaps = match (fields.len() + 1).checked_mul(ALIGNMENT - 1) {
        Some(value) => value,
        None => return usize::MAX,
    };
    let total = match total.checked_add(gaps) {
        Some(value) => value,
        None => return usize::MAX,
    };
    match total.checked_add(ALIGNMENT - 1) {
        Some(value) => value & !(ALIGNMENT - 1),
        None => usize::MAX,
    }
}

const fn tagged(payload: usize) -> usize {
    record(&[WORD, payload])
}

const fn larger(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

// NodeRef = height, thin leaf pointer, PhantomData. Root is its Owned alias.
pub(super) const NODE: usize = record(&[WORD, POINTER, 0]);
pub(super) const OPTIONAL_ROOT: usize = tagged(NODE);
// Handle = actual NodeRef, usize index, PhantomData.
pub(super) const HANDLE: usize = record(&[NODE, WORD, 0]);
pub(super) const OPTIONAL_HANDLE: usize = tagged(HANDLE);
pub(super) const HANDLE_RESULT: usize = tagged(HANDLE);
pub(super) const ASCEND_RESULT: usize = tagged(larger(HANDLE, NODE));
pub(super) const FORCE_NODE: usize = tagged(NODE);
pub(super) const FORCE_HANDLE: usize = tagged(HANDLE);
// SearchResult::{Found,GoDown} both own handles; IndexResult owns usize.
pub(super) const SEARCH_RESULT: usize = tagged(HANDLE);
pub(super) const INDEX_RESULT: usize = tagged(WORD);
pub(super) const LEFT_OR_RIGHT: usize = tagged(WORD);
pub(super) const SPLITPOINT: usize = record(&[WORD, LEFT_OR_RIGHT]);
// SplitResult = borrowed left NodeRef, owning extracted (K,V), owned right Root.
pub(super) const KEY_VALUE: usize = size_of::<(String, Value)>();
pub(super) const SPLIT: usize = record(&[NODE, KEY_VALUE, NODE]);
pub(super) const OPTIONAL_SPLIT: usize = tagged(SPLIT);
pub(super) const SPLIT_AND_HANDLE: usize = record(&[OPTIONAL_SPLIT, HANDLE]);
// DormantMutRef = NonNull<Map> plus PhantomData of the unique map borrow.
pub(super) const DORMANT: usize = record(&[POINTER, 0]);
pub(super) const MAP_AND_DORMANT: usize = record(&[POINTER, DORMANT]);
// entry.rs469-477 uses dormant_map mutably and the fieldless allocator by
// shared loan. Two thin captures bound either precise field capture or one
// coarser self capture; no closure ABI equality is asserted.
pub(super) const SPLIT_ROOT_CLOSURE: usize = record(&[POINTER, POINTER]);
// LazyLeafHandle::{Root,Edge}; LazyLeafRange retains Option of both endpoints.
pub(super) const LAZY_HANDLE: usize = tagged(larger(NODE, HANDLE));
pub(super) const OPTIONAL_LAZY_HANDLE: usize = tagged(LAZY_HANDLE);
pub(super) const LAZY_RANGE: usize = record(&[OPTIONAL_LAZY_HANDLE, OPTIONAL_LAZY_HANDLE]);
// A true const item: profile_matches must not run the record loop before quote.
const TREE_ITER_BOUND: usize = record(&[LAZY_RANGE, WORD, 0]);
pub(super) const HANDLE_AND_KV: usize = record(&[HANDLE, HANDLE]);
pub(super) const OPTIONAL_HANDLE_AND_KV: usize = tagged(HANDLE_AND_KV);
// into_dying/full_range constructs a pair of the same dying-root views.
pub(super) const ROOT_AND_UNIT: usize = record(&[NODE, 0]);
// Unique<T> owns a NonNull<T> and PhantomData<T>; Global is fieldless.
pub(super) const UNIQUE: usize = record(&[POINTER, 0]);
pub(super) const ALLOCATION_TUPLE: usize = record(&[POINTER, 0]);
// core::alloc::AllocError is fieldless; core::convert::Infallible has no
// inhabited variant. These are source-field/tag bounds, not ABI equality with
// an unrelated error type. Each Result/ControlFlow has its own defining row.
pub(super) const THIN_ALLOCATION_RESULT: usize = tagged(POINTER);
pub(super) const ALLOCATION_RESULT: usize = tagged(size_of::<NonNull<[u8]>>());
pub(super) const ALLOC_ERROR_RESIDUAL: usize = tagged(0);
pub(super) const THIN_ALLOCATION_TRY: usize = tagged(larger(ALLOC_ERROR_RESIDUAL, POINTER));
pub(super) const FAT_ALLOCATION_TRY: usize =
    tagged(larger(ALLOC_ERROR_RESIDUAL, size_of::<NonNull<[u8]>>()));
pub(super) const BOX_RESULT: usize = tagged(POINTER);

/// Checks the public geometry anchors of the exact source-defined profile.
pub(super) fn profile_matches() -> bool {
    WORD == 8
        && align_of::<usize>() == ALIGNMENT
        && POINTER == 8
        && align_of::<NonNull<u8>>() == ALIGNMENT
        && KEY == 24
        && align_of::<String>() == ALIGNMENT
        && VALUE == 32
        && align_of::<Value>() == ALIGNMENT
        && size_of::<Number>() == 16
        && size_of::<BTreeMap<String, Value>>() == 24
        && size_of::<Map<String, Value>>() == size_of::<BTreeMap<String, Value>>()
        && align_of::<Map<String, Value>>() == ALIGNMENT
        && size_of::<Box<()>>() == POINTER
        && size_of::<std::collections::btree_map::IntoIter<String, Value>>() <= TREE_ITER_BOUND
        && size_of::<serde_json::map::IntoIter>()
            == size_of::<std::collections::btree_map::IntoIter<String, Value>>()
        && NODE != usize::MAX
        && LAZY_RANGE != usize::MAX
        && SPLIT_AND_HANDLE != usize::MAX
}

#[cfg(test)]
#[path = "layouts_tests.rs"]
mod tests;
