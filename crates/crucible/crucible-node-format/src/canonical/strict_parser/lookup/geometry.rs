//! Bounds the actual immutable BTreeMap private records by their source fields.
//!
//! These are upper bounds, not public ABI mirrors. Rust1.98.1's record/enum
//! layout algorithm and actual node.rs/search.rs field rosters are pinned.
//! One maximum-alignment gap per field plus tail covers field ordering; a word
//! bounds the small default discriminants. No private value is constructed or
//! cast, and no mutable-entry/allocator field is imported as a lookup donor.

use super::{Map, Value};
use std::{
    collections::BTreeMap,
    mem::{align_of, size_of},
    ptr::NonNull,
};

pub(super) const WORD: usize = size_of::<usize>();
pub(super) const REFERENCE: usize = size_of::<&()>();
pub(super) const POINTER: usize = size_of::<NonNull<()>>();
const ALIGNMENT: usize = 8;

const fn record<const N: usize>(fields: [usize; N]) -> usize {
    let mut result = 0usize;
    let mut index = 0usize;
    while index < N {
        result = match result.checked_add(fields[index]) {
            Some(value) => value,
            None => return usize::MAX,
        };
        index += 1;
    }
    let gaps = match (N + 1).checked_mul(ALIGNMENT - 1) {
        Some(value) => value,
        None => return usize::MAX,
    };
    let result = match result.checked_add(gaps) {
        Some(value) => value,
        None => return usize::MAX,
    };
    match result.checked_add(ALIGNMENT - 1) {
        Some(value) => value & !(ALIGNMENT - 1),
        None => usize::MAX,
    }
}

pub(super) const fn tagged(payload: usize) -> usize {
    record([WORD, payload])
}

// NodeRef<Owned/Immut,K,V,Type>: height, NonNull<LeafNode<K,V>>, PhantomData.
pub(super) const NODE: usize = record([WORD, POINTER, 0]);
// Unique<u8>: actual NonNull<u8> field and zero-sized ownership marker.
pub(super) const UNIQUE_U8: usize = record([POINTER, 0]);
// Handle<NodeRef<Immut,...>,KV/Edge>: actual node, idx, PhantomData.
pub(super) const HANDLE: usize = record([NODE, WORD, 0]);
// Found(KV Handle) / GoDown(Edge Handle). A miss owns its real leaf Edge Handle;
// only BTreeMap::get subsequently converts that miss to None.
pub(super) const SEARCH_RESULT: usize = tagged(HANDLE);
pub(super) const INDEX_RESULT: usize = tagged(WORD); // KV(index) / Edge(index)
pub(super) const FORCE_NODE: usize = tagged(NODE); // Leaf(Node) / Internal(Node)
pub(super) const FORCE_HANDLE: usize = tagged(HANDLE);
// These borrowed private Root payloads are thin; derive bounds from that field
// fact, without substituting an unrelated Option/ControlFlow concrete type.
pub(super) const OPTION_ROOT_REFERENCE: usize = tagged(REFERENCE);
pub(super) const ROOT_OPTION_FLOW: usize = tagged(REFERENCE);

pub(super) const SUPPORTED: bool = cfg!(all(target_arch = "x86_64", target_pointer_width = "64"))
    && WORD == 8
    && align_of::<usize>() == ALIGNMENT
    && REFERENCE == 8
    && POINTER == 8
    && align_of::<NonNull<()>>() == ALIGNMENT
    && size_of::<String>() == 24
    && align_of::<String>() == ALIGNMENT
    && size_of::<Value>() == 32
    && align_of::<Value>() == ALIGNMENT
    && size_of::<Vec<Value>>() == 24
    && size_of::<BTreeMap<String, Value>>() == 24
    && align_of::<BTreeMap<String, Value>>() == ALIGNMENT
    && align_of::<Map<String, Value>>() == ALIGNMENT
    && UNIQUE_U8 != usize::MAX
    && NODE != usize::MAX
    && HANDLE != usize::MAX
    && SEARCH_RESULT != usize::MAX
    && INDEX_RESULT != usize::MAX
    && FORCE_NODE != usize::MAX
    && FORCE_HANDLE != usize::MAX
    && OPTION_ROOT_REFERENCE != usize::MAX
    && ROOT_OPTION_FLOW != usize::MAX;
