//! Reproduces requested node layouts for the pinned metadata serializer only.
//!
//! Rust 1.98.1 liballoc has B=6, eleven key/value slots and twelve child edges.
//! These private layout-only mirrors are bound to the source-built compiler and
//! serde_json 1.0.150 default/std features. Actual allocator controls must match
//! them whenever those inputs change; this is not a public BTreeMap ABI claim.

use serde_json::Value;
use std::mem::{MaybeUninit, size_of};
use std::ptr::NonNull;

// Field values are never initialized or dereferenced. The mirrors exist solely
// to reproduce requested Layout sizes, including the compiler's actual padding.
/// Names the pinned uninitialized leaf layout; it is never constructed or dereferenced.
#[allow(dead_code)]
pub struct LeafNode<K, V> {
    parent: Option<NonNull<InternalNode<K, V>>>,
    parent_idx: MaybeUninit<u16>,
    len: u16,
    keys: [MaybeUninit<K>; 11],
    vals: [MaybeUninit<V>; 11],
}

/// Names the pinned uninitialized internal-node layout, solely for size queries.
#[repr(C)]
#[allow(dead_code)]
pub struct InternalNode<K, V> {
    data: LeafNode<K, V>,
    edges: [MaybeUninit<NonNull<LeafNode<K, V>>>; 12],
}

/// Returns the requested pinned internal String/Value node size.
pub fn map_node_bytes() -> usize {
    size_of::<InternalNode<String, Value>>()
}

/// Returns the requested pinned internal String/Value node size.
/// Returns the requested pinned internal node size for the actual key/value types.
pub fn map_node_bytes_for<K, V>() -> usize {
    size_of::<InternalNode<K, V>>()
}

/// Returns the actual Value slot size.
pub fn value_slot_bytes() -> usize {
    size_of::<Value>()
}
