//! Reproduces requested node layouts for the pinned metadata serializer only.
//!
//! Rust 1.98.1 liballoc has B=6, eleven key/value slots and twelve child edges.
//! These private layout-only mirrors are bound to the source-built compiler and
//! serde_json 1.0.150 default/std features. Actual allocator controls must match
//! them whenever those inputs change; this is not a public BTreeMap ABI claim.

use std::mem::{MaybeUninit, size_of};
use std::ptr::NonNull;

use serde_json::Value;

// Field values are never initialized or dereferenced. The mirrors exist solely
// to reproduce requested Layout sizes, including the compiler's actual padding.
#[allow(dead_code)]
struct LeafNode<K, V> {
    parent: Option<NonNull<InternalNode<K, V>>>,
    parent_idx: MaybeUninit<u16>,
    len: u16,
    keys: [MaybeUninit<K>; 11],
    vals: [MaybeUninit<V>; 11],
}

#[repr(C)]
#[allow(dead_code)]
struct InternalNode<K, V> {
    data: LeafNode<K, V>,
    edges: [MaybeUninit<NonNull<LeafNode<K, V>>>; 12],
}

pub(super) fn map_node_bytes() -> usize {
    size_of::<InternalNode<String, Value>>()
}

pub(super) fn map_node_bytes_for<K, V>() -> usize {
    size_of::<InternalNode<K, V>>()
}

pub(super) fn value_slot_bytes() -> usize {
    size_of::<Value>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_value_layout_matches_actual_requested_allocation_control() {
        // Independent source-built malloc controls observed 585 leaf632 and
        // 96 internal728 requests during insertion/splits with these inputs.
        assert_eq!(size_of::<LeafNode<String, Value>>(), 632);
        assert_eq!(map_node_bytes(), 728);
        assert_eq!(value_slot_bytes(), 32);
    }
}
