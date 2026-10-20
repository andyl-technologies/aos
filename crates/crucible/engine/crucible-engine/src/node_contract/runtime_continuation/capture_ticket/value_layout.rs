//! Reproduces requested node layouts for the pinned metadata serializer only.
//!
//! Rust 1.98.1 liballoc has B=6, eleven key/value slots and twelve child edges.
//! These private layout-only mirrors are bound to the source-built compiler and
//! serde_json 1.0.150 default/std features. Actual allocator controls must match
//! them whenever those inputs change; this is not a public BTreeMap ABI claim.

#[cfg(test)]
use serde_json::Value;
use std::mem::size_of;

/// Defines unselected Clone control layouts for the pinned map implementation.
#[path = "value_layout/clone_controls.rs"]
pub(super) mod clone_controls;

pub(super) use crucible_source_birth_data::serialization::value_layout::{
    InternalNode, LeafNode, map_node_bytes, map_node_bytes_for, value_slot_bytes,
};

/// Bounds requested nodes for stable borrowed trees under the pinned B=6 layout.
///
/// An empty tree may retain a root; every further node contains at least one
/// initialized entry. The bound deliberately charges an internal node per entry
/// plus one per container, including all eleven key/value slots and twelve edges.
pub(super) fn protocol_tree_storage(
    containers: usize,
    entries: usize,
    maximum_key_value_bytes: usize,
    maximum_entry_alignment: usize,
    maximum: usize,
) -> Result<usize, crate::node_contract::RuntimeError> {
    use crate::node_contract::RuntimeError;
    use std::{alloc::Layout, mem::align_of};

    if containers == 0 {
        return if entries == 0 {
            Ok(0)
        } else {
            Err(RuntimeError::InvalidReceipt)
        };
    }
    Layout::from_size_align(0, maximum_entry_alignment)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let alignment = maximum_entry_alignment.max(align_of::<usize>());
    // Eight alignment boundaries cover any leaf field order, its trailing
    // padding, and the repr(C) internal node's leaf/edge alignment boundaries.
    let padding = (alignment - 1)
        .checked_mul(8)
        .ok_or(RuntimeError::ResourceLimit)?;
    let node = size_of::<usize>()
        .checked_add(2 * size_of::<u16>())
        .and_then(|n| n.checked_add(12 * size_of::<usize>()))
        .and_then(|n| n.checked_add(maximum_key_value_bytes.checked_mul(11)?))
        .and_then(|n| n.checked_add(padding))
        .ok_or(RuntimeError::ResourceLimit)?;
    let bytes = entries
        .checked_add(containers)
        .and_then(|count| count.checked_mul(node))
        .ok_or(RuntimeError::ResourceLimit)?;
    if bytes > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(bytes)
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

    #[test]
    fn protocol_tree_bound_covers_concrete_and_overaligned_node_layouts()
    -> Result<(), crate::node_contract::RuntimeError> {
        #[repr(align(4096))]
        struct AlignedZero;

        let ordinary = protocol_tree_storage(
            1,
            1,
            size_of::<String>() + size_of::<Value>(),
            std::mem::align_of::<Value>(),
            usize::MAX,
        )?;
        assert!(ordinary >= 2 * map_node_bytes_for::<String, Value>());
        let aligned =
            protocol_tree_storage(1, 0, 0, std::mem::align_of::<AlignedZero>(), usize::MAX)?;
        assert!(aligned >= map_node_bytes_for::<AlignedZero, ()>());
        assert_eq!(protocol_tree_storage(0, 0, 0, 0, 0)?, 0);
        assert!(protocol_tree_storage(0, 1, 0, 8, usize::MAX).is_err());
        assert!(protocol_tree_storage(1, 0, 0, 3, usize::MAX).is_err());
        assert!(protocol_tree_storage(1, usize::MAX, usize::MAX, 8, usize::MAX).is_err());
        assert!(protocol_tree_storage(1, 0, 1, 8, 1).is_err());
        Ok(())
    }
}
