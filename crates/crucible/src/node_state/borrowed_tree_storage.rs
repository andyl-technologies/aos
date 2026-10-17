//! Observes conservative requested node storage for actual borrowed metadata trees.
//!
//! This uses the source-pinned Rust 1.98.1 B=6 layout bound. It is neither a
//! public standard-library ABI promise nor an allocator-resident-byte measure.
//! Key/value heaps, owning parent headers and shared owners are separate terms.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, size_of},
};

use crate::node_contract::NodeRuntime;

use super::{StateError, StateErrorCode};

/// Bounds requested node allocations of one actual borrowed ordered map.
///
/// The observer derives initialized entry count and compiled inline key/value
/// size and alignment from the actual map. It includes an empty-root allowance
/// and conservatively charges an internal node per entry. It allocates nothing.
/// The caller separately walks every independent key/value heap capacity and
/// counts the containing object's inline map handle. No source or state authority
/// is created, and no configured capacity or serialized size is interpreted.
///
/// # Errors
/// Refuses checked arithmetic overflow or a bound above `maximum_bytes`.
pub fn borrowed_btree_map_requested_storage<K, V>(
    tree: &BTreeMap<K, V>,
    maximum_bytes: usize,
) -> Result<usize, StateError> {
    let entry_bytes = size_of::<K>()
        .checked_add(size_of::<V>())
        .ok_or_else(overflow)?;
    NodeRuntime::capture_protocol_tree_storage(
        1,
        tree.len(),
        entry_bytes,
        align_of::<K>().max(align_of::<V>()),
        maximum_bytes,
    )
    .map_err(overflow_reason)
}

/// Bounds requested node allocations of one actual borrowed ordered set.
///
/// The supported compiler represents this as ordered-map nodes with unit values.
/// The same empty-root and per-entry internal-node allowances apply. Entry heaps
/// and the parent's inline set handle remain separately counted; this observer
/// creates neither an allocation nor any source/capture/restoration authority.
///
/// # Errors
/// Refuses checked arithmetic overflow or a bound above `maximum_bytes`.
pub fn borrowed_btree_set_requested_storage<T>(
    tree: &BTreeSet<T>,
    maximum_bytes: usize,
) -> Result<usize, StateError> {
    NodeRuntime::capture_protocol_tree_storage(
        1,
        tree.len(),
        size_of::<T>(),
        align_of::<T>(),
        maximum_bytes,
    )
    .map_err(overflow_reason)
}

fn overflow() -> StateError {
    overflow_reason("borrowed tree inline entry overflow")
}

fn overflow_reason(reason: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        "borrowed metadata tree storage",
        reason.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_still_admits_possible_retained_root_and_independent_budget()
    -> Result<(), StateError> {
        let map = BTreeMap::<String, Vec<u8>>::new();
        let bound = borrowed_btree_map_requested_storage(&map, usize::MAX)?;
        assert!(bound >= NodeRuntime::capture_map_node_storage::<String, Vec<u8>>());
        assert!(bound > 0);
        assert!(borrowed_btree_map_requested_storage(&map, bound - 1).is_err());
        Ok(())
    }

    #[test]
    fn map_nodes_exclude_independently_owned_spare_value_capacity() -> Result<(), StateError> {
        let ordinary = BTreeMap::from([(1u64, Vec::<u8>::new())]);
        let spare = BTreeMap::from([(1u64, Vec::<u8>::with_capacity(8192))]);
        assert_eq!(
            borrowed_btree_map_requested_storage(&ordinary, usize::MAX)?,
            borrowed_btree_map_requested_storage(&spare, usize::MAX)?
        );
        assert!(spare[&1].capacity() >= 8192);
        Ok(())
    }

    #[test]
    fn set_bound_uses_actual_compiled_overalignment() -> Result<(), StateError> {
        #[derive(Eq, Ord, PartialEq, PartialOrd)]
        #[repr(align(4096))]
        struct Aligned;
        let set = BTreeSet::<Aligned>::new();
        let bound = borrowed_btree_set_requested_storage(&set, usize::MAX)?;
        assert!(bound >= NodeRuntime::capture_map_node_storage::<Aligned, ()>());
        assert!(borrowed_btree_set_requested_storage(&set, 4095).is_err());
        Ok(())
    }
}

/// Counts the actual borrowed map without constructing a formatted error.
///
/// This uses the same pinned node geometry as the ordinary observer. It grants
/// no source, allocation or runtime rights; child heaps remain separate terms.
///
/// # Errors
/// Refuses layout overflow or a requested term above the supplied remaining bound.
pub fn borrowed_btree_map_requested_storage_precredit_data<K, V>(
    tree: &BTreeMap<K, V>,
    maximum_bytes: usize,
) -> Result<usize, crate::node_contract::RuntimeError> {
    let entry = size_of::<K>()
        .checked_add(size_of::<V>())
        .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?;
    NodeRuntime::capture_protocol_tree_storage(
        1,
        tree.len(),
        entry,
        align_of::<K>().max(align_of::<V>()),
        maximum_bytes,
    )
}

/// Counts the actual borrowed set without constructing a formatted error.
///
/// The same compiler-specific node bound and separate child terms apply.
///
/// # Errors
/// Refuses checked layout overflow or an exhausted remaining requested bound.
pub fn borrowed_btree_set_requested_storage_precredit_data<T>(
    tree: &BTreeSet<T>,
    maximum_bytes: usize,
) -> Result<usize, crate::node_contract::RuntimeError> {
    NodeRuntime::capture_protocol_tree_storage(
        1,
        tree.len(),
        size_of::<T>(),
        align_of::<T>(),
        maximum_bytes,
    )
}
