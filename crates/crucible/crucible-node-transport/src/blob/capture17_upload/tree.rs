//! Prices all possible new pinned BTree nodes for an actual insertion.
//!
//! Rust 1.98.1 uses B=6: nonroot nodes have at least five entries. A height-h
//! nonleaf root needs at least 2*6^h-1 entries. An insertion can split every
//! level and add a root; all old nodes remain independently live.

use super::*;

fn new_nodes(existing: usize) -> Result<usize, ProviderError> {
    existing.checked_add(1).ok_or_else(exhausted)?;
    if existing == 0 {
        return Ok(1);
    }
    let mut height = 0usize;
    let mut minimum = 11usize;
    while existing >= minimum {
        height = height.checked_add(1).ok_or_else(exhausted)?;
        let Some(next) = minimum
            .checked_add(1)
            .and_then(|n| n.checked_mul(6))
            .and_then(|n| n.checked_sub(1))
        else {
            break;
        };
        minimum = next;
    }
    height.checked_add(2).ok_or_else(exhausted)
}

// Only the two actual receiver map types instantiate this private helper.
// Every new node is priced at the existing source-pinned internal-node upper.
pub(super) fn insertion_data<K, V>(existing: usize) -> Result<usize, ProviderError> {
    crate::retained_metadata::requested_storage::tree_storage_data(
        new_nodes(existing)?,
        0,
        size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or_else(exhausted)?,
        align_of::<K>().max(align_of::<V>()),
    )
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<usize>() * 3 + size_of::<Option<usize>>() + size_of::<Result<usize, ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_bound_tracks_actual_populations_and_refuses_overflow() -> Result<(), ProviderError> {
        for (entries, nodes) in [
            (0, 1),
            (1, 2),
            (10, 2),
            (11, 3),
            (70, 3),
            (71, 4),
            (430, 4),
            (431, 5),
            (2591, 6),
        ] {
            assert_eq!(new_nodes(entries)?, nodes);
        }
        assert!(new_nodes(usize::MAX).is_err());
        assert!(insertion_data::<usize, usize>(71)? > insertion_data::<usize, usize>(70)?);
        Ok(())
    }
}
