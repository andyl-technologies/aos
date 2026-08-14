//! Canonical persistence ordering and transformation helpers.

use super::*;

/// Canonical total-order key for one ready persistence node.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct BlockPersistenceReadyKey {
    dependency_depth: u32,
    transformed_primary: [u8; 32],
    controller_sequence: u64,
    range_start: u64,
    fragment: BlockWriteFragmentId,
}

pub(super) fn persistence_order_key(node: &BlockPersistenceNode) -> BlockPersistenceReadyKey {
    BlockPersistenceReadyKey {
        dependency_depth: node.dependency_depth,
        transformed_primary: expanded_u64(node.transformed_writeback_sequence),
        controller_sequence: node.sequence,
        range_start: node.fragment.start,
        fragment: node.fragment,
    }
}

pub(super) fn transformation_rank(
    node: &BlockPersistenceNode,
) -> ([u8; 32], u64, BlockWriteFragmentId) {
    let primary = match node.ordering {
        BlockPersistenceOrdering::Preserve => expanded_u64(node.writeback_sequence),
        BlockPersistenceOrdering::ReverseReady => expanded_u64(u64::MAX - node.writeback_sequence),
        BlockPersistenceOrdering::DescendingRange => expanded_u64(u64::MAX - node.fragment.start),
        BlockPersistenceOrdering::KeyedPermutation => node.keyed_rank,
    };
    (primary, node.sequence, node.fragment)
}

pub(super) fn expanded_u64(value: u64) -> [u8; 32] {
    let word = value.to_be_bytes();
    let mut expanded = [0_u8; 32];
    for chunk in expanded.chunks_exact_mut(word.len()) {
        chunk.copy_from_slice(&word);
    }
    expanded
}

pub(super) fn compose_transforms(
    transforms: &[ResolvedBlockPersistenceTransform],
) -> Result<Option<ResolvedBlockPersistenceTransform>, DeviceError> {
    let Some(first) = transforms.first().copied() else {
        return Ok(None);
    };
    let mut composed = first;
    for transform in &transforms[1..] {
        if transform.ordering_group != composed.ordering_group
            || (transform.ordering != BlockPersistenceOrdering::Preserve
                && composed.ordering != BlockPersistenceOrdering::Preserve
                && transform.ordering != composed.ordering)
        {
            return Err(invalid("conflicting persistence-order transformations"));
        }
        if composed.ordering == BlockPersistenceOrdering::Preserve {
            composed.ordering = transform.ordering;
        }
        composed.delay_nanos = composed
            .delay_nanos
            .checked_add(transform.delay_nanos)
            .ok_or_else(|| invalid("persistence transformation delay overflow"))?;
        composed.preserve_barriers |= transform.preserve_barriers;
    }
    Ok(Some(composed))
}

pub(super) fn persistence_rank(
    group: Option<[u8; 32]>,
    sequence: u64,
    fragment: BlockWriteFragmentId,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.block-persistence-rank.v1\0");
    hasher.update(&group.unwrap_or([0; 32]));
    hasher.update(&sequence.to_be_bytes());
    hasher.update(&fragment.request_id.to_be_bytes());
    hasher.update(&fragment.fragment_index.to_be_bytes());
    hasher.update(&fragment.start.to_be_bytes());
    hasher.update(&fragment.length.to_be_bytes());
    *hasher.finalize().as_bytes()
}

pub(super) const fn ordering_tag(ordering: BlockPersistenceOrdering) -> u8 {
    match ordering {
        BlockPersistenceOrdering::Preserve => 0,
        BlockPersistenceOrdering::ReverseReady => 1,
        BlockPersistenceOrdering::DescendingRange => 2,
        BlockPersistenceOrdering::KeyedPermutation => 3,
    }
}

pub(super) fn ranges_overlap(
    left_start: u64,
    left_length: u64,
    right_start: u64,
    right_length: u64,
) -> bool {
    left_start < right_start.saturating_add(right_length)
        && right_start < left_start.saturating_add(left_length)
}

pub(super) fn invalid(reason: &'static str) -> DeviceError {
    DeviceError::InvalidBlockFaultDirective { reason }
}
