//! Fixed-slot connection inode and semantic-identity maps.
//!
//! This module owns collision-safe node and semantic probing plus allocation
//! and rehash helpers shared by lookup, FORGET, and file-open transitions.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest, Sha256};

use super::{IndexNodeView, InodeError};

const SEMANTIC_HASH_DOMAIN: &[u8] = b"aos.filesystem-view.inode-semantic.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SemanticKey {
    Record(u64),
    Hardlink(ObjectDigest),
}

#[derive(Clone, Copy)]
pub(super) struct NodeEntry<'bytes> {
    pub(super) node_id: u64,
    pub(super) semantic: SemanticKey,
    pub(super) record: IndexNodeView<'bytes>,
    pub(super) lookup_references: u64,
    pub(super) open_pins: u64,
}

#[derive(Clone, Copy)]
pub(super) enum NodeSlot<'bytes> {
    Empty,
    Tombstone,
    Occupied(NodeEntry<'bytes>),
}

#[derive(Clone, Copy)]
pub(super) enum SemanticSlot {
    Empty,
    Tombstone,
    Occupied {
        hash: [u8; 32],
        key: SemanticKey,
        node_id: u64,
    },
}

pub(super) fn semantic_hash(connection_key: &[u8; 32], key: SemanticKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SEMANTIC_HASH_DOMAIN);
    hash.update(connection_key);
    match key {
        SemanticKey::Record(record) => {
            hash.update([0]);
            hash.update(record.to_le_bytes());
        }
        SemanticKey::Hardlink(group) => {
            hash.update([1]);
            hash.update(group.as_bytes());
        }
    }
    hash.finalize().into()
}

pub(super) fn allocate_node_slots(capacity: usize) -> Result<Vec<NodeSlot<'static>>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, NodeSlot::Empty);
    Ok(slots)
}

pub(super) fn allocate_semantic_slots(capacity: usize) -> Result<Vec<SemanticSlot>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, SemanticSlot::Empty);
    Ok(slots)
}

pub(super) fn node_bucket(node_id: u64, capacity: usize) -> usize {
    let mut value = node_id;
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    value as usize & (capacity - 1)
}

pub(super) fn semantic_bucket(hash: &[u8; 32], capacity: usize) -> usize {
    let prefix = u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]));
    prefix as usize & (capacity - 1)
}

pub(super) fn find_node(slots: &[NodeSlot<'_>], node_id: u64) -> Option<usize> {
    let mut position = node_bucket(node_id, slots.len());
    for _ in 0..slots.len() {
        match slots[position] {
            NodeSlot::Empty => return None,
            NodeSlot::Occupied(entry) if entry.node_id == node_id => return Some(position),
            NodeSlot::Tombstone | NodeSlot::Occupied(_) => {
                position = (position + 1) & (slots.len() - 1);
            }
        }
    }
    None
}

pub(super) fn find_node_insert(slots: &[NodeSlot<'_>], node_id: u64) -> Result<usize, InodeError> {
    let mut position = node_bucket(node_id, slots.len());
    let mut tombstone = None;
    for _ in 0..slots.len() {
        match slots[position] {
            NodeSlot::Empty => return Ok(tombstone.unwrap_or(position)),
            NodeSlot::Tombstone => tombstone.get_or_insert(position),
            NodeSlot::Occupied(entry) if entry.node_id == node_id => {
                return Err(InodeError::InternalInvariant);
            }
            NodeSlot::Occupied(_) => &mut position,
        };
        position = (position + 1) & (slots.len() - 1);
    }
    tombstone.ok_or(InodeError::InternalInvariant)
}

pub(super) fn find_semantic(
    slots: &[SemanticSlot],
    hash: &[u8; 32],
    key: SemanticKey,
) -> Option<u64> {
    find_semantic_slot(slots, hash, key).and_then(|slot| match slots[slot] {
        SemanticSlot::Occupied { node_id, .. } => Some(node_id),
        SemanticSlot::Empty | SemanticSlot::Tombstone => None,
    })
}

pub(super) fn find_semantic_slot(
    slots: &[SemanticSlot],
    hash: &[u8; 32],
    key: SemanticKey,
) -> Option<usize> {
    let mut position = semantic_bucket(hash, slots.len());
    for _ in 0..slots.len() {
        match slots[position] {
            SemanticSlot::Empty => return None,
            SemanticSlot::Occupied {
                hash: candidate,
                key: candidate_key,
                ..
            } if candidate == *hash && candidate_key == key => return Some(position),
            SemanticSlot::Tombstone | SemanticSlot::Occupied { .. } => {
                position = (position + 1) & (slots.len() - 1);
            }
        }
    }
    None
}

pub(super) fn find_semantic_insert(
    slots: &[SemanticSlot],
    hash: &[u8; 32],
    key: SemanticKey,
) -> Result<usize, InodeError> {
    let mut position = semantic_bucket(hash, slots.len());
    let mut tombstone = None;
    for _ in 0..slots.len() {
        match slots[position] {
            SemanticSlot::Empty => return Ok(tombstone.unwrap_or(position)),
            SemanticSlot::Tombstone => {
                tombstone.get_or_insert(position);
            }
            SemanticSlot::Occupied {
                hash: candidate,
                key: candidate_key,
                ..
            } if candidate == *hash && candidate_key == key => {
                return Err(InodeError::InternalInvariant);
            }
            SemanticSlot::Occupied { .. } => {}
        }
        position = (position + 1) & (slots.len() - 1);
    }
    tombstone.ok_or(InodeError::InternalInvariant)
}

pub(super) fn rehash_nodes<'bytes>(
    old: &[NodeSlot<'bytes>],
    new: &mut [NodeSlot<'bytes>],
) -> Result<(), InodeError> {
    for slot in old {
        if let NodeSlot::Occupied(entry) = slot {
            let position = find_node_insert(new, entry.node_id)?;
            new[position] = NodeSlot::Occupied(*entry);
        }
    }
    Ok(())
}

pub(super) fn rehash_semantics(
    old: &[SemanticSlot],
    new: &mut [SemanticSlot],
) -> Result<(), InodeError> {
    for slot in old {
        if let SemanticSlot::Occupied { hash, key, node_id } = slot {
            let position = find_semantic_insert(new, hash, *key)?;
            new[position] = SemanticSlot::Occupied {
                hash: *hash,
                key: *key,
                node_id: *node_id,
            };
        }
    }
    Ok(())
}
