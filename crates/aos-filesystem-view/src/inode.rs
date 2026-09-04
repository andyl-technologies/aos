//! Connection-scoped lazy inode identity over an immutable V2 index.
//!
//! The table assigns monotonically increasing, never-reused node IDs as a
//! connection observes records. Two fixed-slot open-addressed tables map node
//! IDs and semantic identities without relying on unaccounted `HashMap`
//! growth. File records in one validated hard-link group share an inode;
//! records without a hard-link group remain distinct.
//!
//! Heap admission precharges the requested slot layouts and, while growing or
//! compacting, both old arrays and both replacements. The capacity actually
//! returned by `Vec` is checked before state is committed. An allocator may
//! transiently reserve more than requested for one allocation before its
//! capacity can be observed; no subsequent allocation is attempted until that
//! capacity is charged. Allocator metadata and size-class rounding remain
//! unknowable here, so callers must place the serving process in a cgroup
//! memory boundary as the final backstop. This module owns no open handles or
//! kernel inode lifetime.

use std::mem::size_of;

use aos_sandbox_core::{ObjectDigest, PathName};
use sha2::{Digest, Sha256};

use crate::{IndexError, IndexNodeKind, IndexNodeView, ValidatedIndex};

const INITIAL_CAPACITY: usize = 2;
const SEMANTIC_HASH_DOMAIN: &[u8] = b"aos.filesystem-view.inode-semantic.v1\0";

/// Node ID permanently assigned to the connection's root inode.
pub const ROOT_NODE_ID: u64 = 1;

/// Hard ceilings for one connection-scoped inode table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeTableLimits {
    /// Maximum simultaneously retained nodes, including root.
    pub maximum_nodes: u64,
    /// Maximum modeled bytes in retained and replacement slot arrays.
    pub maximum_heap_bytes: u64,
    /// Maximum lookup references retained across the complete connection.
    pub maximum_lookup_references: u64,
    /// Maximum entries accepted in one failure-atomic FORGET batch.
    pub maximum_forget_batch: usize,
}

impl InodeTableLimits {
    /// Creates explicit inode-table resource ceilings.
    #[must_use]
    pub const fn new(
        maximum_nodes: u64,
        maximum_heap_bytes: u64,
        maximum_lookup_references: u64,
        maximum_forget_batch: usize,
    ) -> Self {
        Self {
            maximum_nodes,
            maximum_heap_bytes,
            maximum_lookup_references,
            maximum_forget_batch,
        }
    }
}

/// Portable attributes returned by lookup and getattr.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeAttributes {
    /// Connection-scoped node ID.
    pub node_id: u64,
    /// Artifact-scoped structural-index record ID used for attributes.
    pub record_id: u64,
    /// Portable node kind.
    pub kind: IndexNodeKind,
    /// Portable permission and executable bits.
    pub mode: u16,
    /// Portable owner UID.
    pub uid: u32,
    /// Portable owner GID.
    pub gid: u32,
    /// Normalized modification-time seconds.
    pub mtime_seconds: i64,
    /// Normalized modification-time nanoseconds.
    pub mtime_nanos: u32,
}

/// Result of one byte-exact child lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeLookup {
    /// The immutable index contains no such child; table state is unchanged.
    Negative,
    /// The child exists and now holds the reported lookup-reference count.
    Positive {
        /// Portable attributes and assigned node ID.
        attributes: InodeAttributes,
        /// Lookup references retained for this node after the operation.
        lookup_references: u64,
    },
}

/// Summarizes a successfully applied FORGET batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetSummary {
    /// Number of distinct node IDs changed.
    pub nodes_changed: u64,
    /// Number of non-root inode entries evicted.
    pub nodes_evicted: u64,
    /// Total lookup references released.
    pub references_released: u64,
}

/// Requests release of lookup references for one connection-scoped node ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetRequest {
    /// Node ID whose lookup references should be released.
    pub node_id: u64,
    /// Nonzero number of lookup references to release.
    pub lookup_references: u64,
    node_slot: usize,
    semantic_slot: usize,
    remaining_references: u64,
}

impl ForgetRequest {
    /// Creates one FORGET item.
    #[must_use]
    pub const fn new(node_id: u64, lookup_references: u64) -> Self {
        Self {
            node_id,
            lookup_references,
            node_slot: usize::MAX,
            semantic_slot: usize::MAX,
            remaining_references: 0,
        }
    }
}

/// Reports inode-table admission, identity, or index failure.
#[derive(Debug, thiserror::Error)]
pub enum InodeError {
    /// The immutable structural index rejected an operation.
    #[error("inode index operation failed: {0}")]
    Index(#[from] IndexError),
    /// A configured node, heap, reference, or batch ceiling was exceeded.
    #[error("inode table exceeds the configured {0} ceiling")]
    LimitExceeded(&'static str),
    /// A pre-admitted fixed-slot allocation was refused.
    #[error("inode table allocation was refused")]
    AllocationRefused,
    /// The node ID was never assigned or has already become stale.
    #[error("inode node ID is stale")]
    StaleNode,
    /// A child lookup used a non-directory parent.
    #[error("inode lookup parent is not a directory")]
    ParentNotDirectory,
    /// A FORGET item requested zero references.
    #[error("inode FORGET count must be nonzero")]
    ZeroForgetCount,
    /// A FORGET batch would release more references than are retained.
    #[error("inode FORGET count exceeds retained lookup references")]
    ForgetUnderflow,
    /// An internal fixed-table invariant was violated.
    #[error("inode table invariant violated")]
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticKey {
    Record(u64),
    Hardlink(ObjectDigest),
}

#[derive(Clone, Copy)]
struct NodeEntry<'bytes> {
    node_id: u64,
    semantic: SemanticKey,
    record: IndexNodeView<'bytes>,
    lookup_references: u64,
}

#[derive(Clone, Copy)]
enum NodeSlot<'bytes> {
    Empty,
    Tombstone,
    Occupied(NodeEntry<'bytes>),
}

#[derive(Clone, Copy)]
enum SemanticSlot {
    Empty,
    Tombstone,
    Occupied {
        hash: [u8; 32],
        key: SemanticKey,
        node_id: u64,
    },
}

/// Lazily assigns inode identities for one connection and one immutable index.
///
/// The caller supplies an opaque hashing key that must be unique per
/// connection and unpredictable to the untrusted tree producer. Key secrecy
/// prevents chosen semantic identities from clustering on the table's probe
/// bucket bits; exact semantic-key comparison independently preserves
/// correctness if full SHA-256 digests collide. The key must not be reused as
/// a public identifier. The table performs no randomness or persistence.
pub struct InodeTable<'index, 'bytes> {
    index: &'index ValidatedIndex<'bytes>,
    connection_key: [u8; 32],
    limits: InodeTableLimits,
    nodes: Vec<NodeSlot<'bytes>>,
    semantics: Vec<SemanticSlot>,
    live: usize,
    node_tombstones: usize,
    semantic_tombstones: usize,
    total_lookup_references: u64,
    next_node_id: u64,
    #[cfg(test)]
    rebuilds: u64,
}

impl<'index, 'bytes> InodeTable<'index, 'bytes> {
    /// Creates a table containing the pinned root with one lookup reference.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::Index`] for a validation-only V1 artifact,
    /// [`InodeError::LimitExceeded`] when root cannot be admitted, or
    /// [`InodeError::AllocationRefused`] when either initial table allocation
    /// fails.
    pub fn new(
        index: &'index ValidatedIndex<'bytes>,
        connection_key: [u8; 32],
        limits: InodeTableLimits,
    ) -> Result<Self, InodeError> {
        if !index.supports_point_lookup() {
            return Err(InodeError::Index(IndexError::PointLookupUnavailable));
        }
        if limits.maximum_nodes == 0
            || limits.maximum_lookup_references == 0
            || limits.maximum_forget_batch == 0
        {
            return Err(InodeError::LimitExceeded("count"));
        }
        let initial_heap = table_bytes(INITIAL_CAPACITY)?;
        if initial_heap > limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }

        let mut nodes = allocate_node_slots(INITIAL_CAPACITY)?;
        admit_second_allocation(
            0,
            slot_vector_bytes(&nodes)?,
            modeled_bytes::<SemanticSlot>(INITIAL_CAPACITY)?,
            limits.maximum_heap_bytes,
        )?;
        let mut semantics = allocate_semantic_slots(INITIAL_CAPACITY)?;
        let actual_heap = slot_vector_bytes(&nodes)?
            .checked_add(slot_vector_bytes(&semantics)?)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if actual_heap > limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }

        let root = index.retained_root()?;
        let semantic = SemanticKey::Record(root.record_id());
        let hash = semantic_hash(&connection_key, semantic);
        let node_slot = find_node_insert(&nodes, ROOT_NODE_ID)?;
        let semantic_slot = find_semantic_insert(&semantics, &hash, semantic)?;
        nodes[node_slot] = NodeSlot::Occupied(NodeEntry {
            node_id: ROOT_NODE_ID,
            semantic,
            record: root,
            lookup_references: 1,
        });
        semantics[semantic_slot] = SemanticSlot::Occupied {
            hash,
            key: semantic,
            node_id: ROOT_NODE_ID,
        };

        Ok(Self {
            index,
            connection_key,
            limits,
            nodes,
            semantics,
            live: 1,
            node_tombstones: 0,
            semantic_tombstones: 0,
            total_lookup_references: 1,
            next_node_id: ROOT_NODE_ID + 1,
            #[cfg(test)]
            rebuilds: 0,
        })
    }

    /// Returns the currently modeled retained slot-array bytes.
    #[must_use]
    pub fn heap_bytes(&self) -> u64 {
        slot_vector_bytes(&self.nodes)
            .and_then(|nodes| {
                nodes
                    .checked_add(slot_vector_bytes(&self.semantics)?)
                    .ok_or(InodeError::LimitExceeded("heap bytes"))
            })
            .unwrap_or(u64::MAX)
    }

    /// Returns the number of live inode entries, including root.
    #[must_use]
    pub fn live_nodes(&self) -> u64 {
        self.live as u64
    }

    /// Returns lookup references retained across the complete connection.
    #[must_use]
    pub const fn total_lookup_references(&self) -> u64 {
        self.total_lookup_references
    }

    /// Looks up a child and lazily assigns or reuses its inode identity.
    ///
    /// Negative lookup does not create retained state. Positive lookup either
    /// increments an existing inode reference or atomically admits both map
    /// entries for a new inode. Hard-link members coalesce by their validated
    /// portable group digest.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] for a stale or non-directory parent, index
    /// inconsistency, identifier exhaustion, a configured admission ceiling,
    /// or allocation refusal. Failure leaves semantic inode state unchanged.
    pub fn lookup(&mut self, parent: u64, name: &PathName) -> Result<InodeLookup, InodeError> {
        let parent_entry = self.node_entry(parent).ok_or(InodeError::StaleNode)?;
        if parent_entry.record.kind() != IndexNodeKind::Directory {
            return Err(InodeError::ParentNotDirectory);
        }
        let Some(record) = self
            .index
            .retained_lookup_child(&parent_entry.record, name)?
        else {
            return Ok(InodeLookup::Negative);
        };
        let semantic = semantic_key(&record)?;
        let hash = semantic_hash(&self.connection_key, semantic);
        if let Some(node_id) = find_semantic(&self.semantics, &hash, semantic) {
            let slot = find_node(&self.nodes, node_id).ok_or(InodeError::InternalInvariant)?;
            let NodeSlot::Occupied(mut entry) = self.nodes[slot] else {
                return Err(InodeError::InternalInvariant);
            };
            if entry.semantic != semantic {
                return Err(InodeError::InternalInvariant);
            }
            let next = entry
                .lookup_references
                .checked_add(1)
                .ok_or(InodeError::LimitExceeded("lookup references"))?;
            let next_total = self
                .total_lookup_references
                .checked_add(1)
                .ok_or(InodeError::LimitExceeded("lookup references"))?;
            if next_total > self.limits.maximum_lookup_references {
                return Err(InodeError::LimitExceeded("lookup references"));
            }
            entry.lookup_references = next;
            self.nodes[slot] = NodeSlot::Occupied(entry);
            self.total_lookup_references = next_total;
            return Ok(positive(entry));
        }

        self.insert_new(semantic, hash, record)
    }

    /// Returns attributes for a live node without changing lookup references.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::StaleNode`] if the node was never assigned or was
    /// evicted after its last lookup reference was forgotten.
    pub fn getattr(&self, node_id: u64) -> Result<InodeAttributes, InodeError> {
        self.node_entry(node_id)
            .map(attributes)
            .ok_or(InodeError::StaleNode)
    }

    /// Applies a bounded batch of lookup-reference releases atomically.
    ///
    /// The caller-owned batch is sorted in place and duplicate node IDs are
    /// coalesced into its prefix. Its order and contents may therefore change
    /// even when this method returns an error. The complete coalesced prefix is
    /// checked without allocation before any table count or map slot changes.
    /// Non-root nodes are evicted at zero references; root remains pinned even
    /// at zero.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] for an oversized batch, zero count, stale node,
    /// aggregate underflow, or arithmetic overflow. Failure changes nothing.
    pub fn forget(&mut self, batch: &mut [ForgetRequest]) -> Result<ForgetSummary, InodeError> {
        if batch.len() > self.limits.maximum_forget_batch {
            return Err(InodeError::LimitExceeded("FORGET batch"));
        }
        batch.sort_unstable_by_key(|item| item.node_id);
        let mut coalesced = 0_usize;
        for position in 0..batch.len() {
            let mut item = batch[position];
            item.node_slot = usize::MAX;
            item.semantic_slot = usize::MAX;
            item.remaining_references = 0;
            if item.lookup_references == 0 {
                return Err(InodeError::ZeroForgetCount);
            }
            if coalesced != 0 && batch[coalesced - 1].node_id == item.node_id {
                batch[coalesced - 1].lookup_references = batch[coalesced - 1]
                    .lookup_references
                    .checked_add(item.lookup_references)
                    .ok_or(InodeError::ForgetUnderflow)?;
            } else {
                batch[coalesced] = item;
                coalesced = coalesced
                    .checked_add(1)
                    .ok_or(InodeError::LimitExceeded("FORGET batch"))?;
            }
        }

        let mut summary = ForgetSummary {
            nodes_changed: 0,
            nodes_evicted: 0,
            references_released: 0,
        };
        for item in &mut batch[..coalesced] {
            let node_slot = find_node(&self.nodes, item.node_id).ok_or(InodeError::StaleNode)?;
            let NodeSlot::Occupied(entry) = self.nodes[node_slot] else {
                return Err(InodeError::InternalInvariant);
            };
            let retained = entry.lookup_references;
            if item.lookup_references > retained {
                return Err(InodeError::ForgetUnderflow);
            }
            item.node_slot = node_slot;
            item.remaining_references = retained
                .checked_sub(item.lookup_references)
                .ok_or(InodeError::ForgetUnderflow)?;
            summary.nodes_changed = summary
                .nodes_changed
                .checked_add(1)
                .ok_or(InodeError::ForgetUnderflow)?;
            summary.references_released = summary
                .references_released
                .checked_add(item.lookup_references)
                .ok_or(InodeError::ForgetUnderflow)?;
            if retained == item.lookup_references && item.node_id != ROOT_NODE_ID {
                let hash = semantic_hash(&self.connection_key, entry.semantic);
                let semantic_slot = find_semantic_slot(&self.semantics, &hash, entry.semantic)
                    .ok_or(InodeError::InternalInvariant)?;
                if !matches!(
                    self.semantics[semantic_slot],
                    SemanticSlot::Occupied { node_id, .. } if node_id == item.node_id
                ) {
                    return Err(InodeError::InternalInvariant);
                }
                item.semantic_slot = semantic_slot;
                summary.nodes_evicted = summary
                    .nodes_evicted
                    .checked_add(1)
                    .ok_or(InodeError::ForgetUnderflow)?;
            }
        }
        let next_total = self
            .total_lookup_references
            .checked_sub(summary.references_released)
            .ok_or(InodeError::InternalInvariant)?;
        let evicted =
            usize::try_from(summary.nodes_evicted).map_err(|_| InodeError::InternalInvariant)?;
        let next_live = self
            .live
            .checked_sub(evicted)
            .ok_or(InodeError::InternalInvariant)?;
        let next_node_tombstones = self
            .node_tombstones
            .checked_add(evicted)
            .ok_or(InodeError::InternalInvariant)?;
        let next_semantic_tombstones = self
            .semantic_tombstones
            .checked_add(evicted)
            .ok_or(InodeError::InternalInvariant)?;

        for item in &batch[..coalesced] {
            if item.semantic_slot != usize::MAX {
                self.nodes[item.node_slot] = NodeSlot::Tombstone;
                self.semantics[item.semantic_slot] = SemanticSlot::Tombstone;
            } else if let NodeSlot::Occupied(entry) = &mut self.nodes[item.node_slot] {
                entry.lookup_references = item.remaining_references;
            }
        }
        self.total_lookup_references = next_total;
        self.live = next_live;
        self.node_tombstones = next_node_tombstones;
        self.semantic_tombstones = next_semantic_tombstones;
        Ok(summary)
    }

    fn insert_new(
        &mut self,
        semantic: SemanticKey,
        hash: [u8; 32],
        record: IndexNodeView<'bytes>,
    ) -> Result<InodeLookup, InodeError> {
        if self.live as u64 >= self.limits.maximum_nodes {
            return Err(InodeError::LimitExceeded("nodes"));
        }
        let node_id = self.next_node_id;
        let next_node_id = node_id
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("node IDs"))?;
        let entry = NodeEntry {
            node_id,
            semantic,
            record,
            lookup_references: 1,
        };
        let next_live = self
            .live
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("nodes"))?;
        let next_total = self
            .total_lookup_references
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("lookup references"))?;
        if next_total > self.limits.maximum_lookup_references {
            return Err(InodeError::LimitExceeded("lookup references"));
        }

        let node_slot = find_node_insert(&self.nodes, node_id)?;
        let semantic_slot = find_semantic_insert(&self.semantics, &hash, semantic)?;
        let reuses_node_tombstone = matches!(self.nodes[node_slot], NodeSlot::Tombstone);
        let reuses_semantic_tombstone =
            matches!(self.semantics[semantic_slot], SemanticSlot::Tombstone);

        if let Some(target) =
            self.rebuild_capacity(next_live, reuses_node_tombstone, reuses_semantic_tombstone)?
        {
            let replacement_bytes = table_bytes(target)?;
            let peak = self
                .heap_bytes()
                .checked_add(replacement_bytes)
                .ok_or(InodeError::LimitExceeded("heap bytes"))?;
            if peak > self.limits.maximum_heap_bytes {
                return Err(InodeError::LimitExceeded("heap bytes"));
            }
            let mut nodes = allocate_node_slots(target)?;
            admit_second_allocation(
                self.heap_bytes(),
                slot_vector_bytes(&nodes)?,
                modeled_bytes::<SemanticSlot>(target)?,
                self.limits.maximum_heap_bytes,
            )?;
            let mut semantics = allocate_semantic_slots(target)?;
            let actual_replacement = slot_vector_bytes(&nodes)?
                .checked_add(slot_vector_bytes(&semantics)?)
                .ok_or(InodeError::LimitExceeded("heap bytes"))?;
            let actual_peak = self
                .heap_bytes()
                .checked_add(actual_replacement)
                .ok_or(InodeError::LimitExceeded("heap bytes"))?;
            if actual_peak > self.limits.maximum_heap_bytes {
                return Err(InodeError::LimitExceeded("heap bytes"));
            }
            rehash_nodes(&self.nodes, &mut nodes)?;
            rehash_semantics(&self.semantics, &mut semantics)?;
            let node_slot = find_node_insert(&nodes, node_id)?;
            let semantic_slot = find_semantic_insert(&semantics, &hash, semantic)?;
            nodes[node_slot] = NodeSlot::Occupied(entry);
            semantics[semantic_slot] = SemanticSlot::Occupied {
                hash,
                key: semantic,
                node_id,
            };
            self.nodes = nodes;
            self.semantics = semantics;
            self.node_tombstones = 0;
            self.semantic_tombstones = 0;
            #[cfg(test)]
            {
                self.rebuilds = self.rebuilds.saturating_add(1);
            }
        } else {
            let next_node_tombstones = if reuses_node_tombstone {
                self.node_tombstones
                    .checked_sub(1)
                    .ok_or(InodeError::InternalInvariant)?
            } else {
                self.node_tombstones
            };
            let next_semantic_tombstones = if reuses_semantic_tombstone {
                self.semantic_tombstones
                    .checked_sub(1)
                    .ok_or(InodeError::InternalInvariant)?
            } else {
                self.semantic_tombstones
            };
            self.nodes[node_slot] = NodeSlot::Occupied(entry);
            self.semantics[semantic_slot] = SemanticSlot::Occupied {
                hash,
                key: semantic,
                node_id,
            };
            self.node_tombstones = next_node_tombstones;
            self.semantic_tombstones = next_semantic_tombstones;
        }
        self.live = next_live;
        self.total_lookup_references = next_total;
        self.next_node_id = next_node_id;
        Ok(positive(entry))
    }

    fn rebuild_capacity(
        &self,
        next_live: usize,
        reuses_node_tombstone: bool,
        reuses_semantic_tombstone: bool,
    ) -> Result<Option<usize>, InodeError> {
        if next_live > self.nodes.len() / 2 {
            return self
                .nodes
                .len()
                .checked_mul(2)
                .map(Some)
                .ok_or(InodeError::LimitExceeded("nodes"));
        }
        let node_occupancy = self
            .live
            .checked_add(self.node_tombstones)
            .and_then(|value| value.checked_add(usize::from(!reuses_node_tombstone)))
            .ok_or(InodeError::LimitExceeded("nodes"))?;
        let semantic_occupancy = self
            .live
            .checked_add(self.semantic_tombstones)
            .and_then(|value| value.checked_add(usize::from(!reuses_semantic_tombstone)))
            .ok_or(InodeError::LimitExceeded("nodes"))?;
        let compaction_threshold = self.nodes.len() - self.nodes.len() / 4;
        Ok(
            (node_occupancy > compaction_threshold || semantic_occupancy > compaction_threshold)
                .then_some(self.nodes.len()),
        )
    }

    fn node_entry(&self, node_id: u64) -> Option<NodeEntry<'bytes>> {
        find_node(&self.nodes, node_id).and_then(|slot| match self.nodes[slot] {
            NodeSlot::Occupied(entry) => Some(entry),
            NodeSlot::Empty | NodeSlot::Tombstone => None,
        })
    }
}

fn semantic_key(record: &IndexNodeView<'_>) -> Result<SemanticKey, IndexError> {
    Ok(match record.hardlink_group()? {
        Some(group) => SemanticKey::Hardlink(group),
        None => SemanticKey::Record(record.record_id()),
    })
}

fn positive(entry: NodeEntry<'_>) -> InodeLookup {
    InodeLookup::Positive {
        attributes: attributes(entry),
        lookup_references: entry.lookup_references,
    }
}

fn attributes(entry: NodeEntry<'_>) -> InodeAttributes {
    InodeAttributes {
        node_id: entry.node_id,
        record_id: entry.record.record_id(),
        kind: entry.record.kind(),
        mode: entry.record.mode(),
        uid: entry.record.uid(),
        gid: entry.record.gid(),
        mtime_seconds: entry.record.mtime_seconds(),
        mtime_nanos: entry.record.mtime_nanos(),
    }
}

fn semantic_hash(connection_key: &[u8; 32], key: SemanticKey) -> [u8; 32] {
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

fn table_bytes(capacity: usize) -> Result<u64, InodeError> {
    modeled_bytes::<NodeSlot<'static>>(capacity)?
        .checked_add(modeled_bytes::<SemanticSlot>(capacity)?)
        .ok_or(InodeError::LimitExceeded("heap bytes"))
}

fn modeled_bytes<T>(capacity: usize) -> Result<u64, InodeError> {
    capacity
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(InodeError::LimitExceeded("heap bytes"))
}

fn admit_second_allocation(
    retained: u64,
    first_actual: u64,
    second_requested: u64,
    maximum: u64,
) -> Result<(), InodeError> {
    let peak = retained
        .checked_add(first_actual)
        .and_then(|value| value.checked_add(second_requested))
        .ok_or(InodeError::LimitExceeded("heap bytes"))?;
    if peak > maximum {
        Err(InodeError::LimitExceeded("heap bytes"))
    } else {
        Ok(())
    }
}

fn slot_vector_bytes<T>(slots: &Vec<T>) -> Result<u64, InodeError> {
    modeled_bytes::<T>(slots.capacity())
}

fn allocate_node_slots(capacity: usize) -> Result<Vec<NodeSlot<'static>>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, NodeSlot::Empty);
    Ok(slots)
}

fn allocate_semantic_slots(capacity: usize) -> Result<Vec<SemanticSlot>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, SemanticSlot::Empty);
    Ok(slots)
}

fn node_bucket(node_id: u64, capacity: usize) -> usize {
    let mut value = node_id;
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    value as usize & (capacity - 1)
}

fn semantic_bucket(hash: &[u8; 32], capacity: usize) -> usize {
    let prefix = u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]));
    prefix as usize & (capacity - 1)
}

fn find_node(slots: &[NodeSlot<'_>], node_id: u64) -> Option<usize> {
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

fn find_node_insert(slots: &[NodeSlot<'_>], node_id: u64) -> Result<usize, InodeError> {
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

fn find_semantic(slots: &[SemanticSlot], hash: &[u8; 32], key: SemanticKey) -> Option<u64> {
    find_semantic_slot(slots, hash, key).and_then(|slot| match slots[slot] {
        SemanticSlot::Occupied { node_id, .. } => Some(node_id),
        SemanticSlot::Empty | SemanticSlot::Tombstone => None,
    })
}

fn find_semantic_slot(slots: &[SemanticSlot], hash: &[u8; 32], key: SemanticKey) -> Option<usize> {
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

fn find_semantic_insert(
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

fn rehash_nodes<'bytes>(
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

fn rehash_semantics(old: &[SemanticSlot], new: &mut [SemanticSlot]) -> Result<(), InodeError> {
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

#[cfg(test)]
mod tests {
    use std::io::Cursor as IoCursor;

    use aos_sandbox_core::model::{ContentLayout, FilesystemMetadata};
    use aos_sandbox_core::{
        MediaType, ObjectDescriptor, PathName, RelativePath, descriptor_for_bytes,
        hardlink_group_digest,
    };

    use super::*;
    use crate::index::{IndexNode, IndexRecord, StructuralIndexBuilder};
    use crate::{INDEX_MEDIA_TYPE_V2, IndexExpectation, IndexStaging, validate_index};

    struct Fixture {
        bytes: Vec<u8>,
        tree: ObjectDescriptor,
        root: ObjectDescriptor,
    }

    impl Fixture {
        fn validate(&self) -> ValidatedIndex<'_> {
            let media = MediaType::new(INDEX_MEDIA_TYPE_V2)
                .unwrap_or_else(|error| panic!("media failed: {error}"));
            let descriptor = descriptor_for_bytes(media, &self.bytes);
            validate_index(
                &self.bytes,
                16 * 1024,
                1_048_576,
                &IndexExpectation {
                    index: &descriptor,
                    compiler_abi: [7; 32],
                    tree: &self.tree,
                    root: &self.root,
                    tree_features: 0,
                },
            )
            .unwrap_or_else(|error| panic!("validation failed: {error}"))
        }
    }

    fn fixture() -> Fixture {
        let tree = descriptor("application/vnd.aos.sandbox.tree.v1+cbor", [1; 32]);
        let root = descriptor("application/vnd.aos.sandbox.directory.v1+cbor", [2; 32]);
        let content_descriptor = descriptor("application/vnd.aos.sandbox.content.v1", [3; 32]);
        let content = ContentLayout::whole(content_descriptor);
        let directory_metadata = FilesystemMetadata::new(0o755, 10, 20, 30, 40, Vec::new(), None)
            .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let file_metadata = FilesystemMetadata::new(0o644, 11, 21, 31, 41, Vec::new(), None)
            .unwrap_or_else(|error| panic!("metadata failed: {error}"));
        let paths = [b"a".as_slice(), b"b".as_slice()]
            .into_iter()
            .map(|name| {
                RelativePath::new(vec![
                    PathName::new(name.to_vec())
                        .unwrap_or_else(|error| panic!("name failed: {error}")),
                ])
                .unwrap_or_else(|error| panic!("path failed: {error}"))
            })
            .collect::<Vec<_>>();
        let hardlink = hardlink_group_digest(&paths, &file_metadata, &content)
            .unwrap_or_else(|error| panic!("hardlink failed: {error}"));
        let staging = IndexStaging::new(IoCursor::new(Vec::new()), 16 * 1024, 4096);
        let mut builder =
            StructuralIndexBuilder::new(staging, [7; 32], tree.clone(), root.clone(), 0)
                .unwrap_or_else(|error| panic!("builder failed: {error}"));
        builder
            .push(&IndexRecord {
                parent: u64::MAX,
                depth: 0,
                sibling_ordinal: 0,
                name: &[],
                metadata: &directory_metadata,
                node: IndexNode::Directory { descriptor: &root },
            })
            .unwrap_or_else(|error| panic!("root push failed: {error}"));
        for (ordinal, name) in [b"a".as_slice(), b"b".as_slice()].into_iter().enumerate() {
            builder
                .push(&IndexRecord {
                    parent: 0,
                    depth: 1,
                    sibling_ordinal: ordinal as u32,
                    name,
                    metadata: &file_metadata,
                    node: IndexNode::File {
                        content: &content,
                        hardlink_group: Some(hardlink),
                    },
                })
                .unwrap_or_else(|error| panic!("hardlink push failed: {error}"));
        }
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: 2,
                name: b"c",
                metadata: &file_metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: None,
                },
            })
            .unwrap_or_else(|error| panic!("file push failed: {error}"));
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: 3,
                name: b"d",
                metadata: &file_metadata,
                node: IndexNode::File {
                    content: &content,
                    hardlink_group: None,
                },
            })
            .unwrap_or_else(|error| panic!("file push failed: {error}"));
        let (writer, _) = builder
            .finish()
            .unwrap_or_else(|error| panic!("finish failed: {error}"))
            .into_parts();
        Fixture {
            bytes: writer.into_inner(),
            tree,
            root,
        }
    }

    fn descriptor(media: &str, digest: [u8; 32]) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(media).unwrap_or_else(|error| panic!("media failed: {error}")),
            ObjectDigest::from_bytes(digest),
            0,
        )
    }

    fn generous_limits() -> InodeTableLimits {
        InodeTableLimits::new(32, 1_048_576, 16, 16)
    }

    fn name(value: &[u8]) -> PathName {
        PathName::new(value.to_vec()).unwrap_or_else(|error| panic!("name failed: {error}"))
    }

    fn positive_parts(value: InodeLookup) -> (InodeAttributes, u64) {
        match value {
            InodeLookup::Positive {
                attributes,
                lookup_references,
            } => (attributes, lookup_references),
            InodeLookup::Negative => panic!("expected positive lookup"),
        }
    }

    #[test]
    fn root_getattr_and_negative_lookup_do_not_grow_state() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [9; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let root = table
            .getattr(ROOT_NODE_ID)
            .unwrap_or_else(|error| panic!("getattr failed: {error}"));
        assert_eq!(root.record_id, 0);
        assert_eq!(root.kind, IndexNodeKind::Directory);
        assert_eq!(table.live_nodes(), 1);
        table
            .forget(&mut [ForgetRequest::new(ROOT_NODE_ID, 1)])
            .unwrap_or_else(|error| panic!("root forget failed: {error}"));
        assert_eq!(table.total_lookup_references(), 0);
        assert!(table.getattr(ROOT_NODE_ID).is_ok());
        assert!(matches!(
            table.lookup(ROOT_NODE_ID, &name(b"a")),
            Ok(InodeLookup::Positive { .. })
        ));
        assert_eq!(
            table
                .lookup(ROOT_NODE_ID, &name(b"missing"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
            InodeLookup::Negative
        );
        assert_eq!(table.live_nodes(), 2);
    }

    #[test]
    fn hardlinks_coalesce_and_evicted_ids_are_never_reused() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [4; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (first, first_refs) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"a"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let (second, second_refs) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"b"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert_eq!(first.node_id, second.node_id);
        assert_eq!((first_refs, second_refs), (1, 2));
        assert_eq!(table.total_lookup_references(), 3);
        assert_eq!(table.live_nodes(), 2);

        let summary = table
            .forget(&mut [
                ForgetRequest::new(first.node_id, 1),
                ForgetRequest::new(first.node_id, 1),
            ])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        assert_eq!(summary.nodes_evicted, 1);
        assert_eq!(table.total_lookup_references(), 1);
        assert!(matches!(
            table.getattr(first.node_id),
            Err(InodeError::StaleNode)
        ));
        let (replacement, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"a"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert!(replacement.node_id > first.node_id);
    }

    #[test]
    fn forget_batch_preflight_is_all_or_nothing() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [5; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (a, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"a"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let (c, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert!(matches!(
            table.forget(&mut [
                ForgetRequest::new(a.node_id, 1),
                ForgetRequest::new(c.node_id, 2),
            ]),
            Err(InodeError::ForgetUnderflow)
        ));
        assert_eq!(table.total_lookup_references(), 3);
        assert!(matches!(
            table.getattr(a.node_id),
            Ok(value) if value.node_id == a.node_id
        ));
        assert!(matches!(
            table.getattr(c.node_id),
            Ok(value) if value.node_id == c.node_id
        ));
        assert!(matches!(
            table.forget(&mut [ForgetRequest::new(a.node_id, 0)]),
            Err(InodeError::ZeroForgetCount)
        ));
        assert!(matches!(
            table.forget(&mut [ForgetRequest::new(u64::MAX, 1)]),
            Err(InodeError::StaleNode)
        ));
        table.limits.maximum_forget_batch = 1;
        assert!(matches!(
            table.forget(&mut [
                ForgetRequest::new(a.node_id, 1),
                ForgetRequest::new(c.node_id, 1),
            ]),
            Err(InodeError::LimitExceeded("FORGET batch"))
        ));
        assert_eq!(table.total_lookup_references(), 3);
    }

    #[test]
    fn non_directory_parent_is_refused_and_ungrouped_records_stay_distinct() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [11; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (c, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let (d, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"d"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert_ne!(c.node_id, d.node_id);
        assert_eq!(c.mode, d.mode);
        assert!(matches!(
            table.lookup(c.node_id, &name(b"child")),
            Err(InodeError::ParentNotDirectory)
        ));
        assert_eq!(table.total_lookup_references(), 3);
    }

    #[test]
    fn growth_peak_and_reference_limits_fail_without_partial_identity() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut count_limited =
            InodeTable::new(&index, [6; 32], InodeTableLimits::new(1, 1_048_576, 8, 8))
                .unwrap_or_else(|error| panic!("table failed: {error}"));
        assert!(matches!(
            count_limited.lookup(ROOT_NODE_ID, &name(b"a")),
            Err(InodeError::LimitExceeded("nodes"))
        ));
        assert_eq!(count_limited.live_nodes(), 1);
        assert_eq!(count_limited.total_lookup_references(), 1);

        let mut exact_boundary =
            InodeTable::new(&index, [6; 32], InodeTableLimits::new(2, 1_048_576, 8, 8))
                .unwrap_or_else(|error| panic!("table failed: {error}"));
        assert!(matches!(
            exact_boundary.lookup(ROOT_NODE_ID, &name(b"a")),
            Ok(InodeLookup::Positive { .. })
        ));
        assert_eq!(exact_boundary.live_nodes(), 2);
        assert!(matches!(
            exact_boundary.lookup(ROOT_NODE_ID, &name(b"c")),
            Err(InodeError::LimitExceeded("nodes"))
        ));
        assert_eq!(exact_boundary.live_nodes(), 2);

        let initial_heap = table_bytes(INITIAL_CAPACITY)
            .unwrap_or_else(|error| panic!("accounting failed: {error}"));
        let limits = InodeTableLimits::new(8, initial_heap, 8, 8);
        let mut table = InodeTable::new(&index, [6; 32], limits)
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        assert!(matches!(
            table.lookup(ROOT_NODE_ID, &name(b"a")),
            Err(InodeError::LimitExceeded("heap bytes"))
        ));
        assert_eq!(table.live_nodes(), 1);
        assert!(matches!(table.getattr(2), Err(InodeError::StaleNode)));

        let mut id_exhausted = InodeTable::new(&index, [6; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        id_exhausted.next_node_id = u64::MAX;
        assert!(matches!(
            id_exhausted.lookup(ROOT_NODE_ID, &name(b"a")),
            Err(InodeError::LimitExceeded("node IDs"))
        ));
        assert_eq!(id_exhausted.live_nodes(), 1);
        assert_eq!(id_exhausted.total_lookup_references(), 1);

        let reference_limits = InodeTableLimits::new(8, 1_048_576, 2, 8);
        let mut table = InodeTable::new(&index, [6; 32], reference_limits)
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (a, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"a"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert!(matches!(
            table.lookup(ROOT_NODE_ID, &name(b"b")),
            Err(InodeError::LimitExceeded("lookup references"))
        ));
        assert_eq!(table.total_lookup_references(), 2);
        table
            .forget(&mut [ForgetRequest::new(a.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        assert!(matches!(
            table.getattr(a.node_id),
            Err(InodeError::StaleNode)
        ));
    }

    #[test]
    fn tombstone_churn_compacts_with_monotonic_ids() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [8; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (first, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        table
            .forget(&mut [ForgetRequest::new(first.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        let retained_heap = table.heap_bytes();
        table.limits.maximum_heap_bytes = retained_heap;
        let rebuilds = table.rebuilds;
        let (second, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup under retained heap failed: {error}")),
        );
        assert_eq!(table.rebuilds, rebuilds);
        table
            .forget(&mut [ForgetRequest::new(second.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));

        table.limits.maximum_heap_bytes = generous_limits().maximum_heap_bytes;
        let mut previous = second.node_id;
        let rebuilds_before = table.rebuilds;
        for _ in 0..32 {
            let (entry, _) = positive_parts(
                table
                    .lookup(ROOT_NODE_ID, &name(b"c"))
                    .unwrap_or_else(|error| panic!("lookup failed: {error}")),
            );
            assert!(entry.node_id > previous);
            previous = entry.node_id;
            assert!(table.live <= table.nodes.len() / 2);
            assert!(table.live + table.node_tombstones <= table.nodes.len() * 3 / 4);
            assert!(table.live + table.semantic_tombstones <= table.nodes.len() * 3 / 4);
            table
                .forget(&mut [ForgetRequest::new(entry.node_id, 1)])
                .unwrap_or_else(|error| panic!("forget failed: {error}"));
            assert_eq!(table.live_nodes(), 1);
        }
        assert!(table.rebuilds - rebuilds_before < 32);
    }

    #[test]
    fn duplicate_overflow_and_reverse_map_corruption_fail_before_mutation() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [10; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (a, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"a"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert!(matches!(
            table.forget(&mut [
                ForgetRequest::new(a.node_id, u64::MAX),
                ForgetRequest::new(a.node_id, 1),
            ]),
            Err(InodeError::ForgetUnderflow)
        ));
        assert_eq!(table.total_lookup_references(), 2);

        let semantic = table
            .node_entry(a.node_id)
            .unwrap_or_else(|| panic!("node missing"))
            .semantic;
        let hash = semantic_hash(&table.connection_key, semantic);
        let semantic_slot = find_semantic_slot(&table.semantics, &hash, semantic)
            .unwrap_or_else(|| panic!("semantic missing"));
        table.semantics[semantic_slot] = SemanticSlot::Tombstone;
        assert!(matches!(
            table.forget(&mut [
                ForgetRequest::new(ROOT_NODE_ID, 1),
                ForgetRequest::new(a.node_id, 1),
            ]),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.total_lookup_references(), 2);
        assert_eq!(
            table
                .node_entry(ROOT_NODE_ID)
                .map(|entry| entry.lookup_references),
            Some(1)
        );
        assert_eq!(
            table
                .node_entry(a.node_id)
                .map(|entry| entry.lookup_references),
            Some(1)
        );
    }

    #[test]
    fn actual_first_capacity_is_charged_before_second_allocation() {
        assert!(admit_second_allocation(100, 80, 40, 220).is_ok());
        assert!(matches!(
            admit_second_allocation(100, 81, 40, 220),
            Err(InodeError::LimitExceeded("heap bytes"))
        ));
        assert!(matches!(
            admit_second_allocation(u64::MAX, 1, 1, u64::MAX),
            Err(InodeError::LimitExceeded("heap bytes"))
        ));
    }
}
