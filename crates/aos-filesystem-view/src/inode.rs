//! Connection-scoped lazy inode identity over an immutable V2 or V3 index.
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
//! memory boundary as the final backstop. A third fixed-slot table owns
//! backend-neutral pending and active open identities; it deliberately owns no
//! OS descriptor or FUSE framing.

use std::mem::size_of;

use aos_sandbox_core::PathName;

use crate::{
    DirectoryRange, IndexError, IndexNodeKind, IndexNodeSemantics, IndexNodeView, ValidatedIndex,
};

mod directory;
mod identity;
mod open;

pub use directory::{
    DirectoryCookie, DirectoryHandleId, DirectoryHandleLimits, DirectoryReadEntries,
    DirectoryReadEntry, DirectoryReadKind, DirectoryReservation,
};
use directory::{DirectorySlot, find_directory};
use identity::{
    NodeEntry, NodeSlot, SemanticKey, SemanticSlot, allocate_node_slots, allocate_semantic_slots,
    find_node, find_node_insert, find_semantic, find_semantic_insert, find_semantic_slot,
    node_bucket, rehash_nodes, rehash_semantics, semantic_hash,
};
pub use open::{OpenHandleId, OpenReservation};
use open::{OpenSlot, find_open};
#[cfg(test)]
use open::{allocate_open_slots, open_bucket};

const INITIAL_CAPACITY: usize = 2;

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
    /// Maximum pending and active opens retained across the connection.
    pub maximum_open_handles: u64,
}

impl InodeTableLimits {
    /// Creates explicit inode-table resource ceilings.
    #[must_use]
    pub const fn new(
        maximum_nodes: u64,
        maximum_heap_bytes: u64,
        maximum_lookup_references: u64,
        maximum_forget_batch: usize,
        maximum_open_handles: u64,
    ) -> Self {
        Self {
            maximum_nodes,
            maximum_heap_bytes,
            maximum_lookup_references,
            maximum_forget_batch,
            maximum_open_handles,
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

/// Borrows one authenticated live inode while preventing table mutation.
///
/// Construction reauthenticates the retained record against the exact index.
/// The wrapper borrows its table, so lookup-reference eviction and open-table
/// mutation cannot occur while its record or semantic views are in use.
///
/// ```compile_fail
/// use aos_filesystem_view::{ForgetRequest, InodeError, InodeTable};
///
/// fn cannot_evict_while_borrowed(
///     table: &mut InodeTable<'_, '_>,
///     node_id: u64,
/// ) -> Result<(), InodeError> {
///     let live = table.live_inode(node_id)?;
///     table.forget(&mut [ForgetRequest::new(node_id, 1)])?;
///     let _ = live.attributes();
///     Ok(())
/// }
/// ```
///
/// ```compile_fail
/// use aos_filesystem_view::{IndexNodeView, InodeError, InodeTable};
///
/// fn record_cannot_escape(
///     table: &InodeTable<'_, '_>,
/// ) -> Result<&'static IndexNodeView<'static>, InodeError> {
///     let live = table.live_inode(1)?;
///     Ok(live.record())
/// }
/// ```
///
/// ```compile_fail
/// use aos_filesystem_view::{IndexNodeSemantics, InodeError, InodeTable};
///
/// fn semantics_cannot_escape(
///     table: &InodeTable<'_, '_>,
/// ) -> Result<IndexNodeSemantics<'static>, InodeError> {
///     let live = table.live_inode(1)?;
///     live.semantics()
/// }
/// ```
///
/// ```compile_fail
/// use aos_filesystem_view::{DirectoryRange, InodeError, InodeTable};
///
/// fn directory_range_cannot_escape(
///     table: &InodeTable<'_, '_>,
/// ) -> Result<DirectoryRange<'static>, InodeError> {
///     let live = table.live_inode(1)?;
///     live.directory_range()
/// }
/// ```
pub struct LiveInode<'table, 'index, 'bytes> {
    table: &'table InodeTable<'index, 'bytes>,
    record: IndexNodeView<'bytes>,
    attributes: InodeAttributes,
}

impl LiveInode<'_, '_, '_> {
    /// Returns the connection-scoped attributes captured under this borrow.
    #[must_use]
    pub const fn attributes(&self) -> InodeAttributes {
        self.attributes
    }

    /// Borrows the reauthenticated structural-index record.
    #[must_use]
    pub const fn record(&self) -> &IndexNodeView<'_> {
        &self.record
    }

    /// Borrows authenticated variable metadata and node semantics.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::Index`] if the retained record no longer resolves
    /// exactly within the validated index, which safe callers cannot cause.
    pub fn semantics(&self) -> Result<IndexNodeSemantics<'_>, InodeError> {
        Ok(self.table.index.record_semantics(&self.record)?)
    }

    /// Borrows the canonical child range of a directory inode.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::Index`] if directory iteration is unavailable,
    /// the record is not an authenticated directory, or an index invariant
    /// fails closed.
    pub fn directory_range(&self) -> Result<DirectoryRange<'_>, InodeError> {
        Ok(self.table.index.directory_range(&self.record)?)
    }
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

/// Holds a fully checked FORGET batch before its first table mutation.
pub(crate) struct PreparedForget<'table, 'batch, 'index, 'bytes> {
    table: &'table mut InodeTable<'index, 'bytes>,
    batch: &'batch [ForgetRequest],
    coalesced: usize,
    summary: ForgetSummary,
    next_total: u64,
    next_live: usize,
    next_node_tombstones: usize,
    next_semantic_tombstones: usize,
}

impl PreparedForget<'_, '_, '_, '_> {
    /// Applies the already validated transition without another fallible step.
    pub(crate) fn commit(self) -> ForgetSummary {
        for item in &self.batch[..self.coalesced] {
            if item.semantic_slot != usize::MAX {
                self.table.nodes[item.node_slot] = NodeSlot::Tombstone;
                self.table.semantics[item.semantic_slot] = SemanticSlot::Tombstone;
            } else if let NodeSlot::Occupied(entry) = &mut self.table.nodes[item.node_slot] {
                entry.lookup_references = item.remaining_references;
            }
        }
        self.table.total_lookup_references = self.next_total;
        self.table.live = self.next_live;
        self.table.node_tombstones = self.next_node_tombstones;
        self.table.semantic_tombstones = self.next_semantic_tombstones;
        self.summary
    }
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
    /// A file-open reservation targeted a non-file inode.
    #[error("inode open target is not a file")]
    OpenTargetNotFile,
    /// A FORGET item requested zero references.
    #[error("inode FORGET count must be nonzero")]
    ZeroForgetCount,
    /// A FORGET batch would release more references than are retained.
    #[error("inode FORGET count exceeds retained lookup references")]
    ForgetUnderflow,
    /// An open reservation does not belong to this table or was already used.
    #[error("inode open reservation is invalid or already consumed")]
    InvalidOpenReservation,
    /// The open handle is pending when an active handle was required.
    #[error("inode open handle is still pending")]
    OpenStillPending,
    /// The open handle was never assigned or has already been released.
    #[error("inode open handle is stale")]
    StaleOpenHandle,
    /// The typed open handle belongs to another connection.
    #[error("inode open handle belongs to another connection")]
    ForeignOpenHandle,
    /// Directory handles were not explicitly enabled for this table.
    #[error("inode directory handles are disabled")]
    DirectoryHandlesDisabled,
    /// A directory reservation targeted a non-directory inode.
    #[error("inode directory handle target is not a directory")]
    DirectoryTargetNotDirectory,
    /// A directory reservation is foreign, stale, or already consumed.
    #[error("inode directory reservation is invalid or already consumed")]
    InvalidDirectoryReservation,
    /// The directory handle remains pending.
    #[error("inode directory handle is still pending")]
    DirectoryHandleStillPending,
    /// The directory handle is unknown or was released.
    #[error("inode directory handle is stale")]
    StaleDirectoryHandle,
    /// The typed directory handle belongs to another connection.
    #[error("inode directory handle belongs to another connection")]
    ForeignDirectoryHandle,
    /// A raw handle names the other handle kind.
    #[error("inode handle has the wrong kind")]
    WrongHandleKind,
    /// A READDIR cookie is negative, unrepresentable, or outside the stream.
    #[error("inode directory cookie is invalid")]
    InvalidDirectoryCookie,
    /// An internal fixed-table invariant was violated.
    #[error("inode table invariant violated")]
    InternalInvariant,
}

/// Lazily assigns inode identities for one connection and one immutable index.
///
/// The caller supplies an opaque hashing key that must be unique per
/// connection and unpredictable to the untrusted tree producer. Key secrecy
/// prevents chosen semantic identities from clustering on the table's probe
/// bucket bits; exact semantic-key comparison independently preserves
/// correctness if full SHA-256 digests collide. The key must not be reused as
/// a public identifier. The table performs no randomness or persistence.
/// Dropping it tears down every pending and active handle without callbacks.
pub struct InodeTable<'index, 'bytes> {
    index: &'index ValidatedIndex<'bytes>,
    connection_key: [u8; 32],
    limits: InodeTableLimits,
    nodes: Vec<NodeSlot<'bytes>>,
    semantics: Vec<SemanticSlot>,
    opens: Vec<OpenSlot>,
    directories: Vec<DirectorySlot<'bytes>>,
    directory_limits: Option<DirectoryHandleLimits>,
    live: usize,
    node_tombstones: usize,
    semantic_tombstones: usize,
    live_opens: usize,
    pending_opens: usize,
    open_tombstones: usize,
    live_directories: usize,
    pending_directories: usize,
    directory_tombstones: usize,
    total_lookup_references: u64,
    next_node_id: u64,
    next_handle_id: u64,
    #[cfg(test)]
    refuse_next_open_allocation: bool,
    #[cfg(test)]
    refuse_next_directory_allocation: bool,
    #[cfg(test)]
    directory_rebuilds: u64,
    #[cfg(test)]
    open_rebuilds: u64,
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
        Self::new_inner(index, connection_key, limits, None)
    }

    /// Creates a table with explicitly bounded directory-handle support.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::new`]. Directory storage is charged
    /// only when the first directory handle is reserved.
    pub fn new_with_directory_limits(
        index: &'index ValidatedIndex<'bytes>,
        connection_key: [u8; 32],
        limits: InodeTableLimits,
        directory_limits: DirectoryHandleLimits,
    ) -> Result<Self, InodeError> {
        Self::new_inner(index, connection_key, limits, Some(directory_limits))
    }

    fn new_inner(
        index: &'index ValidatedIndex<'bytes>,
        connection_key: [u8; 32],
        limits: InodeTableLimits,
        directory_limits: Option<DirectoryHandleLimits>,
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
            handle_pins: 0,
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
            opens: Vec::new(),
            directories: Vec::new(),
            directory_limits,
            live: 1,
            node_tombstones: 0,
            semantic_tombstones: 0,
            live_opens: 0,
            pending_opens: 0,
            open_tombstones: 0,
            live_directories: 0,
            pending_directories: 0,
            directory_tombstones: 0,
            total_lookup_references: 1,
            next_node_id: ROOT_NODE_ID + 1,
            next_handle_id: 1,
            #[cfg(test)]
            refuse_next_open_allocation: false,
            #[cfg(test)]
            refuse_next_directory_allocation: false,
            #[cfg(test)]
            directory_rebuilds: 0,
            #[cfg(test)]
            open_rebuilds: 0,
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
                    .and_then(|value| value.checked_add(slot_vector_bytes(&self.opens).ok()?))
                    .and_then(|value| value.checked_add(slot_vector_bytes(&self.directories).ok()?))
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
        self.lookup_bytes(parent, name.as_bytes())
    }

    /// Looks up a byte-slice child without allocating an owned path component.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] under the same conditions as [`Self::lookup`],
    /// including [`IndexError::InvalidPathName`] for malformed component bytes.
    pub fn lookup_bytes(&mut self, parent: u64, name: &[u8]) -> Result<InodeLookup, InodeError> {
        let parent_entry = self.authenticated_node_entry(parent)?;
        if parent_entry.record.kind() != IndexNodeKind::Directory {
            return Err(InodeError::ParentNotDirectory);
        }
        let Some(record) = self
            .index
            .retained_lookup_child_bytes(&parent_entry.record, name)?
        else {
            return Ok(InodeLookup::Negative);
        };
        let semantic = semantic_key(&record)?;
        let hash = semantic_hash(&self.connection_key, semantic);
        if let Some(node_id) = find_semantic(&self.semantics, &hash, semantic) {
            let mut entry = self.authenticated_node_entry(node_id)?;
            let slot = find_node(&self.nodes, node_id).ok_or(InodeError::InternalInvariant)?;
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
    /// evicted after its last lookup reference was forgotten. Record identity
    /// or reverse-map corruption returns [`InodeError::Index`] or
    /// [`InodeError::InternalInvariant`].
    pub fn getattr(&self, node_id: u64) -> Result<InodeAttributes, InodeError> {
        self.authenticated_node_entry(node_id).map(attributes)
    }

    /// Borrows one reauthenticated live inode and prevents table mutation.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::StaleNode`] if the ID is unknown or evicted,
    /// [`InodeError::Index`] if its retained record is foreign or stale, or
    /// [`InodeError::InternalInvariant`] if its slot identity is inconsistent.
    pub fn live_inode(&self, node_id: u64) -> Result<LiveInode<'_, 'index, 'bytes>, InodeError> {
        let entry = self.authenticated_node_entry(node_id)?;
        Ok(LiveInode {
            table: self,
            record: entry.record,
            attributes: attributes(entry),
        })
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
        Ok(self.prepare_forget(batch)?.commit())
    }

    /// Sorts and fully checks a bounded batch without mutating table state.
    pub(crate) fn prepare_forget<'table, 'batch>(
        &'table mut self,
        batch: &'batch mut [ForgetRequest],
    ) -> Result<PreparedForget<'table, 'batch, 'index, 'bytes>, InodeError> {
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
            if retained == item.lookup_references
                && entry.handle_pins == 0
                && item.node_id != ROOT_NODE_ID
            {
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

        Ok(PreparedForget {
            table: self,
            batch,
            coalesced,
            summary,
            next_total,
            next_live,
            next_node_tombstones,
            next_semantic_tombstones,
        })
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
            handle_pins: 0,
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

    /// Reauthenticates every identity edge for a connection-scoped node.
    fn authenticated_node_entry(&self, node_id: u64) -> Result<NodeEntry<'bytes>, InodeError> {
        let entry = self.node_entry(node_id).ok_or(InodeError::StaleNode)?;
        if entry.node_id != node_id {
            return Err(InodeError::InternalInvariant);
        }
        let record = self.index.authenticate_node(&entry.record)?;
        let semantic = semantic_key(&record)?;
        if semantic != entry.semantic {
            return Err(InodeError::InternalInvariant);
        }
        let hash = semantic_hash(&self.connection_key, semantic);
        if find_semantic(&self.semantics, &hash, semantic) != Some(node_id) {
            return Err(InodeError::InternalInvariant);
        }
        Ok(NodeEntry { record, ..entry })
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

#[cfg(test)]
mod tests;
