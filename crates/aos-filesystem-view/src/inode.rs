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

use aos_sandbox_core::{ObjectDigest, PathName};
use sha2::{Digest, Sha256};

use crate::{
    DirectoryRange, IndexError, IndexNodeKind, IndexNodeSemantics, IndexNodeView, ValidatedIndex,
};

const INITIAL_CAPACITY: usize = 2;
const SEMANTIC_HASH_DOMAIN: &[u8] = b"aos.filesystem-view.inode-semantic.v1\0";
const OPEN_RESERVATION_DOMAIN: &[u8] = b"aos.filesystem-view.open-reservation.v1\0";

/// Node ID permanently assigned to the connection's root inode.
pub const ROOT_NODE_ID: u64 = 1;

/// Monotonic connection-scoped identity for one pending or active open.
///
/// IDs are never reused during a connection. This value conveys identity only;
/// it does not contain or represent an OS file descriptor.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct OpenHandleId {
    raw: u64,
    connection_key: [u8; 32],
}

impl std::fmt::Debug for OpenHandleId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenHandleId")
            .field("raw", &self.raw)
            .field("connection", &"<redacted>")
            .finish()
    }
}

impl OpenHandleId {
    /// Returns the connection-scoped integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.raw
    }
}

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

/// Opaque authority to finish one pending open reservation.
///
/// The token is neither copyable nor cloneable. Its private authenticator binds
/// it to the originating connection, node, and handle. Passing it to another
/// table or using it after a successful transition is rejected. Dropping a
/// pending token does not implicitly roll back table state: it leaves a bounded
/// fail-closed pin that must be drained by tearing down the connection.
#[must_use = "a pending open must be activated or explicitly aborted"]
pub struct OpenReservation {
    raw_handle_id: u64,
    node_id: u64,
    authenticator: [u8; 32],
    consumed: bool,
}

impl OpenReservation {
    /// Returns the raw protocol handle reserved for a prospective open reply.
    ///
    /// This untrusted integer is identity to be resolved by the originating
    /// table, not standalone authority. Reading it makes no state transition.
    /// While the reservation is unconsumed, resolution reports a pending open;
    /// after successful [`InodeTable::activate_open`] the same integer resolves
    /// to the active handle, and after [`InodeTable::abort_open`] it is stale.
    #[must_use]
    pub const fn raw_protocol_handle(&self) -> u64 {
        self.raw_handle_id
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
    open_pins: u64,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenState {
    Pending,
    Active,
}

#[derive(Clone, Copy)]
enum OpenSlot {
    Empty,
    Tombstone,
    Occupied {
        raw_handle_id: u64,
        node_id: u64,
        state: OpenState,
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
    opens: Vec<OpenSlot>,
    live: usize,
    node_tombstones: usize,
    semantic_tombstones: usize,
    live_opens: usize,
    pending_opens: usize,
    open_tombstones: usize,
    total_lookup_references: u64,
    next_node_id: u64,
    next_open_handle_id: u64,
    #[cfg(test)]
    refuse_next_open_allocation: bool,
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
            open_pins: 0,
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
            live: 1,
            node_tombstones: 0,
            semantic_tombstones: 0,
            live_opens: 0,
            pending_opens: 0,
            open_tombstones: 0,
            total_lookup_references: 1,
            next_node_id: ROOT_NODE_ID + 1,
            next_open_handle_id: 1,
            #[cfg(test)]
            refuse_next_open_allocation: false,
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

    /// Returns the number of pending and active opens.
    #[must_use]
    pub fn live_open_handles(&self) -> u64 {
        self.live_opens as u64
    }

    /// Returns the number of reservations awaiting activation or abort.
    #[must_use]
    pub fn pending_open_handles(&self) -> u64 {
        self.pending_opens as u64
    }

    /// Reserves a handle identity before backend-specific open work begins.
    ///
    /// The pending reservation pins its inode immediately. The caller must
    /// subsequently call [`Self::activate_open`] after successful external
    /// work or [`Self::abort_open`] after failure. No OS resource is accepted
    /// or retained by this table.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError`] when the node is stale or fails exact identity
    /// authentication, a handle/count/heap ceiling is exceeded, or fixed-slot
    /// allocation fails. Failure leaves all table state unchanged.
    pub fn reserve_open(&mut self, node_id: u64) -> Result<OpenReservation, InodeError> {
        let mut node = self.authenticated_node_entry(node_id)?;
        let node_slot = find_node(&self.nodes, node_id).ok_or(InodeError::StaleNode)?;
        if node.record.kind() != IndexNodeKind::File {
            return Err(InodeError::OpenTargetNotFile);
        }
        let next_pin_count = node
            .open_pins
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open pins"))?;
        if self.live_opens as u64 >= self.limits.maximum_open_handles {
            return Err(InodeError::LimitExceeded("open handles"));
        }

        let raw_handle_id = self.next_open_handle_id;
        let next_handle_id = self
            .next_open_handle_id
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open handle IDs"))?;
        let next_live = self
            .live_opens
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open handles"))?;
        let next_pending = self
            .pending_opens
            .checked_add(1)
            .ok_or(InodeError::LimitExceeded("open handles"))?;
        let insertion = if self.opens.is_empty() {
            None
        } else {
            Some(find_open_insert(&self.opens, raw_handle_id)?)
        };
        let reuses_tombstone =
            insertion.is_some_and(|slot| matches!(self.opens[slot], OpenSlot::Tombstone));
        let target = self.open_rebuild_capacity(next_live, reuses_tombstone)?;

        if let Some(target) = target {
            let mut replacement = self.allocate_open_replacement(target)?;
            rehash_opens(&self.opens, &mut replacement)?;
            let slot = find_open_insert(&replacement, raw_handle_id)?;
            replacement[slot] = OpenSlot::Occupied {
                raw_handle_id,
                node_id,
                state: OpenState::Pending,
            };
            self.opens = replacement;
            self.open_tombstones = 0;
            #[cfg(test)]
            {
                self.open_rebuilds = self.open_rebuilds.saturating_add(1);
            }
        } else {
            let slot = insertion.ok_or(InodeError::InternalInvariant)?;
            let next_tombstones = if reuses_tombstone {
                self.open_tombstones
                    .checked_sub(1)
                    .ok_or(InodeError::InternalInvariant)?
            } else {
                self.open_tombstones
            };
            self.opens[slot] = OpenSlot::Occupied {
                raw_handle_id,
                node_id,
                state: OpenState::Pending,
            };
            self.open_tombstones = next_tombstones;
        }

        node.open_pins = next_pin_count;
        self.nodes[node_slot] = NodeSlot::Occupied(node);
        self.live_opens = next_live;
        self.pending_opens = next_pending;
        self.next_open_handle_id = next_handle_id;
        Ok(OpenReservation {
            raw_handle_id,
            node_id,
            authenticator: open_reservation_authenticator(
                &self.connection_key,
                raw_handle_id,
                node_id,
            ),
            consumed: false,
        })
    }

    /// Makes a pending reservation visible as an active open.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidOpenReservation`] when the token belongs to
    /// another table, is stale, or has already completed.
    pub fn activate_open(
        &mut self,
        reservation: &mut OpenReservation,
    ) -> Result<OpenHandleId, InodeError> {
        let slot = self.pending_reservation_slot(reservation)?;
        let OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state: OpenState::Pending,
        } = self.opens[slot]
        else {
            return Err(InodeError::InvalidOpenReservation);
        };
        let next_pending = self
            .pending_opens
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        self.opens[slot] = OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state: OpenState::Active,
        };
        self.pending_opens = next_pending;
        reservation.consumed = true;
        Ok(self.brand_handle(raw_handle_id))
    }

    /// Aborts a pending reservation and releases its inode pin.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::InvalidOpenReservation`] when the token belongs to
    /// another table, is stale, or has already completed. Invariant failures
    /// are reported without partially releasing state.
    pub fn abort_open(&mut self, reservation: &mut OpenReservation) -> Result<(), InodeError> {
        let slot = self.pending_reservation_slot(reservation)?;
        self.remove_open(slot, reservation.node_id, OpenState::Pending)?;
        reservation.consumed = true;
        Ok(())
    }

    /// Returns attributes for an active open without changing its lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::OpenStillPending`] for a reserved open and
    /// [`InodeError::StaleOpenHandle`] for an unknown or released handle.
    /// A handle branded by another connection returns
    /// [`InodeError::ForeignOpenHandle`]. Record identity or reverse-map
    /// corruption returns [`InodeError::Index`] or
    /// [`InodeError::InternalInvariant`].
    pub fn active_open(&self, handle_id: OpenHandleId) -> Result<InodeAttributes, InodeError> {
        let raw_handle_id = self.validate_handle_brand(handle_id)?;
        let slot = find_open(&self.opens, raw_handle_id).ok_or(InodeError::StaleOpenHandle)?;
        let OpenSlot::Occupied { node_id, state, .. } = self.opens[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == OpenState::Pending {
            return Err(InodeError::OpenStillPending);
        }
        self.authenticated_node_entry(node_id).map(attributes)
    }

    /// Releases one active open exactly once and drops its inode pin.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::OpenStillPending`] for a reserved open,
    /// [`InodeError::StaleOpenHandle`] for an unknown or already released
    /// handle, [`InodeError::ForeignOpenHandle`] for a handle branded by
    /// another connection, or [`InodeError::InternalInvariant`] without
    /// partial mutation when cross-table state is inconsistent.
    pub fn release_open(&mut self, handle_id: OpenHandleId) -> Result<(), InodeError> {
        let raw_handle_id = self.validate_handle_brand(handle_id)?;
        let slot = find_open(&self.opens, raw_handle_id).ok_or(InodeError::StaleOpenHandle)?;
        let OpenSlot::Occupied { node_id, state, .. } = self.opens[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == OpenState::Pending {
            return Err(InodeError::OpenStillPending);
        }
        self.remove_open(slot, node_id, OpenState::Active)
    }

    /// Resolves an untrusted raw FUSE `fh` within this authoritative table.
    ///
    /// A worker must first route the request to the table for the kernel
    /// connection that supplied the raw value. Resolution brands only an
    /// existing active handle; pending reservations are not protocol-visible.
    /// The returned type therefore cannot be replayed against another
    /// conforming connection table.
    ///
    /// # Errors
    ///
    /// Returns [`InodeError::OpenStillPending`] if the raw value names a
    /// reservation that has not activated, or [`InodeError::StaleOpenHandle`]
    /// if it is zero, unknown, or already released.
    pub fn resolve_active_handle(&self, raw: u64) -> Result<OpenHandleId, InodeError> {
        if raw == 0 {
            return Err(InodeError::StaleOpenHandle);
        }
        let slot = find_open(&self.opens, raw).ok_or(InodeError::StaleOpenHandle)?;
        let OpenSlot::Occupied { state, .. } = self.opens[slot] else {
            return Err(InodeError::InternalInvariant);
        };
        if state == OpenState::Pending {
            return Err(InodeError::OpenStillPending);
        }
        Ok(self.brand_handle(raw))
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
                && entry.open_pins == 0
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
            open_pins: 0,
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

    fn pending_reservation_slot(&self, reservation: &OpenReservation) -> Result<usize, InodeError> {
        if reservation.consumed
            || reservation.authenticator
                != open_reservation_authenticator(
                    &self.connection_key,
                    reservation.raw_handle_id,
                    reservation.node_id,
                )
        {
            return Err(InodeError::InvalidOpenReservation);
        }
        let slot = find_open(&self.opens, reservation.raw_handle_id)
            .ok_or(InodeError::InvalidOpenReservation)?;
        if !matches!(
            self.opens[slot],
            OpenSlot::Occupied {
                node_id,
                state: OpenState::Pending,
                ..
            } if node_id == reservation.node_id
        ) {
            return Err(InodeError::InvalidOpenReservation);
        }
        Ok(slot)
    }

    fn open_rebuild_capacity(
        &self,
        next_live: usize,
        reuses_tombstone: bool,
    ) -> Result<Option<usize>, InodeError> {
        if self.opens.is_empty() {
            return Ok(Some(INITIAL_CAPACITY));
        }
        if next_live > self.opens.len() / 2 {
            return self
                .opens
                .len()
                .checked_mul(2)
                .map(Some)
                .ok_or(InodeError::LimitExceeded("open handles"));
        }
        let occupancy = self
            .live_opens
            .checked_add(self.open_tombstones)
            .and_then(|value| value.checked_add(usize::from(!reuses_tombstone)))
            .ok_or(InodeError::LimitExceeded("open handles"))?;
        let compaction_threshold = self.opens.len() - self.opens.len() / 4;
        Ok((occupancy > compaction_threshold).then_some(self.opens.len()))
    }

    fn brand_handle(&self, raw: u64) -> OpenHandleId {
        OpenHandleId {
            raw,
            connection_key: self.connection_key,
        }
    }

    fn validate_handle_brand(&self, handle_id: OpenHandleId) -> Result<u64, InodeError> {
        if handle_id.connection_key != self.connection_key {
            return Err(InodeError::ForeignOpenHandle);
        }
        Ok(handle_id.raw)
    }

    fn allocate_open_replacement(&mut self, target: usize) -> Result<Vec<OpenSlot>, InodeError> {
        let requested = modeled_bytes::<OpenSlot>(target)?;
        let peak = self
            .heap_bytes()
            .checked_add(requested)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if peak > self.limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }
        #[cfg(test)]
        if self.refuse_next_open_allocation {
            self.refuse_next_open_allocation = false;
            return Err(InodeError::AllocationRefused);
        }
        let replacement = allocate_open_slots(target)?;
        let actual_peak = self
            .heap_bytes()
            .checked_add(slot_vector_bytes(&replacement)?)
            .ok_or(InodeError::LimitExceeded("heap bytes"))?;
        if actual_peak > self.limits.maximum_heap_bytes {
            return Err(InodeError::LimitExceeded("heap bytes"));
        }
        Ok(replacement)
    }

    fn remove_open(
        &mut self,
        open_slot: usize,
        node_id: u64,
        expected_state: OpenState,
    ) -> Result<(), InodeError> {
        if !matches!(
            self.opens.get(open_slot),
            Some(OpenSlot::Occupied {
                node_id: candidate,
                state,
                ..
            }) if *candidate == node_id && *state == expected_state
        ) {
            return Err(InodeError::InternalInvariant);
        }
        let node_slot = find_node(&self.nodes, node_id).ok_or(InodeError::InternalInvariant)?;
        let NodeSlot::Occupied(mut node) = self.nodes[node_slot] else {
            return Err(InodeError::InternalInvariant);
        };
        let next_pins = node
            .open_pins
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        let reap = node_id != ROOT_NODE_ID && node.lookup_references == 0 && next_pins == 0;
        let semantic_slot = if reap {
            let hash = semantic_hash(&self.connection_key, node.semantic);
            let slot = find_semantic_slot(&self.semantics, &hash, node.semantic)
                .ok_or(InodeError::InternalInvariant)?;
            if !matches!(
                self.semantics[slot],
                SemanticSlot::Occupied { node_id: candidate, .. } if candidate == node_id
            ) {
                return Err(InodeError::InternalInvariant);
            }
            Some(slot)
        } else {
            None
        };
        let next_live_opens = self
            .live_opens
            .checked_sub(1)
            .ok_or(InodeError::InternalInvariant)?;
        let next_pending_opens = if expected_state == OpenState::Pending {
            self.pending_opens
                .checked_sub(1)
                .ok_or(InodeError::InternalInvariant)?
        } else {
            self.pending_opens
        };
        let next_open_tombstones = self
            .open_tombstones
            .checked_add(1)
            .ok_or(InodeError::InternalInvariant)?;
        let next_live = self
            .live
            .checked_sub(usize::from(reap))
            .ok_or(InodeError::InternalInvariant)?;
        let next_node_tombstones = self
            .node_tombstones
            .checked_add(usize::from(reap))
            .ok_or(InodeError::InternalInvariant)?;
        let next_semantic_tombstones = self
            .semantic_tombstones
            .checked_add(usize::from(reap))
            .ok_or(InodeError::InternalInvariant)?;

        self.opens[open_slot] = OpenSlot::Tombstone;
        self.live_opens = next_live_opens;
        self.pending_opens = next_pending_opens;
        self.open_tombstones = next_open_tombstones;
        if let Some(semantic_slot) = semantic_slot {
            self.nodes[node_slot] = NodeSlot::Tombstone;
            self.semantics[semantic_slot] = SemanticSlot::Tombstone;
        } else {
            node.open_pins = next_pins;
            self.nodes[node_slot] = NodeSlot::Occupied(node);
        }
        self.live = next_live;
        self.node_tombstones = next_node_tombstones;
        self.semantic_tombstones = next_semantic_tombstones;
        Ok(())
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

fn open_reservation_authenticator(
    connection_key: &[u8; 32],
    raw_handle_id: u64,
    node_id: u64,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(OPEN_RESERVATION_DOMAIN);
    hash.update(connection_key);
    hash.update(raw_handle_id.to_le_bytes());
    hash.update(node_id.to_le_bytes());
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

fn allocate_open_slots(capacity: usize) -> Result<Vec<OpenSlot>, InodeError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| InodeError::AllocationRefused)?;
    slots.resize(capacity, OpenSlot::Empty);
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

fn open_bucket(raw_handle_id: u64, capacity: usize) -> usize {
    node_bucket(raw_handle_id, capacity)
}

fn find_open(slots: &[OpenSlot], raw_handle_id: u64) -> Option<usize> {
    if slots.is_empty() {
        return None;
    }
    let mut position = open_bucket(raw_handle_id, slots.len());
    for _ in 0..slots.len() {
        match slots[position] {
            OpenSlot::Empty => return None,
            OpenSlot::Occupied {
                raw_handle_id: candidate,
                ..
            } if candidate == raw_handle_id => return Some(position),
            OpenSlot::Tombstone | OpenSlot::Occupied { .. } => {
                position = (position + 1) & (slots.len() - 1);
            }
        }
    }
    None
}

fn find_open_insert(slots: &[OpenSlot], raw_handle_id: u64) -> Result<usize, InodeError> {
    if slots.is_empty() {
        return Err(InodeError::InternalInvariant);
    }
    let mut position = open_bucket(raw_handle_id, slots.len());
    let mut tombstone = None;
    for _ in 0..slots.len() {
        match slots[position] {
            OpenSlot::Empty => return Ok(tombstone.unwrap_or(position)),
            OpenSlot::Tombstone => {
                tombstone.get_or_insert(position);
            }
            OpenSlot::Occupied {
                raw_handle_id: candidate,
                ..
            } if candidate == raw_handle_id => return Err(InodeError::InternalInvariant),
            OpenSlot::Occupied { .. } => {}
        }
        position = (position + 1) & (slots.len() - 1);
    }
    tombstone.ok_or(InodeError::InternalInvariant)
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

fn rehash_opens(old: &[OpenSlot], new: &mut [OpenSlot]) -> Result<(), InodeError> {
    for slot in old {
        if let OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state,
        } = slot
        {
            let position = find_open_insert(new, *raw_handle_id)?;
            new[position] = OpenSlot::Occupied {
                raw_handle_id: *raw_handle_id,
                node_id: *node_id,
                state: *state,
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
        v3: bool,
    }

    impl Fixture {
        fn validate(&self) -> ValidatedIndex<'_> {
            let media_type = if self.v3 {
                crate::INDEX_MEDIA_TYPE_V3
            } else {
                INDEX_MEDIA_TYPE_V2
            };
            let media =
                MediaType::new(media_type).unwrap_or_else(|error| panic!("media failed: {error}"));
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
        fixture_with_format([3; 32], false)
    }

    fn fixture_v3() -> Fixture {
        fixture_with_format([3; 32], true)
    }

    fn fixture_with_content_digest(content_digest: [u8; 32]) -> Fixture {
        fixture_with_format(content_digest, false)
    }

    fn fixture_with_format(content_digest: [u8; 32], v3: bool) -> Fixture {
        let tree = descriptor("application/vnd.aos.sandbox.tree.v1+cbor", [1; 32]);
        let root = descriptor("application/vnd.aos.sandbox.directory.v1+cbor", [2; 32]);
        let content_descriptor =
            descriptor("application/vnd.aos.sandbox.content.v1", content_digest);
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
        let mut builder = if v3 {
            StructuralIndexBuilder::new_v3(staging, [7; 32], tree.clone(), root.clone(), 0)
        } else {
            StructuralIndexBuilder::new(staging, [7; 32], tree.clone(), root.clone(), 0)
        }
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
        builder
            .push(&IndexRecord {
                parent: 0,
                depth: 1,
                sibling_ordinal: 4,
                name: b"e",
                metadata: &directory_metadata,
                node: IndexNode::Directory { descriptor: &root },
            })
            .unwrap_or_else(|error| panic!("directory push failed: {error}"));
        let (writer, _) = builder
            .finish()
            .unwrap_or_else(|error| panic!("finish failed: {error}"))
            .into_parts();
        Fixture {
            bytes: writer.into_inner(),
            tree,
            root,
            v3,
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
        InodeTableLimits::new(32, 1_048_576, 16, 16, 16)
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
    fn byte_lookup_validates_without_owned_names_or_partial_mutation() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [31; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));

        let found = table
            .lookup_bytes(ROOT_NODE_ID, b"c")
            .unwrap_or_else(|error| panic!("byte lookup failed: {error}"));
        assert!(matches!(found, InodeLookup::Positive { .. }));
        let nodes = table.live_nodes();
        let references = table.total_lookup_references();
        let oversized = [b'a'; 256];
        for invalid in [
            &b""[..],
            &b"."[..],
            &b".."[..],
            &b"a/b"[..],
            &b"a\0b"[..],
            &oversized,
        ] {
            assert!(matches!(
                table.lookup_bytes(ROOT_NODE_ID, invalid),
                Err(InodeError::Index(IndexError::InvalidPathName(_)))
            ));
            assert_eq!(table.live_nodes(), nodes);
            assert_eq!(table.total_lookup_references(), references);
        }
    }

    #[test]
    fn live_inode_reauthenticates_and_bounds_all_borrowed_views() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [32; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"c")
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );

        {
            let live = table
                .live_inode(file.node_id)
                .unwrap_or_else(|error| panic!("live inode failed: {error}"));
            assert_eq!(live.attributes(), file);
            assert_eq!(live.record().record_id(), file.record_id);
            assert_eq!(
                live.semantics()
                    .unwrap_or_else(|error| panic!("semantics failed: {error}"))
                    .logical_size(),
                Some(0)
            );
        }

        table
            .forget(&mut [ForgetRequest::new(file.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        assert!(matches!(
            table.live_inode(file.node_id),
            Err(InodeError::StaleNode)
        ));

        let root = table
            .live_inode(ROOT_NODE_ID)
            .unwrap_or_else(|error| panic!("root live inode failed: {error}"));
        assert!(matches!(
            root.directory_range(),
            Err(InodeError::Index(IndexError::DirectoryIterationUnavailable))
        ));
    }

    #[test]
    fn live_inode_exposes_a_canonical_v3_directory_range() {
        let fixture = fixture_v3();
        let index = fixture.validate();
        let table = InodeTable::new(&index, [40; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let root = table
            .live_inode(ROOT_NODE_ID)
            .unwrap_or_else(|error| panic!("root live inode failed: {error}"));
        let range = root
            .directory_range()
            .unwrap_or_else(|error| panic!("directory range failed: {error}"));
        assert_eq!(range.len(), 5);
        let names = range
            .iter()
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("directory entry failed: {error}"))
                    .node()
                    .name()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                b"a".as_slice(),
                b"b".as_slice(),
                b"c".as_slice(),
                b"d".as_slice(),
                b"e".as_slice(),
            ]
        );
    }

    #[test]
    fn live_inode_rejects_a_foreign_retained_record() {
        let first_fixture = fixture();
        let second_fixture = fixture_with_content_digest([33; 32]);
        let first_index = first_fixture.validate();
        let second_index = second_fixture.validate();
        let foreign_root = second_index
            .root()
            .unwrap_or_else(|error| panic!("foreign root failed: {error}"));
        let mut table = InodeTable::new(&first_index, [34; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let slot = find_node(&table.nodes, ROOT_NODE_ID)
            .unwrap_or_else(|| panic!("root node slot missing"));
        let NodeSlot::Occupied(mut entry) = table.nodes[slot] else {
            panic!("root node entry missing");
        };
        entry.record = foreign_root;
        table.nodes[slot] = NodeSlot::Occupied(entry);

        assert!(matches!(
            table.live_inode(ROOT_NODE_ID),
            Err(InodeError::Index(IndexError::ForeignNode))
        ));
    }

    #[test]
    fn live_inode_rejects_same_artifact_identity_and_reverse_map_corruption() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [35; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (first, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"c")
                .unwrap_or_else(|error| panic!("first lookup failed: {error}")),
        );
        let (second, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"d")
                .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
        );
        let first_slot = find_node(&table.nodes, first.node_id)
            .unwrap_or_else(|| panic!("first node slot missing"));
        let second_entry = table
            .node_entry(second.node_id)
            .unwrap_or_else(|| panic!("second node missing"));
        let NodeSlot::Occupied(original) = table.nodes[first_slot] else {
            panic!("first node missing");
        };
        let live_nodes = table.live_nodes();
        let references = table.total_lookup_references();

        table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
            record: second_entry.record,
            ..original
        });
        assert!(matches!(
            table.live_inode(first.node_id),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.live_nodes(), live_nodes);
        assert_eq!(table.total_lookup_references(), references);

        table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
            semantic: second_entry.semantic,
            ..original
        });
        assert!(matches!(
            table.live_inode(first.node_id),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.live_nodes(), live_nodes);
        assert_eq!(table.total_lookup_references(), references);

        table.nodes[first_slot] = NodeSlot::Occupied(original);
        let hash = semantic_hash(&table.connection_key, original.semantic);
        let semantic_slot = find_semantic_slot(&table.semantics, &hash, original.semantic)
            .unwrap_or_else(|| panic!("first semantic slot missing"));
        table.semantics[semantic_slot] = SemanticSlot::Tombstone;
        assert!(matches!(
            table.live_inode(first.node_id),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.live_nodes(), live_nodes);
        assert_eq!(table.total_lookup_references(), references);
    }

    #[test]
    fn lookup_rejects_same_artifact_directory_swap_before_admission() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [36; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (directory, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"e")
                .unwrap_or_else(|error| panic!("directory lookup failed: {error}")),
        );
        assert_eq!(directory.kind, IndexNodeKind::Directory);
        let directory_entry = table
            .node_entry(directory.node_id)
            .unwrap_or_else(|| panic!("directory entry missing"));
        let root_slot = find_node(&table.nodes, ROOT_NODE_ID)
            .unwrap_or_else(|| panic!("root node slot missing"));
        let NodeSlot::Occupied(root_entry) = table.nodes[root_slot] else {
            panic!("root node entry missing");
        };
        table.nodes[root_slot] = NodeSlot::Occupied(NodeEntry {
            record: directory_entry.record,
            ..root_entry
        });
        let live_nodes = table.live_nodes();
        let references = table.total_lookup_references();
        let next_node_id = table.next_node_id;

        assert!(matches!(
            table.lookup_bytes(ROOT_NODE_ID, b"c"),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.live_nodes(), live_nodes);
        assert_eq!(table.total_lookup_references(), references);
        assert_eq!(table.next_node_id, next_node_id);
    }

    #[test]
    fn lookup_reuse_reauthenticates_the_existing_inode_before_increment() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [37; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (first, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"c")
                .unwrap_or_else(|error| panic!("first lookup failed: {error}")),
        );
        let (second, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"d")
                .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
        );
        let first_slot = find_node(&table.nodes, first.node_id)
            .unwrap_or_else(|| panic!("first node slot missing"));
        let second_entry = table
            .node_entry(second.node_id)
            .unwrap_or_else(|| panic!("second node missing"));
        let NodeSlot::Occupied(first_entry) = table.nodes[first_slot] else {
            panic!("first node missing");
        };
        table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
            record: second_entry.record,
            ..first_entry
        });
        let entry_references = first_entry.lookup_references;
        let total_references = table.total_lookup_references();
        let live_nodes = table.live_nodes();
        let next_node_id = table.next_node_id;

        assert!(matches!(
            table.lookup_bytes(ROOT_NODE_ID, b"c"),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(
            table
                .node_entry(first.node_id)
                .map(|entry| entry.lookup_references),
            Some(entry_references)
        );
        assert_eq!(table.total_lookup_references(), total_references);
        assert_eq!(table.live_nodes(), live_nodes);
        assert_eq!(table.next_node_id, next_node_id);
    }

    #[test]
    fn public_inode_reads_and_open_authorization_reject_record_substitution() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [38; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (first, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"c")
                .unwrap_or_else(|error| panic!("first lookup failed: {error}")),
        );
        let (second, _) = positive_parts(
            table
                .lookup_bytes(ROOT_NODE_ID, b"d")
                .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
        );
        let first_slot = find_node(&table.nodes, first.node_id)
            .unwrap_or_else(|| panic!("first node slot missing"));
        let NodeSlot::Occupied(first_entry) = table.nodes[first_slot] else {
            panic!("first node missing");
        };
        let second_record = table
            .node_entry(second.node_id)
            .unwrap_or_else(|| panic!("second node missing"))
            .record;
        table.nodes[first_slot] = NodeSlot::Occupied(NodeEntry {
            record: second_record,
            ..first_entry
        });
        let heap_bytes = table.heap_bytes();
        let live_nodes = table.live_nodes();
        let references = table.total_lookup_references();
        let live_opens = table.live_open_handles();
        let pending_opens = table.pending_open_handles();
        let next_node_id = table.next_node_id;
        let next_open_handle_id = table.next_open_handle_id;

        assert!(matches!(
            table.getattr(first.node_id),
            Err(InodeError::InternalInvariant)
        ));
        assert!(matches!(
            table.reserve_open(first.node_id),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.heap_bytes(), heap_bytes);
        assert_eq!(table.live_nodes(), live_nodes);
        assert_eq!(table.total_lookup_references(), references);
        assert_eq!(table.live_open_handles(), live_opens);
        assert_eq!(table.pending_open_handles(), pending_opens);
        assert_eq!(table.next_node_id, next_node_id);
        assert_eq!(table.next_open_handle_id, next_open_handle_id);
        assert_eq!(
            table.node_entry(first.node_id).map(|entry| entry.open_pins),
            Some(first_entry.open_pins)
        );

        let mut active_table = InodeTable::new(&index, [39; 32], generous_limits())
            .unwrap_or_else(|error| panic!("active table failed: {error}"));
        let (active_file, _) = positive_parts(
            active_table
                .lookup_bytes(ROOT_NODE_ID, b"c")
                .unwrap_or_else(|error| panic!("active-file lookup failed: {error}")),
        );
        let (replacement, _) = positive_parts(
            active_table
                .lookup_bytes(ROOT_NODE_ID, b"d")
                .unwrap_or_else(|error| panic!("replacement lookup failed: {error}")),
        );
        let mut reservation = active_table
            .reserve_open(active_file.node_id)
            .unwrap_or_else(|error| panic!("reservation failed: {error}"));
        let handle = active_table
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("activation failed: {error}"));
        let active_slot = find_node(&active_table.nodes, active_file.node_id)
            .unwrap_or_else(|| panic!("active node slot missing"));
        let NodeSlot::Occupied(active_entry) = active_table.nodes[active_slot] else {
            panic!("active node missing");
        };
        let replacement_record = active_table
            .node_entry(replacement.node_id)
            .unwrap_or_else(|| panic!("replacement node missing"))
            .record;
        active_table.nodes[active_slot] = NodeSlot::Occupied(NodeEntry {
            record: replacement_record,
            ..active_entry
        });
        let active_heap = active_table.heap_bytes();
        let active_nodes = active_table.live_nodes();
        let active_references = active_table.total_lookup_references();
        let active_opens = active_table.live_open_handles();
        let active_pending = active_table.pending_open_handles();
        let active_next_node = active_table.next_node_id;
        let active_next_open = active_table.next_open_handle_id;

        assert!(matches!(
            active_table.active_open(handle),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(active_table.heap_bytes(), active_heap);
        assert_eq!(active_table.live_nodes(), active_nodes);
        assert_eq!(active_table.total_lookup_references(), active_references);
        assert_eq!(active_table.live_open_handles(), active_opens);
        assert_eq!(active_table.pending_open_handles(), active_pending);
        assert_eq!(active_table.next_node_id, active_next_node);
        assert_eq!(active_table.next_open_handle_id, active_next_open);
        assert_eq!(
            active_table
                .node_entry(active_file.node_id)
                .map(|entry| entry.open_pins),
            Some(active_entry.open_pins)
        );
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
        let mut count_limited = InodeTable::new(
            &index,
            [6; 32],
            InodeTableLimits::new(1, 1_048_576, 8, 8, 8),
        )
        .unwrap_or_else(|error| panic!("table failed: {error}"));
        assert!(matches!(
            count_limited.lookup(ROOT_NODE_ID, &name(b"a")),
            Err(InodeError::LimitExceeded("nodes"))
        ));
        assert_eq!(count_limited.live_nodes(), 1);
        assert_eq!(count_limited.total_lookup_references(), 1);

        let mut exact_boundary = InodeTable::new(
            &index,
            [6; 32],
            InodeTableLimits::new(2, 1_048_576, 8, 8, 8),
        )
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
        let limits = InodeTableLimits::new(8, initial_heap, 8, 8, 8);
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

        let reference_limits = InodeTableLimits::new(8, 1_048_576, 2, 8, 8);
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

    #[test]
    fn pending_and_active_opens_pin_an_inode_until_release() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [12; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let raw_handle = reservation.raw_protocol_handle();
        assert_eq!(reservation.raw_protocol_handle(), raw_handle);
        assert_eq!(table.live_open_handles(), 1);
        assert_eq!(table.pending_open_handles(), 1);
        assert!(matches!(
            table.resolve_active_handle(raw_handle),
            Err(InodeError::OpenStillPending)
        ));

        let forgotten = table
            .forget(&mut [ForgetRequest::new(file.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        assert_eq!(forgotten.nodes_evicted, 0);
        assert!(table.getattr(file.node_id).is_ok());

        let active = table
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("activate failed: {error}"));
        assert_eq!(active.get(), raw_handle);
        assert_eq!(reservation.raw_protocol_handle(), raw_handle);
        let resolved = table
            .resolve_active_handle(raw_handle)
            .unwrap_or_else(|error| panic!("resolve failed: {error}"));
        assert_eq!(resolved, active);
        assert_eq!(
            format!("{active:?}"),
            format!("OpenHandleId {{ raw: {raw_handle}, connection: \"<redacted>\" }}")
        );
        assert_eq!(table.pending_open_handles(), 0);
        assert_eq!(
            table
                .active_open(active)
                .unwrap_or_else(|error| panic!("active lookup failed: {error}"))
                .node_id,
            file.node_id
        );
        table
            .release_open(active)
            .unwrap_or_else(|error| panic!("release failed: {error}"));
        assert_eq!(table.live_open_handles(), 0);
        assert!(matches!(
            table.active_open(active),
            Err(InodeError::StaleOpenHandle)
        ));
        assert!(matches!(
            table.release_open(active),
            Err(InodeError::StaleOpenHandle)
        ));
        assert!(matches!(
            table.getattr(file.node_id),
            Err(InodeError::StaleNode)
        ));
    }

    #[test]
    fn abort_releases_pending_pin_and_reservation_is_single_use() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [13; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let raw_handle = reservation.raw_protocol_handle();
        assert!(matches!(
            table.resolve_active_handle(raw_handle),
            Err(InodeError::OpenStillPending)
        ));
        table
            .forget(&mut [ForgetRequest::new(file.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        table
            .abort_open(&mut reservation)
            .unwrap_or_else(|error| panic!("abort failed: {error}"));
        assert_eq!(reservation.raw_protocol_handle(), raw_handle);
        assert!(matches!(
            table.resolve_active_handle(raw_handle),
            Err(InodeError::StaleOpenHandle)
        ));
        assert!(matches!(
            table.abort_open(&mut reservation),
            Err(InodeError::InvalidOpenReservation)
        ));
        assert_eq!(table.live_open_handles(), 0);
        assert_eq!(table.pending_open_handles(), 0);
        assert!(matches!(
            table.getattr(file.node_id),
            Err(InodeError::StaleNode)
        ));
    }

    #[test]
    fn reservation_and_typed_handle_are_bound_to_unique_connection() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut first = InodeTable::new(&index, [14; 32], generous_limits())
            .unwrap_or_else(|error| panic!("first table failed: {error}"));
        let mut second = InodeTable::new(&index, [20; 32], generous_limits())
            .unwrap_or_else(|error| panic!("second table failed: {error}"));
        let (file, _) = positive_parts(
            first
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = first
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let authenticator = reservation.authenticator;
        reservation.authenticator[0] ^= 1;
        assert!(matches!(
            first.activate_open(&mut reservation),
            Err(InodeError::InvalidOpenReservation)
        ));
        reservation.authenticator = authenticator;
        assert!(matches!(
            second.activate_open(&mut reservation),
            Err(InodeError::InvalidOpenReservation)
        ));
        assert_eq!(second.live_open_handles(), 0);
        let first_handle = first
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("origin activate failed: {error}"));
        let (second_file, _) = positive_parts(
            second
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("second lookup failed: {error}")),
        );
        let mut second_reservation = second
            .reserve_open(second_file.node_id)
            .unwrap_or_else(|error| panic!("second reserve failed: {error}"));
        let second_handle = second
            .activate_open(&mut second_reservation)
            .unwrap_or_else(|error| panic!("second activate failed: {error}"));
        assert_eq!(first_handle.get(), second_handle.get());
        assert_ne!(first_handle, second_handle);
        assert!(matches!(
            first.active_open(second_handle),
            Err(InodeError::ForeignOpenHandle)
        ));
        assert!(matches!(
            first.release_open(second_handle),
            Err(InodeError::ForeignOpenHandle)
        ));
        assert!(first.active_open(first_handle).is_ok());
        first
            .release_open(first_handle)
            .unwrap_or_else(|error| panic!("first release failed: {error}"));
        second
            .release_open(second_handle)
            .unwrap_or_else(|error| panic!("second release failed: {error}"));
    }

    #[test]
    fn open_admission_failures_leave_inode_and_handle_state_unchanged() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut disabled_limits = generous_limits();
        disabled_limits.maximum_open_handles = 0;
        let mut disabled = InodeTable::new(&index, [15; 32], disabled_limits)
            .unwrap_or_else(|error| panic!("disabled table failed: {error}"));
        assert!(matches!(
            disabled.reserve_open(ROOT_NODE_ID),
            Err(InodeError::OpenTargetNotFile)
        ));
        let (file, _) = positive_parts(
            disabled
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        assert!(matches!(
            disabled.reserve_open(file.node_id),
            Err(InodeError::LimitExceeded("open handles"))
        ));
        assert_eq!(disabled.live_open_handles(), 0);

        let mut one_limit = generous_limits();
        one_limit.maximum_open_handles = 1;
        let mut one = InodeTable::new(&index, [19; 32], one_limit)
            .unwrap_or_else(|error| panic!("single-handle table failed: {error}"));
        let (file, _) = positive_parts(
            one.lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut first = one
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("first reserve failed: {error}"));
        let first_id = first.raw_handle_id;
        assert!(matches!(
            one.reserve_open(file.node_id),
            Err(InodeError::LimitExceeded("open handles"))
        ));
        one.abort_open(&mut first)
            .unwrap_or_else(|error| panic!("abort failed: {error}"));
        let second = one
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("second reserve failed: {error}"));
        assert!(second.raw_handle_id > first_id);

        let mut heap_limited = InodeTable::new(&index, [16; 32], generous_limits())
            .unwrap_or_else(|error| panic!("heap table failed: {error}"));
        let (file, _) = positive_parts(
            heap_limited
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        heap_limited.limits.maximum_heap_bytes = heap_limited.heap_bytes();
        assert!(matches!(
            heap_limited.reserve_open(file.node_id),
            Err(InodeError::LimitExceeded("heap bytes"))
        ));
        assert_eq!(heap_limited.live_open_handles(), 0);
        assert!(heap_limited.getattr(file.node_id).is_ok());

        let mut allocation_refused = InodeTable::new(&index, [17; 32], generous_limits())
            .unwrap_or_else(|error| panic!("allocation table failed: {error}"));
        let (file, _) = positive_parts(
            allocation_refused
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        allocation_refused.refuse_next_open_allocation = true;
        assert!(matches!(
            allocation_refused.reserve_open(file.node_id),
            Err(InodeError::AllocationRefused)
        ));
        assert_eq!(allocation_refused.live_open_handles(), 0);
        assert!(allocation_refused.getattr(file.node_id).is_ok());

        allocation_refused.next_open_handle_id = u64::MAX;
        assert!(matches!(
            allocation_refused.reserve_open(file.node_id),
            Err(InodeError::LimitExceeded("open handle IDs"))
        ));
        assert_eq!(allocation_refused.live_open_handles(), 0);
    }

    #[test]
    fn lookup_reference_revival_defers_reap_after_release() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [18; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let handle = table
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("activate failed: {error}"));
        table
            .forget(&mut [ForgetRequest::new(file.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));
        let (revived, references) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("revival failed: {error}")),
        );
        assert_eq!(revived.node_id, file.node_id);
        assert_eq!(references, 1);
        table
            .release_open(handle)
            .unwrap_or_else(|error| panic!("release failed: {error}"));
        assert!(table.getattr(file.node_id).is_ok());
        table
            .forget(&mut [ForgetRequest::new(file.node_id, 1)])
            .unwrap_or_else(|error| panic!("final forget failed: {error}"));
        assert!(matches!(
            table.getattr(file.node_id),
            Err(InodeError::StaleNode)
        ));
    }

    #[test]
    fn open_churn_preserves_load_bounds_and_never_reuses_ids() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [21; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );

        let mut reservations = Vec::new();
        for _ in 0..8 {
            reservations.push(
                table
                    .reserve_open(file.node_id)
                    .unwrap_or_else(|error| panic!("reserve failed: {error}")),
            );
        }
        let mut handles = Vec::new();
        for reservation in &mut reservations {
            handles.push(
                table
                    .activate_open(reservation)
                    .unwrap_or_else(|error| panic!("activate failed: {error}")),
            );
        }
        assert!(handles.windows(2).all(|pair| pair[0].get() < pair[1].get()));
        assert!(table.live_opens <= table.opens.len() / 2);
        for handle in handles {
            table
                .release_open(handle)
                .unwrap_or_else(|error| panic!("release failed: {error}"));
        }

        let mut previous = 8;
        let rebuilds_before = table.open_rebuilds;
        for _ in 0..128 {
            let mut reservation = table
                .reserve_open(file.node_id)
                .unwrap_or_else(|error| panic!("churn reserve failed: {error}"));
            let handle = table
                .activate_open(&mut reservation)
                .unwrap_or_else(|error| panic!("churn activate failed: {error}"));
            assert!(handle.get() > previous);
            previous = handle.get();
            assert!(table.live_opens <= table.opens.len() / 2);
            assert!(table.live_opens + table.open_tombstones <= table.opens.len() * 3 / 4);
            table
                .release_open(handle)
                .unwrap_or_else(|error| panic!("churn release failed: {error}"));
            assert_eq!(table.live_open_handles(), 0);
            assert!(table.live_opens + table.open_tombstones <= table.opens.len() * 3 / 4);
        }
        assert!(table.open_rebuilds - rebuilds_before < 128);
    }

    #[test]
    fn open_growth_and_compaction_charge_retained_plus_replacement() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut growth = InodeTable::new(&index, [22; 32], generous_limits())
            .unwrap_or_else(|error| panic!("growth table failed: {error}"));
        let (file, _) = positive_parts(
            growth
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut first = growth
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("first reserve failed: {error}"));
        let first_handle = growth
            .activate_open(&mut first)
            .unwrap_or_else(|error| panic!("activate failed: {error}"));
        let replacement = modeled_bytes::<OpenSlot>(growth.opens.len() * 2)
            .unwrap_or_else(|error| panic!("model failed: {error}"));
        growth.limits.maximum_heap_bytes = growth.heap_bytes() + replacement - 1;
        assert!(matches!(
            growth.reserve_open(file.node_id),
            Err(InodeError::LimitExceeded("heap bytes"))
        ));
        assert_eq!(growth.live_open_handles(), 1);
        assert!(growth.active_open(first_handle).is_ok());

        let mut compaction = InodeTable::new(&index, [23; 32], generous_limits())
            .unwrap_or_else(|error| panic!("compaction table failed: {error}"));
        let (file, _) = positive_parts(
            compaction
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        compaction.opens = allocate_open_slots(4)
            .unwrap_or_else(|error| panic!("fixture allocation failed: {error}"));
        compaction.opens.fill(OpenSlot::Tombstone);
        let empty = open_bucket(compaction.next_open_handle_id, compaction.opens.len());
        compaction.opens[empty] = OpenSlot::Empty;
        compaction.open_tombstones = 3;
        let replacement = modeled_bytes::<OpenSlot>(compaction.opens.len())
            .unwrap_or_else(|error| panic!("model failed: {error}"));
        compaction.limits.maximum_heap_bytes = compaction.heap_bytes() + replacement - 1;
        let heap_before = compaction.heap_bytes();
        assert!(matches!(
            compaction.reserve_open(file.node_id),
            Err(InodeError::LimitExceeded("heap bytes"))
        ));
        assert_eq!(compaction.heap_bytes(), heap_before);
        assert_eq!(compaction.live_open_handles(), 0);
        assert_eq!(compaction.open_tombstones, 3);
        assert!(compaction.getattr(file.node_id).is_ok());
    }

    #[test]
    fn open_tombstone_reuse_needs_no_replacement_admission() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [25; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut first = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("first reserve failed: {error}"));
        table
            .abort_open(&mut first)
            .unwrap_or_else(|error| panic!("abort failed: {error}"));
        table.opens.fill(OpenSlot::Empty);
        let tombstone = open_bucket(table.next_open_handle_id, table.opens.len());
        table.opens[tombstone] = OpenSlot::Tombstone;
        table.open_tombstones = 1;
        table.limits.maximum_heap_bytes = table.heap_bytes();
        table.refuse_next_open_allocation = true;

        let mut second = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("tombstone reserve failed: {error}"));
        assert!(table.refuse_next_open_allocation);
        assert_eq!(table.open_tombstones, 0);
        table
            .abort_open(&mut second)
            .unwrap_or_else(|error| panic!("second abort failed: {error}"));
    }

    #[test]
    fn release_cross_map_corruption_fails_before_any_removal() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [24; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let handle = table
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("activate failed: {error}"));
        table
            .forget(&mut [ForgetRequest::new(file.node_id, 1)])
            .unwrap_or_else(|error| panic!("forget failed: {error}"));

        let node = table
            .node_entry(file.node_id)
            .unwrap_or_else(|| panic!("pinned node missing"));
        let hash = semantic_hash(&table.connection_key, node.semantic);
        let semantic_slot = find_semantic_slot(&table.semantics, &hash, node.semantic)
            .unwrap_or_else(|| panic!("semantic missing"));
        table.semantics[semantic_slot] = SemanticSlot::Tombstone;
        let live_before = table.live;
        let live_opens_before = table.live_opens;
        let open_tombstones_before = table.open_tombstones;
        assert!(matches!(
            table.release_open(handle),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(table.live, live_before);
        assert_eq!(table.live_opens, live_opens_before);
        assert_eq!(table.open_tombstones, open_tombstones_before);
        assert!(matches!(
            table.active_open(handle),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(
            table
                .node_entry(file.node_id)
                .map(|entry| (entry.lookup_references, entry.open_pins)),
            Some((0, 1))
        );
    }

    #[test]
    fn release_zero_pin_corruption_leaves_slots_and_counters_unchanged() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [26; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let handle = table
            .activate_open(&mut reservation)
            .unwrap_or_else(|error| panic!("activate failed: {error}"));
        let node_slot =
            find_node(&table.nodes, file.node_id).unwrap_or_else(|| panic!("node slot missing"));
        let NodeSlot::Occupied(mut node) = table.nodes[node_slot] else {
            panic!("node slot not occupied");
        };
        node.open_pins = 0;
        table.nodes[node_slot] = NodeSlot::Occupied(node);
        let open_slot =
            find_open(&table.opens, handle.get()).unwrap_or_else(|| panic!("open slot missing"));
        let OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state,
        } = table.opens[open_slot]
        else {
            panic!("open slot not occupied");
        };
        let counters_before = [
            table.live,
            table.node_tombstones,
            table.semantic_tombstones,
            table.live_opens,
            table.pending_opens,
            table.open_tombstones,
        ];
        let ids_before = [
            table.total_lookup_references,
            table.next_node_id,
            table.next_open_handle_id,
        ];

        assert!(matches!(
            table.release_open(handle),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(
            [
                table.live,
                table.node_tombstones,
                table.semantic_tombstones,
                table.live_opens,
                table.pending_opens,
                table.open_tombstones,
            ],
            counters_before
        );
        assert_eq!(
            [
                table.total_lookup_references,
                table.next_node_id,
                table.next_open_handle_id,
            ],
            ids_before
        );
        assert!(matches!(
            table.opens[open_slot],
            OpenSlot::Occupied {
                raw_handle_id: candidate_raw,
                node_id: candidate_node,
                state: candidate_state,
            } if (candidate_raw, candidate_node, candidate_state)
                == (raw_handle_id, node_id, state)
        ));
        assert_eq!(
            table
                .node_entry(file.node_id)
                .map(|entry| (entry.lookup_references, entry.open_pins)),
            Some((node.lookup_references, 0))
        );
    }

    #[test]
    fn abort_zero_pending_counter_leaves_slots_and_counters_unchanged() {
        let fixture = fixture();
        let index = fixture.validate();
        let mut table = InodeTable::new(&index, [27; 32], generous_limits())
            .unwrap_or_else(|error| panic!("table failed: {error}"));
        let (file, _) = positive_parts(
            table
                .lookup(ROOT_NODE_ID, &name(b"c"))
                .unwrap_or_else(|error| panic!("lookup failed: {error}")),
        );
        let mut reservation = table
            .reserve_open(file.node_id)
            .unwrap_or_else(|error| panic!("reserve failed: {error}"));
        let open_slot = find_open(&table.opens, reservation.raw_handle_id)
            .unwrap_or_else(|| panic!("open slot missing"));
        let OpenSlot::Occupied {
            raw_handle_id,
            node_id,
            state,
        } = table.opens[open_slot]
        else {
            panic!("open slot not occupied");
        };
        let node_before = table
            .node_entry(file.node_id)
            .map(|entry| (entry.lookup_references, entry.open_pins));
        table.pending_opens = 0;
        let counters_before = [
            table.live,
            table.node_tombstones,
            table.semantic_tombstones,
            table.live_opens,
            table.pending_opens,
            table.open_tombstones,
        ];
        let ids_before = [
            table.total_lookup_references,
            table.next_node_id,
            table.next_open_handle_id,
        ];

        assert!(matches!(
            table.abort_open(&mut reservation),
            Err(InodeError::InternalInvariant)
        ));
        assert_eq!(
            [
                table.live,
                table.node_tombstones,
                table.semantic_tombstones,
                table.live_opens,
                table.pending_opens,
                table.open_tombstones,
            ],
            counters_before
        );
        assert_eq!(
            [
                table.total_lookup_references,
                table.next_node_id,
                table.next_open_handle_id,
            ],
            ids_before
        );
        assert!(matches!(
            table.opens[open_slot],
            OpenSlot::Occupied {
                raw_handle_id: candidate_raw,
                node_id: candidate_node,
                state: candidate_state,
            } if (candidate_raw, candidate_node, candidate_state)
                == (raw_handle_id, node_id, state)
        ));
        assert_eq!(
            table
                .node_entry(file.node_id)
                .map(|entry| (entry.lookup_references, entry.open_pins)),
            node_before
        );
        assert!(!reservation.consumed);
    }
}
