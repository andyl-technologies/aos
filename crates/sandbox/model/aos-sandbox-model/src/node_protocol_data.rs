//! Canonical non-authorizing node protocol, requests, watch and wire DATA.
//!
//! These values retain exact query, boot, schema and history commitments. They
//! do not authenticate an event, prove a complete inventory, refresh a session
//! or confer any ownership, transport or native mutation authority.

use sha2::{Digest as _, Sha256};

use crate::{
    AssignmentIntentV1, DrainDirectiveV1, NodeBootId, NodeBootLineageV1, NodeId, ObjectDigest,
    ProtocolVersion, SnapshotDependencyRangeV1, SnapshotTransferChunkRequestV1,
    SnapshotTransferManifestV1, SnapshotTransferResumeV1,
};

/// Maximum semantic coordinator-to-node request frame.
pub const MAX_NODE_REQUEST_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum semantic coordinator-to-node response frame.
pub const MAX_NODE_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum assignment rows in one complete resynchronization inventory.
pub const MAX_RESYNC_ASSIGNMENTS: usize = 4_096;
/// Maximum events returned in one watch batch.
pub const MAX_WATCH_EVENTS: usize = 1_024;

/// Reports an invalid coordinator-to-node semantic message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidMultiNodeProtocol {
    /// A node, request, binding, generation, digest, or sequence uses a zero sentinel.
    #[error("multi-node protocol value contains an unspecified identity")]
    Unspecified,
    /// The coordinator-to-node protocol version is not locally compatible.
    #[error("coordinator-to-node protocol version is incompatible")]
    IncompatibleVersion,
    /// Advertised frame limits are zero or exceed compiled allocation ceilings.
    #[error("coordinator-to-node frame limits exceed compiled ceilings")]
    InvalidFrameLimits,
    /// An envelope does not match its authenticated session contract.
    #[error("coordinator-to-node envelope does not match its session")]
    SessionMismatch,
    /// Inventory rows are oversized, unordered, duplicated, or cross-node.
    #[error("assignment inventory is incomplete or noncanonical")]
    InventoryNotCanonical,
    /// Watch events are oversized, unordered, or do not advance their cursor.
    #[error("watch batch must be bounded and strictly ordered")]
    WatchBatchNotCanonical,
    /// A typed response payload does not name the request's exact node-local object.
    #[error("coordinator-to-node response content does not match its request")]
    ResponseContentMismatch,
    /// A response body does not correspond to its request method.
    #[error("coordinator-to-node response method does not match its request")]
    MethodMismatch,
    /// Watch query, authorization, coordinator epoch, bootstrap, or schema binding changed.
    #[error("watch cursor binding requires a fresh authenticated bootstrap")]
    WatchBindingMismatch,
    /// Canonical framing is malformed, truncated, oversized, or has a bad digest.
    #[error("coordinator-to-node canonical frame is invalid")]
    NonCanonicalFrame,
}

/// Describes a rolling same-major schema reader/writer window.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RollingVersionWindowV1 {
    minimum_reader: ProtocolVersion,
    writer: ProtocolVersion,
}

impl RollingVersionWindowV1 {
    /// Constructs one compatible rolling schema window.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::IncompatibleVersion`] when versions
    /// cross majors, use major zero, or the minimum reader is newer than the writer.
    pub const fn new(
        minimum_reader: ProtocolVersion,
        writer: ProtocolVersion,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if minimum_reader.major() == 0
            || minimum_reader.major() != writer.major()
            || minimum_reader.minor() > writer.minor()
        {
            return Err(InvalidMultiNodeProtocol::IncompatibleVersion);
        }
        Ok(Self {
            minimum_reader,
            writer,
        })
    }

    /// Returns the oldest schema semantics required to read the stream.
    #[must_use]
    pub const fn minimum_reader(self) -> ProtocolVersion {
        self.minimum_reader
    }

    /// Returns the schema version emitted by the stream writer.
    #[must_use]
    pub const fn writer(self) -> ProtocolVersion {
        self.writer
    }

    /// Reports whether a reader version is admitted by this rolling window.
    #[must_use]
    pub const fn admits(self, reader: ProtocolVersion) -> bool {
        reader.major() == self.writer.major()
            && reader.minor() >= self.minimum_reader.minor()
            && reader.minor() <= self.writer.minor()
    }
}

/// Binds a resumable watch to coordinator state, query, authorization, and schema.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeWatchBindingV1 {
    coordinator_epoch: u64,
    history_floor_sequence: u64,
    history_floor_event_uid: ObjectDigest,
    bootstrap_watermark: u64,
    query_digest: ObjectDigest,
    authorization_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    schema: RollingVersionWindowV1,
}

impl NodeWatchBindingV1 {
    /// Constructs one immutable watch-stream binding.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::Unspecified`] for zero epoch or digests.
    pub fn new(
        coordinator_epoch: u64,
        history_floor_sequence: u64,
        history_floor_event_uid: ObjectDigest,
        bootstrap_watermark: u64,
        query_digest: ObjectDigest,
        authorization_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        schema: RollingVersionWindowV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if coordinator_epoch == 0
            || query_digest.as_bytes() == &[0; 32]
            || authorization_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || history_floor_event_uid.as_bytes() == &[0; 32]
            || bootstrap_watermark < history_floor_sequence
        {
            return Err(InvalidMultiNodeProtocol::Unspecified);
        }
        Ok(Self {
            coordinator_epoch,
            history_floor_sequence,
            history_floor_event_uid,
            bootstrap_watermark,
            query_digest,
            authorization_digest,
            audience_digest,
            disclosure_domain_digest,
            schema,
        })
    }

    /// Returns the durable coordinator epoch.
    #[must_use]
    pub const fn coordinator_epoch(self) -> u64 {
        self.coordinator_epoch
    }

    /// Returns the complete-bootstrap event watermark.
    #[must_use]
    pub const fn bootstrap_watermark(self) -> u64 {
        self.bootstrap_watermark
    }

    /// Returns the oldest retained event sequence after history compaction.
    #[must_use]
    pub const fn history_floor_sequence(self) -> u64 {
        self.history_floor_sequence
    }

    /// Returns the stable event UID anchoring the compaction floor.
    #[must_use]
    pub const fn history_floor_event_uid(self) -> ObjectDigest {
        self.history_floor_event_uid
    }

    /// Returns the exact canonical query commitment.
    #[must_use]
    pub const fn query_digest(self) -> ObjectDigest {
        self.query_digest
    }

    /// Returns the exact current authorization-policy commitment.
    #[must_use]
    pub const fn authorization_digest(self) -> ObjectDigest {
        self.authorization_digest
    }

    /// Returns the exact authenticated node audience commitment.
    #[must_use]
    pub const fn audience_digest(self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the exact disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the rolling schema compatibility window.
    #[must_use]
    pub const fn schema(self) -> RollingVersionWindowV1 {
        self.schema
    }
}

/// Identifies a resumable event position within one monotonic node boot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeWatchCursorV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    binding: NodeWatchBindingV1,
    event_sequence: u64,
    last_event_uid: ObjectDigest,
}

impl NodeWatchCursorV1 {
    /// Constructs one structurally validated watch cursor.
    ///
    /// This data constructor does not authenticate a bootstrap or its history.
    ///
    /// The event sequence must be at or beyond the binding's complete-bootstrap
    /// watermark. A zero watermark may name the position before the first event.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::Unspecified`] for zero identity
    /// fields, or [`InvalidMultiNodeProtocol::WatchBindingMismatch`] when the
    /// cursor falls below its bootstrap or retained-history floor.
    pub fn new(
        node: NodeId,
        lineage: NodeBootLineageV1,
        binding: NodeWatchBindingV1,
        event_sequence: u64,
        last_event_uid: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if node.as_bytes() == &[0; 16] || last_event_uid.as_bytes() == &[0; 32] {
            return Err(InvalidMultiNodeProtocol::Unspecified);
        }
        if event_sequence < binding.bootstrap_watermark()
            || event_sequence < binding.history_floor_sequence()
            || (event_sequence == binding.history_floor_sequence()
                && event_sequence != binding.bootstrap_watermark()
                && last_event_uid != binding.history_floor_event_uid())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        Ok(Self {
            node,
            lineage,
            binding,
            event_sequence,
            last_event_uid,
        })
    }

    /// Returns the node whose stream is addressed.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the node boot whose stream is addressed.
    #[must_use]
    pub const fn boot(self) -> NodeBootId {
        self.lineage.boot()
    }

    /// Returns the durable node boot generation.
    #[must_use]
    pub const fn boot_generation(self) -> u64 {
        self.lineage.generation()
    }

    /// Returns the durable non-ABA boot lineage.
    #[must_use]
    pub const fn lineage(self) -> NodeBootLineageV1 {
        self.lineage
    }

    /// Returns coordinator, bootstrap, query, authorization, and schema bindings.
    #[must_use]
    pub const fn binding(self) -> NodeWatchBindingV1 {
        self.binding
    }

    /// Returns the event sequence within the boot.
    #[must_use]
    pub const fn event_sequence(self) -> u64 {
        self.event_sequence
    }

    /// Returns the stable UID of the last fully consumed event.
    #[must_use]
    pub const fn last_event_uid(self) -> ObjectDigest {
        self.last_event_uid
    }
}

/// Computes the stable UID for one authenticated watch event.
#[must_use]
pub fn stable_watch_event_uid(
    binding: NodeWatchBindingV1,
    lineage: NodeBootLineageV1,
    event_sequence: u64,
    predecessor_event_uid: ObjectDigest,
    canonical_event_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.coordinator-node.stable-watch-event.v1\0");
    hasher.update(binding.coordinator_epoch().to_be_bytes());
    hasher.update(binding.query_digest().as_bytes());
    hasher.update(binding.authorization_digest().as_bytes());
    hasher.update(binding.audience_digest().as_bytes());
    hasher.update(binding.disclosure_domain_digest().as_bytes());
    hasher.update(binding.schema().minimum_reader().major().to_be_bytes());
    hasher.update(binding.schema().minimum_reader().minor().to_be_bytes());
    hasher.update(binding.schema().writer().major().to_be_bytes());
    hasher.update(binding.schema().writer().minor().to_be_bytes());
    hasher.update(lineage.digest().as_bytes());
    hasher.update(event_sequence.to_be_bytes());
    hasher.update(predecessor_event_uid.as_bytes());
    hasher.update(canonical_event_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Computes the stable history anchor for one complete authenticated relist.
#[must_use]
pub fn stable_watch_bootstrap_uid(
    binding: NodeWatchBindingV1,
    lineage: NodeBootLineageV1,
    inventory_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.coordinator-node.watch-bootstrap.v1\0");
    hasher.update(binding.coordinator_epoch().to_be_bytes());
    hasher.update(binding.bootstrap_watermark().to_be_bytes());
    hasher.update(binding.query_digest().as_bytes());
    hasher.update(binding.authorization_digest().as_bytes());
    hasher.update(binding.audience_digest().as_bytes());
    hasher.update(binding.disclosure_domain_digest().as_bytes());
    hasher.update(binding.schema().minimum_reader().major().to_be_bytes());
    hasher.update(binding.schema().minimum_reader().minor().to_be_bytes());
    hasher.update(binding.schema().writer().major().to_be_bytes());
    hasher.update(binding.schema().writer().minor().to_be_bytes());
    hasher.update(lineage.digest().as_bytes());
    hasher.update(inventory_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Selects one coordinator-to-node semantic request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeRequestBodyV1 {
    /// Requests the complete current node capability snapshot.
    GetCapabilities,
    /// Publishes desired assignment semantics for reconciliation.
    ///
    /// The node must still acquire and verify ownership authority before effects.
    ReconcileAssignment(Box<AssignmentIntentV1>),
    /// Requests a complete independently inventoried assignment snapshot.
    RelistAssignments {
        /// Exact coordinator/query/authorization/schema binding for the relist.
        binding: NodeWatchBindingV1,
    },
    /// Publishes a cordon or drain desired-state generation.
    ReconcileDrain(Box<DrainDirectiveV1>),
    /// Opens or resumes read-only delivery of one immutable snapshot object.
    BeginSnapshotTransfer {
        /// Canonical immutable transfer manifest.
        manifest: Box<SnapshotTransferManifestV1>,
        /// Last integrity-verified chunk boundary, when resuming.
        resume: Option<SnapshotTransferResumeV1>,
    },
    /// Requests one exact immutable byte range committed by a manifest.
    FetchSnapshotChunk {
        /// Exact manifest-derived identity, range, and integrity commitment.
        request: SnapshotTransferChunkRequestV1,
    },
    /// Requests one exact bounded range of a manifest-bound dependency.
    FetchSnapshotDependency {
        /// Exact scoped immutable dependency range.
        request: SnapshotDependencyRangeV1,
    },
    /// Requests events strictly after the supplied cursor.
    Watch {
        /// Last fully consumed event position.
        after: NodeWatchCursorV1,
        /// Maximum number of events, bounded by [`MAX_WATCH_EVENTS`].
        maximum_events: u16,
    },
}

impl NodeRequestBodyV1 {
    /// Returns the closed semantic method DATA discriminator.
    #[must_use]
    pub const fn method(&self) -> NodeMethodV1 {
        match self {
            Self::GetCapabilities => NodeMethodV1::GetCapabilities,
            Self::ReconcileAssignment(_) => NodeMethodV1::ReconcileAssignment,
            Self::RelistAssignments { .. } => NodeMethodV1::RelistAssignments,
            Self::ReconcileDrain(_) => NodeMethodV1::ReconcileDrain,
            Self::BeginSnapshotTransfer { .. } => NodeMethodV1::BeginSnapshotTransfer,
            Self::FetchSnapshotChunk { .. } => NodeMethodV1::FetchSnapshotChunk,
            Self::FetchSnapshotDependency { .. } => NodeMethodV1::FetchSnapshotDependency,
            Self::Watch { .. } => NodeMethodV1::Watch,
        }
    }

    /// Returns the canonical request frame DATA kind.
    #[must_use]
    pub const fn frame_kind(&self) -> CanonicalNodeFrameKindV1 {
        match self {
            Self::GetCapabilities => CanonicalNodeFrameKindV1::GetCapabilitiesRequest,
            Self::ReconcileAssignment(_) => CanonicalNodeFrameKindV1::ReconcileAssignmentRequest,
            Self::RelistAssignments { .. } => CanonicalNodeFrameKindV1::RelistAssignmentsRequest,
            Self::ReconcileDrain(_) => CanonicalNodeFrameKindV1::ReconcileDrainRequest,
            Self::BeginSnapshotTransfer { .. } => {
                CanonicalNodeFrameKindV1::BeginSnapshotTransferRequest
            }
            Self::FetchSnapshotChunk { .. } => CanonicalNodeFrameKindV1::SnapshotChunkRequest,
            Self::FetchSnapshotDependency { .. } => {
                CanonicalNodeFrameKindV1::SnapshotDependencyRequest
            }
            Self::Watch { .. } => CanonicalNodeFrameKindV1::WatchRequest,
        }
    }
}

/// Selects a closed semantic method without admitting or dispatching it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeMethodV1 {
    /// Reads capability DATA.
    GetCapabilities,
    /// Carries assignment desired-state DATA.
    ReconcileAssignment,
    /// Reads complete assignment inventory DATA.
    RelistAssignments,
    /// Carries drain desired-state DATA.
    ReconcileDrain,
    /// Names immutable transfer/resume DATA.
    BeginSnapshotTransfer,
    /// Names a bounded immutable chunk DATA request.
    FetchSnapshotChunk,
    /// Names a bounded immutable dependency DATA request.
    FetchSnapshotDependency,
    /// Names an ordered watch DATA request.
    Watch,
}

/// Selects every canonical coordinator/node and immutable-transfer frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CanonicalNodeFrameKindV1 {
    /// Capability request.
    GetCapabilitiesRequest = 0,
    /// Capability response.
    GetCapabilitiesResponse = 1,
    /// Assignment reconcile request.
    ReconcileAssignmentRequest = 2,
    /// Assignment observation response.
    ReconcileAssignmentResponse = 3,
    /// Complete relist request.
    RelistAssignmentsRequest = 4,
    /// Complete relist response.
    RelistAssignmentsResponse = 5,
    /// Drain reconcile request.
    ReconcileDrainRequest = 6,
    /// Drain observation response.
    ReconcileDrainResponse = 7,
    /// Snapshot transfer begin/resume request.
    BeginSnapshotTransferRequest = 8,
    /// Snapshot transfer begin/resume response.
    BeginSnapshotTransferResponse = 9,
    /// Snapshot chunk request.
    SnapshotChunkRequest = 10,
    /// Snapshot chunk response.
    SnapshotChunkResponse = 11,
    /// Dependency range request.
    SnapshotDependencyRequest = 12,
    /// Dependency range response.
    SnapshotDependencyResponse = 13,
    /// Ordered watch request.
    WatchRequest = 14,
    /// Ordered watch response or typed gap.
    WatchResponse = 15,
}

impl CanonicalNodeFrameKindV1 {
    /// Parses a canonical frame DATA tag, returning `None` for unknown values.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::GetCapabilitiesRequest,
            1 => Self::GetCapabilitiesResponse,
            2 => Self::ReconcileAssignmentRequest,
            3 => Self::ReconcileAssignmentResponse,
            4 => Self::RelistAssignmentsRequest,
            5 => Self::RelistAssignmentsResponse,
            6 => Self::ReconcileDrainRequest,
            7 => Self::ReconcileDrainResponse,
            8 => Self::BeginSnapshotTransferRequest,
            9 => Self::BeginSnapshotTransferResponse,
            10 => Self::SnapshotChunkRequest,
            11 => Self::SnapshotChunkResponse,
            12 => Self::SnapshotDependencyRequest,
            13 => Self::SnapshotDependencyResponse,
            14 => Self::WatchRequest,
            15 => Self::WatchResponse,
            _ => return None,
        })
    }
}
