//! Transport-neutral coordinator-to-node message and resynchronization models.
//!
//! The structures describe semantics after canonical bounded framing and peer
//! authentication. Session bindings prevent cross-session substitution only
//! when a transport authenticates the binding and exact bytes. Assignment
//! messages carry desired state, never an ownership lease or permission to
//! perform effects.
//!
//! Canonical carrier framing is fixed-width except for the final bounded body:
//!
//! ```text
//! magic[8] | kind:u8 | major:u16 | minor:u16 | binding-digest[32]
//! audience-digest[32] | disclosure-digest[32] | request-id[16]
//! body-sha256[32] | body-length:u32 | body[body-length]
//! ```

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{
    NodeId, ObjectDigest, ObservationSequence, OperationId, ProtocolId, ProtocolVersion, SandboxId,
    supported_protocol_version,
};

use super::assignment::{
    AssignmentIntentV1, AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
    NodeAssignmentObservationV1, SnapshotDependencyRangeV1, SnapshotTransferChunkRequestV1,
    SnapshotTransferIdentityV1, SnapshotTransferManifestV1, SnapshotTransferResumeV1,
};
use super::capability::{
    CarrierValidatedCapabilityObservationV1, NodeBootId, NodeBootLineageV1,
    NodeCapabilitySnapshotV1,
};
use super::carrier_authority::{
    AuthenticatedFrameSealV1, CarrierResponseGrantV1, CarrierSessionGrantV1,
};
use super::draining::{DrainDirectiveV1, DrainObservationV1};
use super::evidence::AuthenticatedEvidenceContextV1;

pub(super) mod protobuf_codec_v1;
pub(super) mod semantic_codec_v1;

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
    /// Desired assignment rows are oversized, unordered, duplicated, or cross-node.
    #[error("desired assignments must be a canonical node-local set")]
    DesiredAssignmentsNotCanonical,
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

/// Defines one authenticated coordinator-to-node semantic session.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedNodeSessionV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    binding: [u8; 32],
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    authenticated_frame_digest: ObjectDigest,
    authenticated_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    version: ProtocolVersion,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    replay_fence: ObjectDigest,
}

impl AuthenticatedNodeSessionV1 {
    /// Constructs one bounded session contract after carrier authentication.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for sentinel identity, incompatible
    /// protocol semantics, or frame limits above compiled allocation ceilings.
    pub(super) fn from_authority_grant(
        grant: CarrierSessionGrantV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let node = grant.node();
        let lineage = grant.lineage();
        let binding = grant.binding();
        let audience_digest = grant.audience_digest();
        let disclosure_domain_digest = grant.disclosure_domain_digest();
        let authenticated_frame_digest = grant.authenticated_frame_digest();
        let authenticated_frame_bytes = grant.authenticated_frame_bytes();
        let coordinator_epoch = grant.coordinator_epoch();
        let authenticated_at_unix_seconds = grant.authenticated_at_unix_seconds();
        let valid_until_unix_seconds = grant.valid_until_unix_seconds();
        let version = grant.version();
        let maximum_request_bytes = grant.maximum_request_bytes();
        let maximum_response_bytes = grant.maximum_response_bytes();
        let replay_fence = grant.replay_fence();
        if node.as_bytes() == &[0; 16]
            || binding == [0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || authenticated_frame_digest.as_bytes() == &[0; 32]
            || authenticated_frame_bytes == 0
            || authenticated_frame_bytes > MAX_NODE_RESPONSE_BYTES
            || coordinator_epoch == 0
            || replay_fence.as_bytes() == &[0; 32]
            || valid_until_unix_seconds <= authenticated_at_unix_seconds
        {
            return Err(InvalidMultiNodeProtocol::Unspecified);
        }
        let supported = supported_protocol_version(ProtocolId::CoordinatorNode);
        if version.major() != supported.major() || version.minor() > supported.minor() {
            return Err(InvalidMultiNodeProtocol::IncompatibleVersion);
        }
        if maximum_request_bytes == 0
            || maximum_response_bytes == 0
            || maximum_request_bytes > MAX_NODE_REQUEST_BYTES
            || maximum_response_bytes > MAX_NODE_RESPONSE_BYTES
        {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        Ok(Self {
            node,
            lineage,
            binding,
            audience_digest,
            disclosure_domain_digest,
            authenticated_frame_digest,
            authenticated_frame_bytes,
            coordinator_epoch,
            authenticated_at_unix_seconds,
            valid_until_unix_seconds,
            version,
            maximum_request_bytes,
            maximum_response_bytes,
            replay_fence,
        })
    }

    /// Returns the authenticated peer node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the exact authenticated durable node boot lineage.
    #[must_use]
    pub const fn lineage(&self) -> NodeBootLineageV1 {
        self.lineage
    }

    /// Returns the carrier-authenticated session binding.
    #[must_use]
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Returns the authenticated node/audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the exact carrier handshake-frame commitment.
    #[must_use]
    pub const fn authenticated_frame_digest(&self) -> ObjectDigest {
        self.authenticated_frame_digest
    }

    /// Returns the exact bounded carrier handshake-frame byte count.
    #[must_use]
    pub const fn authenticated_frame_bytes(&self) -> u32 {
        self.authenticated_frame_bytes
    }

    /// Returns the durable coordinator epoch authenticated by the carrier.
    #[must_use]
    pub const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }

    /// Returns the carrier authentication time.
    #[must_use]
    pub const fn authenticated_at_unix_seconds(&self) -> u64 {
        self.authenticated_at_unix_seconds
    }

    /// Returns the fail-closed session currentness deadline.
    #[must_use]
    pub const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }

    /// Reports whether the authenticated session is current at an exact time.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        coordinator_unix_seconds >= self.authenticated_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }

    /// Returns negotiated coordinator-to-node semantics.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the request ceiling enforced before allocation.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> u32 {
        self.maximum_request_bytes
    }

    /// Returns the response ceiling enforced before allocation.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u32 {
        self.maximum_response_bytes
    }

    /// Returns the protected verifier replay-fence commitment.
    #[must_use]
    pub(super) const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }

    /// Returns the carrier-binding commitment without exposing binding bytes.
    #[must_use]
    pub(super) fn binding_digest(&self) -> ObjectDigest {
        carrier_binding_digest(self.binding)
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
    /// Constructs one watch cursor.
    ///
    /// The event sequence must be at or beyond the binding's complete-bootstrap
    /// watermark. A zero watermark may name the position before the first event.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::Unspecified`] for zero identity
    /// fields, or [`InvalidMultiNodeProtocol::WatchBindingMismatch`] when the
    /// cursor falls below its bootstrap or retained-history floor.
    pub(super) fn new(
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

/// Commits a complete bootstrap from which an exact watch may resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeWatchBootstrapV1 {
    cursor: NodeWatchCursorV1,
    inventory_digest: ObjectDigest,
}

impl NodeWatchBootstrapV1 {
    /// Constructs one complete authenticated bootstrap commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::WatchBindingMismatch`] unless the
    /// validated inventory cursor is exactly at its binding's bootstrap watermark.
    pub fn from_validated_inventory(
        inventory: &CarrierValidatedResyncInventoryV1,
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let cursor = inventory.inventory().cursor();
        let inventory_digest = inventory.canonical_inventory_digest();
        if !inventory.is_current_at(coordinator_unix_seconds)
            || cursor.event_sequence() != cursor.binding().bootstrap_watermark()
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        if cursor.last_event_uid()
            != stable_watch_bootstrap_uid(cursor.binding(), cursor.lineage(), inventory_digest)
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        Ok(Self {
            cursor,
            inventory_digest,
        })
    }

    /// Returns the exact watch cursor established by the bootstrap.
    #[must_use]
    pub const fn cursor(self) -> NodeWatchCursorV1 {
        self.cursor
    }

    /// Returns the canonical complete-inventory commitment.
    #[must_use]
    pub const fn inventory_digest(self) -> ObjectDigest {
        self.inventory_digest
    }
}

/// Carries a complete node-local assignment inventory at one watch position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResyncInventoryV1 {
    cursor: NodeWatchCursorV1,
    capabilities: NodeCapabilitySnapshotV1,
    observation_sequence: ObservationSequence,
    assignments: Vec<NodeAssignmentObservationV1>,
}

impl ResyncInventoryV1 {
    /// Constructs one complete, canonical node inventory.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::InventoryNotCanonical`] when rows
    /// exceed bounds, are not strictly ordered by complete assignment key,
    /// name another node or boot, or are newer than the inventory observation
    /// boundary.
    pub fn new(
        cursor: NodeWatchCursorV1,
        capabilities: NodeCapabilitySnapshotV1,
        observation_sequence: ObservationSequence,
        assignments: Vec<NodeAssignmentObservationV1>,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        if observation_sequence.get() == 0 {
            return Err(InvalidMultiNodeProtocol::Unspecified);
        }
        if capabilities.node() != cursor.node()
            || capabilities.lineage() != cursor.lineage()
            || assignments.len() > MAX_RESYNC_ASSIGNMENTS
            || !assignments
                .windows(2)
                .all(|pair| compare_observation_key(&pair[0], &pair[1]).is_lt())
            || assignments.iter().any(|observation| {
                observation.node() != cursor.node()
                    || observation.lineage() != cursor.lineage()
                    || observation.sequence() > observation_sequence
            })
        {
            return Err(InvalidMultiNodeProtocol::InventoryNotCanonical);
        }
        Ok(Self {
            cursor,
            capabilities,
            observation_sequence,
            assignments,
        })
    }

    /// Returns the exact complete-inventory watch position.
    #[must_use]
    pub const fn cursor(&self) -> NodeWatchCursorV1 {
        self.cursor
    }

    /// Returns the capability snapshot for the inventoried node boot.
    #[must_use]
    pub const fn capabilities(&self) -> &NodeCapabilitySnapshotV1 {
        &self.capabilities
    }

    /// Returns the node observation boundary for this inventory.
    #[must_use]
    pub const fn observation_sequence(&self) -> ObservationSequence {
        self.observation_sequence
    }

    /// Returns all observed assignments in canonical complete-key order.
    #[must_use]
    pub fn assignments(&self) -> &[NodeAssignmentObservationV1] {
        &self.assignments
    }
}

/// Marks a complete inventory whose exact carrier frame was authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarrierValidatedResyncInventoryV1 {
    inventory: ResyncInventoryV1,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    carrier_binding_digest: ObjectDigest,
    canonical_inventory_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
}

impl CarrierValidatedResyncInventoryV1 {
    /// Returns the complete validated inventory semantics.
    #[must_use]
    pub const fn inventory(&self) -> &ResyncInventoryV1 {
        &self.inventory
    }

    /// Returns the authenticated carrier-binding commitment.
    #[must_use]
    pub const fn carrier_binding_digest(&self) -> ObjectDigest {
        self.carrier_binding_digest
    }

    /// Returns the digest of exact canonical inventory bytes.
    #[must_use]
    pub const fn canonical_inventory_digest(&self) -> ObjectDigest {
        self.canonical_inventory_digest
    }

    /// Returns the authenticated audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the exact canonical carrier-frame byte count.
    #[must_use]
    pub const fn canonical_frame_bytes(&self) -> u32 {
        self.canonical_frame_bytes
    }

    /// Returns the durable coordinator epoch.
    #[must_use]
    pub const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }

    /// Reports whether this exact authenticated inventory remains current.
    #[must_use]
    pub fn is_current_at(&self, coordinator_unix_seconds: u64) -> bool {
        coordinator_unix_seconds >= self.authenticated_at_unix_seconds
            && coordinator_unix_seconds <= self.valid_until_unix_seconds
    }
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

/// Enforces the exact version-one protobuf envelope and byte-exact decoding.
///
/// Protobuf carries an explicit schema, reader/writer compatibility window,
/// and a generated oneof whose variant must match the outer compatibility
/// frame's kind. Both layers require byte-exact re-encoding, so unknown,
/// duplicate, reordered, trailing, or noncanonical fields fail closed.
/// Evolution requires a negotiated version.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalNodeSemanticCodecV1 {
    legacy_json: bool,
}

impl CanonicalNodeSemanticCodecV1 {
    /// Constructs the sole closed version-one semantic codec.
    #[must_use]
    pub const fn new() -> Self {
        Self { legacy_json: false }
    }

    pub(in crate::multi_node) const fn legacy_json() -> Self {
        Self { legacy_json: true }
    }

    fn verify_bounded_bytes(
        bytes: &[u8],
        maximum_bytes: u32,
    ) -> Result<(), InvalidMultiNodeProtocol> {
        if bytes.is_empty() || bytes.len() > maximum_bytes as usize {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(())
    }

    fn decode_request(
        &self,
        session: &AuthenticatedNodeSessionV1,
        frame: &CanonicalNodeFrameV1<'_>,
        coordinator_unix_seconds: u64,
    ) -> Result<NodeRequestBodyV1, InvalidMultiNodeProtocol> {
        Self::verify_bounded_bytes(frame.body(), session.maximum_request_bytes())?;
        let body = if self.legacy_json {
            semantic_codec_v1::decode_request(
                session,
                frame.kind(),
                frame.body(),
                coordinator_unix_seconds,
            )?
        } else {
            protobuf_codec_v1::decode_request(
                session,
                frame.kind(),
                frame.body(),
                coordinator_unix_seconds,
            )?
        };
        if self.encode_request(&body)?.as_slice() != frame.body() {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(body)
    }

    pub(in crate::multi_node) fn encode_request(
        &self,
        body: &NodeRequestBodyV1,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        let bytes = if self.legacy_json {
            semantic_codec_v1::encode_request(body)?
        } else {
            protobuf_codec_v1::encode_request(body)?
        };
        Self::verify_bounded_bytes(&bytes, MAX_NODE_REQUEST_BYTES)?;
        Ok(bytes)
    }

    fn decode_response(
        &self,
        context: AuthenticatedEvidenceContextV1,
        frame: &CanonicalNodeFrameV1<'_>,
        authenticated_at_unix_seconds: u64,
    ) -> Result<NodeResponseBodyV1, InvalidMultiNodeProtocol> {
        Self::verify_bounded_bytes(frame.body(), MAX_NODE_RESPONSE_BYTES)?;
        let body = if self.legacy_json {
            semantic_codec_v1::decode_response(
                context,
                frame.kind(),
                frame.body(),
                authenticated_at_unix_seconds,
                self,
            )?
        } else {
            protobuf_codec_v1::decode_response(
                context,
                frame.kind(),
                frame.body(),
                authenticated_at_unix_seconds,
                self,
            )?
        };
        if self.encode_response(&body)?.as_slice() != frame.body() {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(body)
    }

    /// Decodes the exact capability snapshot carried by a protected bootstrap.
    pub(super) fn decode_protected_bootstrap_capabilities(
        &self,
        context: AuthenticatedEvidenceContextV1,
        frame: &CanonicalNodeFrameV1<'_>,
        current_unix_seconds: u64,
    ) -> Result<NodeCapabilitySnapshotV1, InvalidMultiNodeProtocol> {
        if frame.kind() != CanonicalNodeFrameKindV1::GetCapabilitiesResponse
            || frame.frame_digest() != context.canonical_frame_digest()
            || frame.binding_digest() != context.carrier_binding_digest()
            || frame.audience_digest() != context.audience_digest()
            || frame.disclosure_domain_digest() != context.disclosure_domain_digest()
            || u32::try_from(frame.bytes().len())
                .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?
                != context.canonical_frame_bytes()
            || !context.is_current_at(current_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        match self.decode_response(context, frame, current_unix_seconds)? {
            NodeResponseBodyV1::Capabilities(snapshot) => Ok(*snapshot),
            _ => Err(InvalidMultiNodeProtocol::MethodMismatch),
        }
    }

    pub(in crate::multi_node) fn encode_response(
        &self,
        body: &NodeResponseBodyV1,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        let bytes = if self.legacy_json {
            semantic_codec_v1::encode_response(body)?
        } else {
            protobuf_codec_v1::encode_response(body)?
        };
        Self::verify_bounded_bytes(&bytes, MAX_NODE_RESPONSE_BYTES)?;
        Ok(bytes)
    }

    pub(super) fn encode_watch_event_body(
        &self,
        body: &NodeWatchEventBodyV1,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        let bytes = if self.legacy_json {
            semantic_codec_v1::encode_watch_event_body(body)?
        } else {
            protobuf_codec_v1::encode_watch_event_body(body)?
        };
        Self::verify_bounded_bytes(&bytes, MAX_NODE_RESPONSE_BYTES)?;
        Ok(bytes)
    }

    pub(super) fn decode_watch_event_body(
        &self,
        bytes: &[u8],
        context: AuthenticatedEvidenceContextV1,
    ) -> Result<NodeWatchEventBodyV1, InvalidMultiNodeProtocol> {
        Self::verify_bounded_bytes(bytes, MAX_NODE_RESPONSE_BYTES)?;
        let body = if self.legacy_json {
            semantic_codec_v1::decode_watch_event_body(bytes, context)?
        } else {
            protobuf_codec_v1::decode_watch_event_body(bytes, context)?
        };
        if self.encode_watch_event_body(&body)?.as_slice() != bytes {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(body)
    }

    pub(super) fn encode_watch_inventory(
        &self,
        inventory: &ResyncInventoryV1,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        let bytes = if self.legacy_json {
            semantic_codec_v1::encode_watch_inventory(inventory)?
        } else {
            protobuf_codec_v1::encode_watch_inventory(inventory)?
        };
        Self::verify_bounded_bytes(&bytes, MAX_NODE_RESPONSE_BYTES)?;
        Ok(bytes)
    }

    pub(super) fn decode_watch_inventory(
        &self,
        bytes: &[u8],
        context: AuthenticatedEvidenceContextV1,
    ) -> Result<ResyncInventoryV1, InvalidMultiNodeProtocol> {
        Self::verify_bounded_bytes(bytes, MAX_NODE_RESPONSE_BYTES)?;
        let inventory = if self.legacy_json {
            semantic_codec_v1::decode_watch_inventory(bytes, context, self)?
        } else {
            protobuf_codec_v1::decode_watch_inventory(bytes, context, self)?
        };
        if self.encode_watch_inventory(&inventory)?.as_slice() != bytes {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(inventory)
    }
}

const fn canonical_frame_kind_name_v1(kind: CanonicalNodeFrameKindV1) -> &'static str {
    match kind {
        CanonicalNodeFrameKindV1::GetCapabilitiesRequest => "get_capabilities_request",
        CanonicalNodeFrameKindV1::GetCapabilitiesResponse => "get_capabilities_response",
        CanonicalNodeFrameKindV1::ReconcileAssignmentRequest => "reconcile_assignment_request",
        CanonicalNodeFrameKindV1::ReconcileAssignmentResponse => "reconcile_assignment_response",
        CanonicalNodeFrameKindV1::RelistAssignmentsRequest => "relist_assignments_request",
        CanonicalNodeFrameKindV1::RelistAssignmentsResponse => "relist_assignments_response",
        CanonicalNodeFrameKindV1::ReconcileDrainRequest => "reconcile_drain_request",
        CanonicalNodeFrameKindV1::ReconcileDrainResponse => "reconcile_drain_response",
        CanonicalNodeFrameKindV1::BeginSnapshotTransferRequest => "begin_snapshot_transfer_request",
        CanonicalNodeFrameKindV1::BeginSnapshotTransferResponse => {
            "begin_snapshot_transfer_response"
        }
        CanonicalNodeFrameKindV1::SnapshotChunkRequest => "snapshot_chunk_request",
        CanonicalNodeFrameKindV1::SnapshotChunkResponse => "snapshot_chunk_response",
        CanonicalNodeFrameKindV1::SnapshotDependencyRequest => "snapshot_dependency_request",
        CanonicalNodeFrameKindV1::SnapshotDependencyResponse => "snapshot_dependency_response",
        CanonicalNodeFrameKindV1::WatchRequest => "watch_request",
        CanonicalNodeFrameKindV1::WatchResponse => "watch_response",
    }
}

impl NodeRequestBodyV1 {
    const fn method(&self) -> NodeMethodV1 {
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

    const fn frame_kind(&self) -> CanonicalNodeFrameKindV1 {
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

/// Carries one request bound to an authenticated session and correlation ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRequestEnvelopeV1 {
    binding: [u8; 32],
    node: NodeId,
    request: OperationId,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    canonical_body_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    body: NodeRequestBodyV1,
}

impl NodeRequestEnvelopeV1 {
    /// Constructs one request under an exact session contract.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for a zero request identity, a
    /// cross-node assignment or drain body, or an invalid watch batch limit.
    pub(super) fn from_canonical_frame(
        session: &AuthenticatedNodeSessionV1,
        canonical_frame: &CanonicalNodeFrameV1<'_>,
        coordinator_unix_seconds: u64,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let request = canonical_frame.request();
        let body = canonical_frame.decode_request_body(session, coordinator_unix_seconds, codec)?;
        let canonical_frame_bytes = u32::try_from(canonical_frame.bytes().len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if request.as_bytes() == &[0; 16]
            || canonical_frame.kind() != body.frame_kind()
            || canonical_frame.version() != session.version()
            || canonical_frame.binding_digest() != carrier_binding_digest(session.binding())
            || canonical_frame.audience_digest() != session.audience_digest()
            || canonical_frame.disclosure_domain_digest() != session.disclosure_domain_digest()
            || canonical_frame_bytes > session.maximum_request_bytes()
            || !session.is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::Unspecified);
        }
        let matches_node = match &body {
            NodeRequestBodyV1::ReconcileAssignment(intent) => intent.node() == session.node(),
            NodeRequestBodyV1::ReconcileDrain(directive) => directive.node() == session.node(),
            NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } => {
                manifest.identity().source_node() == session.node()
                    && manifest.identity().audience_digest() == session.audience_digest()
                    && manifest.identity().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
                    && resume.as_ref().is_none_or(|checkpoint| {
                        checkpoint.identity() == manifest.identity()
                            && manifest
                                .prefix_commitment(checkpoint.next_chunk())
                                .is_ok_and(|digest| digest == checkpoint.verified_prefix_digest())
                    })
            }
            NodeRequestBodyV1::FetchSnapshotChunk { request } => {
                request.identity().source_node() == session.node()
                    && request.identity().audience_digest() == session.audience_digest()
                    && request.identity().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
            }
            NodeRequestBodyV1::FetchSnapshotDependency { request } => {
                request.identity().source_node() == session.node()
                    && request.identity().audience_digest() == session.audience_digest()
                    && request.identity().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
            }
            NodeRequestBodyV1::Watch {
                after,
                maximum_events,
            } => {
                after.node() == session.node()
                    && after.lineage() == session.lineage()
                    && after.binding().coordinator_epoch() == session.coordinator_epoch()
                    && after.binding().audience_digest() == session.audience_digest()
                    && after.binding().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
                    && *maximum_events != 0
                    && usize::from(*maximum_events) <= MAX_WATCH_EVENTS
                    && after.binding().schema().admits(session.version())
            }
            NodeRequestBodyV1::RelistAssignments { binding } => {
                binding.coordinator_epoch() == session.coordinator_epoch()
                    && binding.audience_digest() == session.audience_digest()
                    && binding.disclosure_domain_digest() == session.disclosure_domain_digest()
                    && binding.schema().admits(session.version())
            }
            NodeRequestBodyV1::GetCapabilities => true,
        };
        if !matches_node {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        Ok(Self {
            binding: session.binding(),
            node: session.node(),
            request,
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: canonical_frame.body_digest(),
            canonical_frame_digest: canonical_frame.frame_digest(),
            canonical_frame_bytes,
            body,
        })
    }

    pub(in crate::multi_node) fn from_generated_carrier(
        session: &AuthenticatedNodeSessionV1,
        request: OperationId,
        body: NodeRequestBodyV1,
        semantic_bytes: &[u8],
        carrier_bytes: &[u8],
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let canonical_frame_bytes = u32::try_from(carrier_bytes.len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if request.as_bytes() == &[0; 16]
            || semantic_bytes.is_empty()
            || carrier_bytes.is_empty()
            || canonical_frame_bytes > session.maximum_request_bytes()
            || !session.is_current_at(coordinator_unix_seconds)
            || !request_body_matches_session(session, &body)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        Ok(Self {
            binding: session.binding(),
            node: session.node(),
            request,
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: ObjectDigest::from_bytes(Sha256::digest(semantic_bytes).into()),
            canonical_frame_digest: ObjectDigest::from_bytes(Sha256::digest(carrier_bytes).into()),
            canonical_frame_bytes,
            body,
        })
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }

    /// Returns the target node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the request correlation identity.
    #[must_use]
    pub const fn request(&self) -> OperationId {
        self.request
    }

    /// Returns the authenticated request audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated request disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the canonical semantic request-body commitment.
    #[must_use]
    pub const fn canonical_body_digest(&self) -> ObjectDigest {
        self.canonical_body_digest
    }

    /// Returns the exact canonical request-frame commitment.
    #[must_use]
    pub const fn canonical_frame_digest(&self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Returns the exact bounded request-frame length.
    #[must_use]
    pub const fn canonical_frame_bytes(&self) -> u32 {
        self.canonical_frame_bytes
    }

    /// Returns the semantic request body.
    #[must_use]
    pub const fn body(&self) -> &NodeRequestBodyV1 {
        &self.body
    }
}

fn request_body_matches_session(
    session: &AuthenticatedNodeSessionV1,
    body: &NodeRequestBodyV1,
) -> bool {
    match body {
        NodeRequestBodyV1::ReconcileAssignment(intent) => intent.node() == session.node(),
        NodeRequestBodyV1::ReconcileDrain(directive) => directive.node() == session.node(),
        NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } => {
            manifest.identity().source_node() == session.node()
                && manifest.identity().audience_digest() == session.audience_digest()
                && manifest.identity().disclosure_domain_digest()
                    == session.disclosure_domain_digest()
                && resume.as_ref().is_none_or(|checkpoint| {
                    checkpoint.identity() == manifest.identity()
                        && manifest
                            .prefix_commitment(checkpoint.next_chunk())
                            .is_ok_and(|digest| digest == checkpoint.verified_prefix_digest())
                })
        }
        NodeRequestBodyV1::FetchSnapshotChunk { request } => {
            request.identity().source_node() == session.node()
                && request.identity().audience_digest() == session.audience_digest()
                && request.identity().disclosure_domain_digest()
                    == session.disclosure_domain_digest()
        }
        NodeRequestBodyV1::FetchSnapshotDependency { request } => {
            request.identity().source_node() == session.node()
                && request.identity().audience_digest() == session.audience_digest()
                && request.identity().disclosure_domain_digest()
                    == session.disclosure_domain_digest()
        }
        NodeRequestBodyV1::Watch {
            after,
            maximum_events,
        } => {
            after.node() == session.node()
                && after.lineage() == session.lineage()
                && after.binding().coordinator_epoch() == session.coordinator_epoch()
                && after.binding().audience_digest() == session.audience_digest()
                && after.binding().disclosure_domain_digest() == session.disclosure_domain_digest()
                && *maximum_events != 0
                && usize::from(*maximum_events) <= MAX_WATCH_EVENTS
                && after.binding().schema().admits(session.version())
        }
        NodeRequestBodyV1::RelistAssignments { binding } => {
            binding.coordinator_epoch() == session.coordinator_epoch()
                && binding.audience_digest() == session.audience_digest()
                && binding.disclosure_domain_digest() == session.disclosure_domain_digest()
                && binding.schema().admits(session.version())
        }
        NodeRequestBodyV1::GetCapabilities => true,
    }
}

/// Selects one watch event payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeWatchEventBodyV1 {
    /// Node capabilities or admission state changed.
    Capability(Box<NodeCapabilitySnapshotV1>),
    /// One assignment observation changed.
    Assignment(Box<NodeAssignmentObservationV1>),
    /// One drain observation changed.
    Drain(Box<DrainObservationV1>),
}

/// Stores one ordered node event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeWatchEventV1 {
    cursor: NodeWatchCursorV1,
    predecessor_event_uid: ObjectDigest,
    canonical_event_digest: ObjectDigest,
    canonical_event_bytes: u32,
    body: NodeWatchEventBodyV1,
}

impl NodeWatchEventV1 {
    /// Constructs one event and verifies that its payload names the cursor node and boot.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::InventoryNotCanonical`] when the
    /// payload and cursor do not share one node boot.
    pub(super) fn from_authenticated_history(
        cursor: NodeWatchCursorV1,
        predecessor_event_uid: ObjectDigest,
        body: NodeWatchEventBodyV1,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let matches_cursor = match &body {
            NodeWatchEventBodyV1::Capability(snapshot) => {
                snapshot.node() == cursor.node() && snapshot.lineage() == cursor.lineage()
            }
            NodeWatchEventBodyV1::Assignment(observation) => {
                observation.node() == cursor.node() && observation.lineage() == cursor.lineage()
            }
            NodeWatchEventBodyV1::Drain(observation) => {
                observation.node() == cursor.node() && observation.lineage() == cursor.lineage()
            }
        };
        let canonical_event_body = codec.encode_watch_event_body(&body)?;
        let canonical_event_digest =
            ObjectDigest::from_bytes(Sha256::digest(&canonical_event_body).into());
        let canonical_event_bytes = u32::try_from(canonical_event_body.len())
            .map_err(|_| InvalidMultiNodeProtocol::InventoryNotCanonical)?;
        if !matches_cursor
            || cursor.event_sequence() == 0
            || predecessor_event_uid.as_bytes() == &[0; 32]
            || canonical_event_body.is_empty()
            || canonical_event_body.len() > MAX_NODE_RESPONSE_BYTES as usize
            || cursor.last_event_uid()
                != stable_watch_event_uid(
                    cursor.binding(),
                    cursor.lineage(),
                    cursor.event_sequence(),
                    predecessor_event_uid,
                    canonical_event_digest,
                )
        {
            return Err(InvalidMultiNodeProtocol::InventoryNotCanonical);
        }
        Ok(Self {
            cursor,
            predecessor_event_uid,
            canonical_event_digest,
            canonical_event_bytes,
            body,
        })
    }

    /// Returns this event's resumable cursor.
    #[must_use]
    pub const fn cursor(&self) -> NodeWatchCursorV1 {
        self.cursor
    }

    /// Returns the event payload.
    #[must_use]
    pub const fn body(&self) -> &NodeWatchEventBodyV1 {
        &self.body
    }

    /// Returns the stable predecessor event UID.
    #[must_use]
    pub const fn predecessor_event_uid(&self) -> ObjectDigest {
        self.predecessor_event_uid
    }

    /// Returns the exact canonical event-payload commitment.
    #[must_use]
    pub const fn canonical_event_digest(&self) -> ObjectDigest {
        self.canonical_event_digest
    }

    /// Returns the exact bounded canonical event-body length.
    #[must_use]
    pub const fn canonical_event_bytes(&self) -> u32 {
        self.canonical_event_bytes
    }
}

/// Selects one coordinator-to-node semantic response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeResponseBodyV1 {
    /// Returns a complete capability snapshot.
    Capabilities(Box<NodeCapabilitySnapshotV1>),
    /// Returns the latest observation for reconciled assignment intent.
    Assignment(Box<NodeAssignmentObservationV1>),
    /// Returns complete assignment inventory for resynchronization.
    AssignmentInventory(Box<ResyncInventoryV1>),
    /// Returns the latest observation for reconciled drain intent.
    Drain(Box<DrainObservationV1>),
    /// Confirms a read-only transfer at an exact verified chunk boundary.
    SnapshotTransferReady {
        /// Exact immutable transfer identity.
        identity: SnapshotTransferIdentityV1,
        /// First chunk that still requires delivery.
        next_chunk: u32,
    },
    /// Returns one exact integrity-checked immutable snapshot byte range.
    SnapshotChunk {
        /// Exact immutable transfer identity.
        identity: SnapshotTransferIdentityV1,
        /// Zero-based committed chunk index.
        index: u32,
        /// Exact chunk bytes, bounded by the requested commitment.
        bytes: Vec<u8>,
    },
    /// Returns one exact bounded immutable dependency range.
    SnapshotDependency {
        /// Exact scoped transfer identity.
        identity: SnapshotTransferIdentityV1,
        /// Exact dependency descriptor.
        dependency: aos_sandbox_core::ObjectDescriptor,
        /// Exact byte offset.
        offset: u64,
        /// Exact requested bytes.
        bytes: Vec<u8>,
    },
    /// Returns a strictly ordered event batch.
    WatchBatch {
        /// Events strictly after the request cursor.
        events: Vec<NodeWatchEventV1>,
        /// Supplies the binding required for a fresh bootstrap after a cursor gap.
        cursor_gap: Option<NodeWatchBindingV1>,
    },
}

impl NodeResponseBodyV1 {
    const fn method(&self) -> NodeMethodV1 {
        match self {
            Self::Capabilities(_) => NodeMethodV1::GetCapabilities,
            Self::Assignment(_) => NodeMethodV1::ReconcileAssignment,
            Self::AssignmentInventory(_) => NodeMethodV1::RelistAssignments,
            Self::Drain(_) => NodeMethodV1::ReconcileDrain,
            Self::SnapshotTransferReady { .. } => NodeMethodV1::BeginSnapshotTransfer,
            Self::SnapshotChunk { .. } => NodeMethodV1::FetchSnapshotChunk,
            Self::SnapshotDependency { .. } => NodeMethodV1::FetchSnapshotDependency,
            Self::WatchBatch { .. } => NodeMethodV1::Watch,
        }
    }

    const fn frame_kind(&self) -> CanonicalNodeFrameKindV1 {
        match self {
            Self::Capabilities(_) => CanonicalNodeFrameKindV1::GetCapabilitiesResponse,
            Self::Assignment(_) => CanonicalNodeFrameKindV1::ReconcileAssignmentResponse,
            Self::AssignmentInventory(_) => CanonicalNodeFrameKindV1::RelistAssignmentsResponse,
            Self::Drain(_) => CanonicalNodeFrameKindV1::ReconcileDrainResponse,
            Self::SnapshotTransferReady { .. } => {
                CanonicalNodeFrameKindV1::BeginSnapshotTransferResponse
            }
            Self::SnapshotChunk { .. } => CanonicalNodeFrameKindV1::SnapshotChunkResponse,
            Self::SnapshotDependency { .. } => CanonicalNodeFrameKindV1::SnapshotDependencyResponse,
            Self::WatchBatch { .. } => CanonicalNodeFrameKindV1::WatchResponse,
        }
    }
}

/// Carries one response bound to its exact session and request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeResponseEnvelopeV1 {
    context: AuthenticatedEvidenceContextV1,
    frame_seal: AuthenticatedFrameSealV1,
    binding: [u8; 32],
    node: NodeId,
    lineage: NodeBootLineageV1,
    request: OperationId,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    canonical_body_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    body: NodeResponseBodyV1,
}

impl NodeResponseEnvelopeV1 {
    /// Constructs and validates one response to an exact request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for session mismatch, method
    /// mismatch, cross-node content, or a noncanonical watch batch.
    pub(super) fn from_authenticated_carrier(
        grant: CarrierResponseGrantV1,
        request: &NodeRequestEnvelopeV1,
        canonical_frame: &CanonicalNodeFrameV1<'_>,
        authenticated_at_unix_seconds: u64,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let (session, context, frame_seal) = grant.into_parts();
        let body =
            canonical_frame.decode_response_body(context, authenticated_at_unix_seconds, codec)?;
        let session_binding = session.binding();
        if request.binding() != &session_binding
            || request.node() != session.node()
            || request.audience_digest() != session.audience_digest()
            || request.disclosure_domain_digest() != session.disclosure_domain_digest()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let canonical_frame_bytes = u32::try_from(canonical_frame.bytes().len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if canonical_frame.kind() != body.frame_kind()
            || canonical_frame.version() != session.version()
            || canonical_frame.binding_digest() != carrier_binding_digest(session.binding())
            || canonical_frame.audience_digest() != session.audience_digest()
            || canonical_frame.disclosure_domain_digest() != session.disclosure_domain_digest()
            || canonical_frame.request() != request.request()
            || canonical_frame_bytes > session.maximum_response_bytes()
            || !session.is_current_at(authenticated_at_unix_seconds)
            || context.node() != session.node()
            || context.lineage() != session.lineage()
            || context.audience_digest() != session.audience_digest()
            || context.disclosure_domain_digest() != session.disclosure_domain_digest()
            || context.carrier_binding_digest() != session.binding_digest()
            || context.canonical_frame_digest() != canonical_frame.frame_digest()
            || context.canonical_frame_bytes() != canonical_frame_bytes
            || context.replay_fence() != session.replay_fence()
            || !context.is_current_at(authenticated_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        if request.body().method() != body.method() {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        }
        validate_response_body(&session, request.body(), &body)?;

        Ok(Self {
            context,
            frame_seal,
            binding: session_binding,
            node: session.node(),
            lineage: session.lineage(),
            request: request.request(),
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: canonical_frame.body_digest(),
            canonical_frame_digest: canonical_frame.frame_digest(),
            canonical_frame_bytes,
            coordinator_epoch: session.coordinator_epoch(),
            authenticated_at_unix_seconds,
            valid_until_unix_seconds: session.valid_until_unix_seconds(),
            body,
        })
    }

    pub(in crate::multi_node) fn from_authenticated_generated_carrier(
        grant: CarrierResponseGrantV1,
        request: &NodeRequestEnvelopeV1,
        body: NodeResponseBodyV1,
        body_digest: ObjectDigest,
        carrier_digest: ObjectDigest,
        carrier_bytes: u32,
        authenticated_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let (session, context, frame_seal) = grant.into_parts();
        if request.binding() != &session.binding()
            || request.node() != session.node()
            || request.audience_digest() != session.audience_digest()
            || request.disclosure_domain_digest() != session.disclosure_domain_digest()
            || carrier_bytes == 0
            || carrier_bytes > session.maximum_response_bytes()
            || context.canonical_frame_digest() != carrier_digest
            || context.canonical_frame_bytes() != carrier_bytes
            || context.node() != session.node()
            || context.lineage() != session.lineage()
            || context.audience_digest() != session.audience_digest()
            || context.disclosure_domain_digest() != session.disclosure_domain_digest()
            || context.carrier_binding_digest() != session.binding_digest()
            || context.replay_fence() != session.replay_fence()
            || !context.is_current_at(authenticated_at_unix_seconds)
            || !frame_seal.matches(body.frame_kind(), body_digest, context)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        if request.body().method() != body.method() {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        }
        validate_response_body(&session, request.body(), &body)?;
        Ok(Self {
            context,
            frame_seal,
            binding: session.binding(),
            node: session.node(),
            lineage: session.lineage(),
            request: request.request(),
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: body_digest,
            canonical_frame_digest: carrier_digest,
            canonical_frame_bytes: carrier_bytes,
            coordinator_epoch: session.coordinator_epoch(),
            authenticated_at_unix_seconds,
            valid_until_unix_seconds: session.valid_until_unix_seconds(),
            body,
        })
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }

    /// Returns the responding node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the echoed request correlation identity.
    #[must_use]
    pub const fn request(&self) -> OperationId {
        self.request
    }

    /// Returns the semantic response body.
    #[must_use]
    pub const fn body(&self) -> &NodeResponseBodyV1 {
        &self.body
    }

    /// Returns the canonical semantic response-body commitment.
    #[must_use]
    pub const fn canonical_body_digest(&self) -> ObjectDigest {
        self.canonical_body_digest
    }

    /// Returns the protected carrier context retained by this response.
    #[must_use]
    pub(super) const fn authenticated_context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }

    /// Returns the exact authenticated response-frame commitment.
    #[must_use]
    pub(super) const fn canonical_frame_digest(&self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Reports whether the response's authenticated interval covers `time`.
    #[must_use]
    pub(super) fn is_current_at(&self, time: u64) -> bool {
        time >= self.authenticated_at_unix_seconds && time <= self.valid_until_unix_seconds
    }

    /// Extracts carrier-validated capability evidence from this response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::MethodMismatch`] for another body,
    /// or [`InvalidMultiNodeProtocol::Unspecified`] for a zero canonical digest.
    pub fn validated_capabilities(
        &self,
    ) -> Result<CarrierValidatedCapabilityObservationV1, InvalidMultiNodeProtocol> {
        let NodeResponseBodyV1::Capabilities(snapshot) = &self.body else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        CarrierValidatedCapabilityObservationV1::from_authenticated_carrier(
            (**snapshot).clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
        )
        .map_err(|_| InvalidMultiNodeProtocol::Unspecified)
    }

    /// Extracts a carrier-validated complete inventory from this response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::MethodMismatch`] for another body,
    /// or [`InvalidMultiNodeProtocol::Unspecified`] for a zero canonical digest.
    pub fn validated_inventory(
        &self,
    ) -> Result<CarrierValidatedResyncInventoryV1, InvalidMultiNodeProtocol> {
        let NodeResponseBodyV1::AssignmentInventory(inventory) = &self.body else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        Ok(CarrierValidatedResyncInventoryV1 {
            inventory: (**inventory).clone(),
            audience_digest: self.audience_digest,
            disclosure_domain_digest: self.disclosure_domain_digest,
            carrier_binding_digest: carrier_binding_digest(self.binding),
            canonical_inventory_digest: self.canonical_frame_digest,
            canonical_frame_bytes: self.canonical_frame_bytes,
            coordinator_epoch: self.coordinator_epoch,
            authenticated_at_unix_seconds: self.authenticated_at_unix_seconds,
            valid_until_unix_seconds: self.valid_until_unix_seconds,
        })
    }

    /// Extracts one exact authenticated immutable chunk for the transfer reducer.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless request correlation, method,
    /// carrier context, scoped identity, length, and chunk digest all match.
    pub fn validated_snapshot_chunk(
        &self,
        request_envelope: &NodeRequestEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotChunkV1, InvalidMultiNodeProtocol> {
        if request_envelope.request() != self.request
            || request_envelope.binding() != &self.binding
            || request_envelope.audience_digest() != self.audience_digest
            || request_envelope.disclosure_domain_digest() != self.disclosure_domain_digest
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let NodeRequestBodyV1::FetchSnapshotChunk { request } = request_envelope.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        let NodeResponseBodyV1::SnapshotChunk {
            identity,
            index,
            bytes,
        } = &self.body
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        if identity != &request.identity() || *index != request.chunk().index() {
            return Err(InvalidMultiNodeProtocol::ResponseContentMismatch);
        }
        AuthenticatedSnapshotChunkV1::from_authenticated_carrier(
            *request,
            bytes.clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
            self.authenticated_at_unix_seconds,
        )
        .map_err(|_| InvalidMultiNodeProtocol::ResponseContentMismatch)
    }

    /// Extracts one exact authenticated immutable dependency range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless request correlation, carrier
    /// context, transfer identity, descriptor, offset, and byte count all match.
    pub fn validated_snapshot_dependency_range(
        &self,
        request_envelope: &NodeRequestEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotDependencyRangeV1, InvalidMultiNodeProtocol> {
        if request_envelope.request() != self.request
            || request_envelope.binding() != &self.binding
            || request_envelope.audience_digest() != self.audience_digest
            || request_envelope.disclosure_domain_digest() != self.disclosure_domain_digest
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let NodeRequestBodyV1::FetchSnapshotDependency { request } = request_envelope.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        let NodeResponseBodyV1::SnapshotDependency {
            identity,
            dependency,
            offset,
            bytes,
        } = &self.body
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        if identity != &request.identity()
            || dependency != request.dependency()
            || *offset != request.offset()
            || bytes.len() != request.length() as usize
        {
            return Err(InvalidMultiNodeProtocol::ResponseContentMismatch);
        }
        AuthenticatedSnapshotDependencyRangeV1::from_authenticated_carrier(
            request.clone(),
            bytes.clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
            self.authenticated_at_unix_seconds,
        )
        .map_err(|_| InvalidMultiNodeProtocol::ResponseContentMismatch)
    }

    /// Extracts one carrier-validated capability event from a watch response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::MethodMismatch`] unless the indexed
    /// event is a capability event, or `Unspecified` for a zero commitment.
    pub fn validated_watch_capability(
        &self,
        event_index: usize,
    ) -> Result<CarrierValidatedCapabilityObservationV1, InvalidMultiNodeProtocol> {
        let NodeResponseBodyV1::WatchBatch { events, cursor_gap } = &self.body else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        if cursor_gap.is_some() {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        let Some(NodeWatchEventBodyV1::Capability(snapshot)) =
            events.get(event_index).map(NodeWatchEventV1::body)
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        CarrierValidatedCapabilityObservationV1::from_authenticated_carrier(
            (**snapshot).clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
        )
        .map_err(|_| InvalidMultiNodeProtocol::Unspecified)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeMethodV1 {
    GetCapabilities,
    ReconcileAssignment,
    RelistAssignments,
    ReconcileDrain,
    BeginSnapshotTransfer,
    FetchSnapshotChunk,
    FetchSnapshotDependency,
    Watch,
}

pub(in crate::multi_node) fn validate_response_body(
    session: &AuthenticatedNodeSessionV1,
    request: &NodeRequestBodyV1,
    response: &NodeResponseBodyV1,
) -> Result<(), InvalidMultiNodeProtocol> {
    let node = session.node();
    let content_matches_request = match response {
        NodeResponseBodyV1::Capabilities(snapshot) => {
            snapshot.node() == node && snapshot.lineage() == session.lineage()
        }
        NodeResponseBodyV1::Assignment(observation) => {
            let NodeRequestBodyV1::ReconcileAssignment(intent) = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            observation.node() == node
                && observation.lineage() == session.lineage()
                && observation.matches(intent)
                && observation.desired_generation() <= intent.desired_generation()
        }
        NodeResponseBodyV1::AssignmentInventory(inventory) => {
            let NodeRequestBodyV1::RelistAssignments { binding } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            inventory.cursor().node() == node
                && inventory.cursor().lineage() == session.lineage()
                && inventory.cursor().binding() == *binding
                && binding.audience_digest() == session.audience_digest()
                && binding.disclosure_domain_digest() == session.disclosure_domain_digest()
        }
        NodeResponseBodyV1::Drain(observation) => {
            let NodeRequestBodyV1::ReconcileDrain(directive) = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            observation.node() == node
                && observation.lineage() == session.lineage()
                && observation.matches(directive)
        }
        NodeResponseBodyV1::SnapshotTransferReady {
            identity,
            next_chunk,
        } => {
            let NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            *identity == manifest.identity()
                && *next_chunk
                    == resume
                        .as_ref()
                        .map_or(0, |checkpoint| checkpoint.next_chunk())
        }
        NodeResponseBodyV1::SnapshotChunk {
            identity,
            index,
            bytes,
        } => {
            let NodeRequestBodyV1::FetchSnapshotChunk { request } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            identity == &request.identity()
                && *index == request.chunk().index()
                && request.chunk().verify_bytes(bytes).is_ok()
        }
        NodeResponseBodyV1::SnapshotDependency {
            identity,
            dependency,
            offset,
            bytes,
        } => {
            let NodeRequestBodyV1::FetchSnapshotDependency { request } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            identity == &request.identity()
                && dependency == request.dependency()
                && *offset == request.offset()
                && bytes.len() == request.length() as usize
        }
        NodeResponseBodyV1::WatchBatch { events, cursor_gap } => {
            let NodeRequestBodyV1::Watch {
                after,
                maximum_events,
            } = request
            else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            if let Some(next_binding) = cursor_gap {
                events.is_empty()
                    && next_binding.coordinator_epoch() == session.coordinator_epoch()
                    && next_binding.query_digest() == after.binding().query_digest()
                    && next_binding.authorization_digest() == after.binding().authorization_digest()
                    && next_binding.schema() == after.binding().schema()
                    && next_binding.audience_digest() == session.audience_digest()
                    && next_binding.disclosure_domain_digest() == session.disclosure_domain_digest()
                    && next_binding.history_floor_sequence()
                        >= after.binding().history_floor_sequence()
                    && (next_binding.history_floor_sequence()
                        != after.binding().history_floor_sequence()
                        || next_binding.history_floor_event_uid()
                            == after.binding().history_floor_event_uid())
                    && next_binding.bootstrap_watermark() >= after.event_sequence()
                    && (*next_binding != after.binding()
                        || next_binding.bootstrap_watermark() > after.event_sequence())
            } else {
                events.len() <= usize::from(*maximum_events)
                    && events.len() <= MAX_WATCH_EVENTS
                    && events.iter().all(|event| event.cursor().node() == node)
                    && watch_events_follow(*after, events)
            }
        }
    };
    if content_matches_request {
        Ok(())
    } else if matches!(response, NodeResponseBodyV1::WatchBatch { .. }) {
        Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical)
    } else {
        Err(InvalidMultiNodeProtocol::ResponseContentMismatch)
    }
}

fn watch_events_follow(after: NodeWatchCursorV1, events: &[NodeWatchEventV1]) -> bool {
    let mut previous = after;
    for event in events {
        let cursor = event.cursor();
        let Some(expected_sequence) = previous.event_sequence().checked_add(1) else {
            return false;
        };
        if cursor.node() != previous.node()
            || cursor.lineage() != previous.lineage()
            || cursor.binding() != previous.binding()
            || cursor.event_sequence() != expected_sequence
            || event.predecessor_event_uid() != previous.last_event_uid()
        {
            return false;
        }
        previous = cursor;
    }
    true
}

fn carrier_binding_digest(binding: [u8; 32]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.coordinator-node.carrier-binding.v1\0");
    hasher.update(binding);
    ObjectDigest::from_bytes(hasher.finalize().into())
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

/// Describes one pure resynchronization conclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssignmentResyncActionV1 {
    /// Desired state and node observation name the same assignment generation.
    InSync {
        /// Logical sandbox.
        sandbox: SandboxId,
    },
    /// Exact assignment state exists but current node capabilities no longer
    /// satisfy its required semantics.
    CapabilityDrift {
        /// Logical sandbox blocked by capability drift.
        sandbox: SandboxId,
    },
    /// Exact tuple lacks current lease/Guardian evidence or exact lifecycle realization.
    AuthorityOrLifecycleDrift {
        /// Logical sandbox blocked by stale or mismatched realization evidence.
        sandbox: SandboxId,
    },
    /// Desired assignment semantics are absent or older on the node.
    ///
    /// Republishing this intent does not authorize effects. The node must
    /// acquire current ownership authority before activation.
    RepublishIntent(Box<AssignmentIntentV1>),
    /// Node state does not match current desired assignment and needs a fresh
    /// containment plan under current ownership authority.
    ReportStaleForContainment {
        /// Logical sandbox with stale residual rows.
        sandbox: SandboxId,
        /// All stale rows in canonical complete-key order.
        observations: Vec<NodeAssignmentObservationV1>,
    },
    /// Node inventory contains an unknown assignment that must be quarantined.
    ///
    /// Quarantine is observation-only here; cleanup requires a separately
    /// authorized exact plan.
    QuarantineUnknown {
        /// Unknown logical sandbox.
        sandbox: SandboxId,
        /// All unknown rows for the sandbox in canonical complete-key order.
        observations: Vec<NodeAssignmentObservationV1>,
    },
    /// Node observation is newer than controller state, so reconciliation fails closed.
    FutureObservationConflict {
        /// Logical sandbox whose rows conflict with desired state.
        sandbox: SandboxId,
        /// Complete conflicting row set in canonical complete-key order.
        observations: Vec<NodeAssignmentObservationV1>,
    },
}

/// Stores deterministic actions derived from one complete inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentResyncPlanV1 {
    node: NodeId,
    inventory_cursor: NodeWatchCursorV1,
    inventory_digest: ObjectDigest,
    actions: Vec<AssignmentResyncActionV1>,
}

impl AssignmentResyncPlanV1 {
    /// Returns the inventoried node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the complete inventory cursor.
    #[must_use]
    pub const fn inventory_cursor(&self) -> NodeWatchCursorV1 {
        self.inventory_cursor
    }

    /// Returns the carrier-validated digest of the complete inventory bytes.
    #[must_use]
    pub const fn inventory_digest(&self) -> ObjectDigest {
        self.inventory_digest
    }

    /// Returns actions in canonical sandbox order.
    #[must_use]
    pub fn actions(&self) -> &[AssignmentResyncActionV1] {
        &self.actions
    }
}

/// Derives deterministic reconciliation conclusions from complete inventory.
///
/// The inventory wrapper can only be extracted after the response envelope and
/// exact complete bytes were carrier-validated. Its commitment is correlation
/// evidence, not an authorization signature. No returned action permits
/// ownership acquisition, reassignment, cleanup, or an effect by itself.
///
/// # Errors
///
/// Returns [`InvalidMultiNodeProtocol`] when desired rows are noncanonical or
/// name another node.
pub fn build_assignment_resync_plan(
    desired: &[AssignmentIntentV1],
    validated_inventory: &CarrierValidatedResyncInventoryV1,
    coordinator_unix_seconds: u64,
) -> Result<AssignmentResyncPlanV1, InvalidMultiNodeProtocol> {
    let inventory = validated_inventory.inventory();
    let node = inventory.cursor().node();
    if !validated_inventory.is_current_at(coordinator_unix_seconds) {
        return Err(InvalidMultiNodeProtocol::SessionMismatch);
    }
    if desired.len() > MAX_RESYNC_ASSIGNMENTS
        || !desired
            .windows(2)
            .all(|pair| pair[0].sandbox() < pair[1].sandbox())
        || desired.iter().any(|intent| intent.node() != node)
    {
        return Err(InvalidMultiNodeProtocol::DesiredAssignmentsNotCanonical);
    }

    let observed = inventory.assignments();
    let mut observed_index = 0;
    let mut actions = Vec::with_capacity(desired.len() + observed.len());

    for intent in desired {
        while observed
            .get(observed_index)
            .is_some_and(|observation| observation.sandbox() < intent.sandbox())
        {
            let sandbox = observed[observed_index].sandbox();
            let group_start = observed_index;
            while observed
                .get(observed_index)
                .is_some_and(|observation| observation.sandbox() == sandbox)
            {
                observed_index += 1;
            }
            actions.push(AssignmentResyncActionV1::QuarantineUnknown {
                sandbox,
                observations: observed[group_start..observed_index].to_vec(),
            });
        }

        let group_start = observed_index;
        let mut found_exact = false;
        let mut stale = Vec::new();
        let mut has_conflict = false;
        while observed
            .get(observed_index)
            .is_some_and(|observation| observation.sandbox() == intent.sandbox())
        {
            let observation = &observed[observed_index];
            if observation.matches(intent)
                && observation.desired_generation() == intent.desired_generation()
            {
                if found_exact {
                    // A complete inventory may not silently treat an extra
                    // realization of the desired tuple as synchronized.
                    stale.push(observation.clone());
                } else {
                    found_exact = true;
                }
            } else {
                match compare_assignment(intent, observation) {
                    AssignmentComparisonV1::Stale => stale.push(observation.clone()),
                    AssignmentComparisonV1::Conflict => has_conflict = true,
                }
            }
            observed_index += 1;
        }

        if has_conflict {
            actions.push(AssignmentResyncActionV1::FutureObservationConflict {
                sandbox: intent.sandbox(),
                observations: observed[group_start..observed_index].to_vec(),
            });
            continue;
        }
        if !stale.is_empty() {
            actions.push(AssignmentResyncActionV1::ReportStaleForContainment {
                sandbox: intent.sandbox(),
                observations: stale,
            });
            continue;
        }
        if found_exact {
            let selected_capability = intent.selected_capability_binding();
            let inventory_capabilities = inventory.capabilities();
            let capabilities_match = selected_capability.is_current_at(coordinator_unix_seconds)
                && selected_capability.node() == inventory_capabilities.node()
                && selected_capability.lineage() == inventory_capabilities.lineage()
                && selected_capability.sequence() == inventory_capabilities.sequence()
                && selected_capability.audience_digest() == validated_inventory.audience_digest()
                && selected_capability.disclosure_domain_digest()
                    == validated_inventory.disclosure_domain_digest()
                && selected_capability.carrier_binding_digest()
                    == validated_inventory.carrier_binding_digest()
                && selected_capability.coordinator_epoch()
                    == validated_inventory.coordinator_epoch()
                && intent
                    .assignment()
                    .manifest()
                    .required_features()
                    .iter()
                    .all(|feature| inventory_capabilities.supports_feature(feature));
            let exact_observation = observed[group_start..observed_index]
                .iter()
                .find(|observation| observation.matches(intent));
            let realization_matches = exact_observation.is_some_and(|observation| {
                let exact_phase = match intent.desired_lifecycle() {
                    aos_sandbox_core::state::DesiredSandboxState::Running
                    | aos_sandbox_core::state::DesiredSandboxState::Suspended(_) => {
                        aos_sandbox_core::state::AssignmentPhase::Active
                    }
                    aos_sandbox_core::state::DesiredSandboxState::Stopped => {
                        aos_sandbox_core::state::AssignmentPhase::Fenced
                    }
                    aos_sandbox_core::state::DesiredSandboxState::Deleted => {
                        aos_sandbox_core::state::AssignmentPhase::Released
                    }
                };
                observation.realized_lifecycle() == Some(intent.desired_lifecycle())
                    && observation.phase() == exact_phase
                    && observation
                        .context()
                        .is_current_at(coordinator_unix_seconds)
                    && observation.authority().is_some_and(|authority| {
                        authority.is_current_for(
                            intent,
                            observation.lineage(),
                            coordinator_unix_seconds,
                        )
                    })
            });
            actions.push(if !capabilities_match {
                AssignmentResyncActionV1::CapabilityDrift {
                    sandbox: intent.sandbox(),
                }
            } else if realization_matches {
                AssignmentResyncActionV1::InSync {
                    sandbox: intent.sandbox(),
                }
            } else {
                AssignmentResyncActionV1::AuthorityOrLifecycleDrift {
                    sandbox: intent.sandbox(),
                }
            });
        } else {
            actions.push(AssignmentResyncActionV1::RepublishIntent(Box::new(
                intent.clone(),
            )));
        }
    }

    while let Some(observation) = observed.get(observed_index) {
        let sandbox = observation.sandbox();
        let group_start = observed_index;
        while observed
            .get(observed_index)
            .is_some_and(|observation| observation.sandbox() == sandbox)
        {
            observed_index += 1;
        }
        actions.push(AssignmentResyncActionV1::QuarantineUnknown {
            sandbox,
            observations: observed[group_start..observed_index].to_vec(),
        });
    }

    Ok(AssignmentResyncPlanV1 {
        node,
        inventory_cursor: inventory.cursor(),
        inventory_digest: validated_inventory.canonical_inventory_digest(),
        actions,
    })
}

fn compare_assignment(
    intent: &AssignmentIntentV1,
    observation: &NodeAssignmentObservationV1,
) -> AssignmentComparisonV1 {
    let same_epoch_conflict = observation.epoch() == intent.epoch()
        && (observation.incarnation() != intent.incarnation()
            || observation.desired_generation() > intent.desired_generation()
            || (observation.desired_generation() == intent.desired_generation()
                && observation.assignment_digest() != intent.assignment_digest()));
    if observation.epoch() > intent.epoch() || same_epoch_conflict {
        AssignmentComparisonV1::Conflict
    } else {
        AssignmentComparisonV1::Stale
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssignmentComparisonV1 {
    Stale,
    Conflict,
}

fn compare_observation_key(
    left: &NodeAssignmentObservationV1,
    right: &NodeAssignmentObservationV1,
) -> std::cmp::Ordering {
    left.sandbox()
        .cmp(&right.sandbox())
        .then_with(|| left.epoch().cmp(&right.epoch()))
        .then_with(|| left.incarnation().cmp(&right.incarnation()))
        .then_with(|| left.desired_generation().cmp(&right.desired_generation()))
        .then_with(|| left.assignment_digest().cmp(&right.assignment_digest()))
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
    fn from_byte(byte: u8) -> Option<Self> {
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

/// Borrows one fully validated canonical carrier frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNodeFrameV1<'a> {
    kind: CanonicalNodeFrameKindV1,
    version: ProtocolVersion,
    binding_digest: ObjectDigest,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    request: OperationId,
    body_digest: ObjectDigest,
    frame_digest: ObjectDigest,
    bytes: &'a [u8],
    body: &'a [u8],
}

impl<'a> CanonicalNodeFrameV1<'a> {
    /// Decodes one hostile frame with exact length and digest enforcement.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::NonCanonicalFrame`] for bad magic,
    /// closed discriminant, bounds, trailing bytes, or any digest mismatch.
    pub fn decode(bytes: &'a [u8], maximum_bytes: u32) -> Result<Self, InvalidMultiNodeProtocol> {
        if maximum_bytes == 0 || maximum_bytes > MAX_NODE_RESPONSE_BYTES {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        let mut decoder = BoundedFrameDecoderV1::new(bytes, maximum_bytes as usize)
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        if decoder
            .read_exact(8)
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?
            != b"AOSNODE1"
        {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        let kind = CanonicalNodeFrameKindV1::from_byte(
            decoder
                .read_u8()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        )
        .ok_or(InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let version = ProtocolVersion::new(
            decoder
                .read_u16()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
            decoder
                .read_u16()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        );
        let binding_digest = ObjectDigest::from_bytes(
            decoder
                .read_exact(32)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?
                .try_into()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        );
        let audience_digest = ObjectDigest::from_bytes(
            decoder
                .read_exact(32)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?
                .try_into()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        );
        let disclosure_domain_digest = ObjectDigest::from_bytes(
            decoder
                .read_exact(32)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?
                .try_into()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        );
        let request = OperationId::from_bytes(
            decoder
                .read_exact(16)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?
                .try_into()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        );
        let declared_body_digest = ObjectDigest::from_bytes(
            decoder
                .read_exact(32)
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?
                .try_into()
                .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?,
        );
        let body = decoder
            .read_bounded_bytes(maximum_bytes as usize)
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        decoder
            .finish()
            .map_err(|_| InvalidMultiNodeProtocol::NonCanonicalFrame)?;
        let body_digest = ObjectDigest::from_bytes(Sha256::digest(body).into());
        if version.major() == 0
            || binding_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || request.as_bytes() == &[0; 16]
            || declared_body_digest != body_digest
        {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(Self {
            kind,
            version,
            binding_digest,
            audience_digest,
            disclosure_domain_digest,
            request,
            body_digest,
            frame_digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
            bytes,
            body,
        })
    }

    /// Encodes one exact canonical bounded request frame from semantic state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] when semantic encoding is not
    /// canonical or the resulting frame exceeds a bound.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_request(
        body: &NodeRequestBodyV1,
        version: ProtocolVersion,
        binding_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        request: OperationId,
        maximum_bytes: u32,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        if maximum_bytes == 0 || maximum_bytes > MAX_NODE_REQUEST_BYTES {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        let canonical_body = codec.encode_request(body)?;
        Self::encode_body(
            body.frame_kind(),
            version,
            binding_digest,
            audience_digest,
            disclosure_domain_digest,
            request,
            &canonical_body,
            maximum_bytes,
        )
    }

    /// Encodes one exact canonical bounded response frame from semantic state.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] when semantic encoding is not
    /// canonical or the resulting frame exceeds a bound.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_response(
        body: &NodeResponseBodyV1,
        version: ProtocolVersion,
        binding_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        request: OperationId,
        maximum_bytes: u32,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        validate_watch_event_sources(body, codec)?;
        let canonical_body = codec.encode_response(body)?;
        Self::encode_body(
            body.frame_kind(),
            version,
            binding_digest,
            audience_digest,
            disclosure_domain_digest,
            request,
            &canonical_body,
            maximum_bytes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_body(
        kind: CanonicalNodeFrameKindV1,
        version: ProtocolVersion,
        binding_digest: ObjectDigest,
        audience_digest: ObjectDigest,
        disclosure_domain_digest: ObjectDigest,
        request: OperationId,
        body: &[u8],
        maximum_bytes: u32,
    ) -> Result<Vec<u8>, InvalidMultiNodeProtocol> {
        const HEADER_BYTES: usize = 8 + 1 + 2 + 2 + 32 + 32 + 32 + 16 + 32 + 4;
        let frame_length = HEADER_BYTES
            .checked_add(body.len())
            .ok_or(InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if body.len() > u32::MAX as usize
            || version.major() == 0
            || maximum_bytes == 0
            || maximum_bytes > MAX_NODE_RESPONSE_BYTES
            || frame_length > maximum_bytes as usize
            || frame_length > MAX_NODE_RESPONSE_BYTES as usize
            || binding_digest.as_bytes() == &[0; 32]
            || audience_digest.as_bytes() == &[0; 32]
            || disclosure_domain_digest.as_bytes() == &[0; 32]
            || request.as_bytes() == &[0; 16]
        {
            return Err(InvalidMultiNodeProtocol::InvalidFrameLimits);
        }
        let mut frame = Vec::with_capacity(frame_length);
        frame.extend_from_slice(b"AOSNODE1");
        frame.push(kind as u8);
        frame.extend_from_slice(&version.major().to_be_bytes());
        frame.extend_from_slice(&version.minor().to_be_bytes());
        frame.extend_from_slice(binding_digest.as_bytes());
        frame.extend_from_slice(audience_digest.as_bytes());
        frame.extend_from_slice(disclosure_domain_digest.as_bytes());
        frame.extend_from_slice(request.as_bytes());
        frame.extend_from_slice(ObjectDigest::from_bytes(Sha256::digest(body).into()).as_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        Ok(frame)
    }

    /// Decodes and byte-exactly revalidates the contained semantic request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::NonCanonicalFrame`] unless the codec
    /// accepts the hostile bytes and its canonical source encoding is identical.
    fn decode_request_body(
        &self,
        session: &AuthenticatedNodeSessionV1,
        coordinator_unix_seconds: u64,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<NodeRequestBodyV1, InvalidMultiNodeProtocol> {
        let body = codec.decode_request(session, self, coordinator_unix_seconds)?;
        let canonical = codec.encode_request(&body)?;
        if body.frame_kind() != self.kind
            || canonical.as_slice() != self.body
            || ObjectDigest::from_bytes(Sha256::digest(&canonical).into()) != self.body_digest
        {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(body)
    }

    /// Decodes and byte-exactly revalidates the contained semantic response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::NonCanonicalFrame`] unless the codec
    /// accepts the hostile bytes and its canonical source encoding is identical.
    fn decode_response_body(
        &self,
        context: AuthenticatedEvidenceContextV1,
        authenticated_at_unix_seconds: u64,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<NodeResponseBodyV1, InvalidMultiNodeProtocol> {
        let body = codec.decode_response(context, self, authenticated_at_unix_seconds)?;
        validate_watch_event_sources(&body, codec)?;
        let canonical = codec.encode_response(&body)?;
        if body.frame_kind() != self.kind
            || canonical.as_slice() != self.body
            || ObjectDigest::from_bytes(Sha256::digest(&canonical).into()) != self.body_digest
        {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
        Ok(body)
    }

    /// Returns the closed frame-body kind.
    #[must_use]
    pub const fn kind(&self) -> CanonicalNodeFrameKindV1 {
        self.kind
    }

    /// Returns the independent protocol semantic version.
    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Returns the authenticated channel-binding commitment.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the authenticated audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the exact disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the request correlation identity carried by exact frame bytes.
    #[must_use]
    pub const fn request(&self) -> OperationId {
        self.request
    }

    /// Returns the canonical semantic body commitment.
    #[must_use]
    pub const fn body_digest(&self) -> ObjectDigest {
        self.body_digest
    }

    /// Returns the digest of exact canonical frame bytes.
    #[must_use]
    pub const fn frame_digest(&self) -> ObjectDigest {
        self.frame_digest
    }

    /// Returns exact canonical frame bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the bounded canonical semantic body bytes.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }
}

fn validate_watch_event_sources(
    body: &NodeResponseBodyV1,
    codec: &CanonicalNodeSemanticCodecV1,
) -> Result<(), InvalidMultiNodeProtocol> {
    let NodeResponseBodyV1::WatchBatch { events, .. } = body else {
        return Ok(());
    };
    if events.len() > MAX_WATCH_EVENTS {
        return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
    }
    for event in events {
        let canonical = codec.encode_watch_event_body(event.body())?;
        let digest = ObjectDigest::from_bytes(Sha256::digest(&canonical).into());
        let cursor = event.cursor();
        if canonical.is_empty()
            || canonical.len() > MAX_NODE_RESPONSE_BYTES as usize
            || digest != event.canonical_event_digest()
            || cursor.last_event_uid()
                != stable_watch_event_uid(
                    cursor.binding(),
                    cursor.lineage(),
                    cursor.event_sequence(),
                    event.predecessor_event_uid(),
                    digest,
                )
        {
            return Err(InvalidMultiNodeProtocol::NonCanonicalFrame);
        }
    }
    Ok(())
}

/// Reports a bounded canonical frame-decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BoundedFrameDecodeError {
    /// The frame or a declared field exceeds its allocation-independent ceiling.
    #[error("multi-node frame exceeds its declared bound")]
    LimitExceeded,
    /// A fixed-width or length-prefixed field ends past the frame boundary.
    #[error("multi-node frame is truncated")]
    Truncated,
    /// Canonical decoding left unconsumed trailing bytes.
    #[error("multi-node frame contains trailing bytes")]
    TrailingBytes,
}

/// Reads a borrowed hostile frame using checked, allocation-free primitives.
///
/// Semantic codecs can layer closed discriminants and field validation on
/// these primitives. Every length is checked against both a caller ceiling and
/// the remaining source before any owned allocation is possible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedFrameDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedFrameDecoderV1<'a> {
    /// Opens one borrowed frame after enforcing its carrier-specific ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::LimitExceeded`] when the source is
    /// larger than `maximum_bytes` or the ceiling is zero.
    pub fn new(bytes: &'a [u8], maximum_bytes: usize) -> Result<Self, BoundedFrameDecodeError> {
        if maximum_bytes == 0 || bytes.len() > maximum_bytes {
            return Err(BoundedFrameDecodeError::LimitExceeded);
        }
        Ok(Self { bytes, offset: 0 })
    }

    /// Reads one canonical unsigned byte.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::Truncated`] at end of input.
    pub fn read_u8(&mut self) -> Result<u8, BoundedFrameDecodeError> {
        Ok(self.read_exact(1)?[0])
    }

    /// Reads one canonical big-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::Truncated`] for an incomplete integer.
    pub fn read_u16(&mut self) -> Result<u16, BoundedFrameDecodeError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| BoundedFrameDecodeError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Reads one canonical big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::Truncated`] for an incomplete integer.
    pub fn read_u32(&mut self) -> Result<u32, BoundedFrameDecodeError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| BoundedFrameDecodeError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Reads one canonical big-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::Truncated`] for an incomplete integer.
    pub fn read_u64(&mut self) -> Result<u64, BoundedFrameDecodeError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| BoundedFrameDecodeError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads a `u32`-length-prefixed borrowed byte string under a field ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::LimitExceeded`] before slicing when
    /// the declared length exceeds `maximum_length`, or `Truncated` when the
    /// declared bytes are not present.
    pub fn read_bounded_bytes(
        &mut self,
        maximum_length: usize,
    ) -> Result<&'a [u8], BoundedFrameDecodeError> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| BoundedFrameDecodeError::LimitExceeded)?;
        if length > maximum_length {
            return Err(BoundedFrameDecodeError::LimitExceeded);
        }
        self.read_exact(length)
    }

    /// Completes canonical decoding only when the frame was consumed exactly.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedFrameDecodeError::TrailingBytes`] for unconsumed input.
    pub fn finish(self) -> Result<(), BoundedFrameDecodeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BoundedFrameDecodeError::TrailingBytes)
        }
    }

    /// Reads a fixed-size field without allocating or advancing on failure.
    pub(crate) fn read_array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], BoundedFrameDecodeError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| BoundedFrameDecodeError::Truncated)
    }

    /// Reports whether all input bytes have been consumed.
    pub(crate) fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    /// Returns the exact number of bytes consumed for authenticated prefix binding.
    pub(crate) const fn position(&self) -> usize {
        self.offset
    }

    /// Reads an exact borrowed field without allocating or advancing on failure.
    pub(crate) fn read_exact(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], BoundedFrameDecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BoundedFrameDecodeError::LimitExceeded)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(BoundedFrameDecodeError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
}
