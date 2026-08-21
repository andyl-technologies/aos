//! Domain-separated streaming content-store contracts for campaigns.
//!
//! The module separates immutable logical objects from mutable named refs. A
//! [`ContentId`] identifies canonical plaintext bytes independently of their
//! directory, pack, compression, encryption, cache, or archival placement.
//! [`ImmutableBlobBackend`] and [`MutableRefBackend`] are deliberately distinct:
//! immutable stores may be tiered and mirrored, while one campaign namespace
//! has one authoritative ref backend. Physical blob inventory and candidate
//! removal require the separately held [`BlobStoreAdmin`] capability; complete
//! ref-namespace inventory requires [`RefStoreAdmin`].
//!
//! Built-in memory and directory leaves are public. Composition implementations
//! remain private and can only be assembled through the admitted [`StoreGraph`]
//! configuration algebra.

use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;

mod admin;
mod composition;
mod directory;
mod graph;
mod memory;
mod write_back;

pub use admin::{
    BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary, BlobStoreAdmin,
    InventoryGeneration, PlannedDeleteDisposition, RefInventoryFence, RefInventoryGeneration,
    RefInventoryRecord, RefInventorySummary, RefPublicationGuard, RefStoreAdmin,
};
pub use directory::{DirectoryBlobBackend, DirectoryRefBackend};
pub use graph::{
    StoreGraph, StoreGraphConfig, StoreNodeDescription, StoreNodeId, StoreNodeKind,
    StoreNodeMetrics, StoreNodeMetricsDescription, StoreNodeSpec, StoreWriteBackFlushSummary,
};
pub use memory::{MemoryBlobBackend, MemoryRefBackend};
pub use write_back::{
    WriteBackRetentionAdmin, WriteBackRetentionFence, WriteBackRetentionGeneration,
    WriteBackRetentionRoot, WriteBackRetentionSummary,
};

#[cfg(test)]
mod tests;

const CONTENT_ID_DOMAIN: &[u8] = b"crucible.content-object.v1";

/// Identifies the semantic kind of one logical content object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// Canonical campaign fact or command record.
    CampaignFact,
    /// Immutable campaign snapshot.
    CampaignSnapshot,
    /// Persistent Merkle collection node.
    MerkleNode,
    /// Scenario definition or referenced immutable scenario artifact.
    Scenario,
    /// Canonical scenario configuration and schedule artifact.
    Configuration,
    /// Campaign policy, planner artifact, or planner state.
    Policy,
    /// Exact checkpoint manifest.
    ExactManifest,
    /// Logical guest RAM page or extent.
    RamExtent,
    /// Logical disk page or extent.
    DiskExtent,
    /// Opaque device or QEMU VMState artifact.
    DeviceState,
    /// Canonical observation or measurement object.
    Observation,
    /// Finding or self-contained reproduction artifact.
    Finding,
    /// Rebuildable projection such as frontier, coverage, or statistics.
    Projection,
    /// Log or trace artifact.
    Trace,
}

impl ObjectKind {
    /// Returns the stable wire and path tag for this object kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CampaignFact => "campaign-fact",
            Self::CampaignSnapshot => "campaign-snapshot",
            Self::MerkleNode => "merkle-node",
            Self::Scenario => "scenario",
            Self::Configuration => "configuration",
            Self::Policy => "policy",
            Self::ExactManifest => "exact-manifest",
            Self::RamExtent => "ram-extent",
            Self::DiskExtent => "disk-extent",
            Self::DeviceState => "device-state",
            Self::Observation => "observation",
            Self::Finding => "finding",
            Self::Projection => "projection",
            Self::Trace => "trace",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "campaign-fact" => Some(Self::CampaignFact),
            "campaign-snapshot" => Some(Self::CampaignSnapshot),
            "merkle-node" => Some(Self::MerkleNode),
            "scenario" => Some(Self::Scenario),
            "configuration" => Some(Self::Configuration),
            "policy" => Some(Self::Policy),
            "exact-manifest" => Some(Self::ExactManifest),
            "ram-extent" => Some(Self::RamExtent),
            "disk-extent" => Some(Self::DiskExtent),
            "device-state" => Some(Self::DeviceState),
            "observation" => Some(Self::Observation),
            "finding" => Some(Self::Finding),
            "projection" => Some(Self::Projection),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }
}

/// Domain-separated identity of canonical plaintext object bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId {
    kind: ObjectKind,
    schema_version: u32,
    digest: [u8; 32],
}

impl ContentId {
    /// Computes an identity for canonical bytes of `kind` and `schema_version`.
    #[must_use]
    pub fn for_bytes(kind: ObjectKind, schema_version: u32, bytes: &[u8]) -> Self {
        let logical_length = bytes.len() as u64;
        let mut hasher = content_hasher(kind, schema_version, logical_length);
        hasher.update(bytes);
        Self {
            kind,
            schema_version,
            digest: *hasher.finalize().as_bytes(),
        }
    }

    /// Computes an identity by reading a reopenable bounded source.
    ///
    /// # Errors
    ///
    /// Returns a source I/O error or [`StoreError::InvalidSourceLength`] when
    /// an opened stream does not contain exactly its declared logical length.
    pub fn for_source(
        kind: ObjectKind,
        schema_version: u32,
        source: &dyn BlobSource,
    ) -> Result<Self, StoreError> {
        let digest = digest_source(kind, schema_version, source)?;
        Ok(Self {
            kind,
            schema_version,
            digest,
        })
    }

    /// Returns the semantic object kind.
    #[must_use]
    pub const fn kind(self) -> ObjectKind {
        self.kind
    }

    /// Returns the canonical object schema version.
    #[must_use]
    pub const fn schema_version(self) -> u32 {
        self.schema_version
    }

    /// Returns the raw 32-byte content digest.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Returns whether `bytes` authenticate as this logical object.
    #[must_use]
    pub fn authenticates(self, bytes: &[u8]) -> bool {
        Self::for_bytes(self.kind, self.schema_version, bytes) == self
    }

    /// Renders the stable `kind.schema.digest` representation.
    #[must_use]
    pub fn encode(self) -> String {
        format!(
            "{}.{}.{}",
            self.kind.as_str(),
            self.schema_version,
            encode_hex(&self.digest)
        )
    }

    /// Parses the stable `kind.schema.digest` representation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidId`] when the kind, version, separators, or
    /// digest are malformed.
    pub fn parse(value: &str) -> Result<Self, StoreError> {
        let mut fields = value.split('.');
        let kind = fields
            .next()
            .and_then(ObjectKind::parse)
            .ok_or(StoreError::InvalidId)?;
        let schema_version = fields
            .next()
            .and_then(|field| field.parse::<u32>().ok())
            .ok_or(StoreError::InvalidId)?;
        let digest = fields
            .next()
            .and_then(decode_digest)
            .ok_or(StoreError::InvalidId)?;
        if fields.next().is_some() {
            return Err(StoreError::InvalidId);
        }
        let parsed = Self {
            kind,
            schema_version,
            digest,
        };
        if parsed.encode() != value {
            return Err(StoreError::InvalidId);
        }
        Ok(parsed)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encode())
    }
}

/// Bounded byte range within a logical object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    /// First requested logical byte.
    pub offset: u64,
    /// Number of requested bytes.
    pub length: u64,
}

impl ByteRange {
    /// Validates and builds a non-overflowing range.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRange`] when `offset + length` overflows.
    pub fn new(offset: u64, length: u64) -> Result<Self, StoreError> {
        offset
            .checked_add(length)
            .ok_or(StoreError::InvalidRange { offset, length })?;
        Ok(Self { offset, length })
    }
}

/// Reopenable source of a finite logical byte stream.
///
/// Reopenability lets composition layers retry or mirror a put without
/// buffering an exact-checkpoint extent in RAM. Every successful complete read
/// must produce the same bytes and exactly [`BlobSource::logical_length`]
/// bytes; a source may fail instead. Immutable backends independently
/// authenticate each stream against its [`ContentId`].
pub trait BlobSource: Send + Sync {
    /// Returns the exact number of logical bytes produced by each stream.
    fn logical_length(&self) -> u64;

    /// Opens a new stream positioned at its first logical byte.
    ///
    /// # Errors
    ///
    /// Returns a stable store error when the source cannot be reopened.
    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError>;
}

/// Cloneable handle to a reopenable finite logical byte stream.
///
/// A handle returned by an immutable backend authenticates a complete read as
/// it reaches EOF. Callers using [`BlobHandle::open`] directly must therefore
/// drain the reader and observe its final result before publishing or executing
/// the bytes. [`BlobHandle::copy_to`] and [`BlobHandle::read_all`] enforce that
/// completion rule for common consumers.
#[derive(Clone)]
pub struct BlobHandle {
    source: Arc<dyn BlobSource>,
    logical_length: u64,
    authenticated_id: Option<ContentId>,
    integrity_id: Option<ContentId>,
    self_authenticating: bool,
}

impl BlobHandle {
    /// Wraps a reopenable source.
    #[must_use]
    pub fn new(source: Arc<dyn BlobSource>) -> Self {
        let logical_length = source.logical_length();
        Self {
            source,
            logical_length,
            authenticated_id: None,
            integrity_id: None,
            self_authenticating: false,
        }
    }

    /// Creates an in-memory source from owned bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(Arc::new(BytesBlobSource::new(bytes.into())))
    }

    pub(crate) fn from_authenticated_bytes(id: ContentId, bytes: Arc<[u8]>) -> Self {
        Self::authenticated(id, Arc::new(BytesBlobSource { bytes }))
    }

    pub(crate) fn authenticated(id: ContentId, source: Arc<dyn BlobSource>) -> Self {
        let logical_length = source.logical_length();
        Self {
            source,
            logical_length,
            authenticated_id: Some(id),
            integrity_id: Some(id),
            self_authenticating: true,
        }
    }

    pub(crate) fn integrity_checked(id: ContentId, source: Arc<dyn BlobSource>) -> Self {
        let logical_length = source.logical_length();
        Self {
            source,
            logical_length,
            authenticated_id: None,
            integrity_id: Some(id),
            self_authenticating: true,
        }
    }

    /// Returns the source's declared logical length.
    #[must_use]
    pub fn logical_length(&self) -> u64 {
        self.logical_length
    }

    /// Opens a new stream positioned at its first logical byte.
    ///
    /// A backend handle may defer whole-object authentication until EOF. A
    /// caller that stops early has consumed bytes, but has not completed an
    /// authenticated read.
    ///
    /// # Errors
    ///
    /// Returns a stable store error when the source cannot be reopened.
    pub fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.source.open()
    }

    /// Copies the complete stream to a destination without full-size buffering.
    ///
    /// The destination may contain unauthenticated bytes before this method
    /// returns. A caller that needs atomic publication must write to staging
    /// storage and publish it only after this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidSourceLength`] when the source does not
    /// produce exactly its declared length, [`StoreError::Corrupt`] when a
    /// backend handle fails deferred authentication, or a source or destination
    /// I/O error.
    pub fn copy_to(&self, destination: &mut dyn Write) -> Result<u64, StoreError> {
        copy_handle(self, destination)
    }

    /// Returns a reopenable bounded view of this source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRange`] when the requested range exceeds
    /// this source's declared length.
    pub fn slice(&self, range: Option<ByteRange>) -> Result<Self, StoreError> {
        let Some(range) = range else {
            return Ok(self.clone());
        };
        validate_range(self.logical_length(), range)?;
        let mut sliced = Self::new(Arc::new(RangeBlobSource {
            source: self.clone(),
            range,
        }));
        sliced.integrity_id = self.integrity_id;
        sliced.self_authenticating = self.self_authenticating;
        Ok(sliced)
    }

    /// Reads the complete stream into memory under an explicit byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Quota`] when the declared length exceeds
    /// `max_bytes`, [`StoreError::InvalidSourceLength`] when the actual length
    /// differs, or a source I/O error.
    pub fn read_all(&self, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        read_handle_all(self, max_bytes)
    }

    pub(crate) fn verified_as(&self, id: ContentId) -> Result<Self, StoreError> {
        if self.authenticated_id == Some(id) {
            return Ok(self.clone());
        }
        validate_source(id, self)?;
        let mut verified = self.clone();
        verified.authenticated_id = Some(id);
        verified.integrity_id = Some(id);
        verified.self_authenticating = false;
        Ok(verified)
    }
}

impl BlobSource for BlobHandle {
    fn logical_length(&self) -> u64 {
        self.logical_length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.open()
    }
}

struct BytesBlobSource {
    bytes: Arc<[u8]>,
}

impl BytesBlobSource {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::from(bytes),
        }
    }
}

impl BlobSource for BytesBlobSource {
    fn logical_length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(Cursor::new(self.bytes.clone())))
    }
}

struct RangeBlobSource {
    source: BlobHandle,
    range: ByteRange,
}

impl BlobSource for RangeBlobSource {
    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let mut reader = self.source.open()?;
        discard_exact(&mut reader, self.range.offset)?;
        Ok(Box::new(RangeReader {
            reader,
            output_remaining: self.range.length,
            trailing_remaining: self.source.logical_length()
                - self.range.offset
                - self.range.length,
            finalized: false,
        }))
    }
}

struct RangeReader {
    reader: Box<dyn Read + Send>,
    output_remaining: u64,
    trailing_remaining: u64,
    finalized: bool,
}

impl Read for RangeReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        if self.output_remaining != 0 {
            let limit = usize::try_from(self.output_remaining.min(output.len() as u64))
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            let read = read_retry(&mut self.reader, &mut output[..limit])?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            self.output_remaining -= read as u64;
            return Ok(read);
        }
        discard_io_exact(&mut self.reader, self.trailing_remaining)?;
        let mut extra = [0_u8; 1];
        if read_retry(&mut self.reader, &mut extra)? != 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.finalized = true;
        Ok(0)
    }
}

/// Capabilities advertised by one leaf or composed immutable store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// The store persists data across process restart.
    pub durable: bool,
    /// A successful put may still require a journaled downstream transfer.
    pub deferred_write: bool,
    /// The store admits bounded logical range reads.
    pub range_read: bool,
    /// The store returns bounded readers without full-size buffering.
    pub streaming_read: bool,
    /// The store atomically avoids overwriting an existing logical object.
    pub conditional_create: bool,
    /// The store supports bounded streaming writes without full-size buffering.
    pub streaming_put: bool,
    /// The store can enumerate physical inventory for repair and GC planning.
    pub repair_inventory: bool,
    /// The store can delete objects only through an administrative plan.
    pub planned_delete: bool,
}

/// Physical placement evidence returned after a logical put.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementReceipt {
    /// Stable operational backend instance name.
    pub backend: String,
    /// Whether this placement satisfies durable-storage requirements.
    pub durable: bool,
    /// Logical bytes authenticated by this placement.
    pub logical_length: u64,
}

/// Aggregate result of an immutable logical put.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutReceipt {
    /// Logical object placed by the operation.
    pub id: ContentId,
    /// Successful leaf placements.
    pub placements: Vec<PlacementReceipt>,
}

impl PutReceipt {
    /// Returns whether at least one placement is durable.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.placements.iter().any(|placement| placement.durable)
    }

    pub(crate) fn one(id: ContentId, placement: PlacementReceipt) -> Self {
        Self {
            id,
            placements: vec![placement],
        }
    }
}

/// Stable name of one mutable reference within an authoritative namespace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefName(String);

impl RefName {
    /// Validates a slash-separated reference name.
    ///
    /// Segments may contain ASCII letters, digits, `.`, `_`, and `-`. Empty,
    /// dot, dot-dot, absolute, and non-ASCII segments are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidRefName`] when the name is unsafe.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        const MAX_REF_BYTES: usize = 1_024;
        const MAX_SEGMENT_BYTES: usize = 255;

        let valid = !value.is_empty()
            && value.len() <= MAX_REF_BYTES
            && !value.starts_with('/')
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= MAX_SEGMENT_BYTES
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(StoreError::InvalidRefName { value });
        }
        Ok(Self(value))
    }

    /// Returns the validated reference spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Result of one authoritative mutable-ref compare-and-swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefCasOutcome {
    /// The ref now names `next`.
    Advanced {
        /// Newly published content ID.
        next: ContentId,
    },
    /// The expected value was stale and no ref change occurred.
    Conflict {
        /// Value supplied by the caller.
        expected: Option<ContentId>,
        /// Current authoritative value.
        current: Option<ContentId>,
    },
}

/// Failure returned by immutable/ref store components.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The requested logical object does not exist in this store.
    #[error("content object {id} was not found")]
    NotFound {
        /// Missing logical object.
        id: ContentId,
    },
    /// Logical or physical bytes failed authentication.
    #[error("content object {id} is corrupt")]
    Corrupt {
        /// Logical object whose bytes failed authentication.
        id: ContentId,
    },
    /// A content ID string was malformed.
    #[error("content id is invalid")]
    InvalidId,
    /// A mutable reference name was unsafe.
    #[error("reference name is invalid: {value}")]
    InvalidRefName {
        /// Rejected reference name.
        value: String,
    },
    /// A requested byte range overflowed or exceeded the object.
    #[error("byte range offset={offset} length={length} is invalid")]
    InvalidRange {
        /// Requested starting byte.
        offset: u64,
        /// Requested byte count.
        length: u64,
    },
    /// A composition graph had no route or usable child.
    #[error("store composition is invalid: {reason}")]
    InvalidComposition {
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A closed store graph failed admission.
    #[error("store graph node {node} is invalid: {violation}")]
    InvalidGraph {
        /// Validated node name or `<graph>` for a graph-wide failure.
        node: String,
        /// Stable validation category.
        violation: GraphViolation,
    },
    /// The operation was not authorized by the backend.
    #[error("store operation is unauthorized")]
    Unauthorized,
    /// The requested object or ref schema is incompatible.
    #[error("store object or operation is incompatible")]
    Incompatible,
    /// A configured quota rejected the operation.
    #[error("store quota was exceeded")]
    Quota,
    /// A reopened source produced a length other than its declaration.
    #[error("blob source declared {declared} bytes but produced {observed}")]
    InvalidSourceLength {
        /// Length declared by the source.
        declared: u64,
        /// Bytes observed, capped at one byte beyond the declaration.
        observed: u64,
    },
    /// The backend was temporarily unavailable.
    #[error("store backend is unavailable")]
    Unavailable,
    /// A backend lacks a required capability.
    #[error("store backend lacks required capability: {capability}")]
    Unsupported {
        /// Stable capability name.
        capability: &'static str,
    },
    /// An internal synchronization primitive was poisoned.
    #[error("store lock was poisoned during {operation}")]
    Poisoned {
        /// Operation that attempted to acquire the lock.
        operation: &'static str,
    },
    /// A filesystem operation failed.
    #[error("store filesystem operation {operation} failed")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// A source or sink stream failed independently of a physical backend path.
    #[error("store stream operation {operation} failed")]
    StreamIo {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying stream failure.
        #[source]
        source: io::Error,
    },
}

/// Stable reason that a closed store graph failed admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphViolation {
    /// The graph contains no nodes.
    Empty,
    /// No logical object kinds were admitted.
    NoAdmittedKinds,
    /// A node identifier is malformed.
    InvalidNodeId,
    /// A referenced node does not exist.
    MissingNode,
    /// The graph contains a directed cycle.
    Cycle,
    /// A configured node is unreachable from the root.
    UnreachableNode,
    /// The graph exceeds its node-count limit.
    TooManyNodes,
    /// A path through the graph exceeds its depth limit.
    TooDeep,
    /// A composition has no required child or route.
    EmptyChildren,
    /// A routed node does not cover exactly the kinds that can reach it.
    RouteCoverage,
    /// A tiered node names an invalid write tier.
    InvalidWriteTier,
    /// A child lacks a capability required by its parent layer.
    UnsupportedChild,
    /// A write-back node has invalid pending-transfer bounds.
    InvalidWriteBackBounds,
    /// A journal and another persistent graph path overlap lexically.
    OverlappingAdministrativePath,
}

impl fmt::Display for GraphViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "empty graph",
            Self::NoAdmittedKinds => "no admitted object kinds",
            Self::InvalidNodeId => "invalid node identifier",
            Self::MissingNode => "missing referenced node",
            Self::Cycle => "directed cycle",
            Self::UnreachableNode => "unreachable node",
            Self::TooManyNodes => "node-count limit exceeded",
            Self::TooDeep => "graph-depth limit exceeded",
            Self::EmptyChildren => "empty child set",
            Self::RouteCoverage => "incomplete or extraneous route coverage",
            Self::InvalidWriteTier => "invalid write tier",
            Self::UnsupportedChild => "unsupported child capability",
            Self::InvalidWriteBackBounds => "invalid write-back bounds",
            Self::OverlappingAdministrativePath => "overlapping administrative path",
        })
    }
}

/// Streaming immutable logical-object backend.
pub trait ImmutableBlobBackend: Send + Sync {
    /// Returns the stable operational backend name.
    fn name(&self) -> &str;

    /// Returns capabilities available through this component.
    fn capabilities(&self) -> BackendCapabilities;

    /// Returns whether an authenticated logical object is present.
    ///
    /// # Errors
    ///
    /// Returns a backend error when presence cannot be distinguished safely.
    fn contains(&self, id: ContentId) -> Result<bool, StoreError>;

    /// Returns a handle that authenticates a complete object or bounded range.
    ///
    /// Authentication may complete only when a stream opened from the handle
    /// reaches EOF. A caller must use a complete-read helper or drain the stream
    /// and observe its final result before trusting the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] for absence, [`StoreError::Corrupt`] for
    /// failed authentication, [`StoreError::InvalidRange`] for an invalid range,
    /// or another backend failure.
    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError>;

    /// Idempotently places canonical bytes under their expected logical ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when the source does not authenticate as
    /// `id`, or another backend failure when placement cannot complete.
    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError>;
}

/// Authoritative mutable-reference backend.
pub trait MutableRefBackend: Send + Sync {
    /// Acquires shared authority for one children-before-ref publication.
    ///
    /// The returned guard must remain live from before the transaction's first
    /// immutable child write until its final authoritative ref comparison.
    /// Administrative ref inventory acquires the exclusive side of the same
    /// lifecycle fence.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the publication lifecycle cannot be fenced.
    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError>;

    /// Reads one named ref.
    ///
    /// # Errors
    ///
    /// Returns a backend or record-validation error.
    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError>;

    /// Conditionally replaces one named ref.
    ///
    /// # Errors
    ///
    /// Returns a backend or record-validation error. A stale expected value is
    /// reported as [`RefCasOutcome::Conflict`], not an error.
    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError>;
}

pub(crate) fn validate_bytes(id: ContentId, bytes: &[u8]) -> Result<(), StoreError> {
    if id.authenticates(bytes) {
        Ok(())
    } else {
        Err(StoreError::Corrupt { id })
    }
}

pub(crate) fn validate_source(id: ContentId, source: &dyn BlobSource) -> Result<(), StoreError> {
    match ContentId::for_source(id.kind(), id.schema_version(), source) {
        Ok(actual) if actual == id => Ok(()),
        Ok(_) | Err(StoreError::InvalidSourceLength { .. }) => Err(StoreError::Corrupt { id }),
        Err(StoreError::StreamIo { source, .. }) if source.kind() == io::ErrorKind::InvalidData => {
            Err(StoreError::Corrupt { id })
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn read_handle_all(source: &BlobHandle, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
    let logical_length = source.logical_length();
    if logical_length > max_bytes {
        return Err(StoreError::Quota);
    }
    let capacity = usize::try_from(logical_length).map_err(|_| StoreError::Quota)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| StoreError::Quota)?;
    let mut reader = source.open()?;
    reader
        .by_ref()
        .take(logical_length)
        .read_to_end(&mut bytes)
        .map_err(|error| map_stream_error("read-blob-source", source.integrity_id, error))?;
    let observed = bytes.len() as u64;
    let mut extra = [0_u8; 1];
    let has_extra = read_retry(&mut reader, &mut extra).map_err(|error| {
        map_stream_error("verify-blob-source-length", source.integrity_id, error)
    })? != 0;
    if observed != logical_length || has_extra {
        return Err(StoreError::InvalidSourceLength {
            declared: logical_length,
            observed: observed.saturating_add(u64::from(has_extra)),
        });
    }
    Ok(bytes)
}

fn copy_handle(source: &BlobHandle, destination: &mut dyn Write) -> Result<u64, StoreError> {
    let logical_length = source.logical_length();
    let mut reader = source.open()?;
    let mut remaining = logical_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let limit =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| StoreError::Quota)?;
        let read = read_retry(&mut reader, &mut buffer[..limit])
            .map_err(|error| map_stream_error("read-blob-source", source.integrity_id, error))?;
        if read == 0 {
            return Err(StoreError::InvalidSourceLength {
                declared: logical_length,
                observed: logical_length - remaining,
            });
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|source| StoreError::StreamIo {
                operation: "write-blob-destination",
                source,
            })?;
        remaining -= read as u64;
    }

    let mut extra = [0_u8; 1];
    let has_extra = read_retry(&mut reader, &mut extra).map_err(|error| {
        map_stream_error("verify-blob-source-length", source.integrity_id, error)
    })? != 0;
    if has_extra {
        return Err(StoreError::InvalidSourceLength {
            declared: logical_length,
            observed: logical_length.saturating_add(1),
        });
    }
    Ok(logical_length)
}

pub(crate) fn copy_source(
    id: ContentId,
    source: &BlobHandle,
    destination: &mut dyn Write,
) -> Result<u64, StoreError> {
    let logical_length = source.logical_length();
    let mut hasher = (!source.self_authenticating || source.authenticated_id != Some(id))
        .then(|| content_hasher(id.kind(), id.schema_version(), logical_length));
    let mut reader = source.open()?;
    let mut remaining = logical_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let limit =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| StoreError::Quota)?;
        let read = read_retry(&mut reader, &mut buffer[..limit])
            .map_err(|error| map_stream_error("read-blob-source", Some(id), error))?;
        if read == 0 {
            return Err(StoreError::Corrupt { id });
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|source| StoreError::StreamIo {
                operation: "write-blob-destination",
                source,
            })?;
        if let Some(hasher) = &mut hasher {
            hasher.update(&buffer[..read]);
        }
        remaining -= read as u64;
    }
    let mut extra = [0_u8; 1];
    if read_retry(&mut reader, &mut extra)
        .map_err(|error| map_stream_error("verify-blob-source-length", Some(id), error))?
        != 0
        || hasher
            .map(|hasher| *hasher.finalize().as_bytes() != id.digest())
            .unwrap_or(false)
    {
        return Err(StoreError::Corrupt { id });
    }
    Ok(logical_length)
}

pub(crate) fn validate_range(logical_length: u64, range: ByteRange) -> Result<(), StoreError> {
    let end = range
        .offset
        .checked_add(range.length)
        .ok_or(StoreError::InvalidRange {
            offset: range.offset,
            length: range.length,
        })?;
    if end > logical_length {
        return Err(StoreError::InvalidRange {
            offset: range.offset,
            length: range.length,
        });
    }
    Ok(())
}

fn content_hasher(kind: ObjectKind, schema_version: u32, logical_length: u64) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(CONTENT_ID_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(CONTENT_ID_DOMAIN);
    hasher.update(&(kind.as_str().len() as u64).to_be_bytes());
    hasher.update(kind.as_str().as_bytes());
    hasher.update(&schema_version.to_be_bytes());
    hasher.update(&logical_length.to_be_bytes());
    hasher
}

fn digest_source(
    kind: ObjectKind,
    schema_version: u32,
    source: &dyn BlobSource,
) -> Result<[u8; 32], StoreError> {
    let logical_length = source.logical_length();
    let mut reader = source.open()?;
    digest_reader(kind, schema_version, logical_length, &mut reader)
}

fn digest_reader(
    kind: ObjectKind,
    schema_version: u32,
    logical_length: u64,
    reader: &mut dyn Read,
) -> Result<[u8; 32], StoreError> {
    let mut hasher = content_hasher(kind, schema_version, logical_length);
    let mut remaining = logical_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let limit =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| StoreError::Quota)?;
        let read =
            read_retry(reader, &mut buffer[..limit]).map_err(|source| StoreError::StreamIo {
                operation: "hash-blob-source",
                source,
            })?;
        if read == 0 {
            return Err(StoreError::InvalidSourceLength {
                declared: logical_length,
                observed: logical_length - remaining,
            });
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    let mut extra = [0_u8; 1];
    if read_retry(reader, &mut extra).map_err(|source| StoreError::StreamIo {
        operation: "verify-blob-source-length",
        source,
    })? != 0
    {
        return Err(StoreError::InvalidSourceLength {
            declared: logical_length,
            observed: logical_length.saturating_add(1),
        });
    }
    Ok(*hasher.finalize().as_bytes())
}

fn discard_exact(reader: &mut dyn Read, remaining: u64) -> Result<(), StoreError> {
    discard_io_exact(reader, remaining).map_err(|source| StoreError::StreamIo {
        operation: "seek-blob-range",
        source,
    })
}

fn discard_io_exact(reader: &mut dyn Read, mut remaining: u64) -> io::Result<()> {
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let read = read_retry(reader, &mut buffer[..limit])?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        remaining -= read as u64;
    }
    Ok(())
}

fn read_retry(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn map_stream_error(
    operation: &'static str,
    id: Option<ContentId>,
    error: io::Error,
) -> StoreError {
    if error.kind() == io::ErrorKind::InvalidData
        && let Some(id) = id
    {
        StoreError::Corrupt { id }
    } else {
        StoreError::StreamIo {
            operation,
            source: error,
        }
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
