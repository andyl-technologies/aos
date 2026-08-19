//! Domain-separated byte-oriented content-store substrate for campaigns.
//!
//! The module separates immutable logical objects from mutable named refs. A
//! [`ContentId`] identifies canonical plaintext bytes independently of their
//! directory, pack, compression, encryption, cache, or archival placement.
//! [`ImmutableBlobBackend`] and [`MutableRefBackend`] are deliberately distinct:
//! immutable stores may be tiered and mirrored, while one campaign namespace
//! has one authoritative ref backend.
//!
//! Initial leaf implementations live in [`memory`] and [`directory`]. Initial
//! composition primitives live in [`composition`]. This module deliberately
//! remains crate-private until reads and writes use the RFC's bounded streaming
//! contract and the complete store-graph validator is present.

use std::fmt;
use std::io;
use std::path::PathBuf;

use thiserror::Error;

mod composition;
mod directory;
mod memory;

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
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(CONTENT_ID_DOMAIN.len() as u64).to_be_bytes());
        hasher.update(CONTENT_ID_DOMAIN);
        hasher.update(&(kind.as_str().len() as u64).to_be_bytes());
        hasher.update(kind.as_str().as_bytes());
        hasher.update(&schema_version.to_be_bytes());
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self {
            kind,
            schema_version,
            digest: *hasher.finalize().as_bytes(),
        }
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

/// Capabilities advertised by one leaf or composed immutable store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// The store persists data across process restart.
    pub durable: bool,
    /// The store admits bounded logical range reads.
    pub range_read: bool,
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
    /// The operation was not authorized by the backend.
    #[error("store operation is unauthorized")]
    Unauthorized,
    /// The requested object or ref schema is incompatible.
    #[error("store object or operation is incompatible")]
    Incompatible,
    /// A configured quota rejected the operation.
    #[error("store quota was exceeded")]
    Quota,
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
}

/// Byte-oriented immutable logical-object backend used by the internal store substrate.
///
/// The module remains crate-private so this fully buffered interface cannot
/// become a production caller contract. Its replacement will stream bounded
/// readers and writers before campaign or exact-checkpoint integration.
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

    /// Reads and authenticates a complete object or bounded logical range.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] for absence, [`StoreError::Corrupt`] for
    /// failed authentication, [`StoreError::InvalidRange`] for an invalid range,
    /// or another backend failure.
    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError>;

    /// Idempotently places canonical bytes under their expected logical ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when `bytes` do not authenticate as `id`,
    /// or another backend failure when placement cannot complete.
    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError>;
}

/// Authoritative mutable-reference backend.
pub trait MutableRefBackend: Send + Sync {
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

pub(crate) fn slice_range(bytes: Vec<u8>, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
    let Some(range) = range else {
        return Ok(bytes);
    };
    let end = range
        .offset
        .checked_add(range.length)
        .ok_or(StoreError::InvalidRange {
            offset: range.offset,
            length: range.length,
        })?;
    let start = usize::try_from(range.offset).map_err(|_| StoreError::InvalidRange {
        offset: range.offset,
        length: range.length,
    })?;
    let end = usize::try_from(end).map_err(|_| StoreError::InvalidRange {
        offset: range.offset,
        length: range.length,
    })?;
    bytes
        .get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or(StoreError::InvalidRange {
            offset: range.offset,
            length: range.length,
        })
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
