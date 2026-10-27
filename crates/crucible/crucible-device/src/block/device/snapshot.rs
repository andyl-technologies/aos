//! Block-device checkpoint snapshot representation.
//!
//! The overlay is carried as a [`BlockOverlayImage`]: chunk records naming
//! each written 4 MiB chunk by content identity, never page bytes. Whoever
//! persists the encoded snapshot persists the chunk objects beside it, and
//! whoever decodes it binds a [`BlockOverlayChunkSource`] before restore.
//!
//! ```text
//! b"crucible.block-snapshot.v7\0" || CBOR {
//!     core: bytes, base_hash: [u8; 32], device_length: u64,
//!     overlay: [(chunk_index, identity?, present[16], dirty[16])] ascending,
//!     storage_faults: bytes, latency: [u64; 5],
//! }
//! ```

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::inflight::PendingResponse;
use crate::snapshot_codec::{
    BoundedVec, SnapshotEncodeError, SnapshotResourceError, admit_input, encode_prefixed,
    map_decode_error,
};
use crate::subnode::{IoCoreSnapshot, IoCoreSnapshotCodecError};

use super::super::overlay_image::{
    BlockOverlayChunk, BlockOverlayChunkSource, BlockOverlayImage, ChunkPageBits,
};
use super::super::{BlockFaultState, BlockFaultStateCodecError};
use super::BlockLatency;

const BLOCK_SNAPSHOT_MAGIC: &[u8] = b"crucible.block-snapshot.v7\0";

/// Compiled byte ceiling for one encoded block-device snapshot.
///
/// The envelope holds the I/O core and storage-fault continuations, which
/// carry their own ceilings, plus the overlay chunk records. Overlay page
/// bytes are never inline, so this ceiling does not grow with written device
/// content.
pub const MAX_BLOCK_SNAPSHOT_BYTES: u64 = 1_073_741_824;

/// The overlay record count is bounded by the device geometry (at most one
/// record per 4 MiB chunk of the device, checked after decoding) and by the
/// admitted input length, not by a separate count ceiling.
const OVERLAY_RECORDS_BOUNDED_BY_GEOMETRY: u64 = u64::MAX;

type SnapshotBytes = BoundedVec<u8, MAX_BLOCK_SNAPSHOT_BYTES>;
type OverlayRecords = BoundedVec<OverlayChunkWire, OVERLAY_RECORDS_BOUNDED_BY_GEOMETRY>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockSnapshotWire {
    core: SnapshotBytes,
    base_hash: [u8; 32],
    device_length: u64,
    overlay: OverlayRecords,
    storage_faults: SnapshotBytes,
    latency: [u64; 5],
}

/// One overlay chunk record: index, identity, present bitmap, dirty bitmap.
#[derive(Serialize, Deserialize)]
struct OverlayChunkWire(u64, Option<[u8; 32]>, [u64; 16], [u64; 16]);

impl From<BlockOverlayChunk> for OverlayChunkWire {
    fn from(chunk: BlockOverlayChunk) -> Self {
        Self(
            chunk.index,
            chunk.identity,
            chunk.present.words(),
            chunk.dirty.words(),
        )
    }
}

impl From<OverlayChunkWire> for BlockOverlayChunk {
    fn from(wire: OverlayChunkWire) -> Self {
        Self {
            index: wire.0,
            identity: wire.1,
            present: ChunkPageBits::from_words(wire.2),
            dirty: ChunkPageBits::from_words(wire.3),
        }
    }
}

/// The device half of a block sub-node's `MaterializedState` ([IO-11], [IO-23]).
///
/// Holds the overlay image (chunk records naming every written 4 MiB chunk by
/// content identity, plus the present and dirty page sets so a mid-epoch
/// restore preserves the next checkpoint's dirty bookkeeping, [IO-7]), the
/// latency model (part of the `World`, [IO-10]), the in-flight responses
/// (inside `core`), the base hash, and the device length. It **never** holds
/// the base image bytes ([TEMP-9]); restore re-supplies the content-addressed
/// base and verifies its hash.
///
/// Cloning a snapshot shares the overlay image; it copies no page bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSnapshot {
    /// The uniform-core snapshot: clock, rings, in-flight responses.
    pub core: IoCoreSnapshot,
    /// The BLAKE3 content hash of the (omitted) base image, for restore checks.
    pub base_hash: [u8; 32],
    /// The device length in bytes (the base image size).
    pub device_length: u64,
    /// The chunked, content-addressed overlay image with its dirty page set.
    pub overlay: BlockOverlayImage,
    /// Volatile cache, durability frontiers, retained versions, and directives.
    pub storage_faults: BlockFaultState,
    /// The deterministic latency model parameters.
    pub latency: BlockLatency,
}

impl BlockSnapshot {
    /// Returns the number of pages dirtied since the last checkpoint boundary.
    #[must_use]
    pub fn delta_page_count(&self) -> usize {
        self.overlay.dirty_page_count()
    }

    /// Returns the in-flight responses captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.core.inflight
    }

    /// Attaches the content-addressed source that serves decoded overlay chunks.
    ///
    /// A decoded snapshot names its overlay chunks by identity only; restore
    /// reads and authenticates them through this source.
    pub fn bind_overlay_source(&mut self, source: Arc<dyn BlockOverlayChunkSource>) {
        self.overlay.bind_source(source);
    }

    /// Returns the distinct identities of every nonzero overlay chunk, ascending.
    ///
    /// These are the content-addressed objects a persisted snapshot depends on.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError::Overlay`] when a live overlay page
    /// cannot be read while its chunk identity is computed.
    pub fn overlay_chunk_identities(&self) -> Result<Vec<[u8; 32]>, BlockSnapshotCodecError> {
        let mut identities = self
            .overlay
            .chunks()
            .map_err(|_| BlockSnapshotCodecError::Overlay)?
            .into_iter()
            .filter_map(|chunk| chunk.identity)
            .collect::<Vec<_>>();
        identities.sort_unstable();
        identities.dedup();
        Ok(identities)
    }

    /// Encodes the complete block-device continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError`] for invalid device geometry,
    /// inconsistent overlay state, an unreadable overlay page, an invalid
    /// nested continuation, or an over-limit serialized checkpoint.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BlockSnapshotCodecError> {
        self.to_canonical_bytes_with_limit(MAX_BLOCK_SNAPSHOT_BYTES)
    }

    /// Encodes the snapshot under an enclosing checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError`] under the same conditions as
    /// [`Self::to_canonical_bytes`], and when the representation exceeds
    /// `maximum`.
    pub fn to_canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, BlockSnapshotCodecError> {
        validate_snapshot(self, maximum)?;
        let records = self
            .overlay
            .chunks()
            .map_err(|_| BlockSnapshotCodecError::Overlay)?
            .into_iter()
            .map(OverlayChunkWire::from)
            .collect::<Vec<_>>();
        let wire = BlockSnapshotWire {
            core: bounded_bytes(
                self.core
                    .canonical_bytes_with_limit(maximum.min(MAX_BLOCK_SNAPSHOT_BYTES))
                    .map_err(map_io_core_error)?,
                "block I/O core bytes",
            )?,
            base_hash: self.base_hash,
            device_length: self.device_length,
            overlay: OverlayRecords::new(records, "block overlay chunk records")
                .map_err(map_resource_error)?,
            storage_faults: bounded_bytes(
                self.storage_faults
                    .to_canonical_bytes_with_limit(maximum.min(MAX_BLOCK_SNAPSHOT_BYTES))
                    .map_err(map_block_fault_error)?,
                "block storage-fault bytes",
            )?,
            latency: [
                self.latency.read_base_ns,
                self.latency.write_base_ns,
                self.latency.flush_ns,
                self.latency.get_length_ns,
                self.latency.per_byte_ns,
            ],
        };
        encode_prefixed(
            &wire,
            BLOCK_SNAPSHOT_MAGIC,
            "block snapshot bytes",
            maximum,
            MAX_BLOCK_SNAPSHOT_BYTES,
        )
        .map_err(map_encode_error)
    }

    /// Decodes and validates a complete block-device continuation.
    ///
    /// The decoded overlay has no chunk source; bind one with
    /// [`Self::bind_overlay_source`] before restoring.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, noncanonical, or restore-invalid state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BlockSnapshotCodecError> {
        Self::from_canonical_bytes_with_limit(bytes, MAX_BLOCK_SNAPSHOT_BYTES)
    }

    /// Decodes the snapshot under an enclosing checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when `bytes` exceeds
    /// `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum: u64,
    ) -> Result<Self, BlockSnapshotCodecError> {
        let payload = bytes
            .strip_prefix(BLOCK_SNAPSHOT_MAGIC)
            .ok_or(BlockSnapshotCodecError::Version)?;
        admit_input(
            bytes,
            "block snapshot bytes",
            maximum,
            MAX_BLOCK_SNAPSHOT_BYTES,
        )
        .map_err(map_resource_error)?;
        let wire: BlockSnapshotWire = ciborium::de::from_reader(payload).map_err(|error| {
            map_decode_error(error).map_or(BlockSnapshotCodecError::Malformed, map_resource_error)
        })?;
        let overlay = BlockOverlayImage::from_chunks(
            wire.device_length,
            wire.overlay
                .into_inner()
                .into_iter()
                .map(BlockOverlayChunk::from),
        )
        .map_err(|_| BlockSnapshotCodecError::Invalid)?;
        let snapshot = Self {
            core: IoCoreSnapshot::from_canonical_bytes_with_limit(
                wire.core.as_slice(),
                maximum.min(MAX_BLOCK_SNAPSHOT_BYTES),
            )
            .map_err(map_io_core_error)?,
            base_hash: wire.base_hash,
            device_length: wire.device_length,
            overlay,
            storage_faults: BlockFaultState::from_canonical_bytes_with_limit(
                wire.storage_faults.as_slice(),
                wire.device_length,
                maximum.min(MAX_BLOCK_SNAPSHOT_BYTES),
            )
            .map_err(map_block_fault_error)?,
            latency: BlockLatency::new(
                wire.latency[0],
                wire.latency[1],
                wire.latency[2],
                wire.latency[3],
                wire.latency[4],
            ),
        };
        validate_snapshot(&snapshot, maximum)?;
        if snapshot.to_canonical_bytes_with_limit(maximum)?.as_slice() != bytes {
            return Err(BlockSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
    }
}

/// Failure to encode or authenticate a complete block-device snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockSnapshotCodecError {
    /// The envelope version is unsupported.
    #[error("unsupported block snapshot version")]
    Version,
    /// The snapshot cannot be serialized or decoded.
    #[error("malformed block snapshot")]
    Malformed,
    /// A nested continuation is invalid.
    #[error("invalid nested block snapshot state")]
    Nested,
    /// The snapshot violates block geometry or overlay invariants.
    #[error("invalid block snapshot state")]
    Invalid,
    /// The snapshot exceeds a configured or compiled resource ceiling.
    #[error(
        "block snapshot resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Resource field that rejected the operation.
        field: &'static str,
        /// Bytes or entries already retained by the operation.
        current: u64,
        /// Additional bytes or entries requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical block snapshot")]
    Noncanonical,
    /// A live overlay page could not be read while its chunk was identified.
    #[error("block snapshot overlay page is unreadable")]
    Overlay,
}

fn bounded_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SnapshotBytes, BlockSnapshotCodecError> {
    SnapshotBytes::new(bytes, field).map_err(map_resource_error)
}

fn map_encode_error(error: SnapshotEncodeError) -> BlockSnapshotCodecError {
    match error {
        SnapshotEncodeError::Malformed => BlockSnapshotCodecError::Malformed,
        SnapshotEncodeError::Resource(error) => map_resource_error(error),
    }
}

fn map_resource_error(error: SnapshotResourceError) -> BlockSnapshotCodecError {
    BlockSnapshotCodecError::ResourceLimit {
        field: error.field,
        current: error.current,
        requested: error.requested,
        configured: error.configured,
        hard: error.hard,
    }
}

fn map_io_core_error(error: IoCoreSnapshotCodecError) -> BlockSnapshotCodecError {
    match error {
        IoCoreSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => BlockSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        _ => BlockSnapshotCodecError::Nested,
    }
}

fn map_block_fault_error(error: BlockFaultStateCodecError) -> BlockSnapshotCodecError {
    match error {
        BlockFaultStateCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => BlockSnapshotCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        },
        _ => BlockSnapshotCodecError::Nested,
    }
}

fn validate_snapshot(
    snapshot: &BlockSnapshot,
    maximum: u64,
) -> Result<(), BlockSnapshotCodecError> {
    snapshot
        .core
        .canonical_length_with_limit(maximum.min(MAX_BLOCK_SNAPSHOT_BYTES))
        .map_err(map_io_core_error)?;
    snapshot
        .storage_faults
        .validate_restore(snapshot.device_length)
        .map_err(|_| BlockSnapshotCodecError::Nested)?;
    // Chunk geometry (every record inside the device, dirty within present)
    // is enforced whenever an image is built, so only the length binding
    // remains to check here.
    if snapshot.overlay.length() != snapshot.device_length {
        return Err(BlockSnapshotCodecError::Invalid);
    }
    Ok(())
}
