//! Block-device checkpoint snapshot representation.

use std::collections::{BTreeMap, BTreeSet};

use crate::inflight::PendingResponse;
use crate::snapshot_codec::{
    BoundedVec, SnapshotEncodeError, SnapshotResourceError, admit_input, encode_prefixed,
    map_decode_error,
};
use crate::subnode::{IoCoreSnapshot, IoCoreSnapshotCodecError};

use super::super::BlockFaultState;
use super::super::overlay::{OverlayDelta, PAGE_SIZE};
use super::BlockLatency;

const BLOCK_SNAPSHOT_MAGIC: &[u8] = b"crucible.block-snapshot.v2\0";
const MAX_BLOCK_SNAPSHOT_PAGES: u64 = 4_194_304;
/// Compiled byte ceiling for one block-device snapshot.
pub const MAX_BLOCK_SNAPSHOT_BYTES: u64 = 1_073_741_824;

type SnapshotBytes = BoundedVec<u8, MAX_BLOCK_SNAPSHOT_BYTES>;
type SnapshotPage = BoundedVec<u8, { PAGE_SIZE as u64 }>;
type SnapshotPages = BoundedVec<(u64, SnapshotPage), MAX_BLOCK_SNAPSHOT_PAGES>;
type SnapshotDirtyPages = BoundedVec<u64, MAX_BLOCK_SNAPSHOT_PAGES>;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockSnapshotWire {
    core: SnapshotBytes,
    base_hash: [u8; 32],
    device_length: u64,
    overlay_delta: SnapshotPages,
    full_pages: SnapshotPages,
    dirty: SnapshotDirtyPages,
    storage_faults: SnapshotBytes,
    latency: [u64; 5],
}

/// The device half of a block sub-node's `MaterializedState` ([IO-11], [IO-23]).
///
/// Holds the overlay delta (dirty pages only), a full-overlay page set for
/// self-contained restore, the dirty page set (so a mid-epoch restore preserves
/// the next checkpoint's delta, [IO-7]), the latency model (part of the `World`,
/// [IO-10]), the in-flight responses
/// (inside `core`), the base hash, and the device length. It **never** holds the
/// base image bytes ([TEMP-9]); restore re-supplies the content-addressed base
/// and verifies its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSnapshot {
    /// The uniform-core snapshot: clock, rings, in-flight responses.
    pub core: IoCoreSnapshot,
    /// The BLAKE3 content hash of the (omitted) base image, for restore checks.
    pub base_hash: [u8; 32],
    /// The device length in bytes (the base image size).
    pub device_length: u64,
    /// The overlay delta: only pages dirtied since the last checkpoint boundary.
    pub overlay_delta: OverlayDelta,
    /// The full overlay page set, for parent-free self-contained restore.
    pub full_pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
    /// The dirty page set at snapshot time.
    pub dirty: BTreeSet<u64>,
    /// Volatile cache, durability frontiers, retained versions, and directives.
    pub storage_faults: BlockFaultState,
    /// The deterministic latency model parameters.
    pub latency: BlockLatency,
}

impl BlockSnapshot {
    /// Returns the number of pages in the captured delta.
    #[must_use]
    pub fn delta_page_count(&self) -> usize {
        self.overlay_delta.pages.len()
    }

    /// Returns the in-flight responses captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.core.inflight
    }

    /// Encodes the complete block-device continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError`] for invalid device geometry,
    /// inconsistent overlay state, an invalid nested continuation, or an
    /// over-limit serialized checkpoint.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BlockSnapshotCodecError> {
        validate_snapshot(self)?;
        let wire = BlockSnapshotWire {
            core: bounded_bytes(
                self.core.canonical_bytes().map_err(map_io_core_error)?,
                "block I/O core bytes",
            )?,
            base_hash: self.base_hash,
            device_length: self.device_length,
            overlay_delta: encode_pages(&self.overlay_delta.pages, "block overlay delta")?,
            full_pages: encode_pages(&self.full_pages, "block full pages")?,
            dirty: bounded_vec_from_iter(
                self.dirty.iter().copied(),
                self.dirty.len(),
                "block dirty pages",
            )?,
            storage_faults: bounded_bytes(
                self.storage_faults
                    .to_canonical_bytes()
                    .map_err(|_| BlockSnapshotCodecError::Nested)?,
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
            MAX_BLOCK_SNAPSHOT_BYTES,
            MAX_BLOCK_SNAPSHOT_BYTES,
        )
        .map_err(map_encode_error)
    }

    /// Decodes and validates a complete block-device continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BlockSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, noncanonical, or restore-invalid state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BlockSnapshotCodecError> {
        let payload = bytes
            .strip_prefix(BLOCK_SNAPSHOT_MAGIC)
            .ok_or(BlockSnapshotCodecError::Version)?;
        admit_input(
            bytes,
            "block snapshot bytes",
            MAX_BLOCK_SNAPSHOT_BYTES,
            MAX_BLOCK_SNAPSHOT_BYTES,
        )
        .map_err(map_resource_error)?;
        let wire: BlockSnapshotWire = ciborium::de::from_reader(payload).map_err(|error| {
            map_decode_error(error).map_or(BlockSnapshotCodecError::Malformed, map_resource_error)
        })?;
        let snapshot = Self {
            core: IoCoreSnapshot::from_canonical_bytes(wire.core.as_slice())
                .map_err(map_io_core_error)?,
            base_hash: wire.base_hash,
            device_length: wire.device_length,
            overlay_delta: OverlayDelta {
                pages: decode_pages(wire.overlay_delta)?,
            },
            full_pages: decode_pages(wire.full_pages)?,
            dirty: wire.dirty.into_inner().into_iter().collect(),
            storage_faults: BlockFaultState::from_canonical_bytes(
                wire.storage_faults.as_slice(),
                wire.device_length,
            )
            .map_err(|_| BlockSnapshotCodecError::Nested)?,
            latency: BlockLatency::new(
                wire.latency[0],
                wire.latency[1],
                wire.latency[2],
                wire.latency[3],
                wire.latency[4],
            ),
        };
        validate_snapshot(&snapshot)?;
        if snapshot.to_canonical_bytes()?.as_slice() != bytes {
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
}

fn encode_pages(
    pages: &BTreeMap<u64, [u8; PAGE_SIZE]>,
    field: &'static str,
) -> Result<SnapshotPages, BlockSnapshotCodecError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(pages.len())
        .map_err(|_| resource_limit(field, 0, pages.len() as u64, MAX_BLOCK_SNAPSHOT_PAGES))?;
    for (offset, page) in pages {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(PAGE_SIZE).map_err(|_| {
            resource_limit("block page bytes", 0, PAGE_SIZE as u64, PAGE_SIZE as u64)
        })?;
        bytes.extend_from_slice(page);
        encoded.push((
            *offset,
            SnapshotPage::new(bytes, "block page bytes").map_err(map_resource_error)?,
        ));
    }
    SnapshotPages::new(encoded, field).map_err(map_resource_error)
}

fn decode_pages(
    pages: SnapshotPages,
) -> Result<BTreeMap<u64, [u8; PAGE_SIZE]>, BlockSnapshotCodecError> {
    let pages = pages.into_inner();
    if pages.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(BlockSnapshotCodecError::Noncanonical);
    }
    pages
        .into_iter()
        .map(|(offset, bytes)| {
            let page = bytes
                .into_inner()
                .try_into()
                .map_err(|_| BlockSnapshotCodecError::Invalid)?;
            Ok((offset, page))
        })
        .collect()
}

fn bounded_bytes(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<SnapshotBytes, BlockSnapshotCodecError> {
    SnapshotBytes::new(bytes, field).map_err(map_resource_error)
}

fn bounded_vec_from_iter<T>(
    values: impl IntoIterator<Item = T>,
    length: usize,
    field: &'static str,
) -> Result<BoundedVec<T, MAX_BLOCK_SNAPSHOT_PAGES>, BlockSnapshotCodecError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(length)
        .map_err(|_| resource_limit(field, 0, length as u64, MAX_BLOCK_SNAPSHOT_PAGES))?;
    encoded.extend(values);
    BoundedVec::new(encoded, field).map_err(map_resource_error)
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

fn resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    hard: u64,
) -> BlockSnapshotCodecError {
    BlockSnapshotCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured: hard,
        hard,
    }
}

fn validate_snapshot(snapshot: &BlockSnapshot) -> Result<(), BlockSnapshotCodecError> {
    snapshot.core.canonical_bytes().map_err(map_io_core_error)?;
    snapshot
        .storage_faults
        .validate_restore(snapshot.device_length)
        .map_err(|_| BlockSnapshotCodecError::Nested)?;
    let maximum_pages = snapshot.device_length.div_ceil(PAGE_SIZE as u64);
    for pages in [&snapshot.overlay_delta.pages, &snapshot.full_pages] {
        if u64::try_from(pages.len()).unwrap_or(u64::MAX) > MAX_BLOCK_SNAPSHOT_PAGES
            || u64::try_from(pages.len()).map_or(true, |count| count > maximum_pages)
            || pages
                .keys()
                .any(|offset| offset % PAGE_SIZE as u64 != 0 || *offset >= snapshot.device_length)
        {
            return Err(BlockSnapshotCodecError::Invalid);
        }
    }
    if snapshot
        .overlay_delta
        .pages
        .iter()
        .any(|(offset, page)| snapshot.full_pages.get(offset) != Some(page))
        || snapshot
            .dirty
            .iter()
            .any(|offset| !snapshot.full_pages.contains_key(offset))
        || u64::try_from(snapshot.dirty.len()).unwrap_or(u64::MAX) > MAX_BLOCK_SNAPSHOT_PAGES
    {
        return Err(BlockSnapshotCodecError::Invalid);
    }
    Ok(())
}
