//! Block-device checkpoint snapshot representation.

use std::collections::{BTreeMap, BTreeSet};

use crate::inflight::PendingResponse;
use crate::subnode::IoCoreSnapshot;

use super::super::BlockFaultState;
use super::super::overlay::{OverlayDelta, PAGE_SIZE};
use super::BlockLatency;

const BLOCK_SNAPSHOT_MAGIC: &[u8] = b"crucible.block-snapshot.v1\0";
const MAX_BLOCK_SNAPSHOT_PAGES: usize = 4_194_304;
const MAX_BLOCK_SNAPSHOT_BYTES: usize = 1_073_741_824;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockSnapshotWire {
    core: Vec<u8>,
    base_hash: [u8; 32],
    device_length: u64,
    overlay_delta: Vec<(u64, Vec<u8>)>,
    full_pages: Vec<(u64, Vec<u8>)>,
    dirty: Vec<u64>,
    storage_faults: Vec<u8>,
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
            core: self
                .core
                .canonical_bytes()
                .map_err(|_| BlockSnapshotCodecError::Nested)?,
            base_hash: self.base_hash,
            device_length: self.device_length,
            overlay_delta: encode_pages(&self.overlay_delta.pages),
            full_pages: encode_pages(&self.full_pages),
            dirty: self.dirty.iter().copied().collect(),
            storage_faults: self
                .storage_faults
                .to_canonical_bytes()
                .map_err(|_| BlockSnapshotCodecError::Nested)?,
            latency: [
                self.latency.read_base_ns,
                self.latency.write_base_ns,
                self.latency.flush_ns,
                self.latency.get_length_ns,
                self.latency.per_byte_ns,
            ],
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&wire, &mut payload)
            .map_err(|_| BlockSnapshotCodecError::Malformed)?;
        if payload.len() > MAX_BLOCK_SNAPSHOT_BYTES {
            return Err(BlockSnapshotCodecError::Limit);
        }
        let mut bytes = Vec::with_capacity(BLOCK_SNAPSHOT_MAGIC.len() + payload.len());
        bytes.extend_from_slice(BLOCK_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
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
        if payload.len() > MAX_BLOCK_SNAPSHOT_BYTES {
            return Err(BlockSnapshotCodecError::Limit);
        }
        let wire: BlockSnapshotWire = ciborium::de::from_reader(payload)
            .map_err(|_| BlockSnapshotCodecError::Malformed)?;
        let snapshot = Self {
            core: IoCoreSnapshot::from_canonical_bytes(&wire.core)
                .map_err(|_| BlockSnapshotCodecError::Nested)?,
            base_hash: wire.base_hash,
            device_length: wire.device_length,
            overlay_delta: OverlayDelta {
                pages: decode_pages(wire.overlay_delta)?,
            },
            full_pages: decode_pages(wire.full_pages)?,
            dirty: wire.dirty.into_iter().collect(),
            storage_faults: BlockFaultState::from_canonical_bytes(
                &wire.storage_faults,
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
    /// The snapshot exceeds a compiled resource ceiling.
    #[error("block snapshot exceeds its size limit")]
    Limit,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical block snapshot")]
    Noncanonical,
}

fn encode_pages(pages: &BTreeMap<u64, [u8; PAGE_SIZE]>) -> Vec<(u64, Vec<u8>)> {
    pages
        .iter()
        .map(|(offset, page)| (*offset, page.to_vec()))
        .collect()
}

fn decode_pages(
    pages: Vec<(u64, Vec<u8>)>,
) -> Result<BTreeMap<u64, [u8; PAGE_SIZE]>, BlockSnapshotCodecError> {
    if pages.len() > MAX_BLOCK_SNAPSHOT_PAGES
        || pages.windows(2).any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(BlockSnapshotCodecError::Limit);
    }
    pages
        .into_iter()
        .map(|(offset, bytes)| {
            let page = bytes
                .try_into()
                .map_err(|_| BlockSnapshotCodecError::Invalid)?;
            Ok((offset, page))
        })
        .collect()
}

fn validate_snapshot(snapshot: &BlockSnapshot) -> Result<(), BlockSnapshotCodecError> {
    snapshot
        .core
        .canonical_bytes()
        .map_err(|_| BlockSnapshotCodecError::Nested)?;
    snapshot
        .storage_faults
        .validate_restore(snapshot.device_length)
        .map_err(|_| BlockSnapshotCodecError::Nested)?;
    let maximum_pages = snapshot.device_length.div_ceil(PAGE_SIZE as u64);
    for pages in [&snapshot.overlay_delta.pages, &snapshot.full_pages] {
        if pages.len() > MAX_BLOCK_SNAPSHOT_PAGES
            || u64::try_from(pages.len()).map_or(true, |count| count > maximum_pages)
            || pages.keys().any(|offset| {
                offset % PAGE_SIZE as u64 != 0 || *offset >= snapshot.device_length
            })
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
        || snapshot.dirty.len() > MAX_BLOCK_SNAPSHOT_PAGES
    {
        return Err(BlockSnapshotCodecError::Invalid);
    }
    Ok(())
}
