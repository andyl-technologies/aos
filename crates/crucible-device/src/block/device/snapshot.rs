//! Block-device checkpoint snapshot representation.

#[path = "snapshot/seed.rs"]
mod seed;

use std::collections::{BTreeMap, BTreeSet};

use crate::DeviceSnapshotAllocation;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use crate::inflight::PendingResponse;
use crate::snapshot_codec::{
    BoundedVec, SnapshotEncodeError, SnapshotResourceError, admit_input,
    encode_prefixed_with_admission, map_decode_error,
};
use crate::subnode::{IoCoreSnapshot, IoCoreSnapshotCodecError};

use super::super::overlay::{OverlayDelta, PAGE_SIZE};
use super::super::{BlockFaultState, BlockFaultStateCodecError};
use super::BlockLatency;

const BLOCK_SNAPSHOT_MAGIC: &[u8] = b"crucible.block-snapshot.v6\0";
const MAX_BLOCK_SNAPSHOT_PAGES: u64 = 4_194_304;
/// Compiled byte ceiling for one block-device snapshot.
pub const MAX_BLOCK_SNAPSHOT_BYTES: u64 = 1_073_741_824;

type SnapshotBytes = BoundedVec<u8, MAX_BLOCK_SNAPSHOT_BYTES>;
type SnapshotPage = BoundedVec<u8, { PAGE_SIZE as u64 }>;
type SnapshotPages = BoundedVec<(u64, SnapshotPage), MAX_BLOCK_SNAPSHOT_PAGES>;
type SnapshotDirtyPages = BoundedVec<u64, MAX_BLOCK_SNAPSHOT_PAGES>;

/// Borrows the exact allocation callback for the concrete block wire tables.
///
/// The callback is carried directly into every custom bounded table. The caller
/// supplies the enclosing parser and retains the accepted allocations' custody;
/// this seed neither discovers an account nor grants a funded output owner.
pub struct BlockSnapshotWireSeed<'a, 'callback> {
    inner: seed::BlockWireSeed<'a, 'callback>,
}

/// Retains a decoded wire until the device codec validates its continuation.
///
/// Its fields are private so an injected parser cannot fabricate device state
/// or extract the intermediate tables outside the codec's validation route.
pub struct DecodedBlockSnapshotWire {
    wire: BlockSnapshotWire,
}

impl<'de> serde::de::DeserializeSeed<'de> for BlockSnapshotWireSeed<'_, '_> {
    type Value = DecodedBlockSnapshotWire;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner
            .deserialize(decoder)
            .map(|wire| DecodedBlockSnapshotWire { wire })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BlockSnapshotWire {
    core: SnapshotBytes,
    base_hash: [u8; 32],
    device_length: u64,
    overlay_delta: SnapshotPages,
    full_pages: SnapshotPages,
    dirty: SnapshotDirtyPages,
    storage_faults: SnapshotBytes,
    latency: [u64; 5],
}

#[derive(Serialize)]
struct BlockSnapshotEncodeWire<'a> {
    core: SnapshotBytes,
    base_hash: [u8; 32],
    device_length: u64,
    overlay_delta: SnapshotPagesRef<'a>,
    full_pages: SnapshotPagesRef<'a>,
    dirty: SnapshotDirtyPagesRef<'a>,
    storage_faults: SnapshotBytes,
    latency: [u64; 5],
}

struct SnapshotPagesRef<'a>(&'a BTreeMap<u64, [u8; PAGE_SIZE]>);

impl Serialize for SnapshotPagesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (offset, page) in self.0 {
            sequence.serialize_element(&(*offset, page.as_slice()))?;
        }
        sequence.end()
    }
}

struct SnapshotDirtyPagesRef<'a>(&'a BTreeSet<u64>);

impl Serialize for SnapshotDirtyPagesRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for offset in self.0 {
            sequence.serialize_element(offset)?;
        }
        sequence.end()
    }
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
        self.to_canonical_bytes_with_admission(maximum, &mut |_| Ok(()), &mut |_| Ok(()))
    }

    fn to_canonical_bytes_with_admission(
        &self,
        maximum: u64,
        admit_allocation: &mut dyn FnMut(u64) -> Result<(), &'static str>,
        admit_collection: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
    ) -> Result<Vec<u8>, BlockSnapshotCodecError> {
        admit_snapshot_resources(self)?;
        validate_snapshot(self, maximum, admit_collection)?;
        let wire = BlockSnapshotEncodeWire {
            core: bounded_bytes(
                self.core
                    .canonical_bytes_with_admission(
                        maximum.min(MAX_BLOCK_SNAPSHOT_BYTES),
                        &mut |bytes| {
                            admit_allocation(bytes).map_err(|_| {
                                IoCoreSnapshotCodecError::Malformed(
                                    "original validation output refused",
                                )
                            })
                        },
                    )
                    .map_err(map_io_core_error)?,
                "block I/O core bytes",
            )?,
            base_hash: self.base_hash,
            device_length: self.device_length,
            overlay_delta: SnapshotPagesRef(&self.overlay_delta.pages),
            full_pages: SnapshotPagesRef(&self.full_pages),
            dirty: SnapshotDirtyPagesRef(&self.dirty),
            storage_faults: bounded_bytes(
                self.storage_faults
                    .to_canonical_bytes_with_admission(
                        maximum.min(MAX_BLOCK_SNAPSHOT_BYTES),
                        admit_allocation,
                    )
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
        encode_prefixed_with_admission(
            &wire,
            BLOCK_SNAPSHOT_MAGIC,
            "block snapshot bytes",
            maximum,
            MAX_BLOCK_SNAPSHOT_BYTES,
            admit_allocation,
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
        Self::finish_decoded_wire(
            bytes,
            maximum,
            wire,
            &mut |_| Ok(()),
            &mut |_| Ok(()),
            |bytes, length, maximum, admit_output, admit_validation| {
                BlockFaultState::from_canonical_bytes_with_decoder(
                    bytes,
                    length,
                    maximum,
                    admit_output,
                    admit_validation,
                    |payload| ciborium::de::from_reader(payload),
                )
            },
        )
    }

    /// Decodes custom wire tables through a supplied borrowed parser seed.
    ///
    /// The parser must use the same saved enclosing account as `admit_table`.
    /// Each callback receives the checked element-table extent before that
    /// table's reservation. Nested ordinary serde members are the supplied
    /// parser's responsibility. The nested fault decoder receives the original
    /// fault envelope after earlier fields have been accepted, preserving its
    /// original parser account and supplied-order errors. The collection callback
    /// names each actual page-map or dirty-set insertion before allocation.
    /// Nested codecs,
    /// validation and canonical output retain their separate purposes.
    /// This method does not certify complete device allocation payment.
    ///
    /// # Errors
    /// Returns the supplied decoder error or the same structural, resource,
    /// nested-state and canonical failures as the ordinary codec. An admission
    /// callback error is a fixed serde relay; its owner retains the typed cause.
    pub fn from_canonical_bytes_with_wire_decoder<F, G>(
        bytes: &[u8],
        maximum: u64,
        admit_table: &mut dyn FnMut(u64) -> Result<(), &'static str>,
        admit_collection: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
        decode: F,
        decode_fault: G,
    ) -> Result<Self, BlockSnapshotCodecError>
    where
        F: for<'a, 'callback> FnOnce(
            &[u8],
            BlockSnapshotWireSeed<'a, 'callback>,
        ) -> Result<
            DecodedBlockSnapshotWire,
            ciborium::de::Error<std::io::Error>,
        >,
        G: FnOnce(
            &[u8],
            u64,
            u64,
            &mut dyn FnMut(u64) -> Result<(), &'static str>,
            &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
        ) -> Result<BlockFaultState, BlockFaultStateCodecError>,
    {
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

        let admission = std::cell::RefCell::new(&mut *admit_table);
        let decoded = decode(
            payload,
            BlockSnapshotWireSeed {
                inner: seed::BlockWireSeed {
                    admission: &admission,
                },
            },
        )
        .map_err(|error| {
            map_decode_error(error).map_or(BlockSnapshotCodecError::Malformed, map_resource_error)
        })?;
        let admit_table = admission.into_inner();
        Self::finish_decoded_wire(
            bytes,
            maximum,
            decoded.wire,
            admit_table,
            admit_collection,
            decode_fault,
        )
    }

    fn finish_decoded_wire<G>(
        bytes: &[u8],
        maximum: u64,
        wire: BlockSnapshotWire,
        admit_allocation: &mut dyn FnMut(u64) -> Result<(), &'static str>,
        admit_collection: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
        decode_fault: G,
    ) -> Result<Self, BlockSnapshotCodecError>
    where
        G: FnOnce(
            &[u8],
            u64,
            u64,
            &mut dyn FnMut(u64) -> Result<(), &'static str>,
            &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
        ) -> Result<BlockFaultState, BlockFaultStateCodecError>,
    {
        let snapshot = Self {
            core: IoCoreSnapshot::from_canonical_bytes_with_admission(
                wire.core.as_slice(),
                maximum.min(MAX_BLOCK_SNAPSHOT_BYTES),
                &mut |bytes| {
                    admit_allocation(bytes).map_err(|_| {
                        IoCoreSnapshotCodecError::Malformed(
                            "original device snapshot allocation refused",
                        )
                    })
                },
            )
            .map_err(map_io_core_error)?,
            base_hash: wire.base_hash,
            device_length: wire.device_length,
            overlay_delta: OverlayDelta {
                pages: decode_pages(wire.overlay_delta, admit_collection)?,
            },
            full_pages: decode_pages(wire.full_pages, admit_collection)?,
            dirty: decode_dirty_pages(wire.dirty, admit_collection)?,
            storage_faults: decode_fault(
                wire.storage_faults.as_slice(),
                wire.device_length,
                maximum.min(MAX_BLOCK_SNAPSHOT_BYTES),
                admit_allocation,
                admit_collection,
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
        admit_snapshot_resources(&snapshot)?;
        validate_snapshot(&snapshot, maximum, admit_collection)?;
        if snapshot
            .to_canonical_bytes_with_admission(maximum, admit_allocation, admit_collection)?
            .as_slice()
            != bytes
        {
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

fn decode_pages(
    pages: SnapshotPages,
    admit: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
) -> Result<BTreeMap<u64, [u8; PAGE_SIZE]>, BlockSnapshotCodecError> {
    let pages = pages.into_inner();
    if pages.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(BlockSnapshotCodecError::Noncanonical);
    }

    let mut decoded = BTreeMap::new();
    for (offset, bytes) in pages {
        let page = bytes
            .into_inner()
            .try_into()
            .map_err(|_| BlockSnapshotCodecError::Invalid)?;
        admit(DeviceSnapshotAllocation::BlockPage).map_err(|_| BlockSnapshotCodecError::Nested)?;
        decoded.insert(offset, page);
    }
    Ok(decoded)
}

fn decode_dirty_pages(
    pages: SnapshotDirtyPages,
    admit: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
) -> Result<BTreeSet<u64>, BlockSnapshotCodecError> {
    let mut decoded = BTreeSet::new();
    for page in pages.into_inner() {
        if !decoded.contains(&page) {
            admit(DeviceSnapshotAllocation::BlockDirtyPage)
                .map_err(|_| BlockSnapshotCodecError::Nested)?;
            decoded.insert(page);
        }
    }
    Ok(decoded)
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

fn validate_snapshot(
    snapshot: &BlockSnapshot,
    maximum: u64,
    admit_collection: &mut dyn FnMut(DeviceSnapshotAllocation) -> Result<(), &'static str>,
) -> Result<(), BlockSnapshotCodecError> {
    snapshot
        .core
        .canonical_length_with_limit(maximum.min(MAX_BLOCK_SNAPSHOT_BYTES))
        .map_err(map_io_core_error)?;
    snapshot
        .storage_faults
        .validate_restore_with_admission(snapshot.device_length, admit_collection)
        .map_err(|_| BlockSnapshotCodecError::Nested)?;
    let maximum_pages = snapshot.device_length.div_ceil(PAGE_SIZE as u64);
    for pages in [&snapshot.overlay_delta.pages, &snapshot.full_pages] {
        if u64::try_from(pages.len()).map_or(true, |count| count > maximum_pages)
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
    {
        return Err(BlockSnapshotCodecError::Invalid);
    }
    Ok(())
}

fn admit_snapshot_resources(snapshot: &BlockSnapshot) -> Result<(), BlockSnapshotCodecError> {
    for (field, count) in [
        ("block overlay delta", snapshot.overlay_delta.pages.len()),
        ("block full pages", snapshot.full_pages.len()),
        ("block dirty pages", snapshot.dirty.len()),
    ] {
        let requested = u64::try_from(count).unwrap_or(u64::MAX);
        if requested > MAX_BLOCK_SNAPSHOT_PAGES {
            return Err(resource_limit(
                field,
                0,
                requested,
                MAX_BLOCK_SNAPSHOT_PAGES,
            ));
        }
    }
    Ok(())
}
