//! Durable codec for the Apache-side half of a QEMU execution checkpoint.

use serde::{Deserialize, Serialize};

use super::{
    QemuHostIoCheckpoint, QemuLive9pIoServicerCheckpoint, QemuLiveBlockIoServicerCheckpoint,
};
use crucible::ContentHash;
use crucible_device::{BlockSnapshot, NinepRequestOpportunity, NinepSnapshot};
use crucible_shmem::{
    RegionHeaderSnapshot, SpscRingError, SpscRingSnapshot, validate_setup_region_header,
};

const MAGIC: &[u8] = b"crucible.qemu-host-io-checkpoint.v1\0";
const MAX_BYTES: usize = 1_610_612_736;
const MAX_PENDING_NINEP_OPPORTUNITIES: usize = 1_048_576;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostIoWire {
    execution_binding: [u8; 32],
    block: Option<BlockWire>,
    ninep: Option<NinepWire>,
    accelerator: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockWire {
    execution_binding: [u8; 32],
    storage_device: Option<[u8; 32]>,
    region_header: RegionHeaderWire,
    vm_slot: u32,
    size_bytes: u64,
    device: Vec<u8>,
    requests: Vec<u8>,
    responses: Vec<u8>,
    frames_processed: u64,
    frames_delivered: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepWire {
    execution_binding: [u8; 32],
    tree: [u8; 32],
    region_header: RegionHeaderWire,
    vm_slot: u32,
    device: Vec<u8>,
    requests: Vec<u8>,
    responses: Vec<u8>,
    pending_fault_opportunities: Vec<(u64, NinepRequestOpportunity, bool)>,
    frames_processed: u64,
    frames_delivered: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionHeaderWire {
    magic: u64,
    abi_version: u32,
    node_count: u32,
    queue_capacity: u32,
    ring_count: u32,
    ring_hdr_off: u64,
    ring_data_off: u64,
    entry_stride: u64,
    region_size: u64,
    icount_shift: u32,
    pause_requested: u8,
    shutdown_requested: u8,
    fault_payload_arena_bytes: u32,
}

impl From<RegionHeaderSnapshot> for RegionHeaderWire {
    fn from(header: RegionHeaderSnapshot) -> Self {
        Self {
            magic: header.magic,
            abi_version: header.abi_version,
            node_count: header.node_count,
            queue_capacity: header.queue_capacity,
            ring_count: header.ring_count,
            ring_hdr_off: header.ring_hdr_off,
            ring_data_off: header.ring_data_off,
            entry_stride: header.entry_stride,
            region_size: header.region_size,
            icount_shift: header.icount_shift,
            pause_requested: header.pause_requested,
            shutdown_requested: header.shutdown_requested,
            fault_payload_arena_bytes: header.fault_payload_arena_bytes,
        }
    }
}

impl From<RegionHeaderWire> for RegionHeaderSnapshot {
    fn from(header: RegionHeaderWire) -> Self {
        Self {
            magic: header.magic,
            abi_version: header.abi_version,
            node_count: header.node_count,
            queue_capacity: header.queue_capacity,
            ring_count: header.ring_count,
            ring_hdr_off: header.ring_hdr_off,
            ring_data_off: header.ring_data_off,
            entry_stride: header.entry_stride,
            region_size: header.region_size,
            icount_shift: header.icount_shift,
            pause_requested: header.pause_requested,
            shutdown_requested: header.shutdown_requested,
            fault_payload_arena_bytes: header.fault_payload_arena_bytes,
        }
    }
}

impl QemuHostIoCheckpoint {
    /// Encodes every Apache-side device continuation paired with QEMU VMState.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostIoCheckpointCodecError`] if any nested checkpoint is
    /// invalid, inconsistent with the execution binding, or over the hard size
    /// ceiling.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, QemuHostIoCheckpointCodecError> {
        let wire = HostIoWire {
            execution_binding: self.execution_binding.bytes,
            block: self.block.as_ref().map(encode_block).transpose()?,
            ninep: self.ninep.as_ref().map(encode_ninep).transpose()?,
            accelerator: encode_accelerator(self)?,
        };
        validate_bindings(&wire)?;

        let mut payload = Vec::new();
        ciborium::ser::into_writer(&wire, &mut payload)
            .map_err(|_| QemuHostIoCheckpointCodecError::Malformed)?;
        if payload.len() > MAX_BYTES {
            return Err(QemuHostIoCheckpointCodecError::Limit);
        }
        let mut bytes = Vec::with_capacity(MAGIC.len() + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes and authenticates every Apache-side device continuation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHostIoCheckpointCodecError`] for unsupported, malformed,
    /// over-limit, binding-mismatched, noncanonical, or restore-invalid state.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        execution_binding: ContentHash,
    ) -> Result<Self, QemuHostIoCheckpointCodecError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(QemuHostIoCheckpointCodecError::Version)?;
        if payload.len() > MAX_BYTES {
            return Err(QemuHostIoCheckpointCodecError::Limit);
        }
        let wire: HostIoWire = ciborium::de::from_reader(payload)
            .map_err(|_| QemuHostIoCheckpointCodecError::Malformed)?;
        validate_bindings(&wire)?;
        if wire.execution_binding != execution_binding.bytes {
            return Err(QemuHostIoCheckpointCodecError::ExecutionBinding);
        }

        let checkpoint = Self {
            execution_binding,
            block: wire.block.map(decode_block).transpose()?,
            ninep: wire.ninep.map(decode_ninep).transpose()?,
            #[cfg(target_os = "linux")]
            accelerator: wire
                .accelerator
                .map(|encoded| crate::QemuLiveAcceleratorCheckpoint::from_canonical_bytes(&encoded))
                .transpose()
                .map_err(|_| QemuHostIoCheckpointCodecError::Nested)?,
        };
        #[cfg(not(target_os = "linux"))]
        if wire.accelerator.is_some() {
            return Err(QemuHostIoCheckpointCodecError::Platform);
        }
        if checkpoint.to_canonical_bytes()?.as_slice() != bytes {
            return Err(QemuHostIoCheckpointCodecError::Noncanonical);
        }
        Ok(checkpoint)
    }
}

/// Failure to encode or authenticate a QEMU host-I/O checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuHostIoCheckpointCodecError {
    /// The envelope version is unsupported.
    #[error("unsupported QEMU host-I/O checkpoint version")]
    Version,
    /// The checkpoint cannot be serialized or decoded.
    #[error("malformed QEMU host-I/O checkpoint")]
    Malformed,
    /// A nested owner checkpoint is invalid.
    #[error("invalid nested QEMU host-I/O checkpoint")]
    Nested,
    /// A nested checkpoint belongs to another VMState identity.
    #[error("QEMU host-I/O execution binding mismatch")]
    ExecutionBinding,
    /// Region, queue, device, counter, or opportunity state is inconsistent.
    #[error("invalid QEMU host-I/O checkpoint state")]
    Invalid,
    /// The checkpoint exceeds a compiled resource ceiling.
    #[error("QEMU host-I/O checkpoint exceeds its size limit")]
    Limit,
    /// A bounded ring allocation cannot be admitted.
    #[error(
        "QEMU host-I/O resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
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
    /// The checkpoint requires a host service unavailable on this platform.
    #[error("QEMU host-I/O checkpoint is unsupported on this platform")]
    Platform,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical QEMU host-I/O checkpoint")]
    Noncanonical,
}

fn validate_bindings(wire: &HostIoWire) -> Result<(), QemuHostIoCheckpointCodecError> {
    if wire.execution_binding.iter().all(|byte| *byte == 0)
        || wire
            .block
            .as_ref()
            .is_some_and(|block| block.execution_binding != wire.execution_binding)
        || wire
            .ninep
            .as_ref()
            .is_some_and(|ninep| ninep.execution_binding != wire.execution_binding)
    {
        return Err(QemuHostIoCheckpointCodecError::ExecutionBinding);
    }
    Ok(())
}

fn encode_block(
    checkpoint: &QemuLiveBlockIoServicerCheckpoint,
) -> Result<BlockWire, QemuHostIoCheckpointCodecError> {
    validate_region_and_rings(
        checkpoint.region_header,
        checkpoint.vm_slot,
        &checkpoint.requests,
        &checkpoint.responses,
    )?;
    if checkpoint.size_bytes != checkpoint.device.device_length
        || checkpoint.frames_delivered > checkpoint.frames_processed
        || checkpoint
            .storage_device
            .is_some_and(|identity| identity.bytes.iter().all(|byte| *byte == 0))
    {
        return Err(QemuHostIoCheckpointCodecError::Invalid);
    }
    Ok(BlockWire {
        execution_binding: checkpoint.execution_binding.bytes,
        storage_device: checkpoint.storage_device.map(|hash| hash.bytes),
        region_header: checkpoint.region_header.into(),
        vm_slot: checkpoint.vm_slot,
        size_bytes: checkpoint.size_bytes,
        device: checkpoint
            .device
            .to_canonical_bytes()
            .map_err(|_| QemuHostIoCheckpointCodecError::Nested)?,
        requests: checkpoint.requests.canonical_bytes().map_err(|error| {
            map_host_ring_error(
                error,
                "block requests",
                checkpoint.region_header.queue_capacity,
            )
        })?,
        responses: checkpoint.responses.canonical_bytes().map_err(|error| {
            map_host_ring_error(
                error,
                "block responses",
                checkpoint.region_header.queue_capacity,
            )
        })?,
        frames_processed: u64::try_from(checkpoint.frames_processed)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
        frames_delivered: u64::try_from(checkpoint.frames_delivered)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
    })
}

fn decode_block(
    wire: BlockWire,
) -> Result<QemuLiveBlockIoServicerCheckpoint, QemuHostIoCheckpointCodecError> {
    let region_header: RegionHeaderSnapshot = wire.region_header.into();
    let queue_capacity = region_header.queue_capacity as usize;
    let checkpoint = QemuLiveBlockIoServicerCheckpoint {
        execution_binding: ContentHash {
            bytes: wire.execution_binding,
        },
        storage_device: wire.storage_device.map(|bytes| ContentHash { bytes }),
        region_header,
        vm_slot: wire.vm_slot,
        size_bytes: wire.size_bytes,
        device: BlockSnapshot::from_canonical_bytes(&wire.device)
            .map_err(|_| QemuHostIoCheckpointCodecError::Nested)?,
        requests: SpscRingSnapshot::from_canonical_bytes(&wire.requests, queue_capacity).map_err(
            |error| map_host_ring_error(error, "block requests", region_header.queue_capacity),
        )?,
        responses: SpscRingSnapshot::from_canonical_bytes(&wire.responses, queue_capacity)
            .map_err(|error| {
                map_host_ring_error(error, "block responses", region_header.queue_capacity)
            })?,
        frames_processed: usize::try_from(wire.frames_processed)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
        frames_delivered: usize::try_from(wire.frames_delivered)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
    };
    encode_block(&checkpoint)?;
    Ok(checkpoint)
}

fn encode_ninep(
    checkpoint: &QemuLive9pIoServicerCheckpoint,
) -> Result<NinepWire, QemuHostIoCheckpointCodecError> {
    validate_region_and_rings(
        checkpoint.region_header,
        checkpoint.vm_slot,
        &checkpoint.requests,
        &checkpoint.responses,
    )?;
    if checkpoint.tree.bytes.iter().all(|byte| *byte == 0)
        || checkpoint.frames_delivered > checkpoint.frames_processed
        || checkpoint.pending_fault_opportunities.len() > MAX_PENDING_NINEP_OPPORTUNITIES
        || checkpoint
            .pending_fault_opportunities
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err(QemuHostIoCheckpointCodecError::Invalid);
    }
    for (_, opportunity, _) in &checkpoint.pending_fault_opportunities {
        let rebuilt = NinepRequestOpportunity::from_frame(
            opportunity.request_icount,
            opportunity.identity.transport_sequence,
            opportunity.frame.clone(),
        )
        .map_err(|_| QemuHostIoCheckpointCodecError::Invalid)?;
        if rebuilt != *opportunity {
            return Err(QemuHostIoCheckpointCodecError::Invalid);
        }
    }
    Ok(NinepWire {
        execution_binding: checkpoint.execution_binding.bytes,
        tree: checkpoint.tree.bytes,
        region_header: checkpoint.region_header.into(),
        vm_slot: checkpoint.vm_slot,
        device: checkpoint
            .device
            .to_canonical_bytes()
            .map_err(|_| QemuHostIoCheckpointCodecError::Nested)?,
        requests: checkpoint.requests.canonical_bytes().map_err(|error| {
            map_host_ring_error(
                error,
                "9p requests",
                checkpoint.region_header.queue_capacity,
            )
        })?,
        responses: checkpoint.responses.canonical_bytes().map_err(|error| {
            map_host_ring_error(
                error,
                "9p responses",
                checkpoint.region_header.queue_capacity,
            )
        })?,
        pending_fault_opportunities: checkpoint.pending_fault_opportunities.clone(),
        frames_processed: u64::try_from(checkpoint.frames_processed)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
        frames_delivered: u64::try_from(checkpoint.frames_delivered)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
    })
}

fn decode_ninep(
    wire: NinepWire,
) -> Result<QemuLive9pIoServicerCheckpoint, QemuHostIoCheckpointCodecError> {
    let region_header: RegionHeaderSnapshot = wire.region_header.into();
    let queue_capacity = region_header.queue_capacity as usize;
    let checkpoint = QemuLive9pIoServicerCheckpoint {
        execution_binding: ContentHash {
            bytes: wire.execution_binding,
        },
        tree: ContentHash { bytes: wire.tree },
        region_header,
        vm_slot: wire.vm_slot,
        device: NinepSnapshot::from_canonical_bytes(&wire.device)
            .map_err(|_| QemuHostIoCheckpointCodecError::Nested)?,
        requests: SpscRingSnapshot::from_canonical_bytes(&wire.requests, queue_capacity).map_err(
            |error| map_host_ring_error(error, "9p requests", region_header.queue_capacity),
        )?,
        responses: SpscRingSnapshot::from_canonical_bytes(&wire.responses, queue_capacity)
            .map_err(|error| {
                map_host_ring_error(error, "9p responses", region_header.queue_capacity)
            })?,
        pending_fault_opportunities: wire.pending_fault_opportunities,
        frames_processed: usize::try_from(wire.frames_processed)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
        frames_delivered: usize::try_from(wire.frames_delivered)
            .map_err(|_| QemuHostIoCheckpointCodecError::Limit)?,
    };
    encode_ninep(&checkpoint)?;
    Ok(checkpoint)
}

fn validate_region_and_rings(
    header: RegionHeaderSnapshot,
    vm_slot: u32,
    requests: &SpscRingSnapshot,
    responses: &SpscRingSnapshot,
) -> Result<(), QemuHostIoCheckpointCodecError> {
    validate_setup_region_header(header, header.region_size)
        .map_err(|_| QemuHostIoCheckpointCodecError::Invalid)?;
    if vm_slot >= header.node_count
        || requests.frames.len() > header.queue_capacity as usize
        || responses.frames.len() > header.queue_capacity as usize
    {
        return Err(QemuHostIoCheckpointCodecError::Invalid);
    }
    Ok(())
}

fn map_host_ring_error(
    error: SpscRingError,
    field: &'static str,
    configured_frames: u32,
) -> QemuHostIoCheckpointCodecError {
    match error {
        SpscRingError::SnapshotAllocationFailed { count }
        | SpscRingError::SnapshotTooLarge { len: count, .. } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: count as u64,
                configured: u64::from(configured_frames),
                hard: 1_048_576,
            }
        }
        SpscRingError::SnapshotFrameCountOverflow { count } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: count,
                configured: u64::from(configured_frames),
                hard: 1_048_576,
            }
        }
        SpscRingError::SnapshotPayloadAllocationFailed { len } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: len as u64,
                configured: crucible_shmem::MAX_FRAME_DATA as u64,
                hard: crucible_shmem::MAX_FRAME_DATA as u64,
            }
        }
        SpscRingError::SnapshotByteAllocationFailed { len }
        | SpscRingError::SnapshotLengthOverflow { len } => {
            QemuHostIoCheckpointCodecError::ResourceLimit {
                field,
                current: 0,
                requested: len as u64,
                configured: MAX_BYTES as u64,
                hard: MAX_BYTES as u64,
            }
        }
        _ => QemuHostIoCheckpointCodecError::Nested,
    }
}

#[cfg(target_os = "linux")]
fn encode_accelerator(
    checkpoint: &QemuHostIoCheckpoint,
) -> Result<Option<Vec<u8>>, QemuHostIoCheckpointCodecError> {
    checkpoint
        .accelerator
        .as_ref()
        .map(|state| {
            state
                .to_canonical_bytes()
                .map_err(|_| QemuHostIoCheckpointCodecError::Nested)
        })
        .transpose()
}

#[cfg(not(target_os = "linux"))]
fn encode_accelerator(
    _checkpoint: &QemuHostIoCheckpoint,
) -> Result<Option<Vec<u8>>, QemuHostIoCheckpointCodecError> {
    Ok(None)
}
