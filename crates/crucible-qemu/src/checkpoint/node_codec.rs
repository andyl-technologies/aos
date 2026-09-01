//! Resource admission and byte primitives for node-continuation encoding.
//!
//! The enclosing checkpoint owns the semantic fields. This module owns the
//! versioned binary format's hard ceilings, fallible allocation translation,
//! and cursor operations so malformed persisted state always fails with a
//! typed error before it can amplify into an unbounded allocation.

use crucible_shmem::{SpscRingError, SpscRingSnapshot};

use super::{QemuNetworkTransportCheckpoint, bounded_cbor::HARD_FAT_CHECKPOINT_BYTES};

pub(super) const MAX_NODE_CONTINUATION_FRAMES: usize = 1 << 20;
pub(super) const MAX_NODE_CONTINUATION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_NETWORK_QUEUE_FRAMES: u32 = 1_048_576;
pub(super) const MAX_NODE_CONTINUATION_BYTES: u64 = HARD_FAT_CHECKPOINT_BYTES;
pub(super) const MAX_NODE_CONTINUATION_RING_BYTES: u64 = 8 * 1024 * 1024 * 1024;

impl QemuNetworkTransportCheckpoint {
    pub(crate) fn empty() -> Self {
        Self {
            inbound: SpscRingSnapshot { frames: Vec::new() },
            outbound: SpscRingSnapshot { frames: Vec::new() },
            queue_capacity: crucible_shmem::DEFAULT_QUEUE_CAPACITY,
            router_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
            next_router_inbound_sequence: 0,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        }
    }

    pub(crate) fn bind_outbound_sequence(
        &mut self,
        next_host_sequence: u64,
    ) -> Result<(), QemuNodeCheckpointCodecError> {
        let mut expected = next_host_sequence;
        for frame in &self.outbound.frames {
            if u64::from(frame.seq) != expected {
                return Err(QemuNodeCheckpointCodecError::NetworkTransport);
            }
            expected = expected
                .checked_add(1)
                .ok_or(QemuNodeCheckpointCodecError::NetworkTransport)?;
        }
        if expected > u64::from(u32::MAX) {
            return Err(QemuNodeCheckpointCodecError::NetworkTransport);
        }
        self.next_host_outbound_sequence = next_host_sequence;
        self.next_plugin_outbound_sequence = expected;
        Ok(())
    }

    pub(crate) fn validate_outbound_sequences(&self) -> Result<(), QemuNodeCheckpointCodecError> {
        if self.outbound.frames.len() > self.queue_capacity as usize {
            return Err(QemuNodeCheckpointCodecError::NetworkTransport);
        }
        let mut expected = self.next_host_outbound_sequence;
        for frame in &self.outbound.frames {
            if frame.delivery_state() != Ok(crucible_shmem::FrameDeliveryState::Pending)
                || u64::from(frame.seq) != expected
            {
                return Err(QemuNodeCheckpointCodecError::NetworkTransport);
            }
            expected = expected
                .checked_add(1)
                .ok_or(QemuNodeCheckpointCodecError::NetworkTransport)?;
        }
        if expected != self.next_plugin_outbound_sequence
            || self.next_plugin_outbound_sequence > u64::from(u32::MAX)
        {
            return Err(QemuNodeCheckpointCodecError::NetworkTransport);
        }
        Ok(())
    }

    pub(crate) fn validate_inbound_sequences(&self) -> Result<(), QemuNodeCheckpointCodecError> {
        if self.queue_capacity == 0
            || !self.queue_capacity.is_power_of_two()
            || self.queue_capacity > MAX_NETWORK_QUEUE_FRAMES
            || self.inbound.frames.len() > self.queue_capacity as usize
            || self.next_router_inbound_sequence > u64::from(u32::MAX) + 1
        {
            return Err(QemuNodeCheckpointCodecError::NetworkTransport);
        }
        let Some(first) = self.inbound.frames.first() else {
            return Ok(());
        };
        let mut expected = u64::from(first.seq);
        for frame in &self.inbound.frames {
            if frame.src_node != self.router_slot || u64::from(frame.seq) != expected {
                return Err(QemuNodeCheckpointCodecError::NetworkTransport);
            }
            expected = expected
                .checked_add(1)
                .ok_or(QemuNodeCheckpointCodecError::NetworkTransport)?;
        }
        if expected != self.next_router_inbound_sequence {
            return Err(QemuNodeCheckpointCodecError::NetworkTransport);
        }
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<(), QemuNodeCheckpointCodecError> {
        self.validate_inbound_sequences()?;
        self.validate_outbound_sequences()?;
        self.inbound
            .canonical_len()
            .map_err(|_| QemuNodeCheckpointCodecError::NetworkTransport)?;
        self.outbound
            .canonical_len()
            .map_err(|_| QemuNodeCheckpointCodecError::NetworkTransport)?;
        self.retained_inbound_head()?;
        Ok(())
    }

    pub(super) fn retained_inbound_head(
        &self,
    ) -> Result<Option<crucible_shmem::FrameDeliveryKey>, QemuNodeCheckpointCodecError> {
        let mut retained = None;
        for (index, frame) in self.inbound.frames.iter().enumerate() {
            let state = frame
                .delivery_state()
                .map_err(|_| QemuNodeCheckpointCodecError::NetworkTransport)?;
            if state == crucible_shmem::FrameDeliveryState::Retained {
                if index != 0 || retained.is_some() {
                    return Err(QemuNodeCheckpointCodecError::NetworkTransport);
                }
                retained = Some(frame.delivery_key());
            }
        }
        Ok(retained)
    }

    /// Returns the next plugin-owned network TX sequence after restore.
    #[must_use]
    pub const fn next_plugin_outbound_sequence(&self) -> u64 {
        self.next_plugin_outbound_sequence
    }
}

/// Failure to decode a persisted QEMU node continuation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuNodeCheckpointCodecError {
    /// The codec version or magic does not match.
    #[error("unsupported QEMU node continuation format")]
    Unsupported,
    /// A named field is malformed or truncated.
    #[error("malformed QEMU node continuation field: {0}")]
    Malformed(&'static str),
    /// A bounded encode or decode allocation cannot be admitted.
    #[error(
        "QEMU node continuation resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
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
    /// The decoded continuation belongs to another execution.
    #[error("QEMU node continuation execution binding mismatch")]
    ExecutionBinding,
    /// Logical time is behind raw QEMU time.
    #[error("QEMU node continuation has invalid logical time calibration")]
    LogicalTime,
    /// A pending preemption decision is malformed.
    #[error("QEMU node continuation has an invalid preemption decision")]
    Preemption,
    /// A shared-memory network ring snapshot is malformed.
    #[error("QEMU node continuation has an invalid network transport")]
    NetworkTransport,
    /// Fault transport sequence cursors are invalid.
    #[error("QEMU node continuation has invalid fault sequence cursors")]
    FaultSequence,
    /// Bytes follow the complete encoded value.
    #[error("QEMU node continuation has trailing bytes")]
    Trailing,
}

pub(super) fn ring_canonical_len(
    ring: &SpscRingSnapshot,
    role: &'static str,
) -> Result<usize, QemuNodeCheckpointCodecError> {
    ring.canonical_len()
        .map_err(|error| map_ring_encode_error(error, role))
}

pub(super) fn map_ring_encode_error(
    error: SpscRingError,
    field: &'static str,
) -> QemuNodeCheckpointCodecError {
    match error {
        SpscRingError::SnapshotLengthOverflow { len }
        | SpscRingError::SnapshotAllocationFailed { count: len }
        | SpscRingError::SnapshotTooLarge { len, .. } => resource(
            field,
            0,
            usize_to_u64(len),
            u64::from(MAX_NETWORK_QUEUE_FRAMES),
            u64::from(MAX_NETWORK_QUEUE_FRAMES),
        ),
        SpscRingError::SnapshotFrameCountOverflow { count } => resource(
            field,
            0,
            count,
            u64::from(MAX_NETWORK_QUEUE_FRAMES),
            u64::from(MAX_NETWORK_QUEUE_FRAMES),
        ),
        SpscRingError::SnapshotPayloadAllocationFailed { len } => resource(
            field,
            0,
            usize_to_u64(len),
            crucible_shmem::MAX_FRAME_DATA as u64,
            crucible_shmem::MAX_FRAME_DATA as u64,
        ),
        SpscRingError::SnapshotByteAllocationFailed { len } => resource(
            field,
            0,
            usize_to_u64(len),
            MAX_NODE_CONTINUATION_RING_BYTES,
            MAX_NODE_CONTINUATION_RING_BYTES,
        ),
        _ => QemuNodeCheckpointCodecError::NetworkTransport,
    }
}

pub(super) fn map_ring_decode_error(
    error: SpscRingError,
    field: &'static str,
    configured_frames: u32,
) -> QemuNodeCheckpointCodecError {
    match error {
        SpscRingError::SnapshotAllocationFailed { count }
        | SpscRingError::SnapshotTooLarge { len: count, .. } => resource(
            field,
            0,
            usize_to_u64(count),
            u64::from(configured_frames),
            u64::from(MAX_NETWORK_QUEUE_FRAMES),
        ),
        SpscRingError::SnapshotFrameCountOverflow { count } => resource(
            field,
            0,
            count,
            u64::from(configured_frames),
            u64::from(MAX_NETWORK_QUEUE_FRAMES),
        ),
        SpscRingError::SnapshotPayloadAllocationFailed { len } => resource(
            field,
            0,
            usize_to_u64(len),
            crucible_shmem::MAX_FRAME_DATA as u64,
            crucible_shmem::MAX_FRAME_DATA as u64,
        ),
        SpscRingError::SnapshotByteAllocationFailed { len } => resource(
            field,
            0,
            usize_to_u64(len),
            MAX_NODE_CONTINUATION_RING_BYTES,
            MAX_NODE_CONTINUATION_RING_BYTES,
        ),
        _ => QemuNodeCheckpointCodecError::NetworkTransport,
    }
}

pub(super) fn admit_node_resource(
    field: &'static str,
    current: usize,
    requested: usize,
    configured: u64,
) -> Result<u64, QemuNodeCheckpointCodecError> {
    let current = usize_to_u64(current);
    let requested = usize_to_u64(requested);
    let total = current
        .checked_add(requested)
        .ok_or_else(|| resource(field, current, requested, configured, configured))?;
    if total > configured {
        return Err(resource(field, current, requested, configured, configured));
    }
    Ok(total)
}

pub(super) fn checked_node_encoded_len(
    current: usize,
    requested: usize,
    role: &'static str,
) -> Result<usize, QemuNodeCheckpointCodecError> {
    admit_node_resource(role, current, requested, MAX_NODE_CONTINUATION_BYTES)?;
    current.checked_add(requested).ok_or_else(|| {
        resource(
            role,
            usize_to_u64(current),
            usize_to_u64(requested),
            MAX_NODE_CONTINUATION_BYTES,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })
}

pub(super) fn write_node_continuation_bytes(
    bytes: &mut Vec<u8>,
    value: &[u8],
    role: &'static str,
) -> Result<(), QemuNodeCheckpointCodecError> {
    admit_node_resource(role, bytes.len(), value.len(), MAX_NODE_CONTINUATION_BYTES)?;
    bytes.try_reserve_exact(value.len()).map_err(|_| {
        resource(
            role,
            usize_to_u64(bytes.len()),
            usize_to_u64(value.len()),
            MAX_NODE_CONTINUATION_BYTES,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    bytes.extend_from_slice(value);
    Ok(())
}

pub(super) fn write_node_continuation_count(
    bytes: &mut Vec<u8>,
    count: usize,
    role: &'static str,
) -> Result<(), QemuNodeCheckpointCodecError> {
    let count = u64::try_from(count).map_err(|_| {
        resource(
            role,
            usize_to_u64(bytes.len()),
            u64::MAX,
            MAX_NODE_CONTINUATION_BYTES,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    write_node_continuation_bytes(bytes, &count.to_le_bytes(), role)
}

pub(super) fn write_node_continuation_blob(
    bytes: &mut Vec<u8>,
    value: &[u8],
    role: &'static str,
) -> Result<(), QemuNodeCheckpointCodecError> {
    write_node_continuation_count(bytes, value.len(), role)?;
    write_node_continuation_bytes(bytes, value, role)
}

pub(super) struct NodeContinuationReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NodeContinuationReader<'a> {
    pub(super) fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, QemuNodeCheckpointCodecError> {
        if !bytes.starts_with(magic) {
            return Err(QemuNodeCheckpointCodecError::Unsupported);
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
        })
    }

    pub(super) fn take(
        &mut self,
        length: usize,
        role: &'static str,
    ) -> Result<&'a [u8], QemuNodeCheckpointCodecError> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            resource(
                role,
                usize_to_u64(self.offset),
                usize_to_u64(length),
                MAX_NODE_CONTINUATION_BYTES,
                HARD_FAT_CHECKPOINT_BYTES,
            )
        })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(QemuNodeCheckpointCodecError::Malformed(role))?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn fixed<const N: usize>(
        &mut self,
        role: &'static str,
    ) -> Result<[u8; N], QemuNodeCheckpointCodecError> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.take(N, role)?);
        Ok(value)
    }

    pub(super) fn byte(&mut self, role: &'static str) -> Result<u8, QemuNodeCheckpointCodecError> {
        Ok(self.take(1, role)?[0])
    }

    pub(super) fn u64(&mut self, role: &'static str) -> Result<u64, QemuNodeCheckpointCodecError> {
        Ok(u64::from_le_bytes(self.fixed(role)?))
    }

    pub(super) fn u32(&mut self, role: &'static str) -> Result<u32, QemuNodeCheckpointCodecError> {
        Ok(u32::from_le_bytes(self.fixed(role)?))
    }

    pub(super) fn count(
        &mut self,
        role: &'static str,
        maximum: usize,
    ) -> Result<usize, QemuNodeCheckpointCodecError> {
        let count = self.u64(role)?;
        let maximum = usize_to_u64(maximum);
        if count > maximum {
            return Err(resource(role, 0, count, maximum, maximum));
        }
        usize::try_from(count).map_err(|_| resource(role, 0, count, maximum, maximum))
    }

    pub(super) fn blob(
        &mut self,
        role: &'static str,
    ) -> Result<&'a [u8], QemuNodeCheckpointCodecError> {
        self.blob_bounded(role, MAX_NODE_CONTINUATION_PAYLOAD_BYTES as u64)
    }

    pub(super) fn blob_bounded(
        &mut self,
        role: &'static str,
        maximum: u64,
    ) -> Result<&'a [u8], QemuNodeCheckpointCodecError> {
        let length = self.count_u64(role, maximum)?;
        self.take(length, role)
    }

    pub(super) fn string(
        &mut self,
        role: &'static str,
    ) -> Result<String, QemuNodeCheckpointCodecError> {
        String::from_utf8(
            self.owned_blob_bounded(role, MAX_NODE_CONTINUATION_PAYLOAD_BYTES as u64)?,
        )
        .map_err(|_| QemuNodeCheckpointCodecError::Malformed(role))
    }

    pub(super) fn owned_blob_bounded(
        &mut self,
        role: &'static str,
        maximum: u64,
    ) -> Result<Vec<u8>, QemuNodeCheckpointCodecError> {
        let value = self.blob_bounded(role, maximum)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| resource(role, 0, usize_to_u64(value.len()), maximum, maximum))?;
        owned.extend_from_slice(value);
        Ok(owned)
    }

    pub(super) fn finish(self) -> Result<(), QemuNodeCheckpointCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(QemuNodeCheckpointCodecError::Trailing)
        }
    }

    fn count_u64(
        &mut self,
        role: &'static str,
        maximum: u64,
    ) -> Result<usize, QemuNodeCheckpointCodecError> {
        let count = self.u64(role)?;
        if count > maximum {
            return Err(resource(role, 0, count, maximum, maximum));
        }
        usize::try_from(count).map_err(|_| resource(role, 0, count, maximum, maximum))
    }
}

fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> QemuNodeCheckpointCodecError {
    QemuNodeCheckpointCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
