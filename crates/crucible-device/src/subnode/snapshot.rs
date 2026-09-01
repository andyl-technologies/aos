//! Canonical, bounded snapshot codec for the uniform I/O core.

use super::*;

#[path = "snapshot/reader.rs"]
mod reader;

use reader::IoCoreSnapshotReader;

impl IoCoreSnapshot {
    /// Encodes the complete uniform I/O-core continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] when capacities, queue depths,
    /// delivery ordering, source identities, or frame payload bounds are invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IoCoreSnapshotCodecError> {
        self.canonical_bytes_with_limit(HARD_IO_CORE_CHECKPOINT_BYTES)
    }

    /// Encodes the I/O-core continuation under an enclosing byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] under the same conditions as
    /// [`Self::canonical_bytes`], and when the representation exceeds `maximum`.
    pub fn canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, IoCoreSnapshotCodecError> {
        let encoded_len = self.canonical_length_with_limit(maximum)?;
        let configured = maximum.min(HARD_IO_CORE_CHECKPOINT_BYTES);
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(encoded_len).map_err(|_| {
            io_core_configured_resource_limit(
                "I/O-core snapshot bytes",
                0,
                encoded_len as u64,
                configured,
                HARD_IO_CORE_CHECKPOINT_BYTES,
            )
        })?;
        bytes.extend_from_slice(IO_CORE_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&self.current_icount.to_le_bytes());
        bytes.push(self.shift_bits);
        bytes.extend_from_slice(&self.src_node.to_le_bytes());
        bytes.extend_from_slice(&self.next_seq.to_le_bytes());
        bytes.extend_from_slice(&self.inbox_capacity.to_le_bytes());
        bytes.extend_from_slice(&self.outbox_capacity.to_le_bytes());
        write_io_request_queue(&mut bytes, &self.inbox)?;
        write_io_response_queue(&mut bytes, &self.inflight)?;
        write_io_response_queue(&mut bytes, &self.outbox)?;
        Ok(bytes)
    }

    /// Returns the exact canonical representation length under an enclosing ceiling.
    ///
    /// This validates and admits the complete continuation without allocating
    /// its output representation, allowing parent codecs to enforce their
    /// authored aggregate before constructing nested bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] under the same conditions as
    /// [`Self::canonical_bytes_with_limit`].
    pub fn canonical_length_with_limit(
        &self,
        maximum: u64,
    ) -> Result<usize, IoCoreSnapshotCodecError> {
        validate_io_core_snapshot(self)?;
        io_core_encoded_len(self, maximum.min(HARD_IO_CORE_CHECKPOINT_BYTES))
    }

    /// Decodes and validates a complete uniform I/O-core continuation.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, invalid, noncanonical, or trailing state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, IoCoreSnapshotCodecError> {
        Self::from_canonical_bytes_with_limit(bytes, HARD_IO_CORE_CHECKPOINT_BYTES)
    }

    /// Decodes an I/O-core continuation under an enclosing byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when the input
    /// exceeds `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        maximum: u64,
    ) -> Result<Self, IoCoreSnapshotCodecError> {
        let configured = maximum.min(HARD_IO_CORE_CHECKPOINT_BYTES);
        let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if requested > configured {
            return Err(io_core_configured_resource_limit(
                "I/O-core snapshot bytes",
                0,
                requested,
                configured,
                HARD_IO_CORE_CHECKPOINT_BYTES,
            ));
        }
        let mut reader = IoCoreSnapshotReader::new(bytes)?;
        let current_icount = reader.u64("current icount")?;
        let shift_bits = reader.byte("shift bits")?;
        let src_node = reader.u32("source node")?;
        let next_seq = reader.u32("next sequence")?;
        let inbox_capacity = reader.u64("inbox capacity")?;
        let outbox_capacity = reader.u64("outbox capacity")?;
        let inbox = reader.request_queue("inbox")?;
        let inflight = reader.response_queue("in-flight responses")?;
        let outbox = reader.response_queue("outbox")?;
        reader.finish()?;
        let snapshot = Self {
            current_icount,
            shift_bits,
            src_node,
            next_seq,
            inbox_capacity,
            outbox_capacity,
            inbox,
            inflight,
            outbox,
        };
        validate_io_core_snapshot(&snapshot)?;
        if snapshot.canonical_bytes_with_limit(maximum)?.as_slice() != bytes {
            return Err(IoCoreSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
    }
}

const IO_CORE_SNAPSHOT_MAGIC: &[u8] = b"crucible.io-core-snapshot.v2\0";
const HARD_IO_CORE_CHECKPOINT_ENTRIES: usize = 65_536;
const HARD_IO_CORE_CHECKPOINT_BYTES: u64 = 1_073_741_824;

/// Failure to encode or decode a uniform I/O-core continuation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IoCoreSnapshotCodecError {
    /// The stored format version is unsupported.
    #[error("unsupported I/O-core snapshot version")]
    Version,
    /// A field is truncated or has an unknown tag.
    #[error("malformed I/O-core snapshot field `{0}`")]
    Malformed(&'static str),
    /// A queue, frame payload, representation, or allocation exceeds its bound.
    #[error(
        "I/O-core snapshot resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
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
    /// The decoded state violates a live I/O-core invariant.
    #[error("invalid I/O-core snapshot: {0}")]
    Invalid(&'static str),
    /// The encoded representation or delivery ordering is noncanonical.
    #[error("noncanonical I/O-core snapshot")]
    Noncanonical,
}

fn io_core_encoded_len(
    snapshot: &IoCoreSnapshot,
    configured: u64,
) -> Result<usize, IoCoreSnapshotCodecError> {
    let fixed = IO_CORE_SNAPSHOT_MAGIC.len() as u64 + 33 + 12;
    let mut length = add_io_core_encoded_len(0, fixed, configured)?;
    for request in &snapshot.inbox {
        length = add_io_core_encoded_len(length, 16 + request.payload.len() as u64, configured)?;
    }
    for pending in snapshot.inflight.iter().chain(&snapshot.outbox) {
        length = add_io_core_encoded_len(
            length,
            25 + pending.response.payload.len() as u64,
            configured,
        )?;
    }
    usize::try_from(length).map_err(|_| {
        io_core_configured_resource_limit(
            "I/O-core snapshot bytes",
            0,
            length,
            configured,
            HARD_IO_CORE_CHECKPOINT_BYTES,
        )
    })
}

fn add_io_core_encoded_len(
    current: u64,
    requested: u64,
    configured: u64,
) -> Result<u64, IoCoreSnapshotCodecError> {
    let total = current.checked_add(requested).ok_or_else(|| {
        io_core_configured_resource_limit(
            "I/O-core snapshot bytes",
            current,
            requested,
            configured,
            HARD_IO_CORE_CHECKPOINT_BYTES,
        )
    })?;
    if total > configured || total > HARD_IO_CORE_CHECKPOINT_BYTES {
        return Err(io_core_configured_resource_limit(
            "I/O-core snapshot bytes",
            current,
            requested,
            configured,
            HARD_IO_CORE_CHECKPOINT_BYTES,
        ));
    }
    Ok(total)
}

fn io_core_resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    hard: u64,
) -> IoCoreSnapshotCodecError {
    IoCoreSnapshotCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured: hard,
        hard,
    }
}

fn io_core_configured_resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> IoCoreSnapshotCodecError {
    IoCoreSnapshotCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    }
}

fn validate_io_core_snapshot(snapshot: &IoCoreSnapshot) -> Result<(), IoCoreSnapshotCodecError> {
    if snapshot.shift_bits >= 64 {
        return Err(IoCoreSnapshotCodecError::Invalid("clock shift"));
    }
    for (field, capacity, length) in [
        ("inbox", snapshot.inbox_capacity, snapshot.inbox.len()),
        ("outbox", snapshot.outbox_capacity, snapshot.outbox.len()),
    ] {
        if capacity > HARD_IO_CORE_CHECKPOINT_ENTRIES as u64 {
            return Err(io_core_resource_limit(
                field,
                0,
                capacity,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            ));
        }
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(IoCoreSnapshotCodecError::Invalid("queue capacity"));
        }
        if length > usize::try_from(capacity).unwrap_or(usize::MAX) {
            return Err(io_core_configured_resource_limit(
                field,
                0,
                length as u64,
                capacity,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            ));
        }
    }
    if snapshot.inflight.len() > HARD_IO_CORE_CHECKPOINT_ENTRIES {
        return Err(io_core_resource_limit(
            "in-flight responses",
            0,
            snapshot.inflight.len() as u64,
            HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
        ));
    }
    for request in &snapshot.inbox {
        if request.payload.len() > crucible_shmem::MAX_FRAME_DATA {
            return Err(io_core_resource_limit(
                "request payload",
                0,
                request.payload.len() as u64,
                crucible_shmem::MAX_FRAME_DATA as u64,
            ));
        }
    }
    for queue in [&snapshot.inflight, &snapshot.outbox] {
        for pending in queue {
            if pending.key.src_node != snapshot.src_node {
                return Err(IoCoreSnapshotCodecError::Invalid("response frame"));
            }
            if pending.response.payload.len() > crucible_shmem::MAX_FRAME_DATA {
                return Err(io_core_resource_limit(
                    "response payload",
                    0,
                    pending.response.payload.len() as u64,
                    crucible_shmem::MAX_FRAME_DATA as u64,
                ));
            }
        }
        if queue.windows(2).any(|pair| pair[0].key > pair[1].key) {
            return Err(IoCoreSnapshotCodecError::Noncanonical);
        }
    }
    Ok(())
}

fn write_io_count(
    bytes: &mut Vec<u8>,
    count: usize,
    field: &'static str,
) -> Result<(), IoCoreSnapshotCodecError> {
    if count > HARD_IO_CORE_CHECKPOINT_ENTRIES {
        return Err(io_core_resource_limit(
            field,
            0,
            count as u64,
            HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
        ));
    }
    bytes.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| {
                io_core_resource_limit(
                    field,
                    0,
                    count as u64,
                    HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
                )
            })?
            .to_le_bytes(),
    );
    Ok(())
}

fn write_io_blob(
    bytes: &mut Vec<u8>,
    value: &[u8],
    field: &'static str,
) -> Result<(), IoCoreSnapshotCodecError> {
    if value.len() > crucible_shmem::MAX_FRAME_DATA {
        return Err(io_core_resource_limit(
            field,
            0,
            value.len() as u64,
            crucible_shmem::MAX_FRAME_DATA as u64,
        ));
    }
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| {
                io_core_resource_limit(
                    field,
                    0,
                    value.len() as u64,
                    crucible_shmem::MAX_FRAME_DATA as u64,
                )
            })?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_io_request_queue(
    bytes: &mut Vec<u8>,
    queue: &[Request],
) -> Result<(), IoCoreSnapshotCodecError> {
    write_io_count(bytes, queue.len(), "request queue")?;
    for request in queue {
        bytes.extend_from_slice(&request.request_icount.to_le_bytes());
        bytes.extend_from_slice(&request.request_id.to_le_bytes());
        write_io_blob(bytes, &request.payload, "request payload")?;
    }
    Ok(())
}

fn write_io_response_queue(
    bytes: &mut Vec<u8>,
    queue: &[PendingResponse],
) -> Result<(), IoCoreSnapshotCodecError> {
    write_io_count(bytes, queue.len(), "response queue")?;
    for pending in queue {
        bytes.extend_from_slice(&pending.key.delivery_icount.to_le_bytes());
        bytes.extend_from_slice(&pending.key.src_node.to_le_bytes());
        bytes.extend_from_slice(&pending.key.seq.to_le_bytes());
        bytes.extend_from_slice(&pending.response.request_id.to_le_bytes());
        bytes.push(match pending.response.status {
            crate::request::ResponseStatus::Ok => 1,
            crate::request::ResponseStatus::Error => 2,
        });
        write_io_blob(bytes, &pending.response.payload, "response payload")?;
    }
    Ok(())
}

/// Result of draining a shared-memory request ring into an [`IoCore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmemInboxProcess {
    /// Number of request frames consumed and COMPUTEd.
    pub processed: usize,
    /// First payload byte from each consumed request, or `None` for an empty payload.
    ///
    /// Device-specific servicers use this wire tag for live operation coverage
    /// diagnostics without decoding or peeking at the SPSC ring separately.
    pub request_kinds: Vec<Option<u8>>,
    /// Icount carried by the first request frame consumed in this pass.
    pub first_request_icount: Option<u64>,
    /// Wake actions issued to the request producer as ring slots were freed.
    pub producer_wakes: Vec<WakeAction>,
}

/// Result of publishing due responses into a shared-memory response ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmemDeliveryResult {
    /// Number of due responses published to the shared-memory ring.
    pub delivered: usize,
    /// Wake issued to the response consumer after at least one frame was published.
    pub consumer_wake: Option<WakeAction>,
}

/// Result of consuming one frame from a shared-memory ring and waking its producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmemDequeueResult {
    /// The frame dequeued from the ring, if one was present.
    pub frame: Option<FrameEntry>,
    /// Wake issued to the producer after a live slot was freed.
    pub producer_wake: Option<WakeAction>,
}

#[cfg(test)]
#[path = "snapshot/tests.rs"]
mod tests;
