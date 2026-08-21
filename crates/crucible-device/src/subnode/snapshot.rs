//! Canonical, bounded snapshot codec for the uniform I/O core.

use super::*;

impl IoCoreSnapshot {
    /// Encodes the complete uniform I/O-core continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] when capacities, queue depths,
    /// delivery ordering, source identities, or frame payload bounds are invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IoCoreSnapshotCodecError> {
        validate_io_core_snapshot(self)?;
        let encoded_len = io_core_encoded_len(self)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(encoded_len).map_err(|_| {
            io_core_resource_limit(
                "I/O-core snapshot bytes",
                0,
                encoded_len as u64,
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

    /// Decodes and validates a complete uniform I/O-core continuation.
    ///
    /// # Errors
    ///
    /// Returns [`IoCoreSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, invalid, noncanonical, or trailing state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, IoCoreSnapshotCodecError> {
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
        if snapshot.canonical_bytes()?.as_slice() != bytes {
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

fn io_core_encoded_len(snapshot: &IoCoreSnapshot) -> Result<usize, IoCoreSnapshotCodecError> {
    let fixed = IO_CORE_SNAPSHOT_MAGIC.len() as u64 + 33 + 12;
    let mut length = fixed;
    for request in &snapshot.inbox {
        length = add_io_core_encoded_len(length, 16 + request.payload.len() as u64)?;
    }
    for pending in snapshot.inflight.iter().chain(&snapshot.outbox) {
        length = add_io_core_encoded_len(length, 25 + pending.response.payload.len() as u64)?;
    }
    usize::try_from(length).map_err(|_| {
        io_core_resource_limit(
            "I/O-core snapshot bytes",
            0,
            length,
            HARD_IO_CORE_CHECKPOINT_BYTES,
        )
    })
}

fn add_io_core_encoded_len(current: u64, requested: u64) -> Result<u64, IoCoreSnapshotCodecError> {
    let total = current.checked_add(requested).ok_or_else(|| {
        io_core_resource_limit(
            "I/O-core snapshot bytes",
            current,
            requested,
            HARD_IO_CORE_CHECKPOINT_BYTES,
        )
    })?;
    if total > HARD_IO_CORE_CHECKPOINT_BYTES {
        return Err(io_core_resource_limit(
            "I/O-core snapshot bytes",
            current,
            requested,
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

fn validate_io_core_snapshot(snapshot: &IoCoreSnapshot) -> Result<(), IoCoreSnapshotCodecError> {
    if snapshot.shift_bits >= 64 {
        return Err(IoCoreSnapshotCodecError::Invalid("clock shift"));
    }
    for (field, capacity, length) in [
        ("inbox", snapshot.inbox_capacity, snapshot.inbox.len()),
        ("outbox", snapshot.outbox_capacity, snapshot.outbox.len()),
    ] {
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(IoCoreSnapshotCodecError::Invalid("queue capacity"));
        }
        if capacity > HARD_IO_CORE_CHECKPOINT_ENTRIES as u64
            || length > usize::try_from(capacity).unwrap_or(usize::MAX)
        {
            return Err(io_core_resource_limit(
                field,
                0,
                length as u64,
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
        if queue.iter().any(|pending| {
            pending.key.src_node != snapshot.src_node
                || pending.response.payload.len() > crucible_shmem::MAX_FRAME_DATA
        }) {
            return Err(IoCoreSnapshotCodecError::Invalid("response frame"));
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

struct IoCoreSnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> IoCoreSnapshotReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, IoCoreSnapshotCodecError> {
        let bytes = bytes
            .strip_prefix(IO_CORE_SNAPSHOT_MAGIC)
            .ok_or(IoCoreSnapshotCodecError::Version)?;
        Ok(Self { bytes, offset: 0 })
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], IoCoreSnapshotCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?
            .try_into()
            .map_err(|_| IoCoreSnapshotCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, IoCoreSnapshotCodecError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, IoCoreSnapshotCodecError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, IoCoreSnapshotCodecError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn count(&mut self, field: &'static str) -> Result<usize, IoCoreSnapshotCodecError> {
        let count = usize::try_from(self.u32(field)?)
            .map_err(|_| IoCoreSnapshotCodecError::Malformed(field))?;
        if count > HARD_IO_CORE_CHECKPOINT_ENTRIES {
            return Err(io_core_resource_limit(
                field,
                0,
                count as u64,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            ));
        }
        Ok(count)
    }

    fn blob(&mut self, field: &'static str) -> Result<Vec<u8>, IoCoreSnapshotCodecError> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| IoCoreSnapshotCodecError::Malformed(field))?;
        if length > crucible_shmem::MAX_FRAME_DATA {
            return Err(io_core_resource_limit(
                field,
                0,
                length as u64,
                crucible_shmem::MAX_FRAME_DATA as u64,
            ));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?;
        let mut value = Vec::new();
        value.try_reserve_exact(length).map_err(|_| {
            io_core_resource_limit(
                field,
                0,
                length as u64,
                crucible_shmem::MAX_FRAME_DATA as u64,
            )
        })?;
        value.extend_from_slice(source);
        self.offset = end;
        Ok(value)
    }

    fn request_queue(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<Request>, IoCoreSnapshotCodecError> {
        let count = self.count(field)?;
        let mut queue = Vec::new();
        queue.try_reserve_exact(count).map_err(|_| {
            io_core_resource_limit(
                field,
                0,
                count as u64,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            )
        })?;
        for _ in 0..count {
            queue.push(Request::new(
                self.u64("request icount")?,
                self.u32("request identity")?,
                self.blob("request payload")?,
            ));
        }
        Ok(queue)
    }

    fn response_queue(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<PendingResponse>, IoCoreSnapshotCodecError> {
        let count = self.count(field)?;
        let mut queue = Vec::new();
        queue.try_reserve_exact(count).map_err(|_| {
            io_core_resource_limit(
                field,
                0,
                count as u64,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            )
        })?;
        for _ in 0..count {
            let delivery_icount = self.u64("delivery icount")?;
            let src_node = self.u32("response source")?;
            let sequence = self.u32("response sequence")?;
            let request_id = self.u32("response identity")?;
            let status = match self.byte("response status")? {
                1 => crate::request::ResponseStatus::Ok,
                2 => crate::request::ResponseStatus::Error,
                _ => return Err(IoCoreSnapshotCodecError::Malformed("response status")),
            };
            queue.push(PendingResponse::from_parts(
                delivery_icount,
                src_node,
                sequence,
                crate::request::Response::new(request_id, status, self.blob("response payload")?),
            ));
        }
        Ok(queue)
    }

    fn finish(self) -> Result<(), IoCoreSnapshotCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(IoCoreSnapshotCodecError::Noncanonical)
        }
    }
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
