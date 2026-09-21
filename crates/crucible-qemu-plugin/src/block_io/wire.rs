//! Versioned block request, response, and transport-reset wire types.

use super::*;

/// A mutable view of the outbound block executor ring.
pub struct BlockOutboundRing<'a> {
    pub(super) ring_index: u32,
    pub(super) src_slot: u32,
    pub(super) dst_slot: u32,
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a mut [FrameEntry],
}

impl<'a> BlockOutboundRing<'a> {
    /// Builds an outbound block ring view.
    #[must_use]
    pub fn new(
        ring_index: u32,
        src_slot: u32,
        dst_slot: u32,
        header: &'a RingHeader,
        entries: &'a mut [FrameEntry],
    ) -> Self {
        Self {
            ring_index,
            src_slot,
            dst_slot,
            header,
            entries,
        }
    }
}

/// An immutable consumer view of the inbound block executor ring.
#[derive(Clone, Copy)]
pub struct BlockInboundRing<'a> {
    pub(super) ring_index: u32,
    pub(super) src_slot: u32,
    pub(super) dst_slot: u32,
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a [FrameEntry],
}

impl<'a> BlockInboundRing<'a> {
    /// Builds an inbound block ring view.
    #[must_use]
    pub const fn new(
        ring_index: u32,
        src_slot: u32,
        dst_slot: u32,
        header: &'a RingHeader,
        entries: &'a [FrameEntry],
    ) -> Self {
        Self {
            ring_index,
            src_slot,
            dst_slot,
            header,
            entries,
        }
    }
}

/// A guest block operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOperation {
    /// Read bytes from the block image.
    Read,
    /// Write bytes to the block overlay.
    Write,
    /// Flush pending writes.
    Flush,
    /// Query the device length.
    GetLength,
    /// Discard a payload-free byte range.
    Discard,
}

impl BlockOperation {
    const fn wire_type(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Flush => 2,
            Self::GetLength => 3,
            Self::Discard => 4,
        }
    }

    fn from_wire(operation: u8) -> Result<Self, BlockWireError> {
        match operation {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Flush),
            3 => Ok(Self::GetLength),
            4 => Ok(Self::Discard),
            other => Err(BlockWireError::UnknownOperation { operation: other }),
        }
    }
}

/// A guest block request before it is assigned a wire request id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequest {
    operation: BlockOperation,
    offset: u64,
    count: u32,
    payload: Vec<u8>,
}

impl BlockRequest {
    /// Builds a read request.
    #[must_use]
    pub const fn read(offset: u64, count: u32) -> Self {
        Self {
            operation: BlockOperation::Read,
            offset,
            count,
            payload: Vec::new(),
        }
    }

    /// Builds a write request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::PayloadLengthOverflow`] when the write payload
    /// length cannot fit in the wire-format `count` field.
    pub fn write(offset: u64, payload: Vec<u8>) -> Result<Self, BlockWireError> {
        let count = u32::try_from(payload.len())
            .map_err(|_| BlockWireError::PayloadLengthOverflow { len: payload.len() })?;
        Ok(Self {
            operation: BlockOperation::Write,
            offset,
            count,
            payload,
        })
    }

    /// Builds a flush request.
    #[must_use]
    pub const fn flush() -> Self {
        Self {
            operation: BlockOperation::Flush,
            offset: 0,
            count: 0,
            payload: Vec::new(),
        }
    }

    /// Builds a get-length request.
    #[must_use]
    pub const fn get_length() -> Self {
        Self {
            operation: BlockOperation::GetLength,
            offset: 0,
            count: 0,
            payload: Vec::new(),
        }
    }

    /// Builds a payload-free discard request.
    #[must_use]
    pub const fn discard(offset: u64, count: u32) -> Self {
        Self {
            operation: BlockOperation::Discard,
            offset,
            count,
            payload: Vec::new(),
        }
    }

    /// Returns the operation kind.
    #[must_use]
    pub const fn operation(&self) -> BlockOperation {
        self.operation
    }

    /// Returns the byte offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the requested byte count.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the write payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes a request in the block wire format with the supplied request id.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] when the request payload is inconsistent with
    /// the operation kind or the encoded frame would exceed the shared-memory
    /// frame payload capacity.
    pub fn encode(&self, identity: BlockRequestIdentity) -> Result<Vec<u8>, BlockWireError> {
        if self.operation == BlockOperation::Write && self.payload.len() != self.count as usize {
            return Err(BlockWireError::CountPayloadMismatch {
                count: self.count,
                payload_len: self.payload.len(),
            });
        }
        if self.operation != BlockOperation::Write && !self.payload.is_empty() {
            return Err(BlockWireError::UnexpectedPayload {
                operation: self.operation,
                payload_len: self.payload.len(),
            });
        }
        let payload_len = BLOCK_REQUEST_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(BlockWireError::PayloadLengthOverflow {
                len: self.payload.len(),
            })?;
        if payload_len > MAX_FRAME_DATA {
            return Err(BlockWireError::FramePayload {
                source: FrameEntryError::PayloadLengthExceedsCapacity {
                    len: payload_len,
                    capacity: MAX_FRAME_DATA,
                },
            });
        }
        let mut out = Vec::with_capacity(payload_len);
        out.push(self.operation.wire_type());
        out.push(BLOCK_WIRE_VERSION);
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&identity.epoch.to_le_bytes());
        out.extend_from_slice(&identity.request_id.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a request from the block wire format.
    ///
    /// The returned tuple contains the wire request id and the logical request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] when the payload is shorter than the fixed
    /// header, uses an unsupported version or operation, carries nonzero
    /// reserved bits, or contains an operation-inconsistent body.
    pub fn decode(payload: &[u8]) -> Result<(BlockRequestIdentity, Self), BlockWireError> {
        if payload.len() < BLOCK_REQUEST_HEADER_LEN {
            return Err(BlockWireError::ShortRequest { len: payload.len() });
        }
        let operation = BlockOperation::from_wire(payload[0])?;
        if payload[1] != BLOCK_WIRE_VERSION {
            return Err(BlockWireError::UnsupportedVersion {
                version: payload[1],
            });
        }
        let reserved = u16::from_le_bytes(
            payload[2..4]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        if reserved != 0 {
            return Err(BlockWireError::NonZeroReserved { reserved });
        }
        let epoch = u64::from_le_bytes(
            payload[4..12]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let request_id = u32::from_le_bytes(
            payload[12..16]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let offset = u64::from_le_bytes(
            payload[16..24]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let count = u32::from_le_bytes(
            payload[24..28]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let payload_bytes = &payload[BLOCK_REQUEST_HEADER_LEN..];
        match operation {
            BlockOperation::Write => {
                let count_usize = usize::try_from(count)
                    .map_err(|_| BlockWireError::CountLengthOverflow { count })?;
                if count_usize > payload_bytes.len() {
                    return Err(BlockWireError::RequestCountExceedsPayload {
                        count,
                        available: payload_bytes.len(),
                    });
                }
                if count_usize != payload_bytes.len() {
                    return Err(BlockWireError::RequestCountPayloadMismatch {
                        count,
                        payload_len: payload_bytes.len(),
                    });
                }
                Ok((
                    BlockRequestIdentity::new(epoch, request_id),
                    Self {
                        operation,
                        offset,
                        count,
                        payload: payload_bytes.to_vec(),
                    },
                ))
            }
            _ if !payload_bytes.is_empty() => Err(BlockWireError::UnexpectedPayload {
                operation,
                payload_len: payload_bytes.len(),
            }),
            _ => Ok((
                BlockRequestIdentity::new(epoch, request_id),
                Self {
                    operation,
                    offset,
                    count,
                    payload: Vec::new(),
                },
            )),
        }
    }
}

/// A block executor response ready to expose to the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockResponse {
    status: BlockResponseStatus,
    identity: BlockRequestIdentity,
    request_id: u32,
    payload: Vec<u8>,
}

impl BlockResponse {
    /// Builds a response for tests and callback adapters.
    #[must_use]
    pub fn new(status: BlockResponseStatus, request_id: u32, payload: Vec<u8>) -> Self {
        Self::with_identity(status, BlockRequestIdentity::new(0, request_id), payload)
    }

    /// Builds a response with an explicit epoch-scoped request identity.
    #[must_use]
    pub fn with_identity(
        status: BlockResponseStatus,
        identity: BlockRequestIdentity,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            status,
            identity,
            request_id: identity.request_id,
            payload,
        }
    }

    /// Builds a live transport-reset event for an already-completed request.
    #[must_use]
    pub fn reset_event(identity: BlockRequestIdentity, reset: BlockTransportReset) -> Self {
        Self::with_identity(
            BlockResponseStatus::TransportReset,
            identity,
            reset.encode().to_vec(),
        )
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> BlockResponseStatus {
        self.status
    }

    /// Returns the echoed request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// Returns the epoch-scoped request identity echoed by the response.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        self.identity
    }

    /// Returns the response payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the typed block error for a failed response.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::InvalidErrorPayload`] unless this is an error
    /// response carrying exactly one defined result byte.
    pub fn error_code(&self) -> Result<BlockResponseErrorCode, BlockWireError> {
        if !matches!(
            self.status,
            BlockResponseStatus::Error | BlockResponseStatus::DuplicateProtocolError
        ) || self.payload.len() != 1
        {
            return Err(BlockWireError::InvalidErrorPayload {
                status: self.status.wire_status(),
                len: self.payload.len(),
            });
        }
        BlockResponseErrorCode::from_wire(self.payload[0])
    }

    /// Returns the decoded live transport-reset transition.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::InvalidResetPayload`] unless this response is
    /// a reset with the exact closed payload shape.
    pub fn transport_reset(&self) -> Result<BlockTransportReset, BlockWireError> {
        if self.status != BlockResponseStatus::TransportReset {
            return Err(BlockWireError::InvalidResetPayload {
                len: self.payload.len(),
            });
        }
        BlockTransportReset::decode(&self.payload)
    }

    /// Encodes a response in the block wire format.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError::PayloadLengthOverflow`] when the response
    /// payload length cannot fit in the wire-format `count` field or cannot be
    /// added to the fixed header length.
    pub fn encode(&self) -> Result<Vec<u8>, BlockWireError> {
        let count = u32::try_from(self.payload.len()).map_err(|_| {
            BlockWireError::PayloadLengthOverflow {
                len: self.payload.len(),
            }
        })?;
        let payload_len = BLOCK_RESPONSE_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(BlockWireError::PayloadLengthOverflow {
                len: self.payload.len(),
            })?;
        let mut out = Vec::with_capacity(payload_len);
        out.push(self.status.wire_status());
        out.push(BLOCK_WIRE_VERSION);
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&self.identity.epoch.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a response from the block wire format.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] when the payload is shorter than the fixed
    /// header, uses an unsupported version or status, carries nonzero reserved
    /// bits, or has a `count` field that does not exactly match the payload
    /// bytes that follow the header.
    pub fn decode(payload: &[u8]) -> Result<Self, BlockWireError> {
        if payload.len() < BLOCK_RESPONSE_HEADER_LEN {
            return Err(BlockWireError::ShortResponse { len: payload.len() });
        }
        let status = BlockResponseStatus::from_wire(payload[0])?;
        if payload[1] != BLOCK_WIRE_VERSION {
            return Err(BlockWireError::UnsupportedVersion {
                version: payload[1],
            });
        }
        let reserved = u16::from_le_bytes(
            payload[2..4]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        if reserved != 0 {
            return Err(BlockWireError::NonZeroReserved { reserved });
        }
        let epoch = u64::from_le_bytes(
            payload[4..12]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let request_id = u32::from_le_bytes(
            payload[12..16]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let count = u32::from_le_bytes(
            payload[16..20]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let count_usize =
            usize::try_from(count).map_err(|_| BlockWireError::CountLengthOverflow { count })?;
        let actual = payload.len() - BLOCK_RESPONSE_HEADER_LEN;
        if count_usize > actual {
            return Err(BlockWireError::CountExceedsPayload {
                count,
                available: actual,
            });
        }
        if count_usize != actual {
            return Err(BlockWireError::ResponseCountPayloadMismatch {
                count,
                payload_len: actual,
            });
        }
        let response = Self {
            status,
            identity: BlockRequestIdentity::new(epoch, request_id),
            request_id,
            payload: payload[BLOCK_RESPONSE_HEADER_LEN..BLOCK_RESPONSE_HEADER_LEN + count_usize]
                .to_vec(),
        };
        if matches!(
            status,
            BlockResponseStatus::Error | BlockResponseStatus::DuplicateProtocolError
        ) {
            response.error_code()?;
        } else if status == BlockResponseStatus::TransportReset {
            response.transport_reset()?;
        }
        Ok(response)
    }
}

/// Block response status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockResponseStatus {
    /// Request completed successfully.
    Ok,
    /// Request completed with a device error.
    Error,
    /// Completion requesting a live guest transport reset.
    TransportReset,
    /// Protocol-valid duplicate consumed without a guest completion.
    DuplicateIgnored,
    /// Duplicate carrying a typed protocol error.
    DuplicateProtocolError,
    /// Outstanding request must retry with its existing identity.
    RetryPreserveId,
    /// Outstanding request must retry with a new post-reset identity.
    RetryNewId,
    /// Outstanding completion is intentionally dropped.
    DropCompletion,
}

/// Post-reset request-ID allocation rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportRequestIds {
    /// Keeps the current epoch and monotone counter.
    PreserveMonotonic,
    /// Switches to the supplied epoch and restarts from zero.
    NewEpochFromZero,
}

/// Request treatment while reset recovery blocks admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportUnadmitted {
    /// Rejects the request.
    Reject,
    /// Holds the request until recovery.
    WaitForRecovery,
}

/// Treatment of queued or executing requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportPending {
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
}

/// Treatment of resolved requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportResolved {
    /// Completes the result.
    Complete,
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
}

/// Treatment of completed but undelivered requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportUndelivered {
    /// Delivers the existing result.
    Complete,
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
    /// Drops the completion.
    DropCompletion,
}

/// Decoded live block-transport reset transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockTransportReset {
    /// Epoch active after reset.
    pub next_epoch: u64,
    /// Exact virtual recovery duration.
    pub recovery_nanos: u64,
    /// Post-reset ID allocation.
    pub request_ids: BlockTransportRequestIds,
    /// Whether QEMU must re-enumerate the declared topology.
    pub reenumerate_declared: bool,
    /// Whether old duplicate identities remain suppressed.
    pub preserve_duplicate_history: bool,
    /// Typed failure used by failed request stages.
    pub failure_result: BlockResponseErrorCode,
    /// Admission treatment during recovery.
    pub unadmitted: BlockTransportUnadmitted,
    /// Queued request treatment.
    pub queued: BlockTransportPending,
    /// Executing request treatment.
    pub executing: BlockTransportPending,
    /// Resolved request treatment.
    pub resolved: BlockTransportResolved,
    /// Completed-undelivered request treatment.
    pub completed_undelivered: BlockTransportUndelivered,
    /// Whether the controller buffer survives.
    pub preserve_controller_buffer: bool,
    /// Whether the volatile cache survives.
    pub preserve_volatile_cache: bool,
}

impl BlockTransportReset {
    const PAYLOAD_LEN: usize = 32;

    fn encode(self) -> [u8; Self::PAYLOAD_LEN] {
        let mut payload = [0_u8; Self::PAYLOAD_LEN];
        payload[..8].copy_from_slice(&self.next_epoch.to_le_bytes());
        payload[8..16].copy_from_slice(&self.recovery_nanos.to_le_bytes());
        payload[16] = match self.request_ids {
            BlockTransportRequestIds::PreserveMonotonic => 0,
            BlockTransportRequestIds::NewEpochFromZero => 1,
        };
        payload[17] = u8::from(self.reenumerate_declared);
        payload[18] = u8::from(self.preserve_duplicate_history);
        payload[19] = self.failure_result.to_wire();
        payload[20] = match self.unadmitted {
            BlockTransportUnadmitted::Reject => 0,
            BlockTransportUnadmitted::WaitForRecovery => 1,
        };
        payload[21] = encode_transport_pending(self.queued);
        payload[22] = encode_transport_pending(self.executing);
        payload[23] = match self.resolved {
            BlockTransportResolved::Complete => 0,
            BlockTransportResolved::Fail => 1,
            BlockTransportResolved::RetryPreserveId => 2,
            BlockTransportResolved::RetryNewId => 3,
        };
        payload[24] = match self.completed_undelivered {
            BlockTransportUndelivered::Complete => 0,
            BlockTransportUndelivered::Fail => 1,
            BlockTransportUndelivered::RetryPreserveId => 2,
            BlockTransportUndelivered::RetryNewId => 3,
            BlockTransportUndelivered::DropCompletion => 4,
        };
        payload[25] = u8::from(self.preserve_controller_buffer);
        payload[26] = u8::from(self.preserve_volatile_cache);
        payload
    }

    fn decode(payload: &[u8]) -> Result<Self, BlockWireError> {
        if payload.len() != Self::PAYLOAD_LEN || payload[27..].iter().any(|byte| *byte != 0) {
            return Err(BlockWireError::InvalidResetPayload { len: payload.len() });
        }
        let request_ids = match payload[16] {
            0 => BlockTransportRequestIds::PreserveMonotonic,
            1 => BlockTransportRequestIds::NewEpochFromZero,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let reenumerate_declared = match payload[17] {
            0 => false,
            1 => true,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let preserve_duplicate_history = match payload[18] {
            0 => false,
            1 => true,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let failure_result = BlockResponseErrorCode::from_wire(payload[19])?;
        let unadmitted = match payload[20] {
            0 => BlockTransportUnadmitted::Reject,
            1 => BlockTransportUnadmitted::WaitForRecovery,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let queued = decode_transport_pending(payload[21], payload.len())?;
        let executing = decode_transport_pending(payload[22], payload.len())?;
        let resolved = match payload[23] {
            0 => BlockTransportResolved::Complete,
            1 => BlockTransportResolved::Fail,
            2 => BlockTransportResolved::RetryPreserveId,
            3 => BlockTransportResolved::RetryNewId,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let completed_undelivered = match payload[24] {
            0 => BlockTransportUndelivered::Complete,
            1 => BlockTransportUndelivered::Fail,
            2 => BlockTransportUndelivered::RetryPreserveId,
            3 => BlockTransportUndelivered::RetryNewId,
            4 => BlockTransportUndelivered::DropCompletion,
            _ => return Err(BlockWireError::InvalidResetPayload { len: payload.len() }),
        };
        let preserve_controller_buffer = decode_transport_bool(payload[25], payload.len())?;
        let preserve_volatile_cache = decode_transport_bool(payload[26], payload.len())?;
        let mut epoch = [0_u8; 8];
        epoch.copy_from_slice(&payload[..8]);
        let mut recovery = [0_u8; 8];
        recovery.copy_from_slice(&payload[8..16]);
        Ok(Self {
            next_epoch: u64::from_le_bytes(epoch),
            recovery_nanos: u64::from_le_bytes(recovery),
            request_ids,
            reenumerate_declared,
            preserve_duplicate_history,
            failure_result,
            unadmitted,
            queued,
            executing,
            resolved,
            completed_undelivered,
            preserve_controller_buffer,
            preserve_volatile_cache,
        })
    }
}

fn decode_transport_pending(byte: u8, len: usize) -> Result<BlockTransportPending, BlockWireError> {
    match byte {
        0 => Ok(BlockTransportPending::Fail),
        1 => Ok(BlockTransportPending::RetryPreserveId),
        2 => Ok(BlockTransportPending::RetryNewId),
        _ => Err(BlockWireError::InvalidResetPayload { len }),
    }
}

fn encode_transport_pending(policy: BlockTransportPending) -> u8 {
    match policy {
        BlockTransportPending::Fail => 0,
        BlockTransportPending::RetryPreserveId => 1,
        BlockTransportPending::RetryNewId => 2,
    }
}

fn decode_transport_bool(byte: u8, len: usize) -> Result<bool, BlockWireError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BlockWireError::InvalidResetPayload { len }),
    }
}

/// Closed protocol-neutral error result on the block shared-memory ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockResponseErrorCode {
    /// Device unavailable.
    Offline,
    /// Write to read-only storage.
    ReadOnly,
    /// Invalid addressed range.
    InvalidRange,
    /// Controller or queue busy.
    Busy,
    /// Modeled timeout.
    Timeout,
    /// Uncorrectable medium error.
    MediumError,
    /// Integrity verification error.
    IntegrityError,
    /// Generic I/O error.
    IoError,
    /// Capacity exhausted.
    NoSpace,
    /// Namespace or object absent.
    NotFound,
    /// Stale retained identity.
    Stale,
}

impl BlockResponseErrorCode {
    pub(super) const fn to_wire(self) -> u8 {
        match self {
            Self::Offline => 1,
            Self::ReadOnly => 2,
            Self::InvalidRange => 3,
            Self::Busy => 4,
            Self::Timeout => 5,
            Self::MediumError => 6,
            Self::IntegrityError => 7,
            Self::IoError => 8,
            Self::NoSpace => 9,
            Self::NotFound => 10,
            Self::Stale => 11,
        }
    }

    fn from_wire(code: u8) -> Result<Self, BlockWireError> {
        match code {
            1 => Ok(Self::Offline),
            2 => Ok(Self::ReadOnly),
            3 => Ok(Self::InvalidRange),
            4 => Ok(Self::Busy),
            5 => Ok(Self::Timeout),
            6 => Ok(Self::MediumError),
            7 => Ok(Self::IntegrityError),
            8 => Ok(Self::IoError),
            9 => Ok(Self::NoSpace),
            10 => Ok(Self::NotFound),
            11 => Ok(Self::Stale),
            other => Err(BlockWireError::UnknownErrorCode { code: other }),
        }
    }
}

impl BlockResponseStatus {
    const fn wire_status(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Error => 1,
            Self::TransportReset => 2,
            Self::DuplicateIgnored => 3,
            Self::DuplicateProtocolError => 4,
            Self::RetryPreserveId => 5,
            Self::RetryNewId => 6,
            Self::DropCompletion => 7,
        }
    }

    fn from_wire(status: u8) -> Result<Self, BlockWireError> {
        match status {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Error),
            2 => Ok(Self::TransportReset),
            3 => Ok(Self::DuplicateIgnored),
            4 => Ok(Self::DuplicateProtocolError),
            5 => Ok(Self::RetryPreserveId),
            6 => Ok(Self::RetryNewId),
            7 => Ok(Self::DropCompletion),
            other => Err(BlockWireError::UnknownStatus { status: other }),
        }
    }
}
