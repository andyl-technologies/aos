//! Block-device submit and poll callback core.
//!
//! The block callbacks route guest requests through the deterministic block
//! executor slot. Submit encodes the versioned block wire request into the
//! `(vm_slot -> SLOT_BLK_IO)` SPSC ring and starts the device-I/O time hold. Poll
//! peeks the `(SLOT_BLK_IO -> vm_slot)` ring, exposes a response only after its
//! delivery icount has been reached, and consumes the matching freeze token.

use std::cell::Cell;

use thiserror::Error;

use crucible_shmem::{
    DirectedRing, FrameDeliveryKey, FrameEntry, FrameEntryError, MAX_FRAME_DATA, NodeSlot,
    RingHeader, SLOT_BLK_IO, SpscRingError,
};

use crate::{
    DeviceIoFreezeError, DeviceIoRequestRelease, DeviceIoRequestToken, PluginDeviceIoFreeze,
    shmem_ordering::PluginShmemOrdering,
};

const BLOCK_IO_SLOT_U32: u32 = SLOT_BLK_IO as u32;
const BLOCK_WIRE_VERSION: u8 = 2;
const BLOCK_REQUEST_HEADER_LEN: usize = 20;
const BLOCK_RESPONSE_HEADER_LEN: usize = 12;

/// Registration-time-fixed block callback state.
#[derive(Debug)]
pub struct PluginBlockIo {
    vm_slot: u32,
    block_slot: u32,
    outbound_ring_index: u32,
    inbound_ring_index: u32,
    next_request_id: Cell<u32>,
}

impl PluginBlockIo {
    /// Builds block callback state from the directed rings selected at registration.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError::WrongOutboundRing`] or
    /// [`BlockIoError::WrongInboundRing`] when either ring is not the reserved
    /// block executor ring for `vm_slot`.
    pub fn from_directed_rings(
        vm_slot: u32,
        outbound_ring: DirectedRing,
        inbound_ring: DirectedRing,
    ) -> Result<Self, BlockIoError> {
        if outbound_ring.src_slot != vm_slot || outbound_ring.dst_slot != BLOCK_IO_SLOT_U32 {
            return Err(BlockIoError::WrongOutboundRing {
                expected_src_slot: vm_slot,
                expected_dst_slot: BLOCK_IO_SLOT_U32,
                expected_ring_index: None,
                actual_src_slot: outbound_ring.src_slot,
                actual_dst_slot: outbound_ring.dst_slot,
                actual_ring_index: outbound_ring.index,
            });
        }
        if inbound_ring.src_slot != BLOCK_IO_SLOT_U32 || inbound_ring.dst_slot != vm_slot {
            return Err(BlockIoError::WrongInboundRing {
                expected_src_slot: BLOCK_IO_SLOT_U32,
                expected_dst_slot: vm_slot,
                expected_ring_index: None,
                actual_src_slot: inbound_ring.src_slot,
                actual_dst_slot: inbound_ring.dst_slot,
                actual_ring_index: inbound_ring.index,
            });
        }

        Ok(Self::new(vm_slot, outbound_ring.index, inbound_ring.index))
    }

    /// Builds block callback state for the reserved block rings.
    #[must_use]
    pub const fn new(vm_slot: u32, outbound_ring_index: u32, inbound_ring_index: u32) -> Self {
        Self {
            vm_slot,
            block_slot: BLOCK_IO_SLOT_U32,
            outbound_ring_index,
            inbound_ring_index,
            next_request_id: Cell::new(0),
        }
    }

    /// Returns the VM slot whose block device this state serves.
    #[must_use]
    pub const fn vm_slot(&self) -> u32 {
        self.vm_slot
    }

    /// Returns the reserved block executor slot.
    #[must_use]
    pub const fn block_slot(&self) -> u32 {
        self.block_slot
    }

    /// Returns the outbound block ring index.
    #[must_use]
    pub const fn outbound_ring_index(&self) -> u32 {
        self.outbound_ring_index
    }

    /// Returns the inbound block ring index.
    #[must_use]
    pub const fn inbound_ring_index(&self) -> u32 {
        self.inbound_ring_index
    }

    /// Returns the request id that the next successful submit will assign.
    #[must_use]
    pub fn next_request_id(&self) -> u32 {
        self.next_request_id.get()
    }

    /// Submits one guest block request to the reserved block executor.
    ///
    /// The device-I/O hold is marked active before the frame is published to the
    /// SPSC ring. If enqueue fails, the request token is failed immediately so the
    /// pending counter cannot drift.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] when the ring does not match registration state,
    /// request encoding fails, the request id overflows, the device-I/O freeze
    /// state rejects the submit, or the outbound SPSC enqueue fails.
    pub fn submit_request(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        outbound_ring: &mut BlockOutboundRing<'_>,
        submit_icount: u64,
        request: &BlockRequest,
    ) -> Result<BlockSubmit, BlockIoError> {
        self.check_outbound_ring(outbound_ring)?;

        let request_id = self.next_request_id.get();
        let next_request_id = request_id
            .checked_add(1)
            .ok_or(BlockIoError::RequestIdOverflow { request_id })?;
        let payload = request.encode(request_id)?;
        let frame = FrameEntry::new(submit_icount, self.vm_slot, request_id, &payload)
            .map_err(|source| BlockIoError::Frame { source })?;
        let device_token = freeze
            .begin_independent_submit(slot, submit_icount)
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;

        if let Err(source) = PluginShmemOrdering::enqueue_outbound_frame(
            outbound_ring.header,
            outbound_ring.entries,
            &frame,
        ) {
            let release = freeze
                .fail_request(slot, device_token)
                .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;
            return Err(BlockIoError::RingEnqueueFailed {
                ring_index: self.outbound_ring_index,
                source,
                release,
            });
        }

        self.next_request_id.set(next_request_id);
        Ok(BlockSubmit {
            ring_index: self.outbound_ring_index,
            submit_icount,
            request_id,
            payload_len: payload.len(),
            token: BlockRequestToken {
                request_id,
                device_token,
            },
        })
    }

    /// Polls one block response and delivers it when its delivery icount is due.
    ///
    /// # Errors
    ///
    /// Returns [`BlockIoError`] when the inbound ring does not match registration
    /// state, the response frame is malformed, a due response does not match the
    /// request token, the SPSC dequeue fails, delivery to QEMU fails, or the
    /// device-I/O token cannot be completed.
    pub fn poll_response<D>(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        inbound_ring: &BlockInboundRing<'_>,
        deliver: &mut D,
        current_icount: u64,
        token: BlockRequestToken,
    ) -> Result<BlockPoll, BlockIoError>
    where
        D: BlockGuestCompletion + ?Sized,
    {
        self.check_inbound_ring(inbound_ring)?;
        let Some(head) = peek_head_frame(inbound_ring)? else {
            return Ok(BlockPoll::NotReady { token });
        };
        if head.delivery_icount > current_icount {
            return Ok(BlockPoll::NotReady { token });
        }

        if head.src_node != self.block_slot {
            let release = self.fail_polled_request(freeze, slot, token)?;
            return Err(BlockIoError::UnexpectedSource {
                expected_src_node: self.block_slot,
                actual_src_node: head.src_node,
                frame: head.delivery_key(),
                release,
            });
        }

        let payload = match head.payload() {
            Ok(payload) => payload,
            Err(source) => {
                let release = self.fail_polled_request(freeze, slot, token)?;
                return Err(BlockIoError::MalformedResponse {
                    ring_index: self.inbound_ring_index,
                    frame: head.delivery_key(),
                    source: BlockWireError::FramePayload { source },
                    release,
                });
            }
        };
        let response = match BlockResponse::decode(payload) {
            Ok(response) => response,
            Err(source) => {
                let release = self.fail_polled_request(freeze, slot, token)?;
                return Err(BlockIoError::MalformedResponse {
                    ring_index: self.inbound_ring_index,
                    frame: head.delivery_key(),
                    source,
                    release,
                });
            }
        };
        if response.request_id() != token.request_id {
            let expected_request_id = token.request_id;
            let release = self.fail_polled_request(freeze, slot, token)?;
            return Err(BlockIoError::UnexpectedResponse {
                expected_request_id,
                actual_request_id: response.request_id(),
                frame: head.delivery_key(),
                release,
            });
        }

        let release = freeze
            .complete_request(slot, token.device_token)
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })?;

        let Some(dequeued) =
            PluginShmemOrdering::dequeue_inbound_frame(inbound_ring.header, inbound_ring.entries)
                .map_err(|source| BlockIoError::RingDequeue {
                ring_index: self.inbound_ring_index,
                source,
            })?
        else {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: head.delivery_key(),
                actual: None,
            });
        };
        if dequeued.delivery_key() != head.delivery_key() {
            return Err(BlockIoError::DequeuedUnexpectedFrame {
                ring_index: self.inbound_ring_index,
                expected: head.delivery_key(),
                actual: Some(dequeued.delivery_key()),
            });
        }

        deliver
            .complete_block_response(&response)
            .map_err(|source| BlockIoError::GuestCompletion {
                request_id: response.request_id(),
                release,
                source,
            })?;
        Ok(BlockPoll::Completed { response, release })
    }

    fn fail_polled_request(
        &self,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        token: BlockRequestToken,
    ) -> Result<DeviceIoRequestRelease, BlockIoError> {
        freeze
            .fail_request(slot, token.device_token)
            .map_err(|source| BlockIoError::DeviceIoFreeze { source })
    }

    fn check_outbound_ring(&self, ring: &BlockOutboundRing<'_>) -> Result<(), BlockIoError> {
        if ring.ring_index != self.outbound_ring_index
            || ring.src_slot != self.vm_slot
            || ring.dst_slot != self.block_slot
        {
            Err(BlockIoError::WrongOutboundRing {
                expected_src_slot: self.vm_slot,
                expected_dst_slot: self.block_slot,
                expected_ring_index: Some(self.outbound_ring_index),
                actual_src_slot: ring.src_slot,
                actual_dst_slot: ring.dst_slot,
                actual_ring_index: ring.ring_index,
            })
        } else {
            Ok(())
        }
    }

    fn check_inbound_ring(&self, ring: &BlockInboundRing<'_>) -> Result<(), BlockIoError> {
        if ring.ring_index != self.inbound_ring_index
            || ring.src_slot != self.block_slot
            || ring.dst_slot != self.vm_slot
        {
            Err(BlockIoError::WrongInboundRing {
                expected_src_slot: self.block_slot,
                expected_dst_slot: self.vm_slot,
                expected_ring_index: Some(self.inbound_ring_index),
                actual_src_slot: ring.src_slot,
                actual_dst_slot: ring.dst_slot,
                actual_ring_index: ring.ring_index,
            })
        } else {
            Ok(())
        }
    }
}

/// Handles one safe block submit callback body.
///
/// # Errors
///
/// Returns [`BlockIoError`] when submit validation, freeze state, or ring enqueue
/// fails.
pub fn handle_block_submit_callback(
    block_io: &PluginBlockIo,
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    outbound_ring: &mut BlockOutboundRing<'_>,
    submit_icount: u64,
    request: &BlockRequest,
) -> Result<BlockSubmit, BlockIoError> {
    block_io.submit_request(freeze, slot, outbound_ring, submit_icount, request)
}

/// Handles one safe block poll callback body.
///
/// # Errors
///
/// Returns [`BlockIoError`] when ring validation, response decoding, delivery, or
/// freeze-token completion fails.
pub fn handle_block_poll_callback<D>(
    block_io: &PluginBlockIo,
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    inbound_ring: &BlockInboundRing<'_>,
    deliver: &mut D,
    current_icount: u64,
    token: BlockRequestToken,
) -> Result<BlockPoll, BlockIoError>
where
    D: BlockGuestCompletion + ?Sized,
{
    block_io.poll_response(freeze, slot, inbound_ring, deliver, current_icount, token)
}

/// A mutable view of the outbound block executor ring.
pub struct BlockOutboundRing<'a> {
    ring_index: u32,
    src_slot: u32,
    dst_slot: u32,
    header: &'a RingHeader,
    entries: &'a mut [FrameEntry],
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
    ring_index: u32,
    src_slot: u32,
    dst_slot: u32,
    header: &'a RingHeader,
    entries: &'a [FrameEntry],
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
}

impl BlockOperation {
    const fn wire_type(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Flush => 2,
            Self::GetLength => 3,
        }
    }

    fn from_wire(operation: u8) -> Result<Self, BlockWireError> {
        match operation {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Flush),
            3 => Ok(Self::GetLength),
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
    pub fn encode(&self, request_id: u32) -> Result<Vec<u8>, BlockWireError> {
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
        out.extend_from_slice(&request_id.to_le_bytes());
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
    pub fn decode(payload: &[u8]) -> Result<(u32, Self), BlockWireError> {
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
        let request_id = u32::from_le_bytes(
            payload[4..8]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let offset = u64::from_le_bytes(
            payload[8..16]
                .try_into()
                .map_err(|_| BlockWireError::ShortRequest { len: payload.len() })?,
        );
        let count = u32::from_le_bytes(
            payload[16..20]
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
                    request_id,
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
                request_id,
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
    request_id: u32,
    payload: Vec<u8>,
}

impl BlockResponse {
    /// Builds a response for tests and callback adapters.
    #[must_use]
    pub fn new(status: BlockResponseStatus, request_id: u32, payload: Vec<u8>) -> Self {
        Self {
            status,
            request_id,
            payload,
        }
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
        if self.status != BlockResponseStatus::Error || self.payload.len() != 1 {
            return Err(BlockWireError::InvalidErrorPayload {
                status: self.status.wire_status(),
                len: self.payload.len(),
            });
        }
        BlockResponseErrorCode::from_wire(self.payload[0])
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
        let request_id = u32::from_le_bytes(
            payload[4..8]
                .try_into()
                .map_err(|_| BlockWireError::ShortResponse { len: payload.len() })?,
        );
        let count = u32::from_le_bytes(
            payload[8..12]
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
            request_id,
            payload: payload[BLOCK_RESPONSE_HEADER_LEN..BLOCK_RESPONSE_HEADER_LEN + count_usize]
                .to_vec(),
        };
        if status == BlockResponseStatus::Error {
            response.error_code()?;
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
        }
    }

    fn from_wire(status: u8) -> Result<Self, BlockWireError> {
        match status {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Error),
            other => Err(BlockWireError::UnknownStatus { status: other }),
        }
    }
}

/// A request token that must be consumed by poll completion or failure handling.
#[must_use = "block request tokens must be consumed by block poll completion or failure"]
#[derive(Debug, PartialEq, Eq)]
pub struct BlockRequestToken {
    request_id: u32,
    device_token: DeviceIoRequestToken,
}

impl BlockRequestToken {
    /// Returns the block wire request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// Returns the submit icount carried by the device-I/O token.
    #[must_use]
    pub const fn submit_icount(&self) -> u64 {
        self.device_token.submit_icount()
    }
}

/// Metadata returned after one successful block submit.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockSubmit {
    ring_index: u32,
    submit_icount: u64,
    request_id: u32,
    payload_len: usize,
    token: BlockRequestToken,
}

impl BlockSubmit {
    /// Returns the outbound ring index.
    #[must_use]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    /// Returns the submit icount stamped onto the frame.
    #[must_use]
    pub const fn submit_icount(&self) -> u64 {
        self.submit_icount
    }

    /// Returns the assigned request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// Returns the encoded wire payload length.
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Consumes this submit metadata and returns the completion token.
    pub fn into_token(self) -> BlockRequestToken {
        self.token
    }
}

/// The result of one block poll callback.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockPoll {
    /// No matching response is ready; the token is returned to the caller.
    NotReady {
        /// The still-pending request token.
        token: BlockRequestToken,
    },
    /// A due response was delivered and the freeze token was released.
    Completed {
        /// The decoded response delivered to the guest.
        response: BlockResponse,
        /// Device-I/O release metadata.
        release: DeviceIoRequestRelease,
    },
}

/// A safe adapter for delivering a decoded response to QEMU's block device path.
pub trait BlockGuestCompletion {
    /// Completes one guest block request.
    ///
    /// # Errors
    ///
    /// Returns [`BlockGuestCompletionError`] when the QEMU-facing completion path
    /// cannot expose the response and must fail loudly.
    fn complete_block_response(
        &mut self,
        response: &BlockResponse,
    ) -> Result<(), BlockGuestCompletionError>;
}

/// A loud guest-completion failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("block guest completion failed: {message}")]
pub struct BlockGuestCompletionError {
    message: String,
}

impl BlockGuestCompletionError {
    /// Builds a guest-completion error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An error produced by block callback handling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BlockIoError {
    /// The callback was handed a ring other than the fixed outbound block ring.
    #[error(
        "block outbound ring mismatch: expected src={expected_src_slot} dst={expected_dst_slot} ring={expected_ring_index:?}, got src={actual_src_slot} dst={actual_dst_slot} ring={actual_ring_index}"
    )]
    WrongOutboundRing {
        /// The VM slot fixed at registration.
        expected_src_slot: u32,
        /// The block executor slot fixed at registration.
        expected_dst_slot: u32,
        /// The outbound ring index fixed at registration, if known.
        expected_ring_index: Option<u32>,
        /// The supplied ring's producer slot.
        actual_src_slot: u32,
        /// The supplied ring's consumer slot.
        actual_dst_slot: u32,
        /// The supplied ring's index.
        actual_ring_index: u32,
    },
    /// The callback was handed a ring other than the fixed inbound block ring.
    #[error(
        "block inbound ring mismatch: expected src={expected_src_slot} dst={expected_dst_slot} ring={expected_ring_index:?}, got src={actual_src_slot} dst={actual_dst_slot} ring={actual_ring_index}"
    )]
    WrongInboundRing {
        /// The block executor slot fixed at registration.
        expected_src_slot: u32,
        /// The VM slot fixed at registration.
        expected_dst_slot: u32,
        /// The inbound ring index fixed at registration, if known.
        expected_ring_index: Option<u32>,
        /// The supplied ring's producer slot.
        actual_src_slot: u32,
        /// The supplied ring's consumer slot.
        actual_dst_slot: u32,
        /// The supplied ring's index.
        actual_ring_index: u32,
    },
    /// The request id counter cannot represent another request.
    #[error("block request id overflow at {request_id}")]
    RequestIdOverflow {
        /// The exhausted request id.
        request_id: u32,
    },
    /// Block wire encoding or decoding failed.
    #[error("block wire error: {source}")]
    Wire {
        /// The wire-format error.
        source: BlockWireError,
    },
    /// Constructing a shared-memory frame failed.
    #[error("block frame construction failed: {source}")]
    Frame {
        /// The frame construction error.
        source: FrameEntryError,
    },
    /// Device-I/O freeze state rejected a transition.
    #[error("block device-I/O freeze failed: {source}")]
    DeviceIoFreeze {
        /// The device-I/O freeze error.
        source: DeviceIoFreezeError,
    },
    /// The outbound request enqueue failed after the freeze token was created.
    #[error("block ring {ring_index} enqueue failed after freeze submit: {source}")]
    RingEnqueueFailed {
        /// The outbound ring index.
        ring_index: u32,
        /// The enqueue failure.
        source: SpscRingError,
        /// The release created by failing the just-created freeze token.
        release: DeviceIoRequestRelease,
    },
    /// The inbound ring operation failed.
    #[error("block ring {ring_index} dequeue failed: {source}")]
    RingDequeue {
        /// The inbound ring index.
        ring_index: u32,
        /// The dequeue failure.
        source: SpscRingError,
    },
    /// The inbound ring head could not be decoded as a block response.
    #[error("block ring {ring_index} malformed response at {frame:?}: {source}")]
    MalformedResponse {
        /// The inbound ring index.
        ring_index: u32,
        /// The frame key used to localize the malformed response.
        frame: FrameDeliveryKey,
        /// The decode error.
        source: BlockWireError,
        /// The request release created by failing the pending token.
        release: DeviceIoRequestRelease,
    },
    /// The due response frame was not produced by the reserved block executor.
    #[error(
        "block response source node {actual_src_node} does not match reserved block source {expected_src_node}"
    )]
    UnexpectedSource {
        /// The reserved block executor slot.
        expected_src_node: u32,
        /// The frame's advertised producer node.
        actual_src_node: u32,
        /// The response frame key.
        frame: FrameDeliveryKey,
        /// The request release created by failing the pending token.
        release: DeviceIoRequestRelease,
    },
    /// The due response did not match the request token being polled.
    #[error(
        "block response request id {actual_request_id} does not match token {expected_request_id}"
    )]
    UnexpectedResponse {
        /// The token's request id.
        expected_request_id: u32,
        /// The response request id.
        actual_request_id: u32,
        /// The response frame key.
        frame: FrameDeliveryKey,
        /// The request release created by failing the pending token.
        release: DeviceIoRequestRelease,
    },
    /// The dequeued response did not match the previously peeked head.
    #[error("block ring {ring_index} dequeued {actual:?} after peeking {expected:?}")]
    DequeuedUnexpectedFrame {
        /// The inbound ring index.
        ring_index: u32,
        /// The previewed frame key.
        expected: FrameDeliveryKey,
        /// The dequeued frame key, if any.
        actual: Option<FrameDeliveryKey>,
    },
    /// Delivering the decoded response to the guest failed.
    #[error("block request {request_id} guest completion failed: {source}")]
    GuestCompletion {
        /// The request id being completed.
        request_id: u32,
        /// The request release created before attempting guest completion.
        release: DeviceIoRequestRelease,
        /// The guest completion error.
        source: BlockGuestCompletionError,
    },
}

/// A block wire-format error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BlockWireError {
    /// A payload length cannot fit in a wire count.
    #[error("block payload length {len} cannot fit in u32")]
    PayloadLengthOverflow {
        /// The unrepresentable payload length.
        len: usize,
    },
    /// Request count did not match the write payload length.
    #[error("block request count {count} does not match payload length {payload_len}")]
    CountPayloadMismatch {
        /// The encoded count.
        count: u32,
        /// The actual payload length.
        payload_len: usize,
    },
    /// A non-write request carried a payload.
    #[error("block {operation:?} request unexpectedly carried {payload_len} payload bytes")]
    UnexpectedPayload {
        /// The operation that cannot carry request payload bytes.
        operation: BlockOperation,
        /// The unexpected payload length.
        payload_len: usize,
    },
    /// A frame payload length was invalid.
    #[error("block frame payload error: {source}")]
    FramePayload {
        /// The frame payload error.
        source: FrameEntryError,
    },
    /// Request is shorter than the fixed header.
    #[error("block request length {len} is shorter than header")]
    ShortRequest {
        /// The observed payload length.
        len: usize,
    },
    /// Request operation is unknown.
    #[error("block request operation {operation} is unknown")]
    UnknownOperation {
        /// The unknown operation byte.
        operation: u8,
    },
    /// Response is shorter than the fixed header.
    #[error("block response length {len} is shorter than header")]
    ShortResponse {
        /// The observed payload length.
        len: usize,
    },
    /// Block wire version is unsupported.
    #[error("block wire version {version} is unsupported")]
    UnsupportedVersion {
        /// The unsupported version byte.
        version: u8,
    },
    /// Block wire reserved header bits were nonzero.
    #[error("block wire reserved field {reserved} is nonzero")]
    NonZeroReserved {
        /// The decoded reserved field.
        reserved: u16,
    },
    /// Response status is unknown.
    #[error("block response status {status} is unknown")]
    UnknownStatus {
        /// The unknown status byte.
        status: u8,
    },
    /// Typed response error code is unknown.
    #[error("block response error code {code} is unknown")]
    UnknownErrorCode {
        /// The undefined typed-result byte.
        code: u8,
    },
    /// An error response does not carry exactly one typed-result byte.
    #[error("invalid block error payload for status {status}: length {len}")]
    InvalidErrorPayload {
        /// Response status wire byte.
        status: u8,
        /// Actual payload length.
        len: usize,
    },
    /// Response count cannot be represented locally.
    #[error("block response count {count} cannot fit in usize")]
    CountLengthOverflow {
        /// The unrepresentable wire count.
        count: u32,
    },
    /// Request count exceeds the available payload bytes.
    #[error("block request count {count} exceeds available payload {available}")]
    RequestCountExceedsPayload {
        /// The declared request byte count.
        count: u32,
        /// The available payload bytes after the header.
        available: usize,
    },
    /// Request count did not exactly match the write payload length.
    #[error("block request count {count} does not match payload length {payload_len}")]
    RequestCountPayloadMismatch {
        /// The declared request byte count.
        count: u32,
        /// The actual payload length after the header.
        payload_len: usize,
    },
    /// Response count exceeds the available payload bytes.
    #[error("block response count {count} exceeds available payload {available}")]
    CountExceedsPayload {
        /// The declared response byte count.
        count: u32,
        /// The available payload bytes after the header.
        available: usize,
    },
    /// Response count did not exactly match the payload length.
    #[error("block response count {count} does not match payload length {payload_len}")]
    ResponseCountPayloadMismatch {
        /// The declared response byte count.
        count: u32,
        /// The actual payload length after the header.
        payload_len: usize,
    },
}

impl From<BlockWireError> for BlockIoError {
    fn from(source: BlockWireError) -> Self {
        Self::Wire { source }
    }
}

fn peek_head_frame(ring: &BlockInboundRing<'_>) -> Result<Option<FrameEntry>, BlockIoError> {
    let Some(delivery_icount) =
        PluginShmemOrdering::peek_inbound_delivery_icount(ring.header, ring.entries).map_err(
            |source| BlockIoError::RingDequeue {
                ring_index: ring.ring_index,
                source,
            },
        )?
    else {
        return Ok(None);
    };
    let slot = (PluginShmemOrdering::consumer_read_index(ring.header)
        & (ring.entries.len() as u64 - 1)) as usize;
    let frame = ring.entries[slot].clone();
    if frame.delivery_icount != delivery_icount {
        return Err(BlockIoError::DequeuedUnexpectedFrame {
            ring_index: ring.ring_index,
            expected: FrameDeliveryKey {
                delivery_icount,
                src_node: frame.src_node,
                seq: frame.seq,
            },
            actual: Some(frame.delivery_key()),
        });
    }
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crucible_shmem::{KIND_VM, RegionConfig, RegionLayout, ReservedExecutorSlot};

    #[test]
    fn block_io_state_binds_reserved_block_rings() {
        let layout = layout();
        let (outbound, inbound) = block_rings(layout, 1);
        let block = match PluginBlockIo::from_directed_rings(1, outbound, inbound) {
            Ok(block) => block,
            Err(error) => panic!("block rings should bind: {error}"),
        };

        assert_eq!(block.vm_slot(), 1);
        assert_eq!(block.block_slot(), BLOCK_IO_SLOT_U32);
        assert_eq!(block.outbound_ring_index(), outbound.index);
        assert_eq!(block.inbound_ring_index(), inbound.index);

        let wrong = DirectedRing {
            index: outbound.index,
            src_slot: 1,
            dst_slot: ReservedExecutorSlot::NetRouter.slot() as u32,
        };
        assert_eq!(
            match PluginBlockIo::from_directed_rings(1, wrong, inbound) {
                Ok(_) => panic!("wrong block outbound ring should be rejected"),
                Err(error) => error,
            },
            BlockIoError::WrongOutboundRing {
                expected_src_slot: 1,
                expected_dst_slot: BLOCK_IO_SLOT_U32,
                expected_ring_index: None,
                actual_src_slot: 1,
                actual_dst_slot: ReservedExecutorSlot::NetRouter.slot() as u32,
                actual_ring_index: outbound.index,
            }
        );
    }

    #[test]
    fn block_submit_encodes_request_stamps_icount_and_freezes_time() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let mut ring = outbound_ring(8, 2, &header, &mut entries);
        let request = match BlockRequest::write(4096, b"data".to_vec()) {
            Ok(request) => request,
            Err(error) => panic!("write request should build: {error}"),
        };

        let submit =
            match handle_block_submit_callback(&block, &mut freeze, &slot, &mut ring, 77, &request)
            {
                Ok(submit) => submit,
                Err(error) => panic!("block submit should enqueue: {error}"),
            };

        assert_eq!(submit.ring_index(), 8);
        assert_eq!(submit.submit_icount(), 77);
        assert_eq!(submit.request_id(), 0);
        assert_eq!(submit.payload_len(), BLOCK_REQUEST_HEADER_LEN + 4);
        assert_eq!(block.next_request_id(), 1);
        assert_eq!(freeze.pending_requests(), 1);
        assert_eq!(slot.snapshot().device_io_active, 1);
        assert_eq!(header.write_index(), 1);
        assert_frame(&ring.entries[0], 77, 2, 0);
        assert_eq!(
            ring.entries[0].payload(),
            Ok(&[
                1, 2, 0, 0, // type/version/reserved
                0, 0, 0, 0, // request_id
                0, 0x10, 0, 0, 0, 0, 0, 0, // offset
                4, 0, 0, 0, // count
                b'd', b'a', b't', b'a',
            ][..])
        );
    }

    #[test]
    fn block_submit_wrong_ring_does_not_freeze_or_enqueue() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let mut ring = BlockOutboundRing::new(10, 2, BLOCK_IO_SLOT_U32, &header, &mut entries);

        assert_eq!(
            block.submit_request(
                &mut freeze,
                &slot,
                &mut ring,
                77,
                &BlockRequest::read(0, 512)
            ),
            Err(BlockIoError::WrongOutboundRing {
                expected_src_slot: 2,
                expected_dst_slot: BLOCK_IO_SLOT_U32,
                expected_ring_index: Some(8),
                actual_src_slot: 2,
                actual_dst_slot: BLOCK_IO_SLOT_U32,
                actual_ring_index: 10,
            })
        );
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
        assert_eq!(header.write_index(), 0);
    }

    #[test]
    fn block_submit_rejects_oversized_write_before_copying_payload() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let header = RingHeader::new();
        let mut entries = empty_entries(4);
        let mut ring = outbound_ring(8, 2, &header, &mut entries);
        let request = match BlockRequest::write(4096, vec![0xa5; MAX_FRAME_DATA]) {
            Ok(request) => request,
            Err(error) => {
                panic!("write request should build before frame-size validation: {error}")
            }
        };

        assert_eq!(
            block.submit_request(&mut freeze, &slot, &mut ring, 77, &request),
            Err(BlockIoError::Wire {
                source: BlockWireError::FramePayload {
                    source: FrameEntryError::PayloadLengthExceedsCapacity {
                        len: BLOCK_REQUEST_HEADER_LEN + MAX_FRAME_DATA,
                        capacity: MAX_FRAME_DATA,
                    },
                },
            })
        );
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
        assert_eq!(block.next_request_id(), 0);
        assert_eq!(header.write_index(), 0);
    }

    #[test]
    fn block_submit_full_ring_releases_freeze_token_loudly() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let header = RingHeader::new();
        let mut entries = empty_entries(1);
        enqueue(&header, &mut entries, frame(70, 2, 99, b"occupied"));
        let mut ring = outbound_ring(8, 2, &header, &mut entries);

        let error = match block.submit_request(
            &mut freeze,
            &slot,
            &mut ring,
            77,
            &BlockRequest::read(0, 512),
        ) {
            Ok(_) => panic!("full block ring should fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            BlockIoError::RingEnqueueFailed {
                source: SpscRingError::QueueFull { capacity: 1 },
                ..
            }
        ));
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
        assert_eq!(block.next_request_id(), 0);
    }

    #[test]
    fn block_poll_returns_not_ready_until_delivery_icount_is_reached() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let outbound_header = RingHeader::new();
        let mut outbound_entries = empty_entries(4);
        let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
        let submit = submit_read(&block, &mut freeze, &slot, &mut outbound, 77);
        let token = submit.into_token();
        let inbound_header = RingHeader::new();
        let mut inbound_entries = empty_entries(4);
        enqueue(
            &inbound_header,
            &mut inbound_entries,
            response_frame(90, 0, b"abcd"),
        );
        let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
        let mut completion = RecordingCompletion::default();

        let token =
            match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 89, token) {
                Ok(BlockPoll::NotReady { token }) => token,
                other => panic!("future response should not be ready: {other:?}"),
            };

        assert_eq!(inbound_header.read_index(), 0);
        assert_eq!(freeze.pending_requests(), 1);
        assert!(completion.responses.is_empty());

        let poll =
            match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token) {
                Ok(poll) => poll,
                Err(error) => panic!("due block response should complete: {error}"),
            };

        let BlockPoll::Completed { response, release } = poll else {
            panic!("due response should complete");
        };
        assert_eq!(response.payload(), b"abcd");
        assert_eq!(release.pending_requests(), 0);
        assert!(!release.device_io_active());
        assert_eq!(inbound_header.read_index(), 1);
        assert_eq!(completion.responses, vec![response]);
        assert_eq!(slot.snapshot().device_io_active, 0);
    }

    #[test]
    fn block_poll_rejects_wrong_request_id_and_releases_freeze_token() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let outbound_header = RingHeader::new();
        let mut outbound_entries = empty_entries(4);
        let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
        let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 77).into_token();
        let inbound_header = RingHeader::new();
        let mut inbound_entries = empty_entries(4);
        enqueue(
            &inbound_header,
            &mut inbound_entries,
            response_frame(90, 1, b"wrong"),
        );
        let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
        let mut completion = RecordingCompletion::default();

        let error =
            match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token) {
                Ok(_) => panic!("wrong request id should fail"),
                Err(error) => error,
            };
        match error {
            BlockIoError::UnexpectedResponse {
                expected_request_id: 0,
                actual_request_id: 1,
                frame,
                release,
            } => {
                assert_eq!(frame, response_frame(90, 1, b"wrong").delivery_key());
                assert_eq!(release.pending_requests(), 0);
                assert_eq!(release.outcome(), crate::DeviceIoRequestOutcome::Failed);
            }
            other => panic!("wrong request id should be unexpected response: {other:?}"),
        }
        assert_eq!(inbound_header.read_index(), 0);
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
        assert!(completion.responses.is_empty());
    }

    #[test]
    fn block_poll_rejects_wrong_response_source_and_releases_freeze_token() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let outbound_header = RingHeader::new();
        let mut outbound_entries = empty_entries(4);
        let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
        let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 77).into_token();
        let inbound_header = RingHeader::new();
        let mut inbound_entries = empty_entries(4);
        let malformed_source = frame(90, 99, 0, &encoded_response(0, b"bad-source"));
        enqueue(
            &inbound_header,
            &mut inbound_entries,
            malformed_source.clone(),
        );
        let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
        let mut completion = RecordingCompletion::default();

        let error =
            match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token) {
                Ok(_) => panic!("wrong response source should fail"),
                Err(error) => error,
            };
        match error {
            BlockIoError::UnexpectedSource {
                expected_src_node: BLOCK_IO_SLOT_U32,
                actual_src_node: 99,
                frame,
                release,
            } => {
                assert_eq!(frame, malformed_source.delivery_key());
                assert_eq!(release.pending_requests(), 0);
                assert_eq!(release.outcome(), crate::DeviceIoRequestOutcome::Failed);
            }
            other => panic!("wrong response source should be unexpected source: {other:?}"),
        }
        assert_eq!(inbound_header.read_index(), 0);
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
        assert!(completion.responses.is_empty());
    }

    #[test]
    fn block_poll_guest_completion_failure_still_releases_freeze_token() {
        let slot = NodeSlot::new(KIND_VM);
        let mut freeze = PluginDeviceIoFreeze::new();
        let block = PluginBlockIo::new(2, 8, 9);
        let outbound_header = RingHeader::new();
        let mut outbound_entries = empty_entries(4);
        let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
        let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 77).into_token();
        let inbound_header = RingHeader::new();
        let mut inbound_entries = empty_entries(4);
        enqueue(
            &inbound_header,
            &mut inbound_entries,
            response_frame(90, 0, b"abcd"),
        );
        let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
        let mut completion = RecordingCompletion {
            fail_message: Some("guest completion failure"),
            ..RecordingCompletion::default()
        };

        let error =
            match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token) {
                Ok(_) => panic!("guest completion failure should be returned"),
                Err(error) => error,
            };
        match error {
            BlockIoError::GuestCompletion {
                request_id: 0,
                release,
                source,
            } => {
                assert_eq!(release.pending_requests(), 0);
                assert_eq!(release.outcome(), crate::DeviceIoRequestOutcome::Completed);
                assert_eq!(
                    source,
                    BlockGuestCompletionError::new("guest completion failure")
                );
            }
            other => panic!("guest failure should be guest completion error: {other:?}"),
        }
        assert_eq!(inbound_header.read_index(), 1);
        assert_eq!(freeze.pending_requests(), 0);
        assert_eq!(slot.snapshot().device_io_active, 0);
        assert!(completion.responses.is_empty());
    }

    #[test]
    fn block_response_decode_rejects_nonzero_reserved_and_trailing_payload() {
        let mut reserved = encoded_response(7, b"ok");
        reserved[2] = 1;
        assert_eq!(
            BlockResponse::decode(&reserved),
            Err(BlockWireError::NonZeroReserved { reserved: 1 })
        );

        let mut trailing = encoded_response(7, b"ok");
        trailing.push(b'!');
        assert_eq!(
            BlockResponse::decode(&trailing),
            Err(BlockWireError::ResponseCountPayloadMismatch {
                count: 2,
                payload_len: 3,
            })
        );
    }

    #[test]
    fn block_request_decode_rejects_nonzero_reserved_and_trailing_payload() {
        let Ok(mut reserved) = BlockRequest::read(4096, 512).encode(7) else {
            panic!("read request should encode");
        };
        reserved[2] = 1;
        assert_eq!(
            BlockRequest::decode(&reserved),
            Err(BlockWireError::NonZeroReserved { reserved: 1 })
        );

        let Ok(mut trailing) = BlockRequest::read(4096, 512).encode(7) else {
            panic!("read request should encode");
        };
        trailing.push(b'!');
        assert_eq!(
            BlockRequest::decode(&trailing),
            Err(BlockWireError::UnexpectedPayload {
                operation: BlockOperation::Read,
                payload_len: 1,
            })
        );
    }

    #[test]
    fn block_response_frames_are_stamped_by_reserved_block_slot_and_delivery_icount() {
        let frame = response_frame(123, 9, b"block");

        assert_frame(&frame, 123, BLOCK_IO_SLOT_U32, 9);
        assert!(frame.is_deliverable_at(123));
        assert!(!frame.is_deliverable_at(122));
        assert_eq!(
            frame.payload(),
            Ok(&[
                0, 2, 0, 0, // status/version/reserved
                9, 0, 0, 0, // request_id
                5, 0, 0, 0, // count
                b'b', b'l', b'o', b'c', b'k',
            ][..])
        );
    }

    #[test]
    fn block_response_typed_errors_are_closed_and_exact() {
        let cases = [
            (1, BlockResponseErrorCode::Offline),
            (2, BlockResponseErrorCode::ReadOnly),
            (3, BlockResponseErrorCode::InvalidRange),
            (4, BlockResponseErrorCode::Busy),
            (5, BlockResponseErrorCode::Timeout),
            (6, BlockResponseErrorCode::MediumError),
            (7, BlockResponseErrorCode::IntegrityError),
            (8, BlockResponseErrorCode::IoError),
            (9, BlockResponseErrorCode::NoSpace),
            (10, BlockResponseErrorCode::NotFound),
            (11, BlockResponseErrorCode::Stale),
        ];
        for (wire, expected) in cases {
            let response = BlockResponse::new(BlockResponseStatus::Error, 7, vec![wire]);
            let decoded = BlockResponse::decode(
                &response
                    .encode()
                    .unwrap_or_else(|error| panic!("typed error should encode: {error}")),
            )
            .unwrap_or_else(|error| panic!("typed error should decode: {error}"));
            assert_eq!(
                decoded
                    .error_code()
                    .unwrap_or_else(|error| panic!("typed error should validate: {error}")),
                expected
            );
        }

        for payload in [Vec::new(), vec![0], vec![1, 2]] {
            let response = BlockResponse::new(BlockResponseStatus::Error, 7, payload);
            assert!(
                BlockResponse::decode(
                    &response.encode().unwrap_or_else(|error| panic!(
                        "malformed response should encode: {error}"
                    ))
                )
                .is_err()
            );
        }
    }

    #[derive(Default)]
    struct RecordingCompletion {
        responses: Vec<BlockResponse>,
        fail_message: Option<&'static str>,
    }

    impl BlockGuestCompletion for RecordingCompletion {
        fn complete_block_response(
            &mut self,
            response: &BlockResponse,
        ) -> Result<(), BlockGuestCompletionError> {
            if let Some(message) = self.fail_message {
                return Err(BlockGuestCompletionError::new(message));
            }
            self.responses.push(response.clone());
            Ok(())
        }
    }

    fn layout() -> RegionLayout {
        match RegionLayout::for_config(RegionConfig::new(2, 4, 0)) {
            Ok(layout) => layout,
            Err(error) => panic!("layout should be valid: {error}"),
        }
    }

    fn block_rings(layout: RegionLayout, vm_slot: u32) -> (DirectedRing, DirectedRing) {
        let rings_per_vm = ReservedExecutorSlot::all().len() as u32 * 2;
        let index = vm_slot * rings_per_vm + 2;
        assert!(index + 1 < layout.ring_count);
        (
            DirectedRing {
                index,
                src_slot: vm_slot,
                dst_slot: BLOCK_IO_SLOT_U32,
            },
            DirectedRing {
                index: index + 1,
                src_slot: BLOCK_IO_SLOT_U32,
                dst_slot: vm_slot,
            },
        )
    }

    fn empty_entries(capacity: usize) -> Vec<FrameEntry> {
        vec![FrameEntry::default(); capacity]
    }

    fn outbound_ring<'a>(
        ring_index: u32,
        vm_slot: u32,
        header: &'a RingHeader,
        entries: &'a mut [FrameEntry],
    ) -> BlockOutboundRing<'a> {
        BlockOutboundRing::new(ring_index, vm_slot, BLOCK_IO_SLOT_U32, header, entries)
    }

    fn inbound_ring<'a>(
        ring_index: u32,
        vm_slot: u32,
        header: &'a RingHeader,
        entries: &'a [FrameEntry],
    ) -> BlockInboundRing<'a> {
        BlockInboundRing::new(ring_index, BLOCK_IO_SLOT_U32, vm_slot, header, entries)
    }

    fn submit_read(
        block: &PluginBlockIo,
        freeze: &mut PluginDeviceIoFreeze,
        slot: &NodeSlot,
        outbound: &mut BlockOutboundRing<'_>,
        submit_icount: u64,
    ) -> BlockSubmit {
        match block.submit_request(
            freeze,
            slot,
            outbound,
            submit_icount,
            &BlockRequest::read(0, 4),
        ) {
            Ok(submit) => submit,
            Err(error) => panic!("read submit should succeed: {error}"),
        }
    }

    fn response_frame(delivery_icount: u64, request_id: u32, payload: &[u8]) -> FrameEntry {
        let encoded = encoded_response(request_id, payload);
        frame(delivery_icount, BLOCK_IO_SLOT_U32, request_id, &encoded)
    }

    fn encoded_response(request_id: u32, payload: &[u8]) -> Vec<u8> {
        let response = BlockResponse::new(BlockResponseStatus::Ok, request_id, payload.to_vec());
        match response.encode() {
            Ok(encoded) => encoded,
            Err(error) => panic!("response should encode: {error}"),
        }
    }

    fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
        match FrameEntry::new(delivery_icount, src_node, seq, payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should construct: {error}"),
        }
    }

    fn enqueue(header: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
        if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
            panic!("test frame should enqueue: {error}");
        }
    }

    fn assert_frame(frame: &FrameEntry, delivery_icount: u64, src_node: u32, seq: u32) {
        assert_eq!(frame.delivery_icount, delivery_icount);
        assert_eq!(frame.src_node, src_node);
        assert_eq!(frame.seq, seq);
        assert!(usize::from(frame.len) <= MAX_FRAME_DATA);
    }
}
