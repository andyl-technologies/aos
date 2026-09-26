//! Fail-closed block callback and wire-format errors.

use super::*;

/// An error produced by block callback handling.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BlockIoError {
    /// A serialized plugin transport continuation was not exact and canonical.
    #[error("invalid block transport continuation: {reason}")]
    InvalidTransportContinuation {
        /// Stable fail-loud validation reason.
        reason: &'static str,
    },
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
    /// An asynchronous event frame came from the wrong node.
    #[error(
        "block transport event source {actual_src_node} does not match reserved block source {expected_src_node}"
    )]
    UnexpectedTransportEventSource {
        /// Reserved block executor slot.
        expected_src_node: u32,
        /// Frame producer.
        actual_src_node: u32,
        /// Frame identity.
        frame: FrameDeliveryKey,
    },
    /// An asynchronous transport event was malformed.
    #[error("block transport event at {frame:?} is malformed: {source}")]
    TransportEventMalformed {
        /// Frame identity.
        frame: FrameDeliveryKey,
        /// Closed wire error.
        source: BlockWireError,
    },
    /// An asynchronous event did not belong to a completed request.
    #[error("block transport event for unknown or outstanding identity {identity:?} at {frame:?}")]
    UnknownTransportEventIdentity {
        /// Identity claimed by the event.
        identity: BlockRequestIdentity,
        /// Frame identity retained for deterministic diagnostics.
        frame: FrameDeliveryKey,
    },
    /// Completed-identity history exceeded an authored resource limit.
    #[error(
        "block completed-identity history limit `{field}` refused current={current} requested={requested} configured={configured} hard={hard}"
    )]
    CompletedHistoryResourceLimit {
        /// Stable public resource-limit field.
        field: &'static str,
        /// Usage already owned before the refused reservation.
        current: u64,
        /// Additional atomic usage that was refused.
        requested: u64,
        /// Authored scenario ceiling.
        configured: u64,
        /// Immutable compiled ceiling.
        hard: u64,
    },
    /// A reset response did not describe the only valid next epoch.
    #[error(
        "block transport reset from epoch {current_epoch} to {next_epoch} violates {request_ids:?}"
    )]
    InvalidTransportResetEpoch {
        /// Epoch active before reset.
        current_epoch: u64,
        /// Requested post-reset epoch.
        next_epoch: u64,
        /// Allocation rule that constrained the epoch.
        request_ids: BlockTransportRequestIds,
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
    /// A transport-reset response has a malformed closed payload.
    #[error("invalid block transport-reset payload length {len}")]
    InvalidResetPayload {
        /// Actual reset payload length.
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
