//! Callback completion tokens and guest-facing delivery results.

use super::*;

/// A request token that must be consumed by poll completion or failure handling.
#[must_use = "block request tokens must be consumed by block poll completion or failure"]
#[derive(Debug, PartialEq, Eq)]
pub struct BlockRequestToken {
    pub(super) identity: BlockRequestIdentity,
    pub(super) device_token: DeviceIoRequestToken,
}

impl BlockRequestToken {
    /// Returns the block wire request id.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.identity.request_id
    }

    /// Returns the epoch-scoped wire request identity.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        self.identity
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
    pub(super) ring_index: u32,
    pub(super) submit_icount: u64,
    pub(super) request_id: u32,
    pub(super) payload_len: usize,
    pub(super) token: BlockRequestToken,
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

/// One post-primary guest-transport event consumed independently of a request token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportEvent {
    /// A duplicate success completion was suppressed by transport history.
    IgnoredDuplicate {
        /// Identity of the already-completed request.
        identity: BlockRequestIdentity,
    },
    /// A duplicate carried a modeled protocol error.
    ProtocolError {
        /// Identity of the already-completed request.
        identity: BlockRequestIdentity,
        /// Closed protocol error delivered by the host.
        error: BlockResponseErrorCode,
    },
    /// A duplicate initiated a live controller reset.
    Reset {
        /// Identity whose duplicate initiated the reset.
        identity: BlockRequestIdentity,
        /// Exact guest-facing transition.
        reset: BlockTransportReset,
    },
}

/// A validated transport event held at the ring head until QEMU commits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingBlockTransportEvent {
    pub(super) event: BlockTransportEvent,
    pub(super) frame: FrameDeliveryKey,
}

impl PendingBlockTransportEvent {
    /// Returns the decoded event without consuming the prepared transaction.
    #[must_use]
    pub const fn event(self) -> BlockTransportEvent {
        self.event
    }

    /// Encodes the prepared event for QEMU-side validation.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] if the fixed event payload cannot be encoded.
    pub fn encode(self) -> Result<Vec<u8>, BlockWireError> {
        self.event.encode()
    }
}

impl BlockTransportEvent {
    /// Encodes the event in the same versioned response envelope used by the
    /// shared-memory block transport.
    ///
    /// # Errors
    ///
    /// Returns [`BlockWireError`] if the fixed event payload cannot be encoded.
    pub fn encode(self) -> Result<Vec<u8>, BlockWireError> {
        let response = match self {
            Self::IgnoredDuplicate { identity } => BlockResponse::with_identity(
                BlockResponseStatus::DuplicateIgnored,
                identity,
                Vec::new(),
            ),
            Self::ProtocolError { identity, error } => BlockResponse::with_identity(
                BlockResponseStatus::DuplicateProtocolError,
                identity,
                vec![error.to_wire()],
            ),
            Self::Reset { identity, reset } => BlockResponse::reset_event(identity, reset),
        };
        response.encode()
    }
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
