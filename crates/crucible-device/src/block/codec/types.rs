//! Block request identity, operation, status, reset, and typed-error vocabulary.

use super::*;

/// Stable guest-transport identity of one block request.
///
/// Request IDs are scoped to an epoch so a controller reset may restart its
/// counter without allowing a delayed pre-reset completion to alias a new
/// request.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct BlockRequestIdentity {
    /// Monotone controller generation.
    pub epoch: u64,
    /// Correlation ID allocated within `epoch`.
    pub request_id: u32,
}

impl BlockRequestIdentity {
    /// Builds one request identity.
    #[must_use]
    pub const fn new(epoch: u64, request_id: u32) -> Self {
        Self { epoch, request_id }
    }
}

/// A block operation code, the first byte of every [`BlockRequest`].
///
/// The numeric values are part of the wire ABI and MUST NOT change without a
/// version bump ([IO-8]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockOp {
    /// Read `count` bytes at `offset` (overlay over base).
    Read,
    /// Write the payload `count` bytes at `offset` into the overlay.
    Write,
    /// Flush: a no-op success (the overlay is the durable store).
    Flush,
    /// Get the device length: returns the base image size in bytes.
    GetLength,
    /// Discard `count` bytes at `offset` without carrying a request payload.
    Discard,
}

impl BlockOp {
    /// Returns the wire byte for this operation.
    #[must_use]
    pub fn to_wire(self) -> u8 {
        match self {
            BlockOp::Read => 0,
            BlockOp::Write => 1,
            BlockOp::Flush => 2,
            BlockOp::GetLength => 3,
            BlockOp::Discard => 4,
        }
    }

    /// Decodes an operation from its wire byte.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::UnknownOp`] when `byte` is not a defined
    /// operation code ([IO-8]); the message is malformed and answered with an
    /// error-status response, never parsed past its bounds.
    pub fn from_wire(byte: u8) -> Result<Self, BlockCodecError> {
        match byte {
            0 => Ok(BlockOp::Read),
            1 => Ok(BlockOp::Write),
            2 => Ok(BlockOp::Flush),
            3 => Ok(BlockOp::GetLength),
            4 => Ok(BlockOp::Discard),
            other => Err(BlockCodecError::UnknownOp { op: other }),
        }
    }
}

/// The terminal status byte of a [`BlockResponse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockStatus {
    /// The operation completed successfully.
    Ok,
    /// The operation failed; the payload, if any, carries device error context.
    Error,
    /// The completion initiates a live guest block-transport reset.
    TransportReset,
    /// A protocol-valid duplicate that the guest transport suppresses.
    DuplicateIgnored,
    /// A duplicate that reports a typed protocol error to the guest transport.
    DuplicateProtocolError,
    /// An outstanding request must be retried with its existing identity.
    RetryPreserveId,
    /// An outstanding request must be retried with a new post-reset identity.
    RetryNewId,
    /// An outstanding completion is intentionally dropped by reset policy.
    DropCompletion,
}

/// Post-reset request-ID allocation visible to the guest transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransportRequestIds {
    /// Keeps the current epoch and monotone request-ID counter.
    PreserveMonotonic,
    /// Advances to `next_epoch` and restarts allocation at zero.
    NewEpochFromZero,
}

/// Guest transport treatment of requests arriving during recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransportUnadmitted {
    /// Rejects arrivals with `failure_result`.
    Reject,
    /// Holds arrivals until recovery completes.
    WaitForRecovery,
}

/// Guest transport treatment of queued or executing requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransportPending {
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
}

/// Guest transport treatment of resolved requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockTransportResolved {
    /// Completes the existing result.
    Complete,
    /// Fails the request.
    Fail,
    /// Retries with the existing identity.
    RetryPreserveId,
    /// Retries with a new post-reset identity.
    RetryNewId,
}

/// Guest transport treatment of completed but undelivered requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Guest-facing portion of one live controller reset transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockTransportReset {
    /// Epoch active after the reset completes.
    pub next_epoch: u64,
    /// Exact virtual recovery duration.
    pub recovery_nanos: u64,
    /// Post-reset request-ID allocation rule.
    pub request_ids: BlockTransportRequestIds,
    /// Whether the declared namespace and path sets are re-enumerated.
    pub reenumerate_declared: bool,
    /// Whether pre-reset duplicate-suppression identities remain valid.
    pub preserve_duplicate_history: bool,
    /// Typed result used by every failed request stage.
    pub failure_result: BlockErrorCode,
    /// Treatment of requests arriving during recovery.
    pub unadmitted: BlockTransportUnadmitted,
    /// Treatment of queued requests.
    pub queued: BlockTransportPending,
    /// Treatment of executing requests.
    pub executing: BlockTransportPending,
    /// Treatment of resolved requests.
    pub resolved: BlockTransportResolved,
    /// Treatment of completed but undelivered requests.
    pub completed_undelivered: BlockTransportUndelivered,
    /// Whether the controller buffer is preserved.
    pub preserve_controller_buffer: bool,
    /// Whether the volatile cache is preserved.
    pub preserve_volatile_cache: bool,
}

impl BlockTransportReset {
    const PAYLOAD_LEN: usize = 32;

    pub(super) fn encode(self) -> [u8; Self::PAYLOAD_LEN] {
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
        payload[21] = encode_pending(self.queued);
        payload[22] = encode_pending(self.executing);
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

    pub(super) fn decode(payload: &[u8]) -> Result<Self, BlockCodecError> {
        if payload.len() != Self::PAYLOAD_LEN || payload[27..].iter().any(|byte| *byte != 0) {
            return Err(BlockCodecError::InvalidResetPayload { len: payload.len() });
        }
        let request_ids = match payload[16] {
            0 => BlockTransportRequestIds::PreserveMonotonic,
            1 => BlockTransportRequestIds::NewEpochFromZero,
            _ => return Err(BlockCodecError::InvalidResetPayload { len: payload.len() }),
        };
        let reenumerate_declared = match payload[17] {
            0 => false,
            1 => true,
            _ => return Err(BlockCodecError::InvalidResetPayload { len: payload.len() }),
        };
        let preserve_duplicate_history = match payload[18] {
            0 => false,
            1 => true,
            _ => return Err(BlockCodecError::InvalidResetPayload { len: payload.len() }),
        };
        let failure_result = BlockErrorCode::from_wire(payload[19])?;
        let unadmitted = match payload[20] {
            0 => BlockTransportUnadmitted::Reject,
            1 => BlockTransportUnadmitted::WaitForRecovery,
            _ => return Err(BlockCodecError::InvalidResetPayload { len: payload.len() }),
        };
        let queued = decode_pending(payload[21], payload.len())?;
        let executing = decode_pending(payload[22], payload.len())?;
        let resolved = match payload[23] {
            0 => BlockTransportResolved::Complete,
            1 => BlockTransportResolved::Fail,
            2 => BlockTransportResolved::RetryPreserveId,
            3 => BlockTransportResolved::RetryNewId,
            _ => return Err(BlockCodecError::InvalidResetPayload { len: payload.len() }),
        };
        let completed_undelivered = match payload[24] {
            0 => BlockTransportUndelivered::Complete,
            1 => BlockTransportUndelivered::Fail,
            2 => BlockTransportUndelivered::RetryPreserveId,
            3 => BlockTransportUndelivered::RetryNewId,
            4 => BlockTransportUndelivered::DropCompletion,
            _ => return Err(BlockCodecError::InvalidResetPayload { len: payload.len() }),
        };
        let preserve_controller_buffer = decode_bool(payload[25], payload.len())?;
        let preserve_volatile_cache = decode_bool(payload[26], payload.len())?;
        Ok(Self {
            next_epoch: u64_le(payload, 0),
            recovery_nanos: u64_le(payload, 8),
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

const fn encode_pending(policy: BlockTransportPending) -> u8 {
    match policy {
        BlockTransportPending::Fail => 0,
        BlockTransportPending::RetryPreserveId => 1,
        BlockTransportPending::RetryNewId => 2,
    }
}

fn decode_pending(byte: u8, len: usize) -> Result<BlockTransportPending, BlockCodecError> {
    match byte {
        0 => Ok(BlockTransportPending::Fail),
        1 => Ok(BlockTransportPending::RetryPreserveId),
        2 => Ok(BlockTransportPending::RetryNewId),
        _ => Err(BlockCodecError::InvalidResetPayload { len }),
    }
}

fn decode_bool(byte: u8, len: usize) -> Result<bool, BlockCodecError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BlockCodecError::InvalidResetPayload { len }),
    }
}

/// Closed protocol-neutral block error carried by every failed response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlockErrorCode {
    /// The device is unavailable.
    Offline,
    /// A write targeted read-only storage.
    ReadOnly,
    /// The addressed range is invalid.
    InvalidRange,
    /// The controller or queue is temporarily busy.
    Busy,
    /// The operation exceeded its modeled deadline.
    Timeout,
    /// The medium reported an uncorrectable error.
    MediumError,
    /// Data-integrity verification failed.
    IntegrityError,
    /// A nonspecific device I/O error occurred.
    IoError,
    /// Capacity or allocation was exhausted.
    NoSpace,
    /// A namespace or object does not exist.
    NotFound,
    /// A retained identity is stale.
    Stale,
}

impl BlockErrorCode {
    /// Returns the stable wire byte for this typed result.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
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

    /// Decodes one stable typed-result byte.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::UnknownErrorCode`] for an undefined byte.
    pub fn from_wire(byte: u8) -> Result<Self, BlockCodecError> {
        match byte {
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
            other => Err(BlockCodecError::UnknownErrorCode { code: other }),
        }
    }
}

impl BlockStatus {
    /// Returns the wire byte for this status.
    #[must_use]
    pub fn to_wire(self) -> u8 {
        match self {
            BlockStatus::Ok => 0,
            BlockStatus::Error => 1,
            BlockStatus::TransportReset => 2,
            BlockStatus::DuplicateIgnored => 3,
            BlockStatus::DuplicateProtocolError => 4,
            BlockStatus::RetryPreserveId => 5,
            BlockStatus::RetryNewId => 6,
            BlockStatus::DropCompletion => 7,
        }
    }

    /// Decodes a status from its wire byte.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::UnknownStatus`] when `byte` is not a defined
    /// primary or post-primary transport status.
    pub fn from_wire(byte: u8) -> Result<Self, BlockCodecError> {
        match byte {
            0 => Ok(BlockStatus::Ok),
            1 => Ok(BlockStatus::Error),
            2 => Ok(BlockStatus::TransportReset),
            3 => Ok(BlockStatus::DuplicateIgnored),
            4 => Ok(BlockStatus::DuplicateProtocolError),
            5 => Ok(BlockStatus::RetryPreserveId),
            6 => Ok(BlockStatus::RetryNewId),
            7 => Ok(BlockStatus::DropCompletion),
            other => Err(BlockCodecError::UnknownStatus { status: other }),
        }
    }
}
