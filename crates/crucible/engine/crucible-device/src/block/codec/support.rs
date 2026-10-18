//! Block wire primitive decoders and malformed-message errors.

/// Reads a little-endian `u32` at `offset` from a slice known to be long enough.
///
/// # Panics
///
/// Never panics in practice: every call site passes a fixed-length header slice
/// and a constant `offset` such that `offset + 4 <= header.len()`. The
/// `try_into` cannot fail because the sub-slice is exactly four bytes.
pub(super) fn u32_le(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Reads a little-endian `u64` at `offset` from a slice known to be long enough.
///
/// # Panics
///
/// Never panics in practice; see [`u32_le`] for the length argument.
pub(super) fn u64_le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// A malformed-message failure of the block wire codec.
///
/// Every variant is a pure function of the input bytes; decoding hostile input
/// always lands here rather than panicking ([IO-8], `gate:abi-conformance`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize,
)]
pub enum BlockCodecError {
    /// The buffer is shorter than the fixed header for its message kind.
    #[error("block message header truncated: need {needed} bytes, got {got}")]
    ShortHeader {
        /// The header length required for this message kind.
        needed: usize,
        /// The number of bytes actually present.
        got: usize,
    },

    /// The op byte does not name a defined block operation.
    #[error("unknown block op code {op}")]
    UnknownOp {
        /// The undefined op byte.
        op: u8,
    },

    /// The status byte does not name a defined block status.
    #[error("unknown block status code {status}")]
    UnknownStatus {
        /// The undefined status byte.
        status: u8,
    },

    /// The typed block error byte is undefined.
    #[error("unknown block error code {code}")]
    UnknownErrorCode {
        /// Undefined typed-result byte.
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

    /// The version byte does not match the supported ABI version.
    #[error("block ABI version mismatch: expected {expected}, found {found}")]
    VersionMismatch {
        /// The supported [`crate::block::codec::BLOCK_ABI_VERSION`].
        expected: u8,
        /// The version byte found on the wire.
        found: u8,
    },

    /// The reserved header field was not zero.
    #[error("block message reserved field {reserved} is nonzero")]
    NonZeroReserved {
        /// The nonzero reserved value found on the wire.
        reserved: u16,
    },

    /// The declared `count` exceeds the payload bytes after the header.
    #[error("declared count {count} exceeds available payload {available}")]
    CountExceedsPayload {
        /// The declared byte count.
        count: u32,
        /// The bytes actually available after the header.
        available: usize,
    },

    /// A payload length does not fit the `u32` wire `count` field.
    ///
    /// The block wire `count` is a `u32` ([IO-8]); a payload of more than
    /// `u32::MAX` bytes cannot be faithfully encoded. Rejecting at encode time
    /// is loud and lossless rather than silently clamping the count downward.
    #[error("payload length {len} does not fit the u32 wire count field")]
    CountOverflow {
        /// The payload length that overflowed the `u32` `count` field.
        len: usize,
    },
}
