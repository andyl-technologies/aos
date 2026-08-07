//! The versioned block wire ABI: `BlockRequest` and `BlockResponse` codecs.
//!
//! This module owns the on-wire format the block sub-node speaks across the
//! `SLOT_BLK_IO` shmem rings ([IO-8], [IO-9]). Both messages are a fixed field
//! order with all multi-byte integers in **little-endian**; reserved bytes are
//! zero on emit and ignored on receive. Decoding is fully bounds-checked: an
//! arbitrary byte sequence never panics, never reads out of bounds, and yields a
//! [`BlockCodecError`] when malformed — the fuzz-safe boundary the spec demands.
//!
//! ```text
//! BlockRequest  (VM slot -> SLOT_BLK_IO), little-endian, header = 20 bytes
//!   off 0   u8   op          -- 0=read, 1=write, 2=flush, 3=get_length
//!   off 1   u8   version     -- block wire ABI version (= 2)
//!   off 2   u16  _reserved   -- zero on emit, ignored on receive
//!   off 4   u32  request_id  -- correlates response to request
//!   off 8   u64  offset      -- byte offset (read/write; 0 otherwise)
//!   off 16  u32  count       -- byte count (read/write; 0 otherwise)
//!   off 20  [count bytes]    -- payload, write only (else absent)
//!
//! BlockResponse (SLOT_BLK_IO -> VM slot), little-endian, header = 12 bytes
//!   off 0   u8   status      -- 0=ok, 1=error
//!   off 1   u8   version     -- block wire ABI version (= 2)
//!   off 2   u16  _reserved   -- zero on emit, ignored on receive
//!   off 4   u32  request_id  -- echoes the request
//!   off 8   u32  count       -- response data length
//!   off 12  [count bytes]    -- success data, or one typed-error byte on error
//! ```
//!
//! The encoded bytes are carried as the opaque
//! [`crate::request::Request::payload`] / [`crate::request::Response::payload`]
//! and ride the `FrameEntry.data` field of a `SLOT_BLK_IO` ring frame
//! ([`crucible_shmem::MAX_FRAME_DATA`] = 4608 bytes, which fits a 4 KiB read
//! response plus this 12-byte header). [`crate::subnode::IoCore`] supplies the
//! shmem lifecycle bridge that drains VM-to-block frames, computes responses,
//! publishes block-to-VM frames, and issues the corresponding wake.

/// The block wire ABI version encoded in every request and response.
///
/// A decoder rejects any message whose version byte differs from this constant
/// ([IO-8]); bumping it is a breaking ABI change gated by `gate:abi-conformance`.
pub const BLOCK_ABI_VERSION: u8 = 2;

/// The fixed size in bytes of an encoded [`BlockRequest`] header.
pub const REQUEST_HEADER_LEN: usize = 20;

/// The fixed size in bytes of an encoded [`BlockResponse`] header.
pub const RESPONSE_HEADER_LEN: usize = 12;

/// A block operation code, the first byte of every [`BlockRequest`].
///
/// The numeric values are part of the wire ABI and MUST NOT change without a
/// version bump ([IO-8]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOp {
    /// Read `count` bytes at `offset` (overlay over base).
    Read,
    /// Write the payload `count` bytes at `offset` into the overlay.
    Write,
    /// Flush: a no-op success (the overlay is the durable store).
    Flush,
    /// Get the device length: returns the base image size in bytes.
    GetLength,
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
            other => Err(BlockCodecError::UnknownOp { op: other }),
        }
    }
}

/// The terminal status byte of a [`BlockResponse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    /// The operation completed successfully.
    Ok,
    /// The operation failed; the payload, if any, carries device error context.
    Error,
}

/// Closed protocol-neutral block error carried by every failed response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        }
    }

    /// Decodes a status from its wire byte.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::UnknownStatus`] when `byte` is neither `0`
    /// (ok) nor `1` (error).
    pub fn from_wire(byte: u8) -> Result<Self, BlockCodecError> {
        match byte {
            0 => Ok(BlockStatus::Ok),
            1 => Ok(BlockStatus::Error),
            other => Err(BlockCodecError::UnknownStatus { status: other }),
        }
    }
}

/// A decoded, validated block request.
///
/// Carries the operation, correlation id, and the read/write geometry. For a
/// write, `data` holds exactly `count` bytes; for every other op `data` is empty
/// and `count`/`offset` are zero by convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRequest {
    /// The operation to perform.
    pub op: BlockOp,
    /// The correlation id echoed into the response.
    pub request_id: u32,
    /// The byte offset for a read or write (zero for flush/get-length).
    pub offset: u64,
    /// The byte count for a read or write (zero for flush/get-length).
    pub count: u32,
    /// The write payload (exactly `count` bytes for a write, else empty).
    pub data: Vec<u8>,
}

impl BlockRequest {
    /// Builds a read request for `count` bytes at `offset`.
    #[must_use]
    pub fn read(request_id: u32, offset: u64, count: u32) -> Self {
        Self {
            op: BlockOp::Read,
            request_id,
            offset,
            count,
            data: Vec::new(),
        }
    }

    /// Builds a write request placing `data` at `offset`.
    ///
    /// The stored `count` mirrors `data.len()` as a `u32` view (truncating only
    /// in the impossible >4 GiB case); the authoritative `count` is recomputed
    /// and overflow-checked at [`BlockRequest::encode`] time, so a payload that
    /// does not fit the wire field is rejected there rather than mis-encoded.
    #[must_use]
    pub fn write(request_id: u32, offset: u64, data: Vec<u8>) -> Self {
        let count = u32::try_from(data.len()).unwrap_or(u32::MAX);
        Self {
            op: BlockOp::Write,
            request_id,
            offset,
            count,
            data,
        }
    }

    /// Builds a flush request.
    #[must_use]
    pub fn flush(request_id: u32) -> Self {
        Self {
            op: BlockOp::Flush,
            request_id,
            offset: 0,
            count: 0,
            data: Vec::new(),
        }
    }

    /// Builds a get-length request.
    #[must_use]
    pub fn get_length(request_id: u32) -> Self {
        Self {
            op: BlockOp::GetLength,
            request_id,
            offset: 0,
            count: 0,
            data: Vec::new(),
        }
    }

    /// Encodes this request into its little-endian wire bytes.
    ///
    /// The reserved `u16` is emitted as zero ([IO-8]). For a write the payload
    /// follows the 20-byte header; for every other op no payload is appended.
    /// The wire `count` is the `u32` view of the write payload length.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::CountOverflow`] when a write payload exceeds
    /// `u32::MAX` bytes and cannot be represented in the wire `count` field —
    /// rejected loudly rather than silently clamped ([IO-8]).
    pub fn encode(&self) -> Result<Vec<u8>, BlockCodecError> {
        let count = if self.op == BlockOp::Write {
            u32::try_from(self.data.len()).map_err(|_| BlockCodecError::CountOverflow {
                len: self.data.len(),
            })?
        } else {
            self.count
        };
        let mut out = Vec::with_capacity(REQUEST_HEADER_LEN + self.data.len());
        out.push(self.op.to_wire());
        out.push(BLOCK_ABI_VERSION);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        if self.op == BlockOp::Write {
            out.extend_from_slice(&self.data);
        }
        Ok(out)
    }

    /// Decodes a request from arbitrary bytes, fully bounds-checked.
    ///
    /// Never panics and never reads out of bounds on hostile input: a too-short
    /// buffer, an unknown op, a wrong version, or a `count` that exceeds the
    /// available write payload all return a [`BlockCodecError`] rather than
    /// parsing past the buffer ([IO-8]).
    ///
    /// # Errors
    ///
    /// - [`BlockCodecError::ShortHeader`] when `bytes` is shorter than
    ///   [`REQUEST_HEADER_LEN`].
    /// - [`BlockCodecError::UnknownOp`] when the op byte is undefined.
    /// - [`BlockCodecError::VersionMismatch`] when the version byte is not
    ///   [`BLOCK_ABI_VERSION`].
    /// - [`BlockCodecError::CountExceedsPayload`] when a write's declared
    ///   `count` exceeds the bytes after the header.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockCodecError> {
        let header = bytes
            .get(..REQUEST_HEADER_LEN)
            .ok_or(BlockCodecError::ShortHeader {
                needed: REQUEST_HEADER_LEN,
                got: bytes.len(),
            })?;
        // Indexing into `header` below is bounds-safe: it is exactly
        // REQUEST_HEADER_LEN bytes and every offset is a compile-time constant
        // within that range. `try_into` on fixed slices cannot fail here.
        let op = BlockOp::from_wire(header[0])?;
        let version = header[1];
        if version != BLOCK_ABI_VERSION {
            return Err(BlockCodecError::VersionMismatch {
                expected: BLOCK_ABI_VERSION,
                found: version,
            });
        }
        // header[2..4] is the reserved u16: ignored on receive ([IO-8]).
        let request_id = u32_le(header, 4);
        let offset = u64_le(header, 8);
        let count = u32_le(header, 16);

        let data = if op == BlockOp::Write {
            let want = count as usize;
            let payload = &bytes[REQUEST_HEADER_LEN..];
            if payload.len() < want {
                return Err(BlockCodecError::CountExceedsPayload {
                    count,
                    available: payload.len(),
                });
            }
            payload[..want].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            op,
            request_id,
            offset,
            count,
            data,
        })
    }
}

/// A decoded, validated block response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockResponse {
    /// The terminal status.
    pub status: BlockStatus,
    /// The correlation id echoed from the request.
    pub request_id: u32,
    /// Success data or the single typed-error byte for a failed response.
    pub data: Vec<u8>,
}

impl BlockResponse {
    /// Builds an ok response carrying `data`.
    ///
    /// The wire `count` is recomputed and overflow-checked at
    /// [`BlockResponse::encode`] time, not clamped here.
    #[must_use]
    pub fn ok(request_id: u32, data: Vec<u8>) -> Self {
        Self {
            status: BlockStatus::Ok,
            request_id,
            data,
        }
    }

    /// Builds an error response carrying its exact protocol-neutral result.
    #[must_use]
    pub fn error(request_id: u32, error: BlockErrorCode) -> Self {
        Self {
            status: BlockStatus::Error,
            request_id,
            data: vec![error.to_wire()],
        }
    }

    /// Returns the typed result of an error response.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::InvalidErrorPayload`] unless this is an error
    /// response with exactly one defined typed-result byte.
    pub fn error_code(&self) -> Result<BlockErrorCode, BlockCodecError> {
        if self.status != BlockStatus::Error || self.data.len() != 1 {
            return Err(BlockCodecError::InvalidErrorPayload {
                status: self.status.to_wire(),
                len: self.data.len(),
            });
        }
        BlockErrorCode::from_wire(self.data[0])
    }

    /// Encodes this response into its little-endian wire bytes.
    ///
    /// The reserved `u16` is emitted as zero ([IO-8]).
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::CountOverflow`] when the payload exceeds
    /// `u32::MAX` bytes and cannot be represented in the wire `count` field.
    pub fn encode(&self) -> Result<Vec<u8>, BlockCodecError> {
        let count = u32::try_from(self.data.len()).map_err(|_| BlockCodecError::CountOverflow {
            len: self.data.len(),
        })?;
        let mut out = Vec::with_capacity(RESPONSE_HEADER_LEN + self.data.len());
        out.push(self.status.to_wire());
        out.push(BLOCK_ABI_VERSION);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decodes a response from arbitrary bytes, fully bounds-checked.
    ///
    /// Never panics on hostile input; mirrors [`BlockRequest::decode`].
    ///
    /// # Errors
    ///
    /// - [`BlockCodecError::ShortHeader`] when `bytes` is shorter than
    ///   [`RESPONSE_HEADER_LEN`].
    /// - [`BlockCodecError::UnknownStatus`] when the status byte is undefined.
    /// - [`BlockCodecError::VersionMismatch`] when the version byte is not
    ///   [`BLOCK_ABI_VERSION`].
    /// - [`BlockCodecError::CountExceedsPayload`] when the declared `count`
    ///   exceeds the bytes after the header.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockCodecError> {
        let header = bytes
            .get(..RESPONSE_HEADER_LEN)
            .ok_or(BlockCodecError::ShortHeader {
                needed: RESPONSE_HEADER_LEN,
                got: bytes.len(),
            })?;
        let status = BlockStatus::from_wire(header[0])?;
        let version = header[1];
        if version != BLOCK_ABI_VERSION {
            return Err(BlockCodecError::VersionMismatch {
                expected: BLOCK_ABI_VERSION,
                found: version,
            });
        }
        let request_id = u32_le(header, 4);
        let count = u32_le(header, 8);

        let want = count as usize;
        let payload = &bytes[RESPONSE_HEADER_LEN..];
        if payload.len() < want {
            return Err(BlockCodecError::CountExceedsPayload {
                count,
                available: payload.len(),
            });
        }
        let response = Self {
            status,
            request_id,
            data: payload[..want].to_vec(),
        };
        if status == BlockStatus::Error {
            response.error_code()?;
        }
        Ok(response)
    }
}

/// Reads a little-endian `u32` at `offset` from a slice known to be long enough.
///
/// # Panics
///
/// Never panics in practice: every call site passes a fixed-length header slice
/// and a constant `offset` such that `offset + 4 <= header.len()`. The
/// `try_into` cannot fail because the sub-slice is exactly four bytes.
fn u32_le(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Reads a little-endian `u64` at `offset` from a slice known to be long enough.
///
/// # Panics
///
/// Never panics in practice; see [`u32_le`] for the length argument.
fn u64_le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// A malformed-message failure of the block wire codec.
///
/// Every variant is a pure function of the input bytes; decoding hostile input
/// always lands here rather than panicking ([IO-8], `gate:abi-conformance`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
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

    /// The version byte does not match the supported ABI version.
    #[error("block ABI version mismatch: expected {expected}, found {found}")]
    VersionMismatch {
        /// The supported [`BLOCK_ABI_VERSION`].
        expected: u8,
        /// The version byte found on the wire.
        found: u8,
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
