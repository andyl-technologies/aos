//! Canonical block request construction, encoding, and decoding.

use super::*;

/// A decoded, validated block request.
///
/// Carries the operation, correlation id, and the read/write geometry. For a
/// write, `data` holds exactly `count` bytes; for every other op `data` is empty
/// and `count`/`offset` are zero by convention.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockRequest {
    /// The operation to perform.
    pub op: BlockOp,
    /// The transport generation containing this request.
    pub epoch: u64,
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
            epoch: 0,
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
            epoch: 0,
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
            epoch: 0,
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
            epoch: 0,
            request_id,
            offset: 0,
            count: 0,
            data: Vec::new(),
        }
    }

    /// Builds a payload-free discard request for one exact byte range.
    #[must_use]
    pub fn discard(request_id: u32, offset: u64, count: u32) -> Self {
        Self {
            op: BlockOp::Discard,
            epoch: 0,
            request_id,
            offset,
            count,
            data: Vec::new(),
        }
    }

    /// Returns the complete epoch-scoped request identity.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        BlockRequestIdentity::new(self.epoch, self.request_id)
    }

    /// Assigns the transport identity used by the live adapter.
    #[must_use]
    pub const fn with_identity(mut self, identity: BlockRequestIdentity) -> Self {
        self.epoch = identity.epoch;
        self.request_id = identity.request_id;
        self
    }

    /// Encodes this request into its little-endian wire bytes.
    ///
    /// The reserved `u16` is emitted as zero ([IO-8]). For a write the payload
    /// follows the 28-byte header; for every other op no payload is appended.
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
        out.extend_from_slice(&self.epoch.to_le_bytes());
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
    /// - [`BlockCodecError::NonZeroReserved`] when the reserved header field is
    ///   nonzero.
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
        let reserved = u16::from_le_bytes([header[2], header[3]]);
        if reserved != 0 {
            return Err(BlockCodecError::NonZeroReserved { reserved });
        }
        let epoch = u64_le(header, 4);
        let request_id = u32_le(header, 12);
        let offset = u64_le(header, 16);
        let count = u32_le(header, 24);

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
            epoch,
            request_id,
            offset,
            count,
            data,
        })
    }
}
