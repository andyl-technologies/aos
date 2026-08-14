//! Canonical block response construction, encoding, and decoding.

use super::*;

/// A decoded, validated block response.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockResponse {
    /// The terminal status.
    pub status: BlockStatus,
    /// The transport generation echoed from the request.
    pub epoch: u64,
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
            epoch: 0,
            request_id,
            data,
        }
    }

    /// Builds an error response carrying its exact protocol-neutral result.
    #[must_use]
    pub fn error(request_id: u32, error: BlockErrorCode) -> Self {
        Self {
            status: BlockStatus::Error,
            epoch: 0,
            request_id,
            data: vec![error.to_wire()],
        }
    }

    /// Builds an ok response for one epoch-scoped request.
    #[must_use]
    pub fn ok_for(identity: BlockRequestIdentity, data: Vec<u8>) -> Self {
        Self::ok(identity.request_id, data).with_identity(identity)
    }

    /// Builds an error response for one epoch-scoped request.
    #[must_use]
    pub fn error_for(identity: BlockRequestIdentity, error: BlockErrorCode) -> Self {
        Self::error(identity.request_id, error).with_identity(identity)
    }

    /// Builds a typed live transport-reset completion.
    #[must_use]
    pub fn transport_reset(identity: BlockRequestIdentity, reset: BlockTransportReset) -> Self {
        Self {
            status: BlockStatus::TransportReset,
            epoch: identity.epoch,
            request_id: identity.request_id,
            data: reset.encode().to_vec(),
        }
    }

    /// Builds a transport-only ignored duplicate for a completed identity.
    #[must_use]
    pub fn ignored_duplicate(identity: BlockRequestIdentity) -> Self {
        Self {
            status: BlockStatus::DuplicateIgnored,
            epoch: identity.epoch,
            request_id: identity.request_id,
            data: Vec::new(),
        }
    }

    /// Builds a transport-only duplicate carrying a typed protocol error.
    #[must_use]
    pub fn duplicate_protocol_error(response: &Self) -> Self {
        let mut duplicate = response.clone();
        duplicate.status = BlockStatus::DuplicateProtocolError;
        duplicate
    }

    /// Builds a reset disposition for an outstanding request.
    #[must_use]
    pub fn reset_disposition(identity: BlockRequestIdentity, status: BlockStatus) -> Self {
        debug_assert!(matches!(
            status,
            BlockStatus::RetryPreserveId | BlockStatus::RetryNewId | BlockStatus::DropCompletion
        ));
        Self {
            status,
            epoch: identity.epoch,
            request_id: identity.request_id,
            data: Vec::new(),
        }
    }

    /// Decodes the guest-facing reset transition.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::InvalidResetPayload`] unless this is a reset
    /// response with the exact closed payload shape.
    pub fn transport_reset_directive(&self) -> Result<BlockTransportReset, BlockCodecError> {
        if self.status != BlockStatus::TransportReset {
            return Err(BlockCodecError::InvalidResetPayload {
                len: self.data.len(),
            });
        }
        BlockTransportReset::decode(&self.data)
    }

    /// Returns the complete epoch-scoped request identity.
    #[must_use]
    pub const fn identity(&self) -> BlockRequestIdentity {
        BlockRequestIdentity::new(self.epoch, self.request_id)
    }

    /// Assigns the identity echoed by this response.
    #[must_use]
    pub const fn with_identity(mut self, identity: BlockRequestIdentity) -> Self {
        self.epoch = identity.epoch;
        self.request_id = identity.request_id;
        self
    }

    /// Returns the typed result of an error response.
    ///
    /// # Errors
    ///
    /// Returns [`BlockCodecError::InvalidErrorPayload`] unless this is an error
    /// response with exactly one defined typed-result byte.
    pub fn error_code(&self) -> Result<BlockErrorCode, BlockCodecError> {
        if !matches!(
            self.status,
            BlockStatus::Error | BlockStatus::DuplicateProtocolError
        ) || self.data.len() != 1
        {
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
        out.extend_from_slice(&self.epoch.to_le_bytes());
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
    /// - [`BlockCodecError::NonZeroReserved`] when the reserved header field is
    ///   nonzero.
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
        let reserved = u16::from_le_bytes([header[2], header[3]]);
        if reserved != 0 {
            return Err(BlockCodecError::NonZeroReserved { reserved });
        }
        let epoch = u64_le(header, 4);
        let request_id = u32_le(header, 12);
        let count = u32_le(header, 16);

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
            epoch,
            request_id,
            data: payload[..want].to_vec(),
        };
        if matches!(
            status,
            BlockStatus::Error | BlockStatus::DuplicateProtocolError
        ) {
            response.error_code()?;
        } else if status == BlockStatus::TransportReset {
            response.transport_reset_directive()?;
        }
        Ok(response)
    }
}
