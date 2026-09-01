//! Canonical durable records for drained fault events.

use super::*;

const MAGIC: &[u8] = b"crucible.dequeued-fault-event.v1\0";

impl DequeuedFaultEvent {
    /// Returns the exact canonical record length after authenticating the event.
    ///
    /// This performs every semantic check required by [`Self::canonical_bytes`]
    /// without allocating the output record, so enclosing codecs can admit the
    /// record against their aggregate resource budget first.
    ///
    /// # Errors
    ///
    /// Returns [`FaultEventError`] when the payload exceeds the hard bound, its
    /// length differs from the header, or its authenticated digests are invalid.
    pub fn canonical_length(&self) -> Result<usize, FaultEventError> {
        let payload_length =
            u32::try_from(self.payload.len()).map_err(|_| FaultEventError::Bounds)?;
        if payload_length == 0
            || payload_length > HARD_FAULT_PAYLOAD_BYTES
            || self.header.payload_length != payload_length
        {
            return Err(FaultEventError::Bounds);
        }
        self.header.validate()?;
        self.header.authenticate_payload(&self.payload)?;
        MAGIC
            .len()
            .checked_add(FAULT_EVENT_HEADER_V1_BYTES)
            .and_then(|length| length.checked_add(4))
            .and_then(|length| length.checked_add(self.payload.len()))
            .ok_or(FaultEventError::Bounds)
    }

    /// Encodes this drained event as a canonical durable-checkpoint record.
    ///
    /// The original transport header is retained byte-for-byte so restore can
    /// authenticate the same rule, opportunity, state, and arena-coordinate
    /// evidence that was observed before capture.
    ///
    /// # Errors
    ///
    /// Returns [`FaultEventError`] when the payload exceeds the hard bound, its
    /// length differs from the header, or its authenticated digests are invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultEventError> {
        let encoded_length = self.canonical_length()?;
        let payload_length = self.header.payload_length;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_length)
            .map_err(|_| FaultEventError::CheckpointAllocation)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.header.encode());
        bytes.extend_from_slice(&payload_length.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decodes and authenticates a durable drained-event record.
    ///
    /// # Errors
    ///
    /// Returns [`FaultEventError`] when the version, record framing, event
    /// header, hard payload bound, header length, or either payload digest is
    /// invalid, or when bytes remain after the record.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FaultEventError> {
        let (header, payload_start) = decode(bytes)?;
        let payload = &bytes[payload_start..];
        let mut owned_payload = Vec::new();
        owned_payload
            .try_reserve_exact(payload.len())
            .map_err(|_| FaultEventError::CheckpointAllocation)?;
        owned_payload.extend_from_slice(payload);
        Ok(Self {
            header,
            payload: owned_payload,
        })
    }

    /// Decodes an owned canonical record without duplicating its payload allocation.
    ///
    /// The record is authenticated in place, then its framing prefix is removed
    /// by shifting the already-owned payload within the same allocation.
    ///
    /// # Errors
    ///
    /// Returns [`FaultEventError`] under the same conditions as
    /// [`Self::from_canonical_bytes`].
    pub fn from_canonical_vec(mut bytes: Vec<u8>) -> Result<Self, FaultEventError> {
        let (header, payload_start) = decode(&bytes)?;
        let payload_length = bytes.len().saturating_sub(payload_start);
        bytes.copy_within(payload_start.., 0);
        bytes.truncate(payload_length);
        Ok(Self {
            header,
            payload: bytes,
        })
    }
}

fn decode(bytes: &[u8]) -> Result<(FaultEventHeaderV1, usize), FaultEventError> {
    let body = bytes
        .strip_prefix(MAGIC)
        .ok_or(FaultEventError::CheckpointVersion)?;
    let (header_bytes, body) = body
        .split_at_checked(FAULT_EVENT_HEADER_V1_BYTES)
        .ok_or(FaultEventError::CheckpointLength)?;
    let (length_bytes, payload) = body
        .split_at_checked(4)
        .ok_or(FaultEventError::CheckpointLength)?;
    let length = u32::from_le_bytes(
        length_bytes
            .try_into()
            .map_err(|_| FaultEventError::CheckpointLength)?,
    );
    if length == 0 || length > HARD_FAULT_PAYLOAD_BYTES {
        return Err(FaultEventError::Bounds);
    }
    if payload.len() != usize::try_from(length).map_err(|_| FaultEventError::CheckpointLength)? {
        return Err(FaultEventError::CheckpointLength);
    }
    let header = FaultEventHeaderV1::decode_header(header_bytes)?;
    if header.encode().as_slice() != header_bytes {
        return Err(FaultEventError::CheckpointCanonical);
    }
    if header.payload_length != length {
        return Err(FaultEventError::CheckpointLength);
    }
    header.authenticate_payload(payload)?;
    Ok((header, MAGIC.len() + FAULT_EVENT_HEADER_V1_BYTES + 4))
}
