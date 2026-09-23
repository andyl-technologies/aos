//! Canonical full-history storage for `AOSBSD01` exchange checkpoints.
//!
//! The history codec retains every canonical checkpoint rather than accepting
//! a caller-selected record as the current head. Its outer framing is:
//!
//! ```text
//! AOSBSH01 | version:u16be=1 | record-count:u32be | head-commitment[32] |
//! repeated(record-length:u32be | canonical-AOSBSD01-record)
//! ```

use sha2::{Digest as _, Sha256};

use super::{
    BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES, BrokerSessionDurableError,
    BrokerSessionDurablePhaseV1, BrokerSessionDurableRecordV1, read_u16, read_u32,
};

const MAGIC: &[u8; 8] = b"AOSBSH01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 46;
const MAXIMUM_RECORDS: usize = 8_192;

/// Maximum encoded durable history accepted before allocating record storage.
pub const BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES: usize = 64 * 1024 * 1024;

/// Retains a canonical, gap-free chain ending at its authoritative current head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionDurableHistoryV1 {
    records: Vec<BrokerSessionDurableRecordV1>,
    head_commitment: [u8; 32],
}

impl BrokerSessionDurableHistoryV1 {
    /// Validates a complete checkpoint chain and selects its sole current head.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] for an empty or excessive chain,
    /// a revision gap, a wrong predecessor, an invalid phase transition, or a
    /// changed session, protocol, protected peer, endpoint, context, or request.
    pub fn from_records(
        records: Vec<BrokerSessionDurableRecordV1>,
    ) -> Result<Self, BrokerSessionDurableError> {
        if records.is_empty() || records.len() > MAXIMUM_RECORDS {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        validate_chain(&records)?;
        let head_commitment = records
            .last()
            .ok_or(BrokerSessionDurableError::InvalidLength)?
            .commitment()?;
        Ok(Self {
            records,
            head_commitment,
        })
    }

    /// Decodes one bounded canonical history and validates its full chain.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] for malformed framing, excessive
    /// allocation, a noncanonical record, a false head, or any chain failure.
    pub fn decode(bytes: &[u8]) -> Result<Self, BrokerSessionDurableError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || read_u16(bytes, 8)? != VERSION
        {
            return Err(BrokerSessionDurableError::InvalidFormat);
        }
        let count = usize::try_from(read_u32(bytes, 10)?)
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        if count == 0 || count > MAXIMUM_RECORDS {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        let encoded_head: [u8; 32] = bytes
            .get(14..46)
            .ok_or(BrokerSessionDurableError::InvalidLength)?
            .try_into()
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        let mut cursor = HEADER_BYTES;
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::try_from(read_u32(bytes, cursor)?)
                .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
            cursor = cursor
                .checked_add(4)
                .ok_or(BrokerSessionDurableError::InvalidLength)?;
            if length == 0 || length > BROKER_SESSION_DURABLE_RECORD_MAXIMUM_BYTES {
                return Err(BrokerSessionDurableError::InvalidLength);
            }
            let end = cursor
                .checked_add(length)
                .ok_or(BrokerSessionDurableError::InvalidLength)?;
            let record_bytes = bytes
                .get(cursor..end)
                .ok_or(BrokerSessionDurableError::InvalidLength)?;
            records.push(BrokerSessionDurableRecordV1::decode(record_bytes)?);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        let history = Self::from_records(records)?;
        if history.head_commitment != encoded_head || history.encode()?.as_slice() != bytes {
            return Err(BrokerSessionDurableError::InvalidFormat);
        }
        Ok(history)
    }

    /// Encodes the sole canonical full-history representation.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] when the chain is invalid or the
    /// encoded history exceeds its fixed aggregate allocation ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, BrokerSessionDurableError> {
        validate_chain(&self.records)?;
        let mut encoded_records = Vec::with_capacity(self.records.len());
        let mut capacity = HEADER_BYTES;
        for record in &self.records {
            let bytes = record.encode()?;
            capacity = capacity
                .checked_add(4)
                .and_then(|value| value.checked_add(bytes.len()))
                .ok_or(BrokerSessionDurableError::InvalidLength)?;
            encoded_records.push(bytes);
        }
        if capacity > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        let count = u32::try_from(encoded_records.len())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        let expected_head = self
            .records
            .last()
            .ok_or(BrokerSessionDurableError::InvalidLength)?
            .commitment()?;
        if expected_head != self.head_commitment {
            return Err(BrokerSessionDurableError::Continuity);
        }

        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&self.head_commitment);
        for record in encoded_records {
            let length = u32::try_from(record.len())
                .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&record);
        }
        Ok(bytes)
    }

    /// Returns every validated checkpoint in revision order.
    #[must_use]
    pub fn records(&self) -> &[BrokerSessionDurableRecordV1] {
        &self.records
    }

    /// Returns the authoritative current record selected by the full chain.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError::InvalidLength`] only if an invalid
    /// empty value was somehow retained internally.
    pub fn head(&self) -> Result<&BrokerSessionDurableRecordV1, BrokerSessionDurableError> {
        self.records
            .last()
            .ok_or(BrokerSessionDurableError::InvalidLength)
    }

    /// Returns the commitment of the authoritative current record.
    #[must_use]
    pub const fn head_commitment(&self) -> [u8; 32] {
        self.head_commitment
    }

    /// Returns a commitment to the complete canonical history.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerSessionDurableError`] if the retained chain cannot be encoded.
    pub fn commitment(&self) -> Result<[u8; 32], BrokerSessionDurableError> {
        let bytes = self.encode()?;
        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-broker-session-durable-history-v1\0");
        digest.update(bytes);
        Ok(digest.finalize().into())
    }
}

fn validate_chain(
    records: &[BrokerSessionDurableRecordV1],
) -> Result<(), BrokerSessionDurableError> {
    let first = records
        .first()
        .ok_or(BrokerSessionDurableError::InvalidLength)?;
    if first.revision() != 1
        || first.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
        || first.predecessor() != [0; 32]
    {
        return Err(BrokerSessionDurableError::Continuity);
    }
    for pair in records.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if current.revision()
            != previous
                .revision()
                .checked_add(1)
                .ok_or(BrokerSessionDurableError::SequenceExhausted)?
            || current.predecessor() != previous.commitment()?
            || current.protocol() != previous.protocol()
            || current.endpoint() != previous.endpoint()
            || current.session_binding() != previous.session_binding()
            || current.peer_binding() != previous.peer_binding()
            || current.protected_bindings().protected_context()
                != previous.protected_bindings().protected_context()
            || current.protected_bindings().endpoint_publication()
                != previous.protected_bindings().endpoint_publication()
        {
            return Err(BrokerSessionDurableError::Continuity);
        }
        match (previous.phase(), current.phase()) {
            (
                BrokerSessionDurablePhaseV1::RequestPrepared,
                BrokerSessionDurablePhaseV1::Terminal,
            ) if current.method() == previous.method()
                && current.request_id() == previous.request_id()
                && current.client_sequence() == previous.client_sequence()
                && current.maximum_response_bytes() == previous.maximum_response_bytes()
                && current.request_semantic_binding() == previous.request_semantic_binding()
                && current.request_companion() == previous.request_companion()
                && current.request_packet() == previous.request_packet() => {}
            (
                BrokerSessionDurablePhaseV1::Terminal,
                BrokerSessionDurablePhaseV1::RequestPrepared,
            ) if current.request_id() != previous.request_id()
                && current.client_sequence()
                    == previous
                        .client_sequence()
                        .checked_add(1)
                        .ok_or(BrokerSessionDurableError::SequenceExhausted)? => {}
            _ => return Err(BrokerSessionDurableError::Continuity),
        }
    }
    Ok(())
}
