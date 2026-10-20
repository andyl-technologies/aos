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
    BrokerSessionDurablePhaseV1, BrokerSessionDurableRecordV1,
    BrokerSessionDurableRecordDecodeCaptureV1, BrokerSessionDurableRecordEncodeCaptureV1,
    read_u16, read_u32,
};

const MAGIC: &[u8; 8] = b"AOSBSH01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 46;

/// Bounds the number of complete records accepted in one durable history.
pub const MAXIMUM_RECORDS: usize = 8_192;

/// Maximum encoded durable history accepted before allocating record storage.
pub const BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES: usize = 64 * 1024 * 1024;

/// Retains a canonical, gap-free chain ending at its authoritative current head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerSessionDurableHistoryV1 {
    records: Vec<BrokerSessionDurableRecordV1>,
    head_commitment: [u8; 32],
}


/// Owns partial history decoding as non-authorizing historical DATA.
#[derive(Default)]
pub struct BrokerSessionDurableHistoryDecodeCaptureV1 {
    current_record: Option<BrokerSessionDurableRecordDecodeCaptureV1>,
    canonical: Option<BrokerSessionDurableHistoryEncodeCaptureV1>,
    history: Option<BrokerSessionDurableHistoryV1>,
    chain: Option<BrokerSessionDurableRecordEncodeCaptureV1>,
    records: Vec<BrokerSessionDurableRecordV1>,
    result: Option<Result<(), BrokerSessionDurableError>>,
    attempted: bool,
    closed: Option<BrokerSessionDurableError>,
}

/// Owns partial history encoding as non-authorizing historical DATA.
#[derive(Default)]
pub struct BrokerSessionDurableHistoryEncodeCaptureV1 {
    record: Option<BrokerSessionDurableRecordEncodeCaptureV1>,
    current_bytes: Option<Vec<u8>>,
    remaining: Option<std::vec::IntoIter<Vec<u8>>>,
    bytes: Option<Vec<u8>>,
    encoded_records: Vec<Vec<u8>>,
    head: Option<BrokerSessionDurableRecordEncodeCaptureV1>,
    chain: Option<BrokerSessionDurableRecordEncodeCaptureV1>,
    result: Option<Result<(), BrokerSessionDurableError>>,
    attempted: bool,
    closed: Option<BrokerSessionDurableError>,
}

impl BrokerSessionDurableHistoryDecodeCaptureV1 {
    /// Constructs an empty once-only historical DATA owner.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Bounds this owner's fixed reached result and representation cells.
    ///
    /// The model/row destinations, result, attempted latch and refusal are five
    /// cells. Whole positive child captures drop between row, chain and canonical
    /// phases, so only the largest active child remains on a failed frontier.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        let record = BrokerSessionDurableRecordDecodeCaptureV1::receiving_metadata_cells_v1()?;
        let canonical = BrokerSessionDurableHistoryEncodeCaptureV1::receiving_metadata_cells_v1()?;
        5_usize.checked_add(record.max(canonical))
    }

    /// Borrows the exact first codec refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&BrokerSessionDurableError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows actual reached rows, including an incomplete or refused chain.
    ///
    /// This diagnostic view proves no complete history or current head.
    #[must_use]
    pub fn retained_records(&self) -> &[BrokerSessionDurableRecordV1] {
        self.history.as_ref().map(|history| history.records()).unwrap_or(&self.records)
    }

    /// Borrows the actual head encoding retained through its outer comparison.
    #[must_use]
    pub fn retained_head_encoding(&self) -> Option<&[u8]> {
        self.chain.as_ref().and_then(|capture| capture.encoded())
    }

    /// Borrows the completed representation without creating authority.
    #[must_use]
    pub fn history(&self) -> Option<&BrokerSessionDurableHistoryV1> {
        if self.closed.is_some() || !matches!(self.result, Some(Ok(()))) { return None; }
        self.history.as_ref()
    }

    /// Moves the completed representation out once, preserving failed owners.
    ///
    /// # Errors
    /// Refuses incomplete, failed, or already consumed captures.
    pub fn take_history_once(&mut self) -> Result<BrokerSessionDurableHistoryV1, BrokerSessionDurableError> {
        if self.closed.is_some() || !matches!(self.result, Some(Ok(()))) {
            return Err(self.failure().cloned().unwrap_or(BrokerSessionDurableError::InvalidFormat));
        }
        self.history.take().ok_or(BrokerSessionDurableError::InvalidFormat)
    }
}

impl BrokerSessionDurableHistoryEncodeCaptureV1 {
    /// Constructs an empty once-only historical DATA owner.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Bounds this owner's fixed reached result and representation cells.
    ///
    /// Four encoded backing destinations plus result/attempt/refusal coexist.
    /// The complete row, pair and head child captures drop between phases.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        7_usize.checked_add(
            BrokerSessionDurableRecordEncodeCaptureV1::receiving_metadata_cells_v1()?,
        )
    }

    /// Borrows the exact first codec refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&BrokerSessionDurableError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the completed representation without creating authority.
    #[must_use]
    pub fn encoded(&self) -> Option<&[u8]> {
        if self.closed.is_some() || !matches!(self.result, Some(Ok(()))) { return None; }
        self.bytes.as_deref()
    }

    /// Moves the completed representation out once, preserving failed owners.
    ///
    /// # Errors
    /// Refuses incomplete, failed, or already consumed captures.
    pub fn take_encoded_once(&mut self) -> Result<Vec<u8>, BrokerSessionDurableError> {
        if self.closed.is_some() || !matches!(self.result, Some(Ok(()))) {
            return Err(self.failure().cloned().unwrap_or(BrokerSessionDurableError::InvalidFormat));
        }
        self.bytes.take().ok_or(BrokerSessionDurableError::InvalidFormat)
    }
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
        let head_commitment = validated_head(&records, false, &mut None)?;
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
        let mut work = BrokerSessionDurableHistoryDecodeCaptureV1::new();
        decode_history(bytes, &mut work, false)?;
        work.history.take().ok_or(BrokerSessionDurableError::InvalidFormat)
    }

    /// Decodes into an inert owner that retains every reached failed frontier.
    ///
    /// # Errors
    /// Returns the ordinary codec error, or refuses a repeated capture attempt.
    pub fn decode_retaining(
        bytes: &[u8],
        capture: &mut BrokerSessionDurableHistoryDecodeCaptureV1,
    ) -> Result<(), BrokerSessionDurableError> {
        if capture.attempted {
            capture.closed.get_or_insert(BrokerSessionDurableError::InvalidFormat);
            return Err(BrokerSessionDurableError::InvalidFormat);
        }
        capture.attempted = true;
        let result = decode_history(bytes, capture, true);
        capture.result = Some(result.clone());
        result
    }

    /// Encodes the sole canonical full-history representation.
    ///
    /// # Errors
    /// Returns a chain or aggregate allocation ceiling failure.
    pub fn encode(&self) -> Result<Vec<u8>, BrokerSessionDurableError> {
        let mut work = BrokerSessionDurableHistoryEncodeCaptureV1::new();
        self.encode_history(&mut work, false)?;
        work.bytes.take().ok_or(BrokerSessionDurableError::InvalidFormat)
    }

    /// Encodes into an inert owner retaining partial rows and output on refusal.
    ///
    /// # Errors
    /// Returns the ordinary codec error, or refuses a repeated capture attempt.
    pub fn encode_retaining(
        &self,
        capture: &mut BrokerSessionDurableHistoryEncodeCaptureV1,
    ) -> Result<(), BrokerSessionDurableError> {
        if capture.attempted {
            capture.closed.get_or_insert(BrokerSessionDurableError::InvalidFormat);
            return Err(BrokerSessionDurableError::InvalidFormat);
        }
        capture.attempted = true;
        let result = self.encode_history(capture, true);
        capture.result = Some(result.clone());
        result
    }

    fn encode_history(
        &self,
        work: &mut BrokerSessionDurableHistoryEncodeCaptureV1,
        retaining: bool,
    ) -> Result<(), BrokerSessionDurableError> {
        validate_chain_captured(&self.records, retaining, &mut work.chain)?;
        work.encoded_records = Vec::with_capacity(self.records.len());
        let mut capacity = HEADER_BYTES;
        for record in &self.records {
            work.current_bytes = Some(if retaining {
                work.record = Some(BrokerSessionDurableRecordEncodeCaptureV1::new());
                let current = work.record.as_mut().ok_or(BrokerSessionDurableError::InvalidFormat)?;
                record.encode_retaining(current)?;
                current.take_encoded_once()?
            } else {
                record.encode()?
            });
            let bytes = work.current_bytes.as_ref().ok_or(BrokerSessionDurableError::InvalidFormat)?;
            capacity = capacity
                .checked_add(4)
                .and_then(|value| value.checked_add(bytes.len()))
                .ok_or(BrokerSessionDurableError::InvalidLength)?;
            work.encoded_records.push(work.current_bytes.take()
                .ok_or(BrokerSessionDurableError::InvalidFormat)?);
            drop(work.record.take());
        }
        if capacity > BROKER_SESSION_DURABLE_HISTORY_MAXIMUM_BYTES {
            return Err(BrokerSessionDurableError::InvalidLength);
        }
        let count = u32::try_from(work.encoded_records.len())
            .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
        let expected_head = record_commitment(
            self.records.last().ok_or(BrokerSessionDurableError::InvalidLength)?,
            retaining,
            &mut work.head,
        )?;
        if expected_head != self.head_commitment {
            return Err(BrokerSessionDurableError::Continuity);
        }

        drop(work.head.take());
        work.bytes = Some(Vec::with_capacity(capacity));
        let bytes = work.bytes.as_mut().ok_or(BrokerSessionDurableError::InvalidFormat)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes.extend_from_slice(&self.head_commitment);
        work.remaining = Some(std::mem::take(&mut work.encoded_records).into_iter());
        loop {
            work.current_bytes = work.remaining.as_mut()
                .ok_or(BrokerSessionDurableError::InvalidFormat)?.next();
            let Some(record) = work.current_bytes.as_ref() else { break; };
            let length = u32::try_from(record.len())
                .map_err(|_| BrokerSessionDurableError::InvalidLength)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(record);
            drop(work.current_bytes.take());
        }
        drop(work.remaining.take());
        Ok(())
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
    /// Hashes the canonical representation while retaining a failed encoding.
    ///
    /// # Errors
    /// Returns the ordinary encoding error, or refuses a repeated capture.
    pub fn commitment_retaining(
        &self,
        capture: &mut BrokerSessionDurableHistoryEncodeCaptureV1,
    ) -> Result<[u8; 32], BrokerSessionDurableError> {
        self.encode_retaining(capture)?;
        let bytes = capture.encoded().ok_or(BrokerSessionDurableError::InvalidFormat)?;
        let mut digest = Sha256::new();
        digest.update(b"aos-sandbox-broker-session-durable-history-v1\0");
        digest.update(bytes);
        Ok(digest.finalize().into())
    }

}

fn validate_chain_captured(
    records: &[BrokerSessionDurableRecordV1],
    retaining: bool,
    commitment: &mut Option<BrokerSessionDurableRecordEncodeCaptureV1>,
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
            || current.predecessor() != record_commitment(previous, retaining, commitment)?
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
        // The complete pair comparison no longer borrows its commitment bytes.
        drop(commitment.take());
    }
    Ok(())
}

fn decode_history(
    bytes: &[u8],
    work: &mut BrokerSessionDurableHistoryDecodeCaptureV1,
    retaining: bool,
) -> Result<(), BrokerSessionDurableError> {
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
    // An advertised count alone must not allocate a history. Grow only
    // after the next complete record passes its existing validation.
    work.records = Vec::new();
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
        if retaining {
            work.current_record = Some(BrokerSessionDurableRecordDecodeCaptureV1::new());
            let current = work.current_record.as_mut()
                .ok_or(BrokerSessionDurableError::InvalidFormat)?;
            BrokerSessionDurableRecordV1::decode_retaining(record_bytes, current)?;
            work.records.push(current.take_record_once()?);
            // The parent owns the actual record before its completed scratch drops.
            drop(work.current_record.take());
        } else {
            work.records.push(BrokerSessionDurableRecordV1::decode(record_bytes)?);
        }
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    let head_commitment = validated_head(&work.records, retaining, &mut work.chain)?;
    work.history = Some(BrokerSessionDurableHistoryV1 {
        records: std::mem::take(&mut work.records),
        head_commitment,
    });
    let history = work.history.as_ref().ok_or(BrokerSessionDurableError::InvalidFormat)?;
    if history.head_commitment != encoded_head {
        return Err(BrokerSessionDurableError::InvalidFormat);
    }
    // The actual selected head bytes stay parked through the outer equality.
    drop(work.chain.take());
    let matches = if retaining {
        work.canonical = Some(BrokerSessionDurableHistoryEncodeCaptureV1::new());
        let canonical = work.canonical.as_mut().ok_or(BrokerSessionDurableError::InvalidFormat)?;
        history.encode_retaining(canonical)?;
        canonical.encoded() == Some(bytes)
    } else {
        history.encode()?.as_slice() == bytes
    };
    if !matches {
        return Err(BrokerSessionDurableError::InvalidFormat);
    }
    // No later pure check borrows the canonical comparison buffer.
    drop(work.canonical.take());
    Ok(())
}

fn validated_head(
    records: &[BrokerSessionDurableRecordV1],
    retaining: bool,
    capture: &mut Option<BrokerSessionDurableRecordEncodeCaptureV1>,
) -> Result<[u8; 32], BrokerSessionDurableError> {
    if records.is_empty() || records.len() > MAXIMUM_RECORDS {
        return Err(BrokerSessionDurableError::InvalidLength);
    }
    validate_chain_captured(records, retaining, capture)?;
    let head = record_commitment(
        records.last().ok_or(BrokerSessionDurableError::InvalidLength)?,
        retaining,
        capture,
    )?;
    // A selected caller still owes its outer encoded-head comparison.
    if !retaining {
        drop(capture.take());
    }
    Ok(head)
}

fn record_commitment(
    record: &BrokerSessionDurableRecordV1,
    retaining: bool,
    capture: &mut Option<BrokerSessionDurableRecordEncodeCaptureV1>,
) -> Result<[u8; 32], BrokerSessionDurableError> {
    if retaining {
        *capture = Some(BrokerSessionDurableRecordEncodeCaptureV1::new());
        record.commitment_retaining(capture.as_mut()
            .ok_or(BrokerSessionDurableError::InvalidFormat)?)
    } else {
        record.commitment()
    }
}
