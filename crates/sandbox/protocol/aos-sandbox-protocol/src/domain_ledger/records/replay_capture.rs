//! Retains reached portable projection DATA in the shared replay engine.
//!
//! These owners contain no journal, payer, validation callback or currentness
//! authority. The actual caller pays reached widths before entry. Schema-owned
//! validator internals remain the concrete schema owner's responsibility.

use super::*;
use std::mem::{size_of, take};

mod candidates;
pub use candidates::{CurrentRecordCandidatesCaptureV1, current_record_candidates_with_capture_v1};

mod member_capture;
pub use member_capture::{DurableMemberCaptureV1, decode_durable_member_with_schema_capture_v1};

mod key_capture;
pub use key_capture::{DomainKeyDecodeCaptureV1, decode_domain_key_retaining_v1};

mod schema;
pub use schema::{
    ProtectedDomainSchemaReplayCaptureV1,
    decode_reducer_payload_with_schema_capture_v1,
    replay_projection_records_with_schema_capture_v1,
};
pub(super) use schema::{OrdinarySchemaReplayV1, SchemaReplayDispositionV1};

/// Retains a single projection replay, including partial decoding and grouping.
///
/// Successful projection DATA moves only once. Failure and repeated entry keep
/// the original work and first error resident; creating this sink performs no IO.
#[must_use = "retain this sink beside the actual replay input through its posts"]
pub struct ReplayProjectionRecordsCaptureV1<S: ProtectedDomainSchemaV1> {
    work: ProjectionReplayWorkV1<S>,
    projection: Option<ProtectedDomainProjectionV1<S>>,
    completion: Option<Result<(), DomainLedgerDataError>>,
    closed: Option<DomainLedgerDataError>,
    entered: bool,
    taken: bool,
}

impl<S: ProtectedDomainSchemaV1> ReplayProjectionRecordsCaptureV1<S> {
    /// Creates an inert, allocation-free destination.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            work: ProjectionReplayWorkV1::new(),
            projection: None,
            completion: None,
            closed: None,
            entered: false,
            taken: false,
        }
    }

    /// Borrows the original first replay error before any later reentry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&DomainLedgerDataError> {
        self.completion.as_ref().and_then(|result| result.as_ref().err())
            .or(self.closed.as_ref())
    }

    /// Borrows completed projection DATA without granting currentness.
    #[must_use]
    pub fn projection(&self) -> Option<&ProtectedDomainProjectionV1<S>> {
        if self.failure().is_none() {
            self.projection.as_ref()
        } else {
            None
        }
    }

    /// Moves the actual completed projection once, preserving failed work.
    #[must_use]
    pub fn take_projection_once(&mut self) -> Option<ProtectedDomainProjectionV1<S>> {
        if self.taken || self.failure().is_some()
            || !matches!(self.completion, Some(Ok(())))
        {
            return None;
        }
        self.taken = true;
        self.projection.take()
    }

    /// Sizes the inline retained owner without allocating it.
    #[must_use]
    pub const fn receiving_inline_bytes_v1() -> usize {
        size_of::<Self>()
    }

    /// Bounds a concrete construction temporary plus its retained destination.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)?
            .checked_add(size_of::<borrowed::DurableMemberFrameDataV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<borrowed::ProtectedEnvelopeFrameDataV1<'_>>().checked_mul(2)?)?
            .checked_add(size_of::<borrowed::ReducerFrameDataV1<'_>>().checked_mul(2)?)
    }

    /// Bounds reached typed work carriers, excluding their encoded byte backing.
    ///
    /// The caller supplies actual reached rows, including one current partial.
    /// This uses concrete portable types; it is not an allowance or configured
    /// maximum. Byte backing is charged separately from actual prefix bytes.
    #[must_use]
    pub fn receiving_carrier_bytes_v1(reached_rows: usize) -> Option<usize> {
        let row = size_of::<DurableDomainMemberV1<S>>().checked_mul(3)?
            .checked_add(size_of::<ProtectedDomainEnvelopeV1<S>>().checked_mul(2)?)?
            .checked_add(size_of::<ProtectedDomainReplayTransactionV1<S>>())?
            .checked_add(size_of::<JournalRecord>())?
            .checked_add(size_of::<Vec<u8>>())?
            .checked_add(size_of::<usize>().checked_mul(32)?)?
            .checked_add(size_of::<ProtectedReducerPhaseV1>())?;
        // Four cells cover Vec's first growth even for one reached member.
        row.checked_mul(reached_rows.max(4))
    }

    /// Bounds the owned byte copies of an actual reached encoded row prefix.
    ///
    /// This excludes typed carrier cells, which the separate supplier prices.
    #[must_use]
    pub const fn receiving_encoded_backing_bytes_v1(reached_input_bytes: usize) -> Option<usize> {
        reached_input_bytes.checked_mul(8)
    }

    /// Bounds named rows, lookup entries, group indices and transactions.
    ///
    /// The member/final-projection row plane, seen-key set, transaction groups,
    /// group-member indices, cloned transaction envelopes, canonical journal
    /// records and completed transactions are distinct named collections. Each
    /// has at most one entry per reached row. Moving a member into the final
    /// projection or a group into active scratch does not create another plane.
    /// Fields, phase scalars, Vec capacity and encoded buffers are Memory only.
    #[must_use]
    pub fn receiving_named_entries_v2(reached_rows: usize) -> Option<usize> {
        reached_rows.checked_mul(7)
    }

    /// Bounds retained collection and result destinations for actual reached rows.
    #[must_use]
    pub fn receiving_metadata_cells_v1(reached_rows: usize) -> Option<usize> {
        // Twenty-eight fixed fields, one bounded current companion array and
        // the two derived companion cells coexist with reached row entries.
        reached_rows.checked_mul(12)?.checked_add(28 + MAXIMUM_REDUCER_COMPANIONS + 2)
    }
}

impl<S: ProtectedDomainSchemaV1> Default for ReplayProjectionRecordsCaptureV1<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Replays the same portable engine into an actual retained partial destination.
///
/// # Errors
///
/// Returns a noncanonical marker after retaining the original detailed replay
/// failure. Reentry keeps that original cause and all reached work unchanged.
/// Arbitrary schema-validator internal allocations are outside this DATA sink.
pub fn replay_projection_records_retaining_v1<'records, S: ProtectedDomainSchemaV1>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    validator: &S::ReplayValidator,
    capture: &mut ReplayProjectionRecordsCaptureV1<S>,
) -> Result<(), DomainLedgerDataError> {
    if capture.entered {
        capture.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    capture.entered = true;
    capture.completion = Some(match replay(records, validator, &mut capture.work, &mut OrdinarySchemaReplayV1) {
        Ok(projection) => {
            capture.projection = Some(projection);
            Ok(())
        }
        Err(cause) => Err(cause),
    });
    if matches!(capture.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}

/// Retains generic reducer decoding scratch without borrowing its input buffer.
///
/// The actual caller keeps the original payload beside this owner. Body offsets
/// are passive DATA, not a proof that a replacement byte slice was validated.
#[must_use = "retain this owner beside the actual reducer payload through its posts"]
pub struct ReducerPayloadDecodeCaptureV1 {
    derived: Vec<ObjectDigest>,
    encoded_derived: Vec<u8>,
    companions: Vec<ObjectDigest>,
    body: Option<std::ops::Range<usize>>,
    phase: Option<ProtectedReducerPhaseV1>,
    completion: Option<Result<(), DomainLedgerDataError>>,
    closed: Option<DomainLedgerDataError>,
    entered: bool,
}

impl ReducerPayloadDecodeCaptureV1 {
    /// Creates inert destinations without allocating or parsing input.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            derived: Vec::new(),
            encoded_derived: Vec::new(),
            companions: Vec::new(),
            body: None,
            phase: None,
            completion: None,
            closed: None,
            entered: false,
        }
    }

    /// Borrows the actual first error before a later repeated-entry marker.
    #[must_use]
    pub fn failure(&self) -> Option<&DomainLedgerDataError> {
        self.completion.as_ref().and_then(|result| result.as_ref().err())
            .or(self.closed.as_ref())
    }

    /// Returns offsets into the same actual retained input after complete decoding.
    #[must_use]
    pub fn body_range_v1(&self) -> Option<std::ops::Range<usize>> {
        if self.failure().is_none() { self.body.clone() } else { None }
    }

    /// Returns the decoded phase as DATA after complete decoding.
    #[must_use]
    pub fn phase_v1(&self) -> Option<ProtectedReducerPhaseV1> {
        if self.failure().is_none() { self.phase } else { None }
    }

    /// Borrows the actual reached decoded companion vector.
    #[must_use]
    pub fn companions(&self) -> &[ObjectDigest] {
        &self.companions
    }

    /// Bounds a construction temporary and its retained inline destination.
    #[must_use]
    pub const fn receiving_construction_bytes_v1() -> Option<usize> {
        size_of::<Self>().checked_mul(2)
    }

    /// Bounds the fixed destinations and one reached companion array.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> usize {
        8 + MAXIMUM_REDUCER_COMPANIONS + 2
    }
}

impl Default for ReducerPayloadDecodeCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Decodes reducer DATA through the same engine into an owned partial sink.
///
/// # Errors
///
/// Retains the generic decoder's original first failure and rejects reentry.
/// The schema validator's opaque typed internals remain its owner's responsibility.
pub fn decode_reducer_payload_retaining_v1<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &[u8],
    validator: &S::ReplayValidator,
    capture: &mut ReducerPayloadDecodeCaptureV1,
) -> Result<(), DomainLedgerDataError> {
    if capture.entered {
        capture.closed.get_or_insert(DomainLedgerDataError::NonCanonicalRecord);
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    capture.entered = true;
    capture.completion = Some(match decode_reducer_into_work(
        key, bytes, validator,
        &mut capture.derived, &mut capture.encoded_derived, &mut capture.companions,
        &mut OrdinarySchemaReplayV1,
    ) {
        Some((phase, body)) => {
            capture.phase = Some(phase);
            capture.body = Some(body);
            Ok(())
        }
        None => Err(DomainLedgerDataError::NonCanonicalRecord),
    });
    if matches!(capture.completion, Some(Ok(()))) {
        Ok(())
    } else {
        Err(DomainLedgerDataError::NonCanonicalRecord)
    }
}

pub(super) struct MemberDecodeWorkV1<S: ProtectedDomainSchemaV1> {
    identity: Vec<u8>,
    key: Option<ProtectedDomainKeyV1<S>>,
    payload: Vec<u8>,
    envelope: Option<ProtectedDomainEnvelopeV1<S>>,
    roundtrip: Vec<u8>,
    inner: Vec<u8>,
    encoded: Vec<u8>,
    member: Option<DurableDomainMemberV1<S>>,
    derived: Vec<ObjectDigest>,
    encoded_derived: Vec<u8>,
    decoded_companions: Vec<ObjectDigest>,
}

impl<S: ProtectedDomainSchemaV1> MemberDecodeWorkV1<S> {
    pub(super) const fn new() -> Self {
        Self {
            identity: Vec::new(),
            key: None,
            payload: Vec::new(),
            envelope: None,
            roundtrip: Vec::new(),
            inner: Vec::new(),
            encoded: Vec::new(),
            member: None,
            derived: Vec::new(),
            encoded_derived: Vec::new(),
            decoded_companions: Vec::new(),
        }
    }
}

pub(super) struct TransactionReplayWorkV1<S: ProtectedDomainSchemaV1> {
    grouped: BTreeMap<[u8; 16], Vec<usize>>,
    group: Vec<usize>,
    records: Vec<ProtectedDomainEnvelopeV1<S>>,
    phases: Vec<ProtectedReducerPhaseV1>,
    transaction: Option<JournalTransaction>,
    transactions: Vec<ProtectedDomainReplayTransactionV1<S>>,
}

impl<S: ProtectedDomainSchemaV1> TransactionReplayWorkV1<S> {
    pub(super) const fn new() -> Self {
        Self {
            grouped: BTreeMap::new(),
            group: Vec::new(),
            records: Vec::new(),
            phases: Vec::new(),
            transaction: None,
            transactions: Vec::new(),
        }
    }
}

pub(super) struct ProjectionReplayWorkV1<S: ProtectedDomainSchemaV1> {
    members: Vec<DurableDomainMemberV1<S>>,
    seen: BTreeSet<Vec<u8>>,
    seen_candidate: Option<Vec<u8>>,
    decode: MemberDecodeWorkV1<S>,
    reconstruction: TransactionReplayWorkV1<S>,
}

impl<S: ProtectedDomainSchemaV1> ProjectionReplayWorkV1<S> {
    pub(super) const fn new() -> Self {
        Self {
            members: Vec::new(),
            seen: BTreeSet::new(),
            seen_candidate: None,
            decode: MemberDecodeWorkV1::new(),
            reconstruction: TransactionReplayWorkV1::new(),
        }
    }
}

pub(super) fn replay<'records, S: ProtectedDomainSchemaV1>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    validator: &S::ReplayValidator,
    work: &mut ProjectionReplayWorkV1<S>,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> Result<ProtectedDomainProjectionV1<S>, DomainLedgerDataError> {
    for (namespace, key_bytes, value) in records {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        // The original identity survives even a schema identity refusal.
        work.decode.key = Some(decode_key::<S>(key_bytes, &mut work.decode)?);
        let key = work.decode.key.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        if namespace != S::namespace(key.kind) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        work.seen_candidate = Some(key_bytes.to_vec());
        if work.seen.contains(key_bytes) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        work.seen.insert(work.seen_candidate.take()
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?);
        if work.members.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let key = work.decode.key.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        work.members.push(decode_member::<S>(key, value, validator, &mut work.decode, disposition)?);
        // The complete member owns the result. Completed pure roundtrip scratch
        // has no late borrowers and is disposed before the next input row.
        work.decode = MemberDecodeWorkV1::new();
    }
    work.members.sort_by(|left, right| {
        (
            S::namespace(left.envelope.key.kind) as u8,
            left.envelope.key.as_bytes(),
        )
            .cmp(&(
                S::namespace(right.envelope.key.kind) as u8,
                right.envelope.key.as_bytes(),
            ))
    });
    let mut hasher = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"materialized-projection\0")
        .chain_update((work.members.len() as u64).to_be_bytes());
    for member in &work.members {
        hasher = hasher
            .chain_update([S::namespace(member.envelope.key.kind) as u8])
            .chain_update((member.envelope.key.as_bytes().len() as u32).to_be_bytes())
            .chain_update(member.envelope.key.as_bytes())
            .chain_update((member.encoded.len() as u64).to_be_bytes())
            .chain_update(&member.encoded);
    }
    let transactions = reconstruct(&work.members, &mut work.reconstruction)?;
    let records = take(&mut work.members).into_iter().map(|member| member.envelope).collect();
    Ok(ProtectedDomainProjectionV1 {
        records,
        transactions,
        root: ObjectDigest::from_bytes(hasher.finalize().into()),
    })
}

fn construct_key<S: ProtectedDomainSchemaV1>(
    kind: S::Kind, work: &mut MemberDecodeWorkV1<S>,
) -> Result<ProtectedDomainKeyV1<S>, DomainLedgerDataError> {
    if work.identity.is_empty()
        || work.identity.len() > MAXIMUM_DOMAIN_IDENTITY_BYTES
        || !S::validates_identity(kind, &work.identity)
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let identity_length =
        u16::try_from(work.identity.len()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let mut encoded = Vec::with_capacity(ProtectedDomainKeyV1::<S>::
        encoded_bytes_for_identity_v1(work.identity.len())?);
    encoded.extend_from_slice(S::KEY_PREFIX);
    encoded.push(ENVELOPE_VERSION as u8);
    encoded.push(S::kind_code(kind));
    encoded.extend_from_slice(&identity_length.to_be_bytes());
    encoded.extend_from_slice(&work.identity);

    Ok(ProtectedDomainKeyV1 {
        kind,
        identity: take(&mut work.identity),
        encoded,
        marker: PhantomData,
    })
}

pub(super) fn new_key<S: ProtectedDomainSchemaV1>(
    kind: S::Kind, identity: Vec<u8>,
) -> Result<ProtectedDomainKeyV1<S>, DomainLedgerDataError> {
    let mut work = MemberDecodeWorkV1::new();
    work.identity = identity;
    construct_key(kind, &mut work)
}

fn key_kind<S: ProtectedDomainSchemaV1>(encoded: &[u8]) -> Result<S::Kind, DomainLedgerDataError> {
    let (kind, _) = borrowed::borrow_protected_key_data_v1(encoded, S::KEY_PREFIX)?;
    S::kind_from_code(kind).ok_or(DomainLedgerDataError::NonCanonicalRecord)
}

pub(super) fn ordinary_decode_key<S: ProtectedDomainSchemaV1>(encoded: &[u8])
    -> Result<ProtectedDomainKeyV1<S>, DomainLedgerDataError>
{
    decode_key(encoded, &mut MemberDecodeWorkV1::new())
}

fn decode_key<S: ProtectedDomainSchemaV1>(encoded: &[u8], work: &mut MemberDecodeWorkV1<S>)
    -> Result<ProtectedDomainKeyV1<S>, DomainLedgerDataError>
{
    let kind = key_kind::<S>(encoded)?;
    work.identity = encoded[S::KEY_PREFIX.len() + 4..].to_vec();
    let key = construct_key(kind, work)?;
    work.key = Some(key);
    if work.key.as_ref().is_none_or(|key| key.as_bytes() != encoded) {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    work.key.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)
}

pub(super) fn new_envelope<S: ProtectedDomainSchemaV1>(
    key: ProtectedDomainKeyV1<S>, revision: u64, predecessor: Option<ObjectDigest>,
    payload: Vec<u8>, validator: &S::ReplayValidator, work: &mut MemberDecodeWorkV1<S>,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> Result<ProtectedDomainEnvelopeV1<S>, DomainLedgerDataError> {
    work.key = Some(key);
    work.payload = payload;

    let kind = work.key.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?.kind;
    let validated_phase = if S::is_checkpoint(kind) {
        valid_checkpoint_payload::<S>(&work.payload).then_some(ProtectedReducerPhaseV1::Terminal)
    } else {
        retained_reducer_phase(work, validator, disposition)
    };
    if revision == 0
        || revision == u64::MAX
        || (revision == 1) != predecessor.is_none()
        || predecessor.is_some_and(|digest| digest.as_bytes() == &[0; 32])
        || work.payload.is_empty()
        || work.payload.len() > S::MAXIMUM_PAYLOAD_BYTES
        || validated_phase.is_none()
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let digest = envelope_digest::<S>(
        work.key.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        revision, predecessor, &work.payload,
    );
    Ok(ProtectedDomainEnvelopeV1 {
        key: work.key.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        revision,
        predecessor,
        payload: take(&mut work.payload),
        digest,
        validated_phase: validated_phase.ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
    })
}

pub(super) fn decode_envelope<S: ProtectedDomainSchemaV1>(
    key: ProtectedDomainKeyV1<S>, bytes: &[u8], validator: &S::ReplayValidator,
    work: &mut MemberDecodeWorkV1<S>,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> Result<ProtectedDomainEnvelopeV1<S>, DomainLedgerDataError> {
    work.key = Some(key);
    let frame = borrowed::ProtectedEnvelopeFrameDataV1::decode_structure(
        bytes,
        &S::MAGIC, S::kind_code(work.key.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?.kind),
        S::MAXIMUM_PAYLOAD_BYTES,
    )?;
    let revision = frame.revision;
    let predecessor = frame.predecessor;
    let payload_end = bytes.len() - 32;
    let candidate = new_envelope(
        work.key.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        revision,
        predecessor,
        frame.payload.to_vec(),
        validator, work, disposition,
    )?;
    work.envelope = Some(candidate);
    let candidate = work.envelope.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    work.roundtrip = candidate.encode();
    if candidate.digest.as_bytes() != &bytes[payload_end..]
        || work.roundtrip.as_slice() != bytes
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    work.envelope.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)
}

pub(super) fn encode_member<S: ProtectedDomainSchemaV1>(
    transaction_id: [u8; 16], member_index: u16, member_count: u16,
    set_digest: ObjectDigest, envelope: ProtectedDomainEnvelopeV1<S>,
    work: &mut MemberDecodeWorkV1<S>,
) -> Result<DurableDomainMemberV1<S>, DomainLedgerDataError> {
    work.envelope = Some(envelope);
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.as_bytes() == &[0; 32]
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    work.inner = work.envelope.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?.encode();
    let inner_length =
        u32::try_from(work.inner.len()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    work.encoded = Vec::with_capacity(DURABLE_MEMBER_FIXED_BYTES + work.inner.len());
    work.encoded.extend_from_slice(DURABLE_MEMBER_MAGIC);
    work.encoded.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    work.encoded.extend_from_slice(&[0; 2]);
    work.encoded.extend_from_slice(&transaction_id);
    work.encoded.extend_from_slice(&member_index.to_be_bytes());
    work.encoded.extend_from_slice(&member_count.to_be_bytes());
    work.encoded.extend_from_slice(set_digest.as_bytes());
    work.encoded.extend_from_slice(&inner_length.to_be_bytes());
    work.encoded.extend_from_slice(&work.inner);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"durable-member\0")
        .chain_update(&work.encoded)
        .finalize()
        .into();
    work.encoded.extend_from_slice(&digest);
    Ok(DurableDomainMemberV1 {
        transaction_id,
        member_index,
        member_count,
        set_digest,
        envelope: work.envelope.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        encoded: take(&mut work.encoded),
    })
}

pub(super) fn decode_member<S: ProtectedDomainSchemaV1>(
    key: ProtectedDomainKeyV1<S>, bytes: &[u8], validator: &S::ReplayValidator,
    work: &mut MemberDecodeWorkV1<S>,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> Result<DurableDomainMemberV1<S>, DomainLedgerDataError> {
    work.key = Some(key);
    let frame = borrowed::DurableMemberFrameDataV1::decode(bytes, S::MAXIMUM_PAYLOAD_BYTES, S::HASH_DOMAIN)?;
    let transaction_id = frame.transaction_id;
    let member_index = frame.member_index;
    let member_count = frame.member_count;
    let set_digest = frame.set_digest;
    let envelope = decode_envelope(work.key.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        frame.envelope, validator, work, disposition)?;
    let member = encode_member(
        transaction_id,
        member_index,
        member_count,
        set_digest,
        envelope, work,
    )?;
    work.member = Some(member);
    if work.member.as_ref().ok_or(DomainLedgerDataError::NonCanonicalRecord)?.encoded.as_slice() != bytes {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    work.member.take().ok_or(DomainLedgerDataError::NonCanonicalRecord)
}

fn valid_reducer<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>, bytes: &[u8], validator: &S::ReplayValidator,
    derived: &mut Vec<ObjectDigest>, encoded_derived: &mut Vec<u8>,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> bool {
    let Ok(frame) = borrowed::ReducerFrameDataV1::decode_structure(bytes, S::family(key.kind),
        S::kind_code(key.kind), S::MAXIMUM_PAYLOAD_BYTES) else { return false; };
    let body = frame.body;
    let companions = frame.companions;
    let phase = frame.phase;
    *derived = derived_companions_with_disposition(key, body, disposition);
    *encoded_derived = encode_digest_slice(derived);
    if disposition.decode_phase(validator, key.kind, &key.identity, body) != Some(phase)
        || companions != encoded_derived.as_slice()
    {
        return false;
    }
    borrowed::ReducerFrameDataV1::require_checksum(bytes, S::HASH_DOMAIN).is_ok()
}

fn decode_reducer_into_work<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &[u8],
    validator: &S::ReplayValidator,
    derived: &mut Vec<ObjectDigest>,
    encoded_derived: &mut Vec<u8>,
    decoded_companions: &mut Vec<ObjectDigest>,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> Option<(ProtectedReducerPhaseV1, std::ops::Range<usize>)> {
    if !valid_reducer(key, bytes, validator, derived, encoded_derived, disposition) {
        return None;
    }
    let phase = decode_phase(bytes[12])?;
    let count = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let companions_end = 20 + count * 32;
    let body_length = usize::try_from(u32::from_be_bytes(
        [bytes[16], bytes[17], bytes[18], bytes[19]],
    )).ok()?;
    let body_end = companions_end + body_length;
    *decoded_companions = bytes[20..companions_end].chunks_exact(32)
        .map(|digest| {
            let bytes: [u8; 32] = digest.try_into().ok()?;
            Some(ObjectDigest::from_bytes(bytes))
        }).collect::<Option<Vec<_>>>()?;
    Some((phase, companions_end..body_end))
}

fn retained_reducer_phase<S: ProtectedDomainSchemaV1>(
    work: &mut MemberDecodeWorkV1<S>,
    validator: &S::ReplayValidator,
    disposition: &mut impl SchemaReplayDispositionV1<S>,
) -> Option<ProtectedReducerPhaseV1> {
    decode_reducer_into_work(
        work.key.as_ref()?, &work.payload, validator,
        &mut work.derived, &mut work.encoded_derived, &mut work.decoded_companions,
        disposition,
    ).map(|(phase, _)| phase)
}

pub(super) fn decode_reducer_payload_ordinary<'payload, S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &'payload [u8],
    validator: &S::ReplayValidator,
) -> Result<DecodedReducerPayloadV1<'payload>, DomainLedgerDataError> {
    let mut work = MemberDecodeWorkV1::<S>::new();
    let (phase, body) = decode_reducer_into_work(
        key, bytes, validator,
        &mut work.derived, &mut work.encoded_derived, &mut work.decoded_companions,
        &mut OrdinarySchemaReplayV1,
    ).ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    Ok(DecodedReducerPayloadV1 {
        body: &bytes[body],
        companions: take(&mut work.decoded_companions),
        phase,
    })
}

pub(super) fn reconstruct<S: ProtectedDomainSchemaV1>(
    members: &[DurableDomainMemberV1<S>], work: &mut TransactionReplayWorkV1<S>,
) -> Result<Vec<ProtectedDomainReplayTransactionV1<S>>, DomainLedgerDataError> {
    for (index, member) in members.iter().enumerate() {
        work.grouped.entry(member.transaction_id).or_default().push(index);
    }
    work.transactions = Vec::with_capacity(work.grouped.len());
    while let Some((transaction_id, group)) = work.grouped.pop_first() {
        work.group = group;
        work.group.sort_by_key(|index| members[*index].member_index);
        let first = &members[*work.group.first().ok_or(DomainLedgerDataError::NonCanonicalRecord)?];
        if work.group.iter().any(|index| {
            let member = &members[*index];
            member.member_count != first.member_count
                || member.set_digest != first.set_digest
                || member.transaction_id != transaction_id
        }) || work.group.windows(2).any(|pair|
            members[pair[0]].member_index == members[pair[1]].member_index)
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let complete = usize::from(first.member_count) == work.group.len()
            && work.group.iter().enumerate()
                .all(|(index, member)| usize::from(members[*member].member_index) == index);
        work.records = work.group.iter().map(|index| members[*index].envelope.clone()).collect();
        let phase = if !complete {
            ProtectedDomainReplayPhaseV1::Incomplete
        } else {
            let recomputed = domain_transaction_set_digest::<S>(transaction_id, &work.records);
            if recomputed != first.set_digest {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            work.phases = Vec::with_capacity(work.records.len());
            for record in &work.records {
                work.phases.push(reducer_phase(record)?);
            }
            match aggregate_semantic_phases(&work.phases) {
                ProtectedReducerPhaseV1::Prepared => ProtectedDomainReplayPhaseV1::Prepared,
                ProtectedReducerPhaseV1::Observed => ProtectedDomainReplayPhaseV1::Observed,
                ProtectedReducerPhaseV1::Terminal => ProtectedDomainReplayPhaseV1::Terminal,
                ProtectedReducerPhaseV1::Superseded => ProtectedDomainReplayPhaseV1::Superseded,
            }
        };
        // Phase aggregation is a completed pure leaf before transaction hashing.
        work.phases = Vec::new();
        let records = work.group.iter().map(|index| {
            let member = &members[*index];
            JournalRecord::put(S::namespace(member.envelope.key.kind),
                member.envelope.key.as_bytes().to_vec(), member.encoded.clone())
        }).collect();
        // Nonzero IDs and nonempty groups were already checked by member
        // decoding. Keeping this DATA before its pure hash needs no new grant.
        work.transaction = Some(JournalTransaction::new(transaction_id, records)?);
        let transaction = transaction_digest::<S>(work.transaction.as_ref()
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?);
        work.transaction = None;
        work.transactions.push(ProtectedDomainReplayTransactionV1 {
            transaction_id, transaction, set_digest: first.set_digest, phase,
            records: take(&mut work.records),
        });
        // Only completed pure scratch is disposed here. Failed current groups,
        // remaining groups and all completed transaction results stay resident.
        work.group = Vec::new();
    }
    Ok(take(&mut work.transactions))
}

#[cfg(test)]
mod tests;
