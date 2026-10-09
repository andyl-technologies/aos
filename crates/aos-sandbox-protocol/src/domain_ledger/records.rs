//! Canonical domain keys, envelopes, durable members, and borrowed replay DATA.
//!
//! Schema validators borrow the original role evidence. These decoded values,
//! phase classifications, and projections do not seal currentness or authorize
//! admission, effects, or protected publication. Actual Journal guards remain upper.
//! The keys, envelopes, durable members, reducer payloads, checkpoint hashes, and
//! whole replay fold share one canonical schema owner; splitting that format
//! ownership would duplicate its validation and reconstruction rules.
//!
//! ```text
//! AOSRDP01 | version:u16be | family/kind/phase:u8 | reserved:u8 |
//! companion-count:u16be | body-length:u32be | sorted digests | body | digest
//! AOSDTX01 | version:u16be | reserved:u16be | transaction-ID:16 |
//! member-index/count:u16be | set-digest:32 | envelope-length:u32be | envelope | digest
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::marker::PhantomData;

use aos_sandbox_core::{ObjectDigest, RecordNamespace};
use sha2::{Digest as _, Sha256};

use super::DomainLedgerDataError;
use super::capacity::{
    GlobalCapacityReservationRequestV1, capacity_reservation_identity_is_exact_v1,
};
use super::transaction::{JournalRecord, JournalTransaction};

const ENVELOPE_VERSION: u16 = 1;
const MAXIMUM_DOMAIN_IDENTITY_BYTES: usize = 512;
const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSDCP01";
const REDUCER_PAYLOAD_MAGIC: &[u8; 8] = b"AOSRDP01";
const MAXIMUM_REDUCER_COMPANIONS: usize = 64;
const DURABLE_MEMBER_MAGIC: &[u8; 8] = b"AOSDTX01";
/// Sizes the fixed envelope representation before payload DATA.
pub const ENVELOPE_FIXED_BYTES: usize = 88;
/// Sizes the fixed durable-member representation before envelope DATA.
pub const DURABLE_MEMBER_FIXED_BYTES: usize = 100;

/// Bounds the number of materialized members examined during cold replay.
pub const MAXIMUM_COLD_REPLAY_MEMBERS: usize = 262_144;

/// Classifies record-role DATA; it releases no authority without protected readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedRecordRoleV1 {
    /// Retains ordinary durable state without releasing an external action.
    State,
    /// Publishes a new protected current-state or checkpoint projection.
    Publication,
    /// Records effect intent or effect observation.
    Effect,
}

/// Classifies decoded reducer state without inferring progress from storage role.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ProtectedReducerPhaseV1 {
    /// Durable intent exists and its external action remains eligible.
    Prepared = 1,
    /// Durable observation proves the action was reconciled.
    Observed = 2,
    /// The reducer state is terminal and releases no further effect.
    Terminal = 3,
    /// A newer semantic generation superseded this action.
    Superseded = 4,
}

/// Borrows settlement-member DATA for the actual owner's capacity-lineage validation.
pub struct ProtectedCapacitySettlementMemberV1<'member, K> {
    /// Supplied closed schema kind, not evidence of validation.
    kind: K,
    /// Supplied identity DATA under the original borrow.
    identity: &'member [u8],
    /// Supplied reducer-body DATA under the original borrow.
    body: &'member [u8],
}

impl<'member, K> ProtectedCapacitySettlementMemberV1<'member, K> {
    /// Borrows explicitly unvalidated settlement DATA under its original lifetime.
    #[must_use]
    pub const fn from_unvalidated_data(
        kind: K,
        identity: &'member [u8],
        body: &'member [u8],
    ) -> Self {
        Self {
            kind,
            identity,
            body,
        }
    }

    /// Returns the closed schema kind supplied by the caller.
    #[must_use]
    pub const fn kind(&self) -> K
    where
        K: Copy,
    {
        self.kind
    }

    /// Returns the borrowed identity DATA.
    #[must_use]
    pub const fn identity(&self) -> &'member [u8] {
        self.identity
    }

    /// Returns the borrowed canonical-body DATA.
    #[must_use]
    pub const fn body(&self) -> &'member [u8] {
        self.body
    }
}

/// Defines one closed protected-journal domain.
pub trait ProtectedDomainSchemaV1: Copy + Debug + Eq + Ord + 'static {
    /// Closed domain-specific record kind.
    type Kind: Copy + Debug + Eq + Ord;
    /// Trusted evidence required to authenticate durable reducer bodies.
    type ReplayValidator: Clone;

    /// Eight-byte canonical value magic.
    const MAGIC: [u8; 8];
    /// Domain-separated hash prefix.
    const HASH_DOMAIN: &'static [u8];
    /// Canonical binary key prefix.
    const KEY_PREFIX: &'static [u8];
    /// Maximum canonical payload accepted for one materialized record.
    const MAXIMUM_PAYLOAD_BYTES: usize;

    /// Maps a closed kind to its encoded discriminant.
    fn kind_code(kind: Self::Kind) -> u8;
    /// Decodes a closed kind discriminant.
    fn kind_from_code(code: u8) -> Option<Self::Kind>;
    /// Selects the fixed shared-journal namespace for a kind.
    fn namespace(kind: Self::Kind) -> RecordNamespace;
    /// Returns the canonical within-domain transaction order.
    fn order(kind: Self::Kind) -> u8;
    /// Classifies record-role DATA for upper protected readback.
    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1;
    /// Reports whether the kind is a replay checkpoint.
    fn is_checkpoint(kind: Self::Kind) -> bool;
    /// Returns the closed reducer transaction family for the kind.
    fn family(kind: Self::Kind) -> u8;
    /// Decodes and canonically validates a kind-specific reducer body.
    fn decode_reducer_phase(
        validator: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1>;
    /// Derives a shared project/subject tuple for explicit cross-domain joins.
    fn semantic_tuple(_kind: Self::Kind, _identity: &[u8], _body: &[u8]) -> Option<[u8; 32]> {
        None
    }
    /// Validates the exact terminal successor group for retained capacity.
    fn validates_capacity_settlement(
        _request: &GlobalCapacityReservationRequestV1,
        _admission_transaction_id: [u8; 16],
        _members: &[ProtectedCapacitySettlementMemberV1<'_, Self::Kind>],
    ) -> bool {
        false
    }
    /// Validates the exact domain identity layout for the kind.
    fn validates_identity(kind: Self::Kind, identity: &[u8]) -> bool;
}

/// Names one canonical domain record without exposing namespace selection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtectedDomainKeyV1<S: ProtectedDomainSchemaV1> {
    kind: S::Kind,
    identity: Vec<u8>,
    encoded: Vec<u8>,
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> ProtectedDomainKeyV1<S> {
    /// Constructs a bounded canonical key for a typed domain identity.
    ///
    /// # Errors
    ///
    /// Returns [`DomainLedgerDataError::NonCanonicalRecord`] when the
    /// identity is empty or exceeds the fixed domain-key ceiling.
    pub fn new(kind: S::Kind, identity: Vec<u8>) -> Result<Self, DomainLedgerDataError> {
        if identity.is_empty()
            || identity.len() > MAXIMUM_DOMAIN_IDENTITY_BYTES
            || !S::validates_identity(kind, &identity)
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let identity_length =
            u16::try_from(identity.len()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
        let mut encoded = Vec::with_capacity(S::KEY_PREFIX.len() + 4 + identity.len());
        encoded.extend_from_slice(S::KEY_PREFIX);
        encoded.push(ENVELOPE_VERSION as u8);
        encoded.push(S::kind_code(kind));
        encoded.extend_from_slice(&identity_length.to_be_bytes());
        encoded.extend_from_slice(&identity);

        Ok(Self {
            kind,
            identity,
            encoded,
            marker: PhantomData,
        })
    }

    /// Returns the closed domain record kind.
    #[must_use]
    pub const fn kind(&self) -> S::Kind {
        self.kind
    }

    /// Returns the canonical domain-specific identity bytes.
    #[must_use]
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Returns the canonical shared-journal key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Decodes and round-trips one bounded, closed-schema key.
    ///
    /// # Errors
    ///
    /// Rejects an unknown kind, invalid identity, version, length, or alternate encoding.
    pub fn decode(encoded: &[u8]) -> Result<Self, DomainLedgerDataError> {
        let header = S::KEY_PREFIX.len() + 4;
        if encoded.len() < header || !encoded.starts_with(S::KEY_PREFIX) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let version = encoded[S::KEY_PREFIX.len()];
        let kind = S::kind_from_code(encoded[S::KEY_PREFIX.len() + 1])
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        let length_offset = S::KEY_PREFIX.len() + 2;
        let identity_length = usize::from(u16::from_be_bytes([
            encoded[length_offset],
            encoded[length_offset + 1],
        ]));
        if version != ENVELOPE_VERSION as u8
            || identity_length == 0
            || identity_length > MAXIMUM_DOMAIN_IDENTITY_BYTES
            || encoded.len() != header + identity_length
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        Self::new(kind, encoded[header..].to_vec()).and_then(|key| {
            (key.as_bytes() == encoded)
                .then_some(key)
                .ok_or(DomainLedgerDataError::NonCanonicalRecord)
        })
    }
}

/// Carries one bounded canonical domain value and its exact lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedDomainEnvelopeV1<S: ProtectedDomainSchemaV1> {
    key: ProtectedDomainKeyV1<S>,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    payload: Vec<u8>,
    digest: ObjectDigest,
    validated_phase: ProtectedReducerPhaseV1,
}

impl<S: ProtectedDomainSchemaV1> ProtectedDomainEnvelopeV1<S> {
    /// Constructs one canonical successor envelope.
    ///
    /// Revision one has no predecessor; every later revision requires an exact
    /// nonzero predecessor commitment. The payload is retained byte-for-byte.
    /// The original borrowed schema validator checks its reducer body first;
    /// the resulting envelope is DATA, not a currentness or admission proof.
    ///
    /// # Errors
    ///
    /// Returns [`DomainLedgerDataError::NonCanonicalRecord`] for a
    /// sentinel revision, broken predecessor shape, invalid reducer body, or oversized payload.
    pub fn new_with_validator(
        key: ProtectedDomainKeyV1<S>,
        revision: u64,
        predecessor: Option<ObjectDigest>,
        payload: Vec<u8>,
        validator: &S::ReplayValidator,
    ) -> Result<Self, DomainLedgerDataError> {
        let validated_phase = if S::is_checkpoint(key.kind) {
            valid_checkpoint_payload::<S>(&payload).then_some(ProtectedReducerPhaseV1::Terminal)
        } else {
            decode_reducer_payload_with_validator::<S>(&key, &payload, validator)
                .ok()
                .map(|payload| payload.phase())
        };
        if revision == 0
            || revision == u64::MAX
            || (revision == 1) != predecessor.is_none()
            || predecessor.is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || payload.is_empty()
            || payload.len() > S::MAXIMUM_PAYLOAD_BYTES
            || validated_phase.is_none()
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let digest = envelope_digest::<S>(&key, revision, predecessor, &payload);
        Ok(Self {
            key,
            revision,
            predecessor,
            payload,
            digest,
            validated_phase: validated_phase.ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        })
    }

    /// Returns the canonical journal key.
    #[must_use]
    pub const fn key(&self) -> &ProtectedDomainKeyV1<S> {
        &self.key
    }

    /// Returns the namespace-local monotone revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact predecessor envelope commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Returns the exact canonical domain payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the complete envelope commitment used by successor CAS.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the schema-decoded phase DATA, not currentness or effect permission.
    pub const fn validated_phase(&self) -> ProtectedReducerPhaseV1 {
        self.validated_phase
    }

    /// Encodes the envelope into its unique bounded representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENVELOPE_FIXED_BYTES + self.payload.len());
        bytes.extend_from_slice(&S::MAGIC);
        bytes.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        bytes.push(S::kind_code(self.key.kind));
        bytes.push(0);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        let predecessor = self
            .predecessor
            .map_or([0; 32], |digest| *digest.as_bytes());
        bytes.extend_from_slice(&predecessor);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    /// Decodes and round-trips one envelope under trusted replay evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DomainLedgerDataError::NonCanonicalRecord`] for a
    /// malformed, oversized, digest-mismatched, or alternate encoding.
    pub fn decode(
        key: ProtectedDomainKeyV1<S>,
        bytes: &[u8],
        validator: &S::ReplayValidator,
    ) -> Result<Self, DomainLedgerDataError> {
        if bytes.len() < 88 || bytes.len() > 88 + S::MAXIMUM_PAYLOAD_BYTES {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        if bytes[..8] != S::MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
            || bytes[10] != S::kind_code(key.kind)
            || bytes[11] != 0
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let revision = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
        );
        let predecessor_bytes: [u8; 32] = bytes[20..52]
            .try_into()
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
        let predecessor =
            (predecessor_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(predecessor_bytes));
        let payload_length = usize::try_from(u32::from_be_bytes(
            bytes[52..56]
                .try_into()
                .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
        ))
        .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
        let payload_end = 56_usize
            .checked_add(payload_length)
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        if payload_length == 0
            || payload_length > S::MAXIMUM_PAYLOAD_BYTES
            || bytes.len() != payload_end + 32
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let candidate = Self::new_with_validator(
            key,
            revision,
            predecessor,
            bytes[56..payload_end].to_vec(),
            validator,
        )?;
        if candidate.digest.as_bytes() != &bytes[payload_end..]
            || candidate.encode().as_slice() != bytes
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        Ok(candidate)
    }
}

/// Encodes one canonical durable member without committing it.
///
/// # Errors
///
/// Rejects a zero identity or set digest, invalid member index/count, or unrepresentable envelope.
pub fn encode_durable_member<S: ProtectedDomainSchemaV1>(
    transaction_id: [u8; 16],
    member_index: u16,
    member_count: u16,
    set_digest: ObjectDigest,
    envelope: ProtectedDomainEnvelopeV1<S>,
) -> Result<DurableDomainMemberV1<S>, DomainLedgerDataError> {
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.as_bytes() == &[0; 32]
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let inner = envelope.encode();
    let inner_length =
        u32::try_from(inner.len()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let mut encoded = Vec::with_capacity(DURABLE_MEMBER_FIXED_BYTES + inner.len());
    encoded.extend_from_slice(DURABLE_MEMBER_MAGIC);
    encoded.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&[0; 2]);
    encoded.extend_from_slice(&transaction_id);
    encoded.extend_from_slice(&member_index.to_be_bytes());
    encoded.extend_from_slice(&member_count.to_be_bytes());
    encoded.extend_from_slice(set_digest.as_bytes());
    encoded.extend_from_slice(&inner_length.to_be_bytes());
    encoded.extend_from_slice(&inner);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"durable-member\0")
        .chain_update(&encoded)
        .finalize()
        .into();
    encoded.extend_from_slice(&digest);
    Ok(DurableDomainMemberV1 {
        transaction_id,
        member_index,
        member_count,
        set_digest,
        envelope,
        encoded,
    })
}

/// Decodes and round-trips one durable member under borrowed schema evidence.
///
/// # Errors
///
/// Rejects noncanonical framing, schema data, bounds, or retained commitment mismatches.
pub fn decode_durable_member<S: ProtectedDomainSchemaV1>(
    key: ProtectedDomainKeyV1<S>,
    bytes: &[u8],
    validator: &S::ReplayValidator,
) -> Result<DurableDomainMemberV1<S>, DomainLedgerDataError> {
    if bytes.len() < 189
        || bytes.len() > 188 + S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != DURABLE_MEMBER_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10..12] != [0; 2]
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let transaction_id: [u8; 16] = bytes[12..28]
        .try_into()
        .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let member_index = u16::from_be_bytes([bytes[28], bytes[29]]);
    let member_count = u16::from_be_bytes([bytes[30], bytes[31]]);
    let set_digest = ObjectDigest::from_bytes(
        bytes[32..64]
            .try_into()
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
    );
    let inner_length = usize::try_from(u32::from_be_bytes(
        bytes[64..68]
            .try_into()
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
    ))
    .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let inner_end = 68_usize
        .checked_add(inner_length)
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.as_bytes() == &[0; 32]
        || bytes.len() != inner_end + 32
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"durable-member\0")
        .chain_update(&bytes[..inner_end])
        .finalize()
        .into();
    if bytes[inner_end..] != expected {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let envelope = ProtectedDomainEnvelopeV1::<S>::decode(key, &bytes[68..inner_end], validator)?;
    let member = encode_durable_member(
        transaction_id,
        member_index,
        member_count,
        set_digest,
        envelope,
    )?;
    if member.encoded.as_slice() != bytes {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    Ok(member)
}

/// Carries a replayed, closed materialized domain projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedDomainProjectionV1<S: ProtectedDomainSchemaV1> {
    records: Vec<ProtectedDomainEnvelopeV1<S>>,
    transactions: Vec<ProtectedDomainReplayTransactionV1<S>>,
    root: ObjectDigest,
}

impl<S: ProtectedDomainSchemaV1> ProtectedDomainProjectionV1<S> {
    /// Returns records in canonical namespace/key order.
    #[must_use]
    pub fn records(&self) -> &[ProtectedDomainEnvelopeV1<S>] {
        &self.records
    }

    /// Returns bounded transaction groups reconstructed from durable members.
    #[must_use]
    pub fn transactions(&self) -> &[ProtectedDomainReplayTransactionV1<S>] {
        &self.transactions
    }

    /// Returns the exact materialized projection commitment.
    #[must_use]
    pub const fn root(&self) -> ObjectDigest {
        self.root
    }
}

/// Classifies one transaction group reconstructed during cold replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedDomainReplayPhaseV1 {
    /// At least one decoded reducer member still admits its effect.
    Prepared,
    /// Every actionable member has durable observation but is not terminal.
    Observed,
    /// Decoded reducer state proves the transaction is terminal.
    Terminal,
    /// Decoded reducer state proves the transaction was superseded.
    Superseded,
    /// Some members were superseded, so replay grants no transaction authority.
    Incomplete,
}

/// Retains one bounded transaction group reconstructed from durable records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedDomainReplayTransactionV1<S: ProtectedDomainSchemaV1> {
    transaction_id: [u8; 16],
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    phase: ProtectedDomainReplayPhaseV1,
    records: Vec<ProtectedDomainEnvelopeV1<S>>,
}

impl<S: ProtectedDomainSchemaV1> ProtectedDomainReplayTransactionV1<S> {
    /// Returns the exact durable transaction identity.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    /// Returns the exact commitment to the reconstructed durable transaction.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the complete canonical member-set commitment.
    #[must_use]
    pub const fn set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the fail-closed cold-replay classification.
    #[must_use]
    pub const fn phase(&self) -> ProtectedDomainReplayPhaseV1 {
        self.phase
    }

    /// Returns current typed members in canonical member order.
    #[must_use]
    pub fn records(&self) -> &[ProtectedDomainEnvelopeV1<S>] {
        &self.records
    }
}

/// Retains canonical durable-member DATA without writer or currentness authority.
#[derive(Clone, Debug)]
#[must_use]
pub struct DurableDomainMemberV1<S: ProtectedDomainSchemaV1> {
    transaction_id: [u8; 16],
    member_index: u16,
    member_count: u16,
    set_digest: ObjectDigest,
    envelope: ProtectedDomainEnvelopeV1<S>,
    encoded: Vec<u8>,
}

impl<S: ProtectedDomainSchemaV1> DurableDomainMemberV1<S> {
    /// Returns the stable transaction identity.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    /// Returns the ordered member index.
    #[must_use]
    pub const fn member_index(&self) -> u16 {
        self.member_index
    }

    /// Returns the complete member count.
    #[must_use]
    pub const fn member_count(&self) -> u16 {
        self.member_count
    }

    /// Returns the canonical member-set commitment.
    #[must_use]
    pub const fn set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the decoded envelope DATA.
    #[must_use]
    pub const fn envelope(&self) -> &ProtectedDomainEnvelopeV1<S> {
        &self.envelope
    }

    /// Returns the retained byte-exact canonical member.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Moves the original fields in their declaration order without cloning.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        [u8; 16],
        u16,
        u16,
        ObjectDigest,
        ProtectedDomainEnvelopeV1<S>,
        Vec<u8>,
    ) {
        (
            self.transaction_id,
            self.member_index,
            self.member_count,
            self.set_digest,
            self.envelope,
            self.encoded,
        )
    }
}

/// Carries one structurally authenticated current record before domain trust is
/// available to interpret its reducer body.
///
/// This is untrusted bootstrap DATA, not a currentness witness. Callers must build
/// the domain validator from the candidate set, perform ordinary typed replay,
/// and compare the complete replayed records before treating any field as
/// authority.
pub struct ProtectedCurrentRecordCandidateV1<S: ProtectedDomainSchemaV1> {
    key: ProtectedDomainKeyV1<S>,
    envelope_digest: ObjectDigest,
    body: Vec<u8>,
}

impl<S: ProtectedDomainSchemaV1> ProtectedCurrentRecordCandidateV1<S> {
    /// Returns the structurally validated closed-domain key.
    pub const fn key(&self) -> &ProtectedDomainKeyV1<S> {
        &self.key
    }

    /// Returns the complete current envelope commitment.
    pub const fn envelope_digest(&self) -> ObjectDigest {
        self.envelope_digest
    }

    /// Returns the untrusted reducer body for provisional validator recovery.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Validates the canonical exact successor relationship of supplied DATA.
///
/// # Errors
///
/// Rejects noncanonical revalidation or a revision/predecessor mismatch.
pub fn validate_successor<S: ProtectedDomainSchemaV1>(
    previous: Option<&[u8]>,
    successor: &ProtectedDomainEnvelopeV1<S>,
    validator: &S::ReplayValidator,
) -> Result<(), DomainLedgerDataError> {
    let revalidated = ProtectedDomainEnvelopeV1::<S>::decode(
        successor.key.clone(),
        &successor.encode(),
        validator,
    )?;
    if &revalidated != successor {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    match previous {
        None if successor.revision == 1 && successor.predecessor.is_none() => Ok(()),
        Some(bytes) => {
            let key = successor.key.clone();
            let previous = decode_durable_member::<S>(key, bytes, validator)?.envelope;
            let next_revision = previous
                .revision
                .checked_add(1)
                .ok_or(DomainLedgerDataError::CompareAndSwapFailed)?;
            if successor.revision == next_revision && successor.predecessor == Some(previous.digest)
            {
                Ok(())
            } else {
                Err(DomainLedgerDataError::CompareAndSwapFailed)
            }
        }
        _ => Err(DomainLedgerDataError::CompareAndSwapFailed),
    }
}

/// Replays borrowed materialized rows into canonical projection DATA.
///
/// # Errors
///
/// Rejects noncanonical framing, schema data, bounds, or retained commitment mismatches.
pub fn replay_projection_records<'records, S: ProtectedDomainSchemaV1>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    validator: &S::ReplayValidator,
) -> Result<ProtectedDomainProjectionV1<S>, DomainLedgerDataError> {
    let mut members = Vec::new();
    let mut seen = BTreeSet::new();
    for (namespace, key_bytes, value) in records {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
        if namespace != S::namespace(key.kind) || !seen.insert(key_bytes.to_vec()) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        if members.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        members.push(decode_durable_member::<S>(key, value, validator)?);
    }
    members.sort_by(|left, right| {
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
        .chain_update((members.len() as u64).to_be_bytes());
    for member in &members {
        hasher = hasher
            .chain_update([S::namespace(member.envelope.key.kind) as u8])
            .chain_update((member.envelope.key.as_bytes().len() as u32).to_be_bytes())
            .chain_update(member.envelope.key.as_bytes())
            .chain_update((member.encoded.len() as u64).to_be_bytes())
            .chain_update(&member.encoded);
    }
    let transactions = reconstruct_transactions::<S>(&members)?;
    let records = members.into_iter().map(|member| member.envelope).collect();
    Ok(ProtectedDomainProjectionV1 {
        records,
        transactions,
        root: ObjectDigest::from_bytes(hasher.finalize().into()),
    })
}

/// Structurally decodes borrowed rows as untrusted domain DATA.
///
/// # Errors
/// Rejects malformed framing, namespace mappings, duplicate keys, or hashes.
pub fn current_record_candidates_from_rows<'records, S: ProtectedDomainSchemaV1>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
) -> Result<Vec<ProtectedCurrentRecordCandidateV1<S>>, DomainLedgerDataError> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for (namespace, key_bytes, value) in records {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        if candidates.len() >= MAXIMUM_COLD_REPLAY_MEMBERS || !seen.insert(key_bytes.to_vec()) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }

        let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
        if namespace != S::namespace(key.kind) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        candidates.push(decode_protected_current_candidate::<S>(key, value)?);
    }
    candidates.sort_by(|left, right| {
        (S::namespace(left.key.kind) as u8, left.key.as_bytes())
            .cmp(&(S::namespace(right.key.kind) as u8, right.key.as_bytes()))
    });
    Ok(candidates)
}

fn decode_protected_current_candidate<S: ProtectedDomainSchemaV1>(
    key: ProtectedDomainKeyV1<S>,
    bytes: &[u8],
) -> Result<ProtectedCurrentRecordCandidateV1<S>, DomainLedgerDataError> {
    if bytes.len() < 189
        || bytes.len() > 188 + S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != DURABLE_MEMBER_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10..12] != [0; 2]
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let transaction_id: [u8; 16] = bytes[12..28]
        .try_into()
        .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let member_index = u16::from_be_bytes([bytes[28], bytes[29]]);
    let member_count = u16::from_be_bytes([bytes[30], bytes[31]]);
    let set_digest = &bytes[32..64];
    let envelope_length = usize::try_from(u32::from_be_bytes(
        bytes[64..68]
            .try_into()
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
    ))
    .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let envelope_end = 68_usize
        .checked_add(envelope_length)
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.iter().all(|byte| *byte == 0)
        || bytes.len() != envelope_end + 32
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let member_digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"durable-member\0")
        .chain_update(&bytes[..envelope_end])
        .finalize()
        .into();
    if bytes[envelope_end..] != member_digest {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }

    let envelope = &bytes[68..envelope_end];
    if envelope.len() < 88
        || envelope.len() > 88 + S::MAXIMUM_PAYLOAD_BYTES
        || envelope[..8] != S::MAGIC
        || u16::from_be_bytes([envelope[8], envelope[9]]) != ENVELOPE_VERSION
        || envelope[10] != S::kind_code(key.kind)
        || envelope[11] != 0
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let revision = u64::from_be_bytes(
        envelope[12..20]
            .try_into()
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
    );
    let predecessor_bytes: [u8; 32] = envelope[20..52]
        .try_into()
        .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let predecessor =
        (predecessor_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(predecessor_bytes));
    let payload_length = usize::try_from(u32::from_be_bytes(
        envelope[52..56]
            .try_into()
            .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?,
    ))
    .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let payload_end = 56_usize
        .checked_add(payload_length)
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    if revision == 0
        || revision == u64::MAX
        || (revision == 1) != predecessor.is_none()
        || payload_length == 0
        || payload_length > S::MAXIMUM_PAYLOAD_BYTES
        || envelope.len() != payload_end + 32
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let payload = &envelope[56..payload_end];
    let envelope_digest = envelope_digest::<S>(&key, revision, predecessor, payload);
    if &envelope[payload_end..] != envelope_digest.as_bytes() {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }

    let body = if S::is_checkpoint(key.kind) {
        if !valid_checkpoint_payload::<S>(payload) {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        Vec::new()
    } else {
        structurally_decode_reducer_body::<S>(&key, payload)?.to_vec()
    };
    Ok(ProtectedCurrentRecordCandidateV1 {
        key,
        envelope_digest,
        body,
    })
}

fn structurally_decode_reducer_body<'payload, S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &'payload [u8],
) -> Result<&'payload [u8], DomainLedgerDataError> {
    if bytes.len() < 60
        || bytes.len() > S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != REDUCER_PAYLOAD_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10] != S::family(key.kind)
        || bytes[11] != S::kind_code(key.kind)
        || bytes[13] != 0
        || decode_phase(bytes[12]).is_none()
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let companion_count = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let body_length = usize::try_from(u32::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19],
    ]))
    .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let companions_end = 20_usize
        .checked_add(
            companion_count
                .checked_mul(32)
                .ok_or(DomainLedgerDataError::NonCanonicalRecord)?,
        )
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    let body_end = companions_end
        .checked_add(body_length)
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    if companion_count > MAXIMUM_REDUCER_COMPANIONS
        || body_length < 8
        || bytes.len() != body_end + 32
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let companions = bytes[20..companions_end]
        .chunks_exact(32)
        .map(|digest| {
            digest
                .try_into()
                .map(ObjectDigest::from_bytes)
                .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if companions
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
        || companions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"reducer-payload\0")
        .chain_update(&bytes[..body_end])
        .finalize()
        .into();
    if bytes[body_end..] != expected
        || derived_companions(key, &bytes[companions_end..body_end]) != companions
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    Ok(&bytes[companions_end..body_end])
}

/// Reconstructs bounded canonical transaction groups from durable-member DATA.
///
/// # Errors
///
/// Rejects duplicate, incomplete, or inconsistent member sets and digests.
pub fn reconstruct_transactions<S: ProtectedDomainSchemaV1>(
    members: &[DurableDomainMemberV1<S>],
) -> Result<Vec<ProtectedDomainReplayTransactionV1<S>>, DomainLedgerDataError> {
    let mut grouped: BTreeMap<[u8; 16], Vec<&DurableDomainMemberV1<S>>> = BTreeMap::new();
    for member in members {
        grouped
            .entry(member.transaction_id)
            .or_default()
            .push(member);
    }
    let mut transactions = Vec::with_capacity(grouped.len());
    for (transaction_id, mut group) in grouped {
        group.sort_by_key(|member| member.member_index);
        let first = group
            .first()
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
        if group.iter().any(|member| {
            member.member_count != first.member_count
                || member.set_digest != first.set_digest
                || member.transaction_id != transaction_id
        }) || group
            .windows(2)
            .any(|pair| pair[0].member_index == pair[1].member_index)
        {
            return Err(DomainLedgerDataError::NonCanonicalRecord);
        }
        let complete = usize::from(first.member_count) == group.len()
            && group
                .iter()
                .enumerate()
                .all(|(index, member)| usize::from(member.member_index) == index);
        let records: Vec<_> = group.iter().map(|member| member.envelope.clone()).collect();
        let phase = if !complete {
            ProtectedDomainReplayPhaseV1::Incomplete
        } else {
            let recomputed = domain_transaction_set_digest::<S>(transaction_id, &records);
            if recomputed != first.set_digest {
                return Err(DomainLedgerDataError::NonCanonicalRecord);
            }
            aggregate_reducer_phase::<S>(&records)?
        };
        transactions.push(ProtectedDomainReplayTransactionV1 {
            transaction_id,
            transaction: reconstructed_transaction_digest::<S>(transaction_id, &group)?,
            set_digest: first.set_digest,
            phase,
            records,
        });
    }
    Ok(transactions)
}

/// Returns the schema-decoded reducer phase as DATA, not currentness.
///
/// # Errors
///
/// The stored DATA phase is returned without another validation or admission step.
pub fn reducer_phase<S: ProtectedDomainSchemaV1>(
    envelope: &ProtectedDomainEnvelopeV1<S>,
) -> Result<ProtectedReducerPhaseV1, DomainLedgerDataError> {
    Ok(envelope.validated_phase)
}

fn aggregate_reducer_phase<S: ProtectedDomainSchemaV1>(
    records: &[ProtectedDomainEnvelopeV1<S>],
) -> Result<ProtectedDomainReplayPhaseV1, DomainLedgerDataError> {
    let mut phases = Vec::with_capacity(records.len());
    for record in records {
        phases.push(reducer_phase(record)?);
    }
    Ok(match aggregate_semantic_phases(&phases) {
        ProtectedReducerPhaseV1::Prepared => ProtectedDomainReplayPhaseV1::Prepared,
        ProtectedReducerPhaseV1::Observed => ProtectedDomainReplayPhaseV1::Observed,
        ProtectedReducerPhaseV1::Terminal => ProtectedDomainReplayPhaseV1::Terminal,
        ProtectedReducerPhaseV1::Superseded => ProtectedDomainReplayPhaseV1::Superseded,
    })
}

/// Classifies a collection of decoded reducer-phase DATA.
pub fn aggregate_semantic_phases(phases: &[ProtectedReducerPhaseV1]) -> ProtectedReducerPhaseV1 {
    if phases.contains(&ProtectedReducerPhaseV1::Superseded) {
        ProtectedReducerPhaseV1::Superseded
    } else if phases.contains(&ProtectedReducerPhaseV1::Prepared) {
        ProtectedReducerPhaseV1::Prepared
    } else if phases.contains(&ProtectedReducerPhaseV1::Terminal) {
        ProtectedReducerPhaseV1::Terminal
    } else {
        ProtectedReducerPhaseV1::Observed
    }
}

fn reconstructed_transaction_digest<S: ProtectedDomainSchemaV1>(
    transaction_id: [u8; 16],
    members: &[&DurableDomainMemberV1<S>],
) -> Result<ObjectDigest, DomainLedgerDataError> {
    let records = members
        .iter()
        .map(|member| {
            JournalRecord::put(
                S::namespace(member.envelope.key.kind),
                member.envelope.key.as_bytes().to_vec(),
                member.encoded.clone(),
            )
        })
        .collect();
    let transaction = JournalTransaction::new(transaction_id, records)?;
    Ok(transaction_digest::<S>(&transaction))
}

fn envelope_digest<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    payload: &[u8],
) -> ObjectDigest {
    let predecessor = predecessor.map_or([0; 32], |digest| *digest.as_bytes());
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(S::HASH_DOMAIN)
            .chain_update(b"envelope\0")
            .chain_update((key.as_bytes().len() as u32).to_be_bytes())
            .chain_update(key.as_bytes())
            .chain_update(revision.to_be_bytes())
            .chain_update(predecessor)
            .chain_update((payload.len() as u64).to_be_bytes())
            .chain_update(payload)
            .finalize()
            .into(),
    )
}

/// Hashes the ordered record DATA under the schema's transaction domain.
pub fn transaction_digest<S: ProtectedDomainSchemaV1>(
    transaction: &JournalTransaction,
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"transaction\0")
        .chain_update(transaction.id())
        .chain_update((transaction.records().len() as u64).to_be_bytes());
    for record in transaction.records() {
        hasher = hasher
            .chain_update([record.namespace() as u8])
            .chain_update((record.key().len() as u32).to_be_bytes())
            .chain_update(record.key());
        if let Some(value) = record.value() {
            hasher = hasher
                .chain_update((value.len() as u64).to_be_bytes())
                .chain_update(value);
        }
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Hashes the complete canonical ordered successor DATA set.
pub fn domain_transaction_set_digest<S: ProtectedDomainSchemaV1>(
    transaction_id: [u8; 16],
    successors: &[ProtectedDomainEnvelopeV1<S>],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"transaction-set\0")
        .chain_update(transaction_id)
        .chain_update((successors.len() as u64).to_be_bytes());
    for successor in successors {
        hasher = hasher
            .chain_update([S::namespace(successor.key.kind) as u8])
            .chain_update((successor.key.as_bytes().len() as u32).to_be_bytes())
            .chain_update(successor.key.as_bytes())
            .chain_update(successor.digest.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Encodes checkpoint DATA from supplied sequence and projection-root scalars.
pub fn encode_checkpoint_payload<S: ProtectedDomainSchemaV1>(
    sequence: u64,
    root: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(88);
    bytes.extend_from_slice(CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(root.as_bytes());
    let digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"checkpoint\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&digest);
    bytes
}

/// Encodes a reducer body using the original borrowed schema validator.
///
/// # Errors
///
/// Rejects an invalid body or phase, companion set, or bounded representation.
pub fn encode_reducer_payload_with_validator<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    body: &[u8],
    validator: &S::ReplayValidator,
) -> Result<Vec<u8>, DomainLedgerDataError> {
    let phase = S::decode_reducer_phase(validator, key.kind, &key.identity, body)
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    let companions = derived_companions(key, body);
    if body.len() < 8
        || body.len() > S::MAXIMUM_PAYLOAD_BYTES
        || companions.len() > MAXIMUM_REDUCER_COMPANIONS
        || companions
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        || !companions.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let companion_count =
        u16::try_from(companions.len()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let body_length =
        u32::try_from(body.len()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let capacity = 20_usize
        .checked_add(companions.len().saturating_mul(32))
        .and_then(|length| length.checked_add(body.len()))
        .and_then(|length| length.checked_add(32))
        .ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    if capacity > S::MAXIMUM_PAYLOAD_BYTES {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(REDUCER_PAYLOAD_MAGIC);
    encoded.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    encoded.push(S::family(key.kind));
    encoded.push(S::kind_code(key.kind));
    encoded.push(phase as u8);
    encoded.push(0);
    encoded.extend_from_slice(&companion_count.to_be_bytes());
    encoded.extend_from_slice(&body_length.to_be_bytes());
    for companion in companions {
        encoded.extend_from_slice(companion.as_bytes());
    }
    encoded.extend_from_slice(body);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"reducer-payload\0")
        .chain_update(&encoded)
        .finalize()
        .into();
    encoded.extend_from_slice(&digest);
    Ok(encoded)
}

/// Binds a capacity request to one exact protected-domain schema.
pub fn bind_domain_capacity_request_v1<S: ProtectedDomainSchemaV1>(
    mut request: GlobalCapacityReservationRequestV1,
) -> GlobalCapacityReservationRequestV1 {
    request.owner_id = domain_capacity_owner_id::<S>(&request);
    request
}

fn domain_capacity_owner_id<S: ProtectedDomainSchemaV1>(
    request: &GlobalCapacityReservationRequestV1,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"aos.sandbox.protected-journal.capacity-owner.v1\0")
        .chain_update(S::HASH_DOMAIN)
        .chain_update([request.purpose as u8, request.owner_namespace as u8])
        .chain_update(request.owner_digest)
        .chain_update(request.operation_id)
        .chain_update(request.artifact_digest)
        .chain_update(request.checkpoint_digest)
        .chain_update(request.chain_head_digest)
        .chain_update(request.terminal_records.to_be_bytes())
        .chain_update(request.terminal_bytes.to_be_bytes())
        .chain_update(request.poison_records.to_be_bytes())
        .chain_update(request.poison_bytes.to_be_bytes())
        .finalize()
        .into()
}

/// Compares the supplied capacity DATA identity with the schema hash domain.
pub fn capacity_request_binds_schema<S: ProtectedDomainSchemaV1>(
    request: &GlobalCapacityReservationRequestV1,
) -> bool {
    request.owner_id == domain_capacity_owner_id::<S>(request)
}

/// Validates the durable schema and deterministic identity of one reservation.
pub fn validate_domain_capacity_lineage_v1<S: ProtectedDomainSchemaV1>(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
) -> bool {
    admission_transaction_id != [0; 16]
        && capacity_request_binds_schema::<S>(request)
        && capacity_reservation_identity_is_exact_v1(
            request,
            admission_transaction_id,
            reservation_id,
        )
}

/// Borrows one validated reducer body and owns its bounded companion set.
pub struct DecodedReducerPayloadV1<'payload> {
    body: &'payload [u8],
    companions: Vec<ObjectDigest>,
    phase: ProtectedReducerPhaseV1,
}

impl<'payload> DecodedReducerPayloadV1<'payload> {
    /// Returns the byte-exact canonical reducer body.
    pub const fn body(&self) -> &'payload [u8] {
        self.body
    }

    /// Returns canonical strictly ordered companion commitments.
    pub fn companions(&self) -> &[ObjectDigest] {
        &self.companions
    }

    /// Returns the schema-decoded semantic reducer phase.
    pub const fn phase(&self) -> ProtectedReducerPhaseV1 {
        self.phase
    }
}

/// Decodes a canonical reducer body using the original borrowed schema validator.
///
/// # Errors
///
/// Rejects invalid framing, schema DATA, companion sets, bounds, or commitments.
pub fn decode_reducer_payload_with_validator<'payload, S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &'payload [u8],
    validator: &S::ReplayValidator,
) -> Result<DecodedReducerPayloadV1<'payload>, DomainLedgerDataError> {
    if !valid_reducer_payload::<S>(key, bytes, validator) {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let phase = decode_phase(bytes[12]).ok_or(DomainLedgerDataError::NonCanonicalRecord)?;
    let companion_count = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let companions_end = 20 + companion_count * 32;
    let body_length = usize::try_from(u32::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19],
    ]))
    .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    let body_end = companions_end + body_length;
    let companions = bytes[20..companions_end]
        .chunks_exact(32)
        .map(|digest| {
            let bytes: [u8; 32] = digest
                .try_into()
                .map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
            Ok(ObjectDigest::from_bytes(bytes))
        })
        .collect::<Result<Vec<_>, DomainLedgerDataError>>()?;
    Ok(DecodedReducerPayloadV1 {
        body: &bytes[companions_end..body_end],
        companions,
        phase,
    })
}

fn valid_reducer_payload<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &[u8],
    validator: &S::ReplayValidator,
) -> bool {
    if bytes.len() < 60
        || bytes.len() > S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != REDUCER_PAYLOAD_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10] != S::family(key.kind)
        || bytes[11] != S::kind_code(key.kind)
        || bytes[13] != 0
    {
        return false;
    }
    let Some(phase) = decode_phase(bytes[12]) else {
        return false;
    };
    let companion_count = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    if companion_count > MAXIMUM_REDUCER_COMPANIONS {
        return false;
    }
    let body_length = usize::try_from(u32::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19],
    ]))
    .ok();
    let Some(body_length) = body_length else {
        return false;
    };
    let companions_end = 20_usize.checked_add(companion_count.saturating_mul(32));
    let Some(companions_end) = companions_end else {
        return false;
    };
    let body_end = companions_end.checked_add(body_length);
    let Some(body_end) = body_end else {
        return false;
    };
    if body_length < 8 || bytes.len() != body_end + 32 {
        return false;
    }
    let companions = &bytes[20..companions_end];
    if companions.chunks_exact(32).any(|digest| digest == [0; 32])
        || !companions
            .chunks_exact(32)
            .collect::<Vec<_>>()
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return false;
    }
    let body = &bytes[companions_end..body_end];
    let derived_companions = encode_digest_slice(&derived_companions(key, body));
    if S::decode_reducer_phase(validator, key.kind, &key.identity, body) != Some(phase)
        || companions != derived_companions.as_slice()
    {
        return false;
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"reducer-payload\0")
        .chain_update(&bytes[..body_end])
        .finalize()
        .into();
    bytes[body_end..] == expected
}

fn decode_phase(value: u8) -> Option<ProtectedReducerPhaseV1> {
    match value {
        1 => Some(ProtectedReducerPhaseV1::Prepared),
        2 => Some(ProtectedReducerPhaseV1::Observed),
        3 => Some(ProtectedReducerPhaseV1::Terminal),
        4 => Some(ProtectedReducerPhaseV1::Superseded),
        _ => None,
    }
}

fn derived_companions<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    body: &[u8],
) -> Vec<ObjectDigest> {
    let body_digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(S::HASH_DOMAIN)
            .chain_update(b"canonical-reducer-body\0")
            .chain_update([S::kind_code(key.kind)])
            .chain_update(body)
            .finalize()
            .into(),
    );
    let mut companions = vec![body_digest];
    if let Some(tuple) = S::semantic_tuple(key.kind, &key.identity, body) {
        companions.push(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.protected-journal.subject.v1\0")
                .chain_update(tuple)
                .finalize()
                .into(),
        ));
    }
    companions.sort_unstable();
    companions.dedup();
    companions
}

fn encode_digest_slice(digests: &[ObjectDigest]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(digests.len() * 32);
    for digest in digests {
        bytes.extend_from_slice(digest.as_bytes());
    }
    bytes
}

fn valid_checkpoint_payload<S: ProtectedDomainSchemaV1>(bytes: &[u8]) -> bool {
    if bytes.len() != 88
        || &bytes[..8] != CHECKPOINT_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10..16] != [0; 6]
        || bytes[24..56] == [0; 32]
    {
        return false;
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"checkpoint\0")
        .chain_update(&bytes[..56])
        .finalize()
        .into();
    bytes[56..] == expected
}
