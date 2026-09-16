//! Shared machinery for dormant, domain-typed protected-journal adapters.
//!
//! This module is crate-private infrastructure. Domain modules supply closed
//! record-kind schemas and expose typed aliases, so callers never select an
//! arbitrary journal namespace or manufacture a postcommit capability.
//!
//! Reducer payloads use one canonical wrapper:
//!
//! ```text
//! AOSRDP01 | version:u16 | family:u8 | kind:u8 | phase:u8 | reserved:u8 | companions:u16 |
//! body-length:u32 | sorted-companion-digests | canonical-body | digest
//! ```
//!
//! Materialized values wrap that canonical envelope in one durable transaction
//! member, allowing bounded cold replay to reconstruct grouping and phase:
//!
//! ```text
//! AOSDTX01 | version:u16 | reserved:u16 | transaction-id:[u8;16] |
//! member-index:u16 | member-count:u16 | set-digest:[u8;32] |
//! envelope-length:u32 | canonical-envelope | member-digest:[u8;32]
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, GlobalCapacityReservationV1, Journal, JournalError,
    JournalRecord, JournalTransaction, PreparedGlobalCapacityReservationV1,
    ProtectedJournalPreflight, RecordNamespace, capacity_reservation_identity_is_exact_v1,
};

const ENVELOPE_VERSION: u16 = 1;
const MAXIMUM_DOMAIN_IDENTITY_BYTES: usize = 512;
const CHECKPOINT_MAGIC: &[u8; 8] = b"AOSDCP01";
const REDUCER_PAYLOAD_MAGIC: &[u8; 8] = b"AOSRDP01";
const MAXIMUM_REDUCER_COMPANIONS: usize = 64;
const DURABLE_MEMBER_MAGIC: &[u8; 8] = b"AOSDTX01";
const MAXIMUM_COLD_REPLAY_MEMBERS: usize = 262_144;

/// Classifies the authority which may be released after an exact readback.
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

/// Borrows one fully decoded terminal member for capacity-lineage validation.
pub struct ProtectedCapacitySettlementMemberV1<'member, K> {
    /// Closed schema kind decoded from the canonical key and envelope.
    pub(crate) kind: K,
    /// Exact schema-validated key identity.
    pub(crate) identity: &'member [u8],
    /// Exact schema-decoded canonical reducer body.
    pub(crate) body: &'member [u8],
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
    /// Classifies the authority released by a successfully read-back record.
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

/// Reports malformed domain records, stale plans, and journal failures.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedDomainJournalErrorV1 {
    /// A key, envelope, revision, predecessor, or payload is noncanonical.
    #[error("protected domain journal record is noncanonical")]
    NonCanonicalRecord,
    /// A successor does not exactly extend the currently materialized value.
    #[error("protected domain journal compare-and-swap failed")]
    CompareAndSwapFailed,
    /// A plan or capability was issued by another adapter instance or snapshot.
    #[error("protected domain journal authority is stale or substituted")]
    StaleAuthority,
    /// Durable recovery found a mixture of predecessor and successor values.
    #[error("protected domain journal recovery found divergent state")]
    DivergentRecovery,
    /// The underlying journal rejected or could not durably perform an action.
    #[error(transparent)]
    Journal(#[from] JournalError),
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
    /// Returns [`ProtectedDomainJournalErrorV1::NonCanonicalRecord`] when the
    /// identity is empty or exceeds the fixed domain-key ceiling.
    pub(crate) fn new(
        kind: S::Kind,
        identity: Vec<u8>,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        if identity.is_empty()
            || identity.len() > MAXIMUM_DOMAIN_IDENTITY_BYTES
            || !S::validates_identity(kind, &identity)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let identity_length = u16::try_from(identity.len())
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
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

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, ProtectedDomainJournalErrorV1> {
        let header = S::KEY_PREFIX.len() + 4;
        if encoded.len() < header || !encoded.starts_with(S::KEY_PREFIX) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let version = encoded[S::KEY_PREFIX.len()];
        let kind = S::kind_from_code(encoded[S::KEY_PREFIX.len() + 1])
            .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
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
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Self::new(kind, encoded[header..].to_vec()).and_then(|key| {
            (key.as_bytes() == encoded)
                .then_some(key)
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)
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
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::NonCanonicalRecord`] for a
    /// sentinel revision, broken predecessor shape, or oversized payload.
    /// Constructs a successor only after schema-specific trusted validation.
    pub(crate) fn new_with_validator(
        key: ProtectedDomainKeyV1<S>,
        revision: u64,
        predecessor: Option<ObjectDigest>,
        payload: Vec<u8>,
        validator: &S::ReplayValidator,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
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
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let digest = envelope_digest::<S>(&key, revision, predecessor, &payload);
        Ok(Self {
            key,
            revision,
            predecessor,
            payload,
            digest,
            validated_phase: validated_phase
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
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

    /// Returns the phase established by typed validation at construction.
    pub(crate) const fn validated_phase(&self) -> ProtectedReducerPhaseV1 {
        self.validated_phase
    }

    /// Encodes the envelope into its unique bounded representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(88 + self.payload.len());
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
    /// Returns [`ProtectedDomainJournalErrorV1::NonCanonicalRecord`] for a
    /// malformed, oversized, digest-mismatched, or alternate encoding.
    pub fn decode(
        key: ProtectedDomainKeyV1<S>,
        bytes: &[u8],
        validator: &S::ReplayValidator,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        if bytes.len() < 88 || bytes.len() > 88 + S::MAXIMUM_PAYLOAD_BYTES {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        if bytes[..8] != S::MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
            || bytes[10] != S::kind_code(key.kind)
            || bytes[11] != 0
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let revision = u64::from_be_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
        );
        let predecessor_bytes: [u8; 32] = bytes[20..52]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let predecessor =
            (predecessor_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(predecessor_bytes));
        let payload_length = usize::try_from(u32::from_be_bytes(
            bytes[52..56]
                .try_into()
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
        ))
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let payload_end = 56_usize
            .checked_add(payload_length)
            .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if payload_length == 0
            || payload_length > S::MAXIMUM_PAYLOAD_BYTES
            || bytes.len() != payload_end + 32
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(candidate)
    }
}

pub(crate) fn encode_durable_member<S: ProtectedDomainSchemaV1>(
    transaction_id: [u8; 16],
    member_index: u16,
    member_count: u16,
    set_digest: ObjectDigest,
    envelope: ProtectedDomainEnvelopeV1<S>,
) -> Result<DurableDomainMemberV1<S>, ProtectedDomainJournalErrorV1> {
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.as_bytes() == &[0; 32]
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let inner = envelope.encode();
    let inner_length = u32::try_from(inner.len())
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let mut encoded = Vec::with_capacity(100 + inner.len());
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

pub(crate) fn decode_durable_member<S: ProtectedDomainSchemaV1>(
    key: ProtectedDomainKeyV1<S>,
    bytes: &[u8],
    validator: &S::ReplayValidator,
) -> Result<DurableDomainMemberV1<S>, ProtectedDomainJournalErrorV1> {
    if bytes.len() < 189
        || bytes.len() > 188 + S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != DURABLE_MEMBER_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10..12] != [0; 2]
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let transaction_id: [u8; 16] = bytes[12..28]
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let member_index = u16::from_be_bytes([bytes[28], bytes[29]]);
    let member_count = u16::from_be_bytes([bytes[30], bytes[31]]);
    let set_digest = ObjectDigest::from_bytes(
        bytes[32..64]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
    );
    let inner_length = usize::try_from(u32::from_be_bytes(
        bytes[64..68]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
    ))
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let inner_end = 68_usize
        .checked_add(inner_length)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.as_bytes() == &[0; 32]
        || bytes.len() != inner_end + 32
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let expected: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"durable-member\0")
        .chain_update(&bytes[..inner_end])
        .finalize()
        .into();
    if bytes[inner_end..] != expected {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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

#[derive(Clone, Debug)]
pub(crate) struct DurableDomainMemberV1<S: ProtectedDomainSchemaV1> {
    pub(crate) transaction_id: [u8; 16],
    pub(crate) member_index: u16,
    pub(crate) member_count: u16,
    pub(crate) set_digest: ObjectDigest,
    pub(crate) envelope: ProtectedDomainEnvelopeV1<S>,
    pub(crate) encoded: Vec<u8>,
}

/// Carries one structurally authenticated current record before domain trust is
/// available to interpret its reducer body.
///
/// This is deliberately crate-private bootstrap material. Callers must build
/// the domain validator from the candidate set, perform ordinary typed replay,
/// and compare the complete replayed records before treating any field as
/// authority.
pub(crate) struct ProtectedCurrentRecordCandidateV1<S: ProtectedDomainSchemaV1> {
    key: ProtectedDomainKeyV1<S>,
    envelope_digest: ObjectDigest,
    body: Vec<u8>,
}

impl<S: ProtectedDomainSchemaV1> ProtectedCurrentRecordCandidateV1<S> {
    /// Returns the structurally validated closed-domain key.
    pub(crate) const fn key(&self) -> &ProtectedDomainKeyV1<S> {
        &self.key
    }

    /// Returns the complete current envelope commitment.
    pub(crate) const fn envelope_digest(&self) -> ObjectDigest {
        self.envelope_digest
    }

    /// Returns the untrusted reducer body for provisional validator recovery.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Seals one exact protected-journal currentness boundary.
#[derive(Clone, Debug)]
pub struct ProtectedDomainSnapshotV1<S: ProtectedDomainSchemaV1> {
    instance: Arc<AdapterInstanceV1>,
    sequence: u64,
    root: ObjectDigest,
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> ProtectedDomainSnapshotV1<S> {
    /// Returns the exact shared-journal sequence at this sealed boundary.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the complete materialized domain projection commitment.
    #[must_use]
    pub const fn projection_root(&self) -> ObjectDigest {
        self.root
    }
}

/// Holds one exact compare-and-swap transaction before durable mutation.
#[must_use = "a prepared journal transaction must be committed or deliberately discarded"]
pub struct PreparedDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    snapshot: ProtectedDomainSnapshotV1<S>,
    transaction: JournalTransaction,
    before: Vec<Option<Vec<u8>>>,
    after: Vec<Vec<u8>>,
    roles: Vec<ProtectedRecordRoleV1>,
    digest: ObjectDigest,
    set_digest: ObjectDigest,
}

impl<S: ProtectedDomainSchemaV1> PreparedDomainTransactionV1<S> {
    /// Returns the stable transaction identifier bound into durable members.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 16] {
        *self.transaction.id()
    }

    /// Returns the exact canonical domain transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Holds one exact domain admission transaction joined to retained capacity.
#[must_use = "a capacity-reserved admission must be committed or deliberately discarded"]
pub struct PreparedCapacityReservedDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    request: GlobalCapacityReservationRequestV1,
    reservation_id: [u8; 32],
    reservation: PreparedGlobalCapacityReservationV1,
    preflight: ProtectedJournalPreflight,
}

/// Retains exact capacity admission state after an ambiguous durable append.
#[must_use = "capacity admission ambiguity must be resolved against protected reopen"]
pub struct DomainCapacityAdmissionUnknownV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    request: GlobalCapacityReservationRequestV1,
    reservation_id: [u8; 32],
}

/// Holds one move-only terminal-capacity authority without exposing the journal.
#[must_use = "reserved capacity must be consumed by one exact terminal settlement"]
pub struct DomainCapacityReservationV1<S: ProtectedDomainSchemaV1> {
    reservation: GlobalCapacityReservationV1,
    request: GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    marker: PhantomData<S>,
}

impl<S: ProtectedDomainSchemaV1> DomainCapacityReservationV1<S> {
    /// Returns the authenticated request and admission transaction for lineage checks.
    #[must_use]
    pub const fn authenticated_binding(&self) -> (GlobalCapacityReservationRequestV1, [u8; 16]) {
        (self.request, self.admission_transaction_id)
    }

    /// Returns the authenticated deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.reservation.reservation_id()
    }

    /// Returns the authenticated digest of the exact admitted domain transaction.
    #[must_use]
    pub(crate) const fn owner_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.request.owner_digest)
    }

    /// Returns the authenticated transaction ID that admitted the reservation.
    #[must_use]
    pub(crate) const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission_transaction_id
    }
}

/// Holds one exact terminal domain transaction and its capacity deletion.
#[must_use = "a reserved terminal transaction must be committed or deliberately discarded"]
pub struct PreparedCapacitySettlementDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    reservation: DomainCapacityReservationV1<S>,
    preflight: ProtectedJournalPreflight,
}

/// Retains an exact reserved terminal transaction after ambiguous durability.
#[must_use = "capacity settlement ambiguity must be resolved against protected reopen"]
pub struct DomainCapacitySettlementUnknownV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
    combined: JournalTransaction,
    request: GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
}

/// Retains the exact transaction after an ambiguous append or synchronization.
#[must_use = "outcome-unknown state must be resolved against a reopened journal"]
pub struct DomainOutcomeUnknownV1<S: ProtectedDomainSchemaV1> {
    prepared: PreparedDomainTransactionV1<S>,
}

/// Retains one composite exact-readback capability for a whole transaction.
#[must_use = "postcommit authority must be revalidated and consumed as one transaction"]
pub struct DomainPostcommitCapabilityV1<S: ProtectedDomainSchemaV1> {
    instance: Arc<AdapterInstanceV1>,
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    sequence: u64,
    root: ObjectDigest,
    records: Vec<DomainPostcommitRecordV1<S>>,
    marker: PhantomData<S>,
}

/// Carries a consumed, current postcommit transaction to a dormant domain seam.
#[must_use = "validated postcommit authority must be consumed by one dormant action"]
pub struct ValidatedDomainPostcommitV1<'current, S: ProtectedDomainSchemaV1> {
    transaction: ObjectDigest,
    set_digest: ObjectDigest,
    records: Vec<DomainPostcommitRecordV1<S>>,
    current: PhantomData<&'current ()>,
}

/// Retains one exact typed envelope proven by postcommit readback.
#[derive(Debug)]
pub struct DomainPostcommitRecordV1<S: ProtectedDomainSchemaV1> {
    namespace: RecordNamespace,
    role: ProtectedRecordRoleV1,
    phase: ProtectedReducerPhaseV1,
    transaction_phase: ProtectedReducerPhaseV1,
    envelope: ProtectedDomainEnvelopeV1<S>,
    encoded: Vec<u8>,
}

impl<S: ProtectedDomainSchemaV1> DomainPostcommitRecordV1<S> {
    /// Returns the fixed shared-journal namespace selected by the domain kind.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the exact canonical envelope read back after durable commit.
    #[must_use]
    pub const fn envelope(&self) -> &ProtectedDomainEnvelopeV1<S> {
        &self.envelope
    }

    /// Reports whether decoded terminal state may publish protected current state.
    #[must_use]
    pub fn is_publication(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Publication)
            && self.phase == ProtectedReducerPhaseV1::Terminal
            && self.transaction_phase == ProtectedReducerPhaseV1::Terminal
    }

    /// Reports whether decoded state still admits exactly one external effect.
    #[must_use]
    pub fn is_effect(&self) -> bool {
        matches!(self.role, ProtectedRecordRoleV1::Effect)
            && self.phase == ProtectedReducerPhaseV1::Prepared
            && self.transaction_phase == ProtectedReducerPhaseV1::Prepared
    }

    /// Returns the phase decoded from the canonical reducer body.
    #[must_use]
    pub const fn phase(&self) -> ProtectedReducerPhaseV1 {
        self.phase
    }
}

/// Reports a successful exact readback and any role-specific authority.
#[must_use = "postcommit capabilities must be consumed or deliberately discarded"]
pub struct AppliedDomainTransactionV1<S: ProtectedDomainSchemaV1> {
    transaction: ObjectDigest,
    snapshot: ProtectedDomainSnapshotV1<S>,
    capability: Option<DomainPostcommitCapabilityV1<S>>,
}

impl<S: ProtectedDomainSchemaV1> AppliedDomainTransactionV1<S> {
    /// Returns the exact canonical transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the sealed postcommit journal snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &ProtectedDomainSnapshotV1<S> {
        &self.snapshot
    }

    /// Takes the composite transaction capability for current revalidation.
    #[must_use]
    pub fn take_postcommit(&mut self) -> Option<DomainPostcommitCapabilityV1<S>> {
        self.capability.take()
    }
}

/// Distinguishes exact commit success from an outcome requiring reopen.
#[must_use = "ambiguous commits must retain their recovery token"]
pub enum DomainCommitOutcomeV1<S: ProtectedDomainSchemaV1> {
    /// Every successor was durably committed and read back exactly.
    Applied(AppliedDomainTransactionV1<S>),
    /// The append or synchronization result is unknown until protected reopen.
    OutcomeUnknown {
        /// Retains the exact predecessor and successor transaction.
        pending: DomainOutcomeUnknownV1<S>,
        /// Reports the underlying durability failure.
        cause: JournalError,
    },
}

/// Classifies recovery of one exact outcome-unknown transaction.
#[must_use = "recovered transactions must be applied, retried, or quarantined"]
pub enum DomainRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Reopen found every exact successor value.
    Applied(AppliedDomainTransactionV1<S>),
    /// Reopen found every exact predecessor and permits only the retained retry.
    Retry(PreparedDomainTransactionV1<S>),
    /// Reopen found mixed or substituted state and retains the evidence.
    Diverged(DomainOutcomeUnknownV1<S>),
}

/// Retains a prepared transaction when commit preflight fails before mutation.
#[must_use]
pub enum DomainRetainedCommitV1<S: ProtectedDomainSchemaV1> {
    /// Commit reached its ordinary applied or outcome-unknown classification.
    Outcome(DomainCommitOutcomeV1<S>),
    /// Preflight failed without consuming the exact prepared transaction.
    Retryable {
        /// Exact transaction remains move-only retry custody.
        prepared: PreparedDomainTransactionV1<S>,
        /// Fail-closed preflight diagnostic.
        error: ProtectedDomainJournalErrorV1,
    },
}

/// Retains an outcome-unknown token when cold recovery cannot be evaluated.
#[must_use]
pub enum DomainRetainedRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Recovery reached its ordinary applied, retry, or diverged classification.
    Outcome(DomainRecoveryV1<S>),
    /// Reopen validation failed before consuming the opaque pending token.
    Retryable {
        /// Exact pending transaction remains available for another cold reopen.
        pending: DomainOutcomeUnknownV1<S>,
        /// Fail-closed protected replay diagnostic.
        error: ProtectedDomainJournalErrorV1,
    },
}

/// Distinguishes capacity-reserved admission success from ambiguous durability.
#[must_use = "ambiguous capacity admissions must retain their recovery token"]
pub enum DomainCapacityAdmissionCommitOutcomeV1<S: ProtectedDomainSchemaV1> {
    /// Domain successors and their global reservation were read back exactly.
    Applied {
        /// Carries the ordinary exact-readback domain result.
        domain: AppliedDomainTransactionV1<S>,
        /// Authorizes one later bounded terminal settlement.
        reservation: DomainCapacityReservationV1<S>,
    },
    /// Admission may or may not have reached durable storage.
    OutcomeUnknown {
        /// Retains the exact domain and capacity admission transaction.
        pending: DomainCapacityAdmissionUnknownV1<S>,
        /// Reports the underlying append or synchronization failure.
        cause: JournalError,
    },
}

/// Classifies protected-reopen recovery of a capacity admission.
#[must_use = "recovered capacity admission state must be applied, retried, or quarantined"]
pub enum DomainCapacityAdmissionRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Reopen found the exact domain successors and reservation.
    Applied {
        /// Carries the ordinary exact-readback domain result.
        domain: AppliedDomainTransactionV1<S>,
        /// Authorizes one later bounded terminal settlement.
        reservation: DomainCapacityReservationV1<S>,
    },
    /// Reopen found every predecessor and no reservation.
    Retry(PreparedCapacityReservedDomainTransactionV1<S>),
    /// Reopen found mixed, substituted, or incomplete state.
    Diverged(DomainCapacityAdmissionUnknownV1<S>),
}

/// Distinguishes capacity settlement success from ambiguous durability.
#[must_use = "ambiguous capacity settlements must retain their recovery token"]
pub enum DomainCapacitySettlementCommitOutcomeV1<S: ProtectedDomainSchemaV1> {
    /// Terminal domain successors were read back and capacity was released.
    Applied(AppliedDomainTransactionV1<S>),
    /// Settlement may or may not have reached durable storage.
    OutcomeUnknown {
        /// Retains the exact terminal transaction and reservation identity.
        pending: DomainCapacitySettlementUnknownV1<S>,
        /// Reports the underlying append or synchronization failure.
        cause: JournalError,
    },
}

/// Classifies protected-reopen recovery of a capacity settlement.
#[must_use = "recovered capacity settlement must be applied, retried, or quarantined"]
pub enum DomainCapacitySettlementRecoveryV1<S: ProtectedDomainSchemaV1> {
    /// Reopen found terminal successors and no retained reservation.
    Applied(AppliedDomainTransactionV1<S>),
    /// Reopen found every predecessor and the exact retained reservation.
    Retry(PreparedCapacitySettlementDomainTransactionV1<S>),
    /// Reopen found mixed, substituted, or incomplete state.
    Diverged(DomainCapacitySettlementUnknownV1<S>),
}

/// Carries a complete current transaction reconstructed during cold replay.
#[must_use = "cold-replayed authority must be revalidated and consumed"]
pub enum ReplayedDomainPostcommitV1<S: ProtectedDomainSchemaV1> {
    /// The complete current transaction retains an effect eligible to run.
    Prepared(DomainPostcommitCapabilityV1<S>),
    /// The complete current transaction contains a terminal publication.
    Terminal(DomainPostcommitCapabilityV1<S>),
}

#[derive(Debug)]
struct AdapterInstanceV1;

/// Owns dormant protected currentness for one closed journal domain.
pub struct ProtectedDomainJournalV1<'journal, S: ProtectedDomainSchemaV1> {
    journal: &'journal mut Journal,
    instance: Arc<AdapterInstanceV1>,
    validator: S::ReplayValidator,
    marker: PhantomData<S>,
}

impl<'journal, S: ProtectedDomainSchemaV1> ProtectedDomainJournalV1<'journal, S> {
    /// Claims a protected-open journal without activating any runtime consumer.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] unless the journal retains protected storage
    /// provenance and is healthy.
    /// Claims a journal with the trusted evidence used for typed replay.
    pub(crate) fn claim_with_validator(
        journal: &'journal mut Journal,
        validator: S::ReplayValidator,
    ) -> Result<Self, ProtectedDomainJournalErrorV1> {
        journal.ensure_protected_authority()?;
        Ok(Self {
            journal,
            instance: Arc::new(AdapterInstanceV1),
            validator,
            marker: PhantomData,
        })
    }

    /// Replays and validates the complete materialized domain projection.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for poison, malformed keys,
    /// foreign namespace mappings, alternate encodings, or allocation bounds.
    pub fn replay(&self) -> Result<ProtectedDomainProjectionV1<S>, ProtectedDomainJournalErrorV1> {
        self.journal.ensure_healthy()?;
        replay_projection::<S>(self.journal, &self.validator)
    }

    /// Reconstructs current pending or terminal authority from durable members.
    ///
    /// Incomplete or state-only groups never become postcommit authority. The
    /// returned composite remains bound to this adapter instance and must pass
    /// [`DomainPostcommitCapabilityV1::consume`] before use.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for malformed grouping,
    /// excessive replay state, poison, or a substituted current envelope.
    pub fn recover_current_postcommit(
        &self,
        transaction_id: [u8; 16],
    ) -> Result<Option<ReplayedDomainPostcommitV1<S>>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        let mut members = Vec::new();
        for (namespace, key_bytes, value) in self.journal.all_records() {
            if !key_bytes.starts_with(S::KEY_PREFIX) {
                continue;
            }
            let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
            if namespace != S::namespace(key.kind) {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
            let member = decode_durable_member::<S>(key, value, &self.validator)?;
            if member.transaction_id == transaction_id {
                if members.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
                    return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
                }
                members.push(member);
            }
        }
        if members.is_empty() {
            return Ok(None);
        }
        members.sort_by_key(|member| member.member_index);
        let transactions = reconstruct_transactions::<S>(&members)?;
        let transaction = transactions
            .into_iter()
            .next()
            .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if transaction.transaction_id != transaction_id
            || transaction.phase == ProtectedDomainReplayPhaseV1::Incomplete
            || transaction.phase == ProtectedDomainReplayPhaseV1::Observed
            || transaction.phase == ProtectedDomainReplayPhaseV1::Superseded
        {
            return Ok(None);
        }
        let transaction_digest = transaction.transaction;
        let set_digest = transaction.set_digest;
        let mut records = Vec::with_capacity(members.len());
        for member in members {
            records.push(DomainPostcommitRecordV1 {
                namespace: S::namespace(member.envelope.key.kind),
                role: S::role(member.envelope.key.kind),
                phase: reducer_phase(&member.envelope)?,
                transaction_phase: match transaction.phase {
                    ProtectedDomainReplayPhaseV1::Prepared => ProtectedReducerPhaseV1::Prepared,
                    ProtectedDomainReplayPhaseV1::Observed => ProtectedReducerPhaseV1::Observed,
                    ProtectedDomainReplayPhaseV1::Terminal => ProtectedReducerPhaseV1::Terminal,
                    ProtectedDomainReplayPhaseV1::Superseded => ProtectedReducerPhaseV1::Superseded,
                    ProtectedDomainReplayPhaseV1::Incomplete => return Ok(None),
                },
                envelope: member.envelope,
                encoded: member.encoded,
            });
        }
        let capability = DomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: transaction_digest,
            set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        };
        Ok(Some(match transaction.phase {
            ProtectedDomainReplayPhaseV1::Prepared => {
                ReplayedDomainPostcommitV1::Prepared(capability)
            }
            ProtectedDomainReplayPhaseV1::Terminal => {
                ReplayedDomainPostcommitV1::Terminal(capability)
            }
            ProtectedDomainReplayPhaseV1::Observed
            | ProtectedDomainReplayPhaseV1::Superseded
            | ProtectedDomainReplayPhaseV1::Incomplete => {
                return Ok(None);
            }
        }))
    }

    /// Captures a sealed exact current-state boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] when replay validation fails.
    pub fn snapshot(&self) -> Result<ProtectedDomainSnapshotV1<S>, ProtectedDomainJournalErrorV1> {
        let projection = self.replay()?;
        Ok(ProtectedDomainSnapshotV1 {
            instance: Arc::clone(&self.instance),
            sequence: self.journal.snapshot_sequence(),
            root: projection.root,
            marker: PhantomData,
        })
    }

    /// Revalidates one sealed snapshot without exposing raw journal authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] unless the
    /// adapter instance, shared sequence, and projection root remain exact.
    pub(crate) fn revalidate_snapshot(
        &self,
        snapshot: &ProtectedDomainSnapshotV1<S>,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(snapshot)
    }

    /// Constructs the canonical payload for a checkpoint of current state.
    ///
    /// The payload binds the protected shared-journal sequence and the exact
    /// materialized domain root. [`Self::plan`] accepts no alternate checkpoint
    /// payload. This per-domain adapter deliberately exposes no compaction;
    /// only a complete shared-journal owner may establish a global floor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] when replay validation fails.
    fn checkpoint_payload(&self) -> Result<Vec<u8>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        Ok(encode_checkpoint_payload::<S>(&snapshot))
    }

    /// Constructs a checkpoint successor bound to the exact current snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] unless `key` names the closed
    /// checkpoint kind or the requested revision/predecessor shape is invalid.
    pub fn checkpoint_successor(
        &self,
        key: ProtectedDomainKeyV1<S>,
        revision: u64,
        predecessor: Option<ObjectDigest>,
    ) -> Result<ProtectedDomainEnvelopeV1<S>, ProtectedDomainJournalErrorV1> {
        if !S::is_checkpoint(key.kind) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let payload = self.checkpoint_payload()?;
        ProtectedDomainEnvelopeV1::new_with_validator(
            key,
            revision,
            predecessor,
            payload,
            &self.validator,
        )
    }

    /// Plans one exact ordered atomic compare-and-swap transaction.
    ///
    /// Successors are sorted by the schema's closed kind order and canonical
    /// key. Each must directly extend the currently materialized envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] for duplicate keys, stale
    /// predecessors, skipped revisions, malformed current state, or journal
    /// preflight failure.
    pub fn plan(
        &self,
        transaction_id: [u8; 16],
        mut successors: Vec<ProtectedDomainEnvelopeV1<S>>,
    ) -> Result<PreparedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        successors.sort_by(|left, right| {
            (S::order(left.key.kind), left.key.as_bytes())
                .cmp(&(S::order(right.key.kind), right.key.as_bytes()))
        });
        if successors.is_empty()
            || successors.windows(2).any(|pair| pair[0].key == pair[1].key)
            || (successors.len() != 1
                && successors
                    .iter()
                    .any(|successor| S::is_checkpoint(successor.key.kind)))
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        let mut records = Vec::with_capacity(successors.len());
        let mut before = Vec::with_capacity(successors.len());
        let mut after = Vec::with_capacity(successors.len());
        let mut roles = Vec::with_capacity(successors.len());
        let member_count = u16::try_from(successors.len())
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let set_digest = domain_transaction_set_digest::<S>(transaction_id, &successors);
        let mut checkpoint = false;
        for (index, successor) in successors.into_iter().enumerate() {
            if S::is_checkpoint(successor.key.kind) {
                if checkpoint || successor.payload != encode_checkpoint_payload::<S>(&snapshot) {
                    return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
                }
                checkpoint = true;
            }
            let namespace = S::namespace(successor.key.kind);
            let previous = self.journal.get(namespace, successor.key.as_bytes());
            validate_successor(previous, &successor, &self.validator)?;
            let member_index = u16::try_from(index)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            let durable = encode_durable_member(
                transaction_id,
                member_index,
                member_count,
                set_digest,
                successor,
            )?;
            let key = durable.envelope.key.as_bytes().to_vec();
            let encoded = durable.encoded;

            before.push(previous.map(<[u8]>::to_vec));
            after.push(encoded.clone());
            roles.push(S::role(durable.envelope.key.kind));
            records.push(JournalRecord::put(namespace, key, encoded));
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        let digest = transaction_digest::<S>(&transaction);
        Ok(PreparedDomainTransactionV1 {
            snapshot,
            transaction,
            before,
            after,
            roles,
            digest,
            set_digest,
        })
    }

    /// Joins an exact prepared domain admission to a global capacity reservation.
    ///
    /// The purpose guard validates the complete closed namespace set. Neither
    /// the underlying journal nor the prepared [`JournalTransaction`] leaves
    /// this engine.
    ///
    /// # Errors
    ///
    /// Returns an error for stale domain CAS state, an unbound request digest,
    /// a foreign purpose namespace set, or failed capacity preflight.
    pub fn prepare_capacity_reserved_admission(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        request: GlobalCapacityReservationRequestV1,
    ) -> Result<PreparedCapacityReservedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        if request.owner_digest != *prepared.digest.as_bytes()
            || !capacity_request_binds_schema::<S>(&request)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.transaction, request.purpose)?;

        let transaction_id = *prepared.transaction.id();
        let authority = self
            .journal
            .claim_global_capacity_reservation_authority(request.purpose)?;
        let reservation =
            authority.prepare_global_capacity_reservation_v1(request, transaction_id)?;
        let reservation_id = reservation.reservation_id();
        let combined = capacity_admission_transaction(&prepared.transaction, reservation.record())?;
        let preflight =
            authority.preflight_global_capacity_reservation_v1(&reservation, &combined)?;

        Ok(PreparedCapacityReservedDomainTransactionV1 {
            prepared,
            combined,
            request,
            reservation_id,
            reservation,
            preflight,
        })
    }

    /// Commits an exact domain admission and capacity record atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain snapshot or predecessor values changed.
    /// Durability failures are returned as retained outcome-unknown state.
    pub fn commit_capacity_reserved_admission(
        &mut self,
        prepared: PreparedCapacityReservedDomainTransactionV1<S>,
    ) -> Result<DomainCapacityAdmissionCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared.prepared, false)?;
        if prepared.request.owner_digest != *prepared.prepared.digest.as_bytes()
            || !capacity_request_binds_schema::<S>(&prepared.request)
            || prepared.reservation_id != prepared.reservation.reservation_id()
            || capacity_admission_transaction(
                &prepared.prepared.transaction,
                prepared.reservation.record(),
            )? != prepared.combined
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.prepared.transaction, prepared.request.purpose)?;

        let PreparedCapacityReservedDomainTransactionV1 {
            prepared: domain,
            combined,
            request,
            reservation_id,
            reservation,
            preflight,
        } = prepared;
        let commit = {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.commit_global_capacity_reservation_v1(&preflight, reservation, &combined)
        };
        let (_, reservation) = match commit {
            Ok(applied) => applied,
            Err(cause) => {
                return Ok(DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainCapacityAdmissionUnknownV1 {
                        prepared: domain,
                        combined,
                        request,
                        reservation_id,
                    },
                    cause,
                });
            }
        };
        if validate_expected_values(self.journal, &domain, true).is_err()
            || !reservation.matches_request(&request, *domain.transaction.id())
            || reservation.reservation_id() != reservation_id
        {
            return Ok(DomainCapacityAdmissionCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacityAdmissionUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    reservation_id,
                },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        let admission_transaction_id = *domain.transaction.id();
        let domain = self.applied(domain)?;
        Ok(DomainCapacityAdmissionCommitOutcomeV1::Applied {
            domain,
            reservation: DomainCapacityReservationV1 {
                reservation,
                request,
                admission_transaction_id,
                marker: PhantomData,
            },
        })
    }

    /// Recovers one exact capacity admission after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or the purpose authority cannot
    /// be validated. Mixed state is retained as [`DomainCapacityAdmissionRecoveryV1::Diverged`].
    pub fn recover_capacity_reserved_admission(
        &mut self,
        pending: DomainCapacityAdmissionUnknownV1<S>,
    ) -> Result<DomainCapacityAdmissionRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let DomainCapacityAdmissionUnknownV1 {
            mut prepared,
            combined,
            request,
            reservation_id,
        } = pending;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        let admission_transaction_id = *prepared.transaction.id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        if after {
            let reservation = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                authority.recover_global_capacity_reservation_v1(reservation_id)
            };
            if let Ok(reservation) = reservation {
                if reservation.matches_request(&request, admission_transaction_id) {
                    let domain = self.applied(prepared)?;
                    return Ok(DomainCapacityAdmissionRecoveryV1::Applied {
                        domain,
                        reservation: DomainCapacityReservationV1 {
                            reservation,
                            request,
                            admission_transaction_id,
                            marker: PhantomData,
                        },
                    });
                }
            }
            return Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
                DomainCapacityAdmissionUnknownV1 {
                    prepared,
                    combined,
                    request,
                    reservation_id,
                },
            ));
        }

        if before {
            prepared.snapshot = self.snapshot()?;
            let (reservation, preflight) = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                let reservation = authority
                    .prepare_global_capacity_reservation_v1(request, admission_transaction_id)?;
                if reservation.reservation_id() != reservation_id
                    || capacity_admission_transaction(&prepared.transaction, reservation.record())?
                        != combined
                {
                    return Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
                        DomainCapacityAdmissionUnknownV1 {
                            prepared,
                            combined,
                            request,
                            reservation_id,
                        },
                    ));
                }
                let preflight =
                    authority.preflight_global_capacity_reservation_v1(&reservation, &combined)?;
                (reservation, preflight)
            };
            return Ok(DomainCapacityAdmissionRecoveryV1::Retry(
                PreparedCapacityReservedDomainTransactionV1 {
                    prepared,
                    combined,
                    request,
                    reservation_id,
                    reservation,
                    preflight,
                },
            ));
        }

        Ok(DomainCapacityAdmissionRecoveryV1::Diverged(
            DomainCapacityAdmissionUnknownV1 {
                prepared,
                combined,
                request,
                reservation_id,
            },
        ))
    }

    /// Recovers one move-only capacity authority from an exact durable identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained reservation exactly matches the
    /// request, admission transaction, domain binding, and purpose authority.
    pub fn recover_domain_capacity_reservation(
        &mut self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
        reservation_id: [u8; 32],
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.recover_global_capacity_reservation_v1(reservation_id)?
        };
        if !reservation.matches_request(&request, admission_transaction_id) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers capacity by its complete deterministic request binding.
    ///
    /// This endpoint avoids requiring a reducer to persist the reservation ID,
    /// which would otherwise form a cycle with the domain transaction digest.
    ///
    /// # Errors
    ///
    /// Returns an error unless exactly one current reservation matches the
    /// request and admission transaction under the closed purpose authority.
    pub fn recover_domain_capacity_reservation_for_request(
        &mut self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        if !capacity_request_binds_schema::<S>(&request) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let reservation_ids = self
            .journal
            .records(RecordNamespace::GlobalCapacityReservation)
            .filter_map(|(key, _)| key.get(key.len().checked_sub(32)?..)?.try_into().ok())
            .collect::<Vec<[u8; 32]>>();
        let mut matching = None;
        let authority = self
            .journal
            .claim_global_capacity_reservation_authority(request.purpose)?;
        for reservation_id in reservation_ids {
            let reservation = match authority.recover_global_capacity_reservation_v1(reservation_id)
            {
                Ok(reservation) => reservation,
                Err(JournalError::ForeignAuthorityNamespace) => continue,
                Err(error) => return Err(error.into()),
            };
            if !reservation.matches_request(&request, admission_transaction_id) {
                continue;
            }
            if matching.replace(reservation).is_some() {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
            }
        }
        let reservation = matching.ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers a domain reservation after the original owner digest was superseded.
    ///
    /// The namespace-46 record remains the sole source of the authenticated
    /// original owner digest and admission transaction identity. The caller
    /// supplies every stable lineage field plus the deterministic reservation
    /// ID, and the purpose guard rejects substitutions before returning the
    /// move-only settlement authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained record is canonical, provenance
    /// backed, schema-owned, and exactly matches the stable recovery binding.
    pub fn recover_domain_capacity_reservation_by_binding(
        &mut self,
        reservation_id: [u8; 32],
        binding: GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(binding.purpose)?;
            authority.recover_global_capacity_reservation_by_binding_v1(reservation_id, &binding)?
        };
        let request = reservation.request();
        let admission_transaction_id = reservation.admission_transaction_id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Recovers the unique domain reservation from stable lineage alone.
    ///
    /// Enumeration and authentication of namespace 46 stay inside the sealed
    /// purpose guard. The returned request and admission transaction are those
    /// retained by the unique canonical record, never caller-shaped values.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or multiple matches, malformed provenance, a
    /// foreign purpose, or a request that does not bind this domain schema.
    pub fn recover_unique_domain_capacity_reservation_by_binding(
        &mut self,
        binding: GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<DomainCapacityReservationV1<S>, ProtectedDomainJournalErrorV1> {
        let reservation = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(binding.purpose)?;
            authority.recover_unique_global_capacity_reservation_v1(&binding)?
        };
        let request = reservation.request();
        let admission_transaction_id = reservation.admission_transaction_id();
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation.reservation_id(),
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        Ok(DomainCapacityReservationV1 {
            reservation,
            request,
            admission_transaction_id,
            marker: PhantomData,
        })
    }

    /// Joins an exact terminal domain transaction to its reservation deletion.
    ///
    /// # Errors
    ///
    /// Returns an error for stale domain CAS, nonterminal semantic state,
    /// substituted reservation binding, foreign namespaces, or capacity bounds.
    pub fn prepare_capacity_settlement(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
        reservation: DomainCapacityReservationV1<S>,
    ) -> Result<PreparedCapacitySettlementDomainTransactionV1<S>, ProtectedDomainJournalErrorV1>
    {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        let phases = postcommit_records(&prepared, &self.validator)?;
        if aggregate_semantic_phases(&phases.iter().map(|record| record.phase).collect::<Vec<_>>())
            != ProtectedReducerPhaseV1::Terminal
            || !reservation
                .reservation
                .matches_request(&reservation.request, reservation.admission_transaction_id)
            || !capacity_request_binds_schema::<S>(&reservation.request)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let decoded = phases
            .iter()
            .map(|record| {
                decode_reducer_payload_with_validator::<S>(
                    record.envelope.key(),
                    record.envelope.payload(),
                    &self.validator,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let members = phases
            .iter()
            .zip(&decoded)
            .map(|(record, payload)| ProtectedCapacitySettlementMemberV1 {
                kind: record.envelope.key.kind,
                identity: record.envelope.key.identity(),
                body: payload.body(),
            })
            .collect::<Vec<_>>();
        if !S::validates_capacity_settlement(
            &reservation.request,
            reservation.admission_transaction_id,
            &members,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        validate_capacity_domain_shape(&prepared.transaction, reservation.request.purpose)?;

        let combined = capacity_settlement_transaction(
            &prepared.transaction,
            reservation.reservation.settlement_record(),
        )?;
        let preflight = {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(reservation.request.purpose)?;
            authority.preflight_reserved_terminal_v1(&reservation.reservation, &combined)?
        };
        Ok(PreparedCapacitySettlementDomainTransactionV1 {
            prepared,
            combined,
            reservation,
            preflight,
        })
    }

    /// Commits one exact terminal branch and releases its retained capacity.
    ///
    /// # Errors
    ///
    /// Returns an error when the domain snapshot or predecessor values changed.
    /// Durability failure retains exact outcome-unknown settlement state.
    pub fn commit_capacity_settlement(
        &mut self,
        prepared: PreparedCapacitySettlementDomainTransactionV1<S>,
    ) -> Result<DomainCapacitySettlementCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared.prepared, false)?;
        let PreparedCapacitySettlementDomainTransactionV1 {
            prepared: domain,
            combined,
            reservation,
            preflight,
        } = prepared;
        let DomainCapacityReservationV1 {
            reservation: raw_reservation,
            request,
            admission_transaction_id,
            marker: _,
        } = reservation;
        let reservation_id = raw_reservation.reservation_id();
        let commit = {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.commit_reserved_terminal_v1(&preflight, raw_reservation, &combined)
        };
        if let Err(cause) = commit {
            return Ok(DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacitySettlementUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    admission_transaction_id,
                    reservation_id,
                },
                cause,
            });
        }
        if validate_expected_values(self.journal, &domain, true).is_err() {
            return Ok(DomainCapacitySettlementCommitOutcomeV1::OutcomeUnknown {
                pending: DomainCapacitySettlementUnknownV1 {
                    prepared: domain,
                    combined,
                    request,
                    admission_transaction_id,
                    reservation_id,
                },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        self.applied(domain)
            .map(DomainCapacitySettlementCommitOutcomeV1::Applied)
    }

    /// Recovers one ambiguous capacity settlement after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns an error when protected replay or the purpose authority fails.
    pub fn recover_capacity_settlement(
        &mut self,
        pending: DomainCapacitySettlementUnknownV1<S>,
    ) -> Result<DomainCapacitySettlementRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let DomainCapacitySettlementUnknownV1 {
            mut prepared,
            combined,
            request,
            admission_transaction_id,
            reservation_id,
        } = pending;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        if !validate_domain_capacity_lineage_v1::<S>(
            &request,
            admission_transaction_id,
            reservation_id,
        ) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        if after {
            let reservation = {
                let authority = self
                    .journal
                    .claim_global_capacity_reservation_authority(request.purpose)?;
                authority.lookup_global_capacity_reservation_v1(reservation_id)?
            };
            if reservation.is_none() {
                return self
                    .applied(prepared)
                    .map(DomainCapacitySettlementRecoveryV1::Applied);
            }
        } else if before {
            prepared.snapshot = self.snapshot()?;
            let reservation = self.recover_domain_capacity_reservation(
                request,
                admission_transaction_id,
                reservation_id,
            )?;
            if capacity_settlement_transaction(
                &prepared.transaction,
                reservation.reservation.settlement_record(),
            )? == combined
            {
                let preflight = {
                    let authority = self
                        .journal
                        .claim_global_capacity_reservation_authority(request.purpose)?;
                    authority.preflight_reserved_terminal_v1(&reservation.reservation, &combined)?
                };
                return Ok(DomainCapacitySettlementRecoveryV1::Retry(
                    PreparedCapacitySettlementDomainTransactionV1 {
                        prepared,
                        combined,
                        reservation,
                        preflight,
                    },
                ));
            }
        }

        Ok(DomainCapacitySettlementRecoveryV1::Diverged(
            DomainCapacitySettlementUnknownV1 {
                prepared,
                combined,
                request,
                admission_transaction_id,
                reservation_id,
            },
        ))
    }

    /// Commits a plan and releases authority only after exact readback.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] for a plan
    /// issued by another instance or invalidated by an intervening commit.
    pub fn commit(
        &mut self,
        prepared: PreparedDomainTransactionV1<S>,
    ) -> Result<DomainCommitOutcomeV1<S>, ProtectedDomainJournalErrorV1> {
        self.validate_snapshot(&prepared.snapshot)?;
        validate_expected_values(self.journal, &prepared, false)?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&prepared.transaction))?;
        if let Err(cause) = self.journal.commit(&prepared.transaction) {
            return Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        if validate_expected_values(self.journal, &prepared, true).is_err() {
            return Ok(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        self.applied(prepared).map(DomainCommitOutcomeV1::Applied)
    }

    /// Commits while retaining the exact prepared token on preflight failure.
    pub fn commit_retaining(
        &mut self,
        mut prepared: PreparedDomainTransactionV1<S>,
    ) -> DomainRetainedCommitV1<S> {
        if self.validate_snapshot(&prepared.snapshot).is_err() {
            if let Err(error) = self.replay() {
                return DomainRetainedCommitV1::Retryable { prepared, error };
            }
            if values_match(self.journal, &prepared, true) {
                return match self.applied_retaining(prepared) {
                    Ok(applied) => {
                        DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::Applied(applied))
                    }
                    Err((prepared, _)) => {
                        DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                            pending: DomainOutcomeUnknownV1 { prepared },
                            cause: JournalError::AuthorityPreflightMismatch,
                        })
                    }
                };
            }
            if !values_match(self.journal, &prepared, false) {
                return DomainRetainedCommitV1::Retryable {
                    prepared,
                    error: ProtectedDomainJournalErrorV1::CompareAndSwapFailed,
                };
            }
            prepared.snapshot = match self.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => return DomainRetainedCommitV1::Retryable { prepared, error },
            };
        }
        if let Err(error) = validate_expected_values(self.journal, &prepared, false) {
            return DomainRetainedCommitV1::Retryable { prepared, error };
        }
        if let Err(error) = self
            .journal
            .preflight_transactions(std::slice::from_ref(&prepared.transaction))
            .map_err(ProtectedDomainJournalErrorV1::from)
        {
            return DomainRetainedCommitV1::Retryable { prepared, error };
        }
        if let Err(cause) = self.journal.commit(&prepared.transaction) {
            return DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause,
            });
        }
        if validate_expected_values(self.journal, &prepared, true).is_err() {
            return DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                pending: DomainOutcomeUnknownV1 { prepared },
                cause: JournalError::AuthorityPreflightMismatch,
            });
        }
        match self.applied_retaining(prepared) {
            Ok(applied) => DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::Applied(applied)),
            Err((prepared, _)) => {
                DomainRetainedCommitV1::Outcome(DomainCommitOutcomeV1::OutcomeUnknown {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    cause: JournalError::AuthorityPreflightMismatch,
                })
            }
        }
    }

    /// Resolves an ambiguous transaction after protected reopen.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1`] if the reopened journal is
    /// poisoned or its domain projection is malformed.
    pub fn recover(
        &self,
        pending: DomainOutcomeUnknownV1<S>,
    ) -> Result<DomainRecoveryV1<S>, ProtectedDomainJournalErrorV1> {
        self.replay()?;
        let prepared = pending.prepared;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        if after {
            return self.applied(prepared).map(DomainRecoveryV1::Applied);
        }
        if before {
            let mut prepared = prepared;
            prepared.snapshot = self.snapshot()?;
            self.journal
                .preflight_transactions(std::slice::from_ref(&prepared.transaction))?;
            return Ok(DomainRecoveryV1::Retry(prepared));
        }
        Ok(DomainRecoveryV1::Diverged(DomainOutcomeUnknownV1 {
            prepared,
        }))
    }

    /// Recovers while retaining the opaque pending token on transient failure.
    pub fn recover_retaining(
        &self,
        pending: DomainOutcomeUnknownV1<S>,
    ) -> DomainRetainedRecoveryV1<S> {
        if let Err(error) = self.replay() {
            return DomainRetainedRecoveryV1::Retryable { pending, error };
        }
        let prepared = pending.prepared;
        let before = values_match(self.journal, &prepared, false);
        let after = values_match(self.journal, &prepared, true);
        if after {
            return match self.applied_retaining(prepared) {
                Ok(applied) => {
                    DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Applied(applied))
                }
                Err((prepared, error)) => DomainRetainedRecoveryV1::Retryable {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    error,
                },
            };
        }
        if before {
            let mut prepared = prepared;
            prepared.snapshot = match self.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return DomainRetainedRecoveryV1::Retryable {
                        pending: DomainOutcomeUnknownV1 { prepared },
                        error,
                    };
                }
            };
            if let Err(error) = self
                .journal
                .preflight_transactions(std::slice::from_ref(&prepared.transaction))
                .map_err(ProtectedDomainJournalErrorV1::from)
            {
                return DomainRetainedRecoveryV1::Retryable {
                    pending: DomainOutcomeUnknownV1 { prepared },
                    error,
                };
            }
            return DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Retry(prepared));
        }
        DomainRetainedRecoveryV1::Outcome(DomainRecoveryV1::Diverged(DomainOutcomeUnknownV1 {
            prepared,
        }))
    }

    fn validate_snapshot(
        &self,
        snapshot: &ProtectedDomainSnapshotV1<S>,
    ) -> Result<(), ProtectedDomainJournalErrorV1> {
        let current = self.snapshot()?;
        if !Arc::ptr_eq(&snapshot.instance, &self.instance)
            || snapshot.sequence != current.sequence
            || snapshot.root != current.root
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    fn applied(
        &self,
        prepared: PreparedDomainTransactionV1<S>,
    ) -> Result<AppliedDomainTransactionV1<S>, ProtectedDomainJournalErrorV1> {
        let snapshot = self.snapshot()?;
        let records = postcommit_records(&prepared, &self.validator)?;
        let capability = Some(DomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: prepared.digest,
            set_digest: prepared.set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        });
        Ok(AppliedDomainTransactionV1 {
            transaction: prepared.digest,
            snapshot,
            capability,
        })
    }

    fn applied_retaining(
        &self,
        prepared: PreparedDomainTransactionV1<S>,
    ) -> Result<
        AppliedDomainTransactionV1<S>,
        (
            PreparedDomainTransactionV1<S>,
            ProtectedDomainJournalErrorV1,
        ),
    > {
        let snapshot = match self.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return Err((prepared, error)),
        };
        let records = match postcommit_records(&prepared, &self.validator) {
            Ok(records) => records,
            Err(error) => return Err((prepared, error)),
        };
        let capability = Some(DomainPostcommitCapabilityV1 {
            instance: Arc::clone(&self.instance),
            transaction: prepared.digest,
            set_digest: prepared.set_digest,
            sequence: snapshot.sequence,
            root: snapshot.root,
            records,
            marker: PhantomData,
        });
        Ok(AppliedDomainTransactionV1 {
            transaction: prepared.digest,
            snapshot,
            capability,
        })
    }
}

impl<S: ProtectedDomainSchemaV1> DomainPostcommitCapabilityV1<S> {
    /// Returns the transaction represented by this composite capability.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the commitment to every ordered transaction member.
    #[must_use]
    pub const fn transaction_set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the exact postcommit shared-journal sequence.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the complete postcommit materialized domain projection.
    #[must_use]
    pub const fn projection_root(&self) -> ObjectDigest {
        self.root
    }

    /// Consumes the composite capability after exact current-envelope replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedDomainJournalErrorV1::StaleAuthority`] if the journal
    /// is unhealthy, another commit advanced it, or any transaction member is
    /// no longer byte-exact current state.
    pub fn consume<'current>(
        self,
        authority: &'current ProtectedDomainJournalV1<'_, S>,
    ) -> Result<ValidatedDomainPostcommitV1<'current, S>, ProtectedDomainJournalErrorV1> {
        let current = authority.snapshot()?;
        if !Arc::ptr_eq(&self.instance, &authority.instance)
            || self.sequence != current.sequence
            || self.root != current.root
            || self.records.iter().any(|record| {
                authority
                    .journal
                    .get(record.namespace, record.envelope.key.as_bytes())
                    != Some(record.encoded.as_slice())
            })
        {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(ValidatedDomainPostcommitV1 {
            transaction: self.transaction,
            set_digest: self.set_digest,
            records: self.records,
            current: PhantomData,
        })
    }
}

impl<S: ProtectedDomainSchemaV1> ValidatedDomainPostcommitV1<'_, S> {
    /// Returns the exact atomic transaction commitment.
    #[must_use]
    pub const fn transaction_digest(&self) -> ObjectDigest {
        self.transaction
    }

    /// Returns the commitment to every ordered transaction member.
    #[must_use]
    pub const fn transaction_set_digest(&self) -> ObjectDigest {
        self.set_digest
    }

    /// Returns the complete ordered transaction member set.
    #[must_use]
    pub fn records(&self) -> &[DomainPostcommitRecordV1<S>] {
        &self.records
    }
}

pub(crate) fn validate_successor<S: ProtectedDomainSchemaV1>(
    previous: Option<&[u8]>,
    successor: &ProtectedDomainEnvelopeV1<S>,
    validator: &S::ReplayValidator,
) -> Result<(), ProtectedDomainJournalErrorV1> {
    let revalidated = ProtectedDomainEnvelopeV1::<S>::decode(
        successor.key.clone(),
        &successor.encode(),
        validator,
    )?;
    if &revalidated != successor {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    match previous {
        None if successor.revision == 1 && successor.predecessor.is_none() => Ok(()),
        Some(bytes) => {
            let key = successor.key.clone();
            let previous = decode_durable_member::<S>(key, bytes, validator)?.envelope;
            let next_revision = previous
                .revision
                .checked_add(1)
                .ok_or(ProtectedDomainJournalErrorV1::CompareAndSwapFailed)?;
            if successor.revision == next_revision && successor.predecessor == Some(previous.digest)
            {
                Ok(())
            } else {
                Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed)
            }
        }
        _ => Err(ProtectedDomainJournalErrorV1::CompareAndSwapFailed),
    }
}

fn postcommit_records<S: ProtectedDomainSchemaV1>(
    prepared: &PreparedDomainTransactionV1<S>,
    validator: &S::ReplayValidator,
) -> Result<Vec<DomainPostcommitRecordV1<S>>, ProtectedDomainJournalErrorV1> {
    if prepared.transaction.records().len() != prepared.roles.len()
        || prepared.transaction.records().len() != prepared.after.len()
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let mut records = Vec::new();
    for ((record, role), value) in prepared
        .transaction
        .records()
        .iter()
        .zip(&prepared.roles)
        .zip(&prepared.after)
    {
        if record.value() != Some(value.as_slice()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let key = ProtectedDomainKeyV1::<S>::decode(record.key())?;
        if record.namespace() != S::namespace(key.kind) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let durable = decode_durable_member::<S>(key, value, validator)?;
        let postcommit = DomainPostcommitRecordV1 {
            namespace: record.namespace(),
            role: *role,
            phase: reducer_phase(&durable.envelope)?,
            transaction_phase: ProtectedReducerPhaseV1::Observed,
            envelope: durable.envelope,
            encoded: durable.encoded,
        };
        records.push(postcommit);
    }
    let transaction_phase = aggregate_semantic_phases(
        &records
            .iter()
            .map(|record| record.phase)
            .collect::<Vec<_>>(),
    );
    for record in &mut records {
        record.transaction_phase = transaction_phase;
    }
    Ok(records)
}

fn validate_expected_values<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
    prepared: &PreparedDomainTransactionV1<S>,
    after: bool,
) -> Result<(), ProtectedDomainJournalErrorV1> {
    values_match(journal, prepared, after)
        .then_some(())
        .ok_or(ProtectedDomainJournalErrorV1::CompareAndSwapFailed)
}

fn values_match<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
    prepared: &PreparedDomainTransactionV1<S>,
    after: bool,
) -> bool {
    let records = prepared.transaction.records();
    if records.len() != prepared.before.len() || records.len() != prepared.after.len() {
        return false;
    }
    records
        .iter()
        .zip(prepared.before.iter().zip(&prepared.after))
        .all(|(record, (before, after_value))| {
            let expected = if after {
                Some(after_value.as_slice())
            } else {
                before.as_deref()
            };
            journal.get(record.namespace(), record.key()) == expected
        })
}

fn capacity_admission_transaction(
    domain: &JournalTransaction,
    reservation: &JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    if reservation.namespace() != RecordNamespace::GlobalCapacityReservation
        || domain
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
    {
        return Err(JournalError::InvalidTransaction);
    }
    let mut records = domain.records().to_vec();
    records.push(reservation.clone());
    JournalTransaction::new(*domain.id(), records)
}

fn validate_capacity_domain_shape(
    transaction: &JournalTransaction,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<(), JournalError> {
    let mut publisher_authority = false;
    let mut publication = false;
    let mut effect = false;
    for record in transaction.records() {
        match record.namespace() {
            RecordNamespace::PublisherAuthority => publisher_authority = true,
            RecordNamespace::AuthorityPublication => publication = true,
            RecordNamespace::Effect => effect = true,
            _ => return Err(JournalError::ForeignAuthorityNamespace),
        }
    }
    let closed = match purpose {
        GlobalCapacityReservationPurposeV1::PublisherCompletion => {
            publisher_authority && publication
        }
        GlobalCapacityReservationPurposeV1::RuntimeExecution => {
            effect && !publisher_authority && !publication
        }
    };
    closed
        .then_some(())
        .ok_or(JournalError::ForeignAuthorityNamespace)
}

fn capacity_settlement_transaction(
    domain: &JournalTransaction,
    settlement: JournalRecord,
) -> Result<JournalTransaction, JournalError> {
    capacity_admission_transaction(domain, &settlement)
}

pub(crate) fn replay_projection<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
    validator: &S::ReplayValidator,
) -> Result<ProtectedDomainProjectionV1<S>, ProtectedDomainJournalErrorV1> {
    let mut members = Vec::new();
    let mut seen = BTreeSet::new();
    for (namespace, key_bytes, value) in journal.all_records() {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
        if namespace != S::namespace(key.kind) || !seen.insert(key_bytes.to_vec()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        if members.len() >= MAXIMUM_COLD_REPLAY_MEMBERS {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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

/// Structurally authenticates every current record for one domain without
/// interpreting its reducer body.
///
/// # Errors
///
/// Returns [`ProtectedDomainJournalErrorV1`] for an unprotected or unhealthy
/// journal, malformed framing, incorrect namespace mapping, or any failed
/// canonical hash check.
pub(crate) fn protected_current_record_candidates_v1<S: ProtectedDomainSchemaV1>(
    journal: &Journal,
) -> Result<Vec<ProtectedCurrentRecordCandidateV1<S>>, ProtectedDomainJournalErrorV1> {
    journal.ensure_protected_authority()?;

    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for (namespace, key_bytes, value) in journal.all_records() {
        if !key_bytes.starts_with(S::KEY_PREFIX) {
            continue;
        }
        if candidates.len() >= MAXIMUM_COLD_REPLAY_MEMBERS || !seen.insert(key_bytes.to_vec()) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }

        let key = ProtectedDomainKeyV1::<S>::decode(key_bytes)?;
        if namespace != S::namespace(key.kind) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
) -> Result<ProtectedCurrentRecordCandidateV1<S>, ProtectedDomainJournalErrorV1> {
    if bytes.len() < 189
        || bytes.len() > 188 + S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != DURABLE_MEMBER_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10..12] != [0; 2]
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let transaction_id: [u8; 16] = bytes[12..28]
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let member_index = u16::from_be_bytes([bytes[28], bytes[29]]);
    let member_count = u16::from_be_bytes([bytes[30], bytes[31]]);
    let set_digest = &bytes[32..64];
    let envelope_length = usize::try_from(u32::from_be_bytes(
        bytes[64..68]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
    ))
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let envelope_end = 68_usize
        .checked_add(envelope_length)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if transaction_id == [0; 16]
        || member_count == 0
        || member_index >= member_count
        || set_digest.iter().all(|byte| *byte == 0)
        || bytes.len() != envelope_end + 32
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let member_digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"durable-member\0")
        .chain_update(&bytes[..envelope_end])
        .finalize()
        .into();
    if bytes[envelope_end..] != member_digest {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }

    let envelope = &bytes[68..envelope_end];
    if envelope.len() < 88
        || envelope.len() > 88 + S::MAXIMUM_PAYLOAD_BYTES
        || envelope[..8] != S::MAGIC
        || u16::from_be_bytes([envelope[8], envelope[9]]) != ENVELOPE_VERSION
        || envelope[10] != S::kind_code(key.kind)
        || envelope[11] != 0
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let revision = u64::from_be_bytes(
        envelope[12..20]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
    );
    let predecessor_bytes: [u8; 32] = envelope[20..52]
        .try_into()
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let predecessor =
        (predecessor_bytes != [0; 32]).then_some(ObjectDigest::from_bytes(predecessor_bytes));
    let payload_length = usize::try_from(u32::from_be_bytes(
        envelope[52..56]
            .try_into()
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
    ))
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let payload_end = 56_usize
        .checked_add(payload_length)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if revision == 0
        || revision == u64::MAX
        || (revision == 1) != predecessor.is_none()
        || payload_length == 0
        || payload_length > S::MAXIMUM_PAYLOAD_BYTES
        || envelope.len() != payload_end + 32
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let payload = &envelope[56..payload_end];
    let envelope_digest = envelope_digest::<S>(&key, revision, predecessor, payload);
    if &envelope[payload_end..] != envelope_digest.as_bytes() {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }

    let body = if S::is_checkpoint(key.kind) {
        if !valid_checkpoint_payload::<S>(payload) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
) -> Result<&'payload [u8], ProtectedDomainJournalErrorV1> {
    if bytes.len() < 60
        || bytes.len() > S::MAXIMUM_PAYLOAD_BYTES
        || &bytes[..8] != REDUCER_PAYLOAD_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != ENVELOPE_VERSION
        || bytes[10] != S::family(key.kind)
        || bytes[11] != S::kind_code(key.kind)
        || bytes[13] != 0
        || decode_phase(bytes[12]).is_none()
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let companion_count = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let body_length = usize::try_from(u32::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19],
    ]))
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let companions_end = 20_usize
        .checked_add(
            companion_count
                .checked_mul(32)
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
        )
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let body_end = companions_end
        .checked_add(body_length)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if companion_count > MAXIMUM_REDUCER_COMPANIONS
        || body_length < 8
        || bytes.len() != body_end + 32
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let companions = bytes[20..companions_end]
        .chunks_exact(32)
        .map(|digest| {
            digest
                .try_into()
                .map(ObjectDigest::from_bytes)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if companions
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
        || companions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(&bytes[companions_end..body_end])
}

fn reconstruct_transactions<S: ProtectedDomainSchemaV1>(
    members: &[DurableDomainMemberV1<S>],
) -> Result<Vec<ProtectedDomainReplayTransactionV1<S>>, ProtectedDomainJournalErrorV1> {
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
            .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        if group.iter().any(|member| {
            member.member_count != first.member_count
                || member.set_digest != first.set_digest
                || member.transaction_id != transaction_id
        }) || group
            .windows(2)
            .any(|pair| pair[0].member_index == pair[1].member_index)
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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

fn reducer_phase<S: ProtectedDomainSchemaV1>(
    envelope: &ProtectedDomainEnvelopeV1<S>,
) -> Result<ProtectedReducerPhaseV1, ProtectedDomainJournalErrorV1> {
    Ok(envelope.validated_phase)
}

fn aggregate_reducer_phase<S: ProtectedDomainSchemaV1>(
    records: &[ProtectedDomainEnvelopeV1<S>],
) -> Result<ProtectedDomainReplayPhaseV1, ProtectedDomainJournalErrorV1> {
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

fn aggregate_semantic_phases(phases: &[ProtectedReducerPhaseV1]) -> ProtectedReducerPhaseV1 {
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
) -> Result<ObjectDigest, ProtectedDomainJournalErrorV1> {
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

fn transaction_digest<S: ProtectedDomainSchemaV1>(
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

fn domain_transaction_set_digest<S: ProtectedDomainSchemaV1>(
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

fn encode_checkpoint_payload<S: ProtectedDomainSchemaV1>(
    snapshot: &ProtectedDomainSnapshotV1<S>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(88);
    bytes.extend_from_slice(CHECKPOINT_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&snapshot.sequence.to_be_bytes());
    bytes.extend_from_slice(snapshot.root.as_bytes());
    let digest: [u8; 32] = Sha256::new()
        .chain_update(S::HASH_DOMAIN)
        .chain_update(b"checkpoint\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&digest);
    bytes
}

/// Encodes a reducer body only after schema-specific trusted validation.
pub(crate) fn encode_reducer_payload_with_validator<S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    body: &[u8],
    validator: &S::ReplayValidator,
) -> Result<Vec<u8>, ProtectedDomainJournalErrorV1> {
    let phase = S::decode_reducer_phase(validator, key.kind, &key.identity, body)
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let companions = derived_companions(key, body);
    if body.len() < 8
        || body.len() > S::MAXIMUM_PAYLOAD_BYTES
        || companions.len() > MAXIMUM_REDUCER_COMPANIONS
        || companions
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        || !companions.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let companion_count = u16::try_from(companions.len())
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let body_length =
        u32::try_from(body.len()).map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let capacity = 20_usize
        .checked_add(companions.len().saturating_mul(32))
        .and_then(|length| length.checked_add(body.len()))
        .and_then(|length| length.checked_add(32))
        .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if capacity > S::MAXIMUM_PAYLOAD_BYTES {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
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
pub(crate) fn bind_domain_capacity_request_v1<S: ProtectedDomainSchemaV1>(
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

fn capacity_request_binds_schema<S: ProtectedDomainSchemaV1>(
    request: &GlobalCapacityReservationRequestV1,
) -> bool {
    request.owner_id == domain_capacity_owner_id::<S>(request)
}

/// Validates the durable schema and deterministic identity of one reservation.
pub(crate) fn validate_domain_capacity_lineage_v1<S: ProtectedDomainSchemaV1>(
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
pub(crate) struct DecodedReducerPayloadV1<'payload> {
    body: &'payload [u8],
    companions: Vec<ObjectDigest>,
    phase: ProtectedReducerPhaseV1,
}

impl<'payload> DecodedReducerPayloadV1<'payload> {
    /// Returns the byte-exact canonical reducer body.
    pub(crate) const fn body(&self) -> &'payload [u8] {
        self.body
    }

    /// Returns canonical strictly ordered companion commitments.
    pub(crate) fn companions(&self) -> &[ObjectDigest] {
        &self.companions
    }

    /// Returns the schema-decoded semantic reducer phase.
    pub(crate) const fn phase(&self) -> ProtectedReducerPhaseV1 {
        self.phase
    }
}

/// Decodes a reducer body only under the same trusted schema evidence.
pub(crate) fn decode_reducer_payload_with_validator<'payload, S: ProtectedDomainSchemaV1>(
    key: &ProtectedDomainKeyV1<S>,
    bytes: &'payload [u8],
    validator: &S::ReplayValidator,
) -> Result<DecodedReducerPayloadV1<'payload>, ProtectedDomainJournalErrorV1> {
    if !valid_reducer_payload::<S>(key, bytes, validator) {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    let phase = decode_phase(bytes[12]).ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let companion_count = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let companions_end = 20 + companion_count * 32;
    let body_length = usize::try_from(u32::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19],
    ]))
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    let body_end = companions_end + body_length;
    let companions = bytes[20..companions_end]
        .chunks_exact(32)
        .map(|digest| {
            let bytes: [u8; 32] = digest
                .try_into()
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            Ok(ObjectDigest::from_bytes(bytes))
        })
        .collect::<Result<Vec<_>, ProtectedDomainJournalErrorV1>>()?;
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
