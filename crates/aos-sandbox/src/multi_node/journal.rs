//! Durable journal, replay, compaction-floor, and partial-effect recovery models.
//!
//! One canonical hash chain covers capability, assignment, drain, transfer,
//! and watch state. Reducers are pure and do not perform effects; they make
//! equivocation, skipped history, and unsafe compaction explicit.
//!
//! Domain state and its enclosing journal objects use bounded canonical bytes:
//!
//! ```text
//! AOSJDOM1 | domain:u8 | state-length:u32 | closed typed domain state | state-sha256
//! AOSJREC1 | domain:u8 | operation[16] | sequence:u64 | predecessor[32]
//!          | semantic-payload[32] | state-length:u32 | AOSJDOM1-payload
//!          | effect:u8 | effect[32] | commitment[32]
//! AOSJCHK1 | domain:u8 | floor:u64 | floor-record[32] | state-length:u32
//!          | AOSJDOM1-payload | operation[16] | semantic-payload[32]
//!          | effect:u8 | effect[32] | generation:u64 | commitment[32]
//! ```

use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{ObjectDigest, OperationId};

use super::assignment::{AssignmentEffectPlanV1, AssignmentIntentV1};
use super::evidence::AuthenticatedEvidenceContextV1;
use super::reducer_state::{MultiNodeReducerStateV1, decode_state, encode_state};
use super::store_authority::{
    ProtectedStoreCommitGrantV1, ProtectedStoreObjectKindV1, ProtectedStoreRestoreGrantV1,
};

/// Maximum capability reducer-state bytes, including 256 maximum-length features.
pub const MAX_CAPABILITY_JOURNAL_STATE_BYTES: usize = 96 * 1024;
/// Maximum assignment reducer-state bytes, including manifest and affinity sets.
pub const MAX_ASSIGNMENT_JOURNAL_STATE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum drain reducer-state bytes, including all bounded assignment rows.
pub const MAX_DRAIN_JOURNAL_STATE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum transfer reducer-state bytes, including all 65,536 chunk checkpoints.
///
/// The state intentionally retains both the immutable manifest and protected
/// staged-object projections, so its bound must cover two independently
/// validated representations of the maximum chunk set.
pub const MAX_SNAPSHOT_JOURNAL_STATE_BYTES: usize = 80 * 1024 * 1024;
/// Maximum watch reducer-state bytes, including one bounded event batch projection.
pub const MAX_WATCH_JOURNAL_STATE_BYTES: usize = 20 * 1024 * 1024;
/// Maximum bytes accepted by any one canonical domain-state payload.
pub const MAX_MULTI_NODE_DOMAIN_STATE_BYTES: usize = MAX_SNAPSHOT_JOURNAL_STATE_BYTES;
/// Maximum bytes accepted by any canonical journal record or checkpoint.
pub const MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES: usize = MAX_MULTI_NODE_DOMAIN_STATE_BYTES
    + CANONICAL_DOMAIN_ENVELOPE_BYTES
    + CANONICAL_CHECKPOINT_BYTES;
/// Maximum protected successor records admitted by one restore operation.
pub const MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS: usize = 65_536;

const CANONICAL_DOMAIN_ENVELOPE_BYTES: usize = 8 + 1 + 4 + 32;
const CANONICAL_RECORD_BYTES: usize = 8 + 1 + 16 + 8 + 32 + 32 + 4 + 1 + 32 + 32;
const CANONICAL_CHECKPOINT_BYTES: usize = 8 + 1 + 8 + 32 + 4 + 16 + 32 + 1 + 32 + 8 + 32;

/// Selects an independently replayed multi-node journal domain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MultiNodeJournalDomainV1 {
    /// Capability observation and boot-lineage state.
    Capability = 0,
    /// Assignment intent, acceptance, and authority observation state.
    Assignment = 1,
    /// Drain directive, generation, and containment state.
    Drain = 2,
    /// Snapshot/dependency staging and publication state.
    SnapshotTransfer = 3,
    /// Watch bootstrap, event history, and compaction state.
    Watch = 4,
}

/// Selects the durable partial-effect boundary represented by a record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum JournalEffectStateV1 {
    /// Desired state is durable and no effect was admitted.
    IntentCommitted = 0,
    /// Exact effect inputs and idempotency identity are durable.
    EffectPrepared = 1,
    /// The external effect was observed but its state commit is incomplete.
    EffectObserved = 2,
    /// State and effect observation committed atomically or by verified recovery.
    Committed = 3,
    /// Recovery is driving an exact idempotent compensation.
    Compensating = 4,
    /// Fail-closed containment completed after ambiguous partial effect.
    Contained = 5,
}

/// Retains a durable effect boundary without recreating effect authority.
///
/// A protected record or checkpoint authenticates this projection. Callers may
/// use it to choose fail-closed recovery, but must obtain fresh verifier-issued
/// evidence before retrying, committing, or compensating an external effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableJournalEffectV1 {
    operation: OperationId,
    payload_digest: ObjectDigest,
    state: JournalEffectStateV1,
    effect_digest: ObjectDigest,
}

impl DurableJournalEffectV1 {
    fn from_record(record: &MultiNodeJournalRecordV1) -> Self {
        Self {
            operation: record.operation(),
            payload_digest: record.payload_digest(),
            state: record.effect_state(),
            effect_digest: record.effect_digest(),
        }
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact semantic input commitment.
    #[must_use]
    pub const fn payload_digest(self) -> ObjectDigest {
        self.payload_digest
    }

    /// Returns the closed partial-effect state.
    #[must_use]
    pub const fn state(self) -> JournalEffectStateV1 {
        self.state
    }

    /// Returns the exact effect input or observation commitment.
    #[must_use]
    pub const fn effect_digest(self) -> ObjectDigest {
        self.effect_digest
    }
}

/// Reports malformed, skipped, equivocated, or unsafely compacted journal history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidMultiNodeJournal {
    /// A sequence, digest, operation, or compaction generation is zero.
    #[error("multi-node journal value is unspecified")]
    Unspecified,
    /// A record does not directly extend the canonical hash chain.
    #[error("multi-node journal record skips or contradicts history")]
    HistoryGap,
    /// One sequence was reused for different canonical record content.
    #[error("multi-node journal sequence equivocated")]
    Equivocation,
    /// A checkpoint does not exactly cover the reducer's current history.
    #[error("multi-node journal compaction checkpoint is unsafe")]
    UnsafeCompaction,
    /// A partial-effect recovery transition violates the closed state graph.
    #[error("multi-node partial-effect recovery transition is invalid")]
    InvalidRecoveryTransition,
    /// A protected-store receipt is absent, stale, or bound to other bytes.
    #[error("multi-node protected-store receipt does not match")]
    ProtectedStoreMismatch,
    /// A journal/state payload is noncanonical, truncated, or oversized.
    #[error("multi-node journal payload is not canonical")]
    NonCanonicalPayload,
}

/// Carries the exact bounded canonical reducer state for one journal domain.
///
/// The payload is preserved in records and checkpoints so restore can
/// reconstruct domain state instead of recovering only a hash commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJournalPayloadV1 {
    state: MultiNodeReducerStateV1,
    canonical_state: Vec<u8>,
    digest: ObjectDigest,
}

impl CanonicalJournalPayloadV1 {
    /// Captures a complete typed reducer state under its closed domain schema.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] when the body
    /// is oversized or cannot round-trip through the domain's concrete codec.
    pub fn new(state: MultiNodeReducerStateV1) -> Result<Self, InvalidMultiNodeJournal> {
        let canonical_state = encode_state(&state)?;
        if canonical_state.is_empty() || canonical_state.len() > domain_state_budget(state.domain())
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let restored = decode_state(state.domain(), &canonical_state)?;
        if restored != state {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let digest = ObjectDigest::from_bytes(Sha256::digest(&canonical_state).into());
        Ok(Self {
            state,
            canonical_state,
            digest,
        })
    }

    /// Returns the domain whose complete reducer state is encoded.
    #[must_use]
    pub const fn domain(&self) -> MultiNodeJournalDomainV1 {
        self.state.domain()
    }

    /// Returns the exact canonical reducer-state bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical_state
    }

    /// Returns the fully decoded closed domain projection.
    #[must_use]
    pub const fn state(&self) -> &MultiNodeReducerStateV1 {
        &self.state
    }

    /// Returns the exact assignment commitment carried by an assignment projection.
    #[must_use]
    pub fn assignment_digest(&self) -> Option<ObjectDigest> {
        match &self.state {
            MultiNodeReducerStateV1::Assignment(state) => Some(state.intent().assignment_digest()),
            _ => None,
        }
    }

    /// Returns the selected capability identity/currentness commitment.
    #[must_use]
    pub fn assignment_capability_evidence_digest(&self) -> Option<ObjectDigest> {
        match &self.state {
            MultiNodeReducerStateV1::Assignment(state) => Some(state.capability_evidence_digest()),
            _ => None,
        }
    }

    /// Returns the complete typed assignment projection, when present.
    #[must_use]
    pub fn assignment_state(&self) -> Option<&super::reducer_state::AssignmentJournalStateV1> {
        match &self.state {
            MultiNodeReducerStateV1::Assignment(state) => Some(state),
            _ => None,
        }
    }

    /// Returns the complete typed snapshot-transfer projection, when present.
    #[must_use]
    pub fn snapshot_transfer_state(
        &self,
    ) -> Option<&super::reducer_state::SnapshotTransferJournalStateV1> {
        match &self.state {
            MultiNodeReducerStateV1::SnapshotTransfer(state) => Some(state),
            _ => None,
        }
    }

    /// Returns the commitment derived from the retained exact bytes.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Encodes the domain state in its unique bounded canonical envelope.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CANONICAL_DOMAIN_ENVELOPE_BYTES + self.as_bytes().len());
        bytes.extend_from_slice(b"AOSJDOM1");
        bytes.push(self.domain() as u8);
        bytes.extend_from_slice(&(self.as_bytes().len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.as_bytes());
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    /// Decodes one exact canonical domain-state envelope.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for malformed,
    /// oversized, digest-mismatched, or noncanonical domain state.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, InvalidMultiNodeJournal> {
        if bytes.len() < 53
            || bytes.len() > MAX_MULTI_NODE_DOMAIN_STATE_BYTES + CANONICAL_DOMAIN_ENVELOPE_BYTES
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let mut decoder = JournalPayloadDecoderV1::new(bytes)?;
        decoder.expect_magic(b"AOSJDOM1")?;
        let domain = decode_domain(decoder.read_u8()?)?;
        let length = usize::try_from(decoder.read_u32()?)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        if length > domain_state_budget(domain) {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let canonical_state = decoder.read_exact(length)?;
        let state = decode_state(domain, canonical_state)?;
        let payload = Self::new(state)?;
        let digest = ObjectDigest::from_bytes(decoder.read_array()?);
        decoder.finish()?;
        if digest != payload.digest() || payload.encode_canonical().as_slice() != bytes {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(payload)
    }
}

/// Holds one singular protected-store issuance.
#[derive(Debug, Eq, PartialEq)]
struct ProtectedStoreReceiptInnerV1 {
    kind: ProtectedStoreObjectKindV1,
    canonical_bytes_digest: ObjectDigest,
    storage_domain_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    opaque_receipt_commitment: ObjectDigest,
    replay_fence: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    context: AuthenticatedEvidenceContextV1,
}

/// Carries one opaque, verifier-issued protected-store acknowledgement.
///
/// No public or crate-visible constructor exists. The only issuance path
/// consumes a singular grant from the private protected-store authority and
/// revalidates its exact canonical bytes, replay fence, and currentness.
#[derive(Debug, Eq, PartialEq)]
pub struct ProtectedStoreReceiptV1 {
    issuance: ProtectedStoreReceiptInnerV1,
}

impl ProtectedStoreReceiptV1 {
    fn from_authority_grant(
        kind: ProtectedStoreObjectKindV1,
        canonical_bytes: &[u8],
        grant: ProtectedStoreCommitGrantV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if grant.kind() != kind {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let receipt = Self {
            issuance: ProtectedStoreReceiptInnerV1 {
                kind,
                canonical_bytes_digest: grant.canonical_bytes_digest(),
                storage_domain_digest: grant.storage_domain_digest(),
                durability_generation: grant.durability_generation(),
                protected_root_digest: grant.protected_root_digest(),
                opaque_receipt_commitment: grant.opaque_receipt_commitment(),
                replay_fence: grant.replay_fence(),
                authority_binding_digest: grant.authority_binding_digest(),
                context: grant.context(),
            },
        };
        if !receipt.matches(kind, canonical_bytes, verified_at_unix_seconds) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(receipt)
    }

    fn matches(
        &self,
        kind: ProtectedStoreObjectKindV1,
        canonical_bytes: &[u8],
        verified_at_unix_seconds: u64,
    ) -> bool {
        self.issuance.kind == kind
            && self.issuance.canonical_bytes_digest
                == ObjectDigest::from_bytes(Sha256::digest(canonical_bytes).into())
            && self.issuance.storage_domain_digest.as_bytes() != &[0; 32]
            && self.issuance.durability_generation != 0
            && self.issuance.protected_root_digest.as_bytes() != &[0; 32]
            && self.issuance.opaque_receipt_commitment.as_bytes() != &[0; 32]
            && self.issuance.replay_fence.as_bytes() != &[0; 32]
            && self.issuance.context.replay_fence() == self.issuance.replay_fence
            && self
                .issuance
                .authority_binding_digest
                .is_none_or(|digest| digest.as_bytes() != &[0; 32])
            && self
                .issuance
                .context
                .is_current_at(verified_at_unix_seconds)
    }
}

/// Stores one canonical hash-chained durable journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiNodeJournalRecordV1 {
    domain: MultiNodeJournalDomainV1,
    operation: OperationId,
    sequence: u64,
    predecessor_digest: ObjectDigest,
    payload_digest: ObjectDigest,
    state_payload: CanonicalJournalPayloadV1,
    effect_state: JournalEffectStateV1,
    effect_digest: ObjectDigest,
    digest: ObjectDigest,
}

impl MultiNodeJournalRecordV1 {
    /// Constructs one canonical record extending an exact predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::Unspecified`] for zero values.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        domain: MultiNodeJournalDomainV1,
        operation: OperationId,
        sequence: u64,
        predecessor_digest: ObjectDigest,
        payload_digest: ObjectDigest,
        state_payload: CanonicalJournalPayloadV1,
        effect_state: JournalEffectStateV1,
        effect_digest: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if operation.as_bytes() == &[0; 16]
            || sequence == 0
            || predecessor_digest.as_bytes() == &[0; 32]
            || payload_digest.as_bytes() == &[0; 32]
            || state_payload.domain() != domain
            || effect_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidMultiNodeJournal::Unspecified);
        }
        let digest = journal_record_digest(
            domain,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            state_payload.digest(),
            effect_state,
            effect_digest,
        );
        Ok(Self {
            domain,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            state_payload,
            effect_state,
            effect_digest,
            digest,
        })
    }

    /// Returns the independently replayed state domain.
    #[must_use]
    pub const fn domain(&self) -> MultiNodeJournalDomainV1 {
        self.domain
    }

    /// Returns the idempotent operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the monotonic sequence above the current compaction floor.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the exact predecessor record or checkpoint commitment.
    #[must_use]
    pub const fn predecessor_digest(&self) -> ObjectDigest {
        self.predecessor_digest
    }

    /// Returns the canonical semantic payload commitment.
    #[must_use]
    pub const fn payload_digest(&self) -> ObjectDigest {
        self.payload_digest
    }

    /// Returns the complete exact canonical reducer-state payload.
    #[must_use]
    pub const fn state_payload(&self) -> &CanonicalJournalPayloadV1 {
        &self.state_payload
    }

    /// Returns the closed partial-effect state.
    #[must_use]
    pub const fn effect_state(&self) -> JournalEffectStateV1 {
        self.effect_state
    }

    /// Returns the exact effect input/observation commitment.
    #[must_use]
    pub const fn effect_digest(&self) -> ObjectDigest {
        self.effect_digest
    }

    /// Returns this canonical record's hash-chain commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Encodes this record into its unique bounded canonical representation.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let state_payload = self.state_payload.encode_canonical();
        let mut bytes = Vec::with_capacity(CANONICAL_RECORD_BYTES + state_payload.len());
        bytes.extend_from_slice(b"AOSJREC1");
        bytes.push(self.domain as u8);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(self.predecessor_digest.as_bytes());
        bytes.extend_from_slice(self.payload_digest.as_bytes());
        bytes.extend_from_slice(&(state_payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&state_payload);
        bytes.push(self.effect_state as u8);
        bytes.extend_from_slice(self.effect_digest.as_bytes());
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    /// Decodes and verifies one exact bounded canonical record payload.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for any wrong
    /// length, magic, discriminant, sentinel, digest, or trailing byte.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, InvalidMultiNodeJournal> {
        if bytes.len() < 215 || bytes.len() > MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let mut decoder = JournalPayloadDecoderV1::new(bytes)?;
        decoder.expect_magic(b"AOSJREC1")?;
        let domain = decode_domain(decoder.read_u8()?)?;
        let operation = OperationId::from_bytes(decoder.read_array()?);
        let sequence = decoder.read_u64()?;
        let predecessor_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let payload_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let state_payload = decoder.read_domain_payload(domain)?;
        let effect_state = decode_effect_state(decoder.read_u8()?)?;
        let effect_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let encoded_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        decoder.finish()?;
        let record = Self::new(
            domain,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            state_payload,
            effect_state,
            effect_digest,
        )
        .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        if record.digest() != encoded_digest || record.encode_canonical().as_slice() != bytes {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(record)
    }
}

/// Couples a journal record to an opaque protected-store durability receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedJournalRecordV1 {
    record: MultiNodeJournalRecordV1,
    receipt: Arc<ProtectedStoreReceiptV1>,
}

impl ProtectedJournalRecordV1 {
    /// Constructs evidence only inside the protected-store verifier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::ProtectedStoreMismatch`] unless the
    /// receipt binds the exact canonical record bytes, storage domain,
    /// monotonic durability generation, authenticated audience, and currentness.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authority_commit(
        record_bytes: &[u8],
        grant: ProtectedStoreCommitGrantV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let record = MultiNodeJournalRecordV1::decode_canonical(record_bytes)?;
        let receipt = ProtectedStoreReceiptV1::from_authority_grant(
            ProtectedStoreObjectKindV1::Record,
            record_bytes,
            grant,
            verified_at_unix_seconds,
        )?;
        let authority_shape_valid = match record.domain() {
            MultiNodeJournalDomainV1::Assignment => {
                receipt.issuance.authority_binding_digest.is_some()
            }
            _ => receipt.issuance.authority_binding_digest.is_none(),
        };
        if !authority_shape_valid {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(Self {
            record,
            receipt: Arc::new(receipt),
        })
    }

    /// Returns the exact protected journal record.
    #[must_use]
    pub const fn record(&self) -> &MultiNodeJournalRecordV1 {
        &self.record
    }

    /// Returns the protected-store domain commitment.
    #[must_use]
    pub fn storage_domain_digest(&self) -> ObjectDigest {
        self.receipt.issuance.storage_domain_digest
    }

    /// Returns the monotonic protected-store durability generation.
    #[must_use]
    pub fn durability_generation(&self) -> u64 {
        self.receipt.issuance.durability_generation
    }

    /// Returns the authenticated protected-store root commitment.
    #[must_use]
    pub fn protected_root_digest(&self) -> ObjectDigest {
        self.receipt.issuance.protected_root_digest
    }

    /// Returns the opaque protected-store receipt commitment.
    #[must_use]
    pub fn receipt_commitment(&self) -> ObjectDigest {
        self.receipt.issuance.opaque_receipt_commitment
    }

    /// Returns the protected store's durable replay-fence commitment.
    #[must_use]
    pub fn replay_fence(&self) -> ObjectDigest {
        self.receipt.issuance.replay_fence
    }

    /// Returns the authenticated assignment carrier contract, when required.
    #[must_use]
    pub fn authority_binding_digest(&self) -> Option<ObjectDigest> {
        self.receipt.issuance.authority_binding_digest
    }

    /// Returns the exact authenticated verifier context.
    #[must_use]
    pub fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.receipt.issuance.context
    }
}

/// Commits replay state at a safe durable history-compaction floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiNodeJournalCheckpointV1 {
    domain: MultiNodeJournalDomainV1,
    floor_sequence: u64,
    floor_record_digest: ObjectDigest,
    reduced_state: CanonicalJournalPayloadV1,
    floor_effect: DurableJournalEffectV1,
    compaction_generation: u64,
    digest: ObjectDigest,
}

impl MultiNodeJournalCheckpointV1 {
    /// Returns the independently replayed journal domain.
    #[must_use]
    pub const fn domain(&self) -> MultiNodeJournalDomainV1 {
        self.domain
    }

    /// Returns the exact compacted floor sequence.
    #[must_use]
    pub const fn floor_sequence(&self) -> u64 {
        self.floor_sequence
    }

    /// Returns the exact compacted floor record commitment.
    #[must_use]
    pub const fn floor_record_digest(&self) -> ObjectDigest {
        self.floor_record_digest
    }

    /// Returns the canonical reduced-state commitment at the floor.
    #[must_use]
    pub const fn reduced_state_digest(&self) -> ObjectDigest {
        self.reduced_state.digest()
    }

    /// Returns the complete canonical reducer state at the compacted floor.
    #[must_use]
    pub const fn reduced_state(&self) -> &CanonicalJournalPayloadV1 {
        &self.reduced_state
    }

    /// Returns the historical partial-effect boundary at the compacted floor.
    #[must_use]
    pub const fn floor_effect(&self) -> DurableJournalEffectV1 {
        self.floor_effect
    }

    /// Returns the monotonic compaction generation.
    #[must_use]
    pub const fn compaction_generation(&self) -> u64 {
        self.compaction_generation
    }

    /// Returns the canonical checkpoint commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Encodes this checkpoint into its unique bounded canonical representation.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let reduced_state = self.reduced_state.encode_canonical();
        let mut bytes = Vec::with_capacity(CANONICAL_CHECKPOINT_BYTES + reduced_state.len());
        bytes.extend_from_slice(b"AOSJCHK1");
        bytes.push(self.domain as u8);
        bytes.extend_from_slice(&self.floor_sequence.to_be_bytes());
        bytes.extend_from_slice(self.floor_record_digest.as_bytes());
        bytes.extend_from_slice(&(reduced_state.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&reduced_state);
        bytes.extend_from_slice(self.floor_effect.operation.as_bytes());
        bytes.extend_from_slice(self.floor_effect.payload_digest.as_bytes());
        bytes.push(self.floor_effect.state as u8);
        bytes.extend_from_slice(self.floor_effect.effect_digest.as_bytes());
        bytes.extend_from_slice(&self.compaction_generation.to_be_bytes());
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    /// Decodes and verifies one exact bounded canonical checkpoint payload.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for malformed,
    /// sentinel, digest-mismatched, or trailing data.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, InvalidMultiNodeJournal> {
        if bytes.len() < 227 || bytes.len() > MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let mut decoder = JournalPayloadDecoderV1::new(bytes)?;
        decoder.expect_magic(b"AOSJCHK1")?;
        let domain = decode_domain(decoder.read_u8()?)?;
        let floor_sequence = decoder.read_u64()?;
        let floor_record_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let reduced_state = decoder.read_domain_payload(domain)?;
        let floor_effect = DurableJournalEffectV1 {
            operation: OperationId::from_bytes(decoder.read_array()?),
            payload_digest: ObjectDigest::from_bytes(decoder.read_array()?),
            state: decode_effect_state(decoder.read_u8()?)?,
            effect_digest: ObjectDigest::from_bytes(decoder.read_array()?),
        };
        let compaction_generation = decoder.read_u64()?;
        let digest = ObjectDigest::from_bytes(decoder.read_array()?);
        decoder.finish()?;
        if floor_sequence == 0
            || floor_record_digest.as_bytes() == &[0; 32]
            || floor_effect.operation.as_bytes() == &[0; 16]
            || floor_effect.payload_digest.as_bytes() == &[0; 32]
            || floor_effect.effect_digest.as_bytes() == &[0; 32]
            || compaction_generation == 0
            || digest
                != checkpoint_digest(
                    domain,
                    floor_sequence,
                    floor_record_digest,
                    reduced_state.digest(),
                    floor_effect,
                    compaction_generation,
                )
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let checkpoint = Self {
            domain,
            floor_sequence,
            floor_record_digest,
            reduced_state,
            floor_effect,
            compaction_generation,
            digest,
        };
        if checkpoint.encode_canonical().as_slice() != bytes {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(checkpoint)
    }
}

/// Couples a journal checkpoint to an opaque protected-store receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedJournalCheckpointV1 {
    checkpoint: MultiNodeJournalCheckpointV1,
    receipt: Arc<ProtectedStoreReceiptV1>,
}

impl ProtectedJournalCheckpointV1 {
    /// Constructs evidence only inside the protected-store verifier boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::ProtectedStoreMismatch`] unless exact
    /// canonical checkpoint bytes and every durability/currentness binding agree.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authority_commit(
        checkpoint_bytes: &[u8],
        grant: ProtectedStoreCommitGrantV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let checkpoint = MultiNodeJournalCheckpointV1::decode_canonical(checkpoint_bytes)?;
        let receipt = ProtectedStoreReceiptV1::from_authority_grant(
            ProtectedStoreObjectKindV1::Checkpoint,
            checkpoint_bytes,
            grant,
            verified_at_unix_seconds,
        )?;
        if receipt.issuance.authority_binding_digest.is_some() {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(Self {
            checkpoint,
            receipt: Arc::new(receipt),
        })
    }

    /// Returns the exact protected checkpoint.
    #[must_use]
    pub const fn checkpoint(&self) -> &MultiNodeJournalCheckpointV1 {
        &self.checkpoint
    }

    /// Returns the protected-store domain commitment.
    #[must_use]
    pub fn storage_domain_digest(&self) -> ObjectDigest {
        self.receipt.issuance.storage_domain_digest
    }

    /// Returns the monotonic protected-store durability generation.
    #[must_use]
    pub fn durability_generation(&self) -> u64 {
        self.receipt.issuance.durability_generation
    }

    /// Returns the authenticated protected-store root commitment.
    #[must_use]
    pub fn protected_root_digest(&self) -> ObjectDigest {
        self.receipt.issuance.protected_root_digest
    }

    /// Returns the opaque protected-store receipt commitment.
    #[must_use]
    pub fn receipt_commitment(&self) -> ObjectDigest {
        self.receipt.issuance.opaque_receipt_commitment
    }

    /// Returns the protected store's durable replay-fence commitment.
    #[must_use]
    pub fn replay_fence(&self) -> ObjectDigest {
        self.receipt.issuance.replay_fence
    }

    /// Returns the exact authenticated verifier context.
    #[must_use]
    pub fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.receipt.issuance.context
    }
}

/// Reports a pure journal application result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalApplyOutcomeV1 {
    /// The record directly extended canonical history.
    Applied,
    /// The exact current record was replayed.
    Replay,
    /// A record at or below the compacted floor was ignored.
    BelowCompactionFloor,
}

/// Replays one journal domain with explicit compaction floors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiNodeJournalReducerV1 {
    domain: MultiNodeJournalDomainV1,
    floor_sequence: u64,
    floor_record_digest: Option<ObjectDigest>,
    floor_digest: ObjectDigest,
    restored_state: Option<CanonicalJournalPayloadV1>,
    restored_effect: Option<DurableJournalEffectV1>,
    current: Option<MultiNodeJournalRecordV1>,
    compaction_generation: u64,
    storage_domain_digest: Option<ObjectDigest>,
    storage_replay_fence: Option<ObjectDigest>,
    durability_generation: u64,
    current_receipt_commitment: Option<ObjectDigest>,
    current_authority_binding_digest: Option<ObjectDigest>,
}

impl MultiNodeJournalReducerV1 {
    /// Starts replay above an authenticated nonzero genesis commitment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::Unspecified`] for a zero genesis digest.
    pub fn new(
        domain: MultiNodeJournalDomainV1,
        genesis_digest: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if genesis_digest.as_bytes() == &[0; 32] {
            return Err(InvalidMultiNodeJournal::Unspecified);
        }
        Ok(Self {
            domain,
            floor_sequence: 0,
            floor_record_digest: None,
            floor_digest: genesis_digest,
            restored_state: None,
            restored_effect: None,
            current: None,
            compaction_generation: 0,
            storage_domain_digest: None,
            storage_replay_fence: None,
            durability_generation: 0,
            current_receipt_commitment: None,
            current_authority_binding_digest: None,
        })
    }

    /// Restores a reducer from a protected checkpoint and protected successors.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] for a stale receipt, another domain
    /// or protected store, nonmonotonic durability, or broken record history.
    pub(super) fn restore_from_authority(
        grant: ProtectedStoreRestoreGrantV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let (
            protected_checkpoint,
            records,
            coordinator_unix_seconds,
            storage_domain_digest,
            replay_fence,
        ) = grant.into_parts();
        let checkpoint = protected_checkpoint.checkpoint();
        if records.len() > MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS
            || protected_checkpoint.storage_domain_digest() != storage_domain_digest
            || protected_checkpoint.replay_fence() != replay_fence
            || !protected_checkpoint
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let mut reducer = Self {
            domain: checkpoint.domain(),
            floor_sequence: checkpoint.floor_sequence(),
            floor_record_digest: Some(checkpoint.floor_record_digest()),
            floor_digest: checkpoint.digest(),
            restored_state: Some(checkpoint.reduced_state().clone()),
            restored_effect: Some(checkpoint.floor_effect()),
            current: None,
            compaction_generation: checkpoint.compaction_generation(),
            storage_domain_digest: Some(protected_checkpoint.storage_domain_digest()),
            storage_replay_fence: Some(protected_checkpoint.replay_fence()),
            durability_generation: protected_checkpoint.durability_generation(),
            current_receipt_commitment: None,
            current_authority_binding_digest: None,
        };
        for record in records {
            reducer.apply(record, coordinator_unix_seconds)?;
        }
        Ok(reducer)
    }

    /// Applies one direct canonical successor or exact replay.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] for another domain, skipped history,
    /// or same-sequence equivocation.
    ///
    /// Domain and compaction-floor ordering is evaluated before receipt
    /// currentness. A byte-exact record below the floor is historical input and
    /// is ignored even after its old receipt expires; reuse of the exact floor
    /// sequence with different content is still rejected as equivocation.
    pub fn apply(
        &mut self,
        protected_record: ProtectedJournalRecordV1,
        coordinator_unix_seconds: u64,
    ) -> Result<JournalApplyOutcomeV1, InvalidMultiNodeJournal> {
        let record = protected_record.record();
        if record.domain() != self.domain {
            return Err(InvalidMultiNodeJournal::HistoryGap);
        }
        if record.sequence() < self.floor_sequence {
            return Ok(JournalApplyOutcomeV1::BelowCompactionFloor);
        }
        if record.sequence() == self.floor_sequence {
            return if self.floor_record_digest == Some(record.digest()) {
                Ok(JournalApplyOutcomeV1::BelowCompactionFloor)
            } else {
                Err(InvalidMultiNodeJournal::Equivocation)
            };
        }
        if !protected_record
            .context()
            .is_current_at(coordinator_unix_seconds)
            || self
                .storage_domain_digest
                .is_some_and(|domain| domain != protected_record.storage_domain_digest())
            || self
                .storage_replay_fence
                .is_some_and(|fence| fence != protected_record.replay_fence())
            || protected_record.durability_generation() < self.durability_generation
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        if protected_record.durability_generation() == self.durability_generation {
            return if self.current.as_ref() == Some(record)
                && self.current_receipt_commitment == Some(protected_record.receipt_commitment())
                && self.current_authority_binding_digest
                    == protected_record.authority_binding_digest()
            {
                Ok(JournalApplyOutcomeV1::Replay)
            } else {
                Err(InvalidMultiNodeJournal::ProtectedStoreMismatch)
            };
        }
        if let Some(current) = &self.current {
            if record.sequence() == current.sequence() {
                if record != current {
                    return Err(InvalidMultiNodeJournal::Equivocation);
                }
                self.durability_generation = protected_record.durability_generation();
                self.current_receipt_commitment = Some(protected_record.receipt_commitment());
                self.current_authority_binding_digest = protected_record.authority_binding_digest();
                return Ok(JournalApplyOutcomeV1::Replay);
            }
            if record.sequence() != current.sequence().saturating_add(1)
                || record.predecessor_digest() != current.digest()
            {
                return Err(InvalidMultiNodeJournal::HistoryGap);
            }
        } else if record.sequence() != self.floor_sequence.saturating_add(1)
            || record.predecessor_digest() != self.floor_digest
        {
            return Err(InvalidMultiNodeJournal::HistoryGap);
        }
        self.restored_state = Some(record.state_payload().clone());
        self.restored_effect = Some(DurableJournalEffectV1::from_record(record));
        self.current = Some(record.clone());
        self.storage_domain_digest = Some(protected_record.storage_domain_digest());
        self.storage_replay_fence = Some(protected_record.replay_fence());
        self.durability_generation = protected_record.durability_generation();
        self.current_receipt_commitment = Some(protected_record.receipt_commitment());
        self.current_authority_binding_digest = protected_record.authority_binding_digest();
        Ok(JournalApplyOutcomeV1::Applied)
    }

    /// Creates a checkpoint only at the exact current replay boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::Unspecified`] without current history
    /// or when the complete reduced state names another journal domain.
    pub fn checkpoint(
        &self,
        reduced_state: CanonicalJournalPayloadV1,
    ) -> Result<MultiNodeJournalCheckpointV1, InvalidMultiNodeJournal> {
        let current = self
            .current
            .as_ref()
            .ok_or(InvalidMultiNodeJournal::Unspecified)?;
        if reduced_state.domain() != self.domain
            || reduced_state.digest() != current.state_payload().digest()
            || reduced_state.as_bytes() != current.state_payload().as_bytes()
        {
            return Err(InvalidMultiNodeJournal::Unspecified);
        }
        let generation = self.compaction_generation.saturating_add(1);
        let digest = checkpoint_digest(
            self.domain,
            current.sequence(),
            current.digest(),
            reduced_state.digest(),
            DurableJournalEffectV1::from_record(current),
            generation,
        );
        Ok(MultiNodeJournalCheckpointV1 {
            domain: self.domain,
            floor_sequence: current.sequence(),
            floor_record_digest: current.digest(),
            reduced_state,
            floor_effect: DurableJournalEffectV1::from_record(current),
            compaction_generation: generation,
            digest,
        })
    }

    /// Advances the compaction floor only to an exact current checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::UnsafeCompaction`] for any mismatch.
    pub fn compact(
        &mut self,
        protected_checkpoint: ProtectedJournalCheckpointV1,
        coordinator_unix_seconds: u64,
    ) -> Result<(), InvalidMultiNodeJournal> {
        if !protected_checkpoint
            .context()
            .is_current_at(coordinator_unix_seconds)
            || self
                .storage_domain_digest
                .is_some_and(|domain| domain != protected_checkpoint.storage_domain_digest())
            || self
                .storage_replay_fence
                .is_some_and(|fence| fence != protected_checkpoint.replay_fence())
            || protected_checkpoint.durability_generation() <= self.durability_generation
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let checkpoint = protected_checkpoint.checkpoint();
        let current = self
            .current
            .as_ref()
            .ok_or(InvalidMultiNodeJournal::UnsafeCompaction)?;
        if checkpoint.domain != self.domain
            || checkpoint.floor_sequence != current.sequence()
            || checkpoint.floor_record_digest != current.digest()
            || &checkpoint.reduced_state != current.state_payload()
            || checkpoint.floor_effect != DurableJournalEffectV1::from_record(current)
            || checkpoint.compaction_generation != self.compaction_generation.saturating_add(1)
        {
            return Err(InvalidMultiNodeJournal::UnsafeCompaction);
        }
        self.floor_sequence = checkpoint.floor_sequence;
        self.floor_record_digest = Some(checkpoint.floor_record_digest);
        self.floor_digest = checkpoint.digest;
        self.restored_state = Some(checkpoint.reduced_state.clone());
        self.restored_effect = Some(checkpoint.floor_effect);
        self.compaction_generation = checkpoint.compaction_generation;
        self.storage_domain_digest = Some(protected_checkpoint.storage_domain_digest());
        self.storage_replay_fence = Some(protected_checkpoint.replay_fence());
        self.durability_generation = protected_checkpoint.durability_generation();
        self.current = None;
        self.current_receipt_commitment = None;
        self.current_authority_binding_digest = None;
        Ok(())
    }

    /// Returns the complete canonical domain state after checkpoint and replay.
    ///
    /// This is the exact capability, assignment, drain, snapshot-transfer, or
    /// watch reducer payload from the latest accepted record, falling back to
    /// the checkpoint payload when no successor exists.
    #[must_use]
    pub fn restored_state(&self) -> Option<&CanonicalJournalPayloadV1> {
        self.restored_state.as_ref()
    }

    /// Returns the latest fully decoded typed reducer projection.
    #[must_use]
    pub fn restored_projection(&self) -> Option<&MultiNodeReducerStateV1> {
        self.restored_state
            .as_ref()
            .map(CanonicalJournalPayloadV1::state)
    }

    /// Returns the protected history's latest partial-effect recovery boundary.
    ///
    /// This historical projection never authorizes an effect. It remains
    /// available after compaction so recovery can fail closed and seek fresh
    /// authority for the exact operation and commitments.
    #[must_use]
    pub const fn restored_effect(&self) -> Option<DurableJournalEffectV1> {
        self.restored_effect
    }

    /// Issues a sealed semantic grant for the current prepared assignment effect.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::InvalidRecoveryTransition`] unless the
    /// exact current row is protected, assignment-bound, and commits a prepared
    /// operation and effect.
    pub(super) fn issue_assignment_effect_grant(
        &self,
        plan: AssignmentEffectPlanV1,
    ) -> Result<AssignmentEffectSemanticGrantV1, InvalidMultiNodeJournal> {
        let record = self
            .current
            .as_ref()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let receipt_commitment = self
            .current_receipt_commitment
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let authority_binding_digest = self
            .current_authority_binding_digest
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let assignment = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let intent = assignment.intent();
        if self.domain != MultiNodeJournalDomainV1::Assignment
            || record.domain() != MultiNodeJournalDomainV1::Assignment
            || record.effect_state() != JournalEffectStateV1::EffectPrepared
            || record.payload_digest() != intent.assignment_digest()
            || !plan.matches(record.operation(), intent, record.effect_digest())
        {
            return Err(InvalidMultiNodeJournal::InvalidRecoveryTransition);
        }
        Ok(AssignmentEffectSemanticGrantV1 {
            plan,
            record_digest: record.digest(),
            receipt_commitment,
            authority_binding_digest,
        })
    }
}

/// Carries one reducer-issued prepared-assignment semantic commitment.
///
/// Construction remains private to [`MultiNodeJournalReducerV1`]. The move-only
/// grant prevents an effect from being authorized solely from caller-provided
/// operation or digest scalars.
#[must_use]
pub(super) struct AssignmentEffectSemanticGrantV1 {
    plan: AssignmentEffectPlanV1,
    record_digest: ObjectDigest,
    receipt_commitment: ObjectDigest,
    authority_binding_digest: ObjectDigest,
}

impl AssignmentEffectSemanticGrantV1 {
    pub(super) const fn operation(&self) -> OperationId {
        self.plan.operation()
    }

    pub(super) const fn payload_digest(&self) -> ObjectDigest {
        self.plan.intent().assignment_digest()
    }

    pub(super) const fn effect_digest(&self) -> ObjectDigest {
        self.plan.effect_digest()
    }

    pub(super) const fn intent(&self) -> &AssignmentIntentV1 {
        self.plan.intent()
    }

    pub(super) fn matches(
        &self,
        operation: OperationId,
        intent: &AssignmentIntentV1,
        effect_digest: ObjectDigest,
    ) -> bool {
        self.plan.matches(operation, intent, effect_digest)
    }

    pub(super) const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }

    pub(super) const fn receipt_commitment(&self) -> ObjectDigest {
        self.receipt_commitment
    }

    pub(super) const fn authority_binding_digest(&self) -> ObjectDigest {
        self.authority_binding_digest
    }
}

/// Reduces exact partial-effect recovery without guessing ambiguous state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialEffectRecoveryV1 {
    operation: OperationId,
    tuple_digest: ObjectDigest,
    state: JournalEffectStateV1,
    effect_digest: ObjectDigest,
    journal_record: ProtectedJournalRecordV1,
}

impl PartialEffectRecoveryV1 {
    /// Constructs recovery at a durable prepared boundary.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::Unspecified`] unless the protected
    /// record is current and commits a fully specified prepared effect.
    pub fn from_protected_prepared(
        journal_record: ProtectedJournalRecordV1,
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let record = journal_record.record();
        let operation = record.operation();
        let tuple_digest = record.payload_digest();
        let effect_digest = record.effect_digest();
        if operation.as_bytes() == &[0; 16]
            || tuple_digest.as_bytes() == &[0; 32]
            || effect_digest.as_bytes() == &[0; 32]
            || record.effect_state() != JournalEffectStateV1::EffectPrepared
            || !journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::Unspecified);
        }
        Ok(Self {
            operation,
            tuple_digest,
            state: JournalEffectStateV1::EffectPrepared,
            effect_digest,
            journal_record,
        })
    }

    /// Advances the closed recovery state graph for the exact same effect.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] for stale or cross-store evidence,
    /// an impossible edge, or a changed effect commitment.
    pub fn advance(
        &mut self,
        journal_record: ProtectedJournalRecordV1,
        coordinator_unix_seconds: u64,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let record = journal_record.record();
        let next = record.effect_state();
        if !journal_record
            .context()
            .is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        if journal_record == self.journal_record {
            return Ok(());
        }
        let prior_context = self.journal_record.context();
        let valid = self.state == next
            || matches!(
                (self.state, next),
                (
                    JournalEffectStateV1::EffectPrepared,
                    JournalEffectStateV1::EffectObserved
                ) | (
                    JournalEffectStateV1::EffectPrepared,
                    JournalEffectStateV1::Compensating
                ) | (
                    JournalEffectStateV1::EffectObserved,
                    JournalEffectStateV1::Committed
                ) | (
                    JournalEffectStateV1::EffectObserved,
                    JournalEffectStateV1::Compensating
                ) | (
                    JournalEffectStateV1::Compensating,
                    JournalEffectStateV1::Contained
                )
            );
        if !valid
            || record.domain() != self.journal_record.record().domain()
            || record.operation() != self.operation
            || record.payload_digest() != self.tuple_digest
            || record.effect_digest() != self.effect_digest
            || journal_record.storage_domain_digest() != self.journal_record.storage_domain_digest()
            || journal_record.replay_fence() != self.journal_record.replay_fence()
            || journal_record.authority_binding_digest()
                != self.journal_record.authority_binding_digest()
            || journal_record.durability_generation() <= self.journal_record.durability_generation()
            || journal_record.context().node() != prior_context.node()
            || journal_record.context().lineage() != prior_context.lineage()
            || journal_record.context().audience_digest() != prior_context.audience_digest()
            || journal_record.context().disclosure_domain_digest()
                != prior_context.disclosure_domain_digest()
            || journal_record.context().coordinator_epoch() != prior_context.coordinator_epoch()
            || journal_record.context().carrier_binding_digest()
                != prior_context.carrier_binding_digest()
            || journal_record.context().replay_fence() != prior_context.replay_fence()
            || record.sequence() != self.journal_record.record().sequence().saturating_add(1)
            || record.predecessor_digest() != self.journal_record.record().digest()
        {
            return Err(InvalidMultiNodeJournal::InvalidRecoveryTransition);
        }
        self.state = next;
        self.journal_record = journal_record;
        Ok(())
    }

    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the exact semantic tuple commitment.
    #[must_use]
    pub const fn tuple_digest(&self) -> ObjectDigest {
        self.tuple_digest
    }

    /// Returns the current partial-effect recovery state.
    #[must_use]
    pub const fn state(&self) -> JournalEffectStateV1 {
        self.state
    }

    /// Returns the exact protected journal record committing this state.
    #[must_use]
    pub const fn journal_record(&self) -> &ProtectedJournalRecordV1 {
        &self.journal_record
    }

    /// Encodes exact partial-effect recovery state canonically and boundedly.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(153);
        bytes.extend_from_slice(b"AOSJSTA1");
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.tuple_digest.as_bytes());
        bytes.push(self.state as u8);
        bytes.extend_from_slice(self.effect_digest.as_bytes());
        bytes.extend_from_slice(self.journal_record.receipt_commitment().as_bytes());
        let digest = ObjectDigest::from_bytes(Sha256::digest(&bytes).into());
        bytes.extend_from_slice(digest.as_bytes());
        bytes
    }

    /// Restores exact partial-effect state from a canonical durable payload.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::NonCanonicalPayload`] for any wrong
    /// length, sentinel, state discriminant, digest, or trailing byte.
    pub fn restore_canonical(
        bytes: &[u8],
        journal_record: ProtectedJournalRecordV1,
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if bytes.len() != 153 || bytes.len() > MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let mut decoder = JournalPayloadDecoderV1::new(bytes)?;
        decoder.expect_magic(b"AOSJSTA1")?;
        let operation = OperationId::from_bytes(decoder.read_array()?);
        let tuple_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let state = decode_effect_state(decoder.read_u8()?)?;
        let effect_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let protected_receipt_commitment = ObjectDigest::from_bytes(decoder.read_array()?);
        let encoded_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        decoder.finish()?;
        if operation.as_bytes() == &[0; 16]
            || tuple_digest.as_bytes() == &[0; 32]
            || effect_digest.as_bytes() == &[0; 32]
            || state == JournalEffectStateV1::IntentCommitted
            || journal_record.receipt_commitment() != protected_receipt_commitment
            || journal_record.record().operation() != operation
            || journal_record.record().payload_digest() != tuple_digest
            || journal_record.record().effect_state() != state
            || journal_record.record().effect_digest() != effect_digest
            || !journal_record
                .context()
                .is_current_at(coordinator_unix_seconds)
            || ObjectDigest::from_bytes(Sha256::digest(&bytes[..121]).into()) != encoded_digest
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let recovery = Self {
            operation,
            tuple_digest,
            state,
            effect_digest,
            journal_record,
        };
        if recovery.encode_canonical().as_slice() != bytes {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(recovery)
    }
}

fn decode_domain(byte: u8) -> Result<MultiNodeJournalDomainV1, InvalidMultiNodeJournal> {
    match byte {
        0 => Ok(MultiNodeJournalDomainV1::Capability),
        1 => Ok(MultiNodeJournalDomainV1::Assignment),
        2 => Ok(MultiNodeJournalDomainV1::Drain),
        3 => Ok(MultiNodeJournalDomainV1::SnapshotTransfer),
        4 => Ok(MultiNodeJournalDomainV1::Watch),
        _ => Err(InvalidMultiNodeJournal::NonCanonicalPayload),
    }
}

const fn domain_state_budget(domain: MultiNodeJournalDomainV1) -> usize {
    match domain {
        MultiNodeJournalDomainV1::Capability => MAX_CAPABILITY_JOURNAL_STATE_BYTES,
        MultiNodeJournalDomainV1::Assignment => MAX_ASSIGNMENT_JOURNAL_STATE_BYTES,
        MultiNodeJournalDomainV1::Drain => MAX_DRAIN_JOURNAL_STATE_BYTES,
        MultiNodeJournalDomainV1::SnapshotTransfer => MAX_SNAPSHOT_JOURNAL_STATE_BYTES,
        MultiNodeJournalDomainV1::Watch => MAX_WATCH_JOURNAL_STATE_BYTES,
    }
}

fn decode_effect_state(byte: u8) -> Result<JournalEffectStateV1, InvalidMultiNodeJournal> {
    match byte {
        0 => Ok(JournalEffectStateV1::IntentCommitted),
        1 => Ok(JournalEffectStateV1::EffectPrepared),
        2 => Ok(JournalEffectStateV1::EffectObserved),
        3 => Ok(JournalEffectStateV1::Committed),
        4 => Ok(JournalEffectStateV1::Compensating),
        5 => Ok(JournalEffectStateV1::Contained),
        _ => Err(InvalidMultiNodeJournal::NonCanonicalPayload),
    }
}

struct JournalPayloadDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> JournalPayloadDecoderV1<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, InvalidMultiNodeJournal> {
        if bytes.len() > MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn expect_magic(&mut self, magic: &[u8; 8]) -> Result<(), InvalidMultiNodeJournal> {
        if self.read_exact(8)? != magic {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, InvalidMultiNodeJournal> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, InvalidMultiNodeJournal> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, InvalidMultiNodeJournal> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_domain_payload(
        &mut self,
        domain: MultiNodeJournalDomainV1,
    ) -> Result<CanonicalJournalPayloadV1, InvalidMultiNodeJournal> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        if length > MAX_MULTI_NODE_DOMAIN_STATE_BYTES + CANONICAL_DOMAIN_ENVELOPE_BYTES {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }

        let payload = CanonicalJournalPayloadV1::decode_canonical(self.read_exact(length)?)?;
        if payload.domain() != domain {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        Ok(payload)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], InvalidMultiNodeJournal> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], InvalidMultiNodeJournal> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), InvalidMultiNodeJournal> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(InvalidMultiNodeJournal::NonCanonicalPayload)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn journal_record_digest(
    domain: MultiNodeJournalDomainV1,
    operation: OperationId,
    sequence: u64,
    predecessor_digest: ObjectDigest,
    payload_digest: ObjectDigest,
    state_payload_digest: ObjectDigest,
    effect_state: JournalEffectStateV1,
    effect_digest: ObjectDigest,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.multi-node-journal-record.v1\0");
    hasher.update([domain as u8]);
    hasher.update(operation.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(predecessor_digest.as_bytes());
    hasher.update(payload_digest.as_bytes());
    hasher.update(state_payload_digest.as_bytes());
    hasher.update([effect_state as u8]);
    hasher.update(effect_digest.as_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn checkpoint_digest(
    domain: MultiNodeJournalDomainV1,
    floor_sequence: u64,
    floor_record_digest: ObjectDigest,
    reduced_state_digest: ObjectDigest,
    floor_effect: DurableJournalEffectV1,
    generation: u64,
) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.multi-node-journal-checkpoint.v1\0");
    hasher.update([domain as u8]);
    hasher.update(floor_sequence.to_be_bytes());
    hasher.update(floor_record_digest.as_bytes());
    hasher.update(reduced_state_digest.as_bytes());
    hasher.update(floor_effect.operation.as_bytes());
    hasher.update(floor_effect.payload_digest.as_bytes());
    hasher.update([floor_effect.state as u8]);
    hasher.update(floor_effect.effect_digest.as_bytes());
    hasher.update(generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
