//! Canonical Operation and OwnershipGate ledger DATA and their key layouts.
//!
//! This private owner bounds and decodes durable inputs; it neither authenticates
//! activation facts nor reads a journal, supplies currentness, or grants effects.
//! Admission, state transitions, publication joins, and recovery remain with the
//! Reconciler. The V2 operation tail delegates to the existing public-metadata
//! owner rather than duplicating that format.
//!
//! The established records have these layouts:
//!
//! ```text
//! Operation V1 (40 bytes):
//!   version:u8 || state:u8 || flags:u8 || reserved:u8 || effect_count:u32le
//!   || runtime_intent_digest_or_zero:32bytes
//! Operation V2 (104 bytes):
//!   V1 header with version=2/public flag || public_metadata:64bytes
//! OwnershipGate V1:
//!   magic:AOSOGT01 || version:u16be || state:u8 || reserved:5bytes
//!   || operation_id:16bytes || request_digest:32bytes
//!   || idempotency_length:u16be || key_id_length:u16be
//!   || authority_generation:u64be || authority_fingerprint:32bytes
//!   || claim_length:u32be || draft_length:u32be
//!   || claim_digest:32bytes || draft_digest:32bytes || publication_digest:32bytes
//!   || lease_generation:u64be || lease_digest:32bytes
//!   || idempotency_key || authority_key_id || canonical_claim || canonical_draft
//! ```

use aos_sandbox_core::bounded_codec::{BoundedReader, ReadError};
use aos_sandbox_core::model::{KeyReference, KeyUsage, StableKeyId};
use aos_sandbox_core::{ObjectDigest, OperationId};
use aos_sandbox_ownership_protocol::{CLAIM_BYTES, OwnershipClaimV1};

use super::ReconcilerError;
use super::public_operation::{DurablePublicOperationV1, PUBLIC_OPERATION_RECORD_BYTES};
use crate::journal::IdempotencyKey;
use crate::publication::AuthorityPublicationDraftV1;

pub(super) const RECORD_VERSION_V1: u8 = 1;
const RECORD_VERSION_V2: u8 = 2;
const OPERATION_FLAG_OWNERSHIP_GATED: u8 = 1;
const OPERATION_FLAG_PUBLIC: u8 = 2;
pub(super) const OPERATION_RUNTIME_INTENT_DIGEST_BYTES: usize = 32;
pub(super) const OPERATION_RECORD_V1_BYTES: usize = 8 + OPERATION_RUNTIME_INTENT_DIGEST_BYTES;
pub(super) const OPERATION_RECORD_V2_BYTES: usize =
    OPERATION_RECORD_V1_BYTES + PUBLIC_OPERATION_RECORD_BYTES;
pub(super) const OPERATION_KEY_BYTES: usize = 16;
const EFFECT_KEY_BYTES: usize = 20;
// The default journal transaction bound is 4096 records. Admission also
// carries desired-state, operation, and idempotency records atomically.
pub(super) const MAXIMUM_EFFECTS: usize = 4093;
pub(super) const MAXIMUM_GATED_EFFECTS: usize = 4092;
const MAXIMUM_OWNERSHIP_DRAFT_BYTES: usize = 15 * 1024 * 1024;
const OWNERSHIP_GATE_MAGIC: &[u8; 8] = b"AOSOGT01";
const OWNERSHIP_GATE_VERSION: u16 = 1;
const OWNERSHIP_GATE_FIXED_BYTES: usize = 252;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum OperationState {
    Accepted = 1,
    Applying = 2,
    Succeeded = 3,
    PermanentlyBlocked = 4,
    OwnershipPending = 5,
    CanceledBeforeCommit = 6,
    FailedBeforeCommit = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OperationRecord {
    pub(super) state: OperationState,
    pub(super) effect_count: u32,
    pub(super) ownership_gated: bool,
    pub(super) runtime_intent_digest: Option<ObjectDigest>,
    pub(super) public_operation: Option<DurablePublicOperationV1>,
}

impl OperationState {
    fn from_byte(value: u8) -> Result<Self, ReconcilerError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Applying),
            3 => Ok(Self::Succeeded),
            4 => Ok(Self::PermanentlyBlocked),
            5 => Ok(Self::OwnershipPending),
            6 => Ok(Self::CanceledBeforeCommit),
            7 => Ok(Self::FailedBeforeCommit),
            _ => Err(ReconcilerError::CorruptLedger("unknown operation state")),
        }
    }

    pub(super) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::PermanentlyBlocked
                | Self::CanceledBeforeCommit
                | Self::FailedBeforeCommit
        )
    }
}

/// Carries the bounded non-authorizing inputs durably held before ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipGatePlanV1 {
    pub(super) operation_id: OperationId,
    pub(super) idempotency_key: IdempotencyKey,
    pub(super) request_digest: [u8; 32],
    pub(super) claim: OwnershipClaimV1,
    pub(super) publication_draft: AuthorityPublicationDraftV1,
}

impl OwnershipGatePlanV1 {
    pub(super) fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        claim: OwnershipClaimV1,
        publication_draft: AuthorityPublicationDraftV1,
    ) -> Result<Self, ReconcilerError> {
        let expected_authority = publication_draft.ownership_authority();
        if operation_id.as_bytes() == &[0; 16]
            || request_digest == [0; 32]
            || expected_authority.generation() == 0
            || expected_authority.public_key_sha256().as_bytes() == &[0; 32]
            || expected_authority.usage() != KeyUsage::OwnershipLease
            || publication_draft.canonical_bytes().len() > MAXIMUM_OWNERSHIP_DRAFT_BYTES
        {
            return Err(ReconcilerError::InvalidPlan("invalid ownership gate plan"));
        }
        validate_claim_draft_context(&claim, &publication_draft)?;
        Ok(Self {
            operation_id,
            idempotency_key,
            request_digest,
            claim,
            publication_draft,
        })
    }

    /// Returns the operation whose effects remain gated.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the original normalized request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Returns the exact original idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the exact pinned ownership-authority key reference.
    #[must_use]
    pub const fn expected_authority(&self) -> &KeyReference {
        self.publication_draft.ownership_authority()
    }

    /// Returns the exact canonical ownership claim.
    #[must_use]
    pub const fn claim(&self) -> &OwnershipClaimV1 {
        &self.claim
    }

    /// Returns the validated typed authority-publication draft.
    #[must_use]
    pub const fn publication_draft(&self) -> &AuthorityPublicationDraftV1 {
        &self.publication_draft
    }

    /// Returns the domain-separated digest of the exact draft bytes.
    #[must_use]
    pub const fn publication_draft_digest(&self) -> ObjectDigest {
        self.publication_draft.digest()
    }
}

/// Reports the durable state of an operation's ownership gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnershipGateStatusV1 {
    /// The operation remains unavailable to ordinary reconciliation.
    Pending(OwnershipGatePlanV1),
    /// Exact authority was published and the operation gate was released.
    Activated {
        /// The immutable admitted gate inputs.
        plan: OwnershipGatePlanV1,
        /// The exact activated authority-publication digest.
        publication_digest: ObjectDigest,
        /// The activated ownership-lease generation.
        lease_generation: u64,
        /// The exact activated ownership-lease digest.
        lease_digest: ObjectDigest,
    },
}

pub(crate) fn effect_key(operation_id: OperationId, step: u32) -> [u8; EFFECT_KEY_BYTES] {
    let mut key = [0_u8; EFFECT_KEY_BYTES];
    key[..OPERATION_KEY_BYTES].copy_from_slice(operation_id.as_bytes());
    key[OPERATION_KEY_BYTES..].copy_from_slice(&step.to_be_bytes());
    key
}

pub(super) fn decode_operation_key(bytes: &[u8]) -> Result<OperationId, ReconcilerError> {
    let value: [u8; OPERATION_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("invalid operation key length"))?;
    if value == [0; OPERATION_KEY_BYTES] {
        return Err(ReconcilerError::CorruptLedger("zero operation identity"));
    }
    Ok(OperationId::from_bytes(value))
}

pub(super) fn encode_operation(
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
) -> Vec<u8> {
    encode_operation_record(OperationRecord {
        state,
        effect_count,
        ownership_gated,
        runtime_intent_digest,
        public_operation: None,
    })
}

pub(super) fn encode_operation_record(operation: OperationRecord) -> Vec<u8> {
    let public = operation.public_operation;
    let mut bytes = Vec::with_capacity(if public.is_some() {
        OPERATION_RECORD_V2_BYTES
    } else {
        OPERATION_RECORD_V1_BYTES
    });
    bytes.push(if public.is_some() {
        RECORD_VERSION_V2
    } else {
        RECORD_VERSION_V1
    });
    bytes.push(operation.state as u8);
    bytes.push(
        u8::from(operation.ownership_gated) * OPERATION_FLAG_OWNERSHIP_GATED
            | u8::from(public.is_some()) * OPERATION_FLAG_PUBLIC,
    );
    bytes.push(0);
    bytes.extend_from_slice(&operation.effect_count.to_le_bytes());
    match operation.runtime_intent_digest {
        Some(digest) => bytes.extend_from_slice(digest.as_bytes()),
        None => bytes.extend_from_slice(&[0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES]),
    }
    if let Some(public) = public {
        public.encode(&mut bytes);
    }
    bytes
}

pub(super) fn decode_operation(bytes: &[u8]) -> Result<OperationRecord, ReconcilerError> {
    if bytes.len() != OPERATION_RECORD_V1_BYTES && bytes.len() != OPERATION_RECORD_V2_BYTES {
        return Err(ReconcilerError::CorruptLedger(
            "invalid operation record version, flags, or length",
        ));
    }
    let version = bytes[0];
    let state = OperationState::from_byte(bytes[1])?;
    let flags = bytes[2];
    let public = flags & OPERATION_FLAG_PUBLIC != 0;
    if bytes[3] != 0
        || flags & !(OPERATION_FLAG_OWNERSHIP_GATED | OPERATION_FLAG_PUBLIC) != 0
        || (version == RECORD_VERSION_V1 && (bytes.len() != OPERATION_RECORD_V1_BYTES || public))
        || (version == RECORD_VERSION_V2 && (bytes.len() != OPERATION_RECORD_V2_BYTES || !public))
        || !matches!(version, RECORD_VERSION_V1 | RECORD_VERSION_V2)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid operation record version, flags, or length",
        ));
    }
    let effect_count = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| ReconcilerError::CorruptLedger("invalid effect count"))?,
    );
    let ownership_gated = flags & OPERATION_FLAG_OWNERSHIP_GATED != 0;
    if effect_count as usize > MAXIMUM_EFFECTS
        || (effect_count == 0 && (state != OperationState::Succeeded || ownership_gated))
    {
        return Err(ReconcilerError::CorruptLedger("invalid effect count"));
    }
    if ownership_gated && effect_count as usize > MAXIMUM_GATED_EFFECTS {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership-gated effect count",
        ));
    }
    if state == OperationState::OwnershipPending && !ownership_gated {
        return Err(ReconcilerError::CorruptLedger(
            "ownership-pending operation lacks gated provenance",
        ));
    }
    let digest: [u8; OPERATION_RUNTIME_INTENT_DIGEST_BYTES] = bytes[8..40]
        .try_into()
        .map_err(|_| ReconcilerError::CorruptLedger("invalid runtime intent digest"))?;
    let runtime_intent_digest = (digest != [0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES])
        .then(|| ObjectDigest::from_bytes(digest));
    if effect_count == 0 && runtime_intent_digest.is_some() {
        return Err(ReconcilerError::CorruptLedger(
            "completed local operation has runtime authority",
        ));
    }
    if runtime_intent_digest.is_some()
        && (!ownership_gated || effect_count as usize > MAXIMUM_GATED_EFFECTS - 1)
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid runtime operation provenance",
        ));
    }
    let public_operation = public
        .then(|| DurablePublicOperationV1::decode(&bytes[40..], state))
        .transpose()?;
    Ok(OperationRecord {
        state,
        effect_count,
        ownership_gated,
        runtime_intent_digest,
        public_operation,
    })
}

fn validate_claim_draft_context(
    claim: &OwnershipClaimV1,
    draft: &AuthorityPublicationDraftV1,
) -> Result<(), ReconcilerError> {
    let assignment = claim.assignment();
    let manifest = draft.manifest();
    let semantics = manifest.manifest();
    if assignment.sandbox() != semantics.sandbox()
        || assignment.incarnation() != semantics.incarnation()
        || assignment.epoch() != semantics.epoch()
        || assignment.digest() != manifest.digest()
        || claim.node() != semantics.node()
        || claim.desired_generation() != semantics.desired_generation()
    {
        return Err(ReconcilerError::InvalidPlan(
            "ownership claim does not match authority publication draft",
        ));
    }
    Ok(())
}

pub(super) fn encode_ownership_gate(
    gate: &OwnershipGateStatusV1,
) -> Result<Vec<u8>, ReconcilerError> {
    let (state, plan, publication_digest, lease_generation, lease_digest) = match gate {
        OwnershipGateStatusV1::Pending(plan) => (1_u8, plan, [0; 32], 0, [0; 32]),
        OwnershipGateStatusV1::Activated {
            plan,
            publication_digest,
            lease_generation,
            lease_digest,
        } => (
            2,
            plan,
            *publication_digest.as_bytes(),
            *lease_generation,
            *lease_digest.as_bytes(),
        ),
    };
    let idempotency_length = u16::try_from(plan.idempotency_key.as_bytes().len())
        .map_err(|_| ReconcilerError::InvalidPlan("ownership idempotency key is too large"))?;
    let expected_authority = plan.expected_authority();
    let key_id = expected_authority.stable_key_id().as_str().as_bytes();
    let key_id_length = u16::try_from(key_id.len())
        .map_err(|_| ReconcilerError::InvalidPlan("ownership authority key ID is too large"))?;
    let draft_length = u32::try_from(plan.publication_draft.canonical_bytes().len())
        .map_err(|_| ReconcilerError::InvalidPlan("ownership publication draft is too large"))?;
    let capacity = OWNERSHIP_GATE_FIXED_BYTES
        .checked_add(plan.idempotency_key.as_bytes().len())
        .and_then(|value| value.checked_add(key_id.len()))
        .and_then(|value| value.checked_add(CLAIM_BYTES))
        .and_then(|value| value.checked_add(plan.publication_draft.canonical_bytes().len()))
        .ok_or(ReconcilerError::InvalidPlan(
            "ownership gate length overflow",
        ))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(OWNERSHIP_GATE_MAGIC);
    bytes.extend_from_slice(&OWNERSHIP_GATE_VERSION.to_be_bytes());
    bytes.push(state);
    bytes.extend_from_slice(&[0; 5]);
    bytes.extend_from_slice(plan.operation_id.as_bytes());
    bytes.extend_from_slice(&plan.request_digest);
    bytes.extend_from_slice(&idempotency_length.to_be_bytes());
    bytes.extend_from_slice(&key_id_length.to_be_bytes());
    bytes.extend_from_slice(&expected_authority.generation().to_be_bytes());
    bytes.extend_from_slice(expected_authority.public_key_sha256().as_bytes());
    bytes.extend_from_slice(&(CLAIM_BYTES as u32).to_be_bytes());
    bytes.extend_from_slice(&draft_length.to_be_bytes());
    bytes.extend_from_slice(plan.claim.digest().as_bytes());
    bytes.extend_from_slice(plan.publication_draft.digest().as_bytes());
    bytes.extend_from_slice(&publication_digest);
    bytes.extend_from_slice(&lease_generation.to_be_bytes());
    bytes.extend_from_slice(&lease_digest);
    bytes.extend_from_slice(plan.idempotency_key.as_bytes());
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(plan.claim.canonical_bytes());
    bytes.extend_from_slice(plan.publication_draft.canonical_bytes());
    Ok(bytes)
}

pub(super) fn decode_ownership_gate(
    bytes: &[u8],
) -> Result<OwnershipGateStatusV1, ReconcilerError> {
    let mut reader = BoundedReader::new(bytes, ownership_gate_read_error);
    if reader.array::<8>()? != *OWNERSHIP_GATE_MAGIC
        || u16::from_be_bytes(reader.array::<2>()?) != OWNERSHIP_GATE_VERSION
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate version",
        ));
    }
    let state = reader.array::<1>()?[0];
    reader.zeros(5)?;
    let operation_bytes = reader.array::<16>()?;
    let request_digest = reader.array::<32>()?;
    let idempotency_length = usize::from(u16::from_be_bytes(reader.array::<2>()?));
    let key_id_length = usize::from(u16::from_be_bytes(reader.array::<2>()?));
    let authority_generation = u64::from_be_bytes(reader.array::<8>()?);
    let authority_fingerprint = reader.array::<32>()?;
    let claim_length = usize::try_from(u32::from_be_bytes(reader.array::<4>()?))
        .map_err(|_| ReconcilerError::CorruptLedger("ownership claim length overflow"))?;
    let draft_length = usize::try_from(u32::from_be_bytes(reader.array::<4>()?))
        .map_err(|_| ReconcilerError::CorruptLedger("ownership draft length overflow"))?;
    let claim_digest = ObjectDigest::from_bytes(reader.array::<32>()?);
    let draft_digest = ObjectDigest::from_bytes(reader.array::<32>()?);
    let publication_digest = ObjectDigest::from_bytes(reader.array::<32>()?);
    let lease_generation = u64::from_be_bytes(reader.array::<8>()?);
    let lease_digest = ObjectDigest::from_bytes(reader.array::<32>()?);
    if operation_bytes == [0; 16]
        || request_digest == [0; 32]
        || idempotency_length == 0
        || idempotency_length > 128
        || key_id_length == 0
        || key_id_length > 255
        || authority_generation == 0
        || authority_fingerprint == [0; 32]
        || claim_length != CLAIM_BYTES
        || draft_length == 0
        || draft_length > MAXIMUM_OWNERSHIP_DRAFT_BYTES
    {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate fields",
        ));
    }
    let expected_length = OWNERSHIP_GATE_FIXED_BYTES
        .checked_add(idempotency_length)
        .and_then(|value| value.checked_add(key_id_length))
        .and_then(|value| value.checked_add(claim_length))
        .and_then(|value| value.checked_add(draft_length))
        .ok_or(ReconcilerError::CorruptLedger(
            "ownership gate length overflow",
        ))?;
    if expected_length != bytes.len() {
        return Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate length",
        ));
    }
    let idempotency = reader.bytes(idempotency_length)?;
    let key_id = std::str::from_utf8(reader.bytes(key_id_length)?)
        .map_err(|_| ReconcilerError::CorruptLedger("ownership key ID is not UTF-8"))?;
    let claim_bytes = reader.bytes(claim_length)?;
    let publication_draft_bytes = reader.bytes(draft_length)?;
    reader.finish()?;
    let claim = OwnershipClaimV1::from_canonical_bytes(claim_bytes)
        .map_err(|_| ReconcilerError::CorruptLedger("invalid canonical ownership claim"))?;
    if claim.canonical_bytes().as_slice() != claim_bytes || claim.digest() != claim_digest {
        return Err(ReconcilerError::CorruptLedger(
            "ownership claim digest mismatch",
        ));
    }
    let encoded_authority = KeyReference::new(
        StableKeyId::new(key_id.to_owned())
            .map_err(|_| ReconcilerError::CorruptLedger("invalid ownership authority key ID"))?,
        authority_generation,
        ObjectDigest::from_bytes(authority_fingerprint),
        KeyUsage::OwnershipLease,
    );
    let publication_draft =
        AuthorityPublicationDraftV1::from_canonical_bytes(publication_draft_bytes)
            .map_err(|_| ReconcilerError::CorruptLedger("invalid authority publication draft"))?;
    if publication_draft.canonical_bytes() != publication_draft_bytes
        || publication_draft.digest() != draft_digest
        || publication_draft.ownership_authority() != &encoded_authority
    {
        return Err(ReconcilerError::CorruptLedger(
            "ownership publication draft does not match gate metadata",
        ));
    }
    let plan = OwnershipGatePlanV1::new(
        OperationId::from_bytes(operation_bytes),
        IdempotencyKey::new(idempotency.to_vec())
            .map_err(|_| ReconcilerError::CorruptLedger("invalid ownership idempotency key"))?,
        request_digest,
        claim,
        publication_draft,
    )
    .map_err(|_| ReconcilerError::CorruptLedger("invalid ownership gate plan"))?;
    match state {
        1 if publication_digest.as_bytes() == &[0; 32]
            && lease_generation == 0
            && lease_digest.as_bytes() == &[0; 32] =>
        {
            Ok(OwnershipGateStatusV1::Pending(plan))
        }
        2 if publication_digest.as_bytes() != &[0; 32]
            && lease_generation != 0
            && lease_digest.as_bytes() != &[0; 32] =>
        {
            Ok(OwnershipGateStatusV1::Activated {
                plan,
                publication_digest,
                lease_generation,
                lease_digest,
            })
        }
        _ => Err(ReconcilerError::CorruptLedger(
            "invalid ownership gate activation state",
        )),
    }
}

fn ownership_gate_read_error(error: ReadError) -> ReconcilerError {
    ReconcilerError::CorruptLedger(match error {
        ReadError::LengthOverflow => "ownership gate length overflow",
        ReadError::Truncated => "truncated ownership gate",
        ReadError::NonzeroReserved => "invalid ownership gate reserved bytes",
        ReadError::TrailingBytes => "trailing ownership gate bytes",
    })
}
