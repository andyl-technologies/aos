//! Owns the complete OwnershipGate historical model and canonical V1 codec.
//!
//! A plan retains the exact bounded Claim, Publication Draft and request DATA.
//! Pending/Activated records describe durable history; decoding neither checks
//! current publication nor activates ownership or creates an executable effect.
//! Native admission, activation, Journal custody and currentness remain upper.
//!
//! The established records have these layouts:
//!
//! ```text
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

use aos_sandbox_model::bounded_codec::{BoundedReader, ReadError};
use aos_sandbox_model::model::{KeyReference, KeyUsage, StableKeyId};
use aos_sandbox_model::{ObjectDigest, OperationId};
use aos_sandbox_ownership_protocol::{CLAIM_BYTES, OwnershipClaimV1};

use super::transaction::IdempotencyKey;
use crate::publication::AuthorityPublicationDraftV1;

const MAXIMUM_OWNERSHIP_DRAFT_BYTES: usize = 15 * 1024 * 1024;
const OWNERSHIP_GATE_MAGIC: &[u8; 8] = b"AOSOGT01";
const OWNERSHIP_GATE_VERSION: u16 = 1;
const OWNERSHIP_GATE_FIXED_BYTES: usize = 252;

/// Carries the bounded non-authorizing inputs durably held before ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipGatePlanV1 {
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_digest: [u8; 32],
    claim: OwnershipClaimV1,
    publication_draft: AuthorityPublicationDraftV1,
}

impl OwnershipGatePlanV1 {
    /// Constructs a bounded plan from the complete original structural inputs.
    ///
    /// This validates Claim/Draft context without authenticating a current
    /// ownership result, publishing a record or granting dispatch eligibility.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, invalid authority usage, oversized Drafts
    /// and Claim/Draft assignment, node or generation mismatches.
    pub fn new(
        operation_id: OperationId,
        idempotency_key: IdempotencyKey,
        request_digest: [u8; 32],
        claim: OwnershipClaimV1,
        publication_draft: AuthorityPublicationDraftV1,
    ) -> Result<Self, OwnershipGateDataErrorV1> {
        let expected_authority = publication_draft.ownership_authority();
        if operation_id.as_bytes() == &[0; 16]
            || request_digest == [0; 32]
            || expected_authority.generation() == 0
            || expected_authority.public_key_sha256().as_bytes() == &[0; 32]
            || expected_authority.usage() != KeyUsage::OwnershipLease
            || publication_draft.canonical_bytes().len() > MAXIMUM_OWNERSHIP_DRAFT_BYTES
        {
            return Err(OwnershipGateDataErrorV1::InvalidPlan(
                "invalid ownership gate plan",
            ));
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

    /// Borrows the original stored request digest without copying its bytes.
    #[must_use]
    pub const fn request_digest_bytes(&self) -> &[u8; 32] {
        &self.request_digest
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
    /// Historical publication and lease identifiers record an activated gate.
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

fn validate_claim_draft_context(
    claim: &OwnershipClaimV1,
    draft: &AuthorityPublicationDraftV1,
) -> Result<(), OwnershipGateDataErrorV1> {
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
        return Err(OwnershipGateDataErrorV1::InvalidPlan(
            "ownership claim does not match authority publication draft",
        ));
    }
    Ok(())
}

/// Encodes the complete historical Gate using the established V1 layout.
///
/// # Errors
///
/// Rejects key or Draft lengths that exceed their integer representations and
/// checked aggregate-length overflow. Encoding does not validate live authority.
pub fn encode_ownership_gate(
    gate: &OwnershipGateStatusV1,
) -> Result<Vec<u8>, OwnershipGateDataErrorV1> {
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
    let idempotency_length =
        u16::try_from(plan.idempotency_key.as_bytes().len()).map_err(|_| {
            OwnershipGateDataErrorV1::InvalidPlan("ownership idempotency key is too large")
        })?;
    let expected_authority = plan.expected_authority();
    let key_id = expected_authority.stable_key_id().as_str().as_bytes();
    let key_id_length = u16::try_from(key_id.len()).map_err(|_| {
        OwnershipGateDataErrorV1::InvalidPlan("ownership authority key ID is too large")
    })?;
    let draft_length =
        u32::try_from(plan.publication_draft.canonical_bytes().len()).map_err(|_| {
            OwnershipGateDataErrorV1::InvalidPlan("ownership publication draft is too large")
        })?;
    let capacity = ownership_gate_encoded_bytes_v1(plan)?;
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

/// Returns the exact pending or activated record width without encoding.
///
/// Both states have identical field widths. This passive calculation neither
/// validates authority nor allocates a record or publication.
///
/// # Errors
/// Rejects checked length overflow before the existing encoder allocates.
pub fn ownership_gate_encoded_bytes_v1(
    plan: &OwnershipGatePlanV1,
) -> Result<usize, OwnershipGateDataErrorV1> {
    OWNERSHIP_GATE_FIXED_BYTES
        .checked_add(plan.idempotency_key.as_bytes().len())
        .and_then(|value| value.checked_add(plan.expected_authority().stable_key_id().as_str().len()))
        .and_then(|value| value.checked_add(CLAIM_BYTES))
        .and_then(|value| value.checked_add(plan.publication_draft.canonical_bytes().len()))
        .ok_or(OwnershipGateDataErrorV1::InvalidPlan(
            "ownership gate length overflow",
        ))
}

/// Decodes the complete bounded V1 record and its original structural context.
///
/// # Errors
///
/// Rejects malformed headers, reserved bytes, bounds, lengths, UTF-8, canonical
/// Claim/Draft bytes, context or activation fields in their original order.
pub fn decode_ownership_gate(
    bytes: &[u8],
) -> Result<OwnershipGateStatusV1, OwnershipGateDataErrorV1> {
    let mut reader = BoundedReader::new(bytes, ownership_gate_read_error);
    if reader.array::<8>()? != *OWNERSHIP_GATE_MAGIC
        || u16::from_be_bytes(reader.array::<2>()?) != OWNERSHIP_GATE_VERSION
    {
        return Err(OwnershipGateDataErrorV1::CorruptLedger(
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
        .map_err(|_| OwnershipGateDataErrorV1::CorruptLedger("ownership claim length overflow"))?;
    let draft_length = usize::try_from(u32::from_be_bytes(reader.array::<4>()?))
        .map_err(|_| OwnershipGateDataErrorV1::CorruptLedger("ownership draft length overflow"))?;
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
        return Err(OwnershipGateDataErrorV1::CorruptLedger(
            "invalid ownership gate fields",
        ));
    }
    let expected_length = OWNERSHIP_GATE_FIXED_BYTES
        .checked_add(idempotency_length)
        .and_then(|value| value.checked_add(key_id_length))
        .and_then(|value| value.checked_add(claim_length))
        .and_then(|value| value.checked_add(draft_length))
        .ok_or(OwnershipGateDataErrorV1::CorruptLedger(
            "ownership gate length overflow",
        ))?;
    if expected_length != bytes.len() {
        return Err(OwnershipGateDataErrorV1::CorruptLedger(
            "invalid ownership gate length",
        ));
    }
    let idempotency = reader.bytes(idempotency_length)?;
    let key_id = std::str::from_utf8(reader.bytes(key_id_length)?)
        .map_err(|_| OwnershipGateDataErrorV1::CorruptLedger("ownership key ID is not UTF-8"))?;
    let claim_bytes = reader.bytes(claim_length)?;
    let publication_draft_bytes = reader.bytes(draft_length)?;
    reader.finish()?;
    let claim = OwnershipClaimV1::from_canonical_bytes(claim_bytes).map_err(|_| {
        OwnershipGateDataErrorV1::CorruptLedger("invalid canonical ownership claim")
    })?;
    if claim.canonical_bytes().as_slice() != claim_bytes || claim.digest() != claim_digest {
        return Err(OwnershipGateDataErrorV1::CorruptLedger(
            "ownership claim digest mismatch",
        ));
    }
    let encoded_authority = KeyReference::new(
        StableKeyId::new(key_id.to_owned()).map_err(|_| {
            OwnershipGateDataErrorV1::CorruptLedger("invalid ownership authority key ID")
        })?,
        authority_generation,
        ObjectDigest::from_bytes(authority_fingerprint),
        KeyUsage::OwnershipLease,
    );
    let publication_draft = AuthorityPublicationDraftV1::from_canonical_bytes(
        publication_draft_bytes,
    )
    .map_err(|_| OwnershipGateDataErrorV1::CorruptLedger("invalid authority publication draft"))?;
    if publication_draft.canonical_bytes() != publication_draft_bytes
        || publication_draft.digest() != draft_digest
        || publication_draft.ownership_authority() != &encoded_authority
    {
        return Err(OwnershipGateDataErrorV1::CorruptLedger(
            "ownership publication draft does not match gate metadata",
        ));
    }
    let plan = OwnershipGatePlanV1::new(
        OperationId::from_bytes(operation_bytes),
        IdempotencyKey::new(idempotency.to_vec()).map_err(|_| {
            OwnershipGateDataErrorV1::CorruptLedger("invalid ownership idempotency key")
        })?,
        request_digest,
        claim,
        publication_draft,
    )
    .map_err(|_| OwnershipGateDataErrorV1::CorruptLedger("invalid ownership gate plan"))?;
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
        _ => Err(OwnershipGateDataErrorV1::CorruptLedger(
            "invalid ownership gate activation state",
        )),
    }
}

fn ownership_gate_read_error(error: ReadError) -> OwnershipGateDataErrorV1 {
    OwnershipGateDataErrorV1::CorruptLedger(match error {
        ReadError::LengthOverflow => "ownership gate length overflow",
        ReadError::Truncated => "truncated ownership gate",
        ReadError::NonzeroReserved => "invalid ownership gate reserved bytes",
        ReadError::TrailingBytes => "trailing ownership gate bytes",
    })
}

/// Reports invalid Gate plan inputs or corrupt retained Gate bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OwnershipGateDataErrorV1 {
    /// Structural plan validation or bounded encoding rejected the inputs.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// The complete retained record violates the original Gate grammar.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
}
