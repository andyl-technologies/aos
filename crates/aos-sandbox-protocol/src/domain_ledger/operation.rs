//! Owns canonical Operation record DATA and Operation/Effect key layouts.
//!
//! Both established record versions share one decoder and an intentionally
//! unchecked encoder. The opaque Copy record holds historical state and optional
//! V2 public metadata. Its constructor and replacement assemble DATA without
//! admitting a transition, validating an Effect, acquiring a clock, or granting
//! ownership, currentness or mutation authority. Those responsibilities remain
//! with the Domain Reconciler and its real protected owners.
//!
//! The durable integer layout is fixed:
//!
//! ```text
//! V1 (40 bytes): version=1:u8 | state:u8 | flags:u8 | reserved=0:u8 |
//!               effect-count:u32le | runtime-intent-digest-or-zero[32]
//! V2 (104 bytes): version=2 header with public flag | V2 public-metadata[64]
//! flags: ownership-gated=0x01, public-metadata=0x02
//! Operation key: operation-id[16]
//! Effect key: operation-id[16] | step:u32be
//! ```
//!
//! A zero runtime-digest slot means absence. Decoding rejects a zero Operation
//! identity, while Effect key construction preserves every supplied identity.
//! Public metadata uses the separate [`super::public_operation`] DATA format.
//!
//! # Examples
//!
//! ```no_run
//! use aos_sandbox_protocol::domain_ledger::operation::{
//!     OperationRecord, decode_operation, encode_operation_record,
//! };
//! use aos_sandbox_protocol::domain_ledger::public_operation::{
//!     OperationState, PublicOperationDataError,
//! };
//!
//! # fn example() -> Result<(), PublicOperationDataError> {
//! let record = OperationRecord::new(OperationState::Accepted, 1, false, None, None);
//! let bytes = encode_operation_record(record);
//! assert_eq!(bytes.len(), 40);
//! assert_eq!(decode_operation(&bytes)?.state(), OperationState::Accepted);
//! # Ok(())
//! # }
//! ```

use aos_sandbox_core::{ObjectDigest, OperationId};

use super::public_operation::{
    DurablePublicOperationV1, OperationState, PUBLIC_OPERATION_RECORD_BYTES,
    PublicOperationDataError,
};

/// Identifies the original Operation record without a public metadata tail.
pub const RECORD_VERSION_V1: u8 = 1;
const RECORD_VERSION_V2: u8 = 2;
const OPERATION_FLAG_OWNERSHIP_GATED: u8 = 1;
const OPERATION_FLAG_PUBLIC: u8 = 2;
/// Bounds the optional runtime-intent digest slot, including its zero sentinel.
pub const OPERATION_RUNTIME_INTENT_DIGEST_BYTES: usize = 32;
/// Bounds the complete fixed-width V1 Operation record.
pub const OPERATION_RECORD_V1_BYTES: usize = 8 + OPERATION_RUNTIME_INTENT_DIGEST_BYTES;
/// Bounds the complete fixed-width V2 Operation record and public metadata tail.
pub const OPERATION_RECORD_V2_BYTES: usize =
    OPERATION_RECORD_V1_BYTES + PUBLIC_OPERATION_RECORD_BYTES;
/// Bounds an Operation key containing exactly one native operation identity.
pub const OPERATION_KEY_BYTES: usize = 16;
const EFFECT_KEY_BYTES: usize = 20;
// The default journal transaction bound is 4096 records. Admission also
// carries desired-state, operation, and idempotency records atomically.
/// Bounds the Effect count of an ordinary decoded Operation record.
pub const MAXIMUM_EFFECTS: usize = 4093;
/// Bounds the Effect count of a decoded ownership-gated Operation record.
///
/// A present runtime-intent digest reserves one further record below this ceiling.
pub const MAXIMUM_GATED_EFFECTS: usize = 4092;

/// Holds historical Operation DATA without a transition or admission permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
    public_operation: Option<DurablePublicOperationV1>,
}


impl OperationRecord {
    /// Assembles the five supplied fields without validating their combination.
    ///
    /// Arguments follow the canonical state, count, gate, runtime digest and
    /// public metadata order. Assembly is infallible and may produce a record
    /// that [`decode_operation`] rejects after encoding. It grants no authority.
    pub const fn new(
        state: OperationState,
        effect_count: u32,
        ownership_gated: bool,
        runtime_intent_digest: Option<ObjectDigest>,
        public_operation: Option<DurablePublicOperationV1>,
    ) -> Self {
        Self {
            state,
            effect_count,
            ownership_gated,
            runtime_intent_digest,
            public_operation,
        }
    }

    /// Returns a Copy of the recorded historical state.
    pub const fn state(self) -> OperationState {
        self.state
    }

    /// Returns the recorded number of ordered Effect steps.
    pub const fn effect_count(self) -> u32 {
        self.effect_count
    }

    /// Returns the historical ownership-gated flag without proving a live gate.
    pub const fn ownership_gated(self) -> bool {
        self.ownership_gated
    }

    /// Returns the optional recorded runtime-intent commitment.
    pub const fn runtime_intent_digest(self) -> Option<ObjectDigest> {
        self.runtime_intent_digest
    }

    /// Returns a Copy of the optional V2 public metadata.
    pub const fn public_operation(self) -> Option<DurablePublicOperationV1> {
        self.public_operation
    }

    /// Replaces state and public metadata while preserving the other three fields.
    ///
    /// This infallible Copy update performs no transition or clock checks. The
    /// caller retains responsibility for validating any live semantic transition
    /// before committing the encoded record to its actual protected journal.
    pub const fn with_state_and_public_operation(
        self,
        state: OperationState,
        public_operation: Option<DurablePublicOperationV1>,
    ) -> Self {
        Self {
            state,
            public_operation,
            ..self
        }
    }
}

/// Encodes an operation identity followed by its big-endian Effect step.
///
/// Construction is infallible and preserves zero identities and every step value.
pub fn effect_key(operation_id: OperationId, step: u32) -> [u8; EFFECT_KEY_BYTES] {
    let mut key = [0_u8; EFFECT_KEY_BYTES];
    key[..OPERATION_KEY_BYTES].copy_from_slice(operation_id.as_bytes());
    key[OPERATION_KEY_BYTES..].copy_from_slice(&step.to_be_bytes());
    key
}

/// Decodes the fixed-width nonzero Operation identity key.
///
/// # Errors
/// Returns [`PublicOperationDataError::CorruptLedger`] for a non-16-byte key
/// before checking whether its identity is zero.
pub fn decode_operation_key(bytes: &[u8]) -> Result<OperationId, PublicOperationDataError> {
    let value: [u8; OPERATION_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| PublicOperationDataError::CorruptLedger("invalid operation key length"))?;
    if value == [0; OPERATION_KEY_BYTES] {
        return Err(PublicOperationDataError::CorruptLedger("zero operation identity"));
    }
    Ok(OperationId::from_bytes(value))
}

/// Encodes the supplied DATA using V1 or V2 according to metadata presence.
///
/// Encoding is intentionally unchecked. It allocates the selected fixed width
/// and writes fields in their established order; it grants no commit authority.
pub fn encode_operation_record(operation: OperationRecord) -> Vec<u8> {
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

/// Decodes a complete canonical V1 or V2 Operation record.
///
/// # Errors
/// Returns [`PublicOperationDataError::CorruptLedger`] for fixed-width, state,
/// header, count, gate or runtime provenance violations, then for any invalid
/// V2 public metadata. Length precedes state; state precedes header validation;
/// count and runtime provenance precede metadata. Decoding proves DATA structure
/// only and does not validate the enclosing Effect or current protected owners.
pub fn decode_operation(bytes: &[u8]) -> Result<OperationRecord, PublicOperationDataError> {
    if bytes.len() != OPERATION_RECORD_V1_BYTES && bytes.len() != OPERATION_RECORD_V2_BYTES {
        return Err(PublicOperationDataError::CorruptLedger(
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
        return Err(PublicOperationDataError::CorruptLedger(
            "invalid operation record version, flags, or length",
        ));
    }
    let effect_count = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| PublicOperationDataError::CorruptLedger("invalid effect count"))?,
    );
    let ownership_gated = flags & OPERATION_FLAG_OWNERSHIP_GATED != 0;
    if effect_count as usize > MAXIMUM_EFFECTS
        || (effect_count == 0 && (state != OperationState::Succeeded || ownership_gated))
    {
        return Err(PublicOperationDataError::CorruptLedger("invalid effect count"));
    }
    if ownership_gated && effect_count as usize > MAXIMUM_GATED_EFFECTS {
        return Err(PublicOperationDataError::CorruptLedger(
            "invalid ownership-gated effect count",
        ));
    }
    if state == OperationState::OwnershipPending && !ownership_gated {
        return Err(PublicOperationDataError::CorruptLedger(
            "ownership-pending operation lacks gated provenance",
        ));
    }
    let digest: [u8; OPERATION_RUNTIME_INTENT_DIGEST_BYTES] = bytes[8..40]
        .try_into()
        .map_err(|_| PublicOperationDataError::CorruptLedger("invalid runtime intent digest"))?;
    let runtime_intent_digest = (digest != [0; OPERATION_RUNTIME_INTENT_DIGEST_BYTES])
        .then(|| ObjectDigest::from_bytes(digest));
    if effect_count == 0 && runtime_intent_digest.is_some() {
        return Err(PublicOperationDataError::CorruptLedger(
            "completed local operation has runtime authority",
        ));
    }
    if runtime_intent_digest.is_some()
        && (!ownership_gated || effect_count as usize > MAXIMUM_GATED_EFFECTS - 1)
    {
        return Err(PublicOperationDataError::CorruptLedger(
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
