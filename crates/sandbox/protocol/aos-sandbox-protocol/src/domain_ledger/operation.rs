//! Owns canonical Operation record DATA and Operation/Effect key layouts.
//!
//! The established record versions and Start-only V3 share one decoder and an intentionally
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
//! V3 (184 bytes): V2 header/public metadata | accepted Start origin[80]
//! flags: ownership-gated=0x01, public-metadata=0x02
//! Operation key: operation-id[16]
//! Effect key: operation-id[16] | step:u32be
//! ```
//!
//! A zero runtime-digest slot means absence. Operation key decoding rejects a
//! zero identity, while Effect key construction preserves every supplied identity.
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

mod start_acceptance;

pub use start_acceptance::{AcceptedStartOriginDataV1, StartNativeOriginDataV1,
    ACCEPTED_START_ORIGIN_BYTES, START_NATIVE_ORIGIN_BYTES};

use aos_sandbox_model::{ObjectDigest, OperationId};

use super::public_operation::{
    DurablePublicOperationV1, OperationState, PUBLIC_OPERATION_RECORD_BYTES,
    PublicOperationDataError,
};

/// Identifies the original Operation record without a public metadata tail.
pub const RECORD_VERSION_V1: u8 = 1;
const RECORD_VERSION_V2: u8 = 2;
const RECORD_VERSION_V3: u8 = 3;
const OPERATION_FLAG_OWNERSHIP_GATED: u8 = 1;
const OPERATION_FLAG_PUBLIC: u8 = 2;
/// Bounds the optional runtime-intent digest slot, including its zero sentinel.
pub const OPERATION_RUNTIME_INTENT_DIGEST_BYTES: usize = 32;
/// Bounds the complete fixed-width V1 Operation record.
pub const OPERATION_RECORD_V1_BYTES: usize = 8 + OPERATION_RUNTIME_INTENT_DIGEST_BYTES;
/// Bounds the complete fixed-width V2 Operation record and public metadata tail.
pub const OPERATION_RECORD_V2_BYTES: usize =
    OPERATION_RECORD_V1_BYTES + PUBLIC_OPERATION_RECORD_BYTES;
/// Bounds public Start metadata and its immutable original-admission tail.
pub const OPERATION_RECORD_V3_BYTES: usize = OPERATION_RECORD_V2_BYTES + ACCEPTED_START_ORIGIN_BYTES;
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
    accepted_start: Option<AcceptedStartOriginDataV1>,
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
            accepted_start: None,
        }
    }

    /// Attaches inert historical Start admission DATA without granting authority.
    ///
    /// Encoding remains unchecked; the sole decoder rejects a tail on another method.
    pub const fn with_accepted_start_origin_v1(mut self, origin: AcceptedStartOriginDataV1) -> Self {
        self.accepted_start = Some(origin);
        self
    }

    /// Returns the immutable accepted Start origin, when historically present.
    pub const fn accepted_start_origin_v1(self) -> Option<AcceptedStartOriginDataV1> {
        self.accepted_start
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
/// Returns [`PublicOperationDataError::CorruptLedger`] for a non-16-byte key or
/// a zero identity. The length check precedes the zero-identity check.
pub fn decode_operation_key(bytes: &[u8]) -> Result<OperationId, PublicOperationDataError> {
    let value: [u8; OPERATION_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| PublicOperationDataError::CorruptLedger("invalid operation key length"))?;
    if value == [0; OPERATION_KEY_BYTES] {
        return Err(PublicOperationDataError::CorruptLedger(
            "zero operation identity",
        ));
    }
    Ok(OperationId::from_bytes(value))
}

/// Encodes historical DATA using V1, V2, or Start-only V3.
///
/// Encoding is intentionally unchecked. It allocates the selected fixed width
/// and writes fields in their established order; it grants no commit authority.
pub fn encode_operation_record(operation: OperationRecord) -> Vec<u8> {
    let public = operation.public_operation;
    let mut bytes = Vec::with_capacity(if operation.accepted_start.is_some() {
        OPERATION_RECORD_V3_BYTES
    } else if public.is_some() {
        OPERATION_RECORD_V2_BYTES
    } else {
        OPERATION_RECORD_V1_BYTES
    });
    bytes.push(if operation.accepted_start.is_some() {
        RECORD_VERSION_V3
    } else if public.is_some() {
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
    if let Some(origin) = operation.accepted_start {
        origin.encode_into_v1(&mut bytes);
    }
    bytes
}

/// Recognizes the version byte of a Controller Operation record as DATA.
///
/// Other services use the shared journal namespace with separate record
/// formats. This discriminator selects the Controller decoder without
/// validating the record, its transition, or any mutation authority.
#[must_use]
pub fn has_operation_record_version_data_v1(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(|version| {
        matches!(*version, RECORD_VERSION_V1 | RECORD_VERSION_V2 | RECORD_VERSION_V3)
    })
}

/// Decodes a complete canonical V1, V2, or Start-only V3 Operation record.
///
/// # Errors
/// Returns [`PublicOperationDataError::CorruptLedger`] for fixed-width, state,
/// header, count, gate or runtime provenance violations, then for any invalid
/// V2 public metadata. Length precedes state; state precedes header validation;
/// count and runtime provenance precede metadata. Decoding proves DATA structure
/// only and does not validate the enclosing Effect or current protected owners.
pub fn decode_operation(bytes: &[u8]) -> Result<OperationRecord, PublicOperationDataError> {
    if bytes.len() != OPERATION_RECORD_V1_BYTES
        && bytes.len() != OPERATION_RECORD_V2_BYTES
        && bytes.len() != OPERATION_RECORD_V3_BYTES
    {
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
        || (version == RECORD_VERSION_V3 && (bytes.len() != OPERATION_RECORD_V3_BYTES || !public))
        || !matches!(version, RECORD_VERSION_V1 | RECORD_VERSION_V2 | RECORD_VERSION_V3)
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
    // Only explicit closed recovery tags admit a pending zero-effect
    // record. Full metadata validation still follows the established header,
    // count and runtime checks; ordinary zero-effect records remain terminal.
    let closed_recovery = version == RECORD_VERSION_V2
        && bytes.get(40) == Some(&25) && matches!(bytes.get(41), Some(1 | 2 | 3));
    if effect_count as usize > MAXIMUM_EFFECTS
        || (effect_count == 0 && (ownership_gated
            || (state != OperationState::Succeeded && !closed_recovery)))
    {
        return Err(PublicOperationDataError::CorruptLedger(
            "invalid effect count",
        ));
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
        .then(|| DurablePublicOperationV1::decode(&bytes[40..OPERATION_RECORD_V2_BYTES], state))
        .transpose()?;
    if state == OperationState::CommittedWithResidualCleanup
        && (version != RECORD_VERSION_V2 || effect_count != 1 || ownership_gated
            || runtime_intent_digest.is_some()
            || public_operation.is_none_or(|public| public.method()
                != crate::public_api::PublicOperationMethodV1::StopSandbox)) {
        return Err(PublicOperationDataError::CorruptLedger("invalid residual Stop operation"));
    }
    if closed_recovery && (effect_count != 0 || ownership_gated
        || runtime_intent_digest.is_some()
        || !(matches!(state, OperationState::Accepted | OperationState::Succeeded)
            || (state == OperationState::PermanentlyBlocked
                && public_operation.is_some_and(|public| public.recovery_kind_v1()
                    == crate::domain_ledger::public_operation::PublicRecoveryKindV1::StopCleanup)))) {
        return Err(PublicOperationDataError::CorruptLedger(
            if bytes.get(41) == Some(&1) {
                "invalid metadata-completion operation"
            } else {
                "invalid cleanup-recovery operation"
            },
        ));
    }
    let accepted_start = if version == RECORD_VERSION_V3 {
        let public = public_operation.ok_or(PublicOperationDataError::CorruptLedger(
            "Start origin lacks public metadata",
        ))?;
        if public.method() != crate::public_api::PublicOperationMethodV1::StartSandbox
            || effect_count != 1 || ownership_gated || runtime_intent_digest.is_some()
        {
            return Err(PublicOperationDataError::CorruptLedger("Start origin on another method"));
        }
        let origin = AcceptedStartOriginDataV1::decode_v1(&bytes[OPERATION_RECORD_V2_BYTES..])?;
        if origin.accepted_clock_v1().wall_seconds() != public.accepted_wall_seconds_v1() {
            return Err(PublicOperationDataError::CorruptLedger("Start origin accepted wall differs"));
        }
        Some(origin)
    } else { None };
    Ok(OperationRecord {
        state,
        effect_count,
        ownership_gated,
        runtime_intent_digest,
        public_operation,
        accepted_start,
    })
}

/// Expands the established lookup at an actual historical row borrower.
///
/// The caller retains its original missing-row and canonical decoder categories.
#[macro_export]
macro_rules! historical_operation_read_data_v2 {
    (read = $read:expr, missing = $missing:expr, project = $project:expr) => {{
        let bytes = $read.ok_or($missing)?;
        $crate::domain_ledger::operation::decode_operation(bytes).map_err($project)
    }};
}
