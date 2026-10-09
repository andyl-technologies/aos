//! Owns canonical Operation record DATA and Operation/Effect key layouts.

use aos_sandbox_core::{ObjectDigest, OperationId};

use super::public_operation::{
    DurablePublicOperationV1, OperationState, PUBLIC_OPERATION_RECORD_BYTES,
    PublicOperationDataError,
};

pub const RECORD_VERSION_V1: u8 = 1;
const RECORD_VERSION_V2: u8 = 2;
const OPERATION_FLAG_OWNERSHIP_GATED: u8 = 1;
const OPERATION_FLAG_PUBLIC: u8 = 2;
pub const OPERATION_RUNTIME_INTENT_DIGEST_BYTES: usize = 32;
pub const OPERATION_RECORD_V1_BYTES: usize = 8 + OPERATION_RUNTIME_INTENT_DIGEST_BYTES;
pub const OPERATION_RECORD_V2_BYTES: usize =
    OPERATION_RECORD_V1_BYTES + PUBLIC_OPERATION_RECORD_BYTES;
pub const OPERATION_KEY_BYTES: usize = 16;
const EFFECT_KEY_BYTES: usize = 20;
// The default journal transaction bound is 4096 records. Admission also
// carries desired-state, operation, and idempotency records atomically.
pub const MAXIMUM_EFFECTS: usize = 4093;
pub const MAXIMUM_GATED_EFFECTS: usize = 4092;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    state: OperationState,
    effect_count: u32,
    ownership_gated: bool,
    runtime_intent_digest: Option<ObjectDigest>,
    public_operation: Option<DurablePublicOperationV1>,
}


impl OperationRecord {
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

    pub const fn state(self) -> OperationState {
        self.state
    }

    pub const fn effect_count(self) -> u32 {
        self.effect_count
    }

    pub const fn ownership_gated(self) -> bool {
        self.ownership_gated
    }

    pub const fn runtime_intent_digest(self) -> Option<ObjectDigest> {
        self.runtime_intent_digest
    }

    pub const fn public_operation(self) -> Option<DurablePublicOperationV1> {
        self.public_operation
    }

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

pub fn effect_key(operation_id: OperationId, step: u32) -> [u8; EFFECT_KEY_BYTES] {
    let mut key = [0_u8; EFFECT_KEY_BYTES];
    key[..OPERATION_KEY_BYTES].copy_from_slice(operation_id.as_bytes());
    key[OPERATION_KEY_BYTES..].copy_from_slice(&step.to_be_bytes());
    key
}

pub fn decode_operation_key(bytes: &[u8]) -> Result<OperationId, PublicOperationDataError> {
    let value: [u8; OPERATION_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| PublicOperationDataError::CorruptLedger("invalid operation key length"))?;
    if value == [0; OPERATION_KEY_BYTES] {
        return Err(PublicOperationDataError::CorruptLedger("zero operation identity"));
    }
    Ok(OperationId::from_bytes(value))
}

pub fn encode_operation(
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

