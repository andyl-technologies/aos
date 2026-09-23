//! Authenticated durable claim for one distinct guest-root population effect.
//!
//! The Storage transaction journal writes the ambiguous form before a worker
//! can copy a byte. Recovery may read back an exact marker, but never infer a
//! fresh mutation grant from this record. A new effect needs a new signed
//! method-31 admission under the current lease.
//!
//! ```text
//! AOSGRA01 | version:u16=1 | key-id[16] | effect-operation[16]
//!          | request-id[16] | sealed-effect-digest[32]
//!          | operation-fence-digest[32] | expected-AOSGRP01[266]
//!          | root-device:u64be | root-inode:u64be | kernel-boot[16]
//!          | effect-deadline-boottime:u64be | phase:u8 | hmac-sha256[32]
//! ```

use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

use crate::StorageStateError;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"AOSGRA01";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"aos.sandbox.storage.guest-root-attempt.v1\0";
const BODY_BYTES: usize = 429;
const RECORD_BYTES: usize = BODY_BYTES + 32;

/// Marks whether a publication claim is still ambiguous or physically read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuestRootAttemptPhaseV1 {
    /// A worker may have mutated the root; recovery is observation-only.
    Ambiguous,
    /// The exact marker and complete package tree were physically read back.
    Complete,
}

impl GuestRootAttemptPhaseV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Ambiguous => 1,
            Self::Complete => 2,
        }
    }

    const fn from_code(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Ambiguous),
            2 => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Retains exactly which signed effect may have populated one pinned root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuestRootPublicationAttemptV1 {
    pub(crate) effect_operation: [u8; 16],
    pub(crate) request_id: [u8; 16],
    pub(crate) sealed_effect_digest: [u8; 32],
    pub(crate) operation_fence_digest: [u8; 32],
    pub(crate) expected_proof: GuestRootPublicationProofV1,
    pub(crate) root_device: u64,
    pub(crate) root_inode: u64,
    pub(crate) kernel_boot: [u8; 16],
    pub(crate) effect_deadline_boottime_nanoseconds: u64,
    pub(crate) phase: GuestRootAttemptPhaseV1,
}

impl GuestRootPublicationAttemptV1 {
    pub(crate) fn validate(self) -> Result<(), StorageStateError> {
        if self.effect_operation == [0; 16]
            || self.effect_operation == self.expected_proof.creation_operation
            || self.request_id == [0; 16]
            || self.sealed_effect_digest == [0; 32]
            || self.operation_fence_digest == [0; 32]
            || self.expected_proof.encode().is_err()
            || self.root_device == 0
            || self.root_inode == 0
            || self.kernel_boot == [0; 16]
            || self.effect_deadline_boottime_nanoseconds == 0
        {
            return Err(StorageStateError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn complete(mut self) -> Result<Self, StorageStateError> {
        if self.phase != GuestRootAttemptPhaseV1::Ambiguous {
            return Err(StorageStateError::InvalidTransition);
        }
        self.phase = GuestRootAttemptPhaseV1::Complete;
        Ok(self)
    }
}

pub(crate) fn encode_attempt(
    attempt: GuestRootPublicationAttemptV1,
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<Vec<u8>, StorageStateError> {
    attempt.validate()?;
    if key_id == [0; 16] || *secret == [0; 32] {
        return Err(StorageStateError::InvalidValue);
    }
    let mut bytes = Vec::with_capacity(RECORD_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&key_id);
    bytes.extend_from_slice(&attempt.effect_operation);
    bytes.extend_from_slice(&attempt.request_id);
    bytes.extend_from_slice(&attempt.sealed_effect_digest);
    bytes.extend_from_slice(&attempt.operation_fence_digest);
    bytes.extend_from_slice(
        &attempt
            .expected_proof
            .encode()
            .map_err(|_| StorageStateError::InvalidValue)?,
    );
    bytes.extend_from_slice(&attempt.root_device.to_be_bytes());
    bytes.extend_from_slice(&attempt.root_inode.to_be_bytes());
    bytes.extend_from_slice(&attempt.kernel_boot);
    bytes.extend_from_slice(&attempt.effect_deadline_boottime_nanoseconds.to_be_bytes());
    bytes.push(attempt.phase.code());
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(DOMAIN);
    mac.update(&attempt.effect_operation);
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    if bytes.len() != RECORD_BYTES {
        return Err(StorageStateError::CorruptRecord);
    }
    Ok(bytes)
}

pub(crate) fn decode_attempt(
    bytes: &[u8],
    effect_operation: [u8; 16],
    key_id: [u8; 16],
    secret: &[u8; 32],
) -> Result<GuestRootPublicationAttemptV1, StorageStateError> {
    if bytes.len() != RECORD_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..26] != key_id
        || bytes[26..42] != effect_operation
    {
        return Err(StorageStateError::CorruptRecord);
    }
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| StorageStateError::InvalidValue)?;
    mac.update(DOMAIN);
    mac.update(&effect_operation);
    mac.update(&bytes[..BODY_BYTES]);
    mac.verify_slice(&bytes[BODY_BYTES..])
        .map_err(|_| StorageStateError::CorruptRecord)?;

    let proof = GuestRootPublicationProofV1::decode(&bytes[122..388])
        .map_err(|_| StorageStateError::CorruptRecord)?;
    let attempt = GuestRootPublicationAttemptV1 {
        effect_operation,
        request_id: field(bytes, 42),
        sealed_effect_digest: field(bytes, 58),
        operation_fence_digest: field(bytes, 90),
        expected_proof: proof,
        root_device: u64::from_be_bytes(field(bytes, 388)),
        root_inode: u64::from_be_bytes(field(bytes, 396)),
        kernel_boot: field(bytes, 404),
        effect_deadline_boottime_nanoseconds: u64::from_be_bytes(field(bytes, 420)),
        phase: GuestRootAttemptPhaseV1::from_code(bytes[428])
            .ok_or(StorageStateError::CorruptRecord)?,
    };
    attempt
        .validate()
        .map_err(|_| StorageStateError::CorruptRecord)?;
    Ok(attempt)
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> GuestRootPublicationAttemptV1 {
        GuestRootPublicationAttemptV1 {
            effect_operation: [1; 16],
            request_id: [2; 16],
            sealed_effect_digest: [3; 32],
            operation_fence_digest: [4; 32],
            expected_proof: GuestRootPublicationProofV1 {
                sandbox: [5; 16],
                incarnation: [6; 16],
                assignment_epoch: 7,
                assignment_digest: [8; 32],
                creation_operation: [9; 16],
                workspace_handle: [10; 32],
                dataset_guid: 11,
                root_image_digest: [12; 32],
                package_binding: [13; 32],
                root_tree_digest: [14; 32],
                feature_mask: 0x003f,
            },
            root_device: 15,
            root_inode: 16,
            kernel_boot: [17; 16],
            effect_deadline_boottime_nanoseconds: 18,
            phase: GuestRootAttemptPhaseV1::Ambiguous,
        }
    }

    #[test]
    fn attempt_round_trips_and_rejects_substitution() {
        let original = attempt();
        let mut bytes = encode_attempt(original, [19; 16], &[20; 32]).unwrap();
        assert_eq!(
            decode_attempt(&bytes, original.effect_operation, [19; 16], &[20; 32]).unwrap(),
            original
        );
        assert!(decode_attempt(&bytes, [21; 16], [19; 16], &[20; 32]).is_err());
        bytes[130] ^= 1;
        assert!(decode_attempt(&bytes, original.effect_operation, [19; 16], &[20; 32]).is_err());
    }

    #[test]
    fn completion_is_monotone() {
        let complete = attempt().complete().unwrap();
        assert_eq!(complete.phase, GuestRootAttemptPhaseV1::Complete);
        assert!(complete.complete().is_err());
    }
}
