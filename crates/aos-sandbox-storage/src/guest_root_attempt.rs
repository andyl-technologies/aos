//! Authenticated durable claim for one distinct guest-root population effect.
//!
//! The Storage transaction journal writes the ambiguous form before a worker
//! can copy a byte. Recovery may read back an exact marker, but never infer a
//! fresh mutation grant from this record. A new effect needs a new signed
//! method-31 admission under the current lease.
//!
//! ```text
//! AOSGRA02 | version:u16=2 | key-id[16] | effect-operation[16]
//!          | request-id[16] | sealed-effect-digest[32]
//!          | operation-fence-digest[32] | expected-AOSGRP01[266]
//!          | root-device:u64be | root-inode:u64be | kernel-boot[16]
//!          | effect-deadline-boottime:u64be | phase:u8 | creation-AOSSGR01[152] | AOSGRC02[304] | hmac-sha256[32]
//! ```

use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use hmac::{Hmac, Mac as _};
use aos_sandbox_protocol::semantics::storage_guest_root::{CanonicalStorageGuestRootArgumentsV1, StorageGuestRootCurrentPublicationDataV2};
use sha2::Sha256;

use crate::StorageStateError;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"AOSGRA02";
const VERSION: u16 = 2;
const DOMAIN: &[u8] = b"aos.sandbox.storage.guest-root-attempt.v2\0";
const BODY_BYTES: usize = 885;
const RECORD_BYTES: usize = BODY_BYTES + 32;
pub(crate) const GUEST_ROOT_ATTEMPT_RECORD_BYTES: usize = RECORD_BYTES;

/// Marks whether a publication claim is still ambiguous or physically read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuestRootAttemptPhaseV2 {
    /// A worker may have mutated the root; recovery is observation-only.
    Ambiguous,
    /// The exact marker and complete package tree were physically read back.
    Complete,
}

impl GuestRootAttemptPhaseV2 {
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
pub(crate) struct GuestRootPublicationAttemptV2 {
    pub(crate) effect_operation: [u8; 16],
    pub(crate) request_id: [u8; 16],
    pub(crate) sealed_effect_digest: [u8; 32],
    pub(crate) operation_fence_digest: [u8; 32],
    pub(crate) expected_proof: GuestRootPublicationProofV1,
    pub(crate) root_device: u64,
    pub(crate) root_inode: u64,
    pub(crate) kernel_boot: [u8; 16],
    pub(crate) effect_deadline_boottime_nanoseconds: u64,
    pub(crate) phase: GuestRootAttemptPhaseV2,
    pub(crate) creation_arguments: CanonicalStorageGuestRootArgumentsV1,
    pub(crate) current_publication: StorageGuestRootCurrentPublicationDataV2,
}

impl GuestRootPublicationAttemptV2 {
    /// Authenticates this attempt's exact current method31 authority records.
    ///
    /// This is the shared passive relation used by the live worker and the
    /// protected completed-state projection. It grants no new effect or time
    /// interval; each caller retains its own actual phase/native/clock gates.
    pub(crate) fn require_authority_v2(
        &self,
        authority: &crate::authorization::StorageAuthorityV1,
        sealed_effect: &[u8],
        sealed_operation_fence: &[u8],
    ) -> Result<aos_sandbox_broker::BrokerEffectIntentV1, crate::StorageAdmissionError> {
        use aos_sandbox_broker::BrokerEffectStatusV1;
        use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb};
        use sha2::Digest as _;

        self.validate().map_err(|_| crate::StorageAdmissionError::VerificationFailed)?;
        let effect = authority.open_admission_intent(&self.request_id, sealed_effect)?;
        let fence = authority.open_operation_fence(&self.effect_operation, sealed_operation_fence)?;
        let assignment = self.current_publication.current_assignment_v2()
            .map_err(|_| crate::StorageAdmissionError::VerificationFailed)?;
        let arguments = self.current_publication.arguments_v2();
        if fence.assignment() != assignment
            || effect.status() != BrokerEffectStatusV1::Pending
            || effect.request_id() != &self.request_id
            || effect.verb() != BrokerVerb::StoragePopulateGuestRoot
            || effect.target() != BrokerGrantTarget::Assignment
            || effect.request_digest() != arguments.argument_commitment().digest()
            || effect.plan_digest() != fence.plan_digest()
            || effect.lease_digest() != fence.local_lease_record().lease_digest()
            || self.current_publication.ownership_lease_digest_v2() != effect.lease_digest().as_bytes()
            || effect.effect_deadline_boottime_nanoseconds() != self.effect_deadline_boottime_nanoseconds
            || effect.host_boot_id() != &self.kernel_boot
            || Sha256::digest(sealed_effect).as_slice() != self.sealed_effect_digest
            || Sha256::digest(sealed_operation_fence).as_slice() != self.operation_fence_digest
        {
            return Err(crate::StorageAdmissionError::VerificationFailed);
        }
        authority.check_current_fence(&fence)?;
        Ok(effect)
    }

    /// Allows only a new effect to repair an expired, unmarked partial copy.
    pub(crate) fn permits_fresh_retry(self, next: Self, current_boottime_nanoseconds: u64) -> bool {
        self.phase == GuestRootAttemptPhaseV2::Ambiguous
            && self.effect_operation != next.effect_operation
            && self.expected_proof == next.expected_proof
            && self.root_device == next.root_device
            && self.root_inode == next.root_inode
            && (self.kernel_boot != next.kernel_boot
                || self.effect_deadline_boottime_nanoseconds <= current_boottime_nanoseconds)
    }

    /// Allows a new current assignment after an independently completed effect.
    ///
    /// An unchanged generation cannot be granted another current binding by a
    /// different operation. Incomplete attempts retain the separate original
    /// stale-repair rule, including its independently required quiescence.
    pub(crate) fn permits_current_successor_v2(self, next: Self) -> bool {
        if self.phase != GuestRootAttemptPhaseV2::Complete
            || self.effect_operation == next.effect_operation
            || self.expected_proof != next.expected_proof
            || self.root_device != next.root_device || self.root_inode != next.root_inode
        { return false; }
        match (self.current_publication.current_assignment_v2(), next.current_publication.current_assignment_v2()) {
            (Ok(prior), Ok(current)) => prior.sandbox() == current.sandbox()
                && prior.incarnation() == current.incarnation() && prior.epoch() == current.epoch()
                && prior.desired_generation() < current.desired_generation(),
            _ => false,
        }
    }

    pub(crate) fn validate(self) -> Result<(), StorageStateError> {
        let creation = self.creation_arguments.assignment_data_v1()
            .map_err(|_| StorageStateError::InvalidValue)?;
        self.current_publication.require_creation_data_v2(creation, self.expected_proof,
            self.current_publication.creation_resource_digest_v2())
            .map_err(|_| StorageStateError::InvalidValue)?;
        if self.effect_operation == [0; 16]
            || self.effect_operation == self.expected_proof.creation_operation
            || self.request_id == [0; 16]
            || self.sealed_effect_digest == [0; 32]
            || self.operation_fence_digest == [0; 32]
            || self.expected_proof.encode().is_err()
            || self.creation_arguments.canonical_bytes()[88..]
                != self.current_publication.arguments_v2().canonical_bytes()[88..]
            || self.current_publication.arguments_v2().canonical_bytes()[88..104] != self.effect_operation
            || self.current_publication.request_id_v2() != &self.request_id
            || self.current_publication.sealed_effect_digest_v2() != &self.sealed_effect_digest
            || self.current_publication.operation_fence_digest_v2() != &self.operation_fence_digest
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
        if self.phase != GuestRootAttemptPhaseV2::Ambiguous {
            return Err(StorageStateError::InvalidTransition);
        }
        self.phase = GuestRootAttemptPhaseV2::Complete;
        Ok(self)
    }
}

pub(crate) fn encode_attempt(
    attempt: GuestRootPublicationAttemptV2,
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
    bytes.extend_from_slice(attempt.creation_arguments.canonical_bytes());
    bytes.extend_from_slice(&attempt.current_publication.encode_v2());
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
) -> Result<GuestRootPublicationAttemptV2, StorageStateError> {
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
    let attempt = GuestRootPublicationAttemptV2 {
        effect_operation,
        request_id: field(bytes, 42),
        sealed_effect_digest: field(bytes, 58),
        operation_fence_digest: field(bytes, 90),
        expected_proof: proof,
        root_device: u64::from_be_bytes(field(bytes, 388)),
        root_inode: u64::from_be_bytes(field(bytes, 396)),
        kernel_boot: field(bytes, 404),
        effect_deadline_boottime_nanoseconds: u64::from_be_bytes(field(bytes, 420)),
        phase: GuestRootAttemptPhaseV2::from_code(bytes[428])
            .ok_or(StorageStateError::CorruptRecord)?,
        creation_arguments: CanonicalStorageGuestRootArgumentsV1::decode_data_v1(&bytes[429..581])
            .map_err(|_| StorageStateError::CorruptRecord)?,
        current_publication: StorageGuestRootCurrentPublicationDataV2::decode_v2(&bytes[581..885])
            .map_err(|_| StorageStateError::CorruptRecord)?,
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

    fn attempt() -> GuestRootPublicationAttemptV2 {
        let creation = aos_sandbox_core::BrokerAssignment::new(
            aos_sandbox_core::SandboxId::from_bytes([5; 16]),
            aos_sandbox_core::IncarnationId::from_bytes([6; 16]),
            aos_sandbox_core::AssignmentEpoch::new(7), aos_sandbox_core::DesiredGeneration::new(1),
            aos_sandbox_core::ObjectDigest::from_bytes([8; 32])).unwrap();
        let creation_arguments = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
            creation, [1; 16], [10; 32], [9; 16]).unwrap();
        let current_publication = StorageGuestRootCurrentPublicationDataV2::from_data_v2(
            creation_arguments, [19; 32], [3; 32], [4; 32], [20; 32], [2; 16]).unwrap();
        GuestRootPublicationAttemptV2 {
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
            phase: GuestRootAttemptPhaseV2::Ambiguous,
            creation_arguments, current_publication,
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
    fn retry_requires_stale_ambiguous_same_root_and_new_effect() {
        let prior = attempt();
        let mut next = prior;
        next.effect_operation = [21; 16];
        next.request_id = [22; 16];
        next.effect_deadline_boottime_nanoseconds = 40;
        assert!(!prior.permits_fresh_retry(next, 17));
        assert!(prior.permits_fresh_retry(next, 18));

        let mut moved = next;
        moved.root_inode += 1;
        assert!(!prior.permits_fresh_retry(moved, 18));
        let mut repinned = next;
        repinned.expected_proof.package_binding = [23; 32];
        assert!(!prior.permits_fresh_retry(repinned, 18));
        assert!(!prior.permits_fresh_retry(prior, 18));

        let complete = prior.complete().unwrap();
        assert!(!complete.permits_fresh_retry(next, 18));
    }

    #[test]
    fn current_successor_preserves_creation_and_requires_completed_predecessor() {
        let prior = attempt();
        let current = aos_sandbox_core::BrokerAssignment::new(
            aos_sandbox_core::SandboxId::from_bytes(prior.expected_proof.sandbox),
            aos_sandbox_core::IncarnationId::from_bytes(prior.expected_proof.incarnation),
            aos_sandbox_core::AssignmentEpoch::new(prior.expected_proof.assignment_epoch),
            aos_sandbox_core::DesiredGeneration::new(2),
            aos_sandbox_core::ObjectDigest::from_bytes([31; 32]),
        ).unwrap();
        let creation = prior.creation_arguments.assignment_data_v1().unwrap();
        let mut next = prior;
        next.effect_operation = [32; 16];
        next.request_id = [33; 16];
        next.creation_arguments = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
            creation, next.effect_operation, prior.expected_proof.workspace_handle,
            prior.expected_proof.creation_operation,
        ).unwrap();
        let arguments = CanonicalStorageGuestRootArgumentsV1::from_protected_assignment(
            current, next.effect_operation, prior.expected_proof.workspace_handle,
            prior.expected_proof.creation_operation,
        ).unwrap();
        next.current_publication = StorageGuestRootCurrentPublicationDataV2::from_data_v2(
            arguments, *prior.current_publication.creation_resource_digest_v2(),
            next.sealed_effect_digest, next.operation_fence_digest,
            *prior.current_publication.ownership_lease_digest_v2(), next.request_id,
        ).unwrap();
        next.validate().unwrap();

        assert!(!prior.permits_current_successor_v2(next));
        assert!(prior.complete().unwrap().permits_current_successor_v2(next));
        assert_eq!(next.expected_proof, prior.expected_proof);
        let bytes = encode_attempt(next, [19; 16], &[20; 32]).unwrap();
        assert_eq!(decode_attempt(&bytes, next.effect_operation, [19; 16], &[20; 32]).unwrap(), next);

        let mut replaced = next;
        replaced.root_inode += 1;
        assert!(!prior.complete().unwrap().permits_current_successor_v2(replaced));
        let mut old_format = bytes;
        old_format[..8].copy_from_slice(b"AOSGRA01");
        assert!(decode_attempt(&old_format, next.effect_operation, [19; 16], &[20; 32]).is_err());
    }

    #[test]
    fn completion_is_monotone() {
        let complete = attempt().complete().unwrap();
        assert_eq!(complete.phase, GuestRootAttemptPhaseV2::Complete);
        assert!(complete.complete().is_err());
    }
}
