//! Controller-signed readback of a durable, held no-Apply effect acknowledgment.
//!
//! ```text
//! AOSCTE01 | version:u16 | reserved[6]=0 | signer-generation:u64 |
//! Root-nonce[16] | Root-cut[32] | Controller-UID:u32 |
//! journal-sequence:u64 | operation[16] | sandbox[16] | source[32] |
//! binding[32] | epoch:u64 | accepted-generation:u64 |
//! effect-transaction[16] | Root-proof-digest[32] |
//! Controller-ACK-record-digest[32] | Ed25519 signature[64]
//! ```
//!
//! The packet attests the Controller journal only while its writer is held.
//! Root must verify the separate Controller-purpose pin and its own proposal
//! and proof under the Root-last writer before recording an ACK.

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::controller_service::journal::production_journal_limits;
use crate::journal::{
    ControllerPolicyEffectAckV1, ControllerPolicyHoldV1, Journal, JournalError, RecordNamespace,
};

use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::public_create_source::current_parentless_create_project_source_v1;

const MAGIC: &[u8; 8] = b"AOSCTE01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.controller-policy-effect-ack.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0";
const BODY_BYTES: usize = 276;

/// Bounds one exact Controller effect-acknowledgment receipt.
pub const CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Names a fresh Root writer session and its expected effect cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerEffectAckChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
}

impl ControllerEffectAckChallengeV1 {
    /// Constructs a nonzero Root challenge.
    ///
    /// # Errors
    ///
    /// Rejects an empty nonce or cut.
    pub fn new(
        nonce: [u8; 16],
        cut: ObjectDigest,
    ) -> Result<Self, ControllerEffectAckReadbackErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(ControllerEffectAckReadbackErrorV1::Stale);
        }
        Ok(Self { nonce, cut })
    }

    /// Returns the Root-generated nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the Root-owned cut commitment.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }
}

/// Retains the exact signed Controller ACK and its journal sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedControllerEffectAckV1 {
    ack: ControllerPolicyEffectAckV1,
    controller_uid: u32,
    journal_sequence: u64,
}

impl VerifiedControllerEffectAckV1 {
    /// Returns the Controller's durable no-Apply acknowledgment.
    #[must_use]
    pub const fn ack(self) -> ControllerPolicyEffectAckV1 {
        self.ack
    }

    /// Returns the protected Controller owner UID.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.controller_uid
    }

    /// Returns the diagnostic Controller journal sequence.
    #[must_use]
    pub const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }
}

/// Rejects an invalid or stale Controller effect-ACK receipt.
#[derive(Debug, thiserror::Error)]
pub enum ControllerEffectAckReadbackErrorV1 {
    /// The receipt, challenge, generation, or Controller state is stale.
    #[error("stale Controller effect acknowledgment")]
    Stale,
    /// The packet signature is invalid for the pinned Controller key.
    #[error("invalid Controller effect acknowledgment signature")]
    Signature,
    /// Protected Controller custody failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Signs the exact acknowledged Controller record under its retained writer.
///
/// The signing key must be the deployment-pinned Controller-purpose key. This
/// function does not accept caller-supplied ACK fields and grants no Apply.
///
/// # Errors
///
/// Rejects non-current Create, missing held ACK, unsafe journal location,
/// changed sequence, or invalid signer generation.
pub fn sign_fixed_controller_effect_ack_readback_v1(
    journal: &mut Journal,
    challenge: ControllerEffectAckChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    let uid = rustix::process::getuid().as_raw();
    sign_controller_effect_ack_at(
        journal,
        Path::new("/var/lib/aos/sandboxd"),
        uid,
        challenge,
        signer_generation,
        signing_key,
    )
}

fn sign_controller_effect_ack_at(
    journal: &mut Journal,
    directory: &Path,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    if uid == 0 || signer_generation == 0 {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    let ack = journal
        .controller_policy_effect_ack_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    if journal.controller_policy_hold_v1()? != Some(ack.hold()) {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let source = current_parentless_create_project_source_v1(
        journal,
        ack.hold().operation(),
        ack.hold().sandbox(),
    )
    .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?;
    if source.commitment() != ack.hold().source()
        || source.accepted_generation() != ack.accepted_generation()
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let bytes = sign_fields(
        ack,
        uid,
        snapshot.sequence(),
        challenge,
        signer_generation,
        signing_key,
    )?;

    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .validate_snapshot_for_effect(&snapshot)?;
    if journal.controller_policy_effect_ack_v1()? != Some(ack)
        || journal.controller_policy_hold_v1()? != Some(ack.hold())
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let source = current_parentless_create_project_source_v1(
        journal,
        ack.hold().operation(),
        ack.hold().sandbox(),
    )
    .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?;
    if source.commitment() != ack.hold().source()
        || source.accepted_generation() != ack.accepted_generation()
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    Ok(bytes)
}

/// Verifies a Controller-purpose signed ACK for one fresh Root challenge.
///
/// The caller must load `signer` from protected Root custody and compare the
/// returned ACK with Root's exact binding and proof before committing anything.
///
/// # Errors
///
/// Rejects malformed fields, substituted challenge/UID/generation, a false
/// Controller record digest, or an invalid signature.
pub fn verify_controller_effect_ack_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerEffectAckChallengeV1,
    expected_uid: u32,
) -> Result<VerifiedControllerEffectAckV1, ControllerEffectAckReadbackErrorV1> {
    if bytes.len() != CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1
        || bytes[..8] != MAGIC[..]
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[16..24] != signer.generation().to_be_bytes()
        || bytes[24..40] != challenge.nonce
        || bytes[40..72] != *challenge.cut.as_bytes()
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let uid = u32::from_be_bytes(take::<4>(bytes, 72)?);
    let sequence = u64::from_be_bytes(take::<8>(bytes, 76)?);
    let hold = ControllerPolicyHoldV1::new(
        OperationId::from_bytes(take(bytes, 84)?),
        SandboxId::from_bytes(take(bytes, 100)?),
        ObjectDigest::from_bytes(take(bytes, 116)?),
        ObjectDigest::from_bytes(take(bytes, 148)?),
        u64::from_be_bytes(take(bytes, 180)?),
    )?;
    let ack = ControllerPolicyEffectAckV1::new(
        hold,
        u64::from_be_bytes(take(bytes, 188)?),
        take(bytes, 196)?,
        ObjectDigest::from_bytes(take(bytes, 212)?),
    )?;
    if uid == 0
        || uid != expected_uid
        || sequence == 0
        || ack.record_digest()?.as_bytes() != &take::<32>(bytes, 244)?
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take(bytes, BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(&signature_preimage(&bytes[..BODY_BYTES]), &signature)
        .map_err(|_| ControllerEffectAckReadbackErrorV1::Signature)?;
    Ok(VerifiedControllerEffectAckV1 {
        ack,
        controller_uid: uid,
        journal_sequence: sequence,
    })
}

fn sign_fields(
    ack: ControllerPolicyEffectAckV1,
    uid: u32,
    sequence: u64,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    if uid == 0 || sequence == 0 || generation == 0 {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let hold = ack.hold();
    let mut bytes = [0; CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&challenge.nonce);
    bytes[40..72].copy_from_slice(challenge.cut.as_bytes());
    bytes[72..76].copy_from_slice(&uid.to_be_bytes());
    bytes[76..84].copy_from_slice(&sequence.to_be_bytes());
    bytes[84..100].copy_from_slice(hold.operation().as_bytes());
    bytes[100..116].copy_from_slice(hold.sandbox().as_bytes());
    bytes[116..148].copy_from_slice(hold.source().as_bytes());
    bytes[148..180].copy_from_slice(hold.binding().as_bytes());
    bytes[180..188].copy_from_slice(&hold.epoch().to_be_bytes());
    bytes[188..196].copy_from_slice(&ack.accepted_generation().to_be_bytes());
    bytes[196..212].copy_from_slice(&ack.effect_transaction());
    bytes[212..244].copy_from_slice(ack.root_proof().as_bytes());
    bytes[244..276].copy_from_slice(ack.record_digest()?.as_bytes());
    let signature = key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn sign_test_controller_effect_ack_readback_v1(
    ack: ControllerPolicyEffectAckV1,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    sign_fields(ack, uid, 7, challenge, generation, key)
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    [SIGNATURE_DOMAIN, body].concat()
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ControllerEffectAckReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_compiler::controller_hold_readback::encode_controller_hold_signer_credential_v1;
    use ed25519_dalek::SigningKey;

    #[test]
    fn signed_ack_is_exact_and_role_pinned() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let credential =
            encode_controller_hold_signer_credential_v1(3, &key.verifying_key()).unwrap();
        let signer = PinnedControllerHoldSignerV1::decode(&credential).unwrap();
        let hold = ControllerPolicyHoldV1::new(
            OperationId::from_bytes([2; 16]),
            SandboxId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
        )
        .unwrap();
        let ack =
            ControllerPolicyEffectAckV1::new(hold, 7, [8; 16], ObjectDigest::from_bytes([9; 32]))
                .unwrap();
        let challenge =
            ControllerEffectAckChallengeV1::new([10; 16], ObjectDigest::from_bytes([11; 32]))
                .unwrap();
        let packet = sign_fields(ack, 12, 13, challenge, 3, &key).unwrap();
        assert_eq!(
            verify_controller_effect_ack_readback_v1(&packet, &signer, challenge, 12)
                .unwrap()
                .ack(),
            ack
        );

        for offset in [16, 24, 40, 72, 76, 84, 148, 180, 188, 196, 212, 244, 276] {
            let mut altered = packet;
            altered[offset] ^= 1;
            assert!(
                verify_controller_effect_ack_readback_v1(&altered, &signer, challenge, 12).is_err()
            );
        }
        let rotated = encode_controller_hold_signer_credential_v1(4, &key.verifying_key()).unwrap();
        assert!(
            verify_controller_effect_ack_readback_v1(
                &packet,
                &PinnedControllerHoldSignerV1::decode(&rotated).unwrap(),
                challenge,
                12
            )
            .is_err()
        );
    }
}
