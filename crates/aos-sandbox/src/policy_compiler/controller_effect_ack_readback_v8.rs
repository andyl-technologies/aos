//! Controller-only signed readback of the protected V8 no-Apply ACK.
//!
//! ```text
//! AOSCTE08 | version:u16=1 | reserved[6]=0 | signer-generation:u64 |
//! Root-nonce[16] | Root-cut[32] | Controller-UID:u32 |
//! journal-sequence:u64 | canonical AOSQ8K01[320] | Ed25519[64]
//! ```
//!
//! The distinct packet domain prevents a V1 qualified-held ACK from being
//! mistaken for a V8 held-CAS receipt. This packet never grants release.

use std::path::Path;

use ed25519_dalek::SigningKey;

use crate::controller_service::journal::production_journal_limits;
use crate::journal::{ControllerPolicyV8EffectAckV1, Journal, RecordNamespace};

use super::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::controller_v8_readback_envelope::{
    ControllerV8ReadbackProtocol, HEADER_BYTES, SIGNATURE_BYTES, sign_packet, verify_packet,
};
use super::public_create_source::current_parentless_create_project_source_v1;

const BODY_BYTES: usize = HEADER_BYTES + 320;
/// Bounds one exact signed V8 Controller ACK packet.
pub const CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1: usize = BODY_BYTES + SIGNATURE_BYTES;

/// Signs the exact held V8 ACK from the protected Controller journal.
///
/// # Errors
///
/// Rejects a stale Create, changed journal, unsafe named location, or invalid
/// signer generation.
pub fn sign_fixed_controller_v8_effect_ack_readback_v1(
    journal: &mut Journal,
    challenge: ControllerEffectAckChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    sign_at(
        journal,
        Path::new("/var/lib/aos/sandboxd"),
        rustix::process::getuid().as_raw(),
        challenge,
        signer_generation,
        signing_key,
    )
}

fn sign_at(
    journal: &mut Journal,
    directory: &Path,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    if uid == 0 || generation == 0 {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    let ack = journal
        .controller_policy_v8_effect_ack_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    require_current_ack(journal, ack)?;
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let packet = sign_fields(ack, uid, snapshot.sequence(), challenge, generation, key)?;

    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .validate_snapshot_for_effect(&snapshot)?;
    require_current_ack(journal, ack)?;
    Ok(packet)
}

pub(super) fn require_current_ack(
    journal: &mut Journal,
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<(), ControllerEffectAckReadbackErrorV1> {
    let hold = ack.attempt().hold();
    if journal.controller_policy_v8_effect_ack_v1()? != Some(ack)
        || journal.controller_policy_v8_attempt_v1()? != Some(ack.attempt())
        || journal.controller_policy_hold_v1()? != Some(hold)
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let source =
        current_parentless_create_project_source_v1(journal, hold.operation(), hold.sandbox())
            .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?;
    if source.commitment() != hold.source()
        || source.accepted_generation() != ack.accepted_generation()
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    Ok(())
}

/// Verifies a V8 Controller-purpose receipt for one Root challenge.
///
/// The caller must additionally compare the decoded ACK to Root's exact
/// held-CAS proposal and consumed AOSPCP02 under its protected writer.
///
/// # Errors
///
/// Rejects a foreign signer, stale nonce/cut/UID, malformed ACK, or signature.
pub fn verify_controller_v8_effect_ack_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerEffectAckChallengeV1,
    expected_uid: u32,
) -> Result<ControllerPolicyV8EffectAckV1, ControllerEffectAckReadbackErrorV1> {
    let record = verify_packet(
        ControllerV8ReadbackProtocol::EffectAck,
        bytes,
        signer,
        challenge,
        expected_uid,
    )?;
    Ok(ControllerPolicyV8EffectAckV1::from_record_bytes(record)?)
}

fn sign_fields(
    ack: ControllerPolicyV8EffectAckV1,
    uid: u32,
    sequence: u64,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    sign_packet(
        ControllerV8ReadbackProtocol::EffectAck,
        &ack.record_bytes()?,
        uid,
        sequence,
        challenge,
        generation,
        key,
    )
}

#[cfg(test)]
pub(crate) fn sign_test_controller_v8_effect_ack_readback_v1(
    ack: ControllerPolicyV8EffectAckV1,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_EFFECT_ACK_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    sign_fields(ack, uid, 7, challenge, generation, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{ControllerPolicyHoldV1, ControllerPolicyV8AttemptV1};
    use crate::policy_compiler::controller_hold_readback::encode_controller_hold_signer_credential_v1;
    use aos_sandbox_core::ObjectDigest;
    use aos_sandbox_core::{OperationId, SandboxId};

    #[test]
    fn v8_signed_ack_rejects_v1_domain_and_substitution() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let pin = encode_controller_hold_signer_credential_v1(3, &key.verifying_key()).unwrap();
        let signer = PinnedControllerHoldSignerV1::decode(&pin).unwrap();
        let hold = ControllerPolicyHoldV1::new(
            OperationId::from_bytes([2; 16]),
            SandboxId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            6,
        )
        .unwrap();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([7; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            8,
            [9; 16],
            ObjectDigest::from_bytes([10; 32]),
            ObjectDigest::from_bytes([11; 32]),
        )
        .unwrap();
        let challenge =
            ControllerEffectAckChallengeV1::new([12; 16], ObjectDigest::from_bytes([13; 32]))
                .unwrap();
        let packet = sign_fields(ack, 14, 15, challenge, 3, &key).unwrap();
        assert_eq!(
            verify_controller_v8_effect_ack_readback_v1(&packet, &signer, challenge, 14).unwrap(),
            ack
        );
        for offset in [0, 16, 24, 40, 72, 76, 84, 100, 200, 300, BODY_BYTES] {
            let mut changed = packet;
            changed[offset] ^= 1;
            assert!(
                verify_controller_v8_effect_ack_readback_v1(&changed, &signer, challenge, 14)
                    .is_err()
            );
        }
        let rotated = encode_controller_hold_signer_credential_v1(4, &key.verifying_key()).unwrap();
        assert!(
            verify_controller_v8_effect_ack_readback_v1(
                &packet,
                &PinnedControllerHoldSignerV1::decode(&rotated).unwrap(),
                challenge,
                14,
            )
            .is_err()
        );
    }
}
