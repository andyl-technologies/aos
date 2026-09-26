//! Nonauthorizing Source signature over one held head and fixed physical names.
//!
//! ```text
//! AOSSRB02 | version:u16=2 | reserved[6]=0 | signer-generation:u64 |
//! nonce[16] | root-cut[32] | project[16] | operation[16] | sandbox[16] |
//! controller-source[32] | ancestry[32] | binding[32] | epoch:u64 |
//! directory(device:u64,inode:u64) | journal(device:u64,inode:u64) |
//! lock(device:u64,inode:u64) | Ed25519 signature[64]
//! ```
//!
//! Physical-name equality is necessary but insufficient: Root must still
//! prove that Controller retained the matching Source writer from the fresh
//! challenge through its CAS and final postflight.

use aos_sandbox_core::ProjectId;
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::journal::{ProtectedJournalNamesV1, SourceDomainPolicyHoldV1};

use super::source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1,
    source_hold_body_v1,
};

const MAGIC: &[u8; 8] = b"AOSSRB02";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-hold-readback.signature.v2\0";
const BODY_BYTES: usize = 272;

/// Bounds one Source-signed held head and physical-name witness.
pub const SOURCE_HOLD_READBACK_BYTES_V2: usize = BODY_BYTES + 64;

/// Signs the existing Source hold fields plus the independently observed names.
pub(crate) fn sign_source_hold_readback_with_names_v2(
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    hold: SourceDomainPolicyHoldV1,
    names: ProtectedJournalNamesV1,
    generation: u64,
    signing_key: &SigningKey,
) -> [u8; SOURCE_HOLD_READBACK_BYTES_V2] {
    let mut packet = [0; SOURCE_HOLD_READBACK_BYTES_V2];
    packet[..224].copy_from_slice(&source_hold_body_v1(challenge, project, hold, generation));
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&2_u16.to_be_bytes());
    packet[224..272].copy_from_slice(&names.to_bytes());
    let signature = signing_key.sign(&signature_preimage(&packet[..BODY_BYTES]));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    packet
}

/// Verifies the exact Source-signed hold and named inode pair under a pinned key.
///
/// This is a read-only witness, not proof of a retained Controller writer or
/// permission to submit, release an owner, or start a public Create effect.
///
/// # Errors
///
/// Rejects altered framing, signer generation, challenge, hold, physical
/// names, or signature.
pub fn verify_source_hold_readback_with_names_v2(
    packet: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected_hold: SourceDomainPolicyHoldV1,
    expected_names: ProtectedJournalNamesV1,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if packet.len() != SOURCE_HOLD_READBACK_BYTES_V2
        || !expected_hold.is_held()
        || project.as_bytes() == &[0; 16]
        || packet.get(..8) != Some(MAGIC)
        || take::<2>(packet, 8)? != 2_u16.to_be_bytes()
        || take::<6>(packet, 10)? != [0; 6]
        || take::<8>(packet, 16)? != signer.generation().to_be_bytes()
        || take::<16>(packet, 24)? != challenge.nonce()
        || take::<32>(packet, 40)? != *challenge.cut().as_bytes()
        || take::<16>(packet, 72)? != *project.as_bytes()
        || take::<16>(packet, 88)? != *expected_hold.operation().as_bytes()
        || take::<16>(packet, 104)? != *expected_hold.sandbox().as_bytes()
        || take::<32>(packet, 120)? != *expected_hold.controller_source().as_bytes()
        || take::<32>(packet, 152)? != *expected_hold.ancestry().as_bytes()
        || take::<32>(packet, 184)? != *expected_hold.binding().as_bytes()
        || take::<8>(packet, 216)? != expected_hold.epoch().to_be_bytes()
        || take::<48>(packet, 224)? != expected_names.to_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(packet, BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(&signature_preimage(&packet[..BODY_BYTES]), &signature)
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceHoldReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(SourceHoldReadbackErrorV1::NonCanonical)
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};

    use super::*;
    use crate::policy_compiler::source_hold_readback::{
        encode_source_hold_readback_signer_credential_v1, verify_current_source_hold_readback_v1,
    };

    #[test]
    fn signed_names_reject_substituted_journal_lock_and_challenge() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let pin =
            encode_source_hold_readback_signer_credential_v1(3, &key.verifying_key()).unwrap();
        let signer = PinnedSourceHoldReadbackSignerV1::decode(&pin).unwrap();
        let challenge =
            SourceHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32])).unwrap();
        let project = ProjectId::from_bytes([10; 16]);
        let hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes([11; 16]),
            SandboxId::from_bytes([12; 16]),
            ObjectDigest::from_bytes([13; 32]),
            ObjectDigest::from_bytes([14; 32]),
            ObjectDigest::from_bytes([15; 32]),
            16,
        )
        .unwrap();
        let mut encoded_names = [0; 48];
        for (index, chunk) in encoded_names.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&(index as u64 + 1).to_be_bytes());
        }
        assert!(ProtectedJournalNamesV1::from_bytes(&[0; 48]).is_err());
        assert!(ProtectedJournalNamesV1::from_bytes(&encoded_names[..47]).is_err());
        let names = ProtectedJournalNamesV1::from_bytes(&encoded_names).unwrap();
        let packet =
            sign_source_hold_readback_with_names_v2(challenge, project, hold, names, 3, &key);
        assert!(
            verify_source_hold_readback_with_names_v2(
                &packet, &signer, challenge, project, hold, names,
            )
            .is_ok()
        );
        assert!(
            verify_current_source_hold_readback_v1(&packet, &signer, challenge, project, hold)
                .is_err()
        );
        let foreign = SigningKey::from_bytes(&[18; 32]);
        let foreign_pin =
            encode_source_hold_readback_signer_credential_v1(3, &foreign.verifying_key()).unwrap();
        let foreign_signer = PinnedSourceHoldReadbackSignerV1::decode(&foreign_pin).unwrap();
        assert!(
            verify_source_hold_readback_with_names_v2(
                &packet,
                &foreign_signer,
                challenge,
                project,
                hold,
                names,
            )
            .is_err()
        );

        for field in [224, 240, 256] {
            let mut altered = packet;
            altered[field + 7] ^= 1;
            assert!(
                verify_source_hold_readback_with_names_v2(
                    &altered, &signer, challenge, project, hold, names,
                )
                .is_err()
            );
        }
        let mut changed_names = encoded_names;
        changed_names[47] ^= 1;
        assert!(
            verify_source_hold_readback_with_names_v2(
                &packet,
                &signer,
                challenge,
                project,
                hold,
                ProtectedJournalNamesV1::from_bytes(&changed_names).unwrap(),
            )
            .is_err()
        );
        let wrong_challenge =
            SourceHoldReadbackChallengeV1::new([17; 16], challenge.cut()).unwrap();
        assert!(
            verify_source_hold_readback_with_names_v2(
                &packet,
                &signer,
                wrong_challenge,
                project,
                hold,
                names,
            )
            .is_err()
        );
    }
}
