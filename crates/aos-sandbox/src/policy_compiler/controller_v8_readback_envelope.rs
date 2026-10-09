//! Shared framing for the distinct Controller V8 signed readbacks.
//!
//! ```text
//! magic[8] | version:u16=1 | reserved[6]=0 | signer-generation:u64 |
//! Root-nonce[16] | Root-cut[32] | Controller-UID:u32 |
//! journal-sequence:u64 | protocol-specific record | Ed25519[64]
//! ```
//!
//! Each protocol selects its own fixed magic, record length, and signature
//! domain here. Its caller retains responsibility for journal currentness and
//! canonical decoding of the record after envelope verification.

use ed25519_dalek::{Signature, Signer as _, SigningKey};

use super::binding_v2::ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1;
use super::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use super::controller_hold_readback::PinnedControllerHoldSignerV1;

/// Bounds the common signed packet header.
pub(super) const HEADER_BYTES: usize = 84;
/// Bounds its Ed25519 signature.
pub(super) const SIGNATURE_BYTES: usize = 64;

/// Selects one compiled Controller V8 receipt or final command format.
#[derive(Clone, Copy)]
pub(super) enum ControllerV8ReadbackProtocol {
    EffectAck,
    RootReceipt,
    FinalRelease,
    Settlement,
}

impl ControllerV8ReadbackProtocol {
    const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::EffectAck => b"AOSCTE08",
            Self::RootReceipt => b"AOSCTR08",
            Self::FinalRelease => b"AOSCTF08",
            Self::Settlement => b"AOSCTS08",
        }
    }

    const fn record_bytes(self) -> usize {
        match self {
            Self::EffectAck => 320,
            Self::RootReceipt => ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1,
            Self::FinalRelease => 476,
            Self::Settlement => 312,
        }
    }

    const fn signature_domain(self) -> &'static [u8] {
        match self {
            Self::EffectAck => b"aos.sandbox.controller-policy-v8-effect-ack.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0",
            Self::RootReceipt => b"aos.sandbox.controller-policy-v8-root-receipt.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0",
            Self::FinalRelease => b"aos.sandbox.controller-policy-v8-final-release.command.v1\0/var/lib/aos/sandboxd/controller.journal\0",
            Self::Settlement => b"aos.sandbox.controller-policy-v8-settlement.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0",
        }
    }

    const fn packet_bytes(self) -> usize {
        HEADER_BYTES + self.record_bytes() + SIGNATURE_BYTES
    }
}

/// Signs one fixed V8 envelope around a canonical owner record.
///
/// # Errors
///
/// Rejects a mismatched packet or record length, or absent owner identity.
pub(super) fn sign_packet<const N: usize>(
    protocol: ControllerV8ReadbackProtocol,
    record: &[u8],
    uid: u32,
    sequence: u64,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; N], ControllerEffectAckReadbackErrorV1> {
    if N != protocol.packet_bytes()
        || record.len() != protocol.record_bytes()
        || uid == 0
        || sequence == 0
        || generation == 0
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let mut bytes = [0; N];
    let body_end = N - SIGNATURE_BYTES;
    bytes[..8].copy_from_slice(protocol.magic());
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&challenge.nonce());
    bytes[40..72].copy_from_slice(challenge.cut().as_bytes());
    bytes[72..76].copy_from_slice(&uid.to_be_bytes());
    bytes[76..HEADER_BYTES].copy_from_slice(&sequence.to_be_bytes());
    bytes[HEADER_BYTES..body_end].copy_from_slice(record);

    let signature = key.sign(&[protocol.signature_domain(), &bytes[..body_end]].concat());
    bytes[body_end..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Verifies the fixed V8 envelope and returns its still-unparsed owner record.
///
/// # Errors
///
/// Rejects foreign framing, signer generation, Root challenge, Controller UID,
/// journal sequence, or signature.
pub(super) fn verify_packet<'a>(
    protocol: ControllerV8ReadbackProtocol,
    bytes: &'a [u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerEffectAckChallengeV1,
    expected_uid: u32,
) -> Result<&'a [u8], ControllerEffectAckReadbackErrorV1> {
    if bytes.len() != protocol.packet_bytes()
        || bytes[..8] != protocol.magic()[..]
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[16..24] != signer.generation().to_be_bytes()
        || bytes[24..40] != challenge.nonce()
        || bytes[40..72] != *challenge.cut().as_bytes()
        || bytes[72..76] != expected_uid.to_be_bytes()
        || expected_uid == 0
        || bytes[76..HEADER_BYTES] == [0; 8]
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let body_end = bytes.len() - SIGNATURE_BYTES;
    let signature = Signature::from_bytes(
        &bytes[body_end..]
            .try_into()
            .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?,
    );
    signer
        .verifying_key()
        .verify_strict(
            &[protocol.signature_domain(), &bytes[..body_end]].concat(),
            &signature,
        )
        .map_err(|_| ControllerEffectAckReadbackErrorV1::Signature)?;
    Ok(&bytes[HEADER_BYTES..body_end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ObjectDigest;

    use crate::policy_compiler::controller_hold_readback::encode_controller_hold_signer_credential_v1;

    #[test]
    fn v8_receipt_envelopes_reject_cross_protocol_packets() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let pin = encode_controller_hold_signer_credential_v1(2, &key.verifying_key()).unwrap();
        let signer = PinnedControllerHoldSignerV1::decode(&pin).unwrap();
        let challenge =
            ControllerEffectAckChallengeV1::new([3; 16], ObjectDigest::from_bytes([4; 32]))
                .unwrap();

        let ack = sign_packet::<{ HEADER_BYTES + 320 + SIGNATURE_BYTES }>(
            ControllerV8ReadbackProtocol::EffectAck,
            &[5; 320],
            6,
            7,
            challenge,
            2,
            &key,
        )
        .unwrap();
        let receipt =
            sign_packet::<{ HEADER_BYTES + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1 + SIGNATURE_BYTES }>(
                ControllerV8ReadbackProtocol::RootReceipt,
                &[8; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1],
                6,
                7,
                challenge,
                2,
                &key,
            )
            .unwrap();
        let final_release = sign_packet::<{ HEADER_BYTES + 476 + SIGNATURE_BYTES }>(
            ControllerV8ReadbackProtocol::FinalRelease,
            &[9; 476],
            6,
            7,
            challenge,
            2,
            &key,
        )
        .unwrap();
        let settlement = sign_packet::<{ HEADER_BYTES + 312 + SIGNATURE_BYTES }>(
            ControllerV8ReadbackProtocol::Settlement,
            &[10; 312],
            6,
            7,
            challenge,
            2,
            &key,
        )
        .unwrap();

        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::EffectAck,
                &ack,
                &signer,
                challenge,
                6
            )
            .is_ok()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::RootReceipt,
                &receipt,
                &signer,
                challenge,
                6
            )
            .is_ok()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::RootReceipt,
                &ack,
                &signer,
                challenge,
                6
            )
            .is_err()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::RootReceipt,
                &final_release,
                &signer,
                challenge,
                6
            )
            .is_err()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::FinalRelease,
                &receipt,
                &signer,
                challenge,
                6
            )
            .is_err()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::EffectAck,
                &receipt,
                &signer,
                challenge,
                6
            )
            .is_err()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::Settlement,
                &settlement,
                &signer,
                challenge,
                6,
            )
            .is_ok()
        );
        assert!(
            verify_packet(
                ControllerV8ReadbackProtocol::RootReceipt,
                &settlement,
                &signer,
                challenge,
                6,
            )
            .is_err()
        );

        let mut wrong_domain = receipt;
        let body_end = wrong_domain.len() - SIGNATURE_BYTES;
        let signature = ed25519_dalek::Signer::sign(
            &key,
            &[
                ControllerV8ReadbackProtocol::EffectAck.signature_domain(),
                &wrong_domain[..body_end],
            ]
            .concat(),
        );
        wrong_domain[body_end..].copy_from_slice(&signature.to_bytes());
        assert!(matches!(
            verify_packet(
                ControllerV8ReadbackProtocol::RootReceipt,
                &wrong_domain,
                &signer,
                challenge,
                6,
            ),
            Err(ControllerEffectAckReadbackErrorV1::Signature)
        ));
    }
}
