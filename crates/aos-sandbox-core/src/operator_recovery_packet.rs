//! Shared byte-exact signature framing for versioned operator recovery packets.
//!
//! Each version supplies its own payload size and domain. This module does not
//! interpret payload fields or allow one version's packet to verify as another.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::operator_recovery_effect::OperatorRecoveryEffectErrorV1;

pub(crate) fn sign_packet<const PAYLOAD: usize, const PACKET: usize>(
    payload: [u8; PAYLOAD],
    domain: &[u8],
    key: &SigningKey,
) -> [u8; PACKET] {
    let mut message = Vec::with_capacity(domain.len() + PAYLOAD);
    message.extend_from_slice(domain);
    message.extend_from_slice(&payload);
    let signature = key.sign(&message).to_bytes();
    let mut packet = [0; PACKET];
    packet[..PAYLOAD].copy_from_slice(&payload);
    packet[PAYLOAD..].copy_from_slice(&signature);
    packet
}

pub(crate) fn verify_packet<const PACKET: usize>(
    packet: &[u8],
    payload_bytes: usize,
    domain: &[u8],
    key: &VerifyingKey,
) -> Result<[u8; PACKET], OperatorRecoveryEffectErrorV1> {
    let bytes: [u8; PACKET] = packet
        .try_into()
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidEncoding)?;
    let signature_bytes: [u8; 64] = bytes[payload_bytes..]
        .try_into()
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidEncoding)?;
    let mut message = Vec::with_capacity(domain.len() + payload_bytes);
    message.extend_from_slice(domain);
    message.extend_from_slice(&bytes[..payload_bytes]);
    key.verify_strict(&message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidSignature)?;
    Ok(bytes)
}

pub(crate) fn array<const N: usize>(
    bytes: &[u8],
) -> Result<[u8; N], OperatorRecoveryEffectErrorV1> {
    bytes
        .try_into()
        .map_err(|_| OperatorRecoveryEffectErrorV1::InvalidEncoding)
}
