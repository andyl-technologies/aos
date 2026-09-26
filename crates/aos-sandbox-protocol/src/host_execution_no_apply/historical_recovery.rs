//! Distinct signed historical Host fence-recovery envelope.
//!
//! ```text
//! AOSCHR01 | version:u16be | reserved[6]=0 |
//! protected-admission-witness-digest:32 | Effect-fence-digest:32 |
//! preliminary-digest:32 | original-signed-request-digest:32 |
//! settlement-session-binding:32 | original-HostState-cut:32 |
//! Controller-H-head:32 | signed-T-outcome:32 |
//! recovery-nonce:16 | Controller-recovery-generation:u64be |
//! Ed25519(domain || preceding):64
//! ```
//!
//! This is not a broker method-42 request and never uses its old deadline as
//! current authority. Signature verification alone grants no Host mutation:
//! the caller must pin the Controller recovery signer/generation independently
//! and rejoin exact protected Host witness, Effect fence, and currentness.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, VerifyingKey};

const MAGIC: &[u8; 8] = b"AOSCHR01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.host-historical-recovery.v1\0";
const SIGNED_BYTES: usize = 296;

/// Exact length of one signed historical Host recovery envelope.
pub const HOST_HISTORICAL_RECOVERY_ENVELOPE_BYTES_V1: usize = 360;

/// Rejects malformed, foreign, or incorrectly signed recovery coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("historical Host recovery envelope is invalid")]
pub struct HostHistoricalRecoveryEnvelopeErrorV1;

/// Carries a Controller-signed request to inspect one historical fence pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedHostHistoricalRecoveryEnvelopeV1 {
    /// Digest of the exact protected AOSCHA01 admission witness row.
    pub witness_digest: ObjectDigest,
    /// Digest of the exact protected AOSCHF01 Effect fence row.
    pub effect_fence_digest: ObjectDigest,
    /// Digest of the protected original AOSCHL01 preliminary row.
    pub preliminary_digest: ObjectDigest,
    /// Digest of the original complete signed method-42 request artifact.
    pub original_signed_request_digest: ObjectDigest,
    /// Session binding retained by the original AOSCHL01 stage.
    pub settlement_session_binding: [u8; 32],
    /// Original HostState five-row cut pinned by the protected witness.
    pub hoststate_cut: ObjectDigest,
    /// Controller-asserted archived original H head.
    pub original_h_head: ObjectDigest,
    /// Controller-asserted signed terminal T outcome digest.
    pub signed_terminal_outcome: ObjectDigest,
    /// Nonzero nonce from the separate recovery request.
    pub recovery_nonce: [u8; 16],
    /// Monotonic Controller recovery generation; external readback must pin it.
    pub recovery_generation: u64,
    /// Ed25519 signature by the separately pinned Controller recovery key.
    pub signature: [u8; 64],
}

impl SignedHostHistoricalRecoveryEnvelopeV1 {
    /// Decodes only the exact versioned canonical envelope.
    ///
    /// # Errors
    ///
    /// Rejects wrong size, version, reserved bits, or sentinel identities.
    pub fn decode(bytes: &[u8]) -> Result<Self, HostHistoricalRecoveryEnvelopeErrorV1> {
        if bytes.len() != HOST_HISTORICAL_RECOVERY_ENVELOPE_BYTES_V1
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10..16] != [0; 6]
        {
            return Err(HostHistoricalRecoveryEnvelopeErrorV1);
        }
        let digest = |start| {
            bytes[start..start + 32]
                .try_into()
                .map(ObjectDigest::from_bytes)
                .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)
        };
        let envelope = Self {
            witness_digest: digest(16)?,
            effect_fence_digest: digest(48)?,
            preliminary_digest: digest(80)?,
            original_signed_request_digest: digest(112)?,
            settlement_session_binding: bytes[144..176]
                .try_into()
                .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)?,
            hoststate_cut: digest(176)?,
            original_h_head: digest(208)?,
            signed_terminal_outcome: digest(240)?,
            recovery_nonce: bytes[272..288]
                .try_into()
                .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)?,
            recovery_generation: u64::from_be_bytes(
                bytes[288..296]
                    .try_into()
                    .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)?,
            ),
            signature: bytes[296..360]
                .try_into()
                .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)?,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Encodes this exact envelope, including its signature.
    #[must_use]
    pub fn encode(self) -> [u8; HOST_HISTORICAL_RECOVERY_ENVELOPE_BYTES_V1] {
        let mut bytes = [0; HOST_HISTORICAL_RECOVERY_ENVELOPE_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        for (start, digest) in [
            (16, self.witness_digest),
            (48, self.effect_fence_digest),
            (80, self.preliminary_digest),
            (112, self.original_signed_request_digest),
            (176, self.hoststate_cut),
            (208, self.original_h_head),
            (240, self.signed_terminal_outcome),
        ] {
            bytes[start..start + 32].copy_from_slice(digest.as_bytes());
        }
        bytes[144..176].copy_from_slice(&self.settlement_session_binding);
        bytes[272..288].copy_from_slice(&self.recovery_nonce);
        bytes[288..296].copy_from_slice(&self.recovery_generation.to_be_bytes());
        bytes[296..360].copy_from_slice(&self.signature);
        bytes
    }

    /// Verifies the dedicated recovery signature against an externally pinned key.
    ///
    /// The pin and current Controller generation must be rechecked by their
    /// protected owners; this pure check is never an authorization result.
    ///
    /// # Errors
    ///
    /// Rejects invalid fields, a malformed public key, or an invalid signature.
    pub fn verify_signature(
        self,
        pinned_controller_recovery_key: [u8; 32],
    ) -> Result<(), HostHistoricalRecoveryEnvelopeErrorV1> {
        self.validate()?;
        let key = VerifyingKey::from_bytes(&pinned_controller_recovery_key)
            .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)?;
        key.verify_strict(
            &self.signature_message(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| HostHistoricalRecoveryEnvelopeErrorV1)
    }

    /// Returns the domain-separated bytes a dedicated Controller signer signs.
    #[must_use]
    pub fn signature_message(self) -> Vec<u8> {
        let bytes = self.encode();
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNED_BYTES);
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&bytes[..SIGNED_BYTES]);
        message
    }

    /// Compares the exact retained Host coordinates without granting authority.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn matches_protected_coordinates(
        self,
        witness_digest: ObjectDigest,
        effect_fence_digest: ObjectDigest,
        preliminary_digest: ObjectDigest,
        original_signed_request_digest: ObjectDigest,
        settlement_session_binding: [u8; 32],
        hoststate_cut: ObjectDigest,
        original_h_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
    ) -> bool {
        self.witness_digest == witness_digest
            && self.effect_fence_digest == effect_fence_digest
            && self.preliminary_digest == preliminary_digest
            && self.original_signed_request_digest == original_signed_request_digest
            && self.settlement_session_binding == settlement_session_binding
            && self.hoststate_cut == hoststate_cut
            && self.original_h_head == original_h_head
            && self.signed_terminal_outcome == signed_terminal_outcome
    }

    fn validate(self) -> Result<(), HostHistoricalRecoveryEnvelopeErrorV1> {
        if [
            self.witness_digest,
            self.effect_fence_digest,
            self.preliminary_digest,
            self.original_signed_request_digest,
            self.hoststate_cut,
            self.original_h_head,
            self.signed_terminal_outcome,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
            || self.settlement_session_binding == [0; 32]
            || self.recovery_nonce == [0; 16]
            || self.recovery_generation == 0
            || self.signature == [0; 64]
        {
            return Err(HostHistoricalRecoveryEnvelopeErrorV1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    #[test]
    fn historical_envelope_requires_dedicated_signature_and_exact_coordinates() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let mut envelope = SignedHostHistoricalRecoveryEnvelopeV1 {
            witness_digest: ObjectDigest::from_bytes([1; 32]),
            effect_fence_digest: ObjectDigest::from_bytes([2; 32]),
            preliminary_digest: ObjectDigest::from_bytes([3; 32]),
            original_signed_request_digest: ObjectDigest::from_bytes([4; 32]),
            settlement_session_binding: [5; 32],
            hoststate_cut: ObjectDigest::from_bytes([6; 32]),
            original_h_head: ObjectDigest::from_bytes([8; 32]),
            signed_terminal_outcome: ObjectDigest::from_bytes([9; 32]),
            recovery_nonce: [10; 16],
            recovery_generation: 11,
            signature: [1; 64],
        };
        envelope.signature = signer.sign(&envelope.signature_message()).to_bytes();
        let bytes = envelope.encode();
        let decoded = SignedHostHistoricalRecoveryEnvelopeV1::decode(&bytes)
            .expect("canonical signed recovery envelope");
        assert_eq!(decoded, envelope);
        assert!(
            decoded
                .verify_signature(signer.verifying_key().to_bytes())
                .is_ok()
        );
        assert!(
            decoded
                .verify_signature(SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes())
                .is_err()
        );
        let mut wrong_domain = decoded;
        wrong_domain.signature = signer.sign(&bytes[..SIGNED_BYTES]).to_bytes();
        assert!(
            wrong_domain
                .verify_signature(signer.verifying_key().to_bytes())
                .is_err()
        );
        assert!(decoded.matches_protected_coordinates(
            decoded.witness_digest,
            decoded.effect_fence_digest,
            decoded.preliminary_digest,
            decoded.original_signed_request_digest,
            decoded.settlement_session_binding,
            decoded.hoststate_cut,
            decoded.original_h_head,
            decoded.signed_terminal_outcome,
        ));
        assert!(!decoded.matches_protected_coordinates(
            ObjectDigest::from_bytes([13; 32]),
            decoded.effect_fence_digest,
            decoded.preliminary_digest,
            decoded.original_signed_request_digest,
            decoded.settlement_session_binding,
            decoded.hoststate_cut,
            decoded.original_h_head,
            decoded.signed_terminal_outcome,
        ));
        assert!(!decoded.matches_protected_coordinates(
            decoded.witness_digest,
            decoded.effect_fence_digest,
            decoded.preliminary_digest,
            decoded.original_signed_request_digest,
            decoded.settlement_session_binding,
            decoded.hoststate_cut,
            ObjectDigest::from_bytes([14; 32]),
            decoded.signed_terminal_outcome,
        ));

        let mut corrupt = bytes;
        corrupt[10] = 1;
        assert!(SignedHostHistoricalRecoveryEnvelopeV1::decode(&corrupt).is_err());
        for offset in [16, 48, 80, 112, 144, 176, 208, 240, 272, 288, 296] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            let decoded = SignedHostHistoricalRecoveryEnvelopeV1::decode(&changed)
                .expect("structurally canonical substitution");
            assert!(
                decoded
                    .verify_signature(signer.verifying_key().to_bytes())
                    .is_err()
            );
        }
    }
}
