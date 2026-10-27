//! Fixed signed receipt for a durably reserved public OpenSSH attach.
//!
//! A dedicated controller attach-grant key signs the exact pending operation,
//! current assignment, and externally provisioned Host trust commitment. The
//! Host verifies this receipt before it may install a route; a broker-plan key
//! does not implicitly authorize this distinct signing domain.
//!
//! ```text
//! AOSAPG01 || operation[16] || execution[16] || sandbox[16]
//!          || incarnation[16] || node[16] || epoch:u64be
//!          || desired_generation:u64be || namespace_generation:u64be
//!          || assignment_digest[32] || lease_generation:u64be
//!          || lease_digest[32] || principal[16] || audit[16]
//!          || expires_at:i64be || request_digest[32] || pending_digest[32]
//!          || trust_digest[32] || gate_config_digest[32] || signature[64]
//! signature = Ed25519("aos.sandbox.public-attach-pending-grant.v1\0" || all preceding bytes)
//! ```

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

const MAGIC: &[u8; 8] = b"AOSAPG01";
const DOMAIN: &[u8] = b"aos.sandbox.public-attach-pending-grant.v1\0";
const PAYLOAD_BYTES: usize = 352;
/// Exact encoded byte count, including the Ed25519 signature.
pub const PUBLIC_ATTACH_GRANT_BYTES: usize = PAYLOAD_BYTES + 64;

/// Binds an admitted attach reservation to exact Host trust and runtime state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicAttachPendingGrantV1 {
    /// Durable controller operation identity.
    pub operation_id: [u8; 16],
    /// Durably admitted execution identity.
    pub execution_id: [u8; 16],
    /// Assigned sandbox identity.
    pub sandbox_id: [u8; 16],
    /// Current runtime incarnation.
    pub incarnation_id: [u8; 16],
    /// Current assigned node.
    pub node_id: [u8; 16],
    /// Current assignment epoch.
    pub assignment_epoch: u64,
    /// Current desired generation.
    pub desired_generation: u64,
    /// Current payload namespace generation.
    pub namespace_generation: u64,
    /// Current signed assignment commitment.
    pub assignment_digest: [u8; 32],
    /// Current protected ownership-lease generation.
    pub lease_generation: u64,
    /// Current protected ownership-lease commitment.
    pub lease_digest: [u8; 32],
    /// Public principal admitted by the controller.
    pub principal_id: [u8; 16],
    /// Durable audit identity.
    pub audit_id: [u8; 16],
    /// Last Unix second for installation or issuance.
    pub expires_at: i64,
    /// Exact public request commitment from the controller CAS.
    pub request_digest: [u8; 32],
    /// Protected pending-record commitment from the controller CAS.
    pub pending_digest: [u8; 32],
    /// Digest of the exact externally provisioned Host trust credential bytes.
    pub trust_digest: [u8; 32],
    /// Digest of exact generated guest sshd configuration bytes.
    pub gate_config_digest: [u8; 32],
}

impl PublicAttachPendingGrantV1 {
    /// Rejects all sentinel fields before signing or accepting a grant.
    ///
    /// # Errors
    ///
    /// Returns an error if any identity or digest is missing or expiry is invalid.
    pub fn validate(&self) -> Result<(), PublicAttachGrantErrorV1> {
        if [
            self.operation_id,
            self.execution_id,
            self.sandbox_id,
            self.incarnation_id,
            self.node_id,
            self.principal_id,
            self.audit_id,
        ]
        .contains(&[0; 16])
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.namespace_generation == 0
            || self.lease_generation == 0
            || self.expires_at <= 0
            || [
                self.assignment_digest,
                self.lease_digest,
                self.request_digest,
                self.pending_digest,
                self.trust_digest,
                self.gate_config_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(PublicAttachGrantErrorV1::InvalidField);
        }
        Ok(())
    }

    fn payload(&self) -> [u8; PAYLOAD_BYTES] {
        let mut output = [0u8; PAYLOAD_BYTES];
        let mut cursor = 0;
        for part in [
            MAGIC.as_slice(),
            &self.operation_id,
            &self.execution_id,
            &self.sandbox_id,
            &self.incarnation_id,
            &self.node_id,
            &self.assignment_epoch.to_be_bytes(),
            &self.desired_generation.to_be_bytes(),
            &self.namespace_generation.to_be_bytes(),
            &self.assignment_digest,
            &self.lease_generation.to_be_bytes(),
            &self.lease_digest,
            &self.principal_id,
            &self.audit_id,
            &self.expires_at.to_be_bytes(),
            &self.request_digest,
            &self.pending_digest,
            &self.trust_digest,
            &self.gate_config_digest,
        ] {
            output[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        }
        output
    }
}

/// Signs one exact protected pending reservation with the dedicated key.
///
/// # Errors
///
/// Returns an error if any grant field is a sentinel.
pub fn sign_public_attach_pending_grant_v1(
    grant: &PublicAttachPendingGrantV1,
    key: &SigningKey,
) -> Result<[u8; PUBLIC_ATTACH_GRANT_BYTES], PublicAttachGrantErrorV1> {
    grant.validate()?;
    let payload = grant.payload();
    let mut message = Vec::with_capacity(DOMAIN.len() + PAYLOAD_BYTES);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&payload);
    let signature = key.sign(&message).to_bytes();

    let mut packet = [0u8; PUBLIC_ATTACH_GRANT_BYTES];
    packet[..PAYLOAD_BYTES].copy_from_slice(&payload);
    packet[PAYLOAD_BYTES..].copy_from_slice(&signature);
    Ok(packet)
}

/// Verifies and decodes one dedicated-key controller pending receipt.
///
/// The caller must obtain `key` from an independently provisioned attach-grant
/// verifier credential, then compare the returned fields with current Host
/// runtime, admitted execution, trust credential, and one-time reservation.
///
/// # Errors
///
/// Returns an error for malformed bytes, an invalid signature, or sentinel data.
pub fn verify_public_attach_pending_grant_v1(
    packet: &[u8],
    key: &VerifyingKey,
) -> Result<PublicAttachPendingGrantV1, PublicAttachGrantErrorV1> {
    let bytes: &[u8; PUBLIC_ATTACH_GRANT_BYTES] = packet
        .try_into()
        .map_err(|_| PublicAttachGrantErrorV1::InvalidEncoding)?;
    if &bytes[..8] != MAGIC {
        return Err(PublicAttachGrantErrorV1::InvalidEncoding);
    }
    let signature_bytes: [u8; 64] = bytes[PAYLOAD_BYTES..]
        .try_into()
        .map_err(|_| PublicAttachGrantErrorV1::InvalidEncoding)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let mut message = Vec::with_capacity(DOMAIN.len() + PAYLOAD_BYTES);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&bytes[..PAYLOAD_BYTES]);
    key.verify_strict(&message, &signature)
        .map_err(|_| PublicAttachGrantErrorV1::InvalidSignature)?;

    let mut cursor = 8;
    let mut take = |length: usize| {
        let start = cursor;
        cursor += length;
        &bytes[start..cursor]
    };
    let grant = PublicAttachPendingGrantV1 {
        operation_id: array(take(16))?,
        execution_id: array(take(16))?,
        sandbox_id: array(take(16))?,
        incarnation_id: array(take(16))?,
        node_id: array(take(16))?,
        assignment_epoch: u64::from_be_bytes(array(take(8))?),
        desired_generation: u64::from_be_bytes(array(take(8))?),
        namespace_generation: u64::from_be_bytes(array(take(8))?),
        assignment_digest: array(take(32))?,
        lease_generation: u64::from_be_bytes(array(take(8))?),
        lease_digest: array(take(32))?,
        principal_id: array(take(16))?,
        audit_id: array(take(16))?,
        expires_at: i64::from_be_bytes(array(take(8))?),
        request_digest: array(take(32))?,
        pending_digest: array(take(32))?,
        trust_digest: array(take(32))?,
        gate_config_digest: array(take(32))?,
    };
    grant.validate()?;
    Ok(grant)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PublicAttachGrantErrorV1> {
    bytes
        .try_into()
        .map_err(|_| PublicAttachGrantErrorV1::InvalidEncoding)
}

/// Reports a malformed or unauthenticated attach-grant receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicAttachGrantErrorV1 {
    /// The byte layout, length, or magic differs from `AOSAPG01`.
    #[error("public attach pending grant has invalid encoding")]
    InvalidEncoding,
    /// A semantic identity or commitment is absent.
    #[error("public attach pending grant has an invalid field")]
    InvalidField,
    /// The dedicated attach-grant key did not sign the exact receipt.
    #[error("public attach pending grant signature is invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::{
        PublicAttachGrantErrorV1, PublicAttachPendingGrantV1, sign_public_attach_pending_grant_v1,
        verify_public_attach_pending_grant_v1,
    };

    fn grant() -> PublicAttachPendingGrantV1 {
        PublicAttachPendingGrantV1 {
            operation_id: [1; 16],
            execution_id: [2; 16],
            sandbox_id: [3; 16],
            incarnation_id: [4; 16],
            node_id: [5; 16],
            assignment_epoch: 6,
            desired_generation: 7,
            namespace_generation: 8,
            assignment_digest: [9; 32],
            lease_generation: 19,
            lease_digest: [20; 32],
            principal_id: [10; 16],
            audit_id: [11; 16],
            expires_at: 2_000_000_000,
            request_digest: [12; 32],
            pending_digest: [13; 32],
            trust_digest: [14; 32],
            gate_config_digest: [15; 32],
        }
    }

    #[test]
    fn dedicated_grant_signature_binds_every_byte() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let packet = sign_public_attach_pending_grant_v1(&grant(), &key).unwrap();
        assert_eq!(
            verify_public_attach_pending_grant_v1(&packet, &key.verifying_key()),
            Ok(grant())
        );

        let mut tampered = packet;
        tampered[32] ^= 1;
        assert_eq!(
            verify_public_attach_pending_grant_v1(&tampered, &key.verifying_key()),
            Err(PublicAttachGrantErrorV1::InvalidSignature)
        );
        assert_eq!(
            verify_public_attach_pending_grant_v1(
                &packet,
                &SigningKey::from_bytes(&[18; 32]).verifying_key()
            ),
            Err(PublicAttachGrantErrorV1::InvalidSignature)
        );
    }
}
