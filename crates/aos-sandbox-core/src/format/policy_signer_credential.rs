//! Canonical public policy-verifier credential DATA.
//!
//! The framing checksum is not a trust boundary. Actual fixed privileged
//! credential custody and the current owner independently authenticate these
//! bytes. The codec reads no files and supplies no signer or live authority.
//!
//! ```text
//! AOSPDK01 or AOSPPK01 | generation:u64be | Ed25519 public key:32 |
//! SHA-256(role-domain || preceding 48 bytes):32
//! ```

use std::io;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

/// Names the two noninterchangeable existing public policy-verifier roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyVerifierRoleV1 {
    /// The independently provisioned deployment-input verifier.
    Deployment,
    /// The independently provisioned project-policy verifier.
    Project,
}

impl PolicyVerifierRoleV1 {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Deployment => b"AOSPDK01",
            Self::Project => b"AOSPPK01",
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::Deployment => b"aos.sandbox.policy-deployment-verifier.v1\0",
            Self::Project => b"aos.sandbox.policy-project-verifier.v1\0",
        }
    }
}

/// Decodes canonical public verifier DATA in the original validation order.
///
/// # Errors
/// Rejects raw keys, wrong length or role, zero generation, changed checksum
/// or malformed Ed25519 key with the existing InvalidData error contract.
pub fn decode_policy_verifier_credential_v1(
    role: PolicyVerifierRoleV1,
    bytes: &[u8],
) -> io::Result<(u64, VerifyingKey)> {
    if bytes.len() != 80 || bytes.get(..8) != Some(role.magic()) {
        return Err(invalid_credential());
    }
    let generation =
        u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| invalid_credential())?);
    if generation == 0 {
        return Err(invalid_credential());
    }
    let expected_checksum = Sha256::new()
        .chain_update(role.domain())
        .chain_update(&bytes[..48])
        .finalize();
    if bytes[48..] != expected_checksum[..] {
        return Err(invalid_credential());
    }
    let key_bytes: [u8; 32] = bytes[16..48].try_into().map_err(|_| invalid_credential())?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| invalid_credential())?;
    Ok((generation, verifying_key))
}

/// Encodes the same public verifier framing without provisioning trust.
///
/// # Errors
/// Rejects generation zero with the existing InvalidData error contract.
pub fn encode_policy_verifier_credential_v1(
    role: PolicyVerifierRoleV1,
    generation: u64,
    key: &VerifyingKey,
) -> io::Result<[u8; 80]> {
    if generation == 0 {
        return Err(invalid_credential());
    }
    let mut bytes = [0_u8; 80];
    bytes[..8].copy_from_slice(role.magic());
    bytes[8..16].copy_from_slice(&generation.to_be_bytes());
    bytes[16..48].copy_from_slice(key.as_bytes());
    let checksum = Sha256::new()
        .chain_update(role.domain())
        .chain_update(&bytes[..48])
        .finalize();
    bytes[48..].copy_from_slice(&checksum);
    Ok(bytes)
}

fn invalid_credential() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid policy signer credential",
    )
}
