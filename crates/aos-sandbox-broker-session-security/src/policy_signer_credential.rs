//! Versioned deployment credentials for policy-signature verification roots.
//!
//! Each 80-byte credential is loaded from one fixed, privileged systemd
//! credential path. Its role-specific magic and checksum make a raw public key
//! or a key intended for another signing role noncanonical. The checksum is
//! framing only; protected credential custody supplies the trust boundary.
//!
//! ```text
//! AOSPDK01 or AOSPPK01 | generation:u64 | Ed25519 public key:32 |
//! SHA-256(role-domain || preceding 48 bytes)
//! ```

use std::io;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

const CREDENTIAL_BYTES: usize = 80;
const DEPLOYMENT_MAGIC: &[u8; 8] = b"AOSPDK01";
const PROJECT_MAGIC: &[u8; 8] = b"AOSPPK01";
const DEPLOYMENT_DOMAIN: &[u8] = b"aos.sandbox.policy-deployment-verifier.v1\0";
const PROJECT_DOMAIN: &[u8] = b"aos.sandbox.policy-project-verifier.v1\0";

/// Selects one non-interchangeable policy-signature verification role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicySignerRoleV1 {
    /// The root deployment-input head signer.
    Deployment,
    /// The independently signed project-policy layer signer.
    Project,
}

impl PolicySignerRoleV1 {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Deployment => DEPLOYMENT_MAGIC,
            Self::Project => PROJECT_MAGIC,
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::Deployment => DEPLOYMENT_DOMAIN,
            Self::Project => PROJECT_DOMAIN,
        }
    }
}

/// Retains a role-specific public key and nonzero deployment generation.
pub struct PinnedPolicySignerV1 {
    generation: u64,
    verifying_key: VerifyingKey,
}

impl PinnedPolicySignerV1 {
    /// Decodes one exact privileged deployment credential.
    ///
    /// # Errors
    ///
    /// Rejects raw legacy keys, wrong roles, zero generations, malformed
    /// Ed25519 keys, and noncanonical or altered framing.
    pub fn decode(role: PolicySignerRoleV1, bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != CREDENTIAL_BYTES || bytes.get(..8) != Some(role.magic()) {
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
        Ok(Self {
            generation,
            verifying_key,
        })
    }

    /// Returns the deployment-controlled key generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the pinned verification key for this role.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Encodes a role-specific credential for privileged deployment provisioning.
///
/// The encoder handles public key material only. The resulting file must be
/// installed as the fixed systemd credential for the selected role; an
/// unprivileged request cannot supply or replace it.
///
/// # Errors
///
/// Rejects generation zero.
pub fn encode_policy_signer_credential_v1(
    role: PolicySignerRoleV1,
    generation: u64,
    key: &VerifyingKey,
) -> io::Result<[u8; CREDENTIAL_BYTES]> {
    if generation == 0 {
        return Err(invalid_credential());
    }
    let mut bytes = [0_u8; CREDENTIAL_BYTES];
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn credential(role: PolicySignerRoleV1, generation: u64, key: &VerifyingKey) -> Vec<u8> {
        let mut bytes = Vec::from(role.magic().as_slice());
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(key.as_bytes());
        let checksum = Sha256::new()
            .chain_update(role.domain())
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    #[test]
    fn role_and_generation_are_pinned_by_exact_credential() {
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let deployment =
            encode_policy_signer_credential_v1(PolicySignerRoleV1::Deployment, 3, &key)
                .expect("canonical credential");
        let decoded = PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &deployment)
            .expect("pinned deployment key");
        assert_eq!(decoded.generation(), 3);
        assert_eq!(decoded.verifying_key(), &key);

        assert!(PinnedPolicySignerV1::decode(PolicySignerRoleV1::Project, &deployment).is_err());
        assert!(
            PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, key.as_bytes()).is_err()
        );
        assert!(
            PinnedPolicySignerV1::decode(
                PolicySignerRoleV1::Deployment,
                &credential(PolicySignerRoleV1::Deployment, 0, &key),
            )
            .is_err()
        );

        let mut altered = deployment;
        altered[20] ^= 1;
        assert!(PinnedPolicySignerV1::decode(PolicySignerRoleV1::Deployment, &altered).is_err());
        assert!(
            encode_policy_signer_credential_v1(PolicySignerRoleV1::Deployment, 0, &key).is_err()
        );
    }
}
