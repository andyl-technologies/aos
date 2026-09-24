//! Fail-closed public-verifier credential custody for the closed owner daemon.
//!
//! ```text
//! lease-verifier-v1[112] = Storage signer projection[80] | Ed25519 key[32]
//! stage-verifier-v2[112] = distinct stage signer projection[80] | key[32]
//! ```
//!
//! systemd supplies these externally provisioned public credentials. No
//! private signing key is generated or loaded here, and neither verifier
//! authorizes Stage, ACTIVE, or descriptor release without a current Storage
//! signer/barrier and C-owner map readback.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::stage_ack::VERIFIER_BYTES;

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-kernel-export-ownerd.service";
const LEASE_FILE: &str = "kernel-export-lease-verifier-v1";
const STAGE_FILE: &str = "kernel-export-stage-verifier-v2";

/// Reports invalid or absent ownerd credential custody.
#[derive(Debug, thiserror::Error)]
pub enum DeploymentCredentialError {
    /// systemd did not provide the exact configured credential directory.
    #[error("owner credential directory is unavailable or unprotected")]
    Directory,
    /// A verifier file differs from the fixed protected role contract.
    #[error("owner {0} verifier is unavailable or noncanonical")]
    Verifier(&'static str),
    /// The two Storage roles reuse an identity or Ed25519 key.
    #[error("owner lease and stage verifier roles are not distinct")]
    ReusedRole,
}

/// Retains only two validated public-key records, never private signing keys.
#[derive(Clone, Debug)]
pub struct OwnerPublicVerifiers {
    lease: [u8; VERIFIER_BYTES],
    stage: [u8; VERIFIER_BYTES],
}

impl OwnerPublicVerifiers {
    /// Loads the exact role files from systemd's root-private credential dir.
    ///
    /// # Errors
    ///
    /// Rejects absent, redirected, non-root, over-permissive, wrong-size,
    /// noncanonical, weak, or role-reused credential records.
    pub fn from_systemd_credentials() -> Result<Self, DeploymentCredentialError> {
        let selected = std::env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or(DeploymentCredentialError::Directory)?;
        if Path::new(&selected) != Path::new(CREDENTIAL_DIRECTORY) {
            return Err(DeploymentCredentialError::Directory);
        }
        let directory = std::fs::symlink_metadata(CREDENTIAL_DIRECTORY)
            .map_err(|_| DeploymentCredentialError::Directory)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || directory.uid() != 0
            || directory.mode() & 0o077 != 0
        {
            return Err(DeploymentCredentialError::Directory);
        }

        let lease = read_verifier(LEASE_FILE)?;
        let stage = read_verifier(STAGE_FILE)?;
        Self::from_bytes(lease, stage)
    }

    /// Validates two exact role projections after protected file custody.
    ///
    /// Tests also use this pure parser; production obtains its bytes only
    /// through [`Self::from_systemd_credentials`].
    ///
    /// # Errors
    ///
    /// Rejects sentinel or reused signer identities, weak or reused keys.
    fn from_bytes(
        lease: [u8; VERIFIER_BYTES],
        stage: [u8; VERIFIER_BYTES],
    ) -> Result<Self, DeploymentCredentialError> {
        validate_verifier(&lease, "lease")?;
        validate_verifier(&stage, "stage")?;
        if lease[..80] == stage[..80] || lease[80..] == stage[80..] {
            return Err(DeploymentCredentialError::ReusedRole);
        }
        Ok(Self { lease, stage })
    }

    /// Borrows the earlier Storage lease public verifier bytes.
    #[must_use]
    pub const fn lease(&self) -> &[u8; VERIFIER_BYTES] {
        &self.lease
    }

    /// Borrows the distinct future PREPARED stage public verifier bytes.
    #[must_use]
    pub const fn stage(&self) -> &[u8; VERIFIER_BYTES] {
        &self.stage
    }
}

fn read_verifier(name: &'static str) -> Result<[u8; VERIFIER_BYTES], DeploymentCredentialError> {
    let path = Path::new(CREDENTIAL_DIRECTORY).join(name);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| DeploymentCredentialError::Verifier(name))?;
    let metadata = file
        .metadata()
        .map_err(|_| DeploymentCredentialError::Verifier(name))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() != VERIFIER_BYTES as u64
    {
        return Err(DeploymentCredentialError::Verifier(name));
    }

    let mut bytes = [0_u8; VERIFIER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| DeploymentCredentialError::Verifier(name))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| DeploymentCredentialError::Verifier(name))?
        != 0
    {
        return Err(DeploymentCredentialError::Verifier(name));
    }
    Ok(bytes)
}

fn validate_verifier(
    bytes: &[u8; VERIFIER_BYTES],
    role: &'static str,
) -> Result<(), DeploymentCredentialError> {
    if bytes[..16] == [0; 16]
        || bytes[16..24] == [0; 8]
        || bytes[24..56] == [0; 32]
        || bytes[56..72] == [0; 16]
        || bytes[72..80] == [0; 8]
    {
        return Err(DeploymentCredentialError::Verifier(role));
    }
    let public_key: [u8; 32] = bytes[80..]
        .try_into()
        .map_err(|_| DeploymentCredentialError::Verifier(role))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| DeploymentCredentialError::Verifier(role))?;
    if key.is_weak() {
        return Err(DeploymentCredentialError::Verifier(role));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn role(value: u8) -> [u8; VERIFIER_BYTES] {
        let mut bytes = [value; VERIFIER_BYTES];
        bytes[16..24].copy_from_slice(&1_u64.to_be_bytes());
        bytes[72..80].copy_from_slice(&1_u64.to_be_bytes());
        bytes[80..].copy_from_slice(
            &SigningKey::from_bytes(&[value; 32])
                .verifying_key()
                .to_bytes(),
        );
        bytes
    }

    #[test]
    fn distinct_public_verifiers_admit_without_authority() {
        let pair = OwnerPublicVerifiers::from_bytes(role(1), role(2)).unwrap();
        assert_ne!(pair.lease(), pair.stage());
    }

    #[test]
    fn reused_or_sentinel_roles_fail_closed() {
        assert!(matches!(
            OwnerPublicVerifiers::from_bytes(role(1), role(1)),
            Err(DeploymentCredentialError::ReusedRole)
        ));
        let mut repeated_key = role(2);
        repeated_key[80..].copy_from_slice(&role(1)[80..]);
        assert!(matches!(
            OwnerPublicVerifiers::from_bytes(role(1), repeated_key),
            Err(DeploymentCredentialError::ReusedRole)
        ));
        let mut repeated_projection = role(2);
        repeated_projection[..80].copy_from_slice(&role(1)[..80]);
        assert!(matches!(
            OwnerPublicVerifiers::from_bytes(role(1), repeated_projection),
            Err(DeploymentCredentialError::ReusedRole)
        ));
        let mut zero_generation = role(1);
        zero_generation[16..24].fill(0);
        assert!(matches!(
            OwnerPublicVerifiers::from_bytes(zero_generation, role(2)),
            Err(DeploymentCredentialError::Verifier("lease"))
        ));
    }
}
