//! Cache-only signer key and physical memory ceiling from fixed credentials.
//!
//! The dedicated signer service loads these three files from its private
//! systemd credential directory. The public pin must match root's separately
//! provisioned `AOSCPK01` pin; this loader cannot establish that deployment
//! relationship or grant Q04 authority by itself. Provisioning must also keep
//! this seed distinct from the Controller's optional v1 diagnostic seed.
//!
//! ```text
//! cache-signer-v2-seed: Ed25519 seed[32]
//! cache-owner-readback-public-key: AOSCPK01 pin[80]
//! cache-signer-v2-memory-ceiling: AOSCSM01 | maximum-memory-bytes:u64be
//! ```

use std::path::Path;

use aos_sandbox_protocol::role_credential::{
    CACHE_OWNER_ROLE_CREDENTIAL_DOMAIN_V1, CACHE_OWNER_ROLE_CREDENTIAL_MAGIC_V1,
    decode_role_credential,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::read_optional_fixed_role_credential_v1;

const SEED_NAME: &str = "cache-signer-v2-seed";
const PIN_NAME: &str = "cache-owner-readback-public-key";
const MEMORY_NAME: &str = "cache-signer-v2-memory-ceiling";
#[cfg(test)]
use aos_sandbox_protocol::role_credential::cache_signer_inputs::MEMORY_MAGIC;

/// Retains a signer-private key and deployment-supplied physical memory ceiling.
///
/// The service reconstructs a signing key only for a bounded challenge flight
/// and rechecks both Cache views. This type cannot prove Controller-held writer
/// custody; its public pin is not root's independently installed pin.
pub(crate) struct CacheSignerCredentialV2 {
    seed: Zeroizing<Vec<u8>>,
    generation: u64,
    maximum_memory_bytes: u64,
}

impl CacheSignerCredentialV2 {
    /// Loads the exact signer-private credential triplet from systemd custody.
    ///
    /// # Errors
    ///
    /// Rejects a missing, relative, partial, unsafe, noncanonical, or
    /// mismatched credential set.
    pub(crate) fn load() -> Result<Self, CacheSignerCredentialErrorV2> {
        let directory =
            std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(CacheSignerCredentialErrorV2)?;
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(CacheSignerCredentialErrorV2);
        }
        Self::from_directory(directory)
    }

    fn from_directory(directory: &Path) -> Result<Self, CacheSignerCredentialErrorV2> {
        let seed = read_optional_fixed_role_credential_v1(directory, SEED_NAME, 32, true)
            .map_err(|_| CacheSignerCredentialErrorV2)?
            .ok_or(CacheSignerCredentialErrorV2)?;
        let pin = read_optional_fixed_role_credential_v1(directory, PIN_NAME, 80, false)
            .map_err(|_| CacheSignerCredentialErrorV2)?
            .ok_or(CacheSignerCredentialErrorV2)?;
        let memory = read_optional_fixed_role_credential_v1(directory, MEMORY_NAME, 16, true)
            .map_err(|_| CacheSignerCredentialErrorV2)?
            .ok_or(CacheSignerCredentialErrorV2)?;

        let (seed_bytes, maximum_memory_bytes) =
            validate_seed_and_memory(seed.as_slice(), &memory)?;

        let signing_key = SigningKey::from_bytes(seed_bytes);
        let (generation, public) = decode_role_credential(
            &pin,
            CACHE_OWNER_ROLE_CREDENTIAL_MAGIC_V1,
            CACHE_OWNER_ROLE_CREDENTIAL_DOMAIN_V1,
        )
        .ok_or(CacheSignerCredentialErrorV2)?;
        require_key_matches(&public, &signing_key)?;

        Ok(Self {
            seed,
            generation,
            maximum_memory_bytes,
        })
    }

    /// Returns the Cache-purpose key generation pinned by this credential.
    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the provisioned physical memory ceiling for quota derivation.
    #[must_use]
    pub(crate) const fn maximum_memory_bytes(&self) -> u64 {
        self.maximum_memory_bytes
    }

    /// Reconstructs the signer key only for one bounded response flight.
    ///
    /// The retained heap seed remains zeroizing, and dalek's enabled zeroize
    /// feature wipes the temporary SigningKey secret when the flight ends.
    pub(crate) fn signing_key(&self) -> Result<SigningKey, CacheSignerCredentialErrorV2> {
        let seed: &[u8; 32] = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| CacheSignerCredentialErrorV2)?;
        Ok(SigningKey::from_bytes(seed))
    }
}

fn validate_seed_and_memory<'seed>(
    seed: &'seed [u8],
    memory: &[u8],
) -> Result<(&'seed [u8; 32], u64), CacheSignerCredentialErrorV2> {
    aos_sandbox_protocol::role_credential::cache_signer_inputs::validate_seed_and_memory(
        seed, memory,
    )
    .map_err(|_| CacheSignerCredentialErrorV2)
}

fn require_key_matches(
    pinned: &ed25519_dalek::VerifyingKey,
    signing_key: &SigningKey,
) -> Result<(), CacheSignerCredentialErrorV2> {
    aos_sandbox_protocol::role_credential::cache_signer_inputs::require_key_matches(
        pinned,
        &signing_key.verifying_key(),
    )
    .map_err(|_| CacheSignerCredentialErrorV2)
}

/// Reports a missing or unsafe signer-private credential set.
#[derive(Debug, thiserror::Error)]
#[error("Cache signer v2 credentials are missing, unsafe, or inconsistent")]
pub(crate) struct CacheSignerCredentialErrorV2;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_sandbox_protocol::cache_owner_readback::encode_cache_owner_readback_signer_credential_v1;


    use super::*;

    #[test]
    fn signer_key_requires_matching_role_pin_and_provisioned_memory_ceiling() {
        let directory = tempfile::tempdir().expect("credential directory");
        let seed = [9; 32];
        let pin = encode_cache_owner_readback_signer_credential_v1(
            7,
            &SigningKey::from_bytes(&seed).verifying_key(),
        )
        .expect("Cache signer pin");
        fs::write(directory.path().join(SEED_NAME), seed).expect("seed");
        fs::set_permissions(
            directory.path().join(SEED_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .expect("seed mode");
        fs::write(directory.path().join(PIN_NAME), pin).expect("pin");
        assert!(CacheSignerCredentialV2::from_directory(directory.path()).is_err());

        let mut memory = [0; 16];
        memory[..8].copy_from_slice(MEMORY_MAGIC);
        memory[8..].copy_from_slice(&4096_u64.to_be_bytes());
        fs::write(directory.path().join(MEMORY_NAME), memory).expect("memory ceiling");
        fs::set_permissions(
            directory.path().join(MEMORY_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .expect("memory mode");
        let credential = CacheSignerCredentialV2::from_directory(directory.path())
            .expect("complete signer credential");
        let _zeroizing_heap_seed: &Zeroizing<Vec<u8>> = &credential.seed;
        assert_eq!(credential.seed.as_slice(), seed);
        assert_eq!(credential.generation(), 7);
        assert_eq!(credential.maximum_memory_bytes(), 4096);

        let foreign_pin = encode_cache_owner_readback_signer_credential_v1(
            7,
            &SigningKey::from_bytes(&[10; 32]).verifying_key(),
        )
        .expect("foreign pin");
        fs::write(directory.path().join(PIN_NAME), foreign_pin).expect("replace pin");
        assert!(CacheSignerCredentialV2::from_directory(directory.path()).is_err());
        fs::write(directory.path().join(PIN_NAME), pin).expect("restore pin");

        memory[8..].fill(0);
        fs::write(directory.path().join(MEMORY_NAME), memory).expect("zero ceiling");
        assert!(CacheSignerCredentialV2::from_directory(directory.path()).is_err());
    }
}
