//! Owns the selected Cache signer key after its genuine fixed F capture.
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

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

mod retained;

pub(crate) use retained::CacheSignerCredentialCaptureV1;

const SEED_NAME: &str = "cache-signer-v2-seed";
const PIN_NAME: &str = "cache-owner-readback-public-key";
const MEMORY_NAME: &str = "cache-signer-v2-memory-ceiling";

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
