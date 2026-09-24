//! Dedicated root-owned Storage ZFS hold receipt signing-key custody.
//!
//! ```text
//! AOSZHK01 | version:u16be=1 | reserved[6]=0 |
//! authority-id[16] | authority-generation:u64be |
//! authority-digest[32] | key-id[16] | key-generation:u64be |
//! ed25519-public[32] | ed25519-seed[32]
//! ```
//!
//! This systemd credential is separate from the LocalLive lease key and
//! operator Repair key. It is pinned at Storage startup and rechecked against
//! the exact credential directory, file identity, and bytes. Signing remains
//! unavailable until Storage can join a protected catalog head, held ZFS
//! readback, and durable Provider attempt under one owner admission.

use std::path::PathBuf;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::storage_zfs_hold_receipt::{
    StorageZfsHoldSignerV1, StorageZfsHoldVerifierV1,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::operator_recovery_credentials::{
    FileIdentity, PinnedCredential, open_directory, read_credential,
};
use crate::service::StorageServiceError;

const CREDENTIAL_NAME: &str = "storage-zfs-hold-key-v1";
const MAGIC: &[u8; 8] = b"AOSZHK01";
const VERSION: u16 = 1;
const KEY_BYTES: usize = 160;

/// Pins the separately provisioned Storage ZFS hold receipt role key.
pub struct StorageZfsHoldKeyV1 {
    directory: PathBuf,
    directory_identity: FileIdentity,
    key: PinnedCredential,
    signer: StorageZfsHoldSignerV1,
    verifier: StorageZfsHoldVerifierV1,
    seed: Zeroizing<[u8; 32]>,
}

impl StorageZfsHoldKeyV1 {
    /// Loads the fixed systemd credential without creating signing authority.
    ///
    /// # Errors
    ///
    /// Rejects an absent, aliased, unsafe, malformed, or changed credential.
    pub fn load() -> Result<Self, StorageServiceError> {
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or_else(|| invalid("Storage ZFS hold credential directory is absent"))?;
        let (fd, directory_identity) = open_directory(&directory)?;
        let key = read_credential(&fd, CREDENTIAL_NAME, KEY_BYTES)?;
        let (signer, verifier, seed) = decode_key_record(&key.bytes)?;
        let retained = Self {
            directory,
            directory_identity,
            key,
            signer,
            verifier,
            seed,
        };
        retained.recheck()?;
        Ok(retained)
    }

    /// Reopens the exact protected key and refuses rotation within this process.
    ///
    /// # Errors
    ///
    /// Rejects any changed directory, file identity, metadata, or key bytes.
    pub fn recheck(&self) -> Result<(), StorageServiceError> {
        let (fd, identity) = open_directory(&self.directory)?;
        if identity != self.directory_identity {
            return Err(invalid("Storage ZFS hold credential directory changed"));
        }
        let current = read_credential(&fd, self.key.name, KEY_BYTES)?;
        if current.identity != self.key.identity || current.bytes != self.key.bytes {
            return Err(invalid("Storage ZFS hold credential changed"));
        }
        let (signer, verifier, seed) = decode_key_record(&current.bytes)?;
        if signer != self.signer || verifier != self.verifier || seed != self.seed {
            return Err(invalid("Storage ZFS hold credential changed"));
        }
        Ok(())
    }

    /// Returns the public verifier projection for trusted publication.
    #[must_use]
    pub const fn verifier(&self) -> StorageZfsHoldVerifierV1 {
        self.verifier
    }
}

fn decode_key_record(
    bytes: &[u8],
) -> Result<
    (
        StorageZfsHoldSignerV1,
        StorageZfsHoldVerifierV1,
        Zeroizing<[u8; 32]>,
    ),
    StorageServiceError,
> {
    if bytes.len() != KEY_BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0; 6].as_slice())
    {
        return Err(invalid("Storage ZFS hold key record is noncanonical"));
    }
    let authority_id = array(bytes, 16)?;
    let authority_generation = u64::from_be_bytes(array(bytes, 32)?);
    let authority_digest = ObjectDigest::from_bytes(array(bytes, 40)?);
    let key_id = array(bytes, 72)?;
    let key_generation = u64::from_be_bytes(array(bytes, 88)?);
    let public_key = array(bytes, 96)?;
    let seed = Zeroizing::new(array(bytes, 128)?);
    if *seed == [0; 32] || SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public_key {
        return Err(invalid(
            "Storage ZFS hold signing key does not match public key",
        ));
    }
    let signer = StorageZfsHoldSignerV1::new(
        authority_id,
        authority_generation,
        authority_digest,
        key_id,
        key_generation,
    )
    .map_err(|_| invalid("Storage ZFS hold signer is invalid"))?;
    let verifier = StorageZfsHoldVerifierV1::new(signer, public_key)
        .map_err(|_| invalid("Storage ZFS hold public key is invalid"))?;
    Ok((signer, verifier, seed))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], StorageServiceError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid("Storage ZFS hold key record is truncated"))
}

fn invalid(message: &str) -> StorageServiceError {
    StorageServiceError::Activation(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> [u8; KEY_BYTES] {
        let mut bytes = [0; KEY_BYTES];
        let seed = [7; 32];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..32].copy_from_slice(&[1; 16]);
        bytes[32..40].copy_from_slice(&2_u64.to_be_bytes());
        bytes[40..72].copy_from_slice(&[3; 32]);
        bytes[72..88].copy_from_slice(&[4; 16]);
        bytes[88..96].copy_from_slice(&5_u64.to_be_bytes());
        bytes[96..128].copy_from_slice(&SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        bytes[128..160].copy_from_slice(&seed);
        bytes
    }

    #[test]
    fn dedicated_role_key_rejects_malformed_and_mismatched_records() {
        assert!(decode_key_record(&record()).is_ok());
        for index in [0, 8, 10, 16, 40, 72, 96, 128] {
            let mut changed = record();
            changed[index] ^= 1;
            if index == 16 || index == 40 || index == 72 {
                // Nonzero identities may change, but their signature role is
                // still bound by the protected exact-byte recheck.
                assert!(decode_key_record(&changed).is_ok());
            } else {
                assert!(decode_key_record(&changed).is_err(), "byte {index}");
            }
        }
    }
}
