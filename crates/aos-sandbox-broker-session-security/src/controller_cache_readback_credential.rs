//! Validates the provisioned Cache-only signer seed without enabling emission.
//!
//! The physical Cache owner currently runs inside the Controller process and
//! shares its UID. Startup verifies the separate-purpose seed and public pin,
//! then drops the seed: no live Create path may sign until the physical owner
//! is held in the canonical cross-owner order.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use aos_sandbox::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use ed25519_dalek::SigningKey;
use rustix::fs::{CWD, Mode, OFlags, openat};
use zeroize::Zeroizing;

const SEED_NAME: &str = "cache-owner-readback-signing-key";
const PIN_NAME: &str = "cache-owner-readback-public-key";

#[derive(Debug, thiserror::Error)]
#[error("Cache owner readback credentials are partial, unsafe, or inconsistent")]
pub(crate) struct CacheReadbackCredentialErrorV1;

/// Verifies the optional role-specific credential pair and forgets its seed.
pub(crate) fn validate_process_cache_readback_credentials_v1(
    broker_plan_public_key: Option<[u8; 32]>,
) -> Result<(), CacheReadbackCredentialErrorV1> {
    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return Ok(());
    };
    if !Path::new(&directory).is_absolute() {
        return Err(CacheReadbackCredentialErrorV1);
    }
    validate_cache_readback_credentials_v1(Path::new(&directory), broker_plan_public_key)
}

fn validate_cache_readback_credentials_v1(
    directory: &Path,
    broker_plan_public_key: Option<[u8; 32]>,
) -> Result<(), CacheReadbackCredentialErrorV1> {
    let seed = read_optional_fixed(directory, SEED_NAME, 32, true)?;
    let pin = read_optional_fixed(directory, PIN_NAME, 80, false)?;
    let (seed, pin) = match (seed, pin) {
        (None, None) => return Ok(()),
        (Some(seed), Some(pin)) => (seed, pin),
        _ => return Err(CacheReadbackCredentialErrorV1),
    };
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        seed.as_slice()
            .try_into()
            .map_err(|_| CacheReadbackCredentialErrorV1)?,
    );
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
    let pinned = PinnedCacheOwnerReadbackSignerV1::decode(&pin)
        .map_err(|_| CacheReadbackCredentialErrorV1)?;
    if pinned.verifying_key() != &verifying_key
        || broker_plan_public_key == Some(verifying_key.to_bytes())
    {
        return Err(CacheReadbackCredentialErrorV1);
    }
    Ok(())
}

fn read_optional_fixed(
    directory: &Path,
    name: &str,
    length: u64,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, CacheReadbackCredentialErrorV1> {
    let descriptor = match openat(
        CWD,
        directory.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(CacheReadbackCredentialErrorV1),
    };
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| CacheReadbackCredentialErrorV1)?;
    if !metadata.is_file()
        || metadata.len() != length
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || private && metadata.mode() & 0o077 != 0
    {
        return Err(CacheReadbackCredentialErrorV1);
    }
    let mut bytes = Zeroizing::new(vec![0; length as usize]);
    file.read_exact(&mut bytes)
        .map_err(|_| CacheReadbackCredentialErrorV1)?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|_| CacheReadbackCredentialErrorV1)?
        != 0
    {
        return Err(CacheReadbackCredentialErrorV1);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_sandbox::cache_residency::encode_cache_owner_readback_signer_credential_v1;

    use super::*;

    #[test]
    fn cache_seed_requires_own_role_pin_and_rejects_broker_key_reuse() {
        let directory = tempfile::tempdir().expect("credential fixture");
        let seed = [9; 32];
        let key = SigningKey::from_bytes(&seed).verifying_key();
        let pin = encode_cache_owner_readback_signer_credential_v1(3, &key).expect("pin");
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_ok());

        let seed_path = directory.path().join(SEED_NAME);
        let pin_path = directory.path().join(PIN_NAME);
        fs::write(&seed_path, seed).expect("seed fixture");
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_err());
        fs::write(&pin_path, pin).expect("pin fixture");
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_ok());
        assert!(
            validate_cache_readback_credentials_v1(directory.path(), Some(key.to_bytes())).is_err()
        );

        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644))
            .expect("unsafe seed mode");
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_err());
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600))
            .expect("restore seed mode");

        let unrelated = SigningKey::from_bytes(&[10; 32]).verifying_key();
        let wrong_key =
            encode_cache_owner_readback_signer_credential_v1(3, &unrelated).expect("wrong key pin");
        fs::write(&pin_path, wrong_key).expect("wrong key fixture");
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_err());

        let mut wrong_role = pin;
        wrong_role[..8].copy_from_slice(b"AOSPPK01");
        fs::write(&pin_path, wrong_role).expect("wrong role fixture");
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_err());
    }
}
