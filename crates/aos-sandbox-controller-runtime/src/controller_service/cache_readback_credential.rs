//! Validates the Controller-held v1 diagnostic Cache seed without enabling emission.
//!
//! The physical Cache owner currently runs inside the Controller process and
//! shares its UID. Startup verifies the separate-purpose seed and public pin,
//! then drops the seed: no live Create path may sign until the physical owner
//! is held in the canonical cross-owner order.

use std::path::Path;

use aos_sandbox_protocol::cache_owner_readback::PinnedCacheOwnerReadbackSignerV1;
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::CredentialOwnerPolicyV1;
use super::credential_receiving::{
    CredentialMetadataV1, CredentialSourceV1, OrdinaryCredentialSourceV1,
};

const SEED_NAME: &str = "cache-owner-readback-signing-key";
const PIN_NAME: &str = "cache-owner-readback-public-key";

#[derive(Debug, thiserror::Error)]
#[error("Cache owner readback credentials are partial, unsafe, or inconsistent")]
pub(crate) struct CacheReadbackCredentialErrorV1;

/// Verifies the optional role-specific credential pair and forgets its seed.
pub(crate) fn validate_process_cache_readback_credentials_v1(
    broker_plan_public_key: Option<[u8; 32]>,
) -> Result<(), CacheReadbackCredentialErrorV1> {
    validate_process_cache_readback_credentials_with_source(
        broker_plan_public_key, &mut OrdinaryCredentialSourceV1,
    )
}

pub(super) fn validate_process_cache_readback_credentials_with_source(
    broker_plan_public_key: Option<[u8; 32]>,
    source: &mut impl CredentialSourceV1,
) -> Result<(), CacheReadbackCredentialErrorV1> {
    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return Ok(());
    };
    source.directory(&directory);
    if !Path::new(&directory).is_absolute() {
        return Err(CacheReadbackCredentialErrorV1);
    }
    validate_cache_readback_credentials_v1_with_source(Path::new(&directory), broker_plan_public_key, source)
}

#[cfg(test)]
fn validate_cache_readback_credentials_v1(
    directory: &Path,
    broker_plan_public_key: Option<[u8; 32]>,
) -> Result<(), CacheReadbackCredentialErrorV1> {
    validate_cache_readback_credentials_v1_with_source(directory, broker_plan_public_key, &mut OrdinaryCredentialSourceV1)
}

fn validate_cache_readback_credentials_v1_with_source(
    directory: &Path,
    broker_plan_public_key: Option<[u8; 32]>,
    source: &mut impl CredentialSourceV1,
) -> Result<(), CacheReadbackCredentialErrorV1> {
    let seed = source.read(
            directory, SEED_NAME, 32, 32,
            CredentialMetadataV1::Protected {
                private: true, owner: CredentialOwnerPolicyV1::Any,
            },
        ).map(|bytes| bytes.map(Zeroizing::new))
        .map_err(|cause| {
            source.retain(cause);
            CacheReadbackCredentialErrorV1
        })?;
    let pin = source.read(
            directory, PIN_NAME, 80, 80,
            CredentialMetadataV1::Protected {
                private: false, owner: CredentialOwnerPolicyV1::Any,
            },
        ).map(|bytes| bytes.map(Zeroizing::new))
        .map_err(|cause| {
            source.retain(cause);
            CacheReadbackCredentialErrorV1
        })?;
    let (seed, pin) = match (seed, pin) {
        (None, None) => return Ok(()),
        (Some(seed), Some(pin)) => (seed, pin),
        _ => return Err(CacheReadbackCredentialErrorV1),
    };
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        seed.as_slice()
            .try_into()
            .map_err(|cause| {
                source.retain(cause);
                CacheReadbackCredentialErrorV1
            })?,
    );
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
    let pinned = PinnedCacheOwnerReadbackSignerV1::decode(&pin)
        .map_err(|cause| {
            source.retain(cause);
            CacheReadbackCredentialErrorV1
        })?;
    if pinned.verifying_key() != &verifying_key
        || broker_plan_public_key == Some(verifying_key.to_bytes())
    {
        return Err(CacheReadbackCredentialErrorV1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_sandbox_protocol::cache_owner_readback::encode_cache_owner_readback_signer_credential_v1;

    use super::*;

    #[test]
    fn selected_invalid_pin_retains_its_actual_decoder_cause() {
        use super::super::credential_receiving::CredentialAttemptV1;

        let directory = tempfile::tempdir().unwrap();
        for (name, bytes) in [(SEED_NAME, vec![9; 32]), (PIN_NAME, vec![0; 80])] {
            let path = directory.path().join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(validate_cache_readback_credentials_v1(directory.path(), None).is_err());

        let mut attempt = CredentialAttemptV1::new();
        assert!(!attempt.capture_once(|source| {
            validate_cache_readback_credentials_v1_with_source(directory.path(), None, source)
                .map(|()| Some(()))
        }));
        let cause = attempt.failure().unwrap();
        assert!(!cause.is::<CacheReadbackCredentialErrorV1>());
        let address = std::ptr::from_ref(cause).cast::<()>();

        assert!(!attempt.capture_once(|_| panic!("closed stage must retain its first decoder")));
        assert!(attempt.take_completed().is_none());
        assert_eq!(std::ptr::from_ref(attempt.failure().unwrap()).cast::<()>(), address);
    }

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
