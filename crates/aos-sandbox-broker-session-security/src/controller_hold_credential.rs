//! Validates the optional Controller-only hold signer without enabling issuance.
//!
//! The seed and AOSCTK01 pin are fixed systemd credentials. Startup checks
//! exact framing, file metadata, key correspondence, and role separation,
//! then forgets the seed. Q04 does not consume this signer yet.

use std::path::Path;

use aos_sandbox::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use aos_sandbox::policy_compiler::PinnedControllerHoldSignerV1;
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::fixed_role_credential::read_optional_fixed_role_credential_v1;

const SEED_NAME: &str = "controller-hold-signing-key";
const PIN_NAME: &str = "controller-hold-public-key";
const CACHE_PIN_NAME: &str = "cache-owner-readback-public-key";

/// Reports unsafe, partial, reused, or inconsistent Controller credentials.
#[derive(Debug, thiserror::Error)]
#[error("Controller hold signer credentials are partial, unsafe, or inconsistent")]
pub(crate) struct ControllerHoldCredentialErrorV1;

/// Validates the optional dedicated pair and drops its private seed.
pub(crate) fn validate_process_controller_hold_credentials_v1(
    broker_plan_public_key: Option<[u8; 32]>,
) -> Result<(), ControllerHoldCredentialErrorV1> {
    let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
        return Ok(());
    };
    if !Path::new(&directory).is_absolute() {
        return Err(ControllerHoldCredentialErrorV1);
    }
    validate_controller_hold_credentials_at(Path::new(&directory), broker_plan_public_key)
}

fn validate_controller_hold_credentials_at(
    directory: &Path,
    broker_plan_public_key: Option<[u8; 32]>,
) -> Result<(), ControllerHoldCredentialErrorV1> {
    let seed = read_optional_fixed_role_credential_v1(directory, SEED_NAME, 32, true)
        .map_err(|_| ControllerHoldCredentialErrorV1)?;
    let pin = read_optional_fixed_role_credential_v1(directory, PIN_NAME, 80, false)
        .map_err(|_| ControllerHoldCredentialErrorV1)?;
    let (seed, pin) = match (seed, pin) {
        (None, None) => return Ok(()),
        (Some(seed), Some(pin)) => (seed, pin),
        _ => return Err(ControllerHoldCredentialErrorV1),
    };
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        seed.as_slice()
            .try_into()
            .map_err(|_| ControllerHoldCredentialErrorV1)?,
    );
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let pinned =
        PinnedControllerHoldSignerV1::decode(&pin).map_err(|_| ControllerHoldCredentialErrorV1)?;
    if pinned.verifying_key() != &key || broker_plan_public_key == Some(key.to_bytes()) {
        return Err(ControllerHoldCredentialErrorV1);
    }
    if let Some(cache_pin) =
        read_optional_fixed_role_credential_v1(directory, CACHE_PIN_NAME, 80, false)
            .map_err(|_| ControllerHoldCredentialErrorV1)?
    {
        let cache = PinnedCacheOwnerReadbackSignerV1::decode(&cache_pin)
            .map_err(|_| ControllerHoldCredentialErrorV1)?;
        if cache.verifying_key() == &key {
            return Err(ControllerHoldCredentialErrorV1);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_sandbox::cache_residency::encode_cache_owner_readback_signer_credential_v1;
    use aos_sandbox::policy_compiler::encode_controller_hold_signer_credential_v1;

    use super::*;

    #[test]
    fn dedicated_pair_rejects_partial_reused_and_unsafe_seed() {
        let directory = tempfile::tempdir().expect("credential fixture");
        let seed = [7; 32];
        let key = SigningKey::from_bytes(&seed).verifying_key();
        let pin = encode_controller_hold_signer_credential_v1(3, &key).unwrap();
        assert!(validate_controller_hold_credentials_at(directory.path(), None).is_ok());

        let seed_path = directory.path().join(SEED_NAME);
        let pin_path = directory.path().join(PIN_NAME);
        fs::write(&seed_path, seed).unwrap();
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_controller_hold_credentials_at(directory.path(), None).is_err());
        fs::write(&pin_path, pin).unwrap();
        assert!(validate_controller_hold_credentials_at(directory.path(), None).is_ok());
        assert!(
            validate_controller_hold_credentials_at(directory.path(), Some(key.to_bytes()))
                .is_err()
        );

        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_controller_hold_credentials_at(directory.path(), None).is_err());

        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
        let cache_pin = encode_cache_owner_readback_signer_credential_v1(4, &key).unwrap();
        fs::write(directory.path().join(CACHE_PIN_NAME), cache_pin).unwrap();
        assert!(validate_controller_hold_credentials_at(directory.path(), None).is_err());
    }
}
