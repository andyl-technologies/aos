//! Signer-private Source seed paired with the independently provisioned pin.
//!
//! ```text
//! source-hold-signing-seed: Ed25519 seed[32]
//! source-hold-public-key: AOSSPK01 pin[80]
//! ```

use std::array::TryFromSliceError;
use std::path::Path;

use aos_sandbox::policy_compiler::{PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::read_optional_fixed_role_credential_v1;

const SEED_NAME: &str = "source-hold-signing-seed";
const PIN_NAME: &str = "source-hold-public-key";

/// Retains the Source-only signing seed behind the fixed service credential.
pub(crate) struct SourceSignerCredentialV1 {
    seed: Zeroizing<Vec<u8>>,
    generation: u64,
}

impl SourceSignerCredentialV1 {
    /// Loads and compares the private seed and exact Source-purpose public pin.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, malformed, or mismatched credential files.
    pub(crate) fn load() -> Result<Self, SourceSignerCredentialErrorV1> {
        let directory =
            std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(SourceSignerCredentialErrorV1)?;
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(SourceSignerCredentialErrorV1);
        }
        Self::from_directory(directory)
    }

    fn from_directory(directory: &Path) -> Result<Self, SourceSignerCredentialErrorV1> {
        let seed = read_optional_fixed_role_credential_v1(directory, SEED_NAME, 32, true)
            .map_err(|_| SourceSignerCredentialErrorV1)?
            .ok_or(SourceSignerCredentialErrorV1)?;
        let pin = read_optional_fixed_role_credential_v1(directory, PIN_NAME, 80, false)
            .map_err(|_| SourceSignerCredentialErrorV1)?
            .ok_or(SourceSignerCredentialErrorV1)?;

        let mut validation = SourceSignerCredentialValidationV1::prearmed();
        let generation = validate_source_signer_credential_v1(&seed, &pin, &mut validation)?;

        Ok(Self { seed, generation })
    }

    /// Returns the provisioned Source signer generation.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Reconstructs the signing key only for one bounded challenge response.
    ///
    /// # Errors
    ///
    /// Rejects a retained seed that no longer has the exact seed length.
    pub(crate) fn signing_key(&self) -> Result<SigningKey, SourceSignerCredentialErrorV1> {
        let seed: &[u8; 32] = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| SourceSignerCredentialErrorV1)?;
        Ok(SigningKey::from_bytes(seed))
    }
}

struct SourceSignerCredentialValidationV1 {
    // Preserve the original pin-before-key drop order on ordinary returns.
    decoded_pin: Option<Result<PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1>>,
    signing_key: Option<SigningKey>,
    seed_length: Option<Result<(), TryFromSliceError>>,
    seed_nonzero: Option<Result<(), SourceSignerCredentialErrorV1>>,
    correspondence: Option<Result<(), SourceSignerCredentialErrorV1>>,
}

impl SourceSignerCredentialValidationV1 {
    fn prearmed() -> Self {
        Self {
            decoded_pin: None,
            signing_key: None,
            seed_length: None,
            seed_nonzero: None,
            correspondence: None,
        }
    }
}

// The loader drops its validation storage on return. It borrows the original
// seed array and calls the Source-purpose decoder once.
fn validate_source_signer_credential_v1(
    seed: &Zeroizing<Vec<u8>>,
    pin: &Zeroizing<Vec<u8>>,
    validation: &mut SourceSignerCredentialValidationV1,
) -> Result<u64, SourceSignerCredentialErrorV1> {
    let seed_bytes: &[u8; 32] = match seed.as_slice().try_into() {
        Ok(seed_bytes) => {
            validation.seed_length = Some(Ok(()));
            seed_bytes
        }
        Err(error) => {
            validation.seed_length = Some(Err(error));
            return Err(SourceSignerCredentialErrorV1);
        }
    };
    if *seed_bytes == [0; 32] {
        validation.seed_nonzero = Some(Err(SourceSignerCredentialErrorV1));
        return Err(SourceSignerCredentialErrorV1);
    }
    validation.seed_nonzero = Some(Ok(()));

    let signing_key = validation
        .signing_key
        .insert(SigningKey::from_bytes(seed_bytes));
    validation.decoded_pin = Some(PinnedSourceHoldReadbackSignerV1::decode(pin));
    let pinned = match validation.decoded_pin.as_ref() {
        Some(Ok(pinned)) => pinned,
        _ => return Err(SourceSignerCredentialErrorV1),
    };
    if pinned.verifying_key() != &signing_key.verifying_key() {
        validation.correspondence = Some(Err(SourceSignerCredentialErrorV1));
        return Err(SourceSignerCredentialErrorV1);
    }
    validation.correspondence = Some(Ok(()));

    Ok(pinned.generation())
}

/// Reports an unsafe or inconsistent Source signer credential set.
#[derive(Debug, thiserror::Error)]
#[error("Source signer credentials are missing, unsafe, or inconsistent")]
pub(crate) struct SourceSignerCredentialErrorV1;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use aos_sandbox::policy_compiler::encode_source_hold_readback_signer_credential_v1;

    use super::*;

    #[test]
    fn source_seed_requires_a_matching_role_pin() {
        let directory = tempfile::tempdir().expect("credential directory");
        let seed = [7; 32];
        let pin = encode_source_hold_readback_signer_credential_v1(
            4,
            &SigningKey::from_bytes(&seed).verifying_key(),
        )
        .expect("Source pin");
        fs::write(directory.path().join(SEED_NAME), seed).expect("seed");
        fs::set_permissions(
            directory.path().join(SEED_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private seed");
        fs::write(directory.path().join(PIN_NAME), pin).expect("pin");
        assert_eq!(
            SourceSignerCredentialV1::from_directory(directory.path())
                .expect("matching Source credentials")
                .generation(),
            4
        );

        fs::write(directory.path().join(PIN_NAME), [0; 80]).expect("foreign pin");
        assert!(SourceSignerCredentialV1::from_directory(directory.path()).is_err());
        fs::write(directory.path().join(PIN_NAME), pin).expect("restore pin");
        fs::set_permissions(
            directory.path().join(SEED_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .expect("unsafe seed mode");
        assert!(SourceSignerCredentialV1::from_directory(directory.path()).is_err());
    }
}
