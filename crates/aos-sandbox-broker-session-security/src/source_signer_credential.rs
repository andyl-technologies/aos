//! Signer-private Source seed paired with the independently provisioned pin.
//!
//! ```text
//! source-hold-signing-seed: Ed25519 seed[32]
//! source-hold-public-key: AOSSPK01 pin[80]
//! ```

use std::array::TryFromSliceError;
use std::path::Path;

use aos_sandbox::policy_compiler::{PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1};
use aos_sandbox_linux::credential::{FixedRoleCredentialReadV1, FixedRoleCredentialReadViewV1};
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

/// Parks the original Source seed, pin, and reached correspondence outcomes.
///
/// This dormant seam is not selected by `load` or any service startup. It owns
/// file acquisition and Source-purpose validation custody only, without a
/// receiving lender, funded memory claim, or admission authority. Partial
/// buffers stay zeroizing; the actual dalek key retains its enabled
/// zeroize-on-drop behavior. Inner codec and cryptographic temporaries are not
/// retained by this reservoir.
pub(crate) struct SourceSignerCredentialReadV1 {
    // Validation drops the public pin and derived key before the raw buffers.
    validation: SourceSignerCredentialValidationV1,
    pin: FixedRoleCredentialReadV1,
    seed: FixedRoleCredentialReadV1,
    seed_required: Option<Result<(), SourceSignerCredentialErrorV1>>,
    pin_required: Option<Result<(), SourceSignerCredentialErrorV1>>,
    completion: Option<Result<u64, SourceSignerCredentialErrorV1>>,
    entered: bool,
}

/// Borrows reached Source acquisition and validation outcomes without replay.
pub(crate) struct SourceSignerCredentialReadViewV1<'a> {
    /// Borrows the seed reader's original file acquisition results.
    pub(crate) seed: FixedRoleCredentialReadViewV1<'a>,
    /// Borrows the pin reader's original file acquisition results.
    pub(crate) pin: FixedRoleCredentialReadViewV1<'a>,
    /// Borrows the required-seed projection, which rejects optional absence.
    pub(crate) seed_required: Option<&'a Result<(), SourceSignerCredentialErrorV1>>,
    /// Borrows the required-pin projection, which rejects optional absence.
    pub(crate) pin_required: Option<&'a Result<(), SourceSignerCredentialErrorV1>>,
    /// Borrows the native seed-length conversion error if it was reached.
    pub(crate) seed_length: Option<&'a Result<(), TryFromSliceError>>,
    /// Borrows the reached all-zero seed rejection or its successful check.
    pub(crate) seed_nonzero: Option<&'a Result<(), SourceSignerCredentialErrorV1>>,
    /// Borrows the one existing Source-purpose decoder result.
    pub(crate) decoded_pin:
        Option<&'a Result<PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1>>,
    /// Borrows the reached seed/pin correspondence result.
    pub(crate) correspondence: Option<&'a Result<(), SourceSignerCredentialErrorV1>>,
    /// Borrows the required Source completion, including its original error.
    pub(crate) completion: Option<&'a Result<u64, SourceSignerCredentialErrorV1>>,
}

/// Borrows the actual key only after complete required Source correspondence.
///
/// This is credential custody, without a startup or payment capability.
pub(crate) struct SourceSignerCredentialReadSuccessV1<'a> {
    /// Carries the generation from the same successfully decoded Source pin.
    pub(crate) generation: u64,
    /// Borrows the actual derived, zeroize-on-drop key retained by this read.
    pub(crate) signing_key: &'a SigningKey,
}

impl SourceSignerCredentialReadV1 {
    /// Constructs both empty readers and validation storage before file access.
    pub(crate) fn prearmed() -> Self {
        Self {
            validation: SourceSignerCredentialValidationV1::prearmed(),
            pin: FixedRoleCredentialReadV1::prearmed(),
            seed: FixedRoleCredentialReadV1::prearmed(),
            seed_required: None,
            pin_required: None,
            completion: None,
            entered: false,
        }
    }

    /// Reads the fixed seed and pin once and parks the reached native results.
    ///
    /// Later entries preserve the first attempt even after absence or failure.
    /// The ordinary lower reader still treats missing files as optional `None`;
    /// only this existing Source required-credential projection rejects them.
    pub(crate) fn read_once(&mut self, directory: &Path) {
        if self.entered {
            return;
        }
        self.entered = true;

        self.completion = Some(self.read_directory(directory));
    }

    fn read_directory(&mut self, directory: &Path) -> Result<u64, SourceSignerCredentialErrorV1> {
        self.seed.read_fixed_once(directory, SEED_NAME, 32, true);
        self.seed_required = Some(match self.seed.outcome() {
            Some(Ok(Some(_))) => Ok(()),
            _ => Err(SourceSignerCredentialErrorV1),
        });
        if !matches!(self.seed_required, Some(Ok(()))) {
            return Err(SourceSignerCredentialErrorV1);
        }

        self.pin.read_fixed_once(directory, PIN_NAME, 80, false);
        self.pin_required = Some(match self.pin.outcome() {
            Some(Ok(Some(_))) => Ok(()),
            _ => Err(SourceSignerCredentialErrorV1),
        });
        if !matches!(self.pin_required, Some(Ok(()))) {
            return Err(SourceSignerCredentialErrorV1);
        }

        let seed = match self.seed.outcome() {
            Some(Ok(Some(seed))) => seed,
            _ => return Err(SourceSignerCredentialErrorV1),
        };
        let pin = match self.pin.outcome() {
            Some(Ok(Some(pin))) => pin,
            _ => return Err(SourceSignerCredentialErrorV1),
        };
        validate_source_signer_credential_v1(seed, pin, &mut self.validation)
    }

    /// Borrows the retained key only after both required reads and validation.
    pub(crate) fn completed(&self) -> Option<SourceSignerCredentialReadSuccessV1<'_>> {
        let generation = match self.completion.as_ref()? {
            Ok(generation) => *generation,
            Err(_) => return None,
        };

        Some(SourceSignerCredentialReadSuccessV1 {
            generation,
            signing_key: self.validation.signing_key.as_ref()?,
        })
    }

    /// Borrows the original reached results without cloning keys or causes.
    pub(crate) fn view(&self) -> SourceSignerCredentialReadViewV1<'_> {
        SourceSignerCredentialReadViewV1 {
            seed: self.seed.view(),
            pin: self.pin.view(),
            seed_required: self.seed_required.as_ref(),
            pin_required: self.pin_required.as_ref(),
            seed_length: self.validation.seed_length.as_ref(),
            seed_nonzero: self.validation.seed_nonzero.as_ref(),
            decoded_pin: self.validation.decoded_pin.as_ref(),
            correspondence: self.validation.correspondence.as_ref(),
            completion: self.completion.as_ref(),
        }
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

// The ordinary loader supplies local storage and drops it on return. The
// retained reader supplies its prearmed storage to this same validation body;
// neither path copies the seed array or calls the purpose decoder twice.
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
