//! Emits the existing seed/public-pin comparison engine into private owners.
//!
//! The macro exposes no callable credential, private key or role constructor.
//! Each invocation lives inside a private validation module and binds its own
//! private error type; native reads, secret ownership and real financial entry
//! stay with the actual selected or ordinary application owner.

/// Emits the sole Source seed/pin comparison implementation with private visibility.
///
/// The caller's private module must import its private
/// `SourceSignerCredentialErrorV1` from its own parent.
#[doc(hidden)]
#[macro_export]
macro_rules! define_source_credential_validation_v1 {
    () => {
use std::error::Error;

use $crate::source_signer_data::{PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1};
use ed25519_dalek::SigningKey;

use super::SourceSignerCredentialErrorV1;

#[derive(Clone, Copy)]
enum Failure {
    Shape,
    ZeroSeed,
    Pin,
    Correspondence,
    Closed,
}

/// Retains one exact seed/pin comparison under its caller's disposition.
pub(super) struct SourceCredentialValidationV1 {
    // Field order preserves ordinary reverse-local destruction: pin then key.
    pin: Option<Result<PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1>>,
    key: Option<SigningKey>,
    shape: Option<Result<(), std::array::TryFromSliceError>>,
    completion: Option<Result<u64, SourceSignerCredentialErrorV1>>,
    first: Option<Failure>,
    entered: bool,
    refused: SourceSignerCredentialErrorV1,
}

impl SourceCredentialValidationV1 {
    /// Creates an empty comparison owner without deriving or decoding a key.
    pub(super) fn new() -> Self {
        Self {
            pin: None, key: None, shape: None, completion: None,
            first: None, entered: false, refused: SourceSignerCredentialErrorV1,
        }
    }

    /// Validates the nonzero seed and its canonical independent Source pin once.
    ///
    /// # Errors
    /// Retains seed-shape, pin-decoding, correspondence or repeated-entry refusal.
    pub(super) fn validate_once(&mut self, seed: &[u8], pin: &[u8]) -> Result<u64, SourceSignerCredentialErrorV1> {
        if self.entered {
            self.first.get_or_insert(Failure::Closed);
            return Err(SourceSignerCredentialErrorV1);
        }
        self.entered = true;
        self.completion = Some(self.validate_inner(seed, pin));
        match &self.completion {
            Some(Ok(generation)) => Ok(*generation),
            _ => Err(SourceSignerCredentialErrorV1),
        }
    }

    fn validate_inner(&mut self, seed: &[u8], pin: &[u8]) -> Result<u64, SourceSignerCredentialErrorV1> {
        let seed: &[u8; 32] = match seed.try_into() {
            Ok(seed) => { self.shape = Some(Ok(())); seed }
            Err(error) => {
                self.shape = Some(Err(error));
                self.first = Some(Failure::Shape);
                return Err(SourceSignerCredentialErrorV1);
            }
        };
        if *seed == [0; 32] {
            self.first = Some(Failure::ZeroSeed);
            return Err(SourceSignerCredentialErrorV1);
        }

        self.key = Some(SigningKey::from_bytes(seed));
        self.pin = Some(PinnedSourceHoldReadbackSignerV1::decode(pin));
        let pinned = match self.pin.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(pinned) => pinned,
            None => {
                self.first = Some(Failure::Pin);
                return Err(SourceSignerCredentialErrorV1);
            }
        };
        if self.key.as_ref().is_none_or(|key| pinned.verifying_key() != &key.verifying_key()) {
            self.first = Some(Failure::Correspondence);
            return Err(SourceSignerCredentialErrorV1);
        }
        Ok(pinned.generation())
    }

    /// Borrows the completed private key together with its actual pin generation.
    pub(super) fn signing_inputs(&self) -> Option<(&SigningKey, u64)> {
        if self.first.is_some() { return None; }
        let generation = *self.completion.as_ref()?.as_ref().ok()?;
        Some((self.key.as_ref()?, generation))
    }

    /// Borrows the first retained native DATA decoding or comparison refusal.
    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            Failure::Shape => self.shape.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _),
            Failure::Pin => self.pin.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _),
            _ => None,
        };
        cause.or(Some(&self.refused))
    }
}

    };
}
