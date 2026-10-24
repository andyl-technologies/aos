//! Retains selected Source startup's whole fixed credential read prefix.
//!
//! Entry is private to the Source executable after its genuine original debit.
//! This DATA/secret owner cannot create a Native service original or funding.

use std::error::Error;
use std::path::Path;

use aos_sandbox_linux::credential::FixedRoleCredentialReadV1;
use ed25519_dalek::SigningKey;

use super::validation::SourceCredentialValidationV1;
use super::{PIN_NAME, SEED_NAME, SourceSignerCredentialErrorV1};

#[derive(Clone, Copy)]
enum Failure { Seed, Pin, Validation, Closed }

/// Retains the selected Source credential originals and independently pinned key.
pub(crate) struct SourceSignerCredentialCaptureV1 {
    // Validation drops before its original pin and seed read reservoirs.
    validation: SourceCredentialValidationV1,
    pin: FixedRoleCredentialReadV1,
    seed: FixedRoleCredentialReadV1,
    first: Option<Failure>,
    entered: bool,
    refused: SourceSignerCredentialErrorV1,
}

impl SourceSignerCredentialCaptureV1 {
    /// Creates empty fixed credential storage without opening any input.
    pub(crate) fn new() -> Self {
        Self {
            validation: SourceCredentialValidationV1::new(),
            pin: FixedRoleCredentialReadV1::prearmed(),
            seed: FixedRoleCredentialReadV1::prearmed(),
            first: None, entered: false, refused: SourceSignerCredentialErrorV1,
        }
    }

    /// Captures both exact fixed files and performs the shared correspondence check.
    ///
    /// # Errors
    /// Retains unavailable/unsafe/inexact reads, a bad seed or pin, mismatched
    /// keys, and reentry without replacing any earlier file or native cause.
    pub(crate) fn capture_once(&mut self, directory: &Path) -> Result<(), SourceSignerCredentialErrorV1> {
        if self.entered {
            self.first.get_or_insert(Failure::Closed);
            return Err(SourceSignerCredentialErrorV1);
        }
        self.entered = true;
        self.seed.read_fixed_once(directory, SEED_NAME, 32, true);
        let seed = match self.seed.outcome() {
            Some(Ok(Some(seed))) => seed,
            _ => { self.first = Some(Failure::Seed); return Err(SourceSignerCredentialErrorV1); }
        };
        self.pin.read_fixed_once(directory, PIN_NAME, 80, false);
        let pin = match self.pin.outcome() {
            Some(Ok(Some(pin))) => pin,
            _ => { self.first = Some(Failure::Pin); return Err(SourceSignerCredentialErrorV1); }
        };
        if self.validation.validate_once(seed, pin).is_err() {
            self.first = Some(Failure::Validation);
            return Err(SourceSignerCredentialErrorV1);
        }
        Ok(())
    }

    /// Borrows only the independently pinned key and generation after completion.
    pub(crate) fn signing_inputs(&self) -> Option<(&SigningKey, u64)> {
        if self.first.is_some() || !self.entered { return None; }
        self.validation.signing_inputs()
    }

    /// Borrows the earliest retained credential or correspondence failure.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            Failure::Seed => self.seed.failure(),
            Failure::Pin => self.pin.failure(),
            Failure::Validation => self.validation.failure(),
            Failure::Closed => None,
        };
        cause.or(Some(&self.refused))
    }
}

#[cfg(test)]
mod tests;
