//! Reads a generic controller's original registrar without issuing commands.
//!
//! The installed owner separately authenticates its surviving native capsule,
//! measured implementation and original source scope. This view reads only the
//! real SDK gate and epoch; it grants neither native nor behavioral authority.

use super::CnpController;
use crate::{
    ProviderError,
    handshake::{Handshake, RegistrationRead},
};

/// Reads the original SDK registrar beneath an authenticated generic controller.
///
/// Only the actual controller can construct the handle. It is neither clonable
/// nor deserializable, exposes no command or mutation API, and cannot replace
/// original owning capsule and kernel checks. A current registrar alone does
/// not attest that its original process remains held by an installed owner.
pub struct CnpRegistrarRead {
    registration: RegistrationRead,
}

impl CnpRegistrarRead {
    /// Compares the actual original gate and epoch without authorizing effects.
    pub fn same_original(&self, other: &Self) -> bool {
        self.registration.same_original(&other.registration)
    }

    /// Reads the real original SDK gate and registration epoch directly.
    ///
    /// No schema verifier, installed callback or native control is invoked.
    /// Native dispatch must still use the same SDK lease, whose registration
    /// check serializes the actual write against revocation.
    ///
    /// # Errors
    /// Refuses a contended, fenced or revoked original registration.
    pub fn ensure_current(&self) -> Result<(), ProviderError> {
        self.registration.ensure_current()
    }
}

impl CnpController {
    /// Issues a read-only view of this controller's authenticated original registrar.
    ///
    /// The handshake must match this same retained connection, not a decoded
    /// peer label or a replacement transport. Installed native source custody
    /// remains a separate mandatory conjunction.
    ///
    /// # Errors
    /// Refuses a fenced controller, changed original registration, or a foreign
    /// handshake. Issuance grants no class, native readiness or execution token.
    pub fn original_registrar_read(
        &self,
        handshake: &Handshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller fenced",
            ));
        }
        handshake.validate_registration(self.authority())?;
        Ok(CnpRegistrarRead {
            registration: self.authority().original_registration_read()?,
        })
    }
}
