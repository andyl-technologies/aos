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
    /// Reports actual retained original registrar allocation data after revocation.
    ///
    /// This reads the two real Arc payload views and inline saved epoch without
    /// locking, renewal, callbacks or I/O. A plain registrar handle has no creator
    /// field; the owning source capsule must check its actual PID/thread first.
    /// These facts do not prove the saved epoch remains current.
    ///
    /// # Errors
    /// Reports checked traversal or requested-layout overflow.
    pub fn retained_metadata_facts_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let Self { registration } = self;
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        registration.observe_retained_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Compares the actual original gate and epoch without authorizing effects.
    pub fn same_original(&self, other: &Self) -> bool {
        self.registration.same_original(&other.registration)
    }

    /// Reads the real original SDK gate and registration epoch directly.
    ///
    /// No schema verifier, installed callback or native control is invoked.
    /// Native dispatch must still use the same SDK lease. Its gate serializes
    /// bounded journal registration against revocation; subsequent socket writes
    /// remain outside that mutex. Immediate transport checks and custody of
    /// already registered original work remain separate obligations.
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

    /// Retains the same original controller read under its typed handshake.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, fenced actor, replaced registration or
    /// another typed handshake. This creates no native or restoration permission.
    pub fn original_registrar_read_extensions(
        &self,
        handshake: &crate::handshake::ExtensionHandshake,
    ) -> Result<CnpRegistrarRead, ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller fenced",
            ));
        }
        handshake.verify_authority(self.authority())?;
        Ok(CnpRegistrarRead {
            registration: self.authority().original_registration_read()?,
        })
    }
}
