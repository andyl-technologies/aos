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
    /// Borrows inert saved and sampled registrar epochs with their alias roles.
    ///
    /// This projection may describe a revoked or contended original. The owning
    /// capture boundary separately fences currentness and records the actual
    /// shared gate and epoch edges; decoding never creates a registration.
    /// Serialization uses only inline sampled data and borrowed static labels.
    pub fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        self.registration.borrowed_settled_history_data()
    }

    /// Records the original shared backing edges without resetting the observer.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self { registration } = self;
        registration.observe_retained_metadata_data(observer)
    }

    /// Records inert original capacities and aliases in caller-precharged banks.
    ///
    /// Both banks are cleared before this independent owner pass. A whole SDK
    /// graph uses the internal nonresetting walker instead. Walking never grows
    /// either bank, locks the registrar, or renews its saved epoch.
    ///
    /// # Errors
    /// Refuses insufficient admitted rows or checked metadata overflow, retaining
    /// already recorded partial rows in the supplied banks.
    pub fn record_settled_history_metadata_data(
        &self,
        records: &mut crate::retained_metadata::records::MetadataRecordBank,
        aliases: &mut crate::retained_metadata::aliases::MetadataAliasBank,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer =
            crate::retained_metadata::MetadataObserver::recording_with_aliases(records, aliases);
        self.observe_settled_history_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Reports fixed borrowed projection and recorder views before walking.
    ///
    /// Caller-owned dynamic record/alias banks, serializer output and aggregate
    /// graph traversal are independent terms; this getter grants no admission.
    pub fn settled_history_counter_scratch_data() -> usize {
        use std::mem::{size_of, size_of_val};

        let terms = [
            size_of::<CnpRegistrarRead>(),
            size_of::<&CnpRegistrarRead>(),
            size_of::<&RegistrationRead>(),
            size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>(),
            size_of::<Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>>(
            ),
            size_of::<&mut crate::retained_metadata::MetadataObserver<'_>>(),
            size_of::<&mut crate::retained_metadata::records::MetadataRecordBank>(),
            size_of::<&mut crate::retained_metadata::aliases::MetadataAliasBank>(),
            RegistrationRead::settled_history_counter_scratch_data(),
        ];
        size_of_val(&terms)
            + size_of::<std::array::IntoIter<usize, 9>>()
            + terms.into_iter().sum::<usize>()
    }

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

    /// Checks historical parent identity without requiring a still-live epoch.
    pub(crate) fn same_authority_data(
        &self,
        authority: &crate::handshake::ConnectionAuthority,
    ) -> bool {
        self.registration.same_authority_data(authority)
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

impl CnpController {
    /// Authenticates this actual Session and Connection's historical registrar.
    ///
    /// This checks the two retained authority copies without locking a gate,
    /// cloning registration handles, renewing a deadline or requiring live
    /// currentness. The capture owner separately holds its SourceRead fence.
    ///
    /// # Errors
    /// Refuses another actual gate, epoch backing, saved registration or
    /// controller role; matching portable values never replace these edges.
    pub fn authenticate_source_registrar_history_data(
        &self,
        read: &CnpRegistrarRead,
    ) -> Result<(), ProviderError> {
        self.session
            .authenticate_source_registrar_history_data(read)
    }

    /// Reports the defining two-copy historical registration comparison views.
    ///
    /// The leaf registrar counter never calls Session, preserving an acyclic
    /// quote. Whole owner output and dynamic metadata banks remain separate.
    pub fn source_registrar_history_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&CnpRegistrarRead>()
            + std::mem::size_of::<Result<(), ProviderError>>()
            + crate::client::ClientSession::source_registrar_history_counter_scratch_data()
    }
}
