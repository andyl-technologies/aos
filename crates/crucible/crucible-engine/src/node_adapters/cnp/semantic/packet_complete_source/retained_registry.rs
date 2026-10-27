//! Retains metadata custody of the actual known installed typed registry family.
//!
//! Registry state is obtained from the SAME original process custody, never from
//! an empty-roster assertion or caller-provided metadata. This loan counts actual
//! backing; it does not verify negotiation, activate a native marker or replace
//! the Source's controller/registrar/semantic authority checks.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_transport::handshake::OriginalExtensionRegistryOwner;
use std::cell::Ref;

impl PacketCompleteSemanticSource {
    /// Retains the actual original process's known installed registry owner once.
    ///
    /// The genuine realization scope already binds this source and controller
    /// to its original native custody. The process forwards its retained typed
    /// Handshake to the SDK's same-Rc registry owner constructor. Partial/final
    /// guard failures keep the owner and make this attempt sticky.
    ///
    /// # Errors
    /// Refuses foreign scope/origin, unknown erased callbacks, another installed
    /// registry, repeated failed custody or any changed current process fence.
    pub fn retain_original_extension_registry_metadata_owner(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.registry_retention_failed.get() {
            return Err(refused(
                "original extension registry retention already failed",
            ));
        }
        self.authenticate_witness_scope(scope)?;
        let mut slot = self
            .original_extension_registry
            .try_borrow_mut()
            .map_err(|_| refused("original extension registry custody already borrowed"))?;
        if let Some(owner) = slot.as_ref() {
            let result = scope
                .native
                .authenticate_original_extension_registry_metadata_owner(owner)
                .and_then(|()| self.authenticate_witness_scope(scope));
            if result.is_err() {
                self.registry_retention_failed.set(true);
            }
            return result;
        }
        if self.registry_retention_attempted.replace(true) {
            return Err(refused(
                "original extension registry retained attempt is incomplete",
            ));
        }
        let result = (|| {
            *slot = Some(scope.native.original_extension_registry_metadata_owner()?);
            let owner = slot
                .as_ref()
                .ok_or_else(|| refused("original extension registry owner absent"))?;
            scope
                .native
                .authenticate_original_extension_registry_metadata_owner(owner)?;
            self.authenticate_witness_scope(scope)
        })();
        if result.is_err() {
            self.registry_retention_failed.set(true);
        }
        result
    }

    /// Borrows actual retained registry metadata custody without issuing authority.
    ///
    /// The factory/node metadata observer still authenticates this loan against
    /// the actual SAME process/typed Handshake before closing its erased owner
    /// row. The private SDK owner has no data or caller-field constructor.
    ///
    /// # Errors
    /// Refuses foreign origin, failed/unissued ownership or a borrowed slot.
    pub fn original_extension_registry_owner_data(
        &self,
    ) -> Result<Ref<'_, OriginalExtensionRegistryOwner>, OperationFailure> {
        self.original_extension_registry_owner_data_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_extension_registry_owner_data_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<Ref<'_, OriginalExtensionRegistryOwner>, E> {
        self.storage_origin_with_error::<E>()?;
        if !self.registry_retention_attempted.get() || self.registry_retention_failed.get() {
            return Err(E::refused(
                "original extension registry metadata custody incomplete",
            ));
        }
        let slot = self
            .original_extension_registry
            .try_borrow()
            .map_err(|_| E::refused("original extension registry metadata already borrowed"))?;
        Ref::filter_map(slot, Option::as_ref)
            .map_err(|_| E::refused("original extension registry metadata owner absent"))
    }

    /// Counts actual known registry and creator backing from the retained owner.
    ///
    /// This is requested storage only. The enclosing inline Option/header is
    /// already in the source Rc row; foreign/unknown callback state is not zero.
    ///
    /// # Errors
    /// Refuses missing/unknown custody, SDK origin failure or storage overrun.
    pub fn original_extension_registry_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.original_extension_registry_storage_data_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_extension_registry_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let owner = self.original_extension_registry_owner_data_with_error::<E>()?;
        Self::complete_retained_metadata_storage_with_error::<E>(
            &owner
                .original_retained_metadata_facts()
                .map_err(E::unknown)?,
            maximum,
        )
    }
}
