//! Retains an explicitly requested import18 installation mechanism.
//!
//! This marker is independent of archived Source family and the legacy
//! invocation/suffix declaration. A format appearing in a roster cannot choose
//! it. The genuine factory requests this branch while constructing its fresh
//! Source, before private Birth, banks, transport or any native effect exists.

use super::*;
use crate::node_contract::RuntimeError;
use crucible_node_provider::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18Selection, native_import18_selection_construction_storage_data,
    native_import18_selection_counter_scratch_data, native_import18_selection_prewalk_data,
};
use std::mem::size_of;

#[derive(Clone, Copy)]
pub(in crate::node_adapters::cnp::semantic::packet_complete_source) enum Import18Declaration {
    Attempted,
    Selected(PacketNativeImport18Selection),
}

impl PacketCompleteSemanticSource {
    /// Prices the defining immutable mechanism comparison before construction.
    ///
    /// The actual Source factory independently admits this temporary and fixed
    /// row alongside its existing Source-copy and whole-owner obligations.
    /// The declaration is inline in the actual Source, with no new heap owner.
    ///
    /// # Errors
    /// Refuses overflow or factory comparison demand beyond `maximum`.
    pub fn native_import18_declaration_construction_storage_data(
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        let (transient, provider_scratch) =
            native_import18_selection_construction_storage_data(maximum)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        let scratch = provider_scratch
            .checked_add(Self::native_import18_declaration_counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        transient
            .checked_add(scratch)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((transient, scratch))
    }

    /// Binds the explicitly requested mechanism to the complete actual launch.
    ///
    /// Only the defining fresh Source construction path calls this method,
    /// under its independently admitted comparison row. Every selected full
    /// contract and required feature is checked by the Provider producer; this
    /// never infers a mechanism from advertised formats or captured media.
    /// Failure after entry poisons this declaration and cannot select a legacy
    /// purpose through the same Source.
    ///
    /// # Errors
    /// Refuses a foreign, already selected or prepared Source, a simultaneous
    /// legacy declaration, another actual launch, or incomplete full contracts.
    pub fn bind_native_import18_declaration_data(
        &mut self,
        selection: PacketNativeImport18Selection,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_declaration.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self.invocation_snapshot_declaration.is_some()
            || self.complete_bytes_launch_reserved.get()
            || self.registry_retention_attempted.get()
            || self.registry_retention_failed.get()
            || self.capture_banks.get_mut().is_some()
            || self.capture_execution.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.registry_capture.get_mut().is_some()
            || self.original_extension_registry.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
        };
        if !unbound {
            return Err(RuntimeError::OutstandingObligations);
        }

        self.native_import18_declaration = Some(Import18Declaration::Attempted);
        self.authenticate_native_launch_data(launch)?;
        selection
            .authenticate_launch_data(launch)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.storage_origin_with_error::<RuntimeError>()?;
        self.native_import18_declaration = Some(Import18Declaration::Selected(selection));
        Ok(())
    }

    /// Reports only the already authenticated immutable requested mechanism.
    ///
    /// This allocation-free cached DATA query is suitable before quote funding.
    /// It creates no memory credit, native admission, mapping or readiness.
    ///
    /// # Errors
    /// Refuses foreign creation or a previously failed explicit declaration.
    pub fn is_original_native_import18_declaration_data(&self) -> Result<bool, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        match self.native_import18_declaration {
            None => Ok(false),
            Some(Import18Declaration::Attempted) => Err(RuntimeError::UnsupportedFacet),
            Some(Import18Declaration::Selected(
                PacketNativeImport18Selection::SourceSignedImport18,
            )) => Ok(true),
        }
    }

    /// Names fixed guards and typed comparison views before installation.
    pub fn native_import18_declaration_counter_scratch_data() -> usize {
        native_import18_selection_prewalk_data()
            + native_import18_selection_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<Import18Declaration>()
            + size_of::<Option<Import18Declaration>>()
            + size_of::<PacketNativeImport18Selection>()
            + size_of::<bool>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<(), crucible_node_provider::ProviderError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}
