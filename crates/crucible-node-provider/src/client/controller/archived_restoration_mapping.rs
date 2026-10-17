//! Prepares exact selected cold mappings on the same fresh controller.

use super::*;

impl CnpController {
    /// Retains an actual complete startup-Capture mapping without installation.
    ///
    /// The native class comes only from the immutable decoder-produced owner.
    /// Source MAC, installed storage admission and the native lease are separate.
    ///
    /// # Errors
    /// Refuses occupied output, old/partial cold owners, changed verified body
    /// references, a stale controller/codec/cut or another fresh scope/nonce.
    pub fn prepare_original_selected_archived_mapping_into(
        &mut self,
        host: &crate::protocol_snapshot::owned11::outer::SealedHistoricalControllerState,
        native: &crate::protocol_snapshot::owned11::native::outer::SealedHistoricalNativeState,
        archive_protocol: &ContentRef,
        native_protocol: &ContentRef,
        nonce: [u8; 32],
        completed: &mut Option<crate::protocol_snapshot::PreparedArchivedProtocolMapping>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if completed.is_some() {
            return Err(ProviderError::Conflict(
                "archived mapping result slot occupied",
            ));
        }
        if let Some(assigned) = &self.original_ack_admit {
            assigned.validate_owned_snapshot()?;
        }
        self.ensure_no_pending_original_complete_restore()?;
        self.session.begin_original_ack_admit(self.budget)?;
        let input = crate::protocol_snapshot::ArchivedProtocolMappingInput {
            host,
            native,
            archive_protocol,
            native_protocol,
            nonce,
        };
        let mapping = self
            .session
            .prepare_original_selected_archived_mapping(input, &self.protocol_owner)?;
        *completed = Some(mapping);
        self.authenticate_archived_protocol_mapping(
            completed
                .as_ref()
                .ok_or(ProviderError::Correlation("archived mapping result absent"))?,
        )
    }

    /// Bounds the independent mapping root and authority clone before construction.
    ///
    /// The caller separately counts the two actual historical ContentRef clones,
    /// the existing sealed owners, all actual current owners and normalization
    /// output. Rc handles retain existing controller/connection/codec allocations;
    /// only the mapping identity creates a new Rc allocation. This numeric DATA
    /// grants no installed action or permission to prepare a transaction.
    ///
    /// # Errors
    /// Refuses a stale actual controller/registration or checked layout overflow.
    pub fn original_archived_mapping_construction_storage_data(
        &self,
    ) -> Result<usize, ProviderError> {
        use crate::protocol_snapshot::{
            ArchivedProtocolMappingIdentity, PreparedArchivedProtocolMapping,
        };
        self.protocol_owner.ensure_current()?;
        let identity = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<ArchivedProtocolMappingIdentity>())
            .map_err(|_| ProviderError::ResourceExhausted("archived mapping identity layout"))?
            .0
            .pad_to_align()
            .size();
        let authority = self.authority().independent_clone_backing_storage_data()?;
        let total = std::mem::size_of::<PreparedArchivedProtocolMapping>()
            .checked_add(identity)
            .and_then(|n| n.checked_add(authority))
            .ok_or(ProviderError::ResourceExhausted(
                "archived mapping construction",
            ))?;
        self.protocol_owner.ensure_current()?;
        Ok(total)
    }

    /// Names actual mapping, class-cursor, authority-clone and result views.
    ///
    /// The installed caller admits this DATA scratch before quoting or preparing
    /// the mapping. Recursive/compiler frames and allocator overhead are separate.
    pub fn original_selected_archived_mapping_counter_scratch_data() -> usize {
        crate::handshake::ConnectionAuthority::independent_clone_counter_scratch_data()
            + crate::protocol_snapshot::owned11::native::outer::SealedHistoricalNativeState::original_selected_restoration_mapping_counter_scratch_data()
            + std::mem::size_of::<crate::protocol_snapshot::ArchivedProtocolMappingInput<'static>>()
            + std::mem::size_of::<crate::protocol_snapshot::ArchivedProtocolMappingTarget<'static>>()
            + std::mem::size_of::<crate::protocol_snapshot::PreparedArchivedProtocolMapping>()
            + std::mem::size_of::<Result<crate::protocol_snapshot::PreparedArchivedProtocolMapping, ProviderError>>()
            + std::mem::size_of::<std::alloc::Layout>()
            + std::mem::size_of::<Result<(std::alloc::Layout, usize), std::alloc::LayoutError>>()
            + std::mem::size_of::<[usize; 4]>()
            + std::mem::size_of::<Result<usize, ProviderError>>()
    }
}
