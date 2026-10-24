//! Binds the selected canonical restoration writer before banks and native birth.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection, canonical_restore_inputs_schema,
};

impl PacketCompleteSemanticSource {
    /// Fixes the closed restoration-input writer before preparation allocation.
    ///
    /// This retains declaration data only. The same actual post-Hello SDK writer
    /// lease, current native boot/registration and authenticated Prepare marker
    /// remain mandatory before any selected upload or segment publication.
    ///
    /// # Errors
    /// Refuses foreign origin, repeated/late binding, an ordinary restoration
    /// selection, missing Owned11 or changed full immutable schema/feature tuples.
    pub fn bind_original_restore_input_emitter_selection(
        &mut self,
        selection: Option<PacketNative5RestoreInputEmitterSelection>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.restore_input_emitter_selection.is_some()
            || self.capture_banks.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(refused(
                "restore input emitter selection is repeated or late",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "restore input emitter selection follows native association",
            ));
        }
        if selection.is_some() {
            if self.selected_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || !matches!(
                    self.selected_capture_profile()?,
                    PacketNative5CaptureProfile::OwnedProtocol11 { .. }
                )
            {
                return Err(refused(
                    "restore input emitter requires complete transfer12",
                ));
            }
            let schema = canonical_restore_inputs_schema().map_err(unknown)?;
            let installation = self.installation();
            if !installation
                .provider
                .implementation
                .formats
                .contains(&schema)
                || !installation
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&schema)
                || !installation
                    .provider
                    .extensions_supported
                    .iter()
                    .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
            {
                return Err(refused(
                    "restore input emitter immutable declaration differs",
                ));
            }
        }
        self.restore_input_emitter_selection = Some(selection);
        Ok(())
    }

    /// Returns the expected closed writer selection after original origin checks.
    ///
    /// # Errors
    /// Refuses another creator process or thread.
    pub fn selected_restore_input_emitter_selection(
        &self,
    ) -> Result<Option<PacketNative5RestoreInputEmitterSelection>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.restore_input_emitter_selection.flatten())
    }
}
