//! Binds separately installed complete restoration grammar before original birth.

use super::*;
use crucible_node_transport::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::service::complete_restore::{
        PacketNative5CompleteRestoreSelection, complete_restore_selected_features,
        complete_restore_selected_schemas,
    },
};

impl PacketCompleteSemanticSource {
    /// Fixes the closed complete restoration selection before banks, key or Child.
    ///
    /// The actual signed source, original target context, prepared mapping and
    /// fresh keyed request remain separate mandatory installation authorities.
    ///
    /// # Errors
    /// Refuses foreign origin, repeated or late binding, incomplete Owned11
    /// declarations or any changed full registered schema/provider tuple.
    pub fn bind_original_complete_restore_selection(
        &mut self,
        selection: Option<PacketNative5CompleteRestoreSelection>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.complete_restore_selection.is_some()
            || self.capture_banks.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(refused("complete restore selection is repeated or late"));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "complete restore selection follows native association",
            ));
        }
        if let Some(selected) = selection {
            if self.selected_protocol_metadata_limits()?.is_none()
                || self.selected_native_ack_codec_metadata_extent()?
                    != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                || self.selected_ack_emitter_selection()?.is_none()
                || !matches!(
                    self.selected_capture_profile()?,
                    PacketNative5CaptureProfile::OwnedProtocol11 { .. }
                )
            {
                return Err(refused(
                    "complete restore selection requires full owning declarations",
                ));
            }
            for schema in complete_restore_selected_schemas(selected).map_err(unknown)? {
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
                        .contains(&schema.id)
                {
                    return Err(refused("complete restore source schema differs"));
                }
            }
            let provider = &self.installation().provider;
            for feature in complete_restore_selected_features(selected) {
                if !provider
                    .extensions_supported
                    .iter()
                    .any(|name| name.as_str() == feature)
                {
                    return Err(refused("complete restore source feature differs"));
                }
            }
        }
        self.complete_restore_selection = Some(selection);
        Ok(())
    }

    /// Returns the expected closed restoration selection after origin validation.
    ///
    /// # Errors
    /// Refuses another creator process or thread.
    pub fn selected_complete_restore_selection(
        &self,
    ) -> Result<Option<PacketNative5CompleteRestoreSelection>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.complete_restore_selection.flatten())
    }
}
