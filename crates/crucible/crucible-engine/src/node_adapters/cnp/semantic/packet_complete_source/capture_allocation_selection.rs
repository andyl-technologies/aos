//! Fixes the original Observe allocation producer before banks or private birth.

use super::*;
use crucible_node_transport::client::CanonicalAckCodecMetadataExtent;
use crucible_node_transport::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection;
use crucible_node_transport::reference_packet::service::capture_allocation::{
    PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE, PacketNative5CaptureAllocationSelection,
    capture_allocation_record_schema, capture_allocation_schema,
};

impl PacketCompleteSemanticSource {
    /// Binds the expected original native allocation producer before preparation.
    ///
    /// This selects immutable correlation data. Only the same original completed
    /// Observe report, native currency owner and checked whole allocation can
    /// subsequently support Capture. None preserves the earlier birth edition.
    ///
    /// # Errors
    /// Refuses foreign origin, repeated or spent preparation, an associated
    /// native, missing owning banks/ACK selection or changed complete schemas.
    pub fn bind_original_capture_allocation_selection(
        &mut self,
        selection: Option<PacketNative5CaptureAllocationSelection>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.capture_allocation_selection.is_some()
            || self.complete_bytes_launch_reserved.get()
            || self.capture_banks.get_mut().is_some()
            || selection.is_some() && self.capture_execution.get_mut().is_some()
            || self.registry_capture.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(refused("capture allocation selection is repeated or late"));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "capture allocation selection follows native association",
            ));
        }
        if selection.is_some() {
            if !matches!(
                self.selected_capture_profile()?,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            ) || self.selected_protocol_metadata_limits()?.is_none()
                || self.selected_ack_emitter_selection()?
                    != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                || self.selected_native_ack_codec_metadata_extent()?
                    != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            {
                return Err(refused(
                    "capture allocation requires the original owning native tuple",
                ));
            }
            let installation = self.installation();
            for schema in [
                capture_allocation_schema().map_err(unknown)?,
                capture_allocation_record_schema().map_err(unknown)?,
            ] {
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
                {
                    return Err(refused("capture allocation complete schema differs"));
                }
            }
            if !installation
                .provider
                .extensions_supported
                .iter()
                .any(|feature| feature.as_str() == PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
            {
                return Err(refused("capture allocation producer feature is absent"));
            }
        }
        // Both inner semantic validators receive this same original choice
        // before any banks/birth/native association can be installed. Schema
        // advertisement alone never enables reading an outer record12.
        match &mut self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_capture_allocation_selection = selection
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_capture_allocation_selection = selection
            }
        }
        self.capture_allocation_selection = Some(selection);
        Ok(())
    }

    /// Returns the original expected allocation producer as correlation data.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread.
    pub fn selected_capture_allocation_selection(
        &self,
    ) -> Result<Option<PacketNative5CaptureAllocationSelection>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.capture_allocation_selection.flatten())
    }
}
