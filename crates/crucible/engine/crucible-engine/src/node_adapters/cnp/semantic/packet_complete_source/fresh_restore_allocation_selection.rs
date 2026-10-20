//! Fixes fresh query grammar before any bank, private key or native birth.

use super::*;
use crucible_node_transport::{
    client::CanonicalAckCodecMetadataExtent,
    reference_packet::service::{
        ack_emitter::PacketNative5AckEmitterSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
        fresh_restore_allocation::{
            PACKET_FRESH_RESTORE_ALLOCATION_FEATURE, PacketNative5FreshRestoreAllocationSelection,
            PacketNativeFreshRestoreAllocationSchema, fresh_restore_allocation_schema,
        },
    },
};

impl PacketCompleteSemanticSource {
    /// Fixes the fresh report family before bank, private birth or Child creation.
    ///
    /// Full immutable grammar is checked before hashes are bound by the caller's
    /// declaration builder. This method retains a selection only; the original
    /// startup grant, completed-Admit query, host credit and whole preparation
    /// remain independently mandatory before any report or restoration effect.
    ///
    /// # Errors
    /// Refuses another creator, repeated/late binding, an incompatible owning
    /// profile or any missing or changed full schema definition or feature.
    pub fn bind_original_fresh_restore_allocation_selection(
        &mut self,
        selection: Option<PacketNative5FreshRestoreAllocationSelection>,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.fresh_restore_allocation_selection.is_some()
            || self.complete_bytes_launch_reserved.get()
            || self.capture_banks.get_mut().is_some()
            || self.registry_capture.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
        {
            return Err(refused("fresh allocation selection is repeated or late"));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "fresh allocation selection follows native association",
            ));
        }
        if selection.is_some() {
            if self.selected_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || self.selected_restore_input_emitter_selection()?
                    != Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
                || !matches!(
                    self.selected_capture_profile()?,
                    PacketNative5CaptureProfile::OwnedProtocol11 { .. }
                )
                || self.selected_protocol_metadata_limits()?.is_none()
                || self.selected_ack_emitter_selection()?
                    != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                || self.selected_native_ack_codec_metadata_extent()?
                    != Some(CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            {
                return Err(refused(
                    "fresh allocation requires the complete original transfer tuple",
                ));
            }
            let installation = self.installation();
            for schema in [
                PacketNativeFreshRestoreAllocationSchema::Query,
                PacketNativeFreshRestoreAllocationSchema::Report,
                PacketNativeFreshRestoreAllocationSchema::Proof,
                PacketNativeFreshRestoreAllocationSchema::Receipt,
                PacketNativeFreshRestoreAllocationSchema::PrepareBinding,
            ] {
                let schema = fresh_restore_allocation_schema(schema).map_err(unknown)?;
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
                    return Err(refused("fresh allocation full immutable schema differs"));
                }
            }
            if !installation
                .provider
                .extensions_supported
                .iter()
                .any(|feature| feature.as_str() == PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
            {
                return Err(refused("fresh allocation producer feature is absent"));
            }
        }
        self.fresh_restore_allocation_selection = Some(selection);
        Ok(())
    }

    /// Returns the expected original fresh report selection as declaration data.
    ///
    /// # Errors
    /// Refuses a foreign creator process or thread.
    pub fn selected_fresh_restore_allocation_selection(
        &self,
    ) -> Result<Option<PacketNative5FreshRestoreAllocationSelection>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.fresh_restore_allocation_selection.flatten())
    }
}
