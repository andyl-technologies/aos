//! Binds independent native metadata row selections before original birth.
//!
//! The private boot body and existing full-body MAC normalization retain this
//! choice. It authorizes no Capture, quote, live reconstruction or whole-world
//! memory. Native code must still reconcile both actual physical metadata banks
//! with its complete current-source walk under the original selected scope.

use super::*;
use crucible_node_transport::reference_packet::service::PacketNative5ProtocolMetadataLimits;

impl PacketCompleteSemanticSource {
    /// Binds independent native before/after row limits before banks or Child.
    ///
    /// The host protocol has separately selected metadata banks. Neither its
    /// capacity nor a protocol byte ceiling can substitute for this selection.
    ///
    /// # Errors
    /// Refuses another origin, repeated/late binding, unsupported rows, missing
    /// selected native codec or any profile other than the complete owning one.
    pub fn bind_original_protocol_metadata_limits(
        &mut self,
        limits: PacketNative5ProtocolMetadataLimits,
    ) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        limits.validate_data().map_err(unknown)?;
        if self.protocol_metadata_limits.is_some()
            || self.capture_banks.get_mut().is_some()
            || self.preconstruction.get_mut().is_some()
            || self.ack_birth_attempted
            || self.ack_peer_birth.get_mut().is_some()
            || self.ack_peer_association.get_mut().is_some()
            || self.selected_native_ack_codec_metadata_extent()?.is_none()
            || self.selected_ack_emitter_selection()?.is_none()
            || !matches!(
                self.selected_capture_profile()?,
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
        {
            return Err(refused(
                "native metadata limits cannot be bound to this source phase",
            ));
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => source.complete_preparation_unbound(),
            CompletePacketOriginal::Reactive(source) => source.complete_preparation_unbound(),
        }?;
        if !unbound {
            return Err(refused(
                "native metadata limits require original unbound preparation",
            ));
        }
        self.protocol_metadata_limits = Some(limits);
        Ok(())
    }

    /// Returns the original finite selection after checking source custody.
    ///
    /// This is correlation data. Actual record/alias capacities and complete
    /// current-walk requirements must independently pass before encoding.
    ///
    /// # Errors
    /// Refuses foreign source process or thread custody.
    pub fn selected_protocol_metadata_limits(
        &self,
    ) -> Result<Option<PacketNative5ProtocolMetadataLimits>, OperationFailure> {
        self.ensure_origin()?;
        Ok(self.protocol_metadata_limits)
    }
}
