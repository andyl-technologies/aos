//! Lends only the immutable cache installed by genuine first completion.
//!
//! Every setter refuses after `verified`; reservation refuses an existing slot.
//! The only successful completion follows Source-key proof, native/held/model
//! correspondence, scheduling construction and the final owning Source fence.
//! Historical readers return separate inert types and cannot create this owner.

use super::*;

impl OriginalSourceRestorationObservationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association) fn original_completed_cache17_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<
        (
            &PacketNativeRestoredRecord,
            &PacketNative5UnderlyingRecord,
            &NativeSchedulingObservation,
            [u8; 32],
        ),
        RuntimeError,
    > {
        self.authenticate_original(source, controller, self.binding)?;
        self.authenticate_verified()?;
        Ok((
            self.record()?,
            self.underlying()?,
            self.scheduling()?,
            self.binding,
        ))
    }
}
