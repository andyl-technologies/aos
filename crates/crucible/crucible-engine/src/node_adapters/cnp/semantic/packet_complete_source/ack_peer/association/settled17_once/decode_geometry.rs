//! Names the actual once-phase, header and upload decoder layouts.
//!
//! The completed output stores only the suffix. Its inline size cannot stand in
//! for the larger independent typed phases and SDK upload frames validated on
//! the way to that output. These layouts are construction DATA, not saved debt.

use super::*;
use crucible_node_transport::{
    bodies::{MethodResult, RequestBody, ResponseBody},
    client::CanonicalAckCodecMetadataExtent,
    envelope::{Envelope, Method},
    reference_packet::service::{
        PacketNative5AckEmitterSelection, PacketNative5ProtocolMetadataLimits,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            activation::upload::PacketRestorationActivationUploadRequest,
        },
        fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    },
};
use std::mem::size_of;

fn phase_layouts() -> [usize; 22] {
    [
        size_of::<AssociationOnce17>(),
        size_of::<RestoreOnce17>(),
        size_of::<TransferPhaseOnce17>(),
        size_of::<TransferOnce17>(),
        size_of::<ActivationOnce17>(),
        size_of::<FirstObservationOnce17>(),
        size_of::<SuffixOnce17>(),
        size_of::<PacketRestorationActivationUploadRequest>(),
        size_of::<Envelope>(),
        size_of::<RequestBody>(),
        size_of::<ResponseBody>(),
        size_of::<MethodResult>(),
        size_of::<Method>(),
        size_of::<PacketNative5AckEmitterSelection>(),
        size_of::<PacketNative5CompleteRestoreSelection>(),
        size_of::<PacketNative5RestoreInputEmitterSelection>(),
        size_of::<PacketNative5CaptureAllocationSelection>(),
        size_of::<PacketNative5FreshRestoreAllocationSelection>(),
        size_of::<CanonicalAckCodecMetadataExtent>(),
        size_of::<PacketNative5ProtocolMetadataLimits>(),
        size_of::<serde_json::Value>(),
        crate::node_contract::NodeRuntime::capture_closed_inline_storage(),
    ]
}

impl OriginalSourceRestoredOnce17Read {
    /// Bounds actual parsed once/header/upload elements independently of output.
    pub(crate) fn completed_decode_element_layout_data() -> usize {
        phase_layouts().into_iter().max().unwrap_or(0)
    }

    /// Names simultaneous fixed phases and the real upload loop owners.
    pub(crate) fn completed_decode_counter_scratch_data() -> usize {
        // All six phase values coexist while the upload loop owns a request,
        // two envelopes, typed request/response and historical response view.
        size_of::<AssociationOnce17>()
            + size_of::<RestoreOnce17>()
            + size_of::<TransferOnce17>()
            + size_of::<ActivationOnce17>()
            + size_of::<FirstObservationOnce17>()
            + size_of::<SuffixOnce17>()
            + size_of::<PacketRestorationActivationUploadRequest>()
            + size_of::<Envelope>() * 2
            + size_of::<RequestBody>()
            + size_of::<ResponseBody>()
            + size_of::<
                crucible_node_transport::retained_metadata::HistoricalResponseBodyData<'static>,
            >()
            + size_of::<Id>()
            + size_of::<[usize; 22]>()
            + size_of::<std::slice::Iter<'static, serde_json::Value>>() * 3
            + size_of::<Result<(), RuntimeError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn once_decode_slot_covers_every_defining_phase_header_and_upload_layout() {
        let slot = OriginalSourceRestoredOnce17Read::completed_decode_element_layout_data();
        for layout in phase_layouts() {
            assert!(slot >= layout);
        }
        assert!(slot >= size_of::<TransferOnce17>());
        assert!(slot >= size_of::<PacketRestorationActivationUploadRequest>());
        assert!(
            OriginalSourceRestoredOnce17Read::completed_decode_counter_scratch_data()
                >= size_of::<Envelope>() * 2
                    + size_of::<PacketRestorationActivationUploadRequest>()
        );
    }
}
