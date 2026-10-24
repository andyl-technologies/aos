//! Supplies actual private Prepare layouts at their original quote boundaries.
//!
//! The fallible shared-attempt calculation stays after authority-clone pricing.
//! Response-owner and defining fixed-counter queries remain at their original
//! expression positions. No private layout definition moves into the lower crate.

use super::*;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::prepare_layout::PrepareFixedLayoutData;

pub(super) fn project() -> Result<PrepareFixedLayoutData, ProviderError> {
    let attempt_shared_bytes = sum(&[
        size_of::<RefCell<NativeCompleteRestorePrepareAttempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            align_of::<RefCell<NativeCompleteRestorePrepareAttempt>>(),
        )?,
    ])?;

    Ok(PrepareFixedLayoutData {
        attempt_shared_bytes,
        envelope_bytes: size_of::<Envelope>(),
        envelope_alignment: align_of::<Envelope>(),
        received_frame_bytes: size_of::<crate::connection::ReceivedFrame>(),
        request_body_bytes: size_of::<crate::bodies::RequestBody>(),
        prepare_result_bytes: size_of::<crate::bodies::PrepareRestoreResult>(),
        prepare_receipt_bytes: size_of::<PacketCompleteRestorePrepareReceipt>(),
        prepare_request_bytes: size_of::<PacketCompleteRestorePrepareRequest>(),
        transfer_proof_bytes: size_of::<PacketCompleteRestoreTransferProof>(),
        prepare_context_bytes: size_of::<PacketCompleteRestorePrepareContext>(),
        content_ref_bytes: size_of::<ContentRef>(),
        connection_incident_bytes: size_of::<crate::connection::ConnectionIncident>(),
    })
}

pub(super) fn response_owner_bytes_data() -> usize {
    Connection::<crate::client::DeadlineStream>::original_prepare_response_owner_layout_data()
}

pub(super) fn counter_output_data() -> usize {
    original_native_prepare_startup_counter_scratch_data()
}

// The original counter retains every term. Only the actual newly constructed
// layout/result headers and two direct forwarding-return headers are added.
pub(super) const fn counter_scratch_data() -> usize {
    // Supplier initializer and successful Result return.
    size_of::<PrepareFixedLayoutData>()
        + size_of::<Result<PrepareFixedLayoutData, ProviderError>>()
        // The real quote receives that Result and retains its actual facts.
        + size_of::<Result<PrepareFixedLayoutData, ProviderError>>()
        + size_of::<PrepareFixedLayoutData>()
        // Response-owner forwarder and defining-counter forwarder returns.
        + size_of::<usize>()
        + size_of::<usize>()
}

#[cfg(test)]
#[path = "layout/original.rs"]
mod original;

#[cfg(test)]
#[path = "layout/tests.rs"]
mod tests;
