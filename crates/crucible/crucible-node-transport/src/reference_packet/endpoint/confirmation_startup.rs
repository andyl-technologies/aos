//! Recounts the actual fourth-Poll publication before response/receipt copies.
//!
//! The original report, completed startup Capture and actual after14 bank stay
//! in their existing endpoint slots. This local numeric plan is recomputed for
//! the sole Poll and is never stored as permission or omitted future state.

use super::*;
use crate::connection::{
    OriginalContinuationContentExtent, OriginalContinuationPrefixKind,
    OriginalContinuationPrefixStorageData, OriginalContinuationPrefixStorageInput,
};
use crate::reference_packet::serialization_storage::actual_serialization_storage_data;
use crate::reference_packet::service::confirmation::{
    PacketNativeAfterConfirmationReceipt, PacketNativeAfterConfirmationRequest,
};
use std::mem::size_of;

fn refused() -> ProviderError {
    ProviderError::Correlation("startup confirmation original Report/after differs")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("startup confirmation complete publication phase")
}
fn limit(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| exhausted())
}
fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(exhausted)
    })
}

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn quote_startup_confirmation_publication(
        &self,
        original: &Envelope,
    ) -> Result<OriginalContinuationPrefixStorageData, ProviderError> {
        let owner = self
            .capture_allocation_attempt
            .as_deref()
            .ok_or_else(refused)?
            .published()?;
        let scratch =
            super::capture_startup::original_startup_capture_endpoint_counter_scratch_data();
        if scratch > limit(owner.report.transients.quote_scratch_bytes)? {
            return Err(exhausted());
        }
        owner.authenticate_native(&self.native)?;
        let flight = self
            .capture
            .as_ref()
            .filter(|flight| flight.complete)
            .ok_or_else(refused)?;
        let after = flight.protocol_after.as_ref().ok_or_else(refused)?;
        let admitted = flight
            .startup14_after_capacity
            .as_ref()
            .ok_or_else(refused)?;
        if after.bytes().len() > admitted.maximum_after_encoded_bytes
            || admitted.maximum_after_encoded_bytes > admitted.reserved_after_encoded_bytes
            || after.original_allocation_facts()?.maximum_encoded_bytes
                != admitted.reserved_after_encoded_bytes
        {
            return Err(refused());
        }
        owner
            .currency
            .authenticate_capture_boundary(&self.native, Some(flight.reservation.request()))?;
        let maximum = limit(owner.report.transients.native_after_encoding_bytes)?;
        let projected = self.native.quote_original_next_capture_request(
            &owner.original_observe,
            limit(self.authority.limits().frame_bytes)?,
            maximum,
        )?;
        let shapes = self.native.quote_startup_confirmation_terminal_shapes(
            &owner.original_observe,
            flight.reservation.request(),
            &owner.currency,
            &projected,
            maximum,
        )?;
        let original_data =
            actual_serialization_storage_data(original, Default::default(), maximum)?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        connection.authenticate_native5_confirmation_poll(original)?;
        let objects = [OriginalContinuationContentExtent {
            maximum_payload_bytes: after.bytes().len(),
            media_type: "application/json",
        }];
        let storage = connection.quote_original_current_continuation_prefix_storage_data(
            original,
            OriginalContinuationPrefixStorageInput {
                kind: OriginalContinuationPrefixKind::AfterConfirmation,
                original: &shapes.confirmation_original,
                terminal: &shapes.confirmation_terminal,
                objects: &objects,
                maximum_requested_bytes: maximum,
            },
        )?;
        let phase = sum(&[
            storage.requested_bytes()?,
            shapes.confirmation_terminal.requested_total()?,
            shapes.capture_terminal.requested_total()?,
            original_data.requested_total()?,
            original_data.requested_total()?,
            original_data.requested_total()?,
            size_of::<PacketNativeAfterConfirmationRequest>(),
            size_of::<PacketNativeAfterConfirmationReceipt>(),
            size_of::<blake3::Hasher>(),
            "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len(),
        ])?;
        if phase > maximum || phase > limit(owner.report.growth.after_confirmation_bytes)? {
            return Err(exhausted());
        }
        storage.authenticate_response_original_clone_data(connection, original)?;
        Ok(storage)
    }
}
