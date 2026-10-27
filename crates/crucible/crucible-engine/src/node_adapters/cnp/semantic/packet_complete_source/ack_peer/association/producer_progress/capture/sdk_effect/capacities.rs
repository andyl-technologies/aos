//! Observes separately retained Source transport DTOs without SDK publication.
//!
//! The live SDK once owner remains in its Controller. This Source owner retains
//! its own typed bodies, payloads and signing partials, including every spare.

use super::super::capacities::{
    fields_layout_data, record_typed_capture_data, typed_capture_counter_scratch_data,
};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::{
    client::OriginalRestoredSuffixBody,
    reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerTypedOwnerData,
    retained_metadata::RetainedCaptureProtocolData,
};

impl CaptureSdkOwners {
    /// Observes all actual Source transport fields without authenticating a stage.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            request_id,
            operation_id,
            body,
            request,
            uploads,
            prefix,
            runtime_object,
            signatures,
            request_ids,
            bodies,
            stage,
        } = self;
        census.observe_inline_data(stage);

        census.observe(request_id)?;
        census.observe(operation_id)?;
        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestoredProducerTyped(
                PacketRestoredProducerTypedOwnerData::Begin(body),
            ),
        )?;
        record_typed_capture_data(
            RestoredSettledCaptureTypedOwnerData::CaptureRequest(request),
            census,
        )?;
        for upload in uploads {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::UploadRequest(upload),
                census,
            )?;
        }

        census.observe(prefix)?;
        census.observe(runtime_object)?;
        signatures.record_capacity_data(census)?;
        census.observe(request_ids)?;
        census.observe_vector_allocation_data(bodies)?;
        for body in bodies {
            let body = match body {
                RestoredSettledCaptureAuxiliaryBody::Begin(body) => {
                    OriginalRestoredSuffixBody::BlobBegin(body)
                }
                RestoredSettledCaptureAuxiliaryBody::Chunk(body) => {
                    OriginalRestoredSuffixBody::BlobChunk(body)
                }
                RestoredSettledCaptureAuxiliaryBody::Finish(body) => {
                    OriginalRestoredSuffixBody::BlobFinish(body)
                }
            };
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredSuffixBody(body),
            )?;
        }
        Ok(())
    }

    /// Names actual borrowed transport fields, body alternatives and iterators.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                request_id,
                operation_id,
                body,
                request,
                uploads,
                prefix,
                runtime_object,
                signatures,
                request_ids,
                bodies,
                stage,
            } = owner;
            (
                request_id,
                operation_id,
                body,
                request,
                uploads,
                prefix,
                runtime_object,
                signatures,
                request_ids,
                bodies,
                stage,
            )
        }) + size_of::<&Self>()
            + size_of::<std::slice::Iter<'_, PacketRestoredSettledCaptureUploadRequest>>()
            + size_of::<&PacketRestoredSettledCaptureUploadRequest>()
            + size_of::<std::slice::Iter<'_, Id>>()
            + size_of::<std::slice::Iter<'_, RestoredSettledCaptureAuxiliaryBody>>()
            + size_of::<&RestoredSettledCaptureAuxiliaryBody>()
            + size_of::<OriginalRestoredSuffixBody<'_>>()
            + size_of::<PacketRestoredProducerTypedOwnerData<'_>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + CaptureSigningOwners::capacity_counter_scratch_data()
            + typed_capture_counter_scratch_data()
    }
}
