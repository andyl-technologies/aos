//! Observes frozen Capture checkpoints and independently retained construction DATA.

use super::super::capacities::{
    fields_layout_data, record_typed_capture_data, record_value_data,
    typed_capture_counter_scratch_data, value_counter_scratch_data,
};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::{
    client::RestoredSettledCaptureTypedOwnerData,
    reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerTypedOwnerData,
    retained_metadata::RetainedCaptureProtocolData,
};
use std::mem::size_of;

impl FrozenCheckpoint {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            record,
            underlying,
            measurement,
            first_observation,
            scope,
            frontier,
        } = self;
        census.observe_inline_data(frontier);

        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestorationNativeEvidence(Some(record), Some(underlying)),
        )?;
        census.observe(measurement)?;
        census.observe(first_observation)?;
        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestorationActivationScope(scope),
        )
    }

    fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                record,
                underlying,
                measurement,
                first_observation,
                scope,
                frontier,
            } = owner;
            (
                record,
                underlying,
                measurement,
                first_observation,
                scope,
                frontier,
            )
        }) + size_of::<&Self>()
            + size_of::<Option<&PacketNativeRestoredRecord>>()
            + size_of::<Option<&PacketNative5UnderlyingRecord>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl CaptureConstructionOwners {
    /// Observes all actual construction and final-object fields without issuance.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            frozen,
            ancestry,
            capture,
            arguments,
            body,
            uploads,
            ids,
            finalization,
            final_started,
            final_value,
            final_bytes,
            final_reference,
            node_bytes,
            node_reference,
        } = self;
        census.observe_inline_data(started);
        census.observe_inline_data(final_started);

        if let Some(frozen) = frozen {
            frozen.record_capacity_data(census)?;
        }
        if let Some(ancestry) = ancestry {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredCaptureAncestry(ancestry),
            )?;
        }
        if let Some(capture) = capture {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::CaptureRequest(capture),
                census,
            )?;
        }
        if let Some(arguments) = arguments {
            record_value_data(arguments, census)?;
        }
        if let Some(body) = body {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredProducerTyped(
                    PacketRestoredProducerTypedOwnerData::Begin(body),
                ),
            )?;
        }
        for upload in uploads.iter().flatten() {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::UploadRequest(upload),
                census,
            )?;
        }
        for id in ids {
            census.observe(id)?;
        }

        finalization.record_capacity_data(census)?;
        if let Some(value) = final_value {
            record_value_data(value, census)?;
        }
        census.observe(final_bytes)?;
        census.observe(final_reference)?;
        census.observe(node_bytes)?;
        census.observe(node_reference)
    }

    /// Names actual borrowed construction fields, fixed-array and child controls.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        type UploadViews<'a> = std::iter::Flatten<
            std::slice::Iter<'a, Option<PacketRestoredSettledCaptureUploadRequest>>,
        >;

        fields_layout_data::<Self, _>(|owner| {
            let Self {
                started,
                frozen,
                ancestry,
                capture,
                arguments,
                body,
                uploads,
                ids,
                finalization,
                final_started,
                final_value,
                final_bytes,
                final_reference,
                node_bytes,
                node_reference,
            } = owner;
            (
                started,
                frozen,
                ancestry,
                capture,
                arguments,
                body,
                uploads,
                ids,
                finalization,
                final_started,
                final_value,
                final_bytes,
                final_reference,
                node_bytes,
                node_reference,
            )
        }) + size_of::<&Self>()
            + size_of::<&FrozenCheckpoint>()
            + size_of::<&PacketRestoredSettledAncestry17>()
            + size_of::<&PacketRestoredSettledCaptureRequest>()
            + size_of::<&BeginRequest>()
            + size_of::<PacketRestoredProducerTypedOwnerData<'_>>()
            + size_of::<std::slice::Iter<'_, Option<PacketRestoredSettledCaptureUploadRequest>>>()
            + size_of::<UploadViews<'_>>()
            + size_of::<&PacketRestoredSettledCaptureUploadRequest>()
            + size_of::<std::slice::Iter<'_, Option<Id>>>()
            + size_of::<&Option<Id>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + FrozenCheckpoint::capacity_counter_scratch_data()
            + super::super::finalization::FinalizationOwners::capacity_counter_scratch_data()
            + typed_capture_counter_scratch_data()
            + value_counter_scratch_data()
    }
}
