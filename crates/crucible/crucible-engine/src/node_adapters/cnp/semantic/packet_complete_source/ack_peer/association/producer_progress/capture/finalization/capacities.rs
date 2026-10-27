//! Observes independent Controller/Journal encodings and typed finalization DATA.

use super::super::capacities::{fields_layout_data, record_value_data, value_counter_scratch_data};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::RetainedCaptureProtocolData;

impl Component {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            completed,
            value,
            bytes,
            reference,
        } = self;
        census.observe_inline_data(started);
        census.observe_inline_data(completed);

        if let Some(value) = value {
            record_value_data(value, census)?;
        }
        census.observe(bytes)?;
        census.observe(reference)
    }

    fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                started,
                completed,
                value,
                bytes,
                reference,
            } = owner;
            (started, completed, value, bytes, reference)
        }) + size_of::<&Self>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_counter_scratch_data()
    }
}

impl FinalizationOwners {
    /// Observes every retained finalization field without finishing its journal.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            started,
            completed,
            controller,
            journal,
            objects,
            history_cut,
            proof,
            proof_reference,
        } = self;
        census.observe_inline_data(started);
        census.observe_inline_data(completed);

        controller.record_capacity_data(census)?;
        journal.record_capacity_data(census)?;
        if let Some(objects) = objects {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredCaptureObjects(objects),
            )?;
        }
        if let Some(cut) = history_cut {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredCaptureHistoryCut(cut),
            )?;
        }
        census.observe(proof)?;
        census.observe(proof_reference)
    }

    /// Names borrowed finalization fields and the actual component controls.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                started,
                completed,
                controller,
                journal,
                objects,
                history_cut,
                proof,
                proof_reference,
            } = owner;
            (
                started,
                completed,
                controller,
                journal,
                objects,
                history_cut,
                proof,
                proof_reference,
            )
        }) + size_of::<&Self>()
            + size_of::<&PacketRestoredSettledJournal17Objects>()
            + size_of::<&PacketRestoredSettledHistoryCut17>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + Component::capacity_counter_scratch_data()
    }
}
