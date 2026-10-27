//! Observes the independent fourth-request and raw terminal backing as DATA.

use super::super::capacities::{
    fields_layout_data, record_typed_capture_data, record_value_data,
    typed_capture_counter_scratch_data, value_counter_scratch_data,
};
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;

impl CaptureConfirmationOwners {
    /// Observes all retained request and raw terminal fields without confirmation.
    ///
    /// # Errors
    /// Refuses exhausted rows, unsupported children or checked geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            attempted,
            request_id,
            terminal_value,
            terminal_bytes,
            request,
        } = self;
        census.observe_inline_data(attempted)?;

        census.observe(request_id)?;
        if let Some(value) = terminal_value {
            record_value_data(value, census)?;
        }
        census.observe(terminal_bytes)?;
        if let Some(request) = request {
            record_typed_capture_data(
                RestoredSettledCaptureTypedOwnerData::ConfirmationRequest(request),
                census,
            )?;
        }
        Ok(())
    }

    /// Names the exact borrowed request, terminal and observer controls.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                attempted,
                request_id,
                terminal_value,
                terminal_bytes,
                request,
            } = owner;
            (
                attempted,
                request_id,
                terminal_value,
                terminal_bytes,
                request,
            )
        }) + size_of::<&Self>()
            + size_of::<&PacketRestoredSettledAfterConfirmationRequest>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_counter_scratch_data()
            + typed_capture_counter_scratch_data()
    }
}
