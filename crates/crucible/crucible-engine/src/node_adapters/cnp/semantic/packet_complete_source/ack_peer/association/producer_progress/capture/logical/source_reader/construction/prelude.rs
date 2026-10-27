//! Quotes the first-history cache required by the historical parent cohort.

use super::*;

impl OriginalSourceRestoredSettled17Read {
    /// Quotes the independently retained first component before parent validation.
    ///
    /// The same actual Source/native/SDK first verifier is used by the final
    /// reader. This subset creates no full Source result or inherited authority.
    ///
    /// # Errors
    /// Refuses malformed selected spans, unsupported typed metadata, incomplete
    /// SDK/native quote inputs, arithmetic overflow or a short independent row.
    pub(crate) fn first_component_decode_construction_data(
        semantic: &[u8],
        controller: &ValidatedControllerSettledHistory17,
        native: &SealedHistoricalRestoredSettledNative17,
        sdk_capture: &ValidatedHistoricalRestoredSettledCapture17,
        maximum: usize,
    ) -> Result<OriginalSourceRestoredSettled17DecodeConstructionData, RuntimeError> {
        let plan =
            PacketRestoredSettledSemantic17Plan::validate(semantic, maximum).map_err(invalid)?;
        let mut fields = Fields::object(plan.source_bytes()).map_err(invalid)?;
        fields.named("capture").map_err(invalid)?;
        fields.named("current_observations").map_err(invalid)?;
        let first = fields.named("first_observation").map_err(invalid)?;
        fields.named("inherited").map_err(invalid)?;
        fields.named("input_history").map_err(invalid)?;
        let installation = fields.named("installation").map_err(invalid)?;
        fields.named("limits").map_err(invalid)?;
        fields.named("once").map_err(invalid)?;
        fields.named("producer").map_err(invalid)?;
        fields.named("schema").map_err(invalid)?;
        let world = fields.named("world").map_err(invalid)?;
        fields.finish().map_err(invalid)?;

        let mut quote = Quote {
            retained: 0,
            transient: 0,
            maximum,
        };
        quote.raw(semantic, true)?;
        quote.retained(NodeRuntime::capture_shared_allocation_storage::<Value>())?;
        quote.retained(size_of::<OriginalSourceRestoredSettled17Prelude>())?;
        quote.typed(installation, Family::Installation.element_layout_data())?;
        // Installation validation canonically compares four full public
        // declarations. Their independent serializer buffers remain pure T.
        for _ in 0..4 {
            quote.raw(installation, false)?;
        }
        quote.transient_typed(world, Family::World.element_layout_data())?;
        quote.first(first)?;
        quote.sdk_first(controller)?;
        quote.transient(
            historical_restoration_association17_validation_transient_for_controller_data(
                controller, maximum,
            )
            .map_err(invalid)?,
        )?;
        let native_work = native
            .source_history17_authentication_geometry_data(controller, sdk_capture, maximum)
            .map_err(invalid)?;
        quote.transient(native_work.maximum_simultaneous_transient_bytes_data())?;
        let scratch = Self::completed_decode_counter_scratch_data()
            .checked_add(native_work.declared_counter_scratch_bytes_data())
            .and_then(|bytes| {
                bytes.checked_add(OriginalSourceRestoredSettled17Prelude::counter_scratch_data())
            })
            .ok_or(RuntimeError::ResourceLimit)?;
        quote
            .total()?
            .checked_add(scratch)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(OriginalSourceRestoredSettled17DecodeConstructionData {
            retained: quote.retained,
            transient: quote.transient,
            scratch,
        })
    }
}
