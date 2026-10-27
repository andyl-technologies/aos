//! Observes retained confirmation, native decoder and bridge phases as DATA.

use super::super::capacities::fields_layout_data;
use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::RetainedCaptureProtocolData;
use std::mem::size_of;

impl CapturePostConfirmationOwners {
    /// Checks any original bridge before the complete Capture lends physical rows.
    ///
    /// # Errors
    /// Refuses a bridge created by another process, thread or Source allocation.
    pub(in super::super) fn check_capacity_creator_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(), RuntimeError> {
        if let Some(bridge) = &self.bridge {
            bridge.check_capacity_creator_data(source)?;
        }
        Ok(())
    }

    /// Observes actual partial and completed children without granting eligibility.
    ///
    /// # Errors
    /// Refuses foreign bridge creators, exhausted rows, unsupported children
    /// or checked capacity geometry/depth overflow.
    pub(in super::super) fn record_capacity_data(
        &self,
        source: &PacketCompleteSemanticSource,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_capacity_creator_data(source)?;
        let Self {
            stage,
            confirmation,
            native_attempt,
            native_output,
            bridge,
        } = self;
        census.observe_inline_data(stage)?;

        confirmation.record_capacity_data(census)?;
        if let Some(attempt) = native_attempt {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredNative17Decode(attempt),
            )?;
        }
        if let Some(output) = native_output {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredNative17CaptureOutputs(output),
            )?;
        }
        if let Some(bridge) = bridge {
            bridge.record_capacity_data(source, census)?;
        }
        self.check_capacity_creator_data(source)
    }

    /// Names the actual borrowed phase fields and defining observer controls.
    pub(in super::super) fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                stage,
                confirmation,
                native_attempt,
                native_output,
                bridge,
            } = owner;
            (stage, confirmation, native_attempt, native_output, bridge)
        }) + size_of::<&Self>()
            + size_of::<&RestoredSettledNative17DecodeAttempt>()
            + size_of::<&ValidatedRestoredSettledNative17CaptureOutputs>()
            + size_of::<&CaptureAdminBridge>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + CaptureConfirmationOwners::capacity_counter_scratch_data()
            + CaptureAdminBridge::capacity_counter_scratch_data()
    }
}
