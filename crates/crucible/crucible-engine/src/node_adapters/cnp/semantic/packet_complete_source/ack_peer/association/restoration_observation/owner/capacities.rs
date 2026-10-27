//! Counts every retained first-observation partial independently of completion.
//!
//! Non-owning source/controller addresses and fixed flags stay inline. Native
//! models without receipts still retain real backing; capacity DATA grants no
//! SourceRead, native evidence, observation claim or publication permission.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::RetainedCaptureProtocolData;

impl OriginalSourceRestorationObservationAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn check_capacity_creator_data(
        &self,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_capacity_creator_data()?;
        let Self {
            process,
            thread,
            source,
            controller,
            binding,
            reserved,
            verified,
            banks,
            values,
            record,
            underlying,
            scheduling,
        } = self;
        census.observe_inline_data(process)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(source)?;
        census.observe_inline_data(controller)?;
        census.observe_inline_data(binding)?;
        census.observe_inline_data(reserved)?;
        census.observe_inline_data(verified)?;

        for bank in banks {
            census.observe(bank)?;
        }
        for value in values.iter().flatten() {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestorationNativeEvidence(
                record.as_ref(),
                underlying.as_ref(),
            ),
        )?;
        if let Some(scheduling) = scheduling.get() {
            census.observe(scheduling)?;
        }
        self.check_capacity_creator_data()
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capacity_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<(
                &u32,
                &std::thread::ThreadId,
                &*const PacketCompleteSemanticSource,
                &*const CnpController,
                &[u8; 32],
                &bool,
                &bool,
                &[Vec<u8>; BANKS],
                &[Option<serde_json::Value>; BANKS],
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
                &std::cell::OnceCell<NativeSchedulingObservation>,
            )>()
            + size_of::<std::slice::Iter<'_, Vec<u8>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'_, Option<serde_json::Value>>>>()
            + size_of::<Option<&NativeSchedulingObservation>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
