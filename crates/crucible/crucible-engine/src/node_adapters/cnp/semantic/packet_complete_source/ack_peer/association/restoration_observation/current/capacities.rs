//! Counts current-observation history slots and independently retained children.
//!
//! Failed or incomplete attempts retain their full actual owners. The Copy
//! construction row contains non-owning correspondence labels, not heap credit.
//! No history stage, quote, signature or capacity row supplies a native claim.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::RetainedCaptureProtocolData;

impl CurrentObservationHistory {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn check_capacity_creator_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.authenticate_origin_data()?;
        for attempt in &self.attempts {
            if let Some(sdk) = &attempt.sdk {
                RetainedCaptureProtocolData::RestoredSuffixAttempt(sdk)
                    .check_original_creator()
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
            }
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
            failed,
            attempts,
        } = self;
        census.observe_inline_data(process);
        census.observe_inline_data(thread);
        census.observe_inline_data(failed);
        census.observe_vector_allocation_data(attempts)?;
        for attempt in attempts {
            attempt.record_capacity_data(census)?;
        }
        self.check_capacity_creator_data()
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capacity_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<(&u32, &ThreadId, &bool, &Vec<CurrentObservationAttempt>)>()
            + size_of::<std::slice::Iter<'_, CurrentObservationAttempt>>()
            + size_of::<&CurrentObservationAttempt>()
            + size_of::<(
                &OriginalRestoredSchedulingObservationConstructionData,
                &Option<Id>,
                &Option<ObserveRequest>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Option<ContentRef>,
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
                &Option<NativeSchedulingObservation>,
                &[u8; 32],
                &Option<[u8; 32]>,
                &Stage,
            )>()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<&ObserveRequest>()
            + size_of::<&NativeSchedulingObservation>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

impl CurrentObservationAttempt {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            row,
            id,
            body,
            sdk,
            measurement,
            record,
            underlying,
            scheduling,
            previous,
            signature,
            stage,
        } = self;
        census.observe_inline_data(row);
        census.observe_inline_data(previous);
        census.observe_inline_data(signature);
        census.observe_inline_data(stage);

        census.observe(id)?;
        if let Some(body) = body {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestorationObservation(
                    RetainedRestorationObservationData::Body(body),
                ),
            )?;
        }
        if let Some(sdk) = sdk {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredSuffixAttempt(sdk),
            )?;
        }
        census.observe(measurement)?;
        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestorationNativeEvidence(
                record.as_ref(),
                underlying.as_ref(),
            ),
        )?;
        if let Some(scheduling) = scheduling {
            census.observe(scheduling)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
