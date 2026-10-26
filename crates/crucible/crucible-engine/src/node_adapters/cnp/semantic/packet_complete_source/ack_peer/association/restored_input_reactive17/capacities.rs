//! Counts retained Input17 and fixed suffix owners without authenticating progress.
//!
//! Both original loans and every nested SDK creator check precede physical rows.
//! Failed and incomplete attempts remain DATA; no signing or Runtime claim moves.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
    records::PacketRuntimeMetadataRecordBank,
};
use std::cell::{BorrowError, Ref};

impl InputReactive17History {
    fn check_capacity_creators_data(&self) -> Result<(), RuntimeError> {
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

    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_capacity_creators_data()?;

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
        self.authenticate_origin_data()
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(&u32, &ThreadId, &bool, &Vec<InputReactive17Attempt>)>()
            + size_of::<std::slice::Iter<'_, InputReactive17Attempt>>()
            + size_of::<&InputReactive17Attempt>()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + InputReactive17Attempt::capacity_counter_scratch_data()
    }
}

impl InputReactive17Attempt {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            row,
            acknowledgement,
            sdk,
            artifact,
            context,
            post,
            record_value,
            record,
            underlying,
            input_result,
            previous,
            signature,
            stage,
        } = self;
        census.observe_inline_data(row);
        census.observe_inline_data(previous);
        census.observe_inline_data(signature);
        census.observe_inline_data(&stage.get());

        if let Some(acknowledgement) = acknowledgement {
            census.observe_inline_data(&acknowledgement.cutoff);
            census.observe(acknowledgement)?;
        }
        if let Some(sdk) = sdk {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredSuffixAttempt(sdk),
            )?;
        }

        for retained in [
            artifact
                .as_ref()
                .map(PacketRestoredInputReactive17RetainedData::Artifact),
            context
                .as_ref()
                .map(PacketRestoredInputReactive17RetainedData::Context),
            post.as_ref()
                .map(PacketRestoredInputReactive17RetainedData::PostCheckpoint),
        ]
        .into_iter()
        .flatten()
        {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredInputReactive17(retained),
            )?;
        }

        if let Some(value) = record_value {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestorationNativeEvidence(
                record.as_ref(),
                underlying.as_ref(),
            ),
        )?;
        if let Some(result) = input_result {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredInputResult(result),
            )?;
        }
        Ok(())
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Option<crate::node_admission::OriginalRestoredInput17ConstructionData>,
                &Option<crate::node_scheduling::NativeInputAcknowledgement>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Option<PacketRestoredInputReactive17Artifact>,
                &Option<PacketRestoredInputReactive17Context>,
                &Option<PacketRestoredInputReactive17PostCheckpointData>,
                &Option<serde_json::Value>,
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
                &Option<InputResult>,
                &[u8; 32],
                &Option<[u8; 32]>,
                &Cell<Stage>,
            )>()
            + size_of::<Stage>()
            + size_of::<&Stage>()
            + size_of::<&crate::node_scheduling::NativeInputAcknowledgement>()
            + size_of::<(
                &crucible_node_format::Id,
                &crucible_node_format::Id,
                &crucible_node_format::Id,
                &Vec<crate::node_contract::OwnerIdentity>,
                &crucible_node_format::Position,
                &ContentRef,
                &ContentRef,
            )>()
            + size_of::<std::slice::Iter<'_, crate::node_contract::OwnerIdentity>>()
            + size_of::<&crate::node_contract::OwnerIdentity>()
            + size_of::<(
                &crucible_node_format::OwnerId,
                &crucible_node_format::IncarnationId,
                &U64,
            )>()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<[Option<PacketRestoredInputReactive17RetainedData<'_>>; 3]>()
            + size_of::<
                std::iter::Flatten<
                    std::array::IntoIter<Option<PacketRestoredInputReactive17RetainedData<'_>>, 3>,
                >,
            >()
            + size_of::<PacketRestoredInputReactive17RetainedData<'_>>()
            + size_of::<&serde_json::Value>()
            + size_of::<Option<&PacketNativeRestoredRecord>>()
            + size_of::<Option<&PacketNative5UnderlyingRecord>>()
            + size_of::<&InputResult>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

impl PacketCompleteSemanticSource {
    /// Reports actual retained Input17 history and fixed suffix seed capacities.
    ///
    /// Both histories are borrowed and their creators checked before physical
    /// rows. Rejected and unfinished slots keep backing without granting input
    /// custody, suffix signing or native completion. Whole-Source scalar work
    /// and the genuine one-use handoff remain independently admitted operations.
    ///
    /// # Errors
    /// Refuses foreign original creators, busy history custody, exhausted rows or
    /// depth, unsupported children and checked allocation geometry overflow.
    pub fn original_restored_input_and_suffix_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let inputs = association
            .as_ref()
            .map(|association| association.restored_inputs.try_borrow())
            .transpose()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let suffix = association
            .as_ref()
            .map(|association| association.restored_suffix.try_borrow())
            .transpose()
            .map_err(|_| RuntimeError::OwnerBusy)?;

        if let Some(inputs) = &inputs {
            inputs.check_capacity_creators_data()?;
        }
        if let Some(seed) = suffix.as_deref().and_then(Option::as_ref) {
            seed.check_capacity_creator_data(self)?;
        }

        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(inputs) = &inputs {
            inputs.record_capacity_data(&mut census)?;
        }
        if let Some(seed) = suffix.as_deref().and_then(Option::as_ref) {
            seed.record_capacity_data(self, &mut census)?;
        }

        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names the actual simultaneous Input and suffix loans and child controls.
    pub fn original_restored_input_and_suffix_capacity_counter_scratch_data() -> usize {
        use super::super::restoration_continuation::OriginalRestoredSuffixSeed;

        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + InputReactive17History::capacity_counter_scratch_data()
            + OriginalRestoredSuffixSeed::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Option<Ref<'_, InputReactive17History>>>()
            + size_of::<Result<Ref<'_, InputReactive17History>, BorrowError>>()
            + size_of::<Option<Result<Ref<'_, InputReactive17History>, BorrowError>>>()
            + size_of::<Result<Option<Ref<'_, InputReactive17History>>, BorrowError>>()
            + size_of::<&Option<Ref<'_, InputReactive17History>>>()
            + size_of::<&Ref<'_, InputReactive17History>>()
            + size_of::<Option<Ref<'_, Option<OriginalRestoredSuffixSeed>>>>()
            + size_of::<Result<Ref<'_, Option<OriginalRestoredSuffixSeed>>, BorrowError>>()
            + size_of::<Option<Result<Ref<'_, Option<OriginalRestoredSuffixSeed>>, BorrowError>>>()
            + size_of::<Result<Option<Ref<'_, Option<OriginalRestoredSuffixSeed>>>, BorrowError>>()
            + size_of::<Option<&Option<OriginalRestoredSuffixSeed>>>()
            + size_of::<Option<&OriginalRestoredSuffixSeed>>()
            + size_of::<&OriginalRestoredSuffixSeed>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<Option<&&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<&&mut PacketRuntimeMetadataRecordBank>()
            + size_of::<usize>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
