//! Counts every retained Producer phase without completing its native history.
//!
//! The original history loan stabilizes the attempt vector. Closed, creator-thread
//! metadata walks invoke no user callbacks, so preflighted per-attempt root loans
//! remain available during traversal without allocating a temporary guard bank.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
    records::PacketRuntimeMetadataRecordBank,
};
use std::cell::BorrowError;

fn durable_root_loan_data(
    root: &RefCell<Option<ContentRef>>,
) -> Result<Ref<'_, Option<ContentRef>>, RuntimeError> {
    root.try_borrow().map_err(|_| RuntimeError::OwnerBusy)
}

impl ProducerProgressHistory {
    fn check_capacity_creator_and_loans_data(&self) -> Result<(), RuntimeError> {
        self.origin_data()?;
        for attempt in &self.attempts {
            for sdk in [
                &attempt.begin,
                &attempt.poll,
                &attempt.retire,
                &attempt.observe,
            ]
            .into_iter()
            .chain(attempt.uploads.iter())
            .flatten()
            {
                RetainedCaptureProtocolData::RestoredSuffixAttempt(sdk)
                    .check_original_creator()
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
            }
            // Preflight every mutable root before the first physical row. All
            // subsequent callees are closed pure walks on this same thread.
            let _root = durable_root_loan_data(&attempt.durable_root)?;
        }
        Ok(())
    }

    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_capacity_creator_and_loans_data()?;
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
        self.origin_data()
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(&u32, &ThreadId, &bool, &Vec<ProducerProgressAttempt>)>()
            + size_of::<std::slice::Iter<'_, ProducerProgressAttempt>>()
            + size_of::<&ProducerProgressAttempt>()
            + size_of::<[&Option<OriginalRestoredSuffixHostAttempt>; 4]>()
            + size_of::<
                std::iter::Flatten<
                    std::iter::Chain<
                        std::array::IntoIter<&Option<OriginalRestoredSuffixHostAttempt>, 4>,
                        std::slice::Iter<'_, Option<OriginalRestoredSuffixHostAttempt>>,
                    >,
                >,
            >()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<&RefCell<Option<ContentRef>>>()
            + size_of::<Ref<'_, Option<ContentRef>>>()
            + size_of::<Result<Ref<'_, Option<ContentRef>>, BorrowError>>()
            + size_of::<Result<Ref<'_, Option<ContentRef>>, RuntimeError>>()
            + ProducerProgressAttempt::capacity_counter_scratch_data()
    }
}

impl ProducerProgressAttempt {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            row,
            slot,
            admission,
            authorization,
            arguments,
            begin_body,
            poll_body,
            retire_body,
            observe_body,
            begin,
            poll,
            retire,
            observe,
            uploads,
            upload_bodies,
            request_ids,
            record_values,
            record_canonical,
            completed_record,
            completed_producer,
            completed_measurement,
            outcome,
            report_value,
            report_bytes,
            report_reference,
            durable_root,
            consumption,
            consumption_value,
            checkpoint_record,
            checkpoint_producer,
            checkpoint_measurement,
            scheduling,
            previous,
            signature,
            stage,
        } = self;
        let root = durable_root_loan_data(durable_root)?;
        census.observe_inline_data(row);
        census.observe_inline_data(slot);
        census.observe_inline_data(previous);
        census.observe_inline_data(signature);
        census.observe_inline_data(&stage.get());

        census.observe(admission)?;
        census.observe(authorization)?;
        census.observe(consumption)?;
        for value in [
            arguments
                .as_ref()
                .map(PacketRestoredProducerTypedOwnerData::Arguments),
            begin_body
                .as_ref()
                .map(PacketRestoredProducerTypedOwnerData::Begin),
            poll_body
                .as_ref()
                .map(PacketRestoredProducerTypedOwnerData::Poll),
            retire_body
                .as_ref()
                .map(PacketRestoredProducerTypedOwnerData::Retire),
            observe_body
                .as_ref()
                .map(PacketRestoredProducerTypedOwnerData::Observe),
        ]
        .into_iter()
        .flatten()
        {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredProducerTyped(value),
            )?;
        }
        census.observe_vector_allocation_data(uploads)?;
        for sdk in [begin, poll, retire, observe]
            .into_iter()
            .chain(uploads.iter())
            .flatten()
        {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredSuffixAttempt(sdk),
            )?;
        }
        census.observe_vector_allocation_data(upload_bodies)?;
        for body in upload_bodies {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredSuffixBody(body.body_data()),
            )?;
        }
        census.observe(request_ids)?;
        for value in record_values
            .iter()
            .chain(std::iter::once(report_value))
            .chain(std::iter::once(consumption_value))
            .flatten()
        {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        for bank in record_canonical {
            census.observe(bank)?;
        }
        for (record, underlying) in [
            (completed_record, completed_producer),
            (checkpoint_record, checkpoint_producer),
        ] {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestorationNativeEvidence(
                    record.as_ref(),
                    underlying.as_ref(),
                ),
            )?;
        }
        census.observe(outcome)?;
        census.observe(report_bytes)?;
        for reference in [
            completed_measurement,
            report_reference,
            checkpoint_measurement,
            &*root,
        ] {
            census.observe(reference)?;
        }
        if let Some(scheduling) = scheduling {
            census.observe(scheduling)?;
        }
        Ok(())
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &OriginalRestoredProducerExecutionConstructionData,
                &usize,
                &Option<OperationAdmission>,
                &Option<crate::node_scheduling::InputPayload>,
                &Option<ExactRunArguments>,
                &Option<BeginRequest>,
                &Option<PollRequest>,
                &Option<RetireRequest>,
                &Option<ObserveRequest>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Vec<Option<OriginalRestoredSuffixHostAttempt>>,
                &Vec<UploadBody>,
                &Vec<Id>,
                &[Option<serde_json::Value>; 4],
                &[Vec<u8>; 4],
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
                &Option<ContentRef>,
                &Option<OperationOutcome>,
                &Option<serde_json::Value>,
                &Vec<u8>,
                &Option<ContentRef>,
                &RefCell<Option<ContentRef>>,
                &Option<crate::node_scheduling::InputPayload>,
                &Option<serde_json::Value>,
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
                &Option<ContentRef>,
                &Option<crate::node_scheduling::NativeSchedulingObservation>,
                &[u8; 32],
                &Option<[u8; 32]>,
                &Cell<Stage>,
            )>()
            + size_of::<&Ref<'_, Option<ContentRef>>>()
            + size_of::<Stage>()
            + size_of::<&Stage>()
            + size_of::<[Option<PacketRestoredProducerTypedOwnerData<'_>>; 5]>()
            + size_of::<
                std::iter::Flatten<
                    std::array::IntoIter<Option<PacketRestoredProducerTypedOwnerData<'_>>, 5>,
                >,
            >()
            + size_of::<PacketRestoredProducerTypedOwnerData<'_>>()
            + size_of::<[&Option<OriginalRestoredSuffixHostAttempt>; 4]>()
            + size_of::<
                std::iter::Flatten<
                    std::iter::Chain<
                        std::array::IntoIter<&Option<OriginalRestoredSuffixHostAttempt>, 4>,
                        std::slice::Iter<'_, Option<OriginalRestoredSuffixHostAttempt>>,
                    >,
                >,
            >()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<std::slice::Iter<'_, UploadBody>>()
            + size_of::<&UploadBody>()
            + size_of::<OriginalRestoredSuffixBody<'_>>()
            + size_of::<
                std::iter::Flatten<
                    std::iter::Chain<
                        std::iter::Chain<
                            std::slice::Iter<'_, Option<serde_json::Value>>,
                            std::iter::Once<&Option<serde_json::Value>>,
                        >,
                        std::iter::Once<&Option<serde_json::Value>>,
                    >,
                >,
            >()
            + size_of::<&serde_json::Value>()
            + size_of::<std::slice::Iter<'_, Vec<u8>>>()
            + size_of::<&Vec<u8>>()
            + size_of::<
                [(
                    &Option<PacketNativeRestoredRecord>,
                    &Option<PacketNative5UnderlyingRecord>,
                ); 2],
            >()
            + size_of::<
                std::array::IntoIter<
                    (
                        &Option<PacketNativeRestoredRecord>,
                        &Option<PacketNative5UnderlyingRecord>,
                    ),
                    2,
                >,
            >()
            + size_of::<[&Option<ContentRef>; 4]>()
            + size_of::<std::array::IntoIter<&Option<ContentRef>, 4>>()
            + size_of::<&crate::node_scheduling::NativeSchedulingObservation>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

impl PacketCompleteSemanticSource {
    /// Reports all actual retained Producer progress phase capacities.
    ///
    /// Original history and nested-root preflight precede physical rows. Failed
    /// attempts and independent partials retain backing without acquiring native
    /// completion, durability or retirement permission. Other Source owners and
    /// complete scalar traversal work require their own accounting.
    ///
    /// # Errors
    /// Refuses foreign creators, busy history/root custody, unsupported children,
    /// exhausted rows/depth or checked allocation geometry overflow.
    pub fn original_restored_producer_progress_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let history = association
            .as_ref()
            .map(|association| association.producer_progress.try_borrow())
            .transpose()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(history) = &history {
            history.check_capacity_creator_and_loans_data()?;
        }
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(history) = &history {
            history.record_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names actual Producer history, per-attempt loans and closed child controls.
    pub fn original_restored_producer_progress_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + ProducerProgressHistory::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Option<Ref<'_, ProducerProgressHistory>>>()
            + size_of::<Result<Ref<'_, ProducerProgressHistory>, BorrowError>>()
            + size_of::<Option<Result<Ref<'_, ProducerProgressHistory>, BorrowError>>>()
            + size_of::<Result<Option<Ref<'_, ProducerProgressHistory>>, BorrowError>>()
            + size_of::<&Option<Ref<'_, ProducerProgressHistory>>>()
            + size_of::<&Ref<'_, ProducerProgressHistory>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<usize>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
