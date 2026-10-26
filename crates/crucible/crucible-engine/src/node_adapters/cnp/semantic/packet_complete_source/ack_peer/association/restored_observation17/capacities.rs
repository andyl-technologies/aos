//! Counts signed Observe17 pending and completed owners under simultaneous loans.
//!
//! Failed attempts retain all independent partials. Neither a stage flag, a MAC
//! DTO nor these capacity rows can complete a Root Window or issue a new claim.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::{
    reference_packet::service::complete_restore::restoration_observe::RetainedRestorationObservationData,
    retained_metadata::{
        RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
        records::PacketRuntimeMetadataRecordBank,
    },
};
use std::cell::{BorrowError, Ref};

/// Holds every mutable owner loan before a child can append physical rows.
struct Observation17CapacityView<'a> {
    owner: &'a Observation17Owner,
    pending: Ref<'a, Option<Observation17Attempt>>,
    completed: Ref<'a, Vec<Observation17Attempt>>,
}

impl Observation17Owner {
    fn capacity_view_data(&self) -> Result<Observation17CapacityView<'_>, RuntimeError> {
        self.authenticate_origin_data()?;
        let Self {
            process: _,
            thread: _,
            pending,
            completed,
        } = self;
        let pending = pending.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let completed = completed
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let view = Observation17CapacityView {
            owner: self,
            pending,
            completed,
        };
        view.check_creator_data()?;
        Ok(view)
    }
}

impl Observation17CapacityView<'_> {
    fn check_creator_data(&self) -> Result<(), RuntimeError> {
        self.owner.authenticate_origin_data()?;
        for attempt in self.completed.iter().chain(self.pending.iter()) {
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
        self.check_creator_data()?;
        census.observe_inline_data(&self.owner.process);
        census.observe_inline_data(&self.owner.thread);
        census.observe_vector_allocation_data(&self.completed)?;
        for attempt in self.completed.iter().chain(self.pending.iter()) {
            attempt.record_capacity_data(census)?;
        }
        self.check_creator_data()
    }

    fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&Observation17Owner>()
            + size_of::<(
                &RefCell<Option<Observation17Attempt>>,
                &RefCell<Vec<Observation17Attempt>>,
            )>()
            + size_of::<Ref<'_, Option<Observation17Attempt>>>()
            + size_of::<Ref<'_, Vec<Observation17Attempt>>>()
            + size_of::<Result<Ref<'_, Option<Observation17Attempt>>, BorrowError>>()
            + size_of::<Result<Ref<'_, Vec<Observation17Attempt>>, BorrowError>>()
            + size_of::<&Ref<'_, Option<Observation17Attempt>>>()
            + size_of::<&Ref<'_, Vec<Observation17Attempt>>>()
            + size_of::<&Vec<Observation17Attempt>>()
            + size_of::<(&u32, &ThreadId)>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<
                std::iter::Chain<
                    std::slice::Iter<'_, Observation17Attempt>,
                    std::option::Iter<'_, Observation17Attempt>,
                >,
            >()
            + size_of::<&Observation17Attempt>()
            + Observation17Attempt::capacity_counter_scratch_data()
    }
}

impl Observation17Attempt {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            ordinal,
            id,
            body,
            request,
            context,
            artifact,
            sdk,
            previous_measurement,
            previous_model,
            previous_frontier,
            measurement,
            record,
            underlying,
            record_value,
            model_value,
            record_bytes,
            model_bytes,
            scheduling,
            previous,
            signature,
            stage,
        } = self;
        census.observe_inline_data(ordinal);
        census.observe_inline_data(previous_frontier);
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
        if let Some(request) = request {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredInputReactive17(
                    PacketRestoredInputReactive17RetainedData::Request(request),
                ),
            )?;
        }
        if let Some(context) = context {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredInputReactive17(
                    PacketRestoredInputReactive17RetainedData::Context(context),
                ),
            )?;
        }
        if let Some(artifact) = artifact {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredInputReactive17(
                    PacketRestoredInputReactive17RetainedData::Artifact(artifact),
                ),
            )?;
        }
        if let Some(sdk) = sdk {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestoredSuffixAttempt(sdk),
            )?;
        }
        census.observe(previous_measurement)?;
        census.observe(previous_model)?;
        census.observe(measurement)?;
        census.observe_capture_protocol_data(
            RetainedCaptureProtocolData::RestorationNativeEvidence(
                record.as_ref(),
                underlying.as_ref(),
            ),
        )?;
        for value in [record_value, model_value].into_iter().flatten() {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        census.observe(record_bytes)?;
        census.observe(model_bytes)?;
        if let Some(scheduling) = scheduling {
            census.observe(scheduling)?;
        }
        Ok(())
    }

    fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &u64,
                &Option<Id>,
                &Option<ObserveRequest>,
                &Option<PacketRestoredInputReactive17Request>,
                &Option<PacketRestoredInputReactive17Context>,
                &Option<PacketRestoredInputReactive17Artifact>,
                &Option<OriginalRestoredSuffixHostAttempt>,
                &Option<ContentRef>,
                &Option<ContentRef>,
                &Option<U64>,
                &Option<ContentRef>,
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
                &Option<serde_json::Value>,
                &Option<serde_json::Value>,
                &Option<Vec<u8>>,
                &Option<Vec<u8>>,
                &Option<NativeSchedulingObservation>,
                &[u8; 32],
                &Option<[u8; 32]>,
                &Stage,
            )>()
            + size_of::<&ObserveRequest>()
            + size_of::<&PacketRestoredInputReactive17Request>()
            + size_of::<&PacketRestoredInputReactive17Context>()
            + size_of::<&PacketRestoredInputReactive17Artifact>()
            + size_of::<&OriginalRestoredSuffixHostAttempt>()
            + size_of::<[&Option<serde_json::Value>; 2]>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<&Option<serde_json::Value>, 2>>>()
            + size_of::<&serde_json::Value>()
            + size_of::<&NativeSchedulingObservation>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

impl PacketCompleteSemanticSource {
    /// Reports actual pending and completed signed Observe17 capacities.
    ///
    /// Both history loans and all original creator checks precede physical rows.
    /// Failed partials remain DATA; the walk grants no observation or native right.
    /// Other Source owners and scalar traversal work need independent accounting.
    ///
    /// # Errors
    /// Refuses foreign creators, busy custody, unsupported children, exhausted
    /// rows/depth or checked allocation geometry overflow.
    pub fn original_restored_observation17_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let view = association
            .as_ref()
            .map(|association| association.restored_observations17.capacity_view_data())
            .transpose()?;
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(view) = &view {
            view.record_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names actual Observe17 history loans, borrowed fields and child controls.
    pub fn original_restored_observation17_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + Observation17CapacityView::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Option<Result<Observation17CapacityView<'_>, RuntimeError>>>()
            + size_of::<Result<Option<Observation17CapacityView<'_>>, RuntimeError>>()
            + size_of::<Option<Observation17CapacityView<'_>>>()
            + size_of::<&Option<Observation17CapacityView<'_>>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<usize>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
