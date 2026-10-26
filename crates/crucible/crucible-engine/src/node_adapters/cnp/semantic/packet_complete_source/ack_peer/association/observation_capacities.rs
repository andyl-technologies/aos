//! Projects first/current observation capacities from the original Source.
//!
//! First-observation banks and current-history slots coexist independently.
//! Other restoration, producer, Capture, input and suffix owners still require
//! their own defining rosters before whole-Source admission can be established.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank,
};
use std::{
    cell::{BorrowError, Ref},
    mem::size_of,
};

impl PacketCompleteSemanticSource {
    /// Reports actual first and current observation owners, including failed partials.
    ///
    /// Creator and current-history loans precede physical rows. This component
    /// neither authenticates observations nor supplies whole-Source work credit.
    ///
    /// # Errors
    /// Refuses foreign creators, busy association/history custody, unsupported
    /// children, exhausted rows/depth or checked layout overflow.
    pub fn original_first_and_current_observation_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let current = association
            .as_ref()
            .map(|association| association.current_observations.try_borrow())
            .transpose()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let first = association
            .as_ref()
            .and_then(|association| association.restoration_observation.as_ref());
        if let Some(first) = first {
            first.check_capacity_creator_data()?;
        }
        if let Some(current) = &current {
            current.check_capacity_creator_data()?;
        }

        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(first) = first {
            first.record_capacity_data(&mut census)?;
        }
        if let Some(current) = &current {
            current.record_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names the real observation projection, history loans and child controls.
    pub fn original_first_and_current_observation_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + restoration_observation::OriginalSourceRestorationObservationAttempt::capacity_counter_scratch_data()
            + restoration_observation::CurrentObservationHistory::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<Ref<'_, restoration_observation::CurrentObservationHistory>>>()
            + size_of::<Result<Ref<'_, restoration_observation::CurrentObservationHistory>, BorrowError>>()
            + size_of::<Option<Result<Ref<'_, restoration_observation::CurrentObservationHistory>, BorrowError>>>()
            + size_of::<Result<Option<Ref<'_, restoration_observation::CurrentObservationHistory>>, BorrowError>>()
            + size_of::<&Option<Ref<'_, restoration_observation::CurrentObservationHistory>>>()
            + size_of::<&Ref<'_, restoration_observation::CurrentObservationHistory>>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Option<&restoration_observation::OriginalSourceRestorationObservationAttempt>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<usize>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "observation_capacities/tests.rs"]
mod tests;
