//! Projects original restoration transfer and activation capacity components.
//!
//! Legacy restoration tickets/mappings, observation, producer, Capture, input and
//! suffix histories still have independent defining rosters. This projection
//! neither replaces those owners nor establishes whole-Source traversal work.

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
    /// Reports original transfer/activation banks and their retained child owners.
    ///
    /// Inline headers belong to this Source. Failed partials remain capacity DATA
    /// independently of phase-order, native-evidence and publication eligibility.
    /// Other restoration/history owners require their own census components.
    ///
    /// # Errors
    /// Refuses another Source/activation creator, busy association custody,
    /// exhausted rows/depth, unsupported child backing or checked layout overflow.
    pub fn original_restoration_phase_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(activation) = association
            .as_ref()
            .and_then(|owner| owner.restoration_activation.as_ref())
        {
            activation.check_capacity_creator_data()?;
        }
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(association) = association.as_ref() {
            if let Some(transfer) = &association.restore_transfer_banks {
                transfer.record_capacity_data(&mut census)?;
            }
            if let Some(activation) = &association.restoration_activation {
                activation.record_capacity_data(&mut census)?;
            }
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names concrete restoration projection, bank-loan and defining child controls.
    pub fn original_restoration_phase_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + restore_transfer_banks::OriginalRestoreTransferBanks::capacity_counter_scratch_data()
            + restoration_activation::OriginalSourceRestorationActivationAttempt::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Option<&restore_transfer_banks::OriginalRestoreTransferBanks>>()
            + size_of::<Option<&restoration_activation::OriginalSourceRestorationActivationAttempt>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<usize>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "restoration_capacities/tests.rs"]
mod tests;
