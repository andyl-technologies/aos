//! Preserves all actual capture-bank slots, including partial and failed history.
//!
//! Association/transfer eligibility remains in the existing lifecycle gates.
//! Every present independent owner is counted even if its companion slot is
//! incomplete. Inline headers belong to the enclosing Source allocation.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
    records::PacketRuntimeMetadataRecordBank,
};
use std::{
    cell::{BorrowError, Ref},
    mem::size_of,
};

impl PacketCompleteCaptureBanks {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            protocol_detached,
            transferred,
            semantic,
            semantic_snapshot,
            ancestry,
            ancestry_record,
            journal,
            journal_record,
            capture_response,
            confirmation_response,
            protocol,
            settled_protocol,
            protocol_payload,
            native_banks,
            native_objects,
            native_after_bank,
            native_after_object,
        } = self;
        census.observe_inline_data(protocol_detached);
        census.observe_inline_data(transferred);

        for reservation in [semantic, ancestry, journal, native_after_bank]
            .into_iter()
            .flatten()
        {
            reservation.record_capacity_data(census)?;
        }
        for reservation in native_banks.iter().flatten() {
            reservation.record_capacity_data(census)?;
        }
        if let Some(snapshot) = semantic_snapshot {
            snapshot.record_capacity_data(census)?;
        }
        for object in [ancestry_record, journal_record, native_after_object]
            .into_iter()
            .flatten()
        {
            census.observe(object)?;
        }
        for object in native_objects.iter().flatten() {
            census.observe(object)?;
        }
        if let Some(response) = capture_response {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::Response(response))?;
        }
        if let Some((response, receipt)) = confirmation_response {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::Response(response))?;
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::AfterConfirmation(receipt),
            )?;
        }
        if let Some(protocol) = protocol {
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::SnapshotReservation(protocol),
            )?;
        }
        if let Some(snapshot) = settled_protocol {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::Snapshot(snapshot))?;
        }
        if let Some((owner, bytes)) = protocol_payload {
            census
                .observe_capture_protocol_data(RetainedCaptureProtocolData::PayloadOwner(owner))?;
            census.observe(bytes)?;
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Reports every actual retained capture-bank capacity and optional rows.
    ///
    /// Partial, failed and independently coexisting slots keep their backing.
    /// These facts establish no completed capture, valid owner association or
    /// whole-Source traversal-work bound. Callers first admit the physical bank
    /// and [`Self::original_complete_capture_banks_capacity_counter_scratch_data`].
    /// Existing byte accounting and lifecycle eligibility remain independent.
    ///
    /// # Errors
    /// Refuses foreign origins, busy custody, SDK observation failure, invalid
    /// layouts, exhausted selected rows or unavailable physical backing.
    pub fn original_complete_capture_banks_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .capture_banks
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(banks) = slot.as_ref() {
            banks.record_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names actual bank loans, iterators, SDK/Core walks and result controls.
    pub fn original_complete_capture_banks_capacity_counter_scratch_data() -> usize {
        type BankSlots = std::array::IntoIter<&'static Option<CnpSemanticSnapshotReservation>, 4>;
        type ObjectSlots = std::array::IntoIter<&'static Option<InputPayload>, 3>;
        type NativeBanks = std::slice::Iter<'static, Option<CnpSemanticSnapshotReservation>>;
        type NativeObjects = std::slice::Iter<'static, Option<InputPayload>>;

        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + size_of::<std::iter::Flatten<BankSlots>>()
            + size_of::<std::iter::Flatten<ObjectSlots>>()
            + size_of::<std::iter::Flatten<NativeBanks>>()
            + size_of::<std::iter::Flatten<NativeObjects>>()
            + super::super::super::semantic_snapshot::capacities::capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&PacketCompleteCaptureBanks>()
            + size_of::<Ref<'static, Option<PacketCompleteCaptureBanks>>>()
            + size_of::<Result<Ref<'static, Option<PacketCompleteCaptureBanks>>, BorrowError>>()
            + size_of::<std::option::Iter<'static, CnpSemanticSnapshotReservation>>()
            + size_of::<std::slice::Iter<'static, Option<CnpSemanticSnapshotReservation>>>()
            + size_of::<std::option::Iter<'static, InputPayload>>()
            + size_of::<std::slice::Iter<'static, Option<InputPayload>>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
