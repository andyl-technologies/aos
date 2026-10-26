//! Counts actual legacy restoration body, mapping and bank components.
//!
//! The Core ticket retains a separate shared original-Source graph. This body
//! projection deliberately excludes that graph; whole-Source admission must
//! visit it independently. Failed bodies remain DATA regardless of eligibility.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
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

impl OriginalCompleteRestoreAttempt {
    fn check_body_capacity_creator_data(&self) -> Result<(), RuntimeError> {
        if let Some(mapping) = &self.mapping {
            RetainedCaptureProtocolData::ArchivedMapping(mapping)
                .check_original_creator()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        Ok(())
    }

    fn record_body_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_body_capacity_creator_data()?;
        let Self {
            ticket: _,
            mapping,
            journal,
            request,
            context,
            normalized,
            banks,
            assigned_digest,
            prepared,
            ready,
            signing_started,
            sealed,
            publishing_started,
            frame_maximum,
        } = self;
        census.observe_inline_data(assigned_digest);
        census.observe_inline_data(prepared);
        census.observe_inline_data(ready);
        census.observe_inline_data(signing_started);
        census.observe_inline_data(sealed);
        census.observe_inline_data(publishing_started);
        census.observe_inline_data(frame_maximum);

        // Raw, normalized and typed owners coexist; none replaces another row.
        for bank in banks {
            census.observe(bank)?;
        }
        for value in normalized.iter().flatten() {
            record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
        }
        census.observe(journal)?;
        census.observe(request)?;
        census.observe(context)?;
        if let Some(mapping) = mapping {
            census.observe_capture_protocol_data(RetainedCaptureProtocolData::ArchivedMapping(
                mapping,
            ))?;
        }
        self.check_body_capacity_creator_data()
    }

    fn body_capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(
                &Option<PreparedArchivedProtocolMapping>,
                &Option<crate::node_adapters::cnp::PacketCompleteSettledJournal>,
                &Option<PacketCompleteRestoreRequest>,
                &Option<PacketCompleteRestoreContext>,
                &[Option<serde_json::Value>; 6],
                &[Vec<u8>; 6],
                &Option<[u8; 32]>,
                &bool,
                &bool,
                &bool,
                &bool,
                &bool,
                &usize,
            )>()
            + size_of::<std::slice::Iter<'_, Vec<u8>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'_, Option<serde_json::Value>>>>()
            + size_of::<Option<&PreparedArchivedProtocolMapping>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

impl PacketCompleteSemanticSource {
    /// Reports retained legacy restoration bodies, mapping and raw banks.
    ///
    /// Inline headers belong to this Source. The shared Core ticket graph and
    /// other Source projections require their own census. No phase, signature,
    /// liveness, native evidence or restoration eligibility is inferred.
    ///
    /// # Errors
    /// Refuses foreign Source/mapping creators, busy association custody,
    /// unsupported backing, row/depth exhaustion or checked layout overflow.
    pub fn original_legacy_restoration_body_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let restore = association
            .as_ref()
            .and_then(|owner| owner.restore.as_ref());
        if let Some(restore) = restore {
            restore.check_body_capacity_creator_data()?;
        }
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(restore) = restore {
            restore.record_body_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names borrowed legacy restoration body and Source projection controls.
    pub fn original_legacy_restoration_body_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + OriginalCompleteRestoreAttempt::body_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<&OriginalAckPeerAssociation>>()
            + size_of::<Option<&OriginalCompleteRestoreAttempt>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<usize>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
