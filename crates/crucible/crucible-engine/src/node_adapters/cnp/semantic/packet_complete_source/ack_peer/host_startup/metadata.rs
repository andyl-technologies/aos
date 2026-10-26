//! Counts the actual weak allocations retained by a Source's host SDK marker.
//!
//! Empty Weak links retain no allocation. Expired original links retain their
//! allocation shells without making their payloads available or renewing a
//! lifecycle. Prospective constructor storage remains a separate original quote.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, records::PacketRuntimeMetadataRecordBank,
};
use std::cell::{BorrowError, Ref};

impl OriginalHostStartupMarker {
    /// Prices the constructor's future origin weak view with the census envelope.
    ///
    /// # Errors
    /// Refuses checked header or requested-allocation arithmetic overflow.
    pub(super) fn origin_capacity_requested_bound_data() -> Result<usize, RuntimeError> {
        let header = NodeRuntime::capture_protocol_shared_header_storage(
            1,
            std::mem::align_of::<OriginalHostSdkOrigin>(),
            usize::MAX,
        )?;
        size_of::<OriginalHostSdkOrigin>()
            .checked_add(header)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Observes actual shared shells without upgrading either original weak link.
    ///
    /// # Errors
    /// Refuses invalid geometry, selected-row exhaustion or unready physical
    /// backing. Earlier records, phase flags and original links stay unchanged.
    pub(super) fn retained_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        self.record_retained_capacity_data(&mut census)?;
        Ok(census.finish())
    }
    /// Includes the marker in its parent's existing census without resetting rows.
    ///
    /// # Errors
    /// Refuses exhausted rows, invalid layout or unready physical backing.
    pub(in super::super) fn record_retained_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            origin,
            complete,
            initial_lifecycle_issued,
            initial_lifecycle_quote,
            initial_lifecycle_completed,
            launch,
        } = self;
        census.observe_inline_data(complete);
        census.observe_inline_data(initial_lifecycle_issued);
        census.observe_inline_data(initial_lifecycle_quote);
        census.observe_inline_data(initial_lifecycle_completed);
        census.observe_weak_allocation_data(origin)?;
        if let Some(launch) = launch {
            launch.record_retained_capacity_data(census)?;
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Reports the original host startup marker's actual shared-allocation rows.
    ///
    /// The caller first admits the bank and
    /// [`Self::original_complete_host_startup_marker_capacity_counter_scratch_data`].
    /// Source and SDK holder allocations and nested SDK data remain independent.
    /// This capacity-only DATA neither upgrades weak custody nor establishes
    /// Hello, completed Initial, live launch or native permission. Existing rows
    /// survive failures, including when the original SDK was already dropped.
    ///
    /// # Errors
    /// Refuses foreign Source origin, borrowed birth/marker custody, invalid
    /// geometry, checked overflow or unready/exhausted physical backing.
    pub fn original_complete_host_startup_marker_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let facts = match birth.as_ref() {
            Some(birth) => {
                let marker = birth
                    .host_startup
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                match marker.as_ref() {
                    Some(marker) => marker.retained_capacity_data(bank)?,
                    None => RetainedProtocolMetadataFacts::default(),
                }
            }
            None => RetainedProtocolMetadataFacts::default(),
        };
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(facts)
    }

    /// Names actual weak-shell census and Source/marker loan controls.
    pub fn original_complete_host_startup_marker_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&OriginalHostStartupMarker>()
            + size_of::<Option<&OriginalHostStartupMarker>>()
            + size_of::<&crate::node_adapters::cnp::semantic::process::OriginalHostLaunchIdentity>()
            + size_of::<Ref<'static, Option<OriginalAckPeerBirth>>>()
            + size_of::<Result<Ref<'static, Option<OriginalAckPeerBirth>>, BorrowError>>()
            + size_of::<Ref<'static, Option<OriginalHostStartupMarker>>>()
            + size_of::<Result<Ref<'static, Option<OriginalHostStartupMarker>>, BorrowError>>()
            + size_of::<Result<Ref<'static, Option<OriginalHostStartupMarker>>, RuntimeError>>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
