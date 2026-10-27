//! Holds the real Capture and materialization loans across their capacity walk.
//!
//! Capacity DATA includes unfinished owners without issuing a construction row,
//! validating native output, signing a bridge or moving Runtime/Source custody.

use super::super::capacities::fields_layout_data;
use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer::association::OriginalAckPeerAssociation;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts,
    records::PacketRuntimeMetadataRecordBank,
};
use std::{
    cell::{BorrowError, Ref, RefCell},
    mem::size_of,
};

/// Binds the actual nested loan to its containing Capture allocation.
struct CaptureCapacityRead<'a> {
    owner: &'a CaptureOnceOwner,
    materialization: Ref<'a, super::super::effect::CaptureMaterializationOwner>,
}

impl CaptureOnceOwner {
    fn capacity_read_data<'a>(
        &'a self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<CaptureCapacityRead<'a>, RuntimeError> {
        let materialization = self
            .materialization
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        self.post_confirmation.check_capacity_creator_data(source)?;
        Ok(CaptureCapacityRead {
            owner: self,
            materialization,
        })
    }

    fn capacity_counter_scratch_data() -> usize {
        fields_layout_data::<Self, _>(|owner| {
            let Self {
                stage,
                construction,
                prefix,
                materialization,
                transport,
                post_confirmation,
            } = owner;
            (
                stage,
                construction,
                prefix,
                materialization,
                transport,
                post_confirmation,
            )
        }) + size_of::<&Self>()
            + size_of::<&RefCell<super::super::effect::CaptureMaterializationOwner>>()
            + size_of::<Ref<'_, super::super::effect::CaptureMaterializationOwner>>()
            + size_of::<
                Result<Ref<'_, super::super::effect::CaptureMaterializationOwner>, BorrowError>,
            >()
            + size_of::<CaptureCapacityRead<'_>>()
            + size_of::<Result<CaptureCapacityRead<'_>, RuntimeError>>()
            + size_of::<&CaptureCapacityRead<'_>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + super::super::effect::CaptureConstructionOwners::capacity_counter_scratch_data()
            + CapturePrefixOwners::capacity_counter_scratch_data()
            + super::super::effect::CaptureMaterializationOwner::capacity_counter_scratch_data()
            + CaptureSdkOwners::capacity_counter_scratch_data()
            + CapturePostConfirmationOwners::capacity_counter_scratch_data()
    }
}

impl CaptureCapacityRead<'_> {
    fn record_capacity_data(
        &self,
        source: &PacketCompleteSemanticSource,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.owner
            .post_confirmation
            .check_capacity_creator_data(source)?;

        let CaptureOnceOwner {
            stage,
            construction,
            prefix,
            materialization: original_cell,
            transport,
            post_confirmation,
        } = self.owner;
        // The private constructor borrows this cell once and keeps that exact
        // guard below; its inline RefCell header belongs to the Source root.
        let _original_cell: &RefCell<super::super::effect::CaptureMaterializationOwner> =
            original_cell;
        census.observe_inline_data(stage)?;

        construction.record_capacity_data(census)?;
        prefix.record_capacity_data(census)?;
        self.materialization.record_capacity_data(census)?;
        if let Some(transport) = transport {
            transport.record_capacity_data(census)?;
        }
        post_confirmation.record_capacity_data(source, census)
    }
}

impl PacketCompleteSemanticSource {
    /// Reports actual retained Capture phase capacities under both original loans.
    ///
    /// The association, Capture owner and nested materialization cell stay
    /// borrowed throughout the closed walk. A retained administrative bridge
    /// must belong to this exact Source allocation before physical rows begin.
    /// Failed phases remain DATA without Capture, signing or completion rights.
    /// Whole-Source scalar work and the genuine one-use handoff remain separate.
    /// The caller admits the companion counter scratch before invoking this walk.
    ///
    /// # Errors
    /// Refuses foreign original creators, busy custody, checked geometry/depth
    /// overflow, unsupported children or exhausted physical metadata rows.
    pub fn original_restored_capture_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let capture = association
            .as_ref()
            .map(|association| association.restored_capture.try_borrow())
            .transpose()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let read = capture
            .as_deref()
            .map(|capture| capture.capacity_read_data(self))
            .transpose()?;

        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        if let Some(read) = &read {
            read.record_capacity_data(self, &mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }

    /// Names the actual Source, Capture and nested materialization loan controls.
    pub fn original_restored_capture_capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<Ref<'_, Option<OriginalAckPeerAssociation>>>()
            + size_of::<Result<Ref<'_, Option<OriginalAckPeerAssociation>>, BorrowError>>()
            + size_of::<Option<Ref<'_, CaptureOnceOwner>>>()
            + size_of::<Result<Ref<'_, CaptureOnceOwner>, BorrowError>>()
            + size_of::<Option<Result<Ref<'_, CaptureOnceOwner>, BorrowError>>>()
            + size_of::<Option<CaptureCapacityRead<'_>>>()
            + size_of::<Option<Result<CaptureCapacityRead<'_>, RuntimeError>>>()
            + size_of::<&PacketRuntimeMetadataRecordBank>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + CaptureOnceOwner::capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
