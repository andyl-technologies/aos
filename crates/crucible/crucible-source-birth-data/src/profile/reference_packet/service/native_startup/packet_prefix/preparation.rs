//! Replays the original selected Observe preparation-frame work as inert DATA.
//!
//! Transport retains launch-family and live connection authentication. This
//! numeric replay checks the complete original scalar quote; it constructs no
//! native owner, frame bank, transport permit or Source authority.

use super::super::report_ack::AckFixedLayoutData;
use super::frames::{ProjectedBody, copy_storage, projected_packet_startup_frame};
use super::{
    OriginalPacketPrefixProjectionStorageData, OriginalPacketPrefixStorageData, add, charge_frame,
    credit, mul, refused,
};
use crate::ProviderError;
use crate::profile::envelope::Method;
use crate::profile::serialization_storage::OriginalSerializationStorageData;
use crucible_node_format::Id;
use std::mem::size_of;

/// Retains the complete original scalar quote beside its returning phase bound.
///
/// Its fields remain opaque. This numeric constructor and equality check do
/// not authenticate the real selected Source/native claim or live builder.
pub struct OriginalNativeObservePreparationStorageData {
    original: OriginalPacketPrefixStorageData,
    maximum_frame_work: usize,
}

impl OriginalNativeObservePreparationStorageData {
    /// Checks every original component before lending its one-frame work bound.
    ///
    /// This does not replace the original complete quote or its actual-owner
    /// reconciliation. The upper selected lifetime caller must combine this
    /// numeric phase with the unchanged sum of all persistent prefix owners.
    ///
    /// # Errors
    /// Refuses a changed original quote, overflow or an insufficient phase cap.
    pub fn maximum_simultaneous_transient_bytes_data(
        &self,
        prefix: &OriginalPacketPrefixStorageData,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        if prefix != &self.original || self.maximum_frame_work > maximum {
            return Err(credit());
        }
        Ok(self.maximum_frame_work)
    }
}

/// Names the actual private replay accumulator's compiled inline width.
pub const FRAME_WORK_BYTES: usize = size_of::<FrameWork>();

/// Names the actual private replay accumulator's mutable receiver view.
pub const FRAME_WORK_MUT_BORROW_BYTES: usize = size_of::<&mut FrameWork>();

// The unchanged frame charge supplies each original summed increment. This
// scalar counter owns no Envelope, DOM, bank or native permission.
fn empty_counter() -> OriginalPacketPrefixStorageData {
    OriginalPacketPrefixStorageData {
        native_retained_backing_bytes: None,
        frames: 0,
        requests: 0,
        evidence_payload_bytes: 0,
        outgoing_framed_bytes: 0,
        incoming_framed_bytes: 0,
        new_transport_credit_bytes: 0,
        original_plan_requested_bytes: 0,
        acknowledgement_index_requested_bytes: 0,
        canonical_requested_bytes: 0,
        record_slots_requested_bytes: 0,
        outgoing_guard_requested_bytes: 0,
        response_iterator_requested_bytes: 0,
        successful_ack_cache_requested_bytes: 0,
        one_open_ack_requested_bytes: 0,
        containment_requested_bytes: 0,
        construction_transient_requested_bytes: 0,
        preparation_transient_requested_bytes: 0,
        declared_quote_scratch_bytes: 0,
        original_literal_required_bytes: 0,
        original_slots_required: 0,
    }
}

fn copy_quote(value: &OriginalPacketPrefixStorageData) -> OriginalPacketPrefixStorageData {
    OriginalPacketPrefixStorageData {
        native_retained_backing_bytes: value.native_retained_backing_bytes,
        frames: value.frames,
        requests: value.requests,
        evidence_payload_bytes: value.evidence_payload_bytes,
        outgoing_framed_bytes: value.outgoing_framed_bytes,
        incoming_framed_bytes: value.incoming_framed_bytes,
        new_transport_credit_bytes: value.new_transport_credit_bytes,
        original_plan_requested_bytes: value.original_plan_requested_bytes,
        acknowledgement_index_requested_bytes: value.acknowledgement_index_requested_bytes,
        canonical_requested_bytes: value.canonical_requested_bytes,
        record_slots_requested_bytes: value.record_slots_requested_bytes,
        outgoing_guard_requested_bytes: value.outgoing_guard_requested_bytes,
        response_iterator_requested_bytes: value.response_iterator_requested_bytes,
        successful_ack_cache_requested_bytes: value.successful_ack_cache_requested_bytes,
        one_open_ack_requested_bytes: value.one_open_ack_requested_bytes,
        containment_requested_bytes: value.containment_requested_bytes,
        construction_transient_requested_bytes: value.construction_transient_requested_bytes,
        preparation_transient_requested_bytes: value.preparation_transient_requested_bytes,
        declared_quote_scratch_bytes: value.declared_quote_scratch_bytes,
        original_literal_required_bytes: value.original_literal_required_bytes,
        original_slots_required: value.original_slots_required,
    }
}

struct FrameWork {
    count: usize,
    summed: usize,
    maximum: usize,
}

impl FrameWork {
    fn charge(
        &mut self,
        frame: OriginalSerializationStorageData,
        request: bool,
        maximum_body_header_bytes: usize,
        acknowledgement_layout: &AckFixedLayoutData,
    ) -> Result<(), ProviderError> {
        let mut counter = empty_counter();
        charge_frame(
            &mut counter,
            frame,
            request,
            65_536,
            maximum_body_header_bytes,
            acknowledgement_layout,
        )?;
        let work = counter.preparation_transient_requested_bytes;
        self.count = add(self.count, 1)?;
        self.summed = add(self.summed, work)?;
        self.maximum = self.maximum.max(work);
        Ok(())
    }
}

/// Replays the original closed terminal and Blob preparation-frame grammar.
///
/// The caller supplies genuine compiled header and ACK layouts, not final rows.
/// It separately authenticates original launch/authority and selected policy.
///
/// # Errors
/// Refuses a zero chunk, the original frame/arithmetic/ACK errors, or a changed
/// complete frame population or summed preparation component, in original order.
pub fn project_frames(
    projection: &OriginalPacketPrefixProjectionStorageData,
    session: &Id,
    incarnation: &Id,
    chunk: usize,
    maximum_body_header_bytes: usize,
    acknowledgement_layout: &AckFixedLayoutData,
) -> Result<OriginalNativeObservePreparationStorageData, ProviderError> {
    if chunk == 0 {
        return Err(credit());
    }
    let mut work = FrameWork {
        count: 0,
        summed: 0,
        maximum: 0,
    };
    work.charge(
        copy_storage(&projection.terminal),
        false,
        maximum_body_header_bytes,
        acknowledgement_layout,
    )?;
    let transfer = add("packet-transfer-".len(), 20)?;
    for object in projection.objects.iter().flatten() {
        for (method, body) in [
            (Method::BlobBegin, ProjectedBody::Begin(transfer, object)),
            (Method::BlobFinish, ProjectedBody::Finish(transfer)),
        ] {
            work.charge(
                projected_packet_startup_frame(
                    session,
                    incarnation,
                    method,
                    body,
                    projection.maximum_requested_bytes,
                )?,
                true,
                maximum_body_header_bytes,
                acknowledgement_layout,
            )?;
        }
        let mut remaining = object.payload;
        while remaining > 0 {
            let bytes = remaining.min(chunk);
            let encoded = mul(bytes.div_ceil(3), 4)?;
            work.charge(
                projected_packet_startup_frame(
                    session,
                    incarnation,
                    Method::BlobChunk,
                    ProjectedBody::Chunk(transfer, encoded),
                    projection.maximum_requested_bytes,
                )?,
                true,
                maximum_body_header_bytes,
                acknowledgement_layout,
            )?;
            remaining -= bytes;
        }
    }
    if work.count != projection.exchange.frames
        || work.summed != projection.exchange.preparation_transient_requested_bytes
    {
        return Err(refused());
    }
    Ok(OriginalNativeObservePreparationStorageData {
        original: copy_quote(&projection.exchange),
        maximum_frame_work: work.maximum,
    })
}
