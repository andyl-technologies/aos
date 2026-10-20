//! Bounds returning work in the selected native Observe preparation loop.
//!
//! The ordinary prefix quote remains complete and unchanged. This additional
//! fixed DATA records the largest one-frame preparation phase from that exact
//! closed projection; all planned, canonical, guard, ACK and incident owners
//! remain in the enclosing retained sum. It grants no transport or Source right.

use super::*;
use crate::reference_packet::service::{
    PacketNative5AckEmitterSelection, PacketNative5CaptureProfile, PacketNative5SourceLaunch,
    capture_allocation::PacketNative5CaptureAllocationSelection,
};

/// Retains the complete original scalar quote beside its returning phase bound.
///
/// No deserializer or public constructor exists. The caller still authenticates
/// the real selected Source/native claim, exact live builder and same originals.
pub(crate) struct OriginalNativeObservePreparationStorageData {
    original: OriginalPacketPrefixStorageData,
    maximum_frame_work: usize,
}

type ProjectionAndPreparation = (
    OriginalPacketPrefixProjectionStorageData,
    OriginalNativeObservePreparationStorageData,
);
type ProjectionAndPreparationResult = Result<ProjectionAndPreparation, ProviderError>;
type PreparationResult = Result<OriginalNativeObservePreparationStorageData, ProviderError>;
type ContentIterator<'a> = std::iter::Flatten<std::slice::Iter<'a, Option<ContentExtent>>>;
type BodyPair<'a> = [(Method, ProjectedBody<'a>); 2];
type BodyIterator<'a> = std::array::IntoIter<(Method, ProjectedBody<'a>), 2>;

impl OriginalNativeObservePreparationStorageData {
    /// Checks every original component before lending its one-frame work bound.
    ///
    /// This does not replace the original complete quote or its actual-owner
    /// reconciliation. Only a selected lifetime caller can use the returned
    /// phase together with the unchanged sum of all persistent prefix owners.
    ///
    /// # Errors
    /// Refuses a changed original quote, overflow or an insufficient phase cap.
    pub(crate) fn maximum_simultaneous_transient_bytes_data(
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

/// Quotes the actual selected OriginalObserve12 producer without changing wire.
///
/// The immutable launch selects this compiled path, never a serialized row or
/// guessed reply. The report caller separately authenticates all full schemas,
/// same Source/native scope and actual builder. The ordinary quote is returned
/// unchanged alongside the additional DATA; it remains fully reconciled.
///
/// # Errors
/// Refuses another launch family, invalid ordinary projection, mismatched full
/// frame population or checked counter/ceiling excess.
pub(crate) fn quote_original_native_observe_prefix_startup_storage_data(
    launch: &PacketNative5SourceLaunch,
    input: OriginalPacketPrefixProjectionInput<'_>,
) -> Result<
    (
        OriginalPacketPrefixProjectionStorageData,
        OriginalNativeObservePreparationStorageData,
    ),
    ProviderError,
> {
    if launch.capture_allocation_selection
        != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        || !matches!(
            launch.capture_profile,
            PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        )
        || launch.protocol_metadata_limits.is_none()
        || launch.ack_emitter_selection != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        || launch.native_codec_metadata_extent
            != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
        || launch.selection.realization.bindings.len() != 1
        || launch.selection.realization.owner_bindings.len() != 1
    {
        return Err(refused());
    }
    let projection = startup::quote_original_packet_prefix_startup_storage_data(launch, input)?;
    let binding = &launch.selection.realization.bindings[0];
    let preparation = project_frames(
        &projection,
        &binding.authority.session_id,
        &binding.authority.incarnation_id,
        allowance(launch.limits.blob_chunk_bytes.get())?.min(4096),
    )?;
    Ok((projection, preparation))
}

impl<S: ProviderStream> Connection<S> {
    /// Counts preparation work from the same actually installed native actor.
    ///
    /// The live report caller has no launch DTO. This method uses its genuine
    /// original admission and immutable selected policy, then the same actual
    /// authority identities and chunk ceiling as the existing live projection.
    /// It grants no method or allocation right. The caller still authenticates
    /// the completed projection against actual reply owners before preparation.
    ///
    /// # Errors
    /// Refuses an absent/stale native admission, another selected family,
    /// changed frame population or full preparation sum, overflow or ceiling.
    pub(crate) fn quote_original_native_observe_preparation_storage_data(
        &self,
        projection: &OriginalPacketPrefixProjectionStorageData,
    ) -> Result<OriginalNativeObservePreparationStorageData, ProviderError> {
        let installed = self.original_native_owned11_admission()?;
        let policy = &installed.policy;
        let selection = policy.original_restoration_activation_selection_data();
        if self.role != EndpointRole::Provider
            || policy.capture_allocation_selection()
                != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || !matches!(
                policy.capture_profile(),
                PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
            || policy.protocol_metadata_limits().is_none()
            || policy.ack_emitter_selection()
                != Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || selection.realization.bindings.len() != 1
            || selection.realization.owner_bindings.len() != 1
        {
            return Err(refused());
        }

        let preparation = project_frames(
            projection,
            self.authority.session_id(),
            self.authority.incarnation_id(),
            allowance(self.authority.limits().blob_chunk_bytes.get())?.min(4096),
        )?;
        installed.authenticate_current(self)?;
        Ok(preparation)
    }
}

// The same unchanged charge_frame implementation supplies each old summed
// preparation increment. This primitive scratch row owns no Envelope, Value,
// canonical bank or transport permit and is never passed to a real builder.
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
    ) -> Result<(), ProviderError> {
        let mut counter = empty_counter();
        charge_frame(&mut counter, frame, request, 65_536)?;
        let work = counter.preparation_transient_requested_bytes;
        self.count = add(self.count, 1)?;
        self.summed = add(self.summed, work)?;
        self.maximum = self.maximum.max(work);
        Ok(())
    }
}

fn project_frames(
    projection: &OriginalPacketPrefixProjectionStorageData,
    session: &Id,
    incarnation: &Id,
    chunk: usize,
) -> Result<OriginalNativeObservePreparationStorageData, ProviderError> {
    if chunk == 0 {
        return Err(credit());
    }
    let mut work = FrameWork {
        count: 0,
        summed: 0,
        maximum: 0,
    };
    work.charge(copy_storage(&projection.terminal), false)?;
    let transfer = add("packet-transfer-".len(), 20)?;
    for object in projection.objects.iter().flatten() {
        for (method, body) in [
            (Method::BlobBegin, ProjectedBody::Begin(transfer, object)),
            (Method::BlobFinish, ProjectedBody::Finish(transfer)),
        ] {
            work.charge(
                continuation::projected_packet_startup_frame(
                    session,
                    incarnation,
                    method,
                    body,
                    projection.maximum_requested_bytes,
                )?,
                true,
            )?;
        }
        let mut remaining = object.payload;
        while remaining > 0 {
            let bytes = remaining.min(chunk);
            let encoded = mul(bytes.div_ceil(3), 4)?;
            work.charge(
                continuation::projected_packet_startup_frame(
                    session,
                    incarnation,
                    Method::BlobChunk,
                    ProjectedBody::Chunk(transfer, encoded),
                    projection.maximum_requested_bytes,
                )?,
                true,
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

/// Names every new fixed row, full result and borrowed iteration view.
///
/// The enclosing selected report getter must add this before entering the
/// additional projection. It changes no ordinary/public counter formula.
pub(crate) fn original_native_observe_preparation_counter_scratch_data() -> usize {
    original_packet_prefix_startup_counter_scratch_data()
        + size_of::<OriginalNativeObservePreparationStorageData>()
        + size_of::<PreparationResult>()
        + size_of::<&Connection<crate::client::DeadlineStream>>()
        + size_of::<&crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission>()
        + size_of::<Result<&crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission, ProviderError>>()
        + size_of::<&std::rc::Rc<crate::reference_packet::Native5Policy>>()
        + size_of::<&PacketNative5CaptureProfile>()
        + size_of::<Option<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>>()
        + size_of::<Option<PacketNative5CaptureAllocationSelection>>()
        + size_of::<Option<PacketNative5AckEmitterSelection>>()
        + size_of::<&crate::reference_packet::control::PacketControlSelection>()
        + size_of::<std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>>()
        + size_of::<Result<std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>, std::cell::BorrowError>>()
        + size_of::<std::rc::Rc<dyn BodySchemaVerifier>>()
        + size_of::<ProjectionAndPreparation>()
        + size_of::<ProjectionAndPreparationResult>()
        + size_of::<OriginalPacketPrefixProjectionStorageData>()
        + size_of::<Result<OriginalPacketPrefixProjectionStorageData, ProviderError>>()
        + 2 * size_of::<OriginalPacketPrefixStorageData>()
        + size_of::<FrameWork>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<&OriginalPacketPrefixProjectionStorageData>()
        + size_of::<&OriginalPacketPrefixStorageData>()
        + size_of::<&mut OriginalPacketPrefixStorageData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&crucible_node_format::NodeBinding>()
        + size_of::<&ContentExtent>()
        + size_of::<&mut FrameWork>()
        + size_of::<std::slice::Iter<'static, Option<ContentExtent>>>()
        + 2 * size_of::<&Id>()
        + size_of::<ContentIterator<'static>>()
        + size_of::<BodyPair<'static>>()
        + size_of::<BodyIterator<'static>>()
        // Chunk, transfer-ID extent, remaining payload, current raw and base64
        // extents coexist in the closed replay; these are explicit data locals.
        + size_of::<(usize, usize, usize, usize, usize)>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

// Tests use a real current fixture only to inspect this DATA projection. This
// cannot install a native selected profile or create transport authority.
#[cfg(test)]
pub(in crate::connection) fn for_test(
    projection: &OriginalPacketPrefixProjectionStorageData,
    authority: &ConnectionAuthority,
) -> Result<OriginalNativeObservePreparationStorageData, ProviderError> {
    project_frames(
        projection,
        authority.session_id(),
        authority.incarnation_id(),
        allowance(authority.limits().blob_chunk_bytes.get())?.min(4096),
    )
}
