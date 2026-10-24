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

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::preparation::OriginalNativeObservePreparationStorageData;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::preparation;

type ProjectionAndPreparation = (
    OriginalPacketPrefixProjectionStorageData,
    OriginalNativeObservePreparationStorageData,
);
type ProjectionAndPreparationResult = Result<ProjectionAndPreparation, ProviderError>;
type PreparationResult = Result<OriginalNativeObservePreparationStorageData, ProviderError>;
type ContentIterator<'a> = std::iter::Flatten<std::slice::Iter<'a, Option<ContentExtent>>>;
type BodyPair<'a> = [(Method, ProjectedBody<'a>); 2];
type BodyIterator<'a> = std::array::IntoIter<(Method, ProjectedBody<'a>), 2>;

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

fn project_frames(
    projection: &OriginalPacketPrefixProjectionStorageData,
    session: &Id,
    incarnation: &Id,
    chunk: usize,
) -> Result<OriginalNativeObservePreparationStorageData, ProviderError> {
    preparation::project_frames(
        projection,
        session,
        incarnation,
        chunk,
        size_of::<ResponseBody>().max(size_of::<RequestBody>()),
        &acknowledgements::ACK_FIXED_LAYOUT,
    )
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
        + preparation::FRAME_WORK_BYTES
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<&OriginalPacketPrefixProjectionStorageData>()
        + size_of::<&OriginalPacketPrefixStorageData>()
        + size_of::<&mut OriginalPacketPrefixStorageData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&crucible_node_format::NodeBinding>()
        + size_of::<&ContentExtent>()
        + preparation::FRAME_WORK_MUT_BORROW_BYTES
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
        // The existing loop rows above remain intact. These are the added
        // upper forwarding call's actual borrowed inputs and returned result.
        + size_of::<&OriginalPacketPrefixProjectionStorageData>()
        + 2 * size_of::<&Id>()
        + size_of::<usize>() // copied chunk argument
        + size_of::<PreparationResult>()
        // The formed ACK loan and the upper/lower/FrameWork parameter views
        // coexist across the nested call; no private layout is mirrored.
        + 4 * size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>()
        // Two compiled max operands and its result, followed by the lower
        // loop and FrameWork charge's distinct owned scalar parameters.
        + 5 * size_of::<usize>()
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
