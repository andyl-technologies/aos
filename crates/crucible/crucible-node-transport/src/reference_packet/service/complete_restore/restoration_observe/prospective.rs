//! Counts independent real held-model and closed first-observation phases.
//!
//! This producer creates no request, scope, proof or model. The same authenticated
//! captured Control constructor supplies initialized and spare model backing.
//! Closed projections count the real one-batch/no-event Observe and the exact
//! earlier World pair that the SDK authenticates before assigning its new cut.

use super::*;
use crate::client::CnpController;
use crate::reference_packet::service::ack_emitter::{
    original_native_restoration_observation_attempt_backing_data,
    original_native_restoration_observation_counter_scratch_data,
};
use crate::reference_packet::service::{PacketNative5SourceLaunch, complete_restore::transfer::*};
use std::mem::size_of;

impl CnpController {
    /// Quotes the independent once-observation row from actual pre-Prepare inputs.
    ///
    /// The real Window separately binds this DATA and adds all simultaneous
    /// Source, Core, SDK and other-child owners before issuing any claim.
    ///
    /// # Errors
    /// Refuses another Controller/launch, missing full negotiated observation
    /// selection, invalid selected raw owner/model geometry or checked demand
    /// beyond the actual finite construction ceiling.
    pub fn quote_original_installed_restoration_observation_construction_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
    ) -> Result<OriginalInstalledRestorationObservationConstructionData, ProviderError> {
        let identity = self.authenticate_original_installed_activation_launch_data(launch)?;
        authenticate_restoration_observe_selection_data(
            self.original_installed_restoration_observation_selection_data()?,
            self.authority(),
        )?;
        let mut row = quote(launch, inputs)?;
        // The generic host receiver can retain unexpected/incomplete provider
        // transfers before the promised root arrives. Price its actual fixed
        // ceilings and every named journal/ACK owner independently of native
        // prefix production; old current owners supply no prospective credit.
        let receiver =
            self.original_observation_receive_storage_data(inputs.maximum_requested_bytes)?;
        row.host_retained = add(row.host_retained, receiver.retained)?;
        row.host_transient = add(row.host_transient, receiver.transient)?;
        row.host_scratch = add(row.host_scratch, receiver.scratch)?;
        row.requested = sum(&[
            row.requested,
            receiver.retained,
            receiver.transient,
            receiver.scratch,
        ])?;
        if row.requested > inputs.maximum_requested_bytes {
            return Err(credit());
        }
        row.controller = identity;
        self.authenticate_original_installed_activation_launch_data(launch)?;
        authenticate_restoration_observe_selection_data(
            self.original_installed_restoration_observation_selection_data()?,
            self.authority(),
        )?;
        Ok(row)
    }
}

fn quote(
    launch: &PacketNative5SourceLaunch,
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
) -> Result<OriginalInstalledRestorationObservationConstructionData, ProviderError> {
    let model = complete_restore_invocation_owner_construction_storage_data(inputs)?;
    quote_from_cached_model_data(launch, &model, inputs.maximum_requested_bytes)
}

/// Projects the same closed proof geometry from already admitted immutable DATA.
///
/// No raw metadata is decoded here, and no Controller or observation is issued.
/// The actual registered holder must bind the cached row to its same ticket and
/// launch before and after this borrow. All returned demand is paid anew.
pub(crate) fn quote_from_cached_model_data(
    launch: &PacketNative5SourceLaunch,
    model: &PacketCompleteRestoreOwnerValidationStorage,
    maximum: usize,
) -> Result<OriginalInstalledRestorationObservationConstructionData, ProviderError> {
    let model_work = sum(&[model.control_bytes, model.model_vector_backing_bytes])?;
    let [wire, terminal, proof, world_original, world_terminal] =
        super::projection::wire_projection_data(maximum)?;
    let objects = [
        crate::connection::OriginalContinuationContentExtent {
            maximum_payload_bytes: proof.maximum_encoded_bytes.min(65_536),
            media_type: "application/json",
        },
        crate::connection::OriginalContinuationContentExtent {
            maximum_payload_bytes: 65_536,
            media_type: "application/json",
        },
    ];
    let prefix = crate::connection::quote_original_packet_prefix_startup_storage_data(
        launch,
        crate::connection::OriginalPacketPrefixProjectionInput {
            terminal: &terminal,
            original: &wire,
            objects: &objects,
            maximum_requested_bytes: maximum,
        },
    )?;
    let scratch = original_installed_restoration_observation_construction_counter_scratch_data();
    // Closed new original/request/body/artifact and actual terminal owners are
    // independent of the existing completed World banks. World reserialization
    // work is counted separately, without recopying its persistent ownership.
    // One parsed result may reserve the Vec push minimum even for one batch.
    // SDK and caller retain independent typed result vectors; native reply
    // construction has its own independently counted typed owner.
    let typed_result_vector = mul(4, size_of::<crucible_node_format::ObservationBatch>())?;
    let host_retained = sum(&[
        mul(wire.requested_total()?, 6)?,
        mul(terminal.requested_total()?, 6)?,
        mul(typed_result_vector, 2)?,
        prefix.source_owner_requested_bytes,
        CnpController::original_installed_restoration_observation_owner_header_bytes_data(),
    ])?;
    // Assignment/digest has the body Value and typed ObserveRequest alive beside
    // its parsed request DTO, whole Envelope Value, canonical output and original.
    // Each independently projected whole owner is counted here, including a
    // malformed body prefix; no encoded-length-as-typed-backing shortcut is used.
    let host_transient = sum(&[
        mul(wire.requested_total()?, 5)?,
        mul(terminal.requested_total()?, 2)?,
        mul(typed_result_vector, 2)?,
        world_original.requested_total()?,
        world_terminal.requested_total()?,
        prefix.requested_bytes()?,
    ])?;
    let native_retained = sum(&[
        original_native_restoration_observation_attempt_backing_data()?,
        model_work,
        mul(wire.requested_total()?, 4)?,
        mul(terminal.requested_total()?, 3)?,
        prefix.source_owner_requested_bytes,
        mul(proof.requested_total()?, 4)?,
        prefix.exchange.requested_bytes()?,
    ])?;
    let native_transient = sum(&[
        model_work,
        mul(wire.requested_total()?, 5)?,
        mul(terminal.requested_total()?, 2)?,
        typed_result_vector,
        mul(proof.requested_total()?, 3)?,
        prefix.requested_bytes()?,
    ])?;
    let native = PacketRestorationActivationAllocationRow {
        retained_requested_bytes: as_u64(native_retained)?,
        maximum_simultaneous_transient_bytes: as_u64(native_transient)?,
        declared_counter_scratch_bytes: as_u64(scratch)?,
    };
    let evidence = sum(&[
        mul(model_work, 2)?,
        proof.requested_total()?,
        size_of::<crate::reference_packet::control::PacketNative5UnderlyingRecord>(),
        size_of::<crate::reference_packet::control::PacketNativeRecord>().max(size_of::<
            crate::reference_packet::connected::PacketConnectedNativeRecord,
        >()),
    ])?;
    let requested = sum(&[
        host_retained,
        host_transient,
        scratch,
        usize::try_from(native.requested_bytes_data()?).map_err(|_| credit())?,
    ])?;
    Ok(OriginalInstalledRestorationObservationConstructionData {
        controller: std::ptr::null(),
        native,
        host_retained,
        host_transient,
        host_scratch: scratch,
        source_evidence_retained: mul(evidence, 2)?,
        source_evidence_transient: sum(&[mul(evidence, 2)?, mul(proof.requested_total()?, 2)?])?,
        source_evidence_scratch: scratch,
        requested,
        scratch,
    })
}

/// Recounts this genuine held model before any new observation proof allocation.
///
/// The native caller first retains its original and typed partials under fixed
/// pre-Child ingress, authenticates the Source MAC and exact actual World pair,
/// then compares each returned axis with the separately admitted signed row.
///
/// # Errors
/// Refuses changed frame limits, invalid raw selected owner/model geometry,
/// arithmetic overflow or a native total exceeding that same signed ceiling.
pub(crate) fn original_native_restoration_observation_required_storage_data(
    launch: &PacketNative5SourceLaunch,
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
    maximum_frame: usize,
) -> Result<PacketRestorationActivationAllocationRow, ProviderError> {
    if usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| credit())? != maximum_frame {
        return Err(invalid());
    }
    let row = quote(launch, inputs)?.native;
    if usize::try_from(row.requested_bytes_data()?).map_err(|_| credit())?
        > inputs.maximum_requested_bytes
    {
        return Err(credit());
    }
    Ok(row)
}

/// Names explicit prospective layouts, conversions and complete return views.
pub fn original_installed_restoration_observation_construction_counter_scratch_data() -> usize {
    use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
    size_of::<&PacketCompleteRestoreOwnerValidationStorage>()
        + size_of::<OriginalInstalledRestorationObservationConstructionData>()
        + size_of::<Result<OriginalInstalledRestorationObservationConstructionData, ProviderError>>(
        )
        + size_of::<[OriginalSerializationStorageData; 5]>()
        + size_of::<Result<[OriginalSerializationStorageData; 5], ProviderError>>()
        + size_of::<std::slice::IterMut<'static, OriginalSerializationStorageData>>()
        + size_of::<[crate::connection::OriginalContinuationContentExtent<'static>; 2]>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionStorageData>()
        + size_of::<
            Result<crate::connection::OriginalPacketPrefixProjectionStorageData, ProviderError>,
        >()
        + size_of::<Result<PacketRestorationActivationAllocationRow, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Vec<crucible_node_format::ObservationBatch>>()
        + size_of::<Result<Vec<crucible_node_format::ObservationBatch>, serde_json::Error>>()
        + size_of::<[usize; 8]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + complete_restore_selected_owner_construction_counter_scratch_data()
        + crate::connection::original_packet_prefix_startup_counter_scratch_data()
        + restoration_observe_protocol_counter_scratch_data()
        + original_native_restoration_observation_counter_scratch_data()
        + CnpController::original_installed_restoration_observation_counter_scratch_data()
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(credit)
}

fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(credit)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    let mut total = 0usize;
    for term in terms {
        total = add(total, *term)?;
    }
    Ok(total)
}

fn as_u64(bytes: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(bytes).map_err(|_| credit())?))
}
