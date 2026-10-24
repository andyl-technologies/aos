//! Quotes complete independent activation owners before the first Prepare.
//!
//! The captured Control/model remains literal behind the physical hold through
//! Arm. WorldActivate prepares its proof before release. This producer counts
//! that actual raw model's construction upper independently of closed future
//! request, receipt, transfer and Source evidence owners. It creates no DTO,
//! digest, request, native owner or permission to spend the resulting DATA.

use super::storage::{OriginalInstalledRestorationActivationConstructionData, PhaseStorage};
use super::*;
use crate::client::CnpController;
use crate::reference_packet::service::{PacketNative5SourceLaunch, complete_restore::transfer::*};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
use std::mem::size_of;

/// Names the defining pre-Prepare producer's fixed parser/projection views.
pub fn original_installed_restoration_activation_construction_counter_scratch_data() -> usize {
    complete_restore_selected_owner_construction_counter_scratch_data()
        + crate::connection::original_packet_prefix_startup_counter_scratch_data()
        + restoration_activation_schema_counter_scratch_data()
        + restoration_activation_retained_native_evidence_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + super::restoration_activation_protocol_counter_scratch_data()
        + crate::reference_packet::service::ack_emitter::native_boot::original_native_restoration_activation_counter_scratch_data()
        + crate::reference_packet::control::original_restoration_coordinator_counter_scratch_data()
        + size_of::<PhaseStorage>()
        + size_of::<Result<PhaseStorage, ProviderError>>()
        + size_of::<PacketRestorationActivationAllocationRow>()
        + size_of::<Result<PacketRestorationActivationAllocationRow, ProviderError>>()
        + size_of::<Option<&[u8]>>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<PacketRestorationActivationCoordinatorConstructionInputs<'static>>()
        + size_of::<[PhaseStorage; 2]>()
        + size_of::<[super::upload::storage::UploadStorage; 2]>()
        + super::upload::restoration_activation_upload_counter_scratch_data()
        + size_of::<OriginalInstalledRestorationActivationConstructionData>()
        + size_of::<Result<OriginalInstalledRestorationActivationConstructionData, ProviderError>>()
        + size_of::<crate::client::OriginalRestorationActivationTargetBindingData<'static>>()
        + size_of::<Result<crate::client::OriginalRestorationActivationTargetBindingData<'static>, ProviderError>>()
        + 3 * size_of::<OriginalSerializationStorageData>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionStorageData>()
        + size_of::<[crate::connection::OriginalContinuationContentExtent<'static>; 2]>()
        + size_of::<[usize; 8]>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<[OriginalSerializationStorageData; 3], ProviderError>>()
        + size_of::<&crate::reference_packet::service::native_startup::contract_value::ContractValue<'static>>()
}

impl CnpController {
    /// Counts the actual held model and the complete two-phase activation work.
    ///
    /// `launch` and `inputs` are the same authenticated pre-Prepare originals
    /// lent by the genuine Core Window. Their encoded bounds are DATA until
    /// that Window independently admits this row with all other live owners.
    /// This allocating permission is never inferred from a schema or a number.
    ///
    /// # Errors
    /// Refuses a different actual controller/launch, unselected full contract,
    /// invalid captured outer14/Control correspondence, exhausted current SDK
    /// banks, malformed bounded model geometry or checked requested overflow.
    pub fn quote_original_installed_restoration_activation_construction_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
        coordinator: &PacketRestorationActivationCoordinatorConstructionInputs<'_>,
    ) -> Result<OriginalInstalledRestorationActivationConstructionData, ProviderError> {
        let identity = self.authenticate_original_installed_activation_launch_data(launch)?;
        let mut result = quote_phases(launch, inputs, coordinator)?;
        result.controller = identity;
        self.authenticate_original_installed_activation_launch_data(launch)?;
        Ok(result)
    }
}

pub(crate) fn quote_phases(
    launch: &PacketNative5SourceLaunch,
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
    coordinator: &PacketRestorationActivationCoordinatorConstructionInputs<'_>,
) -> Result<OriginalInstalledRestorationActivationConstructionData, ProviderError> {
    let arm = quote_base_phase(launch, inputs)?;
    let scratch = original_installed_restoration_activation_construction_counter_scratch_data();
    if coordinator.source_runtime.is_empty()
        || coordinator.maximum_encoded_bytes == 0
        || coordinator.maximum_encoded_bytes > 131_072
        || coordinator.retained_requested_bytes == 0
        || coordinator.maximum_simultaneous_transient_bytes == 0
        || coordinator.declared_counter_scratch_bytes == 0
    {
        return Err(credit());
    }
    let runtime_parse = selected_value_decode_storage_data(
        coordinator.source_runtime,
        inputs.maximum_requested_bytes,
    )?;
    let coordinator_work = sum(&[
        coordinator.maximum_simultaneous_transient_bytes,
        runtime_parse,
        coordinator.declared_counter_scratch_bytes,
    ])?;
    let coordinator_native = coordinator_native_storage(coordinator.maximum_encoded_bytes)?;
    let mut world = arm;
    // These are independently ADDED to native/SDK demand, alongside the real
    // Core/common owners already retained by the issuer. No byte of Core's own
    // funding is transferred to a native parse or a protocol upload.
    world.host_retained = add(
        world.host_retained,
        mul(coordinator.retained_requested_bytes, 2)?,
    )?;
    world.host_transient = add(world.host_transient, coordinator_work)?;
    world.native.retained_requested_bytes = as_u64(sum(&[
        usize::try_from(arm.native.retained_requested_bytes.get()).map_err(|_| credit())?,
        coordinator.retained_requested_bytes,
        coordinator_native.0,
    ])?)?;
    world.native.maximum_simultaneous_transient_bytes = as_u64(sum(&[
        usize::try_from(arm.native.maximum_simultaneous_transient_bytes.get())
            .map_err(|_| credit())?,
        coordinator_work,
        coordinator_native.1,
    ])?)?;
    let frame = usize::try_from(launch.limits.frame_bytes.get()).map_err(|_| credit())?;
    let chunk = usize::try_from(launch.limits.blob_chunk_bytes.get())
        .map_err(|_| credit())?
        .min(4096)
        .min(frame.saturating_sub(4096).saturating_mul(3) / 4);
    let uploads = [
        super::upload::storage::quote(coordinator.maximum_encoded_bytes, chunk, frame)?,
        super::upload::storage::quote(16_384, chunk, frame)?,
    ];
    let upload_requested = uploads.iter().try_fold(0usize, |total, row| {
        add(
            total,
            sum(&[
                row.retained,
                row.transient,
                row.scratch,
                usize::try_from(row.native.requested_bytes_data()?).map_err(|_| credit())?,
            ])?,
        )
    })?;
    let requested = sum(&[
        upload_requested,
        arm.host_retained,
        arm.host_transient,
        scratch,
        usize::try_from(arm.native.requested_bytes_data()?).map_err(|_| credit())?,
        world.host_retained,
        world.host_transient,
        world.host_scratch,
        usize::try_from(world.native.requested_bytes_data()?).map_err(|_| credit())?,
    ])?;
    if requested > inputs.maximum_requested_bytes {
        return Err(credit());
    }
    Ok(OriginalInstalledRestorationActivationConstructionData {
        phases: [arm, world],
        uploads,
        controller: std::ptr::null(),
        requested,
        counter_scratch: scratch,
    })
}

fn quote_base_phase(
    launch: &PacketNative5SourceLaunch,
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
) -> Result<PhaseStorage, ProviderError> {
    // The exact outer14 plan authenticates the embedded Control bytes first.
    // Its closed model parser counts actual spare vector capacities as well as
    // every initialized nested model field. No encoded-length heap shortcut is
    // used for this potentially large inventory construction phase.
    let model = complete_restore_invocation_owner_construction_storage_data(inputs)?;
    let model_work = add(model.control_bytes, model.model_vector_backing_bytes)?;
    let [wire, terminal, proof_wire] =
        super::projection::wire_projection_data(inputs.maximum_requested_bytes)?;
    let receipt_payload = proof_wire.maximum_encoded_bytes.min(65_536);
    // The raw native record adds the exact new original to a projection of the
    // unchanged captured model. The complete Control JSON contains that full
    // inventory as a strict subgraph; two complete model construction views
    // cover its typed copy and independent hash/roundtrip validation. The hard
    // native record ceiling still refuses overlong actual records before any
    // activation effect. That refusal does not erase already retained owners.
    let evidence = sum(&[
        mul(model_work, 2)?,
        proof_wire.requested_total()?,
        size_of::<crate::reference_packet::control::PacketNative5UnderlyingRecord>(),
        size_of::<crate::reference_packet::control::PacketNativeRecord>().max(size_of::<
            crate::reference_packet::connected::PacketConnectedNativeRecord,
        >()),
    ])?;
    let objects = [
        crate::connection::OriginalContinuationContentExtent {
            maximum_payload_bytes: receipt_payload,
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
            maximum_requested_bytes: inputs.maximum_requested_bytes,
        },
    )?;
    let scratch = original_installed_restoration_activation_construction_counter_scratch_data();
    let host_retained = sum(&[
        // Original assignment, immutable custody-cache original and terminal,
        // plus typed command/request/response and their independent Values.
        mul(wire.requested_total()?, 6)?,
        prefix.source_owner_requested_bytes,
        CnpController::original_installed_restoration_activation_owner_header_bytes_data(),
    ])?;
    let host_transient = sum(&[mul(wire.requested_total()?, 3)?, prefix.requested_bytes()?])?;
    let native_retained = sum(&[
        crate::reference_packet::service::ack_emitter::native_boot::original_native_restoration_activation_attempt_backing_data()?,
        model_work, mul(wire.requested_total()?, 4)?, mul(proof_wire.requested_total()?, 4)?,
        prefix.exchange.requested_bytes()?,
    ])?;
    let native_transient = sum(&[
        model_work,
        mul(wire.requested_total()?, 3)?,
        mul(proof_wire.requested_total()?, 3)?,
        prefix.requested_bytes()?,
    ])?;
    let native = PacketRestorationActivationAllocationRow {
        retained_requested_bytes: as_u64(native_retained)?,
        maximum_simultaneous_transient_bytes: as_u64(native_transient)?,
        declared_counter_scratch_bytes: as_u64(scratch)?,
    };
    native.requested_bytes_data()?;
    Ok(PhaseStorage {
        host_retained,
        host_transient,
        host_scratch: scratch,
        native,
        // These are ADDITIONAL Source-owned receipt and underlying record
        // objects. A repeated read-only validator may construct a second full
        // typed proof while the first remains retained through its final fence.
        source_evidence_retained: mul(evidence, 2)?,
        source_evidence_transient: sum(&[
            mul(evidence, 2)?,
            mul(proof_wire.requested_total()?, 2)?,
        ])?,
        source_evidence_scratch: scratch,
    })
}

/// Recounts the real native phase before constructing activation model/proof owners.
///
/// The caller lends the same retained six-input banks as Commit and independently
/// authenticates the Source MAC and each returned axis. Arm has no coordinator;
/// WorldActivate lends its actual content bytes after bounded manifest lookup.
/// No parser, native owner, phase claim or allocation permission is constructed.
pub(crate) fn original_native_restoration_activation_required_storage_data(
    launch: &PacketNative5SourceLaunch,
    inputs: &PacketCompleteRestoreSelectedOwnerInputs<'_>,
    phase: PacketRestorationActivationPhase,
    coordinator: Option<&[u8]>,
) -> Result<PacketRestorationActivationAllocationRow, ProviderError> {
    let mut row = quote_base_phase(launch, inputs)?.native;
    match (phase, coordinator) {
        (PacketRestorationActivationPhase::Arm, None) => {}
        (PacketRestorationActivationPhase::WorldActivate, Some(bytes)) if !bytes.is_empty() => {
            let (retained, transient) = coordinator_native_storage(bytes.len())?;
            row.retained_requested_bytes = as_u64(add(
                usize::try_from(row.retained_requested_bytes.get()).map_err(|_| credit())?,
                retained,
            )?)?;
            row.maximum_simultaneous_transient_bytes = as_u64(add(
                usize::try_from(row.maximum_simultaneous_transient_bytes.get())
                    .map_err(|_| credit())?,
                transient,
            )?)?;
        }
        _ => return Err(invalid()),
    }
    if usize::try_from(row.requested_bytes_data()?).map_err(|_| credit())?
        > inputs.maximum_requested_bytes
    {
        return Err(credit());
    }
    Ok(row)
}

fn coordinator_native_storage(encoded: usize) -> Result<(usize, usize), ProviderError> {
    use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
    let extent = original_json_value_storage_extent_data(encoded)?;
    // The original content bank, parsed Value, an independent typed/Value
    // roundtrip and canonical hash/output work are simultaneous owners. These
    // are independent additions, never the Core coordinator's backing reused.
    // Only WorldBinding/CaptureManifest and their contract children are decoded
    // as DTOs. Bound their actual element layouts independently of Value nodes.
    use crucible_node_format::{
        CaptureManifest, CapturedOwner, ConnectionDescriptor, ContentRef, HashRef, NodeBindingRef,
        PreparedOwner, SchemaRef, WorldBinding,
    };
    let typed_slot = size_of::<WorldBinding>()
        .max(size_of::<CaptureManifest>())
        .max(size_of::<CapturedOwner>())
        .max(size_of::<PreparedOwner>())
        .max(size_of::<NodeBindingRef>())
        .max(size_of::<ConnectionDescriptor>())
        .max(size_of::<SchemaRef>())
        .max(size_of::<HashRef>())
        .max(size_of::<ContentRef>());
    let typed = mul(mul(extent.maximum_value_nodes, 4)?, typed_slot)?;
    let retained = sum(&[encoded, mul(extent.value_dom_requested_bytes, 2)?, typed])?;
    let transient = sum(&[
        encoded,
        mul(extent.canonical_pass_requested_bytes()?, 2)?,
        typed,
        original_installed_restoration_activation_construction_counter_scratch_data(),
    ])?;
    Ok((retained, transient))
}

fn as_u64(value: usize) -> Result<U64, ProviderError> {
    u64::try_from(value).map(U64::new).map_err(|_| credit())
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0, |total, term| add(total, *term))
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("whole installed restoration activation construction")
}
