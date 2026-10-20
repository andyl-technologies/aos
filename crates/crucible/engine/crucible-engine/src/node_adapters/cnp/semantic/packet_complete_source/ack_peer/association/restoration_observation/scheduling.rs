//! Prices and constructs actual restored-model scheduling observations.
//!
//! The raw population producer validates the same captured owner and Control
//! before counting initialized outputs. These counts are DATA. The actual
//! Source helper runs only beneath a genuine Observe read after the complete
//! native record and restored-world correspondence have been authenticated.

use super::*;
use crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics;
use crate::node_scheduling::{NativeProducerBound, NativePublication};
use crucible_node_transport::reference_packet::service::complete_restore::transfer::{
    PacketCompleteRestoreModelOutputPopulationData, PacketCompleteRestoreSelectedOwnerInputs,
    complete_restore_selected_model_output_population_counter_scratch_data,
    complete_restore_selected_model_output_population_data,
};
use crucible_node_transport::reference_packet::{
    connected::PacketConnectedDefinition, coordinator::PacketNative5CoordinatorInstallation,
};

pub(super) fn quote(
    source: &PacketCompleteSemanticSource,
    inputs: &OriginalInstalledRestorationObservationSigningConstructionInputs<'_>,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let transfer = inputs.activation.transfer;
    let content = transfer.archive.content();
    let owner = transfer.ticket.owner()?;
    let raw = PacketCompleteRestoreSelectedOwnerInputs {
        owner_state: content
            .get(&owner.state)
            .ok_or(RuntimeError::UnsupportedFacet)?,
        journal: content
            .get(transfer.journal_reference)
            .ok_or(RuntimeError::UnsupportedFacet)?,
        control: content
            .get(&transfer.journal.native_control)
            .ok_or(RuntimeError::UnsupportedFacet)?,
        anchor: content
            .get(&transfer.journal.native_anchor)
            .ok_or(RuntimeError::UnsupportedFacet)?,
        maximum_input_bytes: transfer.maximum_record_bytes,
        maximum_before_bytes: usize::try_from(
            transfer
                .launch
                .capture_profile
                .native_before_bytes(&transfer.launch.storage)
                .get(),
        )
        .map_err(|_| RuntimeError::ResourceLimit)?,
        maximum_requested_bytes: maximum,
    };
    let model = complete_restore_selected_model_output_population_data(&raw)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    let installation = source.installation();
    let endpoint = match &source.original {
        CompletePacketOriginal::Producer(_) => {
            let port = installation
                .descriptor
                .ports
                .first()
                .ok_or(RuntimeError::UnsupportedFacet)?;
            let lane = port.lanes.first().ok_or(RuntimeError::UnsupportedFacet)?;
            sum(
                [
                    installation.descriptor.id.as_str().len(),
                    port.id.as_str().len(),
                    lane.id.as_str().len(),
                ],
                maximum,
            )?
        }
        CompletePacketOriginal::Reactive(original) => {
            let (definition, _, _) =
                original.complete_retained_declaration_parts_with_error::<RuntimeError>()?;
            match definition.output.as_ref() {
                Some(endpoint) => sum(
                    [
                        endpoint.node_id.as_str().len(),
                        endpoint.port_id.as_str().len(),
                        endpoint.lane_id.as_str().len(),
                    ],
                    maximum,
                )?,
                None if model.initialized_outputs_data() == 0 => 0,
                None => return Err(RuntimeError::UnsupportedFacet),
            }
        }
    };
    let reference = projection::future_reference_backing_data(maximum)?;
    let publication_reference = sum(
        [
            "blake3-256".len(),
            "cnp.blob.v1".len(),
            64,
            "application/octet-stream".len(),
        ],
        maximum,
    )?;
    let per_slot = sum(
        [
            size_of::<NativePublication>(),
            endpoint,
            publication_reference,
            size_of::<crucible_node_format::Position>(),
        ],
        maximum,
    )?;
    let publications = model
        .publication_slots_data()
        .checked_mul(per_slot)
        .ok_or(RuntimeError::ResourceLimit)?;
    // No input/external inventory is manufactured by these actual original
    // helpers. Owners and bounds use real one-element vec! allocations; output
    // collection growth is independently supplied by the defining model scan.
    sum(
        [
            size_of::<NativeSchedulingObservation>(),
            installation.descriptor.id.as_str().len(),
            size_of::<crate::node_contract::OwnerIdentity>(),
            installation.owner.owner.id.as_str().len(),
            installation.binding.authority.incarnation_id.as_str().len(),
            size_of::<NativeProducerBound>(),
            installation.descriptor.id.as_str().len(),
            reference,
            reference,
            publications,
            model.owned_string_payload_backing_bytes_data(),
        ],
        maximum,
    )
}

pub(super) fn construct(
    source: &PacketCompleteSemanticSource,
    world: &crate::node_contract::WorldActivation,
    reference: &ContentRef,
    underlying: &PacketNative5UnderlyingRecord,
) -> Result<NativeSchedulingObservation, RuntimeError> {
    // The existing original helpers retain their normal checks. This new
    // caller discards their diagnostic into RuntimeError, so use the existing
    // finite diagnostic owner instead of invoking an arbitrary Display.
    let _diagnostics = OriginalInitialLifecycleDiagnostics::begin();
    match (&source.original, underlying) {
        (
            CompletePacketOriginal::Producer(original),
            PacketNative5UnderlyingRecord::Producer(record),
        ) => original
            .observation(world, reference, record)
            .map_err(|_| RuntimeError::InvalidReceipt),
        (
            CompletePacketOriginal::Reactive(original),
            PacketNative5UnderlyingRecord::Reactive(record),
        ) => original
            .observation(world, reference, record)
            .map_err(|_| RuntimeError::InvalidReceipt),
        _ => Err(RuntimeError::ForeignAuthority),
    }
}

pub(super) fn authenticate_bound(
    observation: &NativeSchedulingObservation,
    maximum: usize,
) -> Result<(), RuntimeError> {
    if sum(
        [
            size_of::<NativeSchedulingObservation>(),
            NodeRuntime::capture_scheduling_observation_storage_data(observation, maximum)?,
        ],
        usize::MAX,
    )? > maximum
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    type DeclarationParts = (
        &'static PacketConnectedDefinition,
        &'static PacketNative5CoordinatorInstallation,
        &'static crate::node_contract::SavedRuntimeActivation,
    );
    complete_restore_selected_model_output_population_counter_scratch_data()
        + OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
        + size_of::<DeclarationParts>()
        + size_of::<Result<DeclarationParts, RuntimeError>>()
        + size_of::<PacketCompleteRestoreModelOutputPopulationData>()
        + size_of::<
            Result<
                PacketCompleteRestoreModelOutputPopulationData,
                crucible_node_transport::ProviderError,
            >,
        >()
        + size_of::<&crate::node_adapters::cnp::semantic::CnpSemanticInstallation>()
        + size_of::<&crucible_node_format::PortDescriptor>()
        + size_of::<&crucible_node_format::LaneDescriptor>()
        + size_of::<&crucible_node_format::Endpoint>()
        + size_of::<Option<&crucible_node_format::PortDescriptor>>()
        + size_of::<Option<&crucible_node_format::LaneDescriptor>>()
        + size_of::<Option<&crucible_node_format::Endpoint>>()
        + size_of::<(&CompletePacketOriginal, &PacketNative5UnderlyingRecord)>()
        + crate::node_contract::opaque_owner_counter_scratch_data()
        + size_of::<PacketCompleteRestoreSelectedOwnerInputs<'static>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<NativeSchedulingObservation>()
        + size_of::<Result<NativeSchedulingObservation, RuntimeError>>()
        + size_of::<Result<NativeSchedulingObservation, crate::node_contract::OperationFailure>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<[usize; 11]>()
        + size_of::<std::array::IntoIter<usize, 11>>()
        + size_of::<[usize; 4]>()
        + size_of::<std::array::IntoIter<usize, 4>>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<[usize; 2]>()
        + size_of::<std::array::IntoIter<usize, 2>>()
        + size_of::<&PacketNative5UnderlyingRecord>()
        + size_of::<&crate::node_contract::WorldActivation>()
        + size_of::<&ContentRef>()
        + size_of::<Result<(), RuntimeError>>()
}
