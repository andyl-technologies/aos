//! Walks actual selected partial phase owners without callbacks or serialization.
//!
//! Every independent command, terminal, manifest, normalized Value and byte bank
//! is counted by its actual backing. The opaque association accounts its Weak
//! allocation view; the original holder separately owns the complete Window.

use super::super::super::PacketCompleteSemanticSource;
use super::*;
use crate::node_contract::NodeRuntime;
use crucible_node_transport::reference_packet::service::complete_restore::activation::RetainedRestorationActivationData as Data;

fn metadata(value: Data<'_>, maximum: usize) -> Result<usize, RuntimeError> {
    let facts = value
        .original_retained_metadata_facts()
        .map_err(|_| RuntimeError::UnsupportedFacet)?;
    PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(&facts, maximum)
}

pub(super) fn phase_owners(
    state: &InstalledRestorationCustody,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    let InstalledRestorationCustody {
        association: _,
        install_started: _,
        installed: _,
        activation: _,
        operations: _,
        inputs: _,
        commands,
        completed,
        world_manifest,
        world_value,
        world_bytes,
        observation_attempted: _,
        observation_completed,
        observation,
        observation_return,
        current_observations,
        producer_executions,
    } = state;
    let slots = current_observations
        .capacity()
        .checked_mul(current_observation::slot_bytes_data())
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut bytes = storage::sum(
        &[
            slots,
            current_observation::retained_data(current_observations, maximum)?,
            producer_execution::retained_data(producer_executions, maximum)?,
        ],
        maximum,
    )?;
    if let Some(response) = observation_completed {
        let facts = crucible_node_transport::reference_packet::service::complete_restore::restoration_observe::RetainedRestorationObservationData::Response(response)
            .original_retained_metadata_facts().map_err(|_| RuntimeError::UnsupportedFacet)?;
        bytes = storage::sum(
            &[
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?,
            ],
            maximum,
        )?;
    }
    for value in [observation, observation_return].into_iter().flatten() {
        bytes = storage::sum(
            &[
                bytes,
                NodeRuntime::capture_scheduling_observation_storage_data(value, maximum)?,
            ],
            maximum,
        )?;
    }
    for command in commands.iter().flatten() {
        bytes = storage::sum(
            &[bytes, metadata(Data::Command(command), maximum)?],
            maximum,
        )?;
    }
    for response in completed.iter().flatten() {
        bytes = storage::sum(
            &[bytes, metadata(Data::Response(response), maximum)?],
            maximum,
        )?;
    }
    if let Some(manifest) = world_manifest {
        bytes = storage::sum(
            &[bytes, metadata(Data::Manifest(manifest), maximum)?],
            maximum,
        )?;
    }
    if let Some(value) = world_value {
        bytes = storage::sum(&[bytes,
            super::super::super::packet_complete_source::original_retained_value_storage_with_error::<RuntimeError>(value, 0, maximum)?], maximum)?;
    }
    if let Some(value) = world_bytes {
        bytes = storage::sum(&[bytes, value.capacity()], maximum)?;
    }
    Ok(bytes)
}

impl super::super::super::state::SemanticRuntimeCustody {
    pub(in crate::node_adapters::cnp::semantic) fn installed_storage_origin_precredit_data(
        &self,
    ) -> Result<(), RuntimeError> {
        if self.installed_restoration.is_none() {
            return self.dormant_storage_data();
        }
        // Ordinary active histories are not omitted as zero. Their selected
        // raw/capture continuation is a separate required production extension.
        if !self.operations.is_empty() || !self.inputs.is_empty() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn installed_retained_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.installed_storage_origin_precredit_data()?;
        let selected = self
            .installed_restoration
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let mut bytes = selected.retained_requested_storage_data(maximum)?;
        if let Some(value) = &self.arm_attempt {
            bytes = storage::sum(
                &[
                    bytes,
                    NodeRuntime::capture_activation_storage_data(value, maximum)?,
                ],
                maximum,
            )?;
        }
        if let Some(value) = &self.ready {
            bytes = storage::sum(
                &[
                    bytes,
                    NodeRuntime::capture_ready_storage_data(value, maximum)?,
                ],
                maximum,
            )?;
        }
        if let Some(value) = &self.prepared_owner {
            bytes = storage::sum(
                &[
                    bytes,
                    NodeRuntime::capture_prepared_owner_storage_data(value, maximum)?,
                ],
                maximum,
            )?;
        }
        if let Some(value) = &self.activate_response {
            let facts = crucible_node_transport::retained_metadata::RetainedCommonProtocolData::WorldActivate(value)
                .observe_retained_metadata().map_err(|_| RuntimeError::UnsupportedFacet)?;
            bytes = storage::sum(&[bytes, PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(&facts, maximum)?], maximum)?;
        }
        for value in [&self.activation_attempt, &self.active]
            .into_iter()
            .flatten()
        {
            let facts = value.retained_requested_storage_data(maximum)?;
            bytes = storage::sum(&[bytes, facts.independent_bytes()], maximum)?;
            for shared in facts.shared_allocations() {
                bytes = storage::sum(&[bytes, shared.requested_bytes()], maximum)?;
            }
        }
        if let Some((world, observation)) = &self.observation {
            let facts = world.retained_requested_storage_data(maximum)?;
            bytes = storage::sum(
                &[
                    bytes,
                    facts.independent_bytes(),
                    NodeRuntime::capture_scheduling_observation_storage_data(observation, maximum)?,
                ],
                maximum,
            )?;
            for shared in facts.shared_allocations() {
                bytes = storage::sum(&[bytes, shared.requested_bytes()], maximum)?;
            }
        }
        if let Some(value) = &self.reclaimed {
            bytes = storage::sum(
                &[
                    bytes,
                    NodeRuntime::capture_reclamation_storage_data(value, maximum)?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use crate::node_scheduling::NativeSchedulingObservation;
    use std::mem::size_of;
    size_of::<[&Option<NativeSchedulingObservation>; 2]>()
        + size_of::<std::array::IntoIter<&Option<NativeSchedulingObservation>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&Option<NativeSchedulingObservation>, 2>>>()
        + size_of::<std::option::Iter<'static, NativeSchedulingObservation>>()
        + size_of::<Option<&NativeSchedulingObservation>>()
        + size_of::<Result<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts, RuntimeError>>()
        + size_of::<&NativeSchedulingObservation>()
        + size_of::<&crucible_node_transport::bodies::ResponseBody>()
        + size_of::<crucible_node_transport::reference_packet::service::complete_restore::restoration_observe::RetainedRestorationObservationData<'static>>()
        + size_of::<[&Option<WorldActivation>; 2]>()
        + size_of::<std::array::IntoIter<&'static Option<WorldActivation>, 2>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<WorldActivation>, 2>>>()
        + size_of::<std::option::Iter<'static, WorldActivation>>()
        + size_of::<Data<'static>>() + size_of::<Result<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>()
        + size_of::<crucible_node_transport::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Result<usize, RuntimeError>>() + size_of::<Option<&serde_json::Value>>()
        + size_of::<std::slice::Iter<'static, Option<crucible_node_transport::bodies::ResponseBody>>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<crucible_node_transport::bodies::ResponseBody>>>>()
        + size_of::<std::slice::Iter<'static, Option<crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand>>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<crucible_node_transport::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand>>>>()
}
