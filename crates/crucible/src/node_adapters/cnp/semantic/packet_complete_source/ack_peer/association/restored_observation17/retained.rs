//! Counts every retained signed Observe17 partial beneath its actual Source owner.

use super::*;
use crucible_node_provider::reference_packet::service::complete_restore::activation::restoration_activation_retained_native_evidence_data;

pub(super) fn retained_attempt_bytes_with_error<E: StorageError>(
    attempt: &Observation17Attempt,
    mut bytes: usize,
    maximum: usize,
) -> Result<usize, E> {
    use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
        sum_with_error, value_storage_with_error,
    };
    if let Some(id) = &attempt.id {
        bytes = sum_with_error::<E, _>([bytes, id.allocated_capacity()], maximum)?;
    }
    if let Some(body) = &attempt.body {
        let facts = crucible_node_provider::reference_packet::service::complete_restore::restoration_observe::RetainedRestorationObservationData::Body(body)
            .original_retained_metadata_facts().map_err(E::unknown)?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                    &facts, maximum,
                )?,
            ],
            maximum,
        )?;
    }
    for owned in [
        attempt
            .request
            .as_ref()
            .map(PacketRestoredInputReactive17RetainedData::Request),
        attempt
            .context
            .as_ref()
            .map(PacketRestoredInputReactive17RetainedData::Context),
        attempt
            .artifact
            .as_ref()
            .map(PacketRestoredInputReactive17RetainedData::Artifact),
    ]
    .into_iter()
    .flatten()
    {
        let facts = owned
            .original_retained_metadata_data()
            .map_err(E::unknown)?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                    &facts, maximum,
                )?,
            ],
            maximum,
        )?;
    }
    if let Some(sdk) = &attempt.sdk {
        let facts = sdk.retained_metadata_data().map_err(E::unknown)?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                    &facts, maximum,
                )?,
            ],
            maximum,
        )?;
    }
    for reference in [
        attempt.previous_measurement.as_ref(),
        attempt.previous_model.as_ref(),
        attempt.measurement.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                NodeRuntime::capture_reference_storage(reference)
                    .map_err(|_| E::limit("Observe17 full reference backing"))?,
            ],
            maximum,
        )?;
    }
    if let Some(record) = &attempt.record {
        let facts = restoration_activation_retained_native_evidence_data(
            record,
            attempt.underlying.as_ref(),
        )
        .map_err(E::unknown)?;
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<E>(
                    &facts, maximum,
                )?,
            ],
            maximum,
        )?;
    } else if attempt.underlying.is_some() {
        return Err(E::unknown("Observe17 model has no owning restored record"));
    }
    for value in [attempt.model_value.as_ref(), attempt.record_value.as_ref()]
        .into_iter()
        .flatten()
    {
        bytes = sum_with_error::<E, _>(
            [bytes, value_storage_with_error::<E>(value, 0, maximum)?],
            maximum,
        )?;
    }
    for bank in [attempt.model_bytes.as_ref(), attempt.record_bytes.as_ref()]
        .into_iter()
        .flatten()
    {
        bytes = sum_with_error::<E, _>([bytes, bank.capacity()], maximum)?;
    }
    if let Some(scheduling) = &attempt.scheduling {
        bytes = sum_with_error::<E, _>(
            [
                bytes,
                NodeRuntime::capture_scheduling_observation_storage_data(scheduling, maximum)
                    .map_err(|_| E::limit("Observe17 scheduling backing"))?,
            ],
            maximum,
        )?;
    }
    Ok(bytes)
}
