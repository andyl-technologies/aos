//! Authenticates cumulative native state against actual prior public close and ACK custody.

use super::*;
use crate::reference_service::PublicationConsumption;

pub(super) fn validate(
    view: &OriginalLineageWindow<'_>,
    previous: Option<&NativeLineageReceipt>,
) -> Result<(), ProviderError> {
    match (&view.measurement.previous_publication, previous) {
        (None, None) if !view.relation.preceding_publication_acknowledged => Ok(()),
        (Some(prior), Some(native)) if view.relation.preceding_publication_acknowledged => {
            acknowledged(view, prior, native)
        }
        _ => Err(invalid()),
    }
}

fn acknowledged(
    view: &OriginalLineageWindow<'_>,
    prior: &records::Predecessor,
    native: &NativeLineageReceipt,
) -> Result<(), ProviderError> {
    let source = view.controller;
    let measurement: records::Measurement = record(source, &prior.measurement, "application/json")?;
    let relation: records::Relation = record(
        source,
        &measurement.consumption_relation,
        "application/vnd.crucible.reference-consumption-relation+json",
    )?;
    let stop: StopReceipt = validated(source, &prior.stop_receipt)?;
    let observation: ObservationBatch = validated(source, &prior.observation_batch)?;
    let committed: ObservationBatch = validated(source, &prior.committed_observation)?;
    let consumption: PublicationConsumption = validated(source, &prior.publication_consumption)?;

    if measurement.schema != "crucible.reference.lineage-measurement.v1"
        || measurement.native.grant != native.grant
        || measurement.native.output != native.output
        || !measurement.native.application_parked
        || relation.schema != "crucible.reference.consumption-relation.v1"
        || relation.owner != view.origin.owner
        || relation.incarnation != view.origin.incarnation
        || relation.owner_generation != view.origin.owner_generation
        || relation.original_kernel_pid != view.origin.child_pid
        || relation.original_kernel_start_ticks != view.origin.original_kernel_start_ticks
        || relation.native_receipt != native.identity()?
        || relation.native_window != native.grant.window_id
        || relation.measured_host_ns != measurement.native.measured_host_ns
        || stop.session_id != source.bootstrap.authority.session_id
        || stop.incarnation_id != view.origin.incarnation
        || stop.execution_owner_id != view.origin.owner
        || stop.owner_generation != view.origin.owner_generation
        || stop.world_binding_hash != view.stop.world_binding_hash
        || stop.activation_id != view.stop.activation_id
        || stop.world_generation != view.stop.world_generation
        || stop.owner_binding_hash != view.stop.owner_binding_hash
        || stop.grant_id.as_ref() != Some(&native.grant.window_id)
        || stop.production_prefix != native.grant.publication
        || stop.physical_stop != PhysicalStop::ObservationClosed
        || stop.prefix_kind != ClosureKind::Through
        || stop.observation_batch != prior.observation_batch
        || stop.physical_measurement_ref != prior.measurement
        || stop.input_custody != measurement.accepted_input_custody
    {
        return Err(ProviderError::Correlation(
            "lineage original preceding window differs",
        ));
    }

    if observation.visibility != Visibility::Staged
        || observation.operation_id != stop.operation_id
        || observation.execution_owner_id != stop.execution_owner_id
        || observation.owner_generation != stop.owner_generation
        || observation.owner_binding_hash != stop.owner_binding_hash
        || observation.grant_id != stop.grant_id
        || observation.world_binding_hash != stop.world_binding_hash
        || observation.activation_id != stop.activation_id
        || observation.world_generation != stop.world_generation
        || observation.measurement_ref != prior.measurement
        || consumption.session_id != stop.session_id
        || consumption.incarnation_id != stop.incarnation_id
        || consumption.operation_id != stop.operation_id
        || consumption.grant_id != native.grant.window_id
        || consumption.world_binding_hash != stop.world_binding_hash
        || consumption.observation_batch_hash != observation.identity()?
        || consumption.stop_receipt != prior.stop_receipt
        || consumption.publication != native.grant.publication
    {
        return Err(ProviderError::Correlation(
            "lineage original preceding publication differs",
        ));
    }
    let mut expected = observation.clone();
    expected.visibility = Visibility::Committed;
    if committed != expected {
        return Err(ProviderError::Correlation(
            "lineage original preceding commit differs",
        ));
    }

    // Byte-valid receipt records alone are insufficient. Both public operations
    // must already be completed originals in this controller's own namespace.
    let close = source
        .custody
        .originals_by_origin(RequestOrigin::Controller)
        .find(|original| {
            if original.request.method != Method::QuantumClose {
                return false;
            }
            matches!(decode_request(Method::QuantumClose, &original.request.body),
            Ok(RequestBody::QuantumClose(request)) if request.grant_id == native.grant.window_id)
        })
        .ok_or_else(invalid)?;
    let (_, response) = completed(
        source,
        close.request.request_id.0.as_ref().ok_or_else(invalid)?,
        Method::QuantumClose,
    )?;
    let Some(MethodResult::QuantumClose(result)) = response.result else {
        return Err(invalid());
    };
    if result.stop_receipt != prior.stop_receipt
        || result.committed_batch != prior.committed_observation
        || result.grant_id != native.grant.window_id
        || result.quantum_index != native.grant.quantum
    {
        return Err(invalid());
    }

    let retirement = source.custody.originals_by_origin(RequestOrigin::Controller).find(|original| {
        if original.request.method != Method::Retire {
            return false;
        }
        matches!(decode_request(Method::Retire, &original.request.body),
            Ok(RequestBody::Retire(request)) if request.custody_receipt.0.as_ref() == Some(&prior.publication_consumption))
    }).ok_or_else(invalid)?;
    let (_, response) = completed(
        source,
        retirement
            .request
            .request_id
            .0
            .as_ref()
            .ok_or_else(invalid)?,
        Method::Retire,
    )?;
    let Some(MethodResult::Retire(result)) = response.result else {
        return Err(invalid());
    };
    let RequestBody::Retire(request) = decode_request(Method::Retire, &retirement.request.body)?
    else {
        return Err(invalid());
    };
    if request.disposition != RetirementDisposition::Consumed
        || request.operation_ids != [stop.operation_id]
        || request.request_ids.len() != 1
        || result.retired_operation_ids != request.operation_ids
        || result.retired_request_ids != request.request_ids
    {
        return Err(invalid());
    }
    let (_, begin) = completed(source, &request.request_ids[0], Method::Begin)?;
    let Some(MethodResult::QuantumBegin(begin)) = begin.result else {
        return Err(invalid());
    };
    if begin.stop_receipt != prior.stop_receipt
        || begin.observation_batch != prior.observation_batch
        || begin.physical_measurement_ref != prior.measurement
    {
        return Err(invalid());
    }
    Ok(())
}
