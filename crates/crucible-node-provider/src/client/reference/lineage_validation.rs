//! Compares selected records against actual original owning-controller custody.

use super::*;

#[path = "lineage_predecessor.rs"]
mod predecessor;

pub(super) fn control(
    controller: &ReferenceController,
    receipt: &ControlReceipt,
    request: &Id,
    kind: ControlReceiptKind,
) -> Result<(), ProviderError> {
    if receipt.kind != kind
        || receipt.issuer != ReceiptIssuer::Provider
        || receipt.request_id != *request
        || receipt.session_id != controller.bootstrap.authority.session_id
        || receipt.incarnation_id != controller.bootstrap.authority.incarnation_id
        || receipt.owner_ids != [controller.bootstrap.owner_id.clone()]
        || receipt.world_generation
            != match kind {
                ControlReceiptKind::ClosedGate => U64::new(0),
                ControlReceiptKind::InputCustody => controller.bootstrap.world_generation,
                _ => return Err(invalid()),
            }
    {
        return Err(ProviderError::Correlation(
            "lineage original control scope differs",
        ));
    }
    Ok(())
}

pub(super) fn window(
    view: &OriginalLineageWindow<'_>,
    grant: &QuantumBeginArguments,
    result: &QuantumBeginResult,
    accepted: &InputResult,
    begin: &BeginRequest,
) -> Result<(), ProviderError> {
    let source = view.controller;
    let origin = &view.origin;
    let relation = &view.relation;
    let measurement = &view.measurement;
    if origin.schema != "crucible.reference.lineage-origin.v1"
        || origin.dialect != crate::reference_lineage::DIALECT
        || origin.application_status != "parked"
        || origin.physical_pause != "unknown"
        || origin.child_pid.get() == 0
        || origin.owner != source.bootstrap.owner_id
        || origin.incarnation != source.bootstrap.authority.incarnation_id
        || origin.owner_generation != source.bootstrap.authority.owner_generation
        || !source
            .profile
            .implementation
            .artifacts
            .iter()
            .any(|artifact| {
                artifact.id.as_str() == "device" && artifact.content == origin.native_executable
            })
    {
        return Err(ProviderError::Correlation(
            "lineage original origin differs",
        ));
    }

    if relation.schema != "crucible.reference.consumption-relation.v1"
        || measurement.schema != "crucible.reference.lineage-measurement.v1"
        || relation.owner != origin.owner
        || relation.incarnation != origin.incarnation
        || relation.owner_generation != origin.owner_generation
        || relation.original_kernel_pid != origin.child_pid
        || relation.original_kernel_start_ticks != origin.original_kernel_start_ticks
        || relation.initialize_request != origin.initialize_request
        || relation.initialize_response_wire != origin.initialize_response_wire
        || relation.native_window != grant.grant_id
        || relation.input_batch != grant.input_batch
        || relation.native_receipt != view.native.identity()?
        || relation.native_stage != view.stage.identity()?
        || view.stage.original_batch != relation.input_batch
        || relation.previous_closed != view.native.previous_closed
        || relation.complete_consumed_prefix.get() != view.input.events.len() as u64
        || relation.entries.len() != view.input.events.len()
        || relation.measured_host_ns != measurement.native.measured_host_ns
    {
        return Err(ProviderError::Correlation(
            "lineage original relation differs",
        ));
    }

    if measurement.native.grant != view.native.grant
        || measurement.native.output != view.native.output
        || !measurement.native.application_parked
        || measurement.accepted_input_custody != accepted.custody_receipt
    {
        return Err(ProviderError::Correlation(
            "lineage original measurement differs",
        ));
    }

    if view.input.execution_owner_id != source.bootstrap.owner_id
        || view.input.input_epoch != grant.input_epoch
        || view.input.batch_sequence != grant.input_watermark
    {
        return Err(ProviderError::Correlation("lineage original input differs"));
    }

    if begin.binding_hash != source.binding()?.1.identity()?
        || begin.owner_generation != grant.owner_generation
        || begin.activation_id.0.as_ref() != Some(&grant.activation_id)
        || begin.world_generation != grant.world_generation
        || grant.owner_generation != origin.owner_generation
        || view.stage.grant.owner_id != origin.owner
        || view.stage.grant.incarnation_id != origin.incarnation
        || view.stage.grant.generation != origin.owner_generation
        || view.stage.grant.input_batch_id != view.input.batch_id
        || view.stage.grant.host_budget_ns != grant.wall_budget_ns
        || view.stage.grant.window_id != grant.grant_id
        || view.stage.grant.quantum != grant.quantum_index
        || view.stage.grant.start != Position::new(grant.from_ps, 0.into(), Phase::BoundaryControl)
        || view.stage.grant.publication
            != Position::new(grant.until_ps, 0.into(), Phase::Publication)
        || result.grant_id != grant.grant_id
        || result.quantum_index != grant.quantum_index
    {
        return Err(ProviderError::Correlation("lineage original grant differs"));
    }

    if view.stop.operation_id
        != *view.originals[2]
            .request
            .operation_id
            .0
            .as_ref()
            .ok_or_else(invalid)?
        || view.stop.execution_owner_id != origin.owner
        || view.stop.session_id != source.bootstrap.authority.session_id
        || view.stop.incarnation_id != origin.incarnation
        || view.stop.owner_generation != origin.owner_generation
        || view.stop.world_binding_hash != source.bootstrap.world_binding_hash
        || view.stop.activation_id != grant.activation_id
        || view.stop.world_generation != grant.world_generation
        || view.stop.grant_id.as_ref() != Some(&grant.grant_id)
        || view.stop.owner_binding_hash != begin.binding_hash
        || view.stop.reached
            != Some(Position::new(
                grant.until_ps,
                0.into(),
                Phase::BoundaryControl,
            ))
        || view.stop.production_prefix != view.stage.grant.publication
        || view.stop.prefix_kind != ClosureKind::Through
        || view.stop.physical_stop != PhysicalStop::ObservationClosed
        || view.stop.input_custody != accepted.custody_receipt
        || view.stop.observation_batch != result.observation_batch
        || view.stop.physical_measurement_ref != result.physical_measurement_ref
        || view.stop.pending_inventory != result.pending_inventory
    {
        return Err(ProviderError::Correlation("lineage original stop differs"));
    }

    if view.observation.operation_id != view.stop.operation_id
        || view.observation.grant_id != view.stop.grant_id
        || view.observation.owner_binding_hash != begin.binding_hash
        || view.observation.activation_id != grant.activation_id
        || view.observation.world_generation != grant.world_generation
        || view.observation.visibility != Visibility::Staged
        || view.observation.owner_generation != view.stop.owner_generation
        || view.observation.execution_owner_id != origin.owner
        || view.observation.measurement_ref != result.physical_measurement_ref
        || view.observation.world_binding_hash != view.stop.world_binding_hash
        || view.observation.events.len() != 1
    {
        return Err(ProviderError::Correlation(
            "lineage original observation differs",
        ));
    }
    view.stage.validate()?;
    let previous = relation
        .previous_closed
        .as_ref()
        .map(|reference| {
            record::<NativeLineageReceipt>(
                source,
                reference,
                "application/vnd.crucible.reference-lineage-native-receipt+json",
            )
        })
        .transpose()?;
    view.native
        .validate_against(&view.stage, previous.as_ref())?;
    let RequestBody::Input(request) =
        decode_request(Method::Input, &view.originals[1].request.body)?
    else {
        return Err(ProviderError::Correlation(
            "lineage original accepted input differs",
        ));
    };
    if request.events != view.input.events
        || request.batch_id != view.input.batch_id
        || request.batch_sequence != view.input.batch_sequence
        || request.batch_hash != view.input.identity()?
        || request.input_epoch != view.input.input_epoch
    {
        return Err(ProviderError::Correlation(
            "lineage original input custody differs",
        ));
    }
    let custody: ControlReceipt = validated(source, &accepted.custody_receipt)?;
    control(
        source,
        &custody,
        view.originals[1]
            .request
            .request_id
            .0
            .as_ref()
            .ok_or_else(invalid)?,
        ControlReceiptKind::InputCustody,
    )?;
    let input_record: InputCustodyRecord = validated(source, &custody.record_ref)?;
    if input_record.batch_hashes != [view.input.identity()?]
        || input_record.input_watermark != grant.input_watermark
        || input_record.execution_owner_id != origin.owner
        || input_record.owner_generation != origin.owner_generation
        || input_record.input_epoch != grant.input_epoch
    {
        return Err(ProviderError::Correlation(
            "lineage original consumed entry differs",
        ));
    }
    for ((entry, event), consumed) in relation
        .entries
        .iter()
        .zip(&view.input.events)
        .zip(&view.native.consumed)
    {
        let bytes =
            canonical::canonical_json(&serde_json::to_value(event).map_err(ContractError::from)?)?;
        if entry.original_index != consumed.event_index
            || entry.original_event != canonical::content_ref(&bytes, "application/json")?
            || entry.producer != event.source
            || entry.event_id != event.id
            || entry.native_sequence != event.source_sequence
            || entry.byte_start != consumed.byte_start
            || entry.byte_end != consumed.byte_end
            || entry.checksum_after != consumed.checksum_after
            || entry.zero_byte_consumed != (consumed.byte_start == consumed.byte_end)
        {
            return Err(ProviderError::Correlation(
                "lineage original publication differs",
            ));
        }
        entry
            .original_event
            .verify(source.content(&entry.original_event)?)?;
    }
    let event = &view.observation.events[0];
    if event.provenance_ref != result.physical_measurement_ref
        || event.source.node_id != source.bootstrap.node_id
        || event.source_sequence != view.observation.first_sequence
        || event.position != view.stage.grant.publication
        || event.publication_position != event.position
        || event.delivery_position.is_some()
        || event.stage != EventStage::Publication
        || !event.causal_parent_ids.is_empty()
        || event.payload.media_type != "application/octet-stream"
    {
        return Err(ProviderError::Correlation(
            "lineage original native wire differs",
        ));
    }
    let output = canonical::canonical_json(
        &serde_json::to_value(&view.native.output).map_err(ContractError::from)?,
    )?;
    if source.content(&event.payload)? != output {
        return Err(ProviderError::Correlation(
            "lineage original predecessor differs",
        ));
    }
    let initialize: Value = record(source, &relation.initialize_request, "application/json")?;
    if initialize
        != json!({"command":"initialize","dialect":origin.dialect,"owner":origin.owner,"incarnation":origin.incarnation,"generation":origin.owner_generation})
        || wire(source, &relation.initialize_response_wire)?
            != json!({"result":"ready","dialect":origin.dialect,"owner":origin.owner,"incarnation":origin.incarnation,"generation":origin.owner_generation,"child_pid":origin.child_pid})
        || record::<Value>(source, &relation.close_request, "application/json")?
            != json!({"command":"close","window":grant.grant_id})
        || wire(source, &relation.close_response_wire)?
            != json!({"result":"closed","original":view.native})
    {
        return Err(ProviderError::Correlation(
            "lineage original native command differs",
        ));
    }
    predecessor::validate(view, previous.as_ref())?;
    Ok(())
}
