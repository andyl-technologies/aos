//! Checks the decoded closed Node17 history against the same current common rows.
//!
//! Historical incomplete and failed values remain decodable data. This stricter
//! settled-target predicate is used only after the complete Source/native
//! validator has selected this exact node body for a fresh current17 target.

use super::record::*;
use crate::node_contract::{
    NodeRoute, OriginalLineageRuntimeRecord, RuntimeError, SavedRuntimeResult,
};
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_contract::{Id, Validate};

pub(super) fn validate(
    record: &NodeRecord17,
    route: &NodeRoute,
    runtime: &OriginalLineageRuntimeRecord,
    scheduling: &SchedulingSnapshot,
) -> Result<(), RuntimeError> {
    super::metadata::validate(record)?;
    let node = &route.node;
    if record.schema != "source-owned.packet-restored-node-history/17"
        || record.base.schema != "source-owned.packet-semantic-base/17"
        || !record.install_started
        || !record.installed
        || record.base.quarantined
        || record.base.reclaimed.is_some()
        || record.producer_pending.is_some()
        || record.observation_return.is_some()
        || record
            .observation
            .as_ref()
            .is_none_or(|value| value.node != *node || value.owners != route.owners)
        || !record.observation_attempted
        || record.base.active.as_ref() != Some(&runtime.source_activation)
        || record.base.activation_attempt.as_ref() != Some(&runtime.source_activation)
        || record.base.arm_attempt.as_ref() != Some(&runtime.source_activation)
        || runtime.source_activation.world_binding_hash != scheduling.world_binding_hash
        || runtime.capture_cut != scheduling.capture_cut
        || runtime.capture_ordinal != scheduling.capture_ordinal
    {
        return Err(RuntimeError::OutstandingObligations);
    }
    let Some(HistoricalWorld17::World(world)) = &record.activation else {
        return Err(RuntimeError::InvalidReceipt);
    };
    if world.record != runtime.source_activation {
        return Err(RuntimeError::InvalidReceipt);
    }
    validate_world(world)?;
    let ready = record
        .base
        .ready
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    if ready.owners != route.owners || ready.boundary != runtime.source_activation.boundary {
        return Err(RuntimeError::InvalidReceipt);
    }
    ready
        .state_inventory
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    ready
        .ready_receipt
        .validate()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let prepared = record
        .base
        .prepared_owner
        .as_ref()
        .ok_or(RuntimeError::InvalidReceipt)?;
    if route.owners.len() != 1
        || prepared.owner_id != route.owners[0].owner
        || prepared.incarnation_id != route.owners[0].incarnation
        || prepared.owner_generation != route.owners[0].generation
        || prepared.ready_receipt != ready.ready_receipt
    {
        return Err(RuntimeError::InvalidReceipt);
    }

    for admission in &record.original_operations {
        let HistoricalAdmission17::Admission(admission) = admission;
        validate_admission(admission, route, runtime)?;
    }
    for batch in &record.original_inputs {
        let HistoricalBatch17::InputBatch(batch) = batch;
        validate_batch(batch, route, runtime)?;
    }
    for (key, original) in &record.base.operations {
        if key.as_str().strip_prefix("cnp-begin-") != Some(original.operation.as_str())
            || original.route != *route
            || original.activation != runtime.source_activation
            || !original.begin_acknowledged
            || !original.acknowledged
            || original.failure.is_some()
            || !matches!(
                original.cancellation.0.as_str(),
                "not-attempted" | "requested" | "unsupported"
            )
            || original.cancellation.1.is_some()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let saved = current_operation(runtime, &original.operation, node)?;
        if saved.request != original.request || saved.route != original.route {
            return Err(RuntimeError::InvalidReceipt);
        }
        let SavedRuntimeResult::Acknowledged(outcome) = &saved.result else {
            return Err(RuntimeError::OutstandingObligations);
        };
        if original.outcome.as_ref() != Some(outcome) {
            return Err(RuntimeError::InvalidReceipt);
        }
        if let Some(retirement) = &original.retirement {
            retirement
                .reference
                .verify(&retirement.bytes)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        }
    }
    for (key, input) in &record.base.inputs {
        let batch = &input.original;
        let saved = runtime
            .inputs
            .iter()
            .find(|saved| saved.node == *node && saved.stage_operation == batch.stage_operation)
            .ok_or(RuntimeError::InvalidReceipt)?;
        if key != &batch.stage_operation
            || batch.activation != runtime.source_activation
            || batch.node != *node
            || batch.owners != route.owners
            || batch.batch != saved.batch
            || batch.inventory != saved.inventory
            || batch.cutoff != saved.cutoff
            || batch.deliveries != saved.deliveries
            || batch
                .payloads
                .iter()
                .map(|body| &body.reference)
                .ne(saved.payloads.iter())
            || input.acknowledgement != saved.acknowledgement
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        verify_payloads(&batch.payloads)?;
        if let Some(commitment) = &input.commitment {
            verify_payloads(&commitment.context)?;
            if commitment.original.node != *node
                || commitment.original.stage_operation != batch.stage_operation
                || commitment.original.batch != batch.batch
                || commitment.original.inventory != batch.inventory
                || commitment.original.cutoff != batch.cutoff
                || commitment.original.activation != runtime.source_activation
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
    }
    for (index, observation) in record.current_observations.iter().enumerate() {
        if observation.ordinal
            != u64::try_from(index)
                .map_err(|_| RuntimeError::ResourceLimit)?
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?
            || observation.returned.is_some()
            || observation
                .retained
                .as_ref()
                .is_none_or(|value| value.node != *node || value.owners != route.owners)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for attempt in &record.producer_attempts {
        if !matches!(attempt.stage, ProducerStage17::Verified)
            || attempt.returned.is_some()
            || attempt.scheduling_return.is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let HistoricalAdmission17::Admission(admission) = &attempt.admission;
        validate_admission(admission, route, runtime)?;
        let saved = current_operation(runtime, &admission.operation, node)?;
        let SavedRuntimeResult::Acknowledged(outcome) = &saved.result else {
            return Err(RuntimeError::OutstandingObligations);
        };
        let reached = match &outcome.progress {
            crate::node_contract::ProgressEvidence::Exact { reached, .. } => *reached,
            _ => return Err(RuntimeError::UnsupportedFacet),
        };
        if attempt.retained.as_ref() != Some(outcome)
            || attempt.scheduling.as_ref().is_none_or(|observation| {
                observation.node != *node
                    || observation.owners != route.owners
                    || observation.reached != reached
            })
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    if let Some(families) = &record.restored_families {
        if families.schema != "source-owned.packet-restored-node-families/17"
            || !families.started
            || !families.installed
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        families
            .inherited
            .as_ref()
            .ok_or(RuntimeError::InvalidReceipt)?
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        for map in [
            &families.imported_operations,
            &families.base_operations,
            &families.producer_operations,
        ] {
            for (identity, admission) in map {
                let HistoricalAdmission17::Admission(admission) = admission;
                if identity != &admission.operation {
                    return Err(RuntimeError::InvalidReceipt);
                }
                validate_admission(admission, route, runtime)?;
            }
        }
        for map in [&families.imported_inputs, &families.base_inputs] {
            for (identity, batch) in map {
                let HistoricalBatch17::InputBatch(batch) = batch;
                if identity != &batch.stage_operation {
                    return Err(RuntimeError::InvalidReceipt);
                }
                validate_batch(batch, route, runtime)?;
            }
        }
    }
    // Every current common operation must retain its concrete original Node
    // owner in exactly one history family; a duplicate equal body is no alias.
    for saved in runtime
        .operations
        .iter()
        .filter(|saved| saved.route.node == *node)
    {
        let original = record
            .original_operations
            .iter()
            .filter(|row| {
                let HistoricalAdmission17::Admission(row) = row;
                row.operation == saved.operation
            })
            .count();
        let base = record
            .base
            .operations
            .values()
            .filter(|row| row.operation == saved.operation)
            .count();
        let producer = record
            .producer_attempts
            .iter()
            .filter(|row| {
                let HistoricalAdmission17::Admission(admission) = &row.admission;
                admission.operation == saved.operation
            })
            .count();
        let restored = record.restored_families.as_ref().map_or(0, |families| {
            [
                &families.imported_operations,
                &families.base_operations,
                &families.producer_operations,
            ]
            .into_iter()
            .filter(|map| map.contains_key(&saved.operation))
            .count()
        });
        if original
            .checked_add(base)
            .and_then(|sum| sum.checked_add(producer))
            .and_then(|sum| sum.checked_add(restored))
            != Some(1)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    for saved in runtime.inputs.iter().filter(|saved| saved.node == *node) {
        let original = record
            .original_inputs
            .iter()
            .filter(|row| {
                let HistoricalBatch17::InputBatch(row) = row;
                row.stage_operation == saved.stage_operation
            })
            .count();
        let base = record
            .base
            .inputs
            .values()
            .filter(|row| row.original.stage_operation == saved.stage_operation)
            .count();
        let restored = record.restored_families.as_ref().map_or(0, |families| {
            [&families.imported_inputs, &families.base_inputs]
                .into_iter()
                .filter(|map| map.contains_key(&saved.stage_operation))
                .count()
        });
        if original
            .checked_add(base)
            .and_then(|sum| sum.checked_add(restored))
            != Some(1)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

fn current_operation<'a>(
    runtime: &'a OriginalLineageRuntimeRecord,
    operation: &Id,
    node: &Id,
) -> Result<&'a crate::node_contract::SavedRuntimeOperation, RuntimeError> {
    let mut rows = runtime
        .operations
        .iter()
        .filter(|row| &row.operation == operation && &row.route.node == node);
    let row = rows.next().ok_or(RuntimeError::InvalidReceipt)?;
    if rows.next().is_some() {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(row)
}

fn validate_admission(
    admission: &AdmissionRecord17,
    route: &NodeRoute,
    runtime: &OriginalLineageRuntimeRecord,
) -> Result<(), RuntimeError> {
    let saved = current_operation(runtime, &admission.operation, &route.node)?;
    if admission.route != *route
        || admission.route != saved.route
        || admission.request != saved.request
        || admission.activation.record != runtime.source_activation
        || admission.inputs.as_ref().map(|batch| &batch.batch) != saved.input_batch.as_ref()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    validate_world(&admission.activation)?;
    if let Some(batch) = &admission.inputs {
        validate_batch(batch, route, runtime)?;
    }
    Ok(())
}

fn validate_batch(
    batch: &BatchRecord17,
    route: &NodeRoute,
    runtime: &OriginalLineageRuntimeRecord,
) -> Result<(), RuntimeError> {
    let mut rows = runtime
        .inputs
        .iter()
        .filter(|row| row.node == route.node && row.stage_operation == batch.stage_operation);
    let saved = rows.next().ok_or(RuntimeError::InvalidReceipt)?;
    if rows.next().is_some()
        || batch.activation.record != runtime.source_activation
        || batch.node != route.node
        || batch.owners != route.owners
        || batch.batch != saved.batch
        || batch.cutoff != saved.cutoff
        || batch.inventory != saved.inventory
        || batch.deliveries != saved.deliveries
        || batch
            .payloads
            .iter()
            .map(|body| &body.reference)
            .ne(saved.payloads.iter())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    validate_world(&batch.activation)?;
    verify_payloads(&batch.payloads)
}

fn validate_world(world: &WorldRecord17) -> Result<(), RuntimeError> {
    for node in &world.nodes {
        node.node
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        node.readiness
            .state_inventory
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        node.readiness
            .ready_receipt
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    if let Some(publication) = &world.preparation {
        publication
            .coordinator
            .reference
            .verify(&publication.coordinator.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    Ok(())
}

fn verify_payloads(payloads: &[crate::node_scheduling::InputPayload]) -> Result<(), RuntimeError> {
    for payload in payloads {
        payload
            .reference
            .verify(&payload.bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    }
    Ok(())
}
