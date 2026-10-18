//! Validates actual Consumed retirement before advancing the current checkpoint.

use super::*;
use crate::bodies::{
    MethodResult, RequestBody, ResponseShape, RetirementDisposition, decode_request,
};
use crate::envelope::Method;
use crucible_node_contract::{Validate, Visibility, canonical};

/// Joins real Retire and a fresh grant-free Observe to a durable completed action.
///
/// The Source authenticates the durable consumption bytes and genuine scheduling
/// receipt before Retire. The consumption object is not the durable root and
/// neither reference alone proves publication. The Source then authenticates this Observe at its current SDK and
/// SourceRead frontier. No old held cursor/hash is substituted for current work.
///
/// # Errors
/// Refuses changed immutable ancestry, output IDs, consumption reference, route,
/// grant/cursor/counters, partial retirement or a stale/nonmatching observation.
pub fn authenticate_restored_producer_retired_data(
    input: &PacketRestoredProducerRetiredData<'_>,
) -> Result<(), ProviderError> {
    let completed = super::pair_views::Completed::from_live(input.completed);
    let view = super::pair_views::Retired::from_live(input, &completed);
    authenticate_retired_view_data(&view)
}

pub(super) fn authenticate_retired_view_data(
    input: &super::pair_views::Retired<'_, '_>,
) -> Result<(), ProviderError> {
    super::completed::authenticate_completed_view_data(input.completed)?;
    lineage::lineage(
        input.completed.held,
        input.completed.restored,
        input.restored,
    )?;
    lineage::record(input.restored, input.producer)?;
    input.consumption.verify(input.canonical_consumption)?;
    input.durable_root.validate()?;
    let consumption: Consumption = serde_json::from_slice(input.canonical_consumption)
        .map_err(crucible_node_contract::ContractError::from)?;
    let grant = input
        .completed
        .producer
        .grant
        .as_ref()
        .ok_or_else(invalid)?;
    if consumption.schema != "source-owned.packet-consumption.v1"
        || consumption.operation != *input.completed.operation.operation
        || consumption.outputs.len() != grant.newborn.len()
        || consumption
            .outputs
            .iter()
            .zip(&grant.newborn)
            .any(|(id, output)| id != &output.event)
    {
        return Err(invalid());
    }
    input.measurement.validate()?;
    let (begin, _, _) = input.completed.begin.completed_pair_data()?;
    let (poll, _, _) = input.completed.poll.completed_pair_data()?;
    let (retire, _, reply) = lineage::pair_data(input.retire, Method::Retire)?;
    let (observe, _, observation) = lineage::pair_data(input.observe, Method::Observe)?;
    lineage::same_route(poll, retire)?;
    lineage::same_route(retire, observe)?;
    let RequestBody::Retire(request) = decode_request(Method::Retire, &retire.body)? else {
        return Err(invalid());
    };
    let (ResponseShape::Completed { .. }, Some(MethodResult::Retire(result))) =
        (&reply.shape, &reply.result)
    else {
        return Err(invalid());
    };
    if retire.operation_id.0.is_some()
        || observe.operation_id.0.is_some()
        || request.disposition != RetirementDisposition::Consumed
        || !request.extensions.is_empty()
        || request.request_ids.as_slice()
            != std::slice::from_ref(begin.request_id.0.as_ref().ok_or_else(invalid)?)
        || request.operation_ids.as_slice()
            != std::slice::from_ref(input.completed.operation.operation)
        || request.custody_receipt.0.as_ref() != Some(input.consumption)
        || result.retired_request_ids != request.request_ids
        || result.retired_operation_ids != request.operation_ids
        || input.producer.original != *observe
        || input.producer.grant.is_some()
    {
        return Err(invalid());
    }
    let old = &input.completed.producer.inventory;
    let current = &input.producer.inventory;
    if !current.retained_outputs.is_empty()
        || current.pending != old.pending
        || current.reached != old.reached
        || current.gate_closed != old.gate_closed
        || current.private_mutations != old.private_mutations
        || current.packet_effects != old.packet_effects
    {
        return Err(invalid());
    }
    let RequestBody::Observe(request) = decode_request(Method::Observe, &observe.body)? else {
        return Err(invalid());
    };
    let (ResponseShape::Completed { .. }, Some(MethodResult::Observe(result))) =
        (&observation.shape, &observation.result)
    else {
        return Err(invalid());
    };
    let [batch] = result.observations.as_slice() else {
        return Err(invalid());
    };
    let receipt = &input.restored.native_receipt;
    if request.after_observation_sequence.get() != 0
        || request.maximum_items.get() != 1
        || !request.extensions.is_empty()
        || !result.complete
        || result.next_sequence.get() != 1
        || result.inventory_hash
            != canonical::json_hash("source-owned.packet-inventory.v1", current)?
        || batch.schema_version != 1
        || batch.execution_owner_id != receipt.owner
        || batch.world_binding_hash != receipt.world
        || batch.activation_id != input.completed.held.target_activation
        || batch.world_generation != input.completed.held.target_generation
        || batch.owner_generation != receipt.owner_generation
        || batch.operation_id != *observe.request_id.0.as_ref().ok_or_else(invalid)?
        || batch.grant_id.is_some()
        || batch.first_sequence.get() != 0
        || batch.last_sequence.get() != 0
        || !batch.events.is_empty()
        || batch.visibility != Visibility::Staged
        || batch.measurement_ref != *input.measurement
        || !batch.extensions.is_empty()
        || batch.owner_binding_hash != request.binding_hash
        || request.owner_generation != receipt.owner_generation
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Consumption {
    schema: String,
    operation: Id,
    outputs: Vec<Id>,
}
