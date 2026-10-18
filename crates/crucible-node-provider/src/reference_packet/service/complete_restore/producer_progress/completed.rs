//! Validates the completed native grant before durable common publication.

use super::*;
use crate::bodies::{
    BeginArguments, BoundaryPolicy, MethodResult, OperationState, RequestBody, ResponseShape,
    StopReason, decode_request,
};
use crate::envelope::Method;
use crate::reference_packet::{PacketGrant, PacketInventory};
use crucible_node_contract::{BoundKind, OperatingMode, U64, Validate};

/// Joins actual completed Begin/Poll evidence to the last verified checkpoint.
///
/// The caller first admits the complete raw/typed decode and proof work and
/// authenticates every full content reference against the retained raw owners.
/// It separately checks the live Source/Controller/child/read-member frontier.
/// This function supplies DATA correspondence only and permits no callback.
///
/// # Errors
/// Refuses changed ancestry, mismatched originals/arguments, unsupported Input
/// or Begin kinds, partial work, a straddled callback or any changed model effect.
pub fn authenticate_restored_producer_completed_data(
    input: &PacketRestoredProducerCompletedData<'_>,
) -> Result<(), ProviderError> {
    let view = super::pair_views::Completed::from_live(input);
    authenticate_completed_view_data(&view)
}

pub(super) fn authenticate_completed_view_data(
    input: &super::pair_views::Completed<'_>,
) -> Result<(), ProviderError> {
    let crate::reference_packet::service::PacketConnectedSourceProgram::Producer { program } =
        &input.launch.program
    else {
        return Err(invalid());
    };
    let [private, output] = program.events.as_slice() else {
        return Err(invalid());
    };
    let before = &input.checkpoint_producer.inventory;
    if private.payload.is_some()
        || output
            .payload
            .as_ref()
            .is_none_or(|bytes| bytes.as_slice().len() > 32)
        || before.pending.len() > program.events.len()
        || before.pending != program.events[program.events.len() - before.pending.len()..]
        || before.private_mutations.get() != u64::from(before.pending.len() < 2)
        || before.packet_effects.get() != u64::from(before.pending.is_empty())
    {
        return Err(invalid());
    }
    lineage::lineage(input.held, input.checkpoint, input.restored)?;
    lineage::record(input.checkpoint, input.checkpoint_producer)?;
    lineage::record(input.restored, input.producer)?;
    input.measurement.validate()?;
    if input.checkpoint_producer.grant.is_some()
        || !input
            .checkpoint_producer
            .inventory
            .retained_outputs
            .is_empty()
    {
        return Err(invalid());
    }
    let (begin, begin_terminal, begin_response) = lineage::pair_data(input.begin, Method::Begin)?;
    let (poll, _, poll_response) = lineage::pair_data(input.poll, Method::Poll)?;
    lineage::same_route(begin, poll)?;
    if begin.operation_id.0.as_ref() != Some(input.operation.operation)
        || poll.operation_id != begin.operation_id
        || input.producer.original != *begin
    {
        return Err(invalid());
    }
    let RequestBody::Begin(request) = decode_request(Method::Begin, &begin.body)? else {
        return Err(invalid());
    };
    let arguments = match request.decoded_arguments()? {
        BeginArguments::ExactRun(arguments) | BeginArguments::BoundarySettle(arguments) => {
            arguments
        }
        _ => return Err(invalid()),
    };
    let binding = input
        .launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(invalid)?;
    let owner = input
        .launch
        .selection
        .realization
        .owners
        .first()
        .ok_or_else(invalid)?;
    let owner_binding = input
        .launch
        .selection
        .realization
        .owner_bindings
        .first()
        .ok_or_else(invalid)?;
    let expected = &input.operation;
    if (expected.kind == BeginKind::BoundarySettle
        && expected.start.time_ps != expected.limit.time_ps)
        || !matches!(
            expected.kind,
            BeginKind::ExactRun | BeginKind::BoundarySettle
        )
        || request.kind != expected.kind
        || !request.extensions.is_empty()
        || arguments != *input.arguments
        || arguments.grant_id != *expected.operation
        || arguments.start != expected.start
        || arguments.limit != expected.limit
        || arguments.start != input.checkpoint_producer.inventory.reached
        || arguments.mode != OperatingMode::Exact
        || arguments.boundary_policy != BoundaryPolicy::OrdinaryStop
        || arguments.input_watermark.get() != 0
        || arguments.participant_ids != owner.participant_ids
        || arguments.realization_id != input.launch.selection.realize.realization_id
        || arguments.activation_id != input.held.target_activation
        || arguments.world_generation != input.held.target_generation
        || arguments.owner_generation != binding.authority.owner_generation
        || arguments.input_epoch != binding.authority.input_epoch
        || request.binding_hash != owner_binding.identity()?
        || request.owner_generation != arguments.owner_generation
        || request.activation_id.0.as_ref() != Some(&arguments.activation_id)
        || request.world_generation != arguments.world_generation
    {
        return Err(invalid());
    }
    let grant = input.producer.grant.as_ref().ok_or_else(invalid)?;
    transition(&input.checkpoint_producer.inventory, grant, expected)?;
    if grant.inventory != input.producer.inventory {
        return Err(invalid());
    }
    let result = match (&begin_response.shape, &begin_response.result, expected.kind) {
        (
            ResponseShape::Completed { .. },
            Some(MethodResult::ExactRun(value)),
            BeginKind::ExactRun,
        )
        | (
            ResponseShape::Completed { .. },
            Some(MethodResult::BoundarySettle(value)),
            BeginKind::BoundarySettle,
        ) => value,
        _ => return Err(invalid()),
    };
    let attention = grant
        .inventory
        .pending
        .iter()
        .filter(|event| event.payload.is_some())
        .map(|event| event.completion)
        .min()
        .unwrap_or(grant.inventory.reached);
    let stop_reason = if grant.inventory.reached == expected.limit {
        StopReason::Ceiling
    } else {
        StopReason::Attention
    };
    if result.grant_id != *expected.operation
        || result.reached != grant.inventory.reached
        || result.stop_reason != stop_reason
        || result.stop_receipt != *input.measurement
        || result.observation_batch != *input.measurement
        || result.pending_inventory != *input.measurement
        || result.next_attention.kind != BoundKind::At
        || result.next_attention.position != Some(attention)
        || result.next_attention.evidence.as_ref() != Some(input.measurement)
    {
        return Err(invalid());
    }
    let RequestBody::Poll(request) = decode_request(Method::Poll, &poll.body)? else {
        return Err(invalid());
    };
    let (ResponseShape::Completed { .. }, Some(MethodResult::Poll(result))) =
        (&poll_response.shape, &poll_response.result)
    else {
        return Err(invalid());
    };
    if request.after_observation_sequence.get() != 0
        || !request.extensions.is_empty()
        || result.operation_id != *expected.operation
        || result.operation_state != OperationState::Completed
        || result.outcome.0.as_ref() != Some(&begin_terminal.body)
        || !result.observations.is_empty()
        || result.next_observation_sequence.get() != 1
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn transition(
    before: &PacketInventory,
    grant: &PacketGrant,
    operation: &PacketRestoredProducerOperationData<'_>,
) -> Result<(), ProviderError> {
    operation.start.validate()?;
    operation.limit.validate()?;
    if before.gate_closed
        || !before.retained_outputs.is_empty()
        || operation.start != before.reached
        || operation.start > operation.limit
        || grant.operation != *operation.operation
        || grant.start != operation.start
        || grant.limit != operation.limit
        || !grant.complete
        || grant.inventory.gate_closed
    {
        return Err(invalid());
    }
    let completed = before
        .pending
        .iter()
        .take_while(|event| event.completion < operation.limit)
        .count();
    if grant.inventory.pending != before.pending[completed..]
        || grant.inventory.retained_outputs != grant.newborn
    {
        return Err(invalid());
    }
    let mut private = before.private_mutations.get();
    let mut effects = before.packet_effects.get();
    let mut newborn = grant.newborn.iter();
    for event in &before.pending[..completed] {
        if let Some(payload) = &event.payload {
            effects = effects.checked_add(1).ok_or_else(invalid)?;
            let publication = newborn.next().ok_or_else(invalid)?;
            if publication.event != event.id
                || publication.operation != *operation.operation
                || publication.sequence != U64::new(effects)
                || publication.evaluation != event.evaluation
                || publication.publication != event.completion
                || publication.payload != *payload
            {
                return Err(invalid());
            }
        } else {
            private = private.checked_add(1).ok_or_else(invalid)?;
        }
    }
    let reached = before.pending[completed..]
        .first()
        .filter(|event| event.evaluation < operation.limit)
        .map_or(operation.limit, |event| event.evaluation);
    if newborn.next().is_some()
        || grant.inventory.private_mutations.get() != private
        || grant.inventory.packet_effects.get() != effects
        || grant.inventory.reached != reached
    {
        return Err(invalid());
    }
    Ok(())
}
