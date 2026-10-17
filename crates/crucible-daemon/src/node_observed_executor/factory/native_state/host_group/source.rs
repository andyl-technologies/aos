//! Authenticates complete original coordinator and disconnected storage inputs.
//!
//! Signed bytes retain original custody, while regenerated source policy fixes
//! the only supported connection. Native owner readers separately reopen the
//! actual operation, model, input and ACK ledgers before any restoration permit.

use std::collections::BTreeSet;

use crucible::{
    node_admission::{AdmittedGraph, ConnectionDelivery},
    node_contract::{ProgressEvidence, RuntimeSnapshot, SavedRuntimeOperation, SavedRuntimeResult},
    node_scheduling::{
        SchedulingSnapshot,
        event::{Delivery, direct_delivery},
        validate_saved_source,
    },
    node_state::{StateError, StateErrorCode, VerifiedStateContent},
};
use crucible_node_contract::{ContentRef, U64};

use super::profile::IndependentGroupProfile;

pub(super) fn authenticate(
    profile: &IndependentGroupProfile,
    graph: &AdmittedGraph,
    runtime: &RuntimeSnapshot,
    scheduler: &SchedulingSnapshot,
    content: &VerifiedStateContent,
) -> Result<(), StateError> {
    let scenario = &profile.scenario;
    profile
        .metadata
        .as_ref()
        .ok_or_else(|| error("original preserving group has no complete metadata codec"))?
        .authenticate_complete(content)?;
    let world = scenario.world.identity().map_err(error)?;
    if !profile.preserving
        || graph.world() != &scenario.world
        || graph.node_ids().count() != 4
        || scenario.world.connections.len() != 1
        || runtime.schema_version != 1
        || scheduler.schema_version != 1
        || runtime.terminal.is_some()
        || runtime.condition_stop.is_some()
        || runtime.source_activation.world_binding_hash != world
        || scheduler.world_binding_hash != world
        || runtime.source_activation.activation_id != scheduler.source_activation_id
        || runtime.source_activation.generation != scheduler.source_generation
        || runtime.source_activation.boundary != scheduler.source_boundary
        || runtime.capture_cut != scheduler.capture_cut
        || runtime.capture_ordinal != scheduler.capture_ordinal
        || runtime.source_activation.owners.len() != 4
        || runtime.owners.len() != 4
        || !scheduler.external_closed_prefixes.is_empty()
    {
        return Err(error("complete group original coordinator scope differs"));
    }
    for descriptor in &scenario.descriptors {
        if graph.descriptor(&descriptor.id) != Some(descriptor)
            || graph
                .binding(&descriptor.id)
                .is_none_or(|binding| !scenario.compatibility.contains(&binding.compatibility))
        {
            return Err(error(
                "complete group original descriptor or implementation differs",
            ));
        }
    }
    validate_saved_source(graph, scheduler).map_err(error)?;
    for original in &runtime.owners {
        if !runtime
            .source_activation
            .owners
            .contains(&original.identity)
            || graph
                .owner(&original.identity.owner)
                .is_none_or(|binding| binding.owner.state_domain_ids != original.domains)
        {
            return Err(error(
                "complete group original runtime owner or domains differ",
            ));
        }
    }
    if runtime
        .source_activation
        .owners
        .iter()
        .map(|owner| (&owner.owner, &owner.incarnation, owner.generation))
        .ne(scheduler
            .source_owners
            .iter()
            .map(|owner| (&owner.owner, &owner.incarnation, owner.generation)))
    {
        return Err(error(
            "complete group original scheduler owner roster differs",
        ));
    }
    for reference in [
        &scenario.world.scenario_ref,
        &scenario.world.initialization_ref,
        &scenario.world.ownership_ref,
        &scenario.world.coordinator_contract_ref,
    ] {
        verified(content, reference)?;
    }
    for payload in &scheduler.payload_objects {
        if verified(content, &payload.reference)? != payload.bytes {
            return Err(error("complete group original payload body differs"));
        }
    }

    let mut operations = BTreeSet::new();
    for operation in &runtime.operations {
        let binding = graph
            .binding(&operation.route.node)
            .ok_or_else(|| error("complete group operation has foreign node"))?;
        let owner = runtime
            .source_activation
            .owners
            .iter()
            .find(|owner| owner.owner == binding.compatibility.execution_owner.id)
            .ok_or_else(|| error("complete group original operation owner is absent"))?;
        if !operations.insert(&operation.operation)
            || operation.route.owners.as_slice() != std::slice::from_ref(owner)
            || !scheduler.used_operations.contains(&operation.operation)
        {
            return Err(error(
                "complete group original operation identity or owner differs",
            ));
        }
        if let SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) =
            &operation.result
        {
            if outcome.operation != operation.operation
                || outcome.node != operation.route.node
                || outcome.owners != operation.route.owners
                || matches!(outcome.progress, ProgressEvidence::Quantized { .. })
            {
                return Err(error("complete group original native outcome differs"));
            }
            if let Some(observation) = &outcome.scheduling {
                if observation.node != outcome.node
                    || observation.owners != outcome.owners
                    || !observation.external_inputs.is_empty()
                {
                    return Err(error(
                        "complete group observation introduced foreign input authority",
                    ));
                }
                verified(content, &observation.proof_ref)?;
                for bound in &observation.bounds {
                    verified(content, &bound.proof_ref)?;
                }
                for publication in &observation.publications {
                    if publication.endpoint.node_id != outcome.node
                        || verified(content, &publication.payload)? != publication.payload_bytes
                    {
                        return Err(error("complete group original native publication differs"));
                    }
                }
                if let Some(progress) = &observation.input_progress {
                    verified(content, &progress.proof_ref)?;
                    if outcome.node.as_str() == "cpu" && !progress.consumed.is_empty() {
                        return Err(error("disconnected original CPU claimed public input"));
                    }
                }
            }
        }
    }
    authenticate_prefix(graph, runtime, scheduler)?;

    for input in &runtime.inputs {
        if input.node.as_str() == "cpu" || input.node.as_str() == "clock" {
            return Err(error(
                "disconnected original native owner has input custody",
            ));
        }
        verified(content, &input.inventory)?;
        if let Some(ack) = &input.acknowledgement {
            verified(content, &ack.proof_ref)?;
        }
        let consumed =
            authenticate_input_frontier(&runtime.operations, input, &scheduler.used_input_batches)?;
        let batches = scheduler.input_batches.iter().filter(|batch| {
            batch.stage_operation == input.stage_operation && batch.node == input.node
        });
        let mut batches = batches;
        if let Some(batch) = batches.next() {
            if batches.next().is_some()
                || batch.batch != input.batch
                || batch.owners != input.owners
                || batch.cutoff != input.cutoff
                || batch.inventory != input.inventory
                || batch.deliveries != input.deliveries
                || batch.payloads != input.payloads
                || batch.acknowledgement != input.acknowledgement
                || batch.consumed.len() != consumed
                || !batch
                    .consumed
                    .iter()
                    .zip(&input.deliveries)
                    .all(|(identity, delivery)| {
                        identity.producer == delivery.producer
                            && identity.source_sequence == delivery.source_sequence
                    })
            {
                return Err(error(
                    "complete original input batch, consumed prefix or ACK differs",
                ));
            }
        } else if consumed != input.deliveries.len() {
            return Err(error(
                "original unconsumed native input has no coordinator custody",
            ));
        }
        for delivery in &input.deliveries {
            authenticate_delivery(graph, runtime, delivery, content)?;
        }
    }
    if scheduler.input_batches.iter().any(|batch| {
        !runtime
            .inputs
            .iter()
            .any(|input| input.stage_operation == batch.stage_operation && input.node == batch.node)
    }) {
        return Err(error("coordinator omitted original native input custody"));
    }
    for delivery in &scheduler.pending_deliveries {
        authenticate_delivery(graph, runtime, delivery, content)?;
    }
    Ok(())
}

fn authenticate_input_frontier(
    operations: &[SavedRuntimeOperation],
    input: &crucible::node_contract::SavedRuntimeInput,
    used_batches: &[crucible_node_contract::Id],
) -> Result<usize, StateError> {
    let ack = input
        .acknowledgement
        .as_ref()
        .ok_or_else(|| error("original native input has no authentic staging acknowledgement"))?;
    if !input.committed
        || !input.coordinator_committed
        || input.failure.is_some()
        || ack.stage_operation != input.stage_operation
        || ack.batch != input.batch
        || ack.node != input.node
        || ack.owners != input.owners
        || ack.cutoff != input.cutoff
        || ack.inventory != input.inventory
        || !used_batches.contains(&input.batch)
    {
        return Err(error(
            "original input staging scope or coordinator commitment differs",
        ));
    }
    let mut consumed = 0;
    for operation in operations {
        let outcome = match &operation.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome
            }
            _ => continue,
        };
        let Some(progress) = outcome
            .scheduling
            .as_ref()
            .and_then(|observation| observation.input_progress.as_ref())
        else {
            continue;
        };
        if outcome.node != input.node || progress.batch != input.batch {
            continue;
        }
        if operation.input_batch.as_ref() != Some(&input.batch)
            || operation.route.node != input.node
            || operation.route.owners != input.owners
            || outcome.owners != input.owners
            || operation.scheduling_commit.as_ref().is_none_or(|commit| {
                commit.node != input.node || commit.operation != operation.operation
            })
            || progress.consumed.len() > input.deliveries.len()
            || !progress
                .consumed
                .iter()
                .zip(&input.deliveries)
                .all(|(identity, delivery)| {
                    identity.producer == delivery.producer
                        && identity.source_sequence == delivery.source_sequence
                })
        {
            return Err(error(
                "original input consumption has no exact committed native operation",
            ));
        }
        consumed = consumed.max(progress.consumed.len());
    }
    // Native terminal consumption retires the coordinator's active batch, while
    // the runtime preserves its original ACK and complete historical inventory.
    Ok(consumed)
}

fn authenticate_delivery(
    graph: &AdmittedGraph,
    runtime: &RuntimeSnapshot,
    delivery: &Delivery,
    content: &VerifiedStateContent,
) -> Result<(), StateError> {
    let connection = graph
        .world()
        .connections
        .first()
        .ok_or_else(|| error("original group connection is absent"))?;
    let policy = graph
        .connection_policy(&connection.id)
        .ok_or_else(|| error("original group delivery policy is absent"))?;
    let ConnectionDelivery::Fixed { latency_ps } = policy.delivery;
    let mut originals = runtime
        .operations
        .iter()
        .filter_map(|operation| {
            let outcome = match &operation.result {
                SavedRuntimeResult::Complete(outcome)
                | SavedRuntimeResult::Acknowledged(outcome) => outcome,
                _ => return None,
            };
            outcome
                .scheduling
                .as_ref()
                .map(|observation| (operation, observation))
        })
        .flat_map(|(operation, observation)| {
            observation
                .publications
                .iter()
                .filter(move |publication| {
                    publication.publication_id == delivery.publication_id
                        && publication.endpoint.node_id == delivery.producer
                })
                .map(move |publication| (operation, observation, publication))
        });
    let (operation, observation, original) = originals
        .next()
        .ok_or_else(|| error("original delivery has no native terminal publication"))?;
    let commit = operation
        .scheduling_commit
        .as_ref()
        .ok_or_else(|| error("original delivery publication was not committed"))?;
    if originals.next().is_some()
        || commit.node != operation.route.node
        || commit.operation != operation.operation
        || commit
            .retained_outputs
            .iter()
            .filter(|id| **id == original.publication_id)
            .count()
            != 1
        || delivery.connection_id.as_ref() != Some(&connection.id)
        || delivery.connection_policy_ref.as_ref() != Some(&connection.policy_ref)
        || delivery.external_root.is_some()
        || delivery.producer != connection.producer.node_id
        || delivery.consumer != connection.consumer.node_id
        || delivery.producer_endpoint != connection.producer
        || delivery.consumer_endpoint != connection.consumer
        || original.endpoint != connection.producer
        || delivery.provenance_ref != observation.proof_ref
        || delivery.native_sequence != original.native_sequence
        || delivery.evaluation != original.evaluation
        || delivery.causal_parents != original.causal_parents
        || delivery.publication != original.publication
        || delivery.payload != original.payload
        || verified(content, &delivery.payload)? != original.payload_bytes
        || delivery.delivery
            != direct_delivery(original.publication, latency_ps, None).map_err(error)?
    {
        return Err(error(
            "original full Delivery differs from committed native custody",
        ));
    }
    if delivery.source_sequence != original.native_sequence {
        return Err(error("original native and public sequence scopes differ"));
    }
    Ok(())
}

fn authenticate_prefix(
    graph: &AdmittedGraph,
    runtime: &RuntimeSnapshot,
    scheduler: &SchedulingSnapshot,
) -> Result<(), StateError> {
    let endpoint = &graph.world().connections[0].producer;
    if scheduler_lane_missing(graph, endpoint.node_id.as_str()) {
        return Err(error("original source has unsupported publication fanout"));
    }
    let mut sequences = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for operation in &runtime.operations {
        let outcome = match &operation.result {
            SavedRuntimeResult::Complete(outcome) | SavedRuntimeResult::Acknowledged(outcome) => {
                outcome
            }
            _ => continue,
        };
        let Some(observation) = &outcome.scheduling else {
            continue;
        };
        for publication in observation
            .publications
            .iter()
            .filter(|publication| &publication.endpoint == endpoint)
        {
            let commit = operation
                .scheduling_commit
                .as_ref()
                .ok_or_else(|| error("original native publication has no scheduling commitment"))?;
            if commit.node != operation.route.node
                || commit.operation != operation.operation
                || commit
                    .retained_outputs
                    .iter()
                    .filter(|id| **id == publication.publication_id)
                    .count()
                    != 1
                || !sequences.insert(publication.native_sequence)
                || !identities.insert(&publication.publication_id)
            {
                return Err(error(
                    "original committed native publication inventory repeats or differs",
                ));
            }
        }
    }
    let mut producers = scheduler
        .producers
        .iter()
        .filter(|producer| producer.node == endpoint.node_id);
    let producer = producers
        .next()
        .ok_or_else(|| error("original source producer counter is absent"))?;
    let mut lanes = scheduler
        .native_sequences
        .iter()
        .filter(|lane| &lane.endpoint == endpoint);
    let lane = lanes.next();
    let expected_last = sequences
        .len()
        .checked_sub(1)
        .map(|last| U64::new(last as u64));
    if producers.next().is_some()
        || lanes.next().is_some()
        || sequences
            .iter()
            .copied()
            .ne((0..sequences.len()).map(|index| U64::new(index as u64)))
        || producer.next_sequence != Some(U64::new(sequences.len() as u64))
        || lane.map(|lane| lane.last_sequence) != expected_last
    {
        return Err(error(
            "original native FIFO and coordinator prefix counters differ",
        ));
    }
    Ok(())
}

fn scheduler_lane_missing(graph: &AdmittedGraph, producer: &str) -> bool {
    graph
        .world()
        .connections
        .iter()
        .filter(|connection| connection.producer.node_id.as_str() == producer)
        .count()
        != 1
}

fn verified<'a>(
    content: &'a VerifiedStateContent,
    reference: &ContentRef,
) -> Result<&'a [u8], StateError> {
    let bytes = content
        .get(reference)
        .ok_or_else(|| error("original complete group proof body is absent"))?;
    reference.verify(bytes).map_err(error)?;
    Ok(bytes)
}

pub(super) fn error(reason: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "installed independent storage group",
        reason.to_string(),
    )
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;
