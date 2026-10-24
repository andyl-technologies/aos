//! Authenticates full original scheduler batch lineage without assuming emptiness.

use super::*;
use crucible_engine::{node_contract::OwnerIdentity, node_scheduling::RuntimeInputBatch};
use crucible_node_format::{Phase, Position, U64};
use std::collections::BTreeSet;

pub(super) fn authenticate(
    authority: &InstalledPacketConnectedCollectionAuthority,
    batch: &RuntimeInputBatch,
) -> Result<(), EvidenceError> {
    let activation = batch.activation().record();
    if activation.world_binding_hash
        != authority
            .world
            .identity()
            .map_err(|error| evidence_error(error.into()))?
        || activation.owners.len() != 4
        || batch.deliveries().len() > 4
        || batch.payloads().len() > 4
    {
        return Err(evidence_error(refused()));
    }
    for (member, selected) in authority
        .roster
        .sources
        .iter()
        .map(|source| source.installation())
        .enumerate()
    {
        let original = &activation.owners[member];
        if original.owner != selected.owner.owner.id
            || original.incarnation != selected.binding.authority.incarnation_id
            || original.generation != selected.binding.authority.owner_generation
        {
            return Err(evidence_error(refused()));
        }
    }
    let host = authority.host.selection();
    let original = &activation.owners[3];
    if original.owner != host.owner.owner.id
        || original.incarnation != host.binding.authority.incarnation_id
        || original.generation != host.binding.authority.owner_generation
    {
        return Err(evidence_error(refused()));
    }
    let member = authority
        .roster
        .sources
        .iter()
        .position(|source| &source.installation().descriptor.id == batch.node())
        .ok_or_else(|| evidence_error(refused()))?;
    if member == 0 {
        return Err(evidence_error(refused()));
    }
    let selected = authority.roster.sources[member].installation();
    if batch.owners()
        != [OwnerIdentity {
            owner: selected.owner.owner.id.clone(),
            incarnation: selected.binding.authority.incarnation_id.clone(),
            generation: selected.binding.authority.owner_generation,
        }]
    {
        return Err(evidence_error(refused()));
    }
    let inventory =
        canonical::canonical_json(&serde_json::to_value(batch.deliveries()).map_err(|error| {
            evidence_error(crucible_node_format::ContractError::from(error).into())
        })?)
        .map_err(|error| evidence_error(error.into()))?;
    batch
        .inventory()
        .verify(&inventory)
        .map_err(|error| evidence_error(error.into()))?;
    if inventory.len() > 65_536 {
        return Err(evidence_error(refused()));
    }
    let mut previous = None;
    let mut payloads = BTreeSet::new();
    for delivery in batch.deliveries() {
        let connection = authority
            .world
            .connections
            .iter()
            .find(|connection| delivery.connection_id.as_ref() == Some(&connection.id))
            .ok_or_else(|| evidence_error(refused()))?;
        let arrival = delivery
            .publication
            .time_ps
            .checked_add(connection.minimum_latency_ps)
            .map_err(|error| evidence_error(error.into()))?;
        let coordinate = Position::new(
            arrival,
            if connection.minimum_latency_ps.get() == 0 {
                delivery.publication.microstep
            } else {
                U64::new(0)
            },
            Phase::Delivery,
        );
        let key = delivery.key();
        if delivery.external_root.is_some()
            || delivery.connection_policy_ref.as_ref() != Some(&connection.policy_ref)
            || delivery.producer_endpoint != connection.producer
            || delivery.consumer_endpoint != connection.consumer
            || delivery.producer != connection.producer.node_id
            || delivery.consumer != connection.consumer.node_id
            || &delivery.consumer != batch.node()
            || delivery.publication.phase != Phase::Publication
            || delivery.delivery != coordinate
            || delivery.delivery >= batch.cutoff()
            || delivery.native_sequence.get() == 0
            || previous.as_ref().is_some_and(|old| old >= &key)
            || delivery.evaluation.is_none_or(|evaluation| {
                evaluation.phase != Phase::Reaction
                    || evaluation >= delivery.publication
                    || delivery
                        .causal_parents
                        .iter()
                        .any(|parent| parent > &evaluation)
            })
            || delivery
                .causal_parents
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(evidence_error(refused()));
        }
        let body = batch
            .payloads()
            .iter()
            .find(|body| body.reference == delivery.payload)
            .ok_or_else(|| evidence_error(refused()))?;
        if body.bytes.len() > 32 {
            return Err(evidence_error(refused()));
        }
        body.reference
            .verify(&body.bytes)
            .map_err(|error| evidence_error(error.into()))?;
        payloads.insert(&body.reference);
        previous = Some(key);
    }
    if batch
        .payloads()
        .iter()
        .any(|body| !payloads.contains(&body.reference))
        || payloads.len() != batch.payloads().len()
    {
        return Err(evidence_error(refused()));
    }
    // Empty deliveries remain genuine original producer-closed batches only:
    // the attached scheduler's private authority/retained batch was checked by
    // authenticate_input_batch. A sampled empty native queue supplies no closure.
    Ok(())
}
