//! Validates the same opaque scheduler batch's complete fixed-chain coordinates.
//!
//! The Host2 owner authenticates the original batch before this borrowed check.
//! These field checks grant no batch/activation authority and make no body copy.

use crucible_engine::{node_adapters::cnp::CnpSemanticSource, node_scheduling::RuntimeInputBatch};
use crucible_node_format::{ContentRef, Phase, Position, U64};

use super::super::{InstalledPacketCompleteCollectionAuthority, QualificationError, refused};

pub(super) fn authenticate(
    authority: &InstalledPacketCompleteCollectionAuthority,
    batch: &RuntimeInputBatch,
) -> Result<(), QualificationError> {
    let activation = batch.activation().record();
    if activation.world_binding_hash != *authority.host_source().world()
        || activation.owners.len() != 4
        || batch.deliveries().len() > 4
        || batch.payloads().len() > 4
    {
        return Err(refused());
    }
    for source in &authority.roster().sources {
        let selected = source.installation();
        if activation
            .owners
            .iter()
            .filter(|original| {
                original.owner == selected.owner.owner.id
                    && original.incarnation == selected.binding.authority.incarnation_id
                    && original.generation == selected.binding.authority.owner_generation
            })
            .count()
            != 1
        {
            return Err(refused());
        }
    }
    let host = authority.host_source().selection();
    if activation
        .owners
        .iter()
        .filter(|original| {
            original.owner == host.owner.owner.id
                && original.incarnation == host.binding.authority.incarnation_id
                && original.generation == host.binding.authority.owner_generation
        })
        .count()
        != 1
    {
        return Err(refused());
    }
    let member = authority
        .roster()
        .sources
        .iter()
        .position(|source| &source.installation().descriptor.id == batch.node())
        .ok_or_else(refused)?;
    if member == 0 {
        return Err(refused());
    }
    let selected = authority.roster().sources[member].installation();
    let [original] = batch.owners() else {
        return Err(refused());
    };
    if original.owner != selected.owner.owner.id
        || original.incarnation != selected.binding.authority.incarnation_id
        || original.generation != selected.binding.authority.owner_generation
    {
        return Err(refused());
    }

    let mut previous = None;
    let mut payloads: [Option<&ContentRef>; 4] = [None; 4];
    let mut distinct = 0;
    for delivery in batch.deliveries() {
        let connection = authority
            .world()
            .connections
            .iter()
            .find(|connection| delivery.connection_id.as_ref() == Some(&connection.id))
            .ok_or_else(refused)?;
        let arrival = delivery
            .publication
            .time_ps
            .checked_add(connection.minimum_latency_ps)?;
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
            return Err(refused());
        }
        let body = batch
            .payloads()
            .iter()
            .find(|body| body.reference == delivery.payload)
            .ok_or_else(refused)?;
        if body.bytes.len() > 32 {
            return Err(refused());
        }
        body.reference.verify(&body.bytes)?;
        if !payloads[..distinct].contains(&Some(&body.reference)) {
            *payloads.get_mut(distinct).ok_or_else(refused)? = Some(&body.reference);
            distinct += 1;
        }
        previous = Some(key);
    }
    if distinct != batch.payloads().len()
        || batch
            .payloads()
            .iter()
            .any(|body| !payloads[..distinct].contains(&Some(&body.reference)))
    {
        return Err(refused());
    }
    // Empty batches still passed the same source-owned scheduler occurrence
    // check. An empty native queue cannot establish producer frontier closure.
    Ok(())
}
