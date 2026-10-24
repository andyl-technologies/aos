//! Independently derives phased native effects from original consumed input bytes.
//!
//! This model uses the declared schedule and original input journals. It never
//! reads a common OperationOutcome or calls the native program's preview/model.

use super::*;
use crate::node_qualification::packet_collection::complete::witness::effects::{
    Effect, ReactiveEffect,
};
use crucible_node_transport::reference_packet::connected::{
    PacketConnectedDefinition, PacketDeliveredInput,
};

pub(super) fn authenticate(
    oracle: &PacketCompleteNativeOracle,
    observed: &Observed,
    member: usize,
    seal: &Seal,
    grant: &PacketConnectedGrant,
    definition: &PacketConnectedDefinition,
) -> Result<(), QualificationError> {
    let NativeBody::Reactive(record) = &seal.body else {
        return Err(refused());
    };
    let mut commits = observed
        .seals
        .iter()
        .filter(|seal| seal.member == member)
        .filter_map(|seal| match &seal.body {
            NativeBody::Commit(commit) if commit.original.sequence < record.original.sequence => {
                Some((seal, commit))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    commits.sort_by_key(|(_, commit)| commit.original.sequence);
    let mut reactions = Vec::new();
    let mut commit_refs = Vec::new();
    let mut stage_refs = Vec::new();
    for (commit_seal, commit) in commits {
        let stage = stage_for(observed, member, &commit.staged_record)?;
        if stage.cut != commit.cut
            || stage.payloads.len() != stage.deliveries.len()
            || stage.original.sequence >= commit.original.sequence
            || stage.inventory.reached != commit.reached
        {
            return Err(refused());
        }
        let request = commit.original.request_id.0.as_ref().ok_or_else(refused)?;
        let expected = stage
            .deliveries
            .iter()
            .zip(&stage.payloads)
            .map(|(delivery, payload)| {
                Ok(PacketReaction {
                    input_event: delivery.publication_id.clone(),
                    input_producer: delivery.producer.clone(),
                    input_sequence: delivery.source_sequence,
                    stage_operation: stage.cut.stage_operation_id.clone(),
                    commit_request: request.clone(),
                    payload: payload.clone(),
                    parent: delivery.delivery,
                    evaluation: Position::new(
                        delivery.delivery.time_ps,
                        delivery.delivery.microstep,
                        Phase::Reaction,
                    ),
                })
            })
            .collect::<Result<Vec<_>, QualificationError>>()?;
        if expected != commit.reactions {
            return Err(refused());
        }
        // The fixed chain preserves the complete original producer bytes at
        // every hop. A source-authenticated unrelated payload is still outside
        // this independently selected workload.
        let PacketConnectedSourceProgram::Producer { program } = &oracle.programmes[0] else {
            return Err(refused());
        };
        let payload = program.events[1].payload.as_ref().ok_or_else(refused)?;
        if expected.iter().any(|reaction| reaction.payload != *payload) {
            return Err(refused());
        }
        for reaction in &expected {
            if reactions.iter().any(|old: &PacketReaction| {
                old.input_event == reaction.input_event
                    && old.input_producer == reaction.input_producer
            }) {
                return Err(refused());
            }
        }
        reactions.extend(expected);
        commit_refs.push(commit_seal.reference.clone());
        stage_refs.push(commit.staged_record.clone());
    }
    if reactions.len() > 32
        || grant.inventory.commits != commit_refs
        || grant.inventory.stages != stage_refs
    {
        return Err(refused());
    }
    reactions.sort_by(|a, b| {
        (
            a.parent,
            &a.input_producer,
            a.input_sequence,
            &a.input_event,
        )
            .cmp(&(
                b.parent,
                &b.input_producer,
                b.input_sequence,
                &b.input_event,
            ))
    });
    let mut effects = Vec::new();
    let mut pending_reactions = Vec::new();
    let mut delivered = Vec::new();
    let mut pending_publications = Vec::new();
    let mut outputs = Vec::new();
    let mut evaluated = 0u64;
    for reaction in reactions {
        if reaction.parent < grant.limit {
            let delivery = PacketDeliveredInput {
                delivery_operation: operation_at(oracle, observed, member, reaction.parent)?,
                reaction: reaction.clone(),
            };
            effects.push((
                reaction.parent,
                ReactiveEffect::Delivery {
                    delivery: delivery.clone(),
                },
            ));
            delivered.push(delivery);
        }
        if reaction.evaluation >= grant.limit {
            pending_reactions.push(reaction);
            continue;
        }
        evaluated += 1;
        let reaction_operation = operation_at(oracle, observed, member, reaction.evaluation)?;
        effects.push((
            reaction.evaluation,
            ReactiveEffect::Reaction {
                operation: reaction_operation.clone(),
                reaction: reaction.clone(),
            },
        ));
        if definition.output.is_some() {
            let publication = Position::new(
                reaction.evaluation.time_ps,
                reaction.evaluation.microstep.checked_add(U64::new(1))?,
                Phase::Publication,
            );
            if publication.microstep.get() >= 16 {
                return Err(refused());
            }
            let pending = PacketPendingPublication {
                event: Id::new(format!("packet-reaction-{}", reaction.input_event.as_str()))?,
                reaction: reaction.clone(),
                reaction_operation,
                publication,
            };
            if publication >= grant.limit {
                pending_publications.push(pending);
            } else {
                let operation = operation_at(oracle, observed, member, publication)?;
                outputs.push(PacketConnectedPublication {
                    output: PacketPublication {
                        event: pending.event.clone(),
                        operation,
                        sequence: U64::new(0),
                        evaluation: reaction.evaluation,
                        publication,
                        payload: reaction.payload.clone(),
                    },
                    pending,
                });
            }
        }
    }
    outputs.sort_by(|a, b| {
        (a.output.publication, &a.output.event).cmp(&(b.output.publication, &b.output.event))
    });
    for (index, output) in outputs.iter_mut().enumerate() {
        output.output.sequence = U64::new(index as u64 + 1);
        effects.push((
            output.output.publication,
            ReactiveEffect::Publication {
                publication: output.clone(),
            },
        ));
    }
    effects.sort_by_key(|effect| effect.0);
    let actual = &observed.effects[member];
    if effects.len() > actual.len()
        || !effects.iter().zip(actual).all(
            |((_, expected), actual)| matches!(actual,Effect::Reactive(actual) if actual==expected),
        )
    {
        return Err(QualificationError::Refused(
            "original phased effects differ from independent input/cut model",
        ));
    }
    let newborn: Vec<_> = outputs
        .iter()
        .filter(|row| row.output.publication >= grant.start)
        .cloned()
        .collect();
    pending_publications.sort_by(|a, b| (a.publication, &a.event).cmp(&(b.publication, &b.event)));
    if !grant.complete
        || grant.inventory.reached != grant.limit
        || grant.inventory.gate_closed
        || grant.inventory.reactions != pending_reactions
        || grant.inventory.delivered_inputs != delivered
        || grant.inventory.publications != pending_publications
        || grant.inventory.retained_outputs != newborn
        || grant.newborn != newborn
        || grant.inventory.reactions_completed != U64::new(evaluated)
        || grant.inventory.packet_effects != U64::new(outputs.len() as u64)
    {
        return Err(QualificationError::Refused(
            "original phased inventory differs from independent input/cut model",
        ));
    }
    Ok(())
}

fn operation_at(
    oracle: &PacketCompleteNativeOracle,
    observed: &Observed,
    member: usize,
    position: Position,
) -> Result<Id, QualificationError> {
    let node = &oracle.schedule.nodes[member];
    let mut candidates = oracle
        .schedule
        .grants
        .iter()
        .filter(|grant| &grant.node == node)
        .filter(|grant| {
            interval(&grant.request)
                .is_ok_and(|(start, limit)| start <= position && position < limit)
        });
    let grant = candidates.next().ok_or_else(refused)?;
    if candidates.next().is_some() {
        return Err(refused());
    }
    let (start, limit) = interval(&grant.request)?;
    oracle.completion_seal(observed, member, grant, start, limit)?;
    Ok(grant.operation.clone())
}
