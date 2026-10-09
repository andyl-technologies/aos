//! Validates bounded original Root preparation, permission and observation lineage.
//!
//! These checks consume signed historical bodies only. They never construct a
//! current native certificate, public preparation or scheduler permission.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, Id};
use serde::Deserialize;

use crate::{node_contract::*, node_scheduling::InputPayload};

use super::{
    capture::RootWire,
    continuation::{parse, validate_native_origin, validate_preparation_bodies},
    refusal,
};

pub(super) fn decode_ancestry(
    current: &RootWire,
    evidence: &BTreeMap<ContentRef, InputPayload>,
) -> Result<Vec<RootWire>, OperationFailure> {
    let mut ancestry = Vec::new();
    ancestry
        .try_reserve_exact(8)
        .map_err(|_| refusal("ARM ancestry slots are unavailable"))?;
    let mut seen = BTreeSet::new();
    let mut next = current.previous.as_ref();
    while let Some(reference) = next {
        if ancestry.len() >= 7 || !seen.insert(reference.clone()) {
            return Err(refusal(
                "ARM preparation ancestry repeats or exceeds its selected depth",
            ));
        }
        let body = evidence
            .get(reference)
            .ok_or_else(|| refusal("ARM exact previous preparation envelope is absent"))?;
        let previous: RootWire = parse(&body.bytes)?;
        if reference.media_type != "application/json"
            || super::encoding::record(&previous, 16 * 1024 * 1024)? != body.bytes
        {
            return Err(refusal(
                "ARM prior preparation envelope is not exact canonical source bytes",
            ));
        }
        ancestry.push(previous);
        next = ancestry.last().and_then(|wire| wire.previous.as_ref());
    }
    Ok(ancestry)
}

pub(super) fn validate_ancestry(
    current: &RootWire,
    ancestry: &[RootWire],
    evidence: &BTreeMap<ContentRef, InputPayload>,
    node: &Id,
) -> Result<(), OperationFailure> {
    let mut newer = current;
    for (index, older) in ancestry.iter().enumerate() {
        if older.format != current.format
            || older.schema_version != 2
            || older.node != *node
            || older.owners.len() != 1
            || older.source.owner != older.owners[0].owner
            || older.source.incarnation != older.owners[0].incarnation
            || older.source.generation != older.owners[0].generation
            || older.source.model_id != current.source.model_id
            || older.source.native_dialect != current.source.native_dialect
            || older.source.profile != current.source.profile
            || older.source.bindings != current.source.bindings
            || older.maximum_microsteps != current.maximum_microsteps
            || older.maximum_events_per_poll != current.maximum_events_per_poll
            || older.operations.len() > 4096
            || older.packets.len() > 4096
            || older.sessions.len() > 256
            || older.native_outcomes.len() > 512
            || older.observations.len() > 8192
            || older.artifacts.len() > 8192
            || older.source_activation.world_binding_hash
                != newer.source_activation.world_binding_hash
            || older.source_activation.activation_id == newer.source_activation.activation_id
            || older.source_activation.generation >= newer.source_activation.generation
            || older.common_cut > newer.common_cut
            || older.native_boundary.logical_position > newer.native_boundary.logical_position
            || older.output_sequence > newer.output_sequence
            || older.source.owner != newer.source.owner
            || older.source.incarnation == newer.source.incarnation
            || older.source.generation >= newer.source.generation
            || !newer.native_outcomes.starts_with(&older.native_outcomes)
            || older.source_activation.owners.len() != newer.source_activation.owners.len()
            || older
                .source_activation
                .owners
                .iter()
                .zip(&newer.source_activation.owners)
                .any(|(old, fresh)| {
                    old.owner != fresh.owner
                        || old.incarnation == fresh.incarnation
                        || old.generation >= fresh.generation
                })
        {
            return Err(refusal(
                "ARM prior preparation differs from exact selected owner/model/permission lineage",
            ));
        }
        validate_preparation_bodies(older, evidence, node)?;
        if newer.packets.len() < older.packets.len()
            || newer
                .packets
                .iter()
                .zip(&older.packets)
                .any(|(new, old)| new.kind != old.kind || new.body != old.body)
            || newer.sessions.len() < older.sessions.len()
            || newer
                .sessions
                .iter()
                .zip(&older.sessions)
                .any(|(new, old)| {
                    new.token != old.token
                        || new.packet != old.packet
                        || new.transcript != old.transcript
                })
            || !newer.observations.starts_with(&older.observations)
        {
            return Err(refusal(
                "ARM recapture lost exact ordered original control/session bodies",
            ));
        }
        validate_native_origin(newer, evidence, Some(&older.capture))?;
        validate_prefix_ancestry(older, &ancestry[index + 1..])?;
        newer = older;
    }
    validate_native_origin(newer, evidence, None)?;
    if newer.previous.is_some() {
        return Err(refusal(
            "ARM preparation ancestry has no genuine original construction",
        ));
    }
    Ok(())
}

pub(super) fn validate_prefix_ancestry(
    wire: &RootWire,
    ancestors: &[RootWire],
) -> Result<(), OperationFailure> {
    let mut operations = BTreeSet::new();
    for operation in &wire.operations {
        if !operations.insert(&operation.original.operation)
            || operation.original.route.node != wire.node
            || operation.original.route.owners != wire.owners
            || operation.original.input_batch.is_some()
        {
            return Err(refusal(
                "ARM original permission has repeated or foreign owner custody",
            ));
        }
        for prefix in &operation.prefixes {
            let current = prefix.route == operation.original.route
                && prefix.activation == wire.source_activation;
            let historical = ancestors.iter().any(|old| {
                old.operations.iter().any(|saved| {
                    saved.original.operation == operation.original.operation
                        && saved.original.request == operation.original.request
                        && saved.original.input_batch == operation.original.input_batch
                        && saved.prefixes.iter().any(|prior| {
                            prior.body == prefix.body
                                && prior.route == prefix.route
                                && prior.activation == prefix.activation
                        })
                })
            });
            if (!current && !historical) || !wire.native_outcomes.contains(&prefix.body) {
                return Err(refusal(
                    "ARM native prefix lacks its exact original common permission ancestry",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalObservation {
    schema: String,
    boundary: crucible_node_provider::gem5::Gem5Boundary,
    closure: ContentRef,
    owners: Vec<OwnerIdentity>,
    activation: SavedRuntimeActivation,
}

pub(super) fn validate_observation_roster(
    current: &RootWire,
    ancestors: &[RootWire],
    evidence: &BTreeMap<ContentRef, InputPayload>,
) -> Result<(), OperationFailure> {
    let mut seen = BTreeSet::new();
    for reference in &current.observations {
        if !seen.insert(reference) {
            return Err(refusal("ARM original stopped-observation role repeats"));
        }
        let bytes = &evidence
            .get(reference)
            .ok_or_else(|| refusal("ARM original stopped observation is absent"))?
            .bytes;
        let observation: OriginalObservation = parse(bytes)?;
        if observation.schema != "crucible.gem5.arm-root-observation.v1"
            || !evidence.contains_key(&observation.closure)
            || !std::iter::once(current).chain(ancestors).any(|scope| {
                observation.owners == scope.owners
                    && observation.activation == scope.source_activation
                    && observation.boundary.logical_position
                        <= scope.native_boundary.logical_position
            })
        {
            return Err(refusal(
                "ARM stopped observation differs from its signed original native scope",
            ));
        }
    }
    Ok(())
}
