//! Precredits original preparation bodies through borrowed serialization views.
//!
//! The count covers the exact serialized records before owner copies or a JSON
//! value tree are retained. Already owned native initialization is borrowed;
//! neither these views nor the counter clone the graph or activation roster.

use super::*;
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::io::{self, Write};

#[derive(Serialize)]
struct Session<'a, T> {
    format: &'static str,
    version: u16,
    world_hash: &'a crucible_node_contract::HashRef,
    node: &'a Id,
    owners: &'a [OwnerIdentity],
    binding: &'a crucible_node_contract::HashRef,
    initialization: &'a ContentRef,
    initial_native_state: &'a ContentRef,
    original_native_ready: &'a ContentRef,
    complete_original_owners: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_preparation: Option<&'a ContentRef>,
}

#[derive(Serialize)]
struct BorrowedOwner<'a> {
    owner: &'a Id,
    incarnation: &'a Id,
    generation: crucible_node_contract::U64,
}

struct GraphOwners<'a>(&'a AdmittedGraph);

impl Serialize for GraphOwners<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.node_ids().count()))?;
        for node in self.0.node_ids() {
            let binding = self
                .0
                .binding(node)
                .ok_or_else(|| serde::ser::Error::custom("original graph owner is absent"))?;
            sequence.serialize_element(&BorrowedOwner {
                owner: &binding.compatibility.execution_owner.id,
                incarnation: &binding.authority.incarnation_id,
                generation: binding.authority.owner_generation,
            })?;
        }
        sequence.end()
    }
}

fn session<'a, T>(
    node: &'a HostModelNode,
    initial: &'a ContentRef,
    native_ready: &'a ContentRef,
    binding: &'a crucible_node_contract::HashRef,
    owners: T,
) -> Session<'a, T> {
    Session {
        format: if node.public_model_history.is_some() {
            "crucible.host.restored-owned-model-session"
        } else {
            "crucible.host.original-owned-model-session"
        },
        version: 1,
        world_hash: &node.world_hash,
        node: &node.route.node,
        owners: &node.route.owners,
        binding,
        initialization: &node.descriptor.initialization_ref,
        initial_native_state: initial,
        original_native_ready: native_ready,
        complete_original_owners: owners,
        source_preparation: node
            .public_model_history
            .as_ref()
            .map(|history| &history.original.reference),
    }
}

/// Counts the original session through borrowed graph owners before copying them.
pub(super) fn session_length(
    node: &HostModelNode,
    graph: &AdmittedGraph,
    initial: &ContentRef,
    native_ready: &ContentRef,
    binding: &crucible_node_contract::HashRef,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    length(
        &session(node, initial, native_ready, binding, GraphOwners(graph)),
        maximum,
    )
}

/// Encodes an already precredited original session without changing its grammar.
pub(super) fn encode_session(
    node: &HostModelNode,
    preparation: (&ContentRef, &ContentRef, &crucible_node_contract::HashRef),
    owners: &[OwnerIdentity],
) -> Result<Vec<u8>, OperationFailure> {
    let (initial, native_ready, binding) = preparation;
    encode(&session(node, initial, native_ready, binding, owners))
}

/// Counts a fresh restored session against its original target roster.
pub(super) fn restored_session_length(
    node: &HostModelNode,
    initial: &ContentRef,
    native_ready: &ContentRef,
    binding: &crucible_node_contract::HashRef,
    owners: &[OwnerIdentity],
    maximum: usize,
) -> Result<usize, OperationFailure> {
    length(
        &session(node, initial, native_ready, binding, owners),
        maximum,
    )
}

#[derive(Serialize)]
struct ReadyWorld<'a> {
    generation: crucible_node_contract::U64,
    activation_id: &'a Id,
    world_binding_hash: &'a crucible_node_contract::HashRef,
    owners: &'a [OwnerIdentity],
    boundary: Position,
}

#[derive(Serialize)]
struct ReadyBody<'a> {
    format: &'static str,
    version: u16,
    world: ReadyWorld<'a>,
    session: &'a ContentRef,
    initial_native_state: &'a ContentRef,
    original_native_ready: &'a ContentRef,
    inventory: &'a ContentRef,
    boundary: Position,
    owners: &'a [OwnerIdentity],
}

fn ready_body<'a>(
    world: &'a ActivationRecord,
    ready: &'a ReadyAttestation,
    preparation: &'a OriginalOwnedModelPreparation,
) -> ReadyBody<'a> {
    ReadyBody {
        format: "crucible.host.public-owned-model-ready",
        version: 1,
        world: ReadyWorld {
            generation: world.generation,
            activation_id: &world.activation_id,
            world_binding_hash: &world.world_binding_hash,
            owners: &world.owners,
            boundary: world.boundary,
        },
        session: &preparation.session,
        initial_native_state: &preparation.initial_native,
        original_native_ready: &preparation.native_ready,
        inventory: &ready.state_inventory,
        boundary: ready.boundary,
        owners: &ready.owners,
    }
}

/// Counts original readiness without cloning the complete activation or receipt.
pub(super) fn ready_length(
    world: &ActivationRecord,
    ready: &ReadyAttestation,
    preparation: &OriginalOwnedModelPreparation,
    maximum: usize,
) -> Result<usize, OperationFailure> {
    length(&ready_body(world, ready, preparation), maximum)
}

/// Encodes already precredited original readiness using the same closed fields.
pub(super) fn encode_ready(
    world: &ActivationRecord,
    ready: &ReadyAttestation,
    preparation: &OriginalOwnedModelPreparation,
) -> Result<Vec<u8>, OperationFailure> {
    encode(&ready_body(world, ready, preparation))
}

/// Bounds the original fixed native receipt before retaining its byte vector.
pub(super) fn native_ready_length(node: &HostModelNode) -> Result<usize, OperationFailure> {
    node.route
        .owners
        .iter()
        .try_fold("host-model-owned-inactive-v1".len() + 8, |total, owner| {
            total
                .checked_add(owner.owner.as_str().len())
                .and_then(|total| total.checked_add(1))
                .and_then(|total| total.checked_add(owner.incarnation.as_str().len()))
                .and_then(|total| total.checked_add(8))
                .ok_or_else(|| failure("original native readiness geometry overflow"))
        })
}

struct Counter {
    remaining: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("original preparation serialized budget exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn length(value: &impl Serialize, maximum: usize) -> Result<usize, OperationFailure> {
    let mut counter = Counter { remaining: maximum };
    serde_json::to_writer(&mut counter, value).map_err(|error| failure(&error.to_string()))?;
    Ok(maximum - counter.remaining)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, OperationFailure> {
    let value = serde_json::to_value(value).map_err(|error| failure(&error.to_string()))?;
    canonical::canonical_json(&value).map_err(|error| failure(&error.to_string()))
}
