//! Builds the current four-node initial state before any derived commitment.
//!
//! Every operational Host correlation comes from the same original local owner.
//! Logical declarations/content remain independently validated by the unchanged
//! coordinator, Source and complete graph validators after construction.

use super::*;
use crucible_engine::node_contract::OwnerIdentity;
use crucible_node_transport::reference_packet::{
    control::PacketControlSelection, coordinator::PacketConnectedHostSelection,
};
use serde::Serialize;
use serde_json::{Value, json};

pub(super) fn build(
    configuration: &Configuration,
    host_owner: &HostSchedulingOwner,
) -> Result<PacketNative5CoordinatorInstallation, QualificationError> {
    let host = host_owner.source();
    let world_hash = configuration.world.identity()?;
    if host.world() != &world_hash || host.selection() != &configuration.host {
        return Err(refused());
    }
    let mut participants = Vec::with_capacity(3);
    let mut nodes = Vec::with_capacity(4);
    let mut owners = Vec::with_capacity(4);
    let mut owner_bindings = Vec::with_capacity(4);
    for (participant, token) in configuration
        .participants
        .iter()
        .zip(&configuration.initial.native_prepared_tokens)
    {
        let selected = &participant.installation;
        let owner = OwnerIdentity {
            owner: selected.owner.owner.id.clone(),
            incarnation: selected.binding.authority.incarnation_id.clone(),
            generation: selected.binding.authority.owner_generation,
        };
        let provider_bytes = encoded(&selected.provider)?;
        participants.push(PacketControlSelection {
            provider: selected.provider.clone(),
            realization: RealizationManifest {
                schema_version: 1,
                realization_id: selected.realize.realization_id.clone(),
                provider_manifest: canonical::content_ref(&provider_bytes, "application/json")?,
                descriptors: vec![selected.descriptor.clone()],
                bindings: vec![selected.binding.clone()],
                owners: vec![selected.owner.owner.clone()],
                owner_bindings: vec![selected.owner.clone()],
                extensions: Extensions::new(),
            },
            realize: selected.realize.clone(),
            prepared_token: token.clone(),
            admission: selected.admission.clone(),
            transaction: selected.transaction.clone(),
            gate: selected.gate.clone(),
            world: selected.world_binding_hash.clone(),
            admission_receipt: selected.admission_receipt.clone(),
        });
        let mut ports = Vec::with_capacity(selected.descriptor.ports.len());
        for port in &selected.descriptor.ports {
            ports.push(json!([
                port.id,
                configuration.object(&port.configuration_ref)?
            ]));
        }
        nodes.push(json!({
            "descriptor": selected.descriptor,
            "binding": selected.binding,
            "route": {"node": selected.descriptor.id, "owners": [&owner]},
            "facets": ["exact-execution", "preservation"],
            "native_thread_custody": "owner-thread",
            "operating_policy": configuration.object(&selected.binding.compatibility.operating_contract.policy_ref)?,
            "guarantees": configuration.object(&selected.binding.compatibility.guarantees_ref)?,
            "effective_repeatability": Repeatability::Nondeterministic,
            "ports": ports,
        }));
        owners.push(owner);
        owner_bindings.push(selected.owner.clone());
    }
    owners.push(OwnerIdentity {
        owner: configuration.host.owner.owner.id.clone(),
        incarnation: configuration.host.binding.authority.incarnation_id.clone(),
        generation: configuration.host.binding.authority.owner_generation,
    });
    owner_bindings.push(configuration.host.owner.clone());
    let host_initial = host.initial_node_record().map_err(|_| refused())?;
    nodes.push(host_initial.clone());

    let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    let mut connections = Vec::with_capacity(configuration.world.connections.len());
    for connection in &configuration.world.connections {
        connections.push(json!([
            connection.id,
            configuration.object(&connection.policy_ref)?
        ]));
    }
    let template = json!({
        "schema": "crucible/coordinator-initial/1", "schema_version": 1,
        "activation": {
            "generation": configuration.initial.generation,
            "activation_id": configuration.initial.activation_id,
            "world_binding_hash": world_hash, "owners": owners, "boundary": zero,
        },
        "world": configuration.world,
        "ownership": configuration.object(&configuration.world.ownership_ref)?,
        "coordinator": configuration.object(&configuration.world.coordinator_contract_ref)?,
        "requirements": configuration.requirements, "nodes": nodes,
        "owners": owners.iter().zip(&owner_bindings).map(|(owner, binding)| json!({
            "identity": owner, "lifecycle": "Prepared", "operation": null,
            "domains": binding.owner.state_domain_ids,
        })).collect::<Vec<_>>(),
        "owner_bindings": owner_bindings,
        "owner_conflicts": owners.iter().map(|owner| json!([owner.owner, []])).collect::<Vec<_>>(),
        "preparations": [], "connections": connections,
        "limits": {"maximum_nodes": 4, "maximum_owners": 4,
            "maximum_operations": configuration.maximum_operations, "maximum_retained_outputs": 3},
        "world_repeatability": Repeatability::Nondeterministic, "clock": zero,
        "scheduler": {"state": "not_initialized", "operations": [], "inputs": [],
            "publications": [], "deliveries": [], "reservations": []},
    });
    let coordinator = PacketNative5CoordinatorInstallation {
        schema: "source-owned.packet-complete-coordinator-installation/5".into(),
        participants,
        host: PacketConnectedHostSelection {
            descriptor: configuration.host.descriptor.clone(),
            binding: configuration.host.binding.clone(),
            owner: configuration.host.owner.clone(),
            prepared_token: host.prepared_token().clone(),
            initial_node: host_initial,
        },
        template,
    };
    for participant in &coordinator.participants {
        coordinator.validate(participant).map_err(|_| refused())?;
    }
    Ok(coordinator)
}

fn encoded(value: &impl Serialize) -> Result<Vec<u8>, QualificationError> {
    let value: Value = serde_json::to_value(value).map_err(ContractError::from)?;
    Ok(canonical::canonical_json(&value)?)
}
