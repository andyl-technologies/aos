//! Builds one complete three-owner static world without predicting Ready.

use std::collections::BTreeMap;

use crucible_daemon::node_qualification::packet_world_independent_graph_contract;
use crucible_engine::node_admission::{CoordinatorPolicy, OwnershipPolicy, ScenarioRequirements};
use crucible_engine::node_contract::{ActivationRecord, OwnerIdentity};
use crucible_node_format::*;
use crucible_node_transport::{
    reference_packet::{
        PacketEvent, PacketProgramDefinition, control::PacketControlSelection,
        coordinator::PacketWorldCoordinatorInstallation,
    },
    reference_service::InstalledContent,
};
use serde::Serialize;
use serde_json::json;

use super::{definition::Definition, id};

pub(super) struct World {
    pub members: [Definition; 3],
    pub programmes: [PacketProgramDefinition; 3],
    pub requirements: ScenarioRequirements,
    pub content: BTreeMap<ContentRef, Vec<u8>>,
    pub world: WorldBinding,
    pub activation: ActivationRecord,
    pub coordinator: PacketWorldCoordinatorInstallation,
}

pub(super) fn encoded(value: &impl Serialize) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap()
}

fn put(content: &mut BTreeMap<ContentRef, Vec<u8>>, value: &impl Serialize) -> ContentRef {
    let bytes = encoded(value);
    let reference = canonical::content_ref(&bytes, "application/json").unwrap();
    content.insert(reference.clone(), bytes);
    reference
}

pub(super) fn object(
    content: &BTreeMap<ContentRef, Vec<u8>>,
    reference: &ContentRef,
) -> serde_json::Value {
    canonical::parse_json(&content[reference], 65_536).unwrap()
}

impl World {
    pub(super) fn new(executable: ContentRef) -> Self {
        let programmes = std::array::from_fn(|member| PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: vec![
                PacketEvent {
                    id: id(&format!("private-callback-{member}")),
                    evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: id(&format!("packet-callback-{member}")),
                    evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                    payload: Some(Bytes::new(format!("original-peer-{member}").into_bytes())),
                },
            ],
        });
        let mut members = std::array::from_fn(|member| {
            Definition::new(executable.clone(), &programmes[member], member)
        });
        let mut content = BTreeMap::new();
        for member in &members {
            content.extend(member.content.clone());
        }
        let proof_bytes = packet_world_independent_graph_contract().unwrap();
        let proof = canonical::content_ref(&proof_bytes, "application/json").unwrap();
        content.insert(proof.clone(), proof_bytes);
        let requirements = ScenarioRequirements {
            accepted_nondeterministic_nodes: members
                .iter()
                .map(|m| m.installation.descriptor.id.clone())
                .collect(),
            accepted_limited_state_nodes: members
                .iter()
                .map(|m| m.installation.descriptor.id.clone())
                .collect(),
            ..ScenarioRequirements::default()
        };
        let mut ownership = OwnershipPolicy {
            schema_version: 1,
            domains: vec![],
            objects: vec![],
            internal_dependencies: vec![],
            capture_owners: vec![],
            inventory_proof_ref: proof.clone(),
        };
        for member in &members {
            let local: OwnershipPolicy =
                serde_json::from_value(object(&content, &member.world.ownership_ref)).unwrap();
            ownership.domains.extend(local.domains);
            ownership.objects.extend(local.objects);
            ownership.capture_owners.extend(local.capture_owners);
        }
        let coordinator_policy = CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: proof.clone(),
            maximum_microsteps_per_instant: U64::new(1024),
            same_time_closure: vec![],
            operational_policy_ref: proof,
            external_inputs: vec![],
        };
        let models = members
            .iter()
            .map(|m| m.installation.descriptor.initialization_ref.clone())
            .collect::<Vec<_>>();
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref: put(&mut content, &requirements),
            node_bindings: members
                .iter()
                .map(|m| m.installation.owner.node_bindings[0].clone())
                .collect(),
            connections: vec![],
            ownership_ref: put(&mut content, &ownership),
            coordinator_contract_ref: put(&mut content, &coordinator_policy),
            ordering_profile: "superdense-v1".into(),
            initialization_ref: put(&mut content, &models),
            extensions: Extensions::new(),
        };
        for member in &mut members {
            member.installation.world_binding_hash = world.identity().unwrap();
        }
        let owners = members
            .iter()
            .map(|m| OwnerIdentity {
                owner: m.installation.owner.owner.id.clone(),
                incarnation: m.installation.binding.authority.incarnation_id.clone(),
                generation: m.installation.binding.authority.owner_generation,
            })
            .collect::<Vec<_>>();
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let activation = ActivationRecord {
            generation: U64::new(1),
            activation_id: id("packet-whole-world-activation"),
            world_binding_hash: world.identity().unwrap(),
            owners: owners.clone(),
            boundary: zero,
        };
        let participants = members
            .iter()
            .enumerate()
            .map(|(member, data)| {
                let selected = &data.installation;
                let provider_bytes = encoded(&selected.provider);
                PacketControlSelection {
                    provider: selected.provider.clone(),
                    realization: RealizationManifest {
                        schema_version: 1,
                        realization_id: selected.realize.realization_id.clone(),
                        provider_manifest: canonical::content_ref(
                            &provider_bytes,
                            "application/json",
                        )
                        .unwrap(),
                        descriptors: vec![selected.descriptor.clone()],
                        bindings: vec![selected.binding.clone()],
                        owners: vec![selected.owner.owner.clone()],
                        owner_bindings: vec![selected.owner.clone()],
                        extensions: Extensions::new(),
                    },
                    realize: selected.realize.clone(),
                    prepared_token: id(&format!("packet-native-prepared-{member}")),
                    admission: selected.admission.clone(),
                    transaction: selected.transaction.clone(),
                    gate: selected.gate.clone(),
                    world: selected.world_binding_hash.clone(),
                    admission_receipt: selected.admission_receipt.clone(),
                }
            })
            .collect::<Vec<_>>();
        let nodes = members.iter().zip(&owners).map(|(member, owner)| {
            let selected = &member.installation;
            let binding = &selected.binding;
            json!({
                "descriptor":selected.descriptor,"binding":binding,
                "route":{"node":selected.descriptor.id,"owners":[owner]},
                "facets":["exact-execution"],"native_thread_custody":"owner-thread",
                "operating_policy":object(&content,&binding.compatibility.operating_contract.policy_ref),
                "guarantees":object(&content,&binding.compatibility.guarantees_ref),
                "effective_repeatability":Repeatability::Nondeterministic,
                "ports":[[selected.descriptor.ports[0].id,object(&content,&selected.descriptor.ports[0].configuration_ref)]]
            })
        }).collect::<Vec<_>>();
        let template = json!({
            "schema":"crucible/coordinator-initial/1","schema_version":1,
            "activation":{"generation":activation.generation,"activation_id":activation.activation_id,
                "world_binding_hash":activation.world_binding_hash,"owners":owners,"boundary":zero},
            "world":world,"ownership":ownership,"coordinator":coordinator_policy,"requirements":requirements,
            "nodes":nodes,
            "owners":owners.iter().zip(&members).map(|(owner,member)|json!({
                "identity":owner,"lifecycle":"Prepared","operation":null,"domains":member.installation.owner.owner.state_domain_ids
            })).collect::<Vec<_>>(),
            "owner_bindings":members.iter().map(|m|&m.installation.owner).collect::<Vec<_>>(),
            "owner_conflicts":owners.iter().map(|owner|json!([owner.owner,[]])).collect::<Vec<_>>(),
            "preparations":[],"connections":[],
            "limits":{"maximum_nodes":3,"maximum_owners":3,"maximum_operations":27,"maximum_retained_outputs":3},
            "world_repeatability":Repeatability::Nondeterministic,"clock":zero,
            "scheduler":{"state":"not_initialized","operations":[],"inputs":[],"publications":[],"deliveries":[],"reservations":[]}
        });
        let coordinator = PacketWorldCoordinatorInstallation {
            schema: "source-owned.packet-common-coordinator-installation/2".into(),
            participants,
            template,
        };
        for participant in &coordinator.participants {
            coordinator.validate(participant).unwrap();
        }
        Self {
            members,
            programmes,
            requirements,
            content,
            world,
            activation,
            coordinator,
        }
    }

    pub(super) fn initial_coordinator(&self) -> InstalledContent {
        let bytes = encoded(&self.coordinator);
        InstalledContent {
            reference: canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes: Bytes::new(bytes),
        }
    }
}
