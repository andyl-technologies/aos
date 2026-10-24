//! Builds the complete positive-delay then zero-delay original collecting scene.

// crucible-lint: allow panic-shortcut -- Invalid static test fixture construction is an assertion failure.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::rc::Rc;

use crucible_engine::node_admission::*;
use crucible_engine::node_contract::{
    ActivationRecord, HostSchedulingOwner, HostSchedulingSource, OwnerIdentity,
};
use crucible_node_format::*;
use crucible_node_transport::reference_packet::{
    PacketEvent, PacketProgramDefinition,
    connected::{PacketConnectedDefinition, PacketInputConnection},
    control::PacketControlSelection,
    coordinator::{PacketConnectedCoordinatorInstallation, PacketConnectedHostSelection},
    service::PacketConnectedSourceProgram,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::{definition::Definition, host::Host, id};

pub(super) struct World {
    pub members: [Option<Definition>; 3],
    pub programmes: [PacketConnectedSourceProgram; 3],
    pub requirements: ScenarioRequirements,
    pub content: BTreeMap<ContentRef, Vec<u8>>,
    pub world: WorldBinding,
    pub activation: ActivationRecord,
    pub coordinator: PacketConnectedCoordinatorInstallation,
    // This owning handle remains outside the runtime's callback/unwind boundary.
    pub host_owner: HostSchedulingOwner,
    pub host_source: Rc<HostSchedulingSource>,
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

pub(super) fn object(content: &BTreeMap<ContentRef, Vec<u8>>, reference: &ContentRef) -> Value {
    canonical::parse_json(&content[reference], 65_536).unwrap()
}

fn endpoint(member: usize, output: bool) -> Endpoint {
    Endpoint {
        node_id: id(&format!("packet-{member}")),
        port_id: id(if output { "wire_tx" } else { "wire_rx" }),
        lane_id: id(if output { "output" } else { "input" }),
    }
}

impl World {
    pub(super) fn new(peer: ContentRef, host_executable: ContentRef, proof_bytes: Vec<u8>) -> Self {
        Self::with_effect_phases(peer, host_executable, proof_bytes, &[1, 2])
    }

    pub(super) fn with_effect_phases(
        peer: ContentRef,
        host_executable: ContentRef,
        proof_bytes: Vec<u8>,
        effect_phases: &[u16],
    ) -> Self {
        let mut content = BTreeMap::new();
        let proof = canonical::content_ref(&proof_bytes, "application/json").unwrap();
        content.insert(proof.clone(), proof_bytes.clone());
        let host = Host::new(host_executable, proof.clone());
        content.extend(host.content.clone());
        let native_routes: [PacketInputConnection; 2] = std::array::from_fn(|index| {
            let latency = u64::from(index == 0);
            let policy = ConnectionPolicy {
                schema_version: 1,
                maximum_payload_bytes: U64::new(32),
                maximum_pending_events: U64::new(1),
                maximum_pending_bytes: U64::new(32),
                visibility: VisibilityConversion::Direct,
                delivery: ConnectionDelivery::Fixed {
                    latency_ps: U64::new(latency),
                },
                causal_proof_ref: proof.clone(),
                state_domain_ids: vec![id(&format!("zz-packet-link-{index}-state"))],
            };
            PacketInputConnection {
                id: id(&format!("packet-connection-{index}")),
                policy: put(&mut content, &policy),
                producer: endpoint(index, true),
                consumer: endpoint(index + 1, false),
                delay_ps: U64::new(latency),
            }
        });
        let producer = PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: vec![
                PacketEvent {
                    id: id("private-callback-0"),
                    evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: id("packet-callback-0"),
                    evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                    payload: Some(Bytes::new(b"original-producer".to_vec())),
                },
            ],
        };
        let relay = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![native_routes[0].clone()],
            output: Some(endpoint(1, true)),
        };
        let sink = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![native_routes[1].clone()],
            output: None,
        };
        let programmes = [
            PacketConnectedSourceProgram::Producer {
                program: producer.clone(),
            },
            PacketConnectedSourceProgram::Reactive {
                program: relay.clone(),
            },
            PacketConnectedSourceProgram::Reactive {
                program: sink.clone(),
            },
        ];
        let mut members = [
            Definition::new(
                peer.clone(),
                &producer,
                0,
                proof_bytes.clone(),
                effect_phases,
            ),
            Definition::new(peer.clone(), &relay, 1, proof_bytes.clone(), effect_phases),
            Definition::new(peer, &sink, 2, proof_bytes, effect_phases),
        ];
        for member in &members {
            content.extend(member.content.clone());
        }
        let payload_schema = members[0].installation.descriptor.ports[0].lanes[0]
            .payload_schema
            .clone();
        let connections: Vec<ConnectionDescriptor> = native_routes
            .iter()
            .map(|route| ConnectionDescriptor {
                schema_version: 1,
                id: route.id.clone(),
                producer: route.producer.clone(),
                consumer: route.consumer.clone(),
                interface_id: id("source-owned.packet-octets/1"),
                features: vec![],
                payload_schema: payload_schema.clone(),
                minimum_latency_ps: route.delay_ps,
                policy_ref: route.policy.clone(),
                capture_owner_id: host.selection.owner.owner.id.clone(),
                extensions: Extensions::new(),
            })
            .collect();
        let all_nodes: Vec<Id> = members
            .iter()
            .map(|member| member.installation.descriptor.id.clone())
            .chain(std::iter::once(host.selection.descriptor.id.clone()))
            .collect();
        let requirements = ScenarioRequirements {
            accepted_nondeterministic_nodes: all_nodes.clone(),
            accepted_limited_state_nodes: all_nodes,
            ..ScenarioRequirements::default()
        };
        let mut ownership = host.ownership.clone();
        for member in &members {
            let local: OwnershipPolicy =
                serde_json::from_value(object(&content, &member.world.ownership_ref)).unwrap();
            ownership.domains.extend(local.domains);
            ownership.objects.extend(local.objects);
            ownership.capture_owners.extend(local.capture_owners);
        }
        for (index, connection) in connections.iter().enumerate() {
            let mut node_ids = vec![
                connection.producer.node_id.clone(),
                connection.consumer.node_id.clone(),
                host.selection.descriptor.id.clone(),
            ];
            node_ids.sort();
            ownership.objects.push(StateObject {
                id: connection.id.clone(),
                node_ids,
                future_affecting: true,
                state: ObjectState::Mutable {
                    domain_id: id(&format!("zz-packet-link-{index}-state")),
                },
            });
        }
        ownership.domains.sort_by(|a, b| a.id.cmp(&b.id));
        ownership.objects.sort_by(|a, b| a.id.cmp(&b.id));
        ownership
            .capture_owners
            .sort_by(|a, b| a.owner_id.cmp(&b.owner_id));
        let mut coordinator_policy = CoordinatorPolicy {
            schema_version: 1,
            state_closure_ref: proof.clone(),
            maximum_microsteps_per_instant: U64::new(16),
            same_time_closure: members
                .iter()
                .map(|member| SameTimeClosure {
                    execution_owner_id: member.installation.owner.owner.id.clone(),
                    proof_ref: proof.clone(),
                })
                .chain(std::iter::once(SameTimeClosure {
                    execution_owner_id: host.selection.owner.owner.id.clone(),
                    proof_ref: proof.clone(),
                }))
                .collect(),
            operational_policy_ref: proof.clone(),
            external_inputs: vec![],
        };
        coordinator_policy
            .same_time_closure
            .sort_by(|a, b| a.execution_owner_id.cmp(&b.execution_owner_id));
        let mut node_bindings: Vec<NodeBindingRef> = members
            .iter()
            .map(|member| member.installation.owner.node_bindings[0].clone())
            .collect();
        node_bindings.extend(host.selection.owner.node_bindings.clone());
        let models: Vec<ContentRef> = members
            .iter()
            .map(|member| member.installation.descriptor.initialization_ref.clone())
            .chain(std::iter::once(
                host.selection.descriptor.initialization_ref.clone(),
            ))
            .collect();
        let world = WorldBinding {
            schema_version: 1,
            scenario_ref: put(&mut content, &requirements),
            node_bindings,
            connections,
            ownership_ref: put(&mut content, &ownership),
            coordinator_contract_ref: put(&mut content, &coordinator_policy),
            ordering_profile: "superdense-v1".into(),
            initialization_ref: put(&mut content, &models),
            extensions: Extensions::new(),
        };
        for member in &mut members {
            member.installation.world_binding_hash = world.identity().unwrap();
        }
        let host_owner =
            HostSchedulingOwner::new(host.selection.clone(), world.identity().unwrap()).unwrap();
        let host_source = host_owner.source();
        let owners: Vec<OwnerIdentity> = members
            .iter()
            .map(|member| OwnerIdentity {
                owner: member.installation.owner.owner.id.clone(),
                incarnation: member.installation.binding.authority.incarnation_id.clone(),
                generation: member.installation.binding.authority.owner_generation,
            })
            .chain(std::iter::once(OwnerIdentity {
                owner: host.selection.owner.owner.id.clone(),
                incarnation: host.selection.binding.authority.incarnation_id.clone(),
                generation: host.selection.binding.authority.owner_generation,
            }))
            .collect();
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let activation = ActivationRecord {
            generation: U64::new(1),
            activation_id: id("packet-connected-whole-world-activation"),
            world_binding_hash: world.identity().unwrap(),
            owners: owners.clone(),
            boundary: zero,
        };
        let participants: Vec<PacketControlSelection> = members
            .iter()
            .enumerate()
            .map(|(member, data)| {
                let selected = &data.installation;
                PacketControlSelection {
                    provider: selected.provider.clone(),
                    realization: RealizationManifest {
                        schema_version: 1,
                        realization_id: selected.realize.realization_id.clone(),
                        provider_manifest: canonical::content_ref(
                            &encoded(&selected.provider),
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
            .collect();
        let mut nodes: Vec<Value> = members.iter().zip(&owners).map(|(member,owner)| {
            let selected = &member.installation;
            json!({"descriptor":selected.descriptor,"binding":selected.binding,"route":{"node":selected.descriptor.id,"owners":[owner]},
                "facets":["exact-execution"],"native_thread_custody":"owner-thread", "operating_policy":object(&content,&selected.binding.compatibility.operating_contract.policy_ref),
                "guarantees":object(&content,&selected.binding.compatibility.guarantees_ref),"effective_repeatability":Repeatability::Nondeterministic,
                "ports":selected.descriptor.ports.iter().map(|port|json!([port.id,object(&content,&port.configuration_ref)])).collect::<Vec<_>>()})
        }).collect();
        let host_initial = host_source.initial_node_record().unwrap();
        nodes.push(host_initial.clone());
        let owner_bindings: Vec<OwnerBinding> = members
            .iter()
            .map(|member| member.installation.owner.clone())
            .chain(std::iter::once(host.selection.owner.clone()))
            .collect();
        let template = json!({"schema":"crucible/coordinator-initial/1","schema_version":1,
            "activation":{"generation":activation.generation,"activation_id":activation.activation_id,"world_binding_hash":activation.world_binding_hash,"owners":owners,"boundary":zero},
            "world":world,"ownership":ownership,"coordinator":coordinator_policy,"requirements":requirements,"nodes":nodes,
            "owners":owners.iter().zip(&owner_bindings).map(|(owner,binding)|json!({"identity":owner,"lifecycle":"Prepared","operation":null,"domains":binding.owner.state_domain_ids})).collect::<Vec<_>>(),
            "owner_bindings":owner_bindings,"owner_conflicts":owners.iter().map(|owner|json!([owner.owner,[]])).collect::<Vec<_>>(),"preparations":[],
            "connections":world.connections.iter().map(|connection|json!([connection.id,object(&content,&connection.policy_ref)])).collect::<Vec<_>>(),
            "limits":{"maximum_nodes":4,"maximum_owners":4,"maximum_operations":64,"maximum_retained_outputs":3},
            "world_repeatability":Repeatability::Nondeterministic,"clock":zero,"scheduler":{"state":"not_initialized","operations":[],"inputs":[],"publications":[],"deliveries":[],"reservations":[]}});
        let coordinator = PacketConnectedCoordinatorInstallation {
            schema: "source-owned.packet-connected-coordinator-installation/4".into(),
            participants,
            host: PacketConnectedHostSelection {
                descriptor: host.selection.descriptor,
                binding: host.selection.binding,
                owner: host.selection.owner,
                prepared_token: host_source.prepared_token().clone(),
                initial_node: host_initial,
            },
            template,
        };
        for participant in &coordinator.participants {
            coordinator.validate(participant).unwrap_or_else(|error| {
                panic!(
                    "complete coordinator bytes={}, template bytes={}, local bytes={}: {error}",
                    encoded(&coordinator).len(),
                    encoded(&coordinator.template).len(),
                    encoded(participant).len()
                )
            });
        }
        Self {
            members: members.map(Some),
            programmes,
            requirements,
            content,
            world,
            activation,
            coordinator,
            host_owner,
            host_source,
        }
    }
}
