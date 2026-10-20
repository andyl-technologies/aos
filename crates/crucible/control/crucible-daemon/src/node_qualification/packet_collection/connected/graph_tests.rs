//! Tests full preparation-only source structure without issuing native readiness.
//!
//! Static program/source records are controlled fixtures. File custody tests
//! measure the actual test ELF and eight real scratch files; they never launch
//! that ELF as a packet peer or interpret it as native implementation authority.

// crucible-lint: allow panic-shortcut -- Assertions and fixture setup panics are the test oracle.
#![allow(clippy::unwrap_used)]

use crucible_engine::node_adapters::cnp::{PacketConnectedSemanticSource, PacketSemanticSource};
use crucible_engine::node_admission::{
    AdmissionEvidence, CoordinatorPolicy, ObjectState, OwnershipPolicy, QualificationClaim,
};
use crucible_engine::node_contract::HostSchedulingOwner;
use crucible_node_format::{ContentRef, Id, canonical};
use crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram;
use std::{collections::BTreeMap, rc::Rc};

use super::super::super::{PacketFixtureArtifact, PacketFixtureMeasurements};
use super::super::PacketConnectedParticipant;
use super::{
    PacketConnectedGraphOwner, PacketConnectedGraphRequest, PacketConnectedRoster, records,
};

#[path = "graph_tests/configuration.rs"]
mod configuration;
#[path = "graph_tests/definition.rs"]
mod definition;
#[path = "graph_tests/host.rs"]
mod host;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

struct Scene {
    world: configuration::World,
    roster: PacketConnectedRoster,
    measurements: PacketFixtureMeasurements,
    _directory: tempfile::TempDir,
}

impl Scene {
    fn new() -> Self {
        Self::with_distinct_peer(false)
    }

    fn with_distinct_peer(distinct: bool) -> Self {
        Self::with_effect_phases(distinct, &[1, 2])
    }

    fn with_effect_phases(distinct: bool, effect_phases: &[u16]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let host = canonical::content_ref(
            &std::fs::read(&executable).unwrap(),
            "application/octet-stream",
        )
        .unwrap();
        let (peer_path, peer_reference) = if distinct {
            // A copied ELF with inert trailing bytes distinguishes the complete
            // peer measurement from the original host ELF. It is never launched.
            let mut bytes = std::fs::read(&executable).unwrap();
            bytes.extend_from_slice(b"connected graph file-dispatch fixture");
            let path = directory.path().join("distinct-peer");
            std::fs::write(&path, &bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::metadata(&executable).unwrap().permissions())
                .unwrap();
            let reference = canonical::content_ref(&bytes, "application/octet-stream").unwrap();
            (path, reference)
        } else {
            (executable, host.clone())
        };
        let roles = [
            "adapter_source",
            "build_closure",
            "contract_source",
            "harness_source",
            "native_source",
            "program_source",
            "provider_source",
            "recipe",
        ];
        let sources = roles
            .iter()
            .map(|role| {
                let path = directory.path().join(role);
                let bytes = format!("preparation-only controlled {role} bytes");
                std::fs::write(&path, bytes.as_bytes()).unwrap();
                PacketFixtureArtifact {
                    role: (*role).into(),
                    path,
                    content: canonical::content_ref(bytes.as_bytes(), "text/plain").unwrap(),
                }
            })
            .collect();
        let measurements = PacketFixtureMeasurements {
            peer: PacketFixtureArtifact {
                role: "executable".into(),
                path: peer_path,
                content: peer_reference.clone(),
            },
            host: host.clone(),
            sources,
        };
        let proof = records::packet_connected_measured_graph_proof(&[
            measurements.clone(),
            measurements.clone(),
            measurements.clone(),
        ])
        .unwrap();
        let mut world = if effect_phases == [1, 2] {
            configuration::World::new(peer_reference, host, proof)
        } else {
            configuration::World::with_effect_phases(peer_reference, host, proof, effect_phases)
        };
        let interpretation = records::packet_connected_independent_graph_contract().unwrap();
        world.content.insert(
            canonical::content_ref(&interpretation, "application/json").unwrap(),
            interpretation,
        );
        let sources = std::array::from_fn(|member| {
            let selection = world.members[member].take().unwrap().installation;
            match &world.programmes[member] {
                PacketConnectedSourceProgram::Producer { program } => {
                    PacketConnectedParticipant::Producer(Rc::new(
                        PacketSemanticSource::new_for_collecting_connected_world(
                            selection,
                            program.clone(),
                            world.coordinator.clone(),
                        )
                        .unwrap(),
                    ))
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    PacketConnectedParticipant::Reactive(Rc::new(
                        PacketConnectedSemanticSource::new_for_collecting_world(
                            selection,
                            program.clone(),
                            world.coordinator.clone(),
                        )
                        .unwrap(),
                    ))
                }
            }
        });
        let roster = PacketConnectedRoster::new(sources, &world.coordinator).unwrap();
        assert_eq!(
            world.activation.world_binding_hash,
            world.world.identity().unwrap()
        );
        Self {
            world,
            roster,
            measurements,
            _directory: directory,
        }
    }

    fn request<'a>(
        &'a self,
        content: &'a BTreeMap<ContentRef, Vec<u8>>,
    ) -> PacketConnectedGraphRequest<'a> {
        PacketConnectedGraphRequest {
            roster: self.roster.clone(),
            host: self.world.host_source.clone(),
            measurements: [&self.measurements; 3],
            world: &self.world.world,
            requirements: &self.world.requirements,
            content,
            coordinator: &self.world.coordinator,
        }
    }
}

fn replace<T: serde::Serialize>(
    content: &mut BTreeMap<ContentRef, Vec<u8>>,
    reference: &mut ContentRef,
    value: &T,
) {
    let bytes = configuration::encoded(value);
    *reference = canonical::content_ref(&bytes, "application/json").unwrap();
    content.insert(reference.clone(), bytes);
}

#[test]
fn complete_source_structure_includes_host_roles_without_native_readiness() {
    let scene = Scene::new();
    let interpreted = records::validate(&scene.request(&scene.world.content)).unwrap();
    assert_eq!(interpreted.connections.len(), 2);
    assert_eq!(interpreted.closures.len(), 4);
    assert!(scene.world.host_source.authenticate_current().is_err());
    assert!(scene.roster.current_native().is_err());
}

#[test]
fn shared_lane_contract_admits_publication_and_delivery_at_both_endpoints() {
    let scene = Scene::new();
    records::validate(&scene.request(&scene.world.content)).unwrap();
    for source in &scene.roster.sources {
        for port in &source.installation().descriptor.ports {
            let policy: crucible_engine::node_admission::PortPolicy =
                records::decode(&scene.world.content, &port.configuration_ref).unwrap();
            assert!(policy.lanes.iter().all(|lane| lane.effect_phases == [1, 2]));
        }
    }
    assert!(scene.world.host_source.authenticate_current().is_err());
    assert!(scene.roster.current_native().is_err());
}

#[test]
fn shared_lane_contract_refuses_direction_only_and_internal_reaction_phases() {
    // Every variant is sealed before constructing the original source actors;
    // changing a current policy body cannot establish a new definition.
    for phases in [&[1][..], &[2][..], &[1, 2, 3][..]] {
        let scene = Scene::with_effect_phases(false, phases);
        assert!(records::validate(&scene.request(&scene.world.content)).is_err());
        assert!(scene.world.host_source.authenticate_current().is_err());
        assert!(scene.roster.current_native().is_err());
    }
}

#[test]
fn original_host_content_dispatch_uses_the_distinct_retained_host_file() {
    let scene = Scene::with_distinct_peer(true);
    assert_ne!(scene.measurements.peer.content, scene.measurements.host);
    assert!(!scene.world.content.contains_key(&scene.measurements.host));
    let owner = PacketConnectedGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();

    let host = policy
        .content(&scene.measurements.host, 512 * 1024 * 1024)
        .unwrap();
    let peer = policy
        .content(&scene.measurements.peer.content, 512 * 1024 * 1024)
        .unwrap();

    assert_eq!(
        host,
        std::fs::read(std::env::current_exe().unwrap()).unwrap()
    );
    assert_eq!(peer, std::fs::read(&scene.measurements.peer.path).unwrap());
    scene.measurements.host.verify(&host).unwrap();
    scene.measurements.peer.content.verify(&peer).unwrap();
    assert_ne!(host, peer);
    assert!(scene.world.host_source.authenticate_current().is_err());
    assert!(scene.roster.current_native().is_err());
}

#[test]
fn original_host_content_dispatch_refuses_credit_foreign_identity_and_owner_drop() {
    let scene = Scene::with_distinct_peer(true);
    let owner = PacketConnectedGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    let foreign = canonical::content_ref(b"foreign-host", "application/octet-stream").unwrap();

    assert!(policy.content(&scene.measurements.host, 1).is_err());
    assert!(policy.content(&foreign, 512 * 1024 * 1024).is_err());
    assert!(
        policy
            .content(&scene.measurements.host, 512 * 1024 * 1024)
            .is_ok()
    );

    drop(owner);
    assert!(
        policy
            .content(&scene.measurements.host, 512 * 1024 * 1024)
            .is_err()
    );
}

#[test]
fn actual_source_host_inventory_and_transfer_domains_are_not_interchangeable() {
    let scene = Scene::new();
    let mut inventory: OwnershipPolicy =
        records::decode(&scene.world.content, &scene.world.world.ownership_ref).unwrap();
    let connection = &scene.world.world.connections[0];
    let row = inventory
        .objects
        .iter_mut()
        .find(|row| row.id == connection.id)
        .unwrap();
    row.state = ObjectState::Mutable {
        domain_id: scene.world.host_source.domains().coordinator.clone(),
    };
    let mut world = scene.world.world.clone();
    let mut content = scene.world.content.clone();
    replace(&mut content, &mut world.ownership_ref, &inventory);
    let mut request = scene.request(&content);
    request.world = &world;
    assert!(records::validate(&request).is_err());

    // Exercise the original role helper directly too: changing only a native
    // row cannot be hidden behind a structurally complete six-domain count.
    let native = scene
        .roster
        .sources
        .iter()
        .map(|source| source.installation().owner.owner.state_domain_ids[0].clone())
        .collect();
    let host = scene.world.host_source.selection();
    inventory.objects.retain(|row| row.node_ids != [host.descriptor.id.clone()] || !matches!(&row.state, ObjectState::Mutable {domain_id} if domain_id == &scene.world.host_source.domains().coordinator));
    assert!(
        records::validate_host_core_objects(
            &inventory,
            &native,
            &host.descriptor.id,
            &host.owner.owner
        )
        .is_err()
    );
}

#[test]
fn complete_host_closure_and_compiled_schema_bytes_are_required() {
    let scene = Scene::new();
    let mut coordinator: CoordinatorPolicy = records::decode(
        &scene.world.content,
        &scene.world.world.coordinator_contract_ref,
    )
    .unwrap();
    coordinator
        .same_time_closure
        .retain(|row| row.execution_owner_id != scene.world.host_source.selection().owner.owner.id);
    let mut world = scene.world.world.clone();
    let mut content = scene.world.content.clone();
    replace(
        &mut content,
        &mut world.coordinator_contract_ref,
        &coordinator,
    );
    let mut request = scene.request(&content);
    request.world = &world;
    assert!(records::validate(&request).is_err());

    let schema = &scene.roster.sources[1].installation().receipt_schema;
    let mut content = scene.world.content.clone();
    content.remove(&schema.definition);
    assert!(records::validate(&scene.request(&content)).is_err());
}

#[test]
fn original_graph_owner_drop_revokes_retained_file_and_policy_views() {
    let scene = Scene::new();
    let owner = PacketConnectedGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    let connection = &scene.world.world.connections[0];
    let proof = records::decode::<crucible_engine::node_admission::ConnectionPolicy>(
        &scene.world.content,
        &connection.policy_ref,
    )
    .unwrap()
    .causal_proof_ref;
    let world = scene.world.world.identity().unwrap();
    assert!(
        policy
            .qualify(QualificationClaim::Connection {
                world_binding_hash: &world,
                connection_id: &connection.id,
                proof_ref: &proof
            })
            .is_ok()
    );
    drop(owner);
    assert!(
        policy
            .authenticate_schema(&scene.roster.sources[1].installation().receipt_schema)
            .is_err()
    );
    assert!(
        policy
            .content(&scene.world.world.scenario_ref, 65_536)
            .is_err()
    );
}

#[test]
fn equal_host_metadata_cannot_replace_the_original_factory_allocation() {
    let scene = Scene::new();
    let owner = PacketConnectedGraphOwner::install(scene.request(&scene.world.content)).unwrap();
    let policy = owner.graph_policy().unwrap();
    let replacement = HostSchedulingOwner::new(
        scene.world.host_source.selection().clone(),
        scene.world.world.identity().unwrap(),
    )
    .unwrap();
    let reference =
        canonical::json_hash("cnp.admission-requirements.v1", &scene.world.requirements).unwrap();
    assert_eq!(
        replacement.source().prepared_token(),
        scene.world.host_source.prepared_token()
    );
    assert!(
        policy
            .current(
                &scene.roster,
                &replacement.source(),
                &scene.world.world,
                &reference
            )
            .is_err()
    );
    drop(scene.world.host_owner);
    assert!(policy.read_current().is_err());
}

#[test]
fn complete_four_owner_coordinator_has_a_distinct_whole_object_ceiling() {
    use crucible_node_transport::reference_packet::coordinator::{
        PACKET_CONNECTED_COORDINATOR_BYTES, PacketConnectedCoordinatorInstallation,
    };
    let scene = Scene::new();
    let coordinator = &scene.world.coordinator;
    let bytes = configuration::encoded(coordinator);
    assert!(bytes.len() > 65_536);
    assert!(bytes.len() <= PACKET_CONNECTED_COORDINATOR_BYTES);
    assert_eq!(
        PacketConnectedCoordinatorInstallation::decode(&bytes, &coordinator.participants[0])
            .unwrap(),
        *coordinator
    );
    assert_eq!(
        scene.roster.sources[1].installation().maximum_result_bytes,
        65_536
    );
    assert!(scene.roster.current_native().is_err());
}

#[test]
fn oversized_four_owner_object_refuses_without_replacing_original_scope() {
    use crucible_node_transport::reference_packet::coordinator::{
        PACKET_CONNECTED_COORDINATOR_BYTES, PacketConnectedCoordinatorInstallation,
    };
    let scene = Scene::new();
    scene.roster.current_scope().unwrap();
    let original = configuration::encoded(&scene.world.coordinator);
    let mut altered = serde_json::to_value(&scene.world.coordinator).unwrap();
    altered["template"]["oversize_probe"] =
        serde_json::json!("x".repeat(PACKET_CONNECTED_COORDINATOR_BYTES));
    let bytes = canonical::canonical_json(&altered).unwrap();
    assert!(bytes.len() > PACKET_CONNECTED_COORDINATOR_BYTES);
    assert!(
        PacketConnectedCoordinatorInstallation::decode(
            &bytes,
            &scene.world.coordinator.participants[0]
        )
        .is_err()
    );
    assert_eq!(configuration::encoded(&scene.world.coordinator), original);
    scene.roster.current_scope().unwrap();
}
