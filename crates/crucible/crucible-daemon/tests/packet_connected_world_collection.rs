//! Exercises the source-bound connected collecting configuration and native caller.
//!
//! Native acceptance requires the ignored original three-child selector and its
//! explicit measured build inputs. Static construction never supplies readiness.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_engine::node_adapters::cnp::{PacketConnectedSemanticSource, PacketSemanticSource};
use crucible_node_format::{ContentRef, Id, canonical};

#[path = "packet_connected_world_collection/configuration.rs"]
mod configuration;
#[path = "packet_connected_world_collection/definition.rs"]
mod definition;
#[path = "packet_connected_world_collection/host.rs"]
mod host;
#[path = "packet_connected_world_collection/transport.rs"]
mod transport;

#[path = "packet_connected_world_collection/flight.rs"]
mod flight;
#[path = "packet_connected_world_collection/host_witness.rs"]
mod host_witness;
#[path = "packet_connected_world_collection/measurement.rs"]
mod measurement;
#[path = "packet_connected_world_collection/schedule.rs"]
mod schedule;
#[path = "packet_connected_world_collection/setup.rs"]
mod setup;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

#[test]
fn complete_connected_declarations_bind_native_three_and_host_domains() {
    // The constructor intentionally accepts these byte references only as data.
    // No native process, graph, Arm, activation or accepted class exists here.
    let executable: ContentRef =
        canonical::content_ref(b"unexecuted fixture artifact", "application/octet-stream").unwrap();
    let proof = canonical::canonical_json(
        &serde_json::json!({"schema":"unexecuted-connected-fixture-data/1"}),
    )
    .unwrap();
    let scene = configuration::World::new(executable.clone(), executable, proof);
    let [producer, relay, sink] = scene.members.unwrap();
    let [producer_program, relay_program, sink_program] = scene.programmes;
    let crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram::Producer {
        program,
    } = producer_program
    else {
        panic!("original producer declaration changed");
    };
    PacketSemanticSource::new_for_collecting_connected_world(
        producer.installation,
        program,
        scene.coordinator.clone(),
    )
    .unwrap();
    for (member, programme) in [(relay, relay_program), (sink, sink_program)] {
        let crucible_node_transport::reference_packet::service::PacketConnectedSourceProgram::Reactive { program } = programme else { panic!("original reactive declaration changed"); };
        PacketConnectedSemanticSource::new_for_collecting_world(
            member.installation,
            program,
            scene.coordinator.clone(),
        )
        .unwrap();
    }
    assert_eq!(scene.coordinator.participants.len(), 3);
    assert_eq!(scene.world.node_bindings.len(), 4);
    assert_eq!(scene.activation.owners.len(), 4);
    assert_eq!(scene.host_source.domains().connections.len(), 2);
    assert!(
        scene
            .world
            .connections
            .iter()
            .all(|connection| connection.capture_owner_id == scene.coordinator.host.owner.owner.id)
    );
}

#[test]
#[ignore = "actual connected native-three/host-one lifecycle; requires explicitly measured source-built inputs"]
fn three_original_connected_peers_preserve_full_cuts_and_source_consumed_custody() {
    flight::run();
}
