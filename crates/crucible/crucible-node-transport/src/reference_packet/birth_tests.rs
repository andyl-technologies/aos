//! Checks original socket retention at native actor construction boundaries.

// crucible-lint: allow panic-shortcut -- Assertion failure is the data-control verdict.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::reference_packet::connected::{
    PacketConnectedDefinition, PacketConnectedProgram, PacketInputConnection,
};
use crucible_node_format::{Endpoint, canonical};
use std::os::fd::AsRawFd;

fn events() -> Vec<PacketEvent> {
    vec![PacketEvent {
        id: Id::new("original-private-event").unwrap(),
        evaluation: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
        completion: Position::new(U64::new(1), U64::new(0), Phase::Reaction),
        payload: None,
    }]
}

fn definition() -> PacketConnectedDefinition {
    let endpoint = |node: &str| Endpoint {
        node_id: Id::new(node).unwrap(),
        port_id: Id::new("port").unwrap(),
        lane_id: Id::new("lane").unwrap(),
    };
    PacketConnectedDefinition {
        schema: "source-owned.packet-connected-program/4".into(),
        connections: vec![PacketInputConnection {
            id: Id::new("original-route").unwrap(),
            policy: canonical::content_ref(b"original-policy", "application/octet-stream").unwrap(),
            producer: endpoint("producer"),
            consumer: endpoint("consumer"),
            delay_ps: U64::new(1),
        }],
        output: None,
    }
}

#[test]
fn malformed_producer_keeps_same_socket_and_exact_original_events() {
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let fd = socket.as_raw_fd();
    let identity = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    let mut original = events();
    original.push(original[0].clone());
    let expected = original.clone();

    let failure = match PacketProgram::new_retained(original, socket) {
        Err(failure) => failure,
        Ok(_) => panic!("duplicate original events must refuse"),
    };
    assert_eq!(failure.configuration(), &expected);
    assert_eq!(failure.effect_socket().as_raw_fd(), fd);
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap(),
        identity
    );
    peer.send(b"same-original-socket").unwrap();
    let mut bytes = [0; 32];
    let received = failure.effect_socket().recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..received], b"same-original-socket");
}

#[test]
fn malformed_reactive_keeps_same_socket_and_complete_original_definition() {
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let fd = socket.as_raw_fd();
    let identity = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    let mut original = definition();
    original.connections.push(original.connections[0].clone());
    let expected = original.clone();

    let failure = match PacketConnectedProgram::new_retained(original, socket) {
        Err(failure) => failure,
        Ok(_) => panic!("duplicate original routes must refuse"),
    };
    assert_eq!(failure.configuration(), &expected);
    assert_eq!(failure.effect_socket().as_raw_fd(), fd);
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap(),
        identity
    );
    peer.send(b"same-original-socket").unwrap();
    let mut bytes = [0; 32];
    let received = failure.effect_socket().recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..received], b"same-original-socket");
}

#[test]
fn retained_birth_matches_original_closed_initial_model_state() {
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let (other, _other_peer) = UnixDatagram::pair().unwrap();
    let producer = match PacketProgram::new_retained(events(), socket) {
        Ok(program) => program,
        Err(_) => panic!("valid original producer"),
    };
    let legacy = PacketProgram::new(events(), other).unwrap();
    assert_eq!(producer.inventory(), legacy.inventory());

    let (socket, _peer) = UnixDatagram::pair().unwrap();
    let (other, _other_peer) = UnixDatagram::pair().unwrap();
    let reactive = match PacketConnectedProgram::new_retained(definition(), socket) {
        Ok(program) => program,
        Err(_) => panic!("valid original reactive actor"),
    };
    let legacy = PacketConnectedProgram::new(definition(), other).unwrap();
    assert_eq!(reactive.inventory().unwrap(), legacy.inventory().unwrap());
}
