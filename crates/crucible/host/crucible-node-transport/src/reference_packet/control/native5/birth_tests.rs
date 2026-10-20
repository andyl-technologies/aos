//! Checks that refused birth retains the actual original model and effect socket.

// crucible-lint: allow panic-shortcut -- Fixture and assertion panics are the control verdict.
#![allow(clippy::unwrap_used)]

use super::super::tests::{fixture, producer, reactive};
use super::*;
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

#[test]
fn refused_producer_birth_retains_original_socket_and_complete_model() {
    let coordinator = fixture::five();
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let original_fd = socket.as_raw_fd();
    let original_socket = std::fs::read_link(format!("/proc/self/fd/{original_fd}")).unwrap();
    let program = PacketProgram::new(producer().definition().events, socket).unwrap();
    let definition = program.definition();
    let before = program.inventory();
    let mut foreign = coordinator.participants[0].clone();
    foreign.world = canonical::json_hash("native5-foreign-birth", &"world").unwrap();

    let failure =
        PacketControl::new_complete_producer_retained(foreign, program, coordinator.clone())
            .err()
            .unwrap();

    assert_eq!(failure.program().definition(), definition);
    assert_eq!(failure.program().inventory(), before);
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{original_fd}")).unwrap(),
        original_socket
    );
    assert_eq!(peer.send(b"same-original-socket").unwrap(), 20);
    let (selected, program, retained_coordinator, _reason) = failure.into_original_parts();
    assert_ne!(selected.world, coordinator.participants[0].world);
    assert_eq!(retained_coordinator, coordinator);
    assert_eq!(program.inventory(), before);
}

#[test]
fn refused_reactive_birth_retains_original_socket_and_complete_model() {
    let coordinator = fixture::five();
    let (socket, peer) = UnixDatagram::pair().unwrap();
    let original_fd = socket.as_raw_fd();
    let original_socket = std::fs::read_link(format!("/proc/self/fd/{original_fd}")).unwrap();
    let definition = reactive(&coordinator, 1).definition().clone();
    let program = PacketConnectedProgram::new(definition.clone(), socket).unwrap();
    let before = program.inventory().unwrap();
    let mut foreign = coordinator.participants[1].clone();
    foreign.world = canonical::json_hash("native5-foreign-birth", &"world").unwrap();

    let failure =
        PacketControl::new_complete_reactive_retained(foreign, program, coordinator.clone())
            .err()
            .unwrap();

    assert_eq!(failure.program().definition(), &definition);
    assert_eq!(failure.program().inventory().unwrap(), before);
    assert_eq!(
        std::fs::read_link(format!("/proc/self/fd/{original_fd}")).unwrap(),
        original_socket
    );
    assert_eq!(peer.send(b"same-original-socket").unwrap(), 20);
    let (_, program, retained_coordinator, _) = failure.into_original_parts();
    assert_eq!(retained_coordinator, coordinator);
    assert_eq!(program.inventory().unwrap(), before);
}

#[test]
fn retained_birth_transfers_both_original_models_beneath_closed_gates() {
    let coordinator = fixture::five();
    let producer = PacketControl::new_complete_producer_retained(
        coordinator.participants[0].clone(),
        producer(),
        coordinator.clone(),
    )
    .unwrap();
    let reactive = PacketControl::new_complete_reactive_retained(
        coordinator.participants[1].clone(),
        reactive(&coordinator, 1),
        coordinator,
    )
    .unwrap();

    assert!(producer.inventory().unwrap().gate_closed);
    assert!(reactive.inventory().unwrap().gate_closed);
    assert!(producer.complete_storage.is_none());
    assert!(reactive.complete_storage.is_none());
    assert!(!producer.realized);
    assert!(!reactive.realized);
}
