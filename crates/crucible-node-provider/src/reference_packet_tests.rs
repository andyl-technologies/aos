//! Independent actual native socket oracle for finite exact packet callbacks.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Failed actual effect/custody assertions deliberately panic.
// crucible-lint: allow rust-allow -- Test setup unwraps are native witness failures, never acceptance defaults.
#![allow(clippy::unwrap_used)]

use super::*;

fn position(ps: u64, microstep: u64, phase: Phase) -> Position {
    Position::new(U64::new(ps), U64::new(microstep), phase)
}

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}

fn fixture() -> (PacketProgram, UnixDatagram) {
    let (native, oracle) = UnixDatagram::pair().unwrap();
    oracle.set_nonblocking(true).unwrap();
    let events = vec![
        PacketEvent {
            id: id("private"),
            evaluation: position(4, 0, Phase::Reaction),
            completion: position(4, 0, Phase::Reaction),
            payload: None,
        },
        PacketEvent {
            id: id("first"),
            evaluation: position(5, 0, Phase::Reaction),
            completion: position(5, 1, Phase::Publication),
            payload: Some(Bytes::new(vec![0, 255])),
        },
        PacketEvent {
            id: id("second"),
            evaluation: position(5, 1, Phase::Reaction),
            completion: position(5, 2, Phase::Publication),
            payload: Some(Bytes::new(vec![])),
        },
    ];
    (PacketProgram::new(events, native).unwrap(), oracle)
}

fn effects(socket: &UnixDatagram) -> Vec<Vec<u8>> {
    let mut rows = Vec::new();
    let mut buffer = [0; 1025];
    loop {
        match socket.recv(&mut buffer) {
            Ok(size) => rows.push(buffer[..size].to_vec()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("independent native socket oracle failed: {error}"),
        }
    }
    rows
}

#[test]
fn genuine_gate_and_excluded_private_transition_have_no_effect() {
    let (mut native, oracle) = fixture();
    let zero = position(0, 0, Phase::BoundaryControl);
    let cut = position(4, 0, Phase::Reaction);
    assert!(native.execute(id("before-global"), zero, cut).is_err());
    assert!(effects(&oracle).is_empty());

    native.open_gate().unwrap();
    let result = native.execute(id("exclude-private"), zero, cut).unwrap();
    assert_eq!(result.inventory.private_mutations.get(), 0);
    assert_eq!(result.inventory.pending.len(), 3);
    assert!(effects(&oracle).is_empty());
}

#[test]
fn atomic_straddling_step_keeps_complete_callback_and_native_outputs() {
    let (mut native, oracle) = fixture();
    native.open_gate().unwrap();
    let zero = position(0, 0, Phase::BoundaryControl);
    let cut = position(5, 0, Phase::Reaction);
    let result = native.execute(id("straddling"), zero, cut).unwrap();
    assert_eq!(result.inventory.private_mutations.get(), 1);
    assert_eq!(result.inventory.packet_effects.get(), 0);
    assert_eq!(effects(&oracle), vec![vec![0]]);

    native.retire(&id("straddling"), &[]).unwrap();
    let result = native
        .execute(id("same-time"), cut, position(6, 0, Phase::BoundaryControl))
        .unwrap();
    assert_eq!(
        result
            .newborn
            .iter()
            .map(|row| row.sequence.get())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(effects(&oracle), vec![vec![1, 0, 255], vec![1]]);
}

#[test]
fn same_original_and_retirement_cannot_repeat_or_relabel_native_effects() {
    let (mut native, oracle) = fixture();
    native.open_gate().unwrap();
    let zero = position(0, 0, Phase::BoundaryControl);
    let limit = position(6, 0, Phase::BoundaryControl);
    let original = native.execute(id("original"), zero, limit).unwrap().clone();
    assert_eq!(effects(&oracle).len(), 3);
    assert_eq!(
        native.execute(id("original"), zero, limit).unwrap(),
        &original
    );
    assert!(
        native
            .execute(id("original"), zero, position(7, 0, Phase::BoundaryControl))
            .is_err()
    );
    assert!(effects(&oracle).is_empty());
    assert!(native.retire(&id("original"), &[id("first")]).is_err());
    native
        .retire(&id("original"), &[id("first"), id("second")])
        .unwrap();
    native
        .retire(&id("original"), &[id("first"), id("second")])
        .unwrap();
    assert!(native.retire(&id("original"), &[]).is_err());
    assert_eq!(native.original(&id("original")), Some(&original));
    assert!(native.inventory().retained_outputs.is_empty());
    assert!(effects(&oracle).is_empty());
}

#[test]
fn actual_effect_failure_retains_original_and_fences_future_work() {
    let (mut native, oracle) = fixture();
    native.open_gate().unwrap();
    drop(oracle);
    let zero = position(0, 0, Phase::BoundaryControl);
    let limit = position(6, 0, Phase::BoundaryControl);
    assert!(native.execute(id("uncertain"), zero, limit).is_err());
    assert!(!native.original(&id("uncertain")).unwrap().complete);
    assert!(native.execute(id("uncertain"), zero, limit).is_err());
    assert!(native.execute(id("replacement"), zero, limit).is_err());
}

#[test]
fn native_event_and_original_caps_refuse_before_effects() {
    let (socket, oracle) = UnixDatagram::pair().unwrap();
    let event = PacketEvent {
        id: id("bad"),
        evaluation: position(1, 0, Phase::Reaction),
        completion: position(1, 0, Phase::Reaction),
        payload: Some(Bytes::new(vec![0; 1025])),
    };
    assert!(PacketProgram::new(vec![event], socket).is_err());
    oracle.set_nonblocking(true).unwrap();
    assert!(effects(&oracle).is_empty());

    let (mut native, oracle) = fixture();
    native.open_gate().unwrap();
    let zero = position(0, 0, Phase::BoundaryControl);
    for index in 0..MAXIMUM_OPERATIONS {
        native
            .execute(id(&format!("zero-{index}")), zero, zero)
            .unwrap();
        native.retire(&id(&format!("zero-{index}")), &[]).unwrap();
    }
    assert!(native.execute(id("over-credit"), zero, zero).is_err());
    assert_eq!(native.inventory().private_mutations.get(), 0);
    assert!(effects(&oracle).is_empty());
}
