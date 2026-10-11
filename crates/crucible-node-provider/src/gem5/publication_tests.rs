//! Adversarial birth/order checks without native admission authority.

// crucible-lint: allow panic-shortcut -- These publication tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::U64;
use serde_json::json;

use super::*;
use crate::gem5::Gem5ConsolePublication;

fn receipt() -> Gem5Completion {
    let before = Gem5Boundary {
        logical_position: crucible_node_contract::Position::new(
            U64::new(0),
            U64::new(0),
            crucible_node_contract::Phase::BoundaryControl,
        ),
        tick: U64::new(10),
        ordinal: U64::new(100),
        tick_ordinal: U64::new(2),
        has_next_event: true,
        next_tick: U64::new(10),
        next_priority: 0,
        inventory: json!({"native_tick":"10"}),
    };
    let mut after = before.clone();
    after.ordinal = U64::new(101);
    after.tick_ordinal = U64::new(3);
    after.logical_position = Position::new(U64::new(10), U64::new(5), Phase::BoundaryControl);
    let original = Gem5Run {
        kind: "run".to_owned(),
        operation: Id::new("original").unwrap(),
        exclusive_tick: U64::new(20),
        maximum_events: U64::new(50),
        exact_range: None,
    };
    Gem5Completion {
        kind: "completed".to_owned(),
        operation: original.operation.clone(),
        original,
        before,
        after,
        processed_events: U64::new(1),
        reason: "output".to_owned(),
        output: b"native".to_vec(),
        publications: vec![Gem5ConsolePublication {
            output_id: U64::new(1),
            tick: U64::new(10),
            event_ordinal: U64::new(101),
            tick_ordinal: U64::new(3),
            guest_pid: U64::new(100),
            context_id: U64::new(0),
            guest_fd: 1,
            causal_parent: U64::new(0),
            payload: b"native".to_vec(),
        }],
        exit_cause: None,
        exit_code: None,
    }
}

#[test]
fn callback_birth_requires_original_event_tie_and_octets() {
    let original = receipt();
    assert!(validate_completion(&original.before, &original.original, &original).is_ok());

    for change in 0..5 {
        let mut changed = original.clone();
        match change {
            0 => changed.publications[0].event_ordinal = U64::new(100),
            1 => changed.publications[0].tick_ordinal = U64::new(2),
            2 => changed.publications[0].tick = U64::new(11),
            3 => changed.publications[0].payload[0] = b'X',
            _ => changed.publications[0].guest_fd = 2,
        }
        assert!(validate_completion(&changed.before, &changed.original, &changed).is_err());
    }
}

#[test]
fn duplicate_native_output_identity_is_refused_before_ack() {
    let mut changed = receipt();
    changed.publications.push(changed.publications[0].clone());
    changed.output.extend_from_slice(b"native");
    assert!(validate_completion(&changed.before, &changed.original, &changed).is_err());
}

#[test]
fn original_native_fifo_cannot_reset_or_skip_across_prefixes() {
    let previous = receipt();
    let mut next = receipt();
    assert!(validate_output_sequence(std::iter::once(&previous), &next).is_err());

    next.publications[0].output_id = U64::new(2);
    assert!(validate_output_sequence(std::iter::once(&previous), &next).is_ok());

    next.publications[0].output_id = U64::new(3);
    assert!(validate_output_sequence(std::iter::once(&previous), &next).is_err());
}

#[test]
fn exact_callback_exclusive_ceiling_preserves_future_publication_birth() {
    let mut value = receipt();
    value.before.logical_position =
        Position::new(U64::new(10), U64::new(4), Phase::BoundaryControl);
    value.original.exclusive_tick = U64::new(10);
    value.original.exact_range = Some(crate::gem5::Gem5ExactRange {
        start: value.before.logical_position,
        limit: value.after.logical_position,
        maximum_microsteps: U64::new(20),
    });
    assert!(validate_completion(&value.before, &value.original, &value).is_ok());
    // The original birth is Reaction4, its publication is Publication5, and
    // the native cursor parks at BoundaryControl5 before external visibility.
    assert!(value.publications[0].tick_ordinal == U64::new(3));
    let mut overshoot = value.clone();
    overshoot.original.exact_range.as_mut().unwrap().limit =
        Position::new(U64::new(10), U64::new(4), Phase::Reaction);
    assert!(validate_completion(&overshoot.before, &overshoot.original, &overshoot).is_err());
    let mut exhausted = value.clone();
    exhausted
        .original
        .exact_range
        .as_mut()
        .unwrap()
        .maximum_microsteps = U64::new(5);
    assert!(validate_completion(&exhausted.before, &exhausted.original, &exhausted).is_err());
}

#[test]
fn idle_native_time_does_not_fake_a_callback_or_outrun_full_position() {
    let mut value = receipt();
    value.before.logical_position =
        Position::new(U64::new(10), U64::new(4), Phase::BoundaryControl);
    value.after = value.before.clone();
    value.after.logical_position = Position::new(U64::new(10), U64::new(4), Phase::Reaction);
    value.original.exclusive_tick = U64::new(10);
    value.original.maximum_events = U64::new(1);
    value.original.exact_range = Some(crate::gem5::Gem5ExactRange {
        start: value.before.logical_position,
        limit: value.after.logical_position,
        maximum_microsteps: U64::new(20),
    });
    value.processed_events = U64::new(0);
    value.output.clear();
    value.publications.clear();
    value.reason = "horizon".into();
    assert!(validate_completion(&value.before, &value.original, &value).is_ok());
    let mut forged = value.clone();
    forged
        .original
        .exact_range
        .as_mut()
        .unwrap()
        .limit
        .microstep = U64::new(5);
    forged.after.logical_position.microstep = U64::new(5);
    assert!(validate_completion(&forged.before, &forged.original, &forged).is_err());
    let mut forged = value.clone();
    forged.after.tick = U64::new(11);
    assert!(validate_completion(&forged.before, &forged.original, &forged).is_err());
}
