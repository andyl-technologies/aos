//! Event-release latching tests for 9p visibility.
//!
//! These pin the release rule: an update latches the earliest emission of its
//! event strictly after its commit, a re-emission never moves the latch later,
//! lagged event releases fold once their deadline passes, and a restored
//! continuation's latches must match the retained emissions its cursor consumed.

use super::test_support::*;
use super::*;

#[test]
fn event_release_with_data_lag_folds_after_its_first_deadline() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"lagged"),
        split(NinepVisibilityScope::Global),
        on_event(event, coordinate(0, 0)),
        0,
        1,
        &[],
    ));
    ok(state.observe_events(&[emission(event, 5, 1)]));
    assert_eq!(ok(state.advance_visibility(0, 1_005)), (1, 1));
    ok(state.advance_visibility(0, 50_000));
    assert_eq!(state.compacted_frontier(), 1);

    // A re-emission after folding cannot reopen the release for a new session.
    ok(state.observe_events(&[emission(event, 49_500, 0)]));
    state.retire_sessions_except(1);
    assert_eq!(ok(state.advance_visibility(1, 50_000)), (1, 1));
    assert_eq!(
        state.visible_object(1, "/a").map(|object| object.data),
        Some(b"lagged".to_vec())
    );
}

#[test]
fn reemitted_event_never_moves_a_latched_release_later() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"lagged"),
        split(NinepVisibilityScope::Global),
        on_event(event, coordinate(0, 0)),
        0,
        1,
        &[],
    ));
    ok(state.observe_events(&[emission(event, 5, 1)]));
    ok(state.observe_events(&[emission(event, 900, 0)]));
    assert_eq!(latch_of(&state, 0), Some(coordinate(5, 1)));
    assert_eq!(ok(state.advance_visibility(0, 1_005)), (1, 1));

    // A fresh session reads the same fixed deadline, not the re-emission.
    let mut fresh = state.clone();
    fresh.retire_sessions_except(1);
    assert_eq!(ok(fresh.advance_visibility(1, 1_005)), (1, 1));

    // An emission appended out of order at an earlier eligible coordinate is
    // the earliest release and can only move the latch earlier.
    ok(state.observe_events(&[emission(event, 3, 0)]));
    assert_eq!(latch_of(&state, 0), Some(coordinate(3, 0)));
}

#[test]
fn emissions_at_or_before_the_commit_never_release_it() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    let consumed = [emission(event, 50, 0), emission(event, 100, 2)];
    ok(state.observe_events(&consumed));
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        on_event(event, coordinate(100, 2)),
        0,
        0,
        &consumed,
    ));
    assert_eq!(latch_of(&state, 0), None);
    assert_eq!(ok(state.advance_visibility(0, 10_000)), (0, 0));

    // A later evaluation at the commit tick is strictly after the commit.
    ok(state.observe_events(&[emission(event, 100, 3)]));
    assert_eq!(latch_of(&state, 0), Some(coordinate(100, 3)));
    assert_eq!(ok(state.advance_visibility(0, 10_000)), (1, 1));
}

#[test]
fn new_commit_latches_from_consumed_emissions() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    let other = [8; 32];
    let consumed = [emission(other, 7, 0), emission(event, 10, 0)];
    ok(state.observe_events(&consumed));

    // Emissions of other events in the prior slice are ignored.
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        on_event(event, coordinate(5, 0)),
        0,
        0,
        &consumed,
    ));
    assert_eq!(latch_of(&state, 0), Some(coordinate(10, 0)));
    assert_eq!(ok(state.advance_visibility(0, 10)), (1, 1));
    ok(state.verify_event_latches(&consumed));
}

#[test]
fn retired_emissions_advance_the_cursor_without_latching() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        on_event(event, coordinate(5, 0)),
        0,
        0,
        &[],
    ));

    // Emissions 0..3 were appended; only the releasing one is retained.
    ok(state.observe_events_through(&[emission(event, 7, 0)], 3));

    assert_eq!(state.event_cursor(), 3);
    assert_eq!(latch_of(&state, 0), Some(coordinate(7, 0)));
    assert_eq!(
        state.event_subscriptions().collect::<Vec<_>>(),
        vec![(event, coordinate(5, 0))]
    );
    ok(state.verify_event_latches(&[emission(event, 7, 0)]));
    assert!(state.observe_events_through(&[], 2).is_err());
    assert!(
        state
            .observe_events_through(&[emission(event, 8, 0), emission(event, 9, 0)], 4)
            .is_err()
    );
    assert_eq!(state.event_cursor(), 3);
}

#[test]
fn recommit_from_a_later_opportunity_keeps_the_first_subscription() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    let commit = |state: &mut NinepVisibilityState, after| {
        state.commit(
            key(1, 1),
            file("/a", 1, b"one"),
            atomic(NinepVisibilityScope::Global),
            on_event(event, after),
            0,
            0,
            &[],
        )
    };
    assert_eq!(ok(commit(&mut state, coordinate(10, 0))), 0);
    assert_eq!(ok(commit(&mut state, coordinate(500, 0))), 0);

    // The emission precedes the recommit but follows the first commit.
    ok(state.observe_events(&[emission(event, 20, 0)]));
    assert_eq!(latch_of(&state, 0), Some(coordinate(20, 0)));
}

#[test]
fn commit_rejects_prior_emissions_beyond_the_event_cursor() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    assert!(
        state
            .commit(
                key(1, 1),
                file("/a", 1, b"one"),
                atomic(NinepVisibilityScope::Global),
                on_event(event, coordinate(0, 0)),
                0,
                0,
                &[emission(event, 1, 0)],
            )
            .is_err()
    );
    assert_eq!(state.committed_frontier(), 0);
}

#[test]
fn latch_verification_requires_the_consumed_emissions() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        on_event(event, coordinate(0, 0)),
        0,
        0,
        &[],
    ));
    let consumed = [emission(event, 4, 0)];
    ok(state.observe_events(&consumed));
    ok(state.verify_event_latches(&consumed));

    // A log without the releasing emission, or one whose emission differs,
    // did not produce the latch.
    assert!(state.verify_event_latches(&[]).is_err());
    assert!(
        state
            .verify_event_latches(&[emission(event, 6, 0)])
            .is_err()
    );
    assert!(
        state
            .verify_event_latches(&[emission([8; 32], 4, 0)])
            .is_err()
    );
}

#[test]
fn decoded_state_rejects_latches_outside_the_subscription_window() {
    let mut state = NinepVisibilityState::default();
    let event = [9; 32];
    ok(state.observe_events(&[emission(event, 30, 0)]));
    ok(state.commit(
        key(1, 1),
        file("/a", 1, b"one"),
        atomic(NinepVisibilityScope::Global),
        on_event(event, coordinate(20, 0)),
        0,
        0,
        &[emission(event, 30, 0)],
    ));
    ok(state.commit(
        key(2, 1),
        file("/b", 1, b"two"),
        atomic(NinepVisibilityScope::Global),
        NinepVisibilityRelease::AtTicks(5),
        0,
        0,
        &[],
    ));
    assert_eq!(round_trip(&state), state);

    let encode = |updates: BTreeMap<u64, NinepVisibilityUpdate>| {
        let wire = NinepVisibilityStateWire {
            next_sequence: state.next_sequence,
            base_sequence: state.base_sequence,
            release_tick: state.release_tick,
            event_cursor: state.event_cursor,
            session: state.session,
            updates,
            compacted: state.compacted.clone(),
            identities: state.identities.clone(),
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut bytes)
            .unwrap_or_else(|error| panic!("encode wire: {error}"));
        bytes
    };
    let rejected = |bytes: Vec<u8>| {
        ciborium::de::from_reader::<NinepVisibilityState, _>(bytes.as_slice()).is_err()
    };

    let mut at_commit = state.updates.clone();
    if let Some(update) = at_commit.get_mut(&0) {
        update.event_latch = Some(coordinate(20, 0));
    }
    assert!(rejected(encode(at_commit)));

    let mut time_latched = state.updates.clone();
    if let Some(update) = time_latched.get_mut(&1) {
        update.event_latch = Some(coordinate(40, 0));
    }
    assert!(rejected(encode(time_latched)));
}
