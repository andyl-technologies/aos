//! Exact arithmetic, original reaction ordering and inert continuation controls.

// These inert controls assert exact refusal and retained native data.
// crucible-lint: allow panic-shortcut -- Fixture construction and failed invariants deliberately panic.
#![allow(clippy::unwrap_used)]

use super::*;

fn definition() -> RateAlarmClockDefinition {
    RateAlarmClockDefinition {
        numerator: 3.into(),
        denominator: 2.into(),
        epoch_ps: 0.into(),
        epoch_counter: 7.into(),
        drift_ppb: 0,
    }
}

fn reaction(t: u64, microstep: u64) -> Position {
    Position::new(t.into(), microstep.into(), Phase::Reaction)
}

fn arm(name: &str, target: u64) -> Vec<u8> {
    encode(
        &RateAlarmClockRequest::Arm {
            correlation: Id::new(name).unwrap(),
            target: target.into(),
        },
        512,
    )
    .unwrap()
}

#[test]
fn rate_rounding_epoch_drift_and_overflow_are_checked() {
    let rate = definition();
    assert_eq!(rate.reading(1.into()).unwrap(), 8.into());
    assert_eq!(rate.alarm_time(9.into()).unwrap(), 2.into());
    assert!(rate.reading(u64::MAX.into()).is_err());
    let mut altered = rate;
    altered.drift_ppb = -1_000_000_000;
    assert!(altered.reading(0.into()).is_err());
    altered.drift_ppb = -500_000_000;
    assert_eq!(altered.alarm_time(9.into()).unwrap(), 3.into());
    altered.epoch_ps = 10.into();
    assert!(altered.reading(9.into()).is_err());
    assert_eq!(altered.reading(10.into()).unwrap(), 7.into());
}

#[test]
fn exact_cut_pending_alarm_survives_two_fresh_models_once() {
    let mut source = RateAlarmClock::new(definition()).unwrap();
    source.consume(reaction(0, 2), &arm("alarm-a", 13)).unwrap();
    let acknowledged = source.publish(reaction(0, 2)).unwrap();
    assert_eq!(acknowledged[0].0.kind, "armed");
    let cut = Position::new(4.into(), 0.into(), Phase::BoundaryControl);
    source.park(cut).unwrap();
    let saved = source.capture().unwrap();
    drop(source);

    let mut branches = Vec::new();
    for _ in 0..2 {
        let mut branch = RateAlarmClock::new(definition()).unwrap();
        branch.restore(&saved).unwrap();
        assert_eq!(branch.capture().unwrap(), saved);
        assert_eq!(branch.next_position(), Some(reaction(4, 0)));
        let alarm = branch.publish(reaction(4, 0)).unwrap();
        assert_eq!(alarm.len(), 1);
        assert_eq!(alarm[0].0.kind, "alarm");
        assert_eq!(alarm[0].0.counter, 13.into());
        assert!(branch.publish(reaction(4, 0)).is_err());
        branches.push(alarm[0].1.clone());
    }
    assert_eq!(branches[0], branches[1]);
}

#[test]
fn same_reaction_requests_preserve_fifo_and_due_cancel_refuses_without_change() {
    let mut clock = RateAlarmClock::new(definition()).unwrap();
    clock.consume(reaction(0, 3), &arm("first", 13)).unwrap();
    clock.consume(reaction(0, 3), &arm("second", 13)).unwrap();
    let ack = clock.publish(reaction(0, 3)).unwrap();
    assert_eq!(ack[0].0.correlation.as_str(), "first");
    assert_eq!(ack[1].0.correlation.as_str(), "second");
    clock
        .park(Position::new(4.into(), 0.into(), Phase::BoundaryControl))
        .unwrap();
    let before = clock.capture().unwrap();
    let cancel = encode(
        &RateAlarmClockRequest::Cancel {
            correlation: Id::new("cancel").unwrap(),
            alarm: Id::new("first").unwrap(),
        },
        512,
    )
    .unwrap();
    assert!(clock.consume(reaction(4, 0), &cancel).is_err());
    assert_eq!(clock.capture().unwrap(), before);
    let alarms = clock.publish(reaction(4, 0)).unwrap();
    assert_eq!(alarms[0].0.correlation.as_str(), "first");
    assert_eq!(alarms[1].0.correlation.as_str(), "second");
}

#[test]
fn foreign_definition_or_changed_alarm_body_cannot_restore() {
    let mut original = RateAlarmClock::new(definition()).unwrap();
    original.consume(reaction(0, 0), &arm("a", 13)).unwrap();
    original.publish(reaction(0, 0)).unwrap();
    let bytes = original.capture().unwrap();
    let mut forged: Snapshot = serde_json::from_slice(&bytes).unwrap();
    forged.pending[0].reaction = reaction(3, 0);
    let mut target = RateAlarmClock::new(definition()).unwrap();
    let initial = target.capture().unwrap();
    assert!(
        target
            .restore(&encode(&forged, MAXIMUM_CLOCK_STATE_BYTES).unwrap())
            .is_err()
    );
    assert_eq!(target.capture().unwrap(), initial);
    let mut foreign = definition();
    foreign.denominator = 3.into();
    assert!(
        RateAlarmClock::new(foreign)
            .unwrap()
            .restore(&bytes)
            .is_err()
    );
}

#[test]
fn native_credit_and_duplicate_original_refuse_before_mutation() {
    let mut clock = RateAlarmClock::new(definition()).unwrap();
    for index in 0..MAXIMUM_CLOCK_REQUESTS {
        let bytes = encode(
            &RateAlarmClockRequest::Read {
                correlation: Id::new(format!("request-{index}")).unwrap(),
            },
            512,
        )
        .unwrap();
        clock.consume(reaction(0, 0), &bytes).unwrap();
    }
    let before = clock.capture().unwrap();
    let bytes = encode(
        &RateAlarmClockRequest::Read {
            correlation: Id::new("overflow").unwrap(),
        },
        512,
    )
    .unwrap();
    assert!(clock.consume(reaction(0, 0), &bytes).is_err());
    assert_eq!(clock.capture().unwrap(), before);
    assert_eq!(
        clock.publish(reaction(0, 0)).unwrap().len(),
        MAXIMUM_CLOCK_REQUESTS
    );
}
