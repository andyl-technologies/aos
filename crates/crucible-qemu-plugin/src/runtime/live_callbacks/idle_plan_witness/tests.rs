//! Reservation, deduplication and exact-value bounds for advisory idle rows.

use super::*;
use crate::{IdleWakeCause, SchedulerCeiling, compute_idle_wake_plan};

fn plan(current: u64) -> IdleWakePlan {
    compute_idle_wake_plan(
        current,
        ExactDeadlineReport::NoArmedTimer,
        None,
        SchedulerCeiling::new(u64::MAX),
        false,
        None,
    )
    .unwrap_or_else(|error| panic!("original plan: {error}"))
}

#[test]
fn invalid_or_disabled_settings_never_admit_original_plans() {
    for setting in [None, Some("0"), Some("257"), Some("01"), Some("1x")] {
        let witness = IdlePlanWitness::from_setting(setting.map(OsStr::new));
        assert!(
            witness
                .begin(
                    0,
                    0,
                    plan(0),
                    ExactDeadlineReport::NoArmedTimer,
                    AdvanceStopCondition::Ceiling
                )
                .is_none()
        );
    }
}

#[test]
fn runtime_stream_requires_exact_opt_in_and_original_aggregate_allowance() {
    use std::os::unix::ffi::OsStrExt;

    for runtime in [
        None,
        Some(OsStr::new("")),
        Some(OsStr::new("0")),
        Some(OsStr::new("01")),
        Some(OsStr::new("true")),
        Some(OsStr::new("1 ")),
        Some(OsStr::from_bytes(&[0xff])),
    ] {
        let witness = IdlePlanWitness::from_settings(runtime, Some(OsStr::new("64")));
        assert_eq!(witness.budget, 0);
        assert_eq!(witness.owner_pid, 0);
        assert!(
            witness
                .begin(
                    0,
                    0,
                    plan(0),
                    ExactDeadlineReport::NoArmedTimer,
                    AdvanceStopCondition::Ceiling
                )
                .is_none()
        );
    }

    let enabled = IdlePlanWitness::from_settings(Some(OsStr::new("1")), Some(OsStr::new("64")));
    assert_eq!(enabled.budget, 64);
    assert_eq!(enabled.owner_pid, std::process::id());
    assert!(
        enabled
            .begin(
                0,
                0,
                plan(0),
                ExactDeadlineReport::NoArmedTimer,
                AdvanceStopCondition::Ceiling
            )
            .is_some()
    );

    for aggregate in [None, Some("0"), Some("257"), Some("064")] {
        let witness =
            IdlePlanWitness::from_settings(Some(OsStr::new("1")), aggregate.map(OsStr::new));
        assert_eq!(witness.budget, 0);
    }
}

#[test]
fn reserved_returns_bound_nested_plans_and_exact_duplicates_release_allowance() {
    let witness = IdlePlanWitness::from_setting(Some(OsStr::new("4")));
    let first = witness.begin(
        0,
        0,
        plan(0),
        ExactDeadlineReport::NoArmedTimer,
        AdvanceStopCondition::Ceiling,
    );
    let second = witness.begin(
        0,
        1,
        plan(1),
        ExactDeadlineReport::NoArmedTimer,
        AdvanceStopCondition::Ceiling,
    );
    assert!(first.is_some() && second.is_some());
    assert!(
        witness
            .begin(
                0,
                2,
                plan(2),
                ExactDeadlineReport::NoArmedTimer,
                AdvanceStopCondition::Ceiling
            )
            .is_none()
    );
    witness.end(second, Outcome::AdvanceSelected(u64::MAX));
    witness.end(first, Outcome::AdvanceSelected(u64::MAX));
    let inventory = witness
        .inventory
        .lock()
        .unwrap_or_else(|error| panic!("inventory: {error}"));
    assert_eq!(inventory.count, 4);
    assert_eq!(inventory.reserved, 0);
    drop(inventory);

    let witness = IdlePlanWitness::from_setting(Some(OsStr::new("4")));
    for _ in 0..1000 {
        let observation = witness.begin(
            0,
            0,
            plan(0),
            ExactDeadlineReport::NoArmedTimer,
            AdvanceStopCondition::Ceiling,
        );
        assert!(observation.is_some());
        witness.end(observation, Outcome::AlreadyDueReturn(0));
    }
    let inventory = witness
        .inventory
        .lock()
        .unwrap_or_else(|error| panic!("inventory: {error}"));
    assert_eq!(inventory.count, 2);
    assert_eq!(inventory.reserved, 0);
}

#[test]
fn missing_identity_contention_and_dropped_return_remain_inconclusive() {
    let mut witness = IdlePlanWitness::from_setting(Some(OsStr::new("2")));
    witness.owner_pid = witness.owner_pid.wrapping_add(1);
    assert!(
        witness
            .begin(
                0,
                0,
                plan(0),
                ExactDeadlineReport::NoArmedTimer,
                AdvanceStopCondition::Ceiling
            )
            .is_none()
    );

    let witness = IdlePlanWitness::from_setting(Some(OsStr::new("2")));
    let held = witness
        .inventory
        .lock()
        .unwrap_or_else(|error| panic!("inventory: {error}"));
    assert!(
        witness
            .begin(
                0,
                0,
                plan(0),
                ExactDeadlineReport::NoArmedTimer,
                AdvanceStopCondition::Ceiling
            )
            .is_none()
    );
    drop(held);
    let observation = witness.begin(
        0,
        0,
        plan(0),
        ExactDeadlineReport::NoArmedTimer,
        AdvanceStopCondition::Ceiling,
    );
    let held = witness
        .inventory
        .lock()
        .unwrap_or_else(|error| panic!("inventory: {error}"));
    witness.end(observation, Outcome::WaitError);
    assert_eq!(held.reserved, 1);
    drop(held);
    assert!(
        witness
            .begin(
                0,
                1,
                plan(1),
                ExactDeadlineReport::NoArmedTimer,
                AdvanceStopCondition::Ceiling
            )
            .is_none()
    );
}

#[test]
fn maximum_scalar_rows_fit_the_fixed_capture_or_drop_without_partial_output() {
    let original = plan(u64::MAX);
    assert_eq!(original.cause(), IdleWakeCause::SchedulerCeiling);
    let record = Record {
        plan: PlanRecord {
            pid: u32::MAX,
            vcpu: u32::MAX,
            raw: u64::MAX,
            plan: original,
            exact_deadline: ExactDeadlineReport::Armed {
                deadline_ps: u64::MAX,
            },
            stop: AdvanceStopCondition::NextAuthenticatedIdle,
        },
        outcome: Some(Outcome::AdvanceSelected(u64::MAX)),
    };
    let mut bytes = Vec::new();
    record
        .write_to(&mut bytes)
        .unwrap_or_else(|error| panic!("row: {error}"));
    assert!(bytes.len() <= 512, "maximum row bytes={}", bytes.len());
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
}
