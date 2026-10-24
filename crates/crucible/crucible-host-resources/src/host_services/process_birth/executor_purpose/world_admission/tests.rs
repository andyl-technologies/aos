//! Exercises actual mutex refusal and the same real mechanism Original.
//!
//! No authenticated Main, Source, node, native claim or successful provider is
//! created by these controls. Entered-native qualification remains separate.

use super::*;
use crate::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use std::cell::Cell;

#[test]
fn held_control_refuses_before_work_and_keeps_independent_original_post() {
    let control = Mutex::new(73_u64);
    let held = control.lock().unwrap();
    let pointer = std::ptr::from_ref(&*held);
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let operation = original.status().unwrap().operation_id;
    let checks = Cell::new(0);
    let work_entered = Cell::new(false);

    let (result, after) = observe_world_attempt(
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                supervisor.cancel().unwrap();
            }
            original
                .wait_slice()
                .map(|_| ())
                .map_err(ServiceBirthError::from)
        },
        || {
            let _control = borrow_world_control(&control, "real held descriptor control")?;
            work_entered.set(true);
            Ok(())
        },
    );

    assert!(matches!(result, Err(ServiceBirthError::Policy(ref message))
        if matches!(message, std::borrow::Cow::Borrowed("real held descriptor control"))));
    assert!(!work_entered.get());
    assert_eq!(checks.get(), 2);
    assert!(matches!(after, Some(ServiceBirthError::Supervision(actual))
        if actual == original.wait_slice().unwrap_err()));
    assert_eq!(original.status().unwrap().operation_id, operation);
    assert_eq!(std::ptr::from_ref(&*held), pointer);
    assert_eq!(*held, 73);
    drop(held);
    assert!(control.try_lock().is_ok());
}

#[test]
fn refused_prefix_still_observes_post_without_running_work_or_renewing_original() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let operation = original.status().unwrap().operation_id;
    supervisor.cancel().unwrap();
    let refusal = original.wait_slice().unwrap_err();
    let checks = Cell::new(0);
    let entered = Cell::new(false);

    let (result, after) = observe_world_attempt(
        || {
            checks.set(checks.get() + 1);
            original
                .wait_slice()
                .map(|_| ())
                .map_err(ServiceBirthError::from)
        },
        || {
            entered.set(true);
            Ok(())
        },
    );

    assert_eq!(checks.get(), 2);
    assert!(!entered.get());
    assert!(matches!(result, Err(ServiceBirthError::Supervision(actual)) if actual == refusal));
    assert!(matches!(after, Some(ServiceBirthError::Supervision(actual)) if actual == refusal));
    assert_eq!(original.status().unwrap().operation_id, operation);
}

#[test]
fn observation_post_runs_after_work_releases_the_same_control() {
    let control = Mutex::new(81_u64);
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let checks = Cell::new(0);

    let (result, after) = observe_world_attempt(
        || {
            assert!(control.try_lock().is_ok());
            checks.set(checks.get() + 1);
            original
                .wait_slice()
                .map(|_| ())
                .map_err(ServiceBirthError::from)
        },
        || {
            let mut held = borrow_world_control(&control, "mechanism control busy")?;
            *held += 1;
            Ok(())
        },
    );

    assert!(result.is_ok());
    assert!(after.is_none());
    assert_eq!(checks.get(), 2);
    assert_eq!(*control.try_lock().unwrap(), 82);
}
