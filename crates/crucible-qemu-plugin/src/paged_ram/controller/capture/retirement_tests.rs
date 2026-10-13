//! Checks terminal-journal custody without issuing native retirement evidence.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

fn retained_owner(transaction: u64) -> CheckpointPagerOwner {
    let (controller, _, _) = super::super::tests::capture::capture_controller();
    let controller = Arc::new(controller);
    let owner = controller
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .clone();
    CheckpointPagerOwner {
        controller,
        owner,
        service: None,
        transaction,
    }
}

#[test]
fn callback_owner_requires_the_same_state_terminal_transaction() {
    let retained = retained_owner(41);
    assert!(!retained.retirement_completed().unwrap());

    // This fixture exercises the custody decision only; it does not execute the
    // native publisher, acknowledge a root, or qualify checkpoint readiness.
    retained
        .controller
        .state
        .lock()
        .unwrap()
        .checkpoint
        .retired_native_transaction = Some(40);
    assert!(!retained.retirement_completed().unwrap());
    retained
        .controller
        .state
        .lock()
        .unwrap()
        .checkpoint
        .retired_native_transaction = Some(41);

    assert!(retained.retirement_completed().unwrap());
}

#[test]
fn saved_terminal_generation_cannot_hide_an_actual_policy_hold() {
    let retained = retained_owner(41);
    retained.controller.prepare_checkpoint_policy(41).unwrap();
    retained
        .controller
        .state
        .lock()
        .unwrap()
        .checkpoint
        .retired_native_transaction = Some(41);

    assert!(!retained.retirement_completed().unwrap());
    assert!(
        retained
            .controller
            .state
            .lock()
            .unwrap()
            .checkpoint
            .is_held()
    );
}

#[test]
fn replacing_the_actual_paging_owner_cannot_dispose_the_old_callback_owner() {
    let retained = retained_owner(41);
    let (foreign, _, _) = super::super::tests::capture::capture_controller();
    let replacement = foreign
        .state
        .lock()
        .unwrap()
        .owner
        .as_ref()
        .unwrap()
        .clone();
    let old_owner = Arc::downgrade(&retained.owner);
    let mut state = retained.controller.state.lock().unwrap();
    state.checkpoint.retired_native_transaction = Some(41);
    state.owner = Some(replacement);
    drop(state);

    assert!(!retained.retirement_completed().unwrap());
    assert!(old_owner.upgrade().is_some());
}

#[test]
fn busy_state_retains_callback_custody_without_restarting_retirement() {
    let retained = retained_owner(41);
    let mut state = retained.controller.state.lock().unwrap();
    state.checkpoint.retired_native_transaction = Some(41);

    assert!(retained.retirement_completed().is_err());
    assert_eq!(state.checkpoint.retired_native_transaction, Some(41));
}
