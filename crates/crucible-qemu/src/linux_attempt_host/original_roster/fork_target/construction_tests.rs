//! Checks that absent custody never authenticates a Target return.
//!
//! These are negative local witness controls, not Main/Source issuance tests.

use super::*;

#[test]
fn absent_roster_never_becomes_a_returned_target_even_for_old_or_future_epochs() {
    for epoch in [0, 1, u64::MAX] {
        let mut loan = QemuForkTargetConstructionLoan {
            attempt: NativeAccountAttempt {
                roster: Weak::new(),
                index: 0,
                generation: 1,
            },
            epoch,
            process_generation: 2,
            returned: false,
            failed_permit: None,
        };
        assert!(loan.try_finish().is_err());
        assert!(!loan.is_physically_returned());
        assert_eq!(loan.process_generation(), 2);
        assert!(loan.try_finish().is_err());
        assert!(!loan.is_physically_returned());
    }
}

#[test]
fn completed_saved_cleanup_is_observed_without_admitting_a_second_operation() {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationState, HostOperationSupervisor,
    };
    // This is an actual component supervisor/control. It creates no Main,
    // NativeAccountAttempt, Target loan, physical close receipt or role credit.
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let preparation = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let mut cleanup = TargetCleanup::new(preparation);
    let original = cleanup.guard().unwrap();
    let operation_id = original.status().unwrap().operation_id;
    drop(original);
    cleanup.complete_for_return().unwrap();
    assert!(cleanup.completed);
    cleanup.complete_for_return().unwrap();
    let operations = supervisor.operation_statuses().unwrap();
    let saved = operations
        .iter()
        .filter(|status| status.class == HostOperationClass::Cleanup)
        .collect::<Vec<_>>();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].operation_id, operation_id);
    assert_eq!(saved[0].state, HostOperationState::Completed);
}
