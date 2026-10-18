//! Exercises saved operation identity and terminal-parent policy, without Main issuance.
//!
//! These controls use genuine local supervisors and guards. They cannot create
//! an authenticated family, dispatcher purpose, service debit or native grant.

use super::*;
use crate::host_supervision::HostSupervisionError;

#[test]
fn missing_cleanup_verification_does_not_enter_or_substitute_an_operation() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let cleanup = Arc::new(supervisor.begin(HostOperationClass::Cleanup).unwrap());
    let saved = RetainedDispatcherCleanup::default();
    let count = supervisor.operation_statuses().unwrap().len();

    assert!(saved.verify(&cleanup).is_err());

    assert!(saved.entered.get().is_none());
    assert_eq!(supervisor.operation_statuses().unwrap().len(), count);
}

#[test]
fn same_outer_cap_cleanup_cannot_replace_the_exact_saved_operation() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let origin = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let saved = RetainedDispatcherCleanup::default();
    let cleanup = saved.enter(&origin).unwrap();
    let other = Arc::new(supervisor.begin(HostOperationClass::Cleanup).unwrap());
    assert!(other.shares_outer_cap(&supervisor));

    assert!(saved.verify(&other).is_err());
    saved.verify(&cleanup).unwrap();

    let again = saved.enter(&origin).unwrap();
    assert!(Arc::ptr_eq(&cleanup, &again));
}

#[test]
fn first_cleanup_admission_refusal_cannot_be_replaced_by_valid_preparation() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let wrong_class = supervisor.begin(HostOperationClass::PageIn).unwrap();
    let valid_origin = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let saved = RetainedDispatcherCleanup::default();
    assert!(matches!(
        saved.enter(&wrong_class),
        Err(ServiceBirthError::Supervision(
            HostSupervisionError::InvalidBudget
        ))
    ));
    let count = supervisor.operation_statuses().unwrap().len();

    assert!(matches!(
        saved.enter(&valid_origin),
        Err(ServiceBirthError::Supervision(
            HostSupervisionError::InvalidBudget
        ))
    ));

    assert_eq!(supervisor.operation_statuses().unwrap().len(), count);
    assert!(matches!(
        saved.entered.get(),
        Some(Err(HostSupervisionError::InvalidBudget))
    ));
}

#[test]
fn parent_cancellation_blocks_new_work_but_preserves_same_cleanup_until_completion() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let origin = supervisor.begin(HostOperationClass::Preparation).unwrap();
    origin.complete().unwrap();
    supervisor.cancel().unwrap();
    assert!(supervisor.begin(HostOperationClass::Preparation).is_err());
    let mut saved = RetainedDispatcherCleanup::default();
    let before_cleanup = supervisor.operation_statuses().unwrap().len();

    let cleanup = saved.enter(&origin).unwrap();
    saved.verify(&cleanup).unwrap();
    assert!(Arc::ptr_eq(&cleanup, &saved.enter(&origin).unwrap()));
    saved.complete(&cleanup).unwrap();

    assert!(saved.entered.get().is_none());
    assert!(saved.completed);
    assert!(saved.verify(&cleanup).is_err());
    assert!(saved.enter(&origin).is_err());
    drop(cleanup);
    assert_eq!(
        supervisor.operation_statuses().unwrap().len(),
        before_cleanup
    );
    assert!(supervisor.begin(HostOperationClass::PageIn).is_err());
}
