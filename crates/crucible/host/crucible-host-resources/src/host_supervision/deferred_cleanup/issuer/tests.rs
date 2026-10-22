//! Exercises actual issuer ownership, once-only delegation and negative posts.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::TestAllocationObserver;

fn supervisor() -> HostOperationSupervisor {
    HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap()
}

fn delegated(setup: &HostOperationGuard) -> HostDeferredCleanupIssuer {
    let mut output = None;
    setup.delegate_deferred_cleanup_issuer(&mut output).unwrap();
    output.unwrap()
}

#[test]
fn delegation_allocates_nothing_and_reserves_after_actual_setup_return() {
    let supervisor = supervisor();
    let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let (issuer, events) =
        TestAllocationObserver::capture_allocation_events(|| delegated(&setup)).unwrap();

    assert_eq!(events.count, 0);
    assert_eq!(issuer.first_refusal(), None);
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 0);
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    setup.complete().unwrap();
    drop(setup);
    assert!(supervisor.operation_statuses().unwrap().is_empty());

    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut output = None;
    issuer.reserve(&work, &mut output).unwrap();
    let mut cleanup = output.unwrap();
    assert_eq!(cleanup.entered_operation_id(), None);
    work.complete().unwrap();
    drop(work);

    let before_entry = supervisor.elapsed();
    let entered = cleanup.enter().unwrap();
    let state = supervisor.lock().unwrap();
    let actual_started = state.operations.get(&entered.id).unwrap().started;
    assert!(actual_started >= before_entry);
    drop(state);
    entered.complete().unwrap();
}

#[test]
fn equal_cap_identity_and_shared_outer_do_not_authorize_another_budget_owner() {
    let supervisor = supervisor();
    let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let issuer = delegated(&setup);
    let other = supervisor
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    assert_eq!(other.cap_id(), supervisor.cap_id());
    assert!(Arc::ptr_eq(&other.shared.outer, &supervisor.shared.outer));
    let foreign_work = other.begin(HostOperationClass::Quantum).unwrap();
    let mut output = None;

    assert_eq!(
        issuer.reserve(&foreign_work, &mut output),
        Err(HostSupervisionError::Unavailable)
    );
    assert!(output.is_none());
    assert_eq!(other.lock().unwrap().reserved_controls, 0);
    let local_work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    issuer.reserve(&local_work, &mut output).unwrap();
    assert!(output.is_some());
}

#[test]
fn delegation_refuses_wrong_class_occupied_output_and_replacement_after_drop() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let mut output = None;

    assert_eq!(
        work.delegate_deferred_cleanup_issuer(&mut output),
        Err(HostSupervisionError::InvalidBudget)
    );
    assert!(output.is_none());
    setup.delegate_deferred_cleanup_issuer(&mut output).unwrap();
    assert_eq!(
        setup.delegate_deferred_cleanup_issuer(&mut output),
        Err(HostSupervisionError::BorrowedOperation)
    );
    assert!(output.is_some());
    drop(output.take());
    assert_eq!(
        setup.delegate_deferred_cleanup_issuer(&mut output),
        Err(HostSupervisionError::BorrowedOperation)
    );
    assert!(output.is_none());
}

#[test]
fn negative_delegation_post_retains_the_unready_actual_issuer() {
    let supervisor = supervisor();
    let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut output = None;

    let post = setup.delegate_deferred_cleanup_issuer_with(&mut output, || {
        supervisor.cancel().unwrap();
    });
    assert!(post.is_err());
    let issuer = output.unwrap();
    assert_eq!(issuer.first_refusal(), post.err());
    assert!(supervisor.lock().unwrap().cleanup_issuer_delegated);
    let mut reservation = None;
    assert_eq!(issuer.reserve(&work, &mut reservation), post);
    assert!(reservation.is_none());
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 0);
}
