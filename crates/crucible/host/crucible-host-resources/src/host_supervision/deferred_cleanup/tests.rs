//! Exercises real deferred record custody and separate Cleanup entry clocks.

use super::*;
use crate::test_support::TestAllocationObserver;

fn supervisor() -> HostOperationSupervisor {
    HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap()
}

fn reserved(work: &HostOperationGuard) -> HostDeferredCleanupControl {
    let mut output = None;
    work.reserve_deferred_cleanup_control(&mut output).unwrap();
    output.unwrap()
}

#[test]
fn reservation_allocates_nothing_and_enters_after_actual_work_record_retirement() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let (mut cleanup, events) =
        TestAllocationObserver::capture_allocation_events(|| reserved(&work)).unwrap();

    assert_eq!(events.count, 0);
    assert_eq!(cleanup.entered_operation_id(), None);
    assert!(cleanup.current().is_err());
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 1);
    let work_id = work.id;
    work.complete().unwrap();
    drop(work);
    supervisor.cancel().unwrap();
    assert!(!supervisor.lock().unwrap().operations.contains_key(&work_id));
    let before_entry = supervisor.elapsed();

    let entered = cleanup.enter().unwrap().status().unwrap();

    assert_eq!(entered.class, HostOperationClass::Cleanup);
    assert_eq!(entered.state, HostOperationState::Running);
    let state = supervisor.lock().unwrap();
    let actual = state.operations.get(&entered.operation_id).unwrap();
    assert!(actual.started >= before_entry);
    assert_eq!(actual.started, actual.last_progress);
    assert_eq!(state.reserved_controls, 0);
    assert_eq!(state.operations.len(), 1);
    drop(state);
    cleanup.current().unwrap().complete().unwrap();
}

#[test]
fn reserved_cleanup_record_survives_saturation_and_uses_its_original_identity() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut cleanup = reserved(&work);
    let reservation_id = cleanup.id;
    let other_work: Vec<_> = (1..MAX_HOST_WORK_OPERATIONS)
        .map(|_| supervisor.begin(HostOperationClass::PageIn).unwrap())
        .collect();
    let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();

    assert!(matches!(
        supervisor.begin_control(HostOperationClass::Cleanup),
        Err(HostSupervisionError::CapacityExhausted)
    ));
    let next_id = supervisor.lock().unwrap().next_operation;
    assert!(next_id > reservation_id);

    cleanup.enter().unwrap();

    let state = supervisor.lock().unwrap();
    assert_eq!(state.operations.len(), MAX_HOST_OPERATIONS);
    assert_eq!(state.reserved_controls, 0);
    assert_eq!(state.next_operation, next_id);
    assert_eq!(cleanup.entered_operation_id(), Some(reservation_id));
    drop(state);
    drop((setup, other_work));
}

#[test]
fn reservation_refuses_wrong_class_occupied_output_and_a_second_actual_assignment() {
    let supervisor = supervisor();
    let setup = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut output = None;

    assert_eq!(
        setup.reserve_deferred_cleanup_control(&mut output),
        Err(HostSupervisionError::InvalidBudget)
    );
    assert!(output.is_none());
    work.reserve_deferred_cleanup_control(&mut output).unwrap();
    let original_id = output.as_ref().unwrap().id;
    assert_eq!(
        work.reserve_deferred_cleanup_control(&mut output),
        Err(HostSupervisionError::BorrowedOperation)
    );
    assert_eq!(output.as_ref().unwrap().id, original_id);
    drop(output.take());
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 0);
    assert_eq!(
        work.reserve_deferred_cleanup_control(&mut output),
        Err(HostSupervisionError::BorrowedOperation)
    );
    assert!(output.is_none());
}

#[test]
fn a_negative_quantum_post_retains_the_unready_reservation_and_cannot_enter() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut output = None;

    let post = work.reserve_deferred_cleanup_control_with(&mut output, || {
        supervisor.cancel().unwrap();
    });

    assert!(post.is_err());
    let mut cleanup = output.unwrap();
    assert_eq!(cleanup.first_refusal(), post.err());
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 1);
    assert!(cleanup.enter().is_err());
    assert_eq!(cleanup.entered_operation_id(), None);
    drop(cleanup);
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 0);
}

#[test]
fn a_born_negative_cleanup_retains_its_guard_and_first_expiry_without_reentry() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut cleanup = reserved(&work);
    let id = cleanup.id;
    drop(work);

    let first = cleanup
        .enter_with(|| {
            let mut budgets = HostOperationBudgets::default();
            budgets.classes[HostOperationClass::Cleanup as usize] =
                HostOperationBudget::finite(Duration::from_nanos(1));
            supervisor.update_budgets(0, budgets).unwrap();
        })
        .unwrap_err();

    assert!(matches!(first, HostSupervisionError::DeadlineExpired {
        operation_id, class: HostOperationClass::Cleanup,
    } if operation_id == id));
    assert_eq!(cleanup.entered_operation_id(), Some(id));
    assert_eq!(cleanup.first_refusal(), Some(first));
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 0);
    supervisor
        .update_budgets(1, HostOperationBudgets::default())
        .unwrap();
    assert_eq!(cleanup.current().unwrap_err(), first);
    assert!(cleanup.enter().is_err());
    assert_eq!(
        cleanup.entered.as_ref().unwrap().status().unwrap().state,
        HostOperationState::Expired
    );
    drop(cleanup);
    assert!(supervisor.operation_statuses().unwrap().is_empty());
}

#[test]
fn a_prebirth_lock_refusal_keeps_the_reserved_record_and_does_not_repeat_entry() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut cleanup = reserved(&work);
    drop(work);
    let poison = supervisor.clone();
    assert!(
        std::thread::spawn(move || {
            let _held = poison.lock().unwrap();
            panic!("poison the real deferred-entry owner before birth");
        })
        .join()
        .is_err()
    );

    assert_eq!(
        cleanup.enter().unwrap_err(),
        HostSupervisionError::Unavailable
    );
    assert_eq!(cleanup.entered_operation_id(), None);
    assert_eq!(
        cleanup.first_refusal(),
        Some(HostSupervisionError::Unavailable)
    );
    assert!(cleanup.entry_attempted);
    assert!(cleanup.enter().is_err());
    let poisoned = supervisor.shared.state.lock().unwrap_err().into_inner();
    assert_eq!(poisoned.reserved_controls, 1);
    assert!(poisoned.operations.is_empty());
}

#[test]
fn identity_exhaustion_refuses_before_assignment_or_the_once_only_latch() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    supervisor.lock().unwrap().next_operation = u64::MAX;
    let mut output = None;

    assert_eq!(
        work.reserve_deferred_cleanup_control(&mut output),
        Err(HostSupervisionError::IdentityExhausted)
    );

    assert!(output.is_none());
    let state = supervisor.lock().unwrap();
    assert_eq!(state.reserved_controls, 0);
    assert!(
        !state
            .operations
            .get(&work.id)
            .unwrap()
            .deferred_cleanup_reserved
    );
}

#[test]
fn interrupted_entry_post_keeps_born_custody_without_authorizing_current() {
    let supervisor = supervisor();
    let work = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let mut cleanup = reserved(&work);
    drop(work);
    let id = cleanup.id;

    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cleanup.enter_with(|| panic!("interrupt after actual Cleanup birth"));
    }));

    assert!(interrupted.is_err());
    assert_eq!(cleanup.entered_operation_id(), Some(id));
    assert_eq!(cleanup.first_refusal(), None);
    assert!(!cleanup.entry_post_returned);
    assert_eq!(
        cleanup.current().unwrap_err(),
        HostSupervisionError::Unavailable
    );
    assert!(cleanup.enter().is_err());
    assert_eq!(supervisor.lock().unwrap().operations.len(), 1);
    assert_eq!(supervisor.lock().unwrap().reserved_controls, 0);
    drop(cleanup);
    assert!(supervisor.operation_statuses().unwrap().is_empty());
}
