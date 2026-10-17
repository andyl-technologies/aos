//! Local operation custody controls; these tests issue no native lease or root.

use super::*;

#[test]
fn missing_actual_operation_refuses_equal_record_coordinates() {
    let actor = 1_usize as *mut Actor;
    let loan = 2_usize as *mut Receive;
    let mut state = ActorState::default();
    state.address = actor as usize;
    state.record.actor = actor as usize;
    state.record.loan = loan as usize;
    let address = std::ptr::from_mut(&mut state.record).cast();

    assert!(!record_matches(&state, actor, loan, address));
    assert!(!state.registered);
    assert!(state.api.is_none());
}

#[test]
fn foreign_owner_address_cannot_use_an_actual_inline_operation() {
    let controller = super::super::tests::controller();
    let actor = 1_usize as *mut Actor;
    let loan = 2_usize as *mut Receive;
    let mut state = ActorState::default();
    state.address = actor as usize;
    state.record.actor = actor as usize;
    state.record.loan = loan as usize;
    state.record.operation = Some(
        controller
            .begin_inline::<true>(SourceOperationClass::Cleanup)
            .expect("local real operation admission"),
    );
    let mut other = RecordState::default();

    assert!(!record_matches(
        &state,
        actor,
        loan,
        std::ptr::from_mut(&mut other).cast()
    ));
    assert!(!state.registered);
    assert!(state.api.is_none());
}

#[test]
fn inline_completion_journal_survives_a_later_completion_refusal() {
    let controller = super::super::tests::controller();
    let operation = controller
        .begin_inline::<true>(SourceOperationClass::Cleanup)
        .expect("local real operation admission");

    operation
        .complete_observation()
        .expect("original completion");
    let repeated = operation.complete_observation();

    assert!(repeated.is_err());
    assert_eq!(operation.terminal.load(Ordering::Acquire), 1);
    assert!(operation.wait_slice_for_observation().is_err());
}

#[test]
fn expanding_policy_cannot_renew_an_expired_inline_record() {
    let controller = super::super::tests::controller();
    let operation = controller
        .begin_inline::<true>(SourceOperationClass::Cleanup)
        .expect("local real operation admission");
    std::thread::sleep(Duration::from_millis(5));
    controller.state.lock().unwrap().budgets[13].total_ns = Some(1_000_000);

    assert!(operation.wait_slice_for_observation().is_err());
    controller.state.lock().unwrap().budgets[13].total_ns = Some(30_000_000_000);

    assert!(operation.wait_slice_for_observation().is_err());
    assert!(operation.complete_observation().is_err());
    assert_ne!(operation.terminal.load(Ordering::Acquire), 1);
}

#[test]
fn initial_slice_refusal_keeps_the_constructed_record_clock() {
    let controller = super::super::tests::controller();
    controller.state.lock().unwrap().budgets[13].total_ns = Some(0);
    let mut record = RecordState::default();
    record.operation = Some(
        controller
            .begin_inline::<true>(SourceOperationClass::Cleanup)
            .expect("caller-funded inline construction"),
    );

    let operation = record.operation.as_ref().unwrap();
    assert!(operation.wait_slice_for_observation().is_err());

    assert!(record.operation.is_some());
    assert_eq!(operation.terminal.load(Ordering::Acquire), 2);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 1);
    drop(record);
    assert_eq!(controller.operations.capacity.load(Ordering::Acquire), 0);
}

#[test]
fn completed_local_journal_distinguishes_semantic_error_from_unknown_custody() {
    let controller = super::super::tests::controller();
    let operation = controller
        .begin_inline::<true>(SourceOperationClass::Cleanup)
        .expect("caller-funded inline construction");
    operation.complete_observation().unwrap();
    let refusal = operation.complete_observation().unwrap_err();
    let negative = observation_status(&refusal);
    let mut record = RecordState {
        operation: Some(operation),
        end_attempted: true,
        end_result: negative,
        terminal_journal: 2,
        ..RecordState::default()
    };

    // This tests only the actual local completion journal. No native release
    // callback, bank-return fact, postcut or new lease is constructed here.
    assert!(negative < 0);
    assert!(record.completion_known());
    assert_eq!(record.end_result, negative);

    record.end_result = 1;
    assert!(!record.completion_known());
    record.end_result = negative;
    for unknown_or_open in [0, 1] {
        record.terminal_journal = unknown_or_open;
        assert!(!record.completion_known());
    }
    record.terminal_journal = 2;
    record.operation.take();
    assert!(!record.completion_known());
}
