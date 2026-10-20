//! Checks actual retained supervisor loans, phase fences and unwind ownership.

use super::*;

#[test]
fn active_callback_and_inspection_refuse_reentry_before_lending_bank() {
    let state = OriginalSupervisorState::new();
    let incidents = RefCell::new(Vec::with_capacity(7));
    let callback = state.begin_quarantine_callback().unwrap();
    let mut called = false;
    assert!(
        state
            .with_original_incidents(&incidents, &mut |_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
    drop(callback);

    state
        .with_original_incidents(&incidents, &mut |_| {
            assert!(state.begin_quarantine_callback().is_err());
            assert!(
                state
                    .with_original_incidents(&incidents, &mut |_| Ok(()))
                    .is_err()
            );
            Ok(())
        })
        .unwrap();
    assert!(state.begin_quarantine_callback().is_ok());
}

#[test]
fn refusal_and_unwind_leave_same_bank_and_release_only_inspection_phase() {
    let state = OriginalSupervisorState::new();
    let incidents = RefCell::new(Vec::with_capacity(9));
    let pointer = incidents.borrow().as_ptr();
    let capacity = incidents.borrow().capacity();
    assert!(
        state
            .with_original_incidents(&incidents, &mut |_| Err(ProviderError::Conflict(
                "fixture refusal"
            )))
            .is_err()
    );

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ =
            state.with_original_incidents(&incidents, &mut |_| panic!("retained fixture unwind"));
    }));
    assert!(unwind.is_err());
    assert_eq!(incidents.borrow().as_ptr(), pointer);
    assert_eq!(incidents.borrow().capacity(), capacity);
    state
        .with_original_incidents(&incidents, &mut |_| Ok(()))
        .unwrap();
}

#[test]
fn foreign_original_thread_refuses_before_lending_or_mutating_bank() {
    let state = OriginalSupervisorState::new();
    let incidents = RefCell::new(Vec::with_capacity(3));
    let (state, incidents, refused) = std::thread::spawn(move || {
        let mut called = false;
        let refused = state
            .with_original_incidents(&incidents, &mut |_| {
                called = true;
                Ok(())
            })
            .is_err();
        assert!(!called);
        (state, incidents, refused)
    })
    .join()
    .unwrap();
    assert!(refused);
    state
        .with_original_incidents(&incidents, &mut |_| Ok(()))
        .unwrap();
}

#[test]
fn external_supervisor_default_refuses_without_calling_inspection() {
    struct External;
    impl ConnectionSupervisor for External {
        fn quarantine(&self, _: ConnectionIncident) {
            panic!("no fixture quarantine expected");
        }
    }
    let mut called = false;
    assert!(
        External
            .with_original_protocol_state(&mut |_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
}
