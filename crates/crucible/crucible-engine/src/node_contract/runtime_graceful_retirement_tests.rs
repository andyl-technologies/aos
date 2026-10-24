//! Checks actual queue custody across graceful refusal, unwind and reaping.
//!
//! These inert adapter/source models test custody ordering and refusal; their
//! receipts and qualified callback establish no installed native cleanup.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These model tests assert original custody and intentionally unwind one cleanup hook.
#![allow(clippy::unwrap_used)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::node_contract::{RuntimeCustodyQueue, RuntimeCustodySupervisor};

fn queued_runtime() -> (
    NodeRuntime,
    Vec<Rc<RefCell<NativeState>>>,
    RuntimeCustodyQueue,
) {
    let (mut runtime, states) = runtime(OperatingMode::Exact);
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    runtime.custody_slot = Some(
        queue
            .reserve_world(runtime.barrier.record(), runtime.limits)
            .unwrap(),
    );
    (runtime, states, queue)
}

#[test]
fn unsupported_owner_keeps_original_slot_and_never_calls_legacy_quarantine() {
    let (runtime, states, queue) = queued_runtime();
    let mut original = Some(runtime);

    assert!(matches!(
        NodeRuntime::take_graceful_retirement(&mut original),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert!(original.as_ref().unwrap().graceful_retirement);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().graceful_calls == 0)
    );

    drop(original);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 1);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().quarantine_calls == 0)
    );
}

#[test]
fn first_hook_unwind_preserves_world_purpose_before_later_adapter_intent() {
    let (runtime, states, queue) = queued_runtime();
    for state in &states {
        state.borrow_mut().graceful_available = true;
    }
    states[0].borrow_mut().graceful_panics = true;
    let mut original = Some(runtime);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = NodeRuntime::take_graceful_retirement(&mut original);
    }));

    assert!(result.is_err());
    assert!(original.is_none());
    assert_eq!(states[0].borrow().graceful_calls, 1);
    assert_eq!(states[1].borrow().graceful_calls, 0);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().quarantine_calls == 0)
    );
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 1);
}

#[test]
fn actual_model_reclamation_does_not_release_original_history_credit() {
    let (runtime, states, queue) = queued_runtime();
    for state in &states {
        state.borrow_mut().graceful_available = true;
    }
    let mut original = Some(runtime);

    let mut retired = NodeRuntime::take_graceful_retirement(&mut original).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        retired.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(retired.remaining_owners(), 0);
    assert!(retired.shutdown_failure().is_none());
    assert!(
        states
            .iter()
            .all(|state| state.borrow().graceful_calls == 1)
    );

    drop(retired);
    assert!(matches!(
        queue.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 1);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().quarantine_calls == 0)
    );
}

fn reclaimed_original(
    transfer: bool,
) -> (
    Option<QuarantinedRuntime>,
    WorldActivation,
    RuntimeCustodyQueue,
    Vec<Rc<RefCell<NativeState>>>,
) {
    let (mut runtime, states, queue) = queued_runtime();
    let activation = activate(&mut runtime);
    for state in &states {
        state.borrow_mut().graceful_available = true;
    }
    let mut original = Some(runtime);
    let mut retired = NodeRuntime::take_graceful_retirement(&mut original).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        retired.poll_reclamation(&mut context),
        Poll::Ready(Ok(()))
    ));
    if transfer {
        retired.transfer_retirement_resources().unwrap();
    }
    (Some(retired), activation, queue, states)
}

struct DefaultRelease;

impl crate::node_contract::GracefulRetirementQualification for DefaultRelease {}

struct ModelRelease {
    calls: std::cell::Cell<usize>,
    refusal: bool,
    unwind: bool,
}

impl crate::node_contract::GracefulRetirementQualification for ModelRelease {
    fn authenticate_release(
        &self,
        original: &QuarantinedRuntime,
        _: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(original.remaining_owners(), 0);
        assert!(!self.unwind, "authored installed release callback unwind");
        if self.refusal {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(())
    }
}

#[test]
fn default_release_refuses_after_actual_model_transfer_and_keeps_all_credit() {
    let (mut original, activation, queue, states) = reclaimed_original(true);

    assert!(matches!(
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut original,
            &activation,
            &DefaultRelease,
        ),
        Err(RuntimeError::UnsupportedFacet)
    ));
    assert!(original.is_some());
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().retirement_transfer_calls == 1)
    );
    assert!(
        states
            .iter()
            .all(|state| state.borrow().quarantine_calls == 0)
    );
}

#[test]
fn foreign_equal_activation_and_missing_transfer_refuse_before_installed_callback() {
    let (mut original, activation, queue, _) = reclaimed_original(false);
    let (mut foreign, _) = runtime(OperatingMode::Exact);
    let foreign_activation = activate(&mut foreign);
    assert_eq!(activation.record(), foreign_activation.record());
    let qualification = ModelRelease {
        calls: std::cell::Cell::new(0),
        refusal: false,
        unwind: false,
    };

    assert!(
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut original,
            &foreign_activation,
            &qualification,
        )
        .is_err()
    );
    assert!(matches!(
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut original,
            &activation,
            &qualification,
        ),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert_eq!(qualification.calls.get(), 0);
    assert!(original.is_some());
    assert_eq!(queue.reserved_worlds(), 1);
}

#[test]
fn release_refusal_and_callback_unwind_retain_the_same_original_capsule() {
    let (mut original, activation, queue, states) = reclaimed_original(true);
    let before = original.as_ref().unwrap() as *const QuarantinedRuntime;
    let refused = ModelRelease {
        calls: std::cell::Cell::new(0),
        refusal: true,
        unwind: false,
    };

    assert!(
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut original,
            &activation,
            &refused,
        )
        .is_err()
    );
    assert_eq!(refused.calls.get(), 1);
    let unwind = ModelRelease {
        calls: std::cell::Cell::new(0),
        refusal: false,
        unwind: true,
    };
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = QuarantinedRuntime::release_after_authenticated_supervision(
                &mut original,
                &activation,
                &unwind,
            );
        }))
        .is_err()
    );

    assert_eq!(
        original.as_ref().unwrap() as *const QuarantinedRuntime,
        before
    );
    assert_eq!(unwind.calls.get(), 1);
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().graceful_calls == 1)
    );
    assert!(
        states
            .iter()
            .all(|state| state.borrow().quarantine_calls == 0)
    );
}

#[test]
fn explicit_model_release_frees_only_the_original_slot_once() {
    let (mut original, activation, queue, states) = reclaimed_original(true);
    let qualification = ModelRelease {
        calls: std::cell::Cell::new(0),
        refusal: false,
        unwind: false,
    };

    QuarantinedRuntime::release_after_authenticated_supervision(
        &mut original,
        &activation,
        &qualification,
    )
    .unwrap();
    assert!(original.is_none());
    assert_eq!(queue.reserved_worlds(), 0);
    assert_eq!(queue.retained_worlds(), 0);
    assert_eq!(qualification.calls.get(), 1);
    assert!(
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut original,
            &activation,
            &qualification,
        )
        .is_err()
    );
    assert_eq!(qualification.calls.get(), 1);
    assert!(
        states
            .iter()
            .all(|state| state.borrow().retirement_transfer_calls == 1)
    );
    assert!(
        states
            .iter()
            .all(|state| state.borrow().quarantine_calls == 0)
    );
}
