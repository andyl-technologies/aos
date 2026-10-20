//! Checks real Host clock observations and rejection of unissued return selectors.
//!
//! The negative selector fixtures do not create funded subscriptions or Native
//! physical loans. They exercise rejection before any operation is retired.

// crucible-lint: allow panic-shortcut -- causal test fixtures panic to localize clock, custody and wire regressions.
#![allow(clippy::unwrap_used)]

use super::*;

fn binding() -> ActionBinding {
    ActionBinding {
        cap: [1; 32],
        reservation: [2; 32],
        account_generation: 1,
        process_generation: 1,
        loan_sequence: 2,
        token: 0,
        capture: Some(1),
        park_request: None,
        frontier: 7,
    }
}

fn observe(guard: &HostOperationGuard) -> ActionParent {
    let state = guard.supervisor.lock().unwrap();
    parent_snapshot(&guard.supervisor.shared, &state, guard.id, 0, 0).unwrap()
}

#[test]
fn actual_producing_class_and_entered_clock_survive_live_policy_and_progress() {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let guard = supervisor
        .begin_work(HostOperationClass::FingerprintInitialization, 4)
        .unwrap();
    let initial = observe(&guard);

    let mut changed = HostOperationBudgets::default();
    changed.classes[HostOperationClass::FingerprintInitialization as usize].total_timeout =
        Some(Duration::from_secs(60));
    supervisor.update_budgets(0, changed).unwrap();
    guard.progress(1).unwrap();
    let current = observe(&guard);

    assert_eq!(current.class, 4);
    assert_eq!(current.origin_ns, initial.origin_ns);
    assert_eq!(current.started_ns, initial.started_ns);
    assert_eq!(current.started_revision, initial.started_revision);
    assert_eq!(current.policy_revision, 1);
    assert_eq!(current.completed, 1);
    assert_eq!(current.required, 4);
    assert!(current.progress_ns >= initial.progress_ns);

    supervisor.cancel().unwrap();
    let canceled = observe(&guard);
    assert_eq!(canceled.state, 3);
    assert_eq!(canceled.started_ns, initial.started_ns);
    assert_eq!(canceled.progress_ns, current.progress_ns);
}

#[derive(Debug)]
struct UnissuedPublisher;

impl HostActionPublisher for UnissuedPublisher {
    fn retain_parent(&self, _: ActionBinding, _: u32) -> Result<(), HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn publish_parent(
        &self,
        _: ActionBinding,
        _: u32,
        _: ActionParent,
    ) -> Result<(), HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn publish_outer(
        &self,
        _: ActionBinding,
        _: [u8; 32],
        _: HostOuterCapBinding,
    ) -> Result<(), HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn publish_cohort(
        &self,
        _: ActionBinding,
        _: [ActionParent; 4],
        _: u32,
    ) -> Result<(), HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn action_return(&self, _: ActionBinding) -> Result<ActionReturn, HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn unpublished_return(&self, _: ActionBinding) -> Result<(), HostSupervisionError> {
        Err(HostSupervisionError::Unavailable)
    }

    fn invalidate_action(&self, _: ActionBinding) {}
}

fn unissued_receipt(owner: &HostOperationGuard) -> HostActionReturnReceipt {
    HostActionReturnReceipt {
        shared: Arc::clone(&owner.supervisor.shared),
        operation: owner.id,
        row: 0,
        publisher: Arc::new(UnissuedPublisher),
        journal: ActionReturn {
            binding: binding(),
            first: -5,
            post: 0,
            physical_state: 1,
            returned_mask: 1,
            borrowed_mask: 1,
            row_count: 1,
            progress_kind: 0,
            progress_row: 0,
            progress_ns: 0,
            progress_witness: 0,
        },
    }
}

#[test]
fn equal_operation_ids_from_another_real_owner_cannot_retire_a_selector() {
    let first = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let second = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let first_guard = first.begin(HostOperationClass::Quiescence).unwrap();
    let second_guard = second.begin(HostOperationClass::Quiescence).unwrap();
    assert_eq!(first_guard.id, second_guard.id);

    let mut unissued = HostActionLoan {
        supervisor: first.clone(),
        operation: first_guard.id,
        binding: binding(),
        row: 0,
        returned: false,
    };
    let foreign = unissued_receipt(&second_guard);
    assert!(unissued.return_physical(&foreign).is_err());
    assert!(!unissued.returned);
    assert_eq!(
        first_guard.status().unwrap().state,
        HostOperationState::Running
    );
    assert_eq!(
        second_guard.status().unwrap().state,
        HostOperationState::Running
    );
}

#[test]
fn syntax_without_an_actual_membership_cannot_be_returned_or_reused() {
    let owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let guard = owner.begin(HostOperationClass::Quiescence).unwrap();
    let mut unissued = HostActionLoan {
        supervisor: owner,
        operation: guard.id,
        binding: binding(),
        row: 0,
        returned: false,
    };
    let mut receipt = unissued_receipt(&guard);
    assert!(unissued.return_physical(&receipt).is_err());
    assert!(unissued.observe_physical_return().is_err());
    assert!(unissued.observe_unpublished_return().is_err());
    assert!(!unissued.returned);

    receipt.journal.binding.loan_sequence = 4;
    assert!(unissued.return_physical(&receipt).is_err());
    assert_eq!(guard.status().unwrap().state, HostOperationState::Running);
}

#[test]
fn unpublished_receipt_cannot_replace_missing_or_foreign_membership() {
    let first = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let second = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let first_guard = first.begin(HostOperationClass::Quiescence).unwrap();
    let second_guard = second.begin(HostOperationClass::Quiescence).unwrap();
    let publisher: Arc<dyn HostActionPublisher> = Arc::new(UnissuedPublisher);
    let mut selector = HostActionLoan {
        supervisor: first.clone(),
        operation: first_guard.id,
        binding: binding(),
        row: 0,
        returned: false,
    };
    let mut receipt = HostActionUnpublishedReturnReceipt {
        shared: Arc::clone(&second.shared),
        binding: binding(),
        operation: second_guard.id,
        row: 0,
        publisher,
    };

    assert_eq!(first_guard.id, second_guard.id);
    assert!(selector.return_unpublished(&receipt).is_err());
    receipt.shared = Arc::clone(&first.shared);
    assert!(selector.return_unpublished(&receipt).is_err());
    assert!(selector.observe_unpublished_return().is_err());
    assert!(!selector.returned);
    assert_eq!(
        first_guard.status().unwrap().state,
        HostOperationState::Running
    );
    assert_eq!(
        second_guard.status().unwrap().state,
        HostOperationState::Running
    );
    assert!(UnissuedPublisher.unpublished_return(binding()).is_err());
}

#[test]
fn no_capture_preserves_preparation_class_and_original_clock() {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let guard = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let initial = observe(&guard);
    let mut no_capture = binding();
    no_capture.capture = None;
    let mut parents = [ActionParent::default(); 4];
    parents[0] = initial;
    let observation = crucible_qemu_protocol::boundary_action::ActionObservation {
        binding: no_capture,
        primary_count: 1,
        row_count: 1,
        borrowed_mask: 1,
        projected_mask: 1,
        cohort_current: true,
        parents,
    };

    let bytes = observation.encode().unwrap();
    let decoded = crucible_qemu_protocol::boundary_action::ActionObservation::decode(&bytes).unwrap();
    assert_eq!(decoded.binding.capture, None);
    assert_eq!(decoded.parents[0].class, 12);
    assert_eq!(decoded.parents[0].started_ns, initial.started_ns);
    assert_eq!(decoded.parents[0].origin_ns, initial.origin_ns);
    assert_eq!(guard.status().unwrap().state, HostOperationState::Running);
}

fn unissued_park_receipt(owner: &HostOperationGuard) -> HostParentParkReturnReceipt {
    let mut parked = binding();
    parked.capture = None;
    parked.park_request = Some(9);
    HostParentParkReturnReceipt {
        shared: Arc::clone(&owner.supervisor.shared),
        operation: owner.id,
        row: 0,
        publisher: Arc::new(UnissuedPublisher),
        journal: ParentParkReturn {
            binding: parked,
            first: -5,
            post: -110,
            physical_resolution_mask: 255,
            publication_count: 2,
            pair_view_return_mask: 3,
            original_statuses: [-125, -110],
            operation_status: -5,
            return_status: 0,
            stopped_generation: 11,
            native_generation: 13,
        },
    }
}

#[test]
fn complete_native_views_do_not_construct_a_host_membership() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let guard = supervisor.begin(HostOperationClass::Quiescence).unwrap();
    let receipt = unissued_park_receipt(&guard);
    let mut unissued = HostActionLoan {
        supervisor,
        operation: guard.id,
        binding: receipt.journal.binding,
        row: 0,
        returned: false,
    };

    assert!(unissued.observe_parent_park_return().is_err());
    assert!(unissued.return_parent_park_physical(&receipt).is_err());
    assert!(!unissued.returned);
    assert_eq!(guard.status().unwrap().state, HostOperationState::Running);
    assert_eq!(guard.status().unwrap().completed_work_units, 0);
}

#[test]
fn park_receipt_from_another_real_supervisor_cannot_unlink_equal_operation_id() {
    let first = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let second = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let first_guard = first.begin(HostOperationClass::Quiescence).unwrap();
    let second_guard = second.begin(HostOperationClass::Quiescence).unwrap();
    let foreign = unissued_park_receipt(&second_guard);
    let mut unissued = HostActionLoan {
        supervisor: first,
        operation: first_guard.id,
        binding: foreign.journal.binding,
        row: 0,
        returned: false,
    };
    assert_eq!(first_guard.id, second_guard.id);

    assert!(unissued.return_parent_park_physical(&foreign).is_err());

    assert!(!unissued.returned);
    assert_eq!(
        first_guard.status().unwrap().state,
        HostOperationState::Running
    );
    assert_eq!(
        second_guard.status().unwrap().state,
        HostOperationState::Running
    );
}

#[test]
fn unsupported_publisher_and_control_selectors_never_return_park_memberships() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let guard = supervisor.begin(HostOperationClass::Quiescence).unwrap();
    let mut receipt = unissued_park_receipt(&guard);
    assert!(
        UnissuedPublisher
            .parent_park_return(receipt.journal.binding, 0)
            .is_err()
    );
    let mut unissued = HostActionLoan {
        supervisor,
        operation: guard.id,
        binding: binding(),
        row: 0,
        returned: false,
    };
    receipt.journal.binding = binding();

    assert!(unissued.observe_parent_park_return().is_err());
    assert!(unissued.return_parent_park_physical(&receipt).is_err());
    assert!(!unissued.returned);
}

struct DropProbe<'a> {
    events: &'a std::cell::RefCell<Vec<&'static str>>,
    name: &'static str,
    panic: bool,
}

impl Drop for DropProbe<'_> {
    fn drop(&mut self) {
        self.events.borrow_mut().push(self.name);
        if self.panic {
            panic!("actual body destructor refused completion");
        }
    }
}

#[test]
fn complete_box_destruction_precedes_the_same_credit_return() {
    let events = std::cell::RefCell::new(Vec::new());
    let body = Box::new(DropProbe {
        events: &events,
        name: "body",
        panic: false,
    });
    let credit = std::mem::ManuallyDrop::new(DropProbe {
        events: &events,
        name: "credit",
        panic: false,
    });

    drop_body_before_credit(body, credit);

    assert_eq!(*events.borrow(), ["body", "credit"]);
}

#[test]
fn actual_box_drop_unwind_keeps_credit_sticky() {
    let events = std::cell::RefCell::new(Vec::new());
    let body = Box::new(DropProbe {
        events: &events,
        name: "body",
        panic: true,
    });
    let credit = std::mem::ManuallyDrop::new(DropProbe {
        events: &events,
        name: "credit",
        panic: false,
    });

    let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop_body_before_credit(body, credit);
    }));

    assert!(returned.is_err());
    assert_eq!(*events.borrow(), ["body"]);
}
