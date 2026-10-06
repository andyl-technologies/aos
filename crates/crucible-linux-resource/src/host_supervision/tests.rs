//! Behavioral tests for live operational budgets and expiry ordering.

// crucible-lint: allow panic-shortcut -- test fixtures panic to localize invalid supervision and lock assumptions.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn native_cap_bindings_preserve_kernel_origin_across_owners_and_amendments() {
    let root = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let initial = root.outer_cap_binding().unwrap();
    let child = root
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();

    root.amend_outer_cap(0, Some(Duration::from_secs(60)))
        .unwrap();
    let amended = child.outer_cap_binding().unwrap();

    assert_ne!(initial.original_monotonic_ns, 0);
    assert_eq!(amended.original_monotonic_ns, initial.original_monotonic_ns);
    assert_eq!(amended.cap_id, initial.cap_id);
    assert_eq!(amended.revision, 1);
    assert_eq!(amended.allowance, Some(Duration::from_secs(60)));
}

#[test]
fn service_supervision_ignores_idle_lifetime_but_detects_child_operation_expiry() {
    let root = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    assert!(root.wait_for_active_work_change().is_ok());
    assert!(root.operation_statuses().unwrap().is_empty());
    let child = root
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    let operation = child.begin(HostOperationClass::PageIn).unwrap();
    child
        .lock()
        .unwrap()
        .operations
        .get_mut(&operation.id)
        .unwrap()
        .state = HostOperationState::Expired;

    assert!(matches!(
        root.wait_for_active_work_change(),
        Err(HostSupervisionError::DeadlineExpired {
            class: HostOperationClass::PageIn,
            ..
        })
    ));
}

#[test]
fn independent_node_budgets_share_original_outer_authority() {
    let root = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let first = root
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    let second = root
        .new_budget_owner(HostOperationBudgets::default())
        .unwrap();
    let first_guard = first.begin(HostOperationClass::PageIn).unwrap();
    let second_guard = second.begin(HostOperationClass::PageIn).unwrap();
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::PageIn as usize].total_timeout =
        Some(Duration::from_secs(60));

    first.update_budgets(0, budgets).unwrap();
    assert_eq!(first_guard.status().unwrap().applied_policy_revision, 1);
    assert_eq!(second_guard.status().unwrap().applied_policy_revision, 0);
    assert!(root.shares_outer_cap(&first));
    assert_eq!(first.cap_id(), second.cap_id());

    root.amend_outer_cap(0, Some(Duration::from_secs(120)))
        .unwrap();
    assert_eq!(first.outer_cap_status().unwrap().revision, 1);
    assert_eq!(
        second.outer_cap_status().unwrap().allowance,
        Some(Duration::from_secs(120))
    );
    root.cancel().unwrap();
    assert_eq!(
        first_guard.status().unwrap().state,
        HostOperationState::Canceled
    );
    assert_eq!(
        second_guard.status().unwrap().state,
        HostOperationState::Canceled
    );
}

#[test]
fn removing_outer_cap_validates_every_live_node_roster() {
    let root = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::PageIn as usize] = HostOperationBudget::unlimited_quantum();
    let node = root.new_budget_owner(budgets).unwrap();

    assert!(matches!(
        root.amend_outer_cap(0, None),
        Err(HostSupervisionError::UnboundedInfrastructure { .. })
    ));
    node.update_budgets(0, HostOperationBudgets::default())
        .unwrap();
    assert_eq!(root.amend_outer_cap(0, None).unwrap(), 1);
}

#[test]
fn infrastructure_cannot_lose_its_last_bound_and_cleanup_is_independent() {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::PageIn as usize] = HostOperationBudget::unlimited_quantum();

    assert!(matches!(
        HostOperationSupervisor::new(budgets, None),
        Err(HostSupervisionError::UnboundedInfrastructure {
            class: HostOperationClass::PageIn
        })
    ));
    let supervisor = HostOperationSupervisor::new(budgets, Some(Duration::from_secs(10))).unwrap();
    assert!(matches!(
        supervisor.amend_outer_cap(0, None),
        Err(HostSupervisionError::UnboundedInfrastructure { .. })
    ));
    budgets.classes[HostOperationClass::Cleanup as usize] =
        HostOperationBudget::unlimited_quantum();
    assert!(matches!(
        supervisor.update_budgets(0, budgets),
        Err(HostSupervisionError::UnboundedInfrastructure {
            class: HostOperationClass::Cleanup
        })
    ));
}

#[test]
fn live_budget_updates_retain_original_operation_and_progress_coordinates() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let guard = supervisor.begin(HostOperationClass::PageIn).unwrap();
    let original = {
        let state = supervisor.lock().unwrap();
        let operation = state.operations.get(&guard.id).unwrap();
        (operation.started, operation.last_progress)
    };
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::PageIn as usize].total_timeout =
        Some(Duration::from_secs(120));

    assert_eq!(supervisor.update_budgets(0, budgets).unwrap(), 1);
    let status = guard.status().unwrap();
    assert_eq!(status.started_policy_revision, 0);
    assert_eq!(status.applied_policy_revision, 1);
    let state = supervisor.lock().unwrap();
    let operation = state.operations.get(&guard.id).unwrap();
    assert_eq!((operation.started, operation.last_progress), original);
}

#[test]
fn elapsed_cap_wins_amendment_without_a_watcher() {
    let mut supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(1)),
    )
    .unwrap();
    Arc::get_mut(&mut supervisor.shared).unwrap().started = host_now() - Duration::from_secs(2);

    assert!(matches!(
        supervisor.amend_outer_cap(0, Some(Duration::from_secs(60))),
        Err(HostSupervisionError::Terminal {
            state: HostOperationState::Expired
        })
    ));
    assert_eq!(supervisor.outer_cap_status().unwrap().revision, 0);
}

#[test]
fn shortening_below_elapsed_accepts_revision_and_cancels_atomically() {
    let mut supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(60)),
    )
    .unwrap();
    Arc::get_mut(&mut supervisor.shared).unwrap().started = host_now() - Duration::from_secs(2);

    assert_eq!(
        supervisor
            .amend_outer_cap(0, Some(Duration::from_secs(1)))
            .unwrap(),
        1
    );
    let status = supervisor.outer_cap_status().unwrap();
    assert_eq!(status.state, HostOperationState::Expired);
    assert_eq!(status.remaining, Some(Duration::ZERO));
    assert!(supervisor.complete().is_err());
    assert!(supervisor.begin(HostOperationClass::Cleanup).is_ok());
}

#[test]
fn repeated_progress_does_not_renew_a_stalled_operation() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let guard = supervisor.begin(HostOperationClass::Transfer).unwrap();
    guard.progress(1).unwrap();
    let coordinate = supervisor
        .lock()
        .unwrap()
        .operations
        .get(&guard.id)
        .unwrap()
        .last_progress;

    guard.progress(1).unwrap();
    assert_eq!(
        supervisor
            .lock()
            .unwrap()
            .operations
            .get(&guard.id)
            .unwrap()
            .last_progress,
        coordinate
    );
    assert_eq!(
        guard.progress(0),
        Err(HostSupervisionError::ProgressRegressed)
    );
}

#[test]
fn completed_and_canceled_work_cannot_be_revived() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let guard = supervisor.begin(HostOperationClass::PageIn).unwrap();
    guard.complete().unwrap();
    supervisor
        .update_budgets(0, HostOperationBudgets::default())
        .unwrap();
    assert_eq!(guard.status().unwrap().state, HostOperationState::Completed);
    supervisor.cancel().unwrap();
    assert!(matches!(
        supervisor.amend_outer_cap(0, Some(Duration::from_secs(5))),
        Err(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled
        })
    ));
}

#[test]
fn policy_changes_wake_a_waiting_guard() {
    let mut budgets = HostOperationBudgets::default();
    budgets.classes[HostOperationClass::Quantum as usize].poll_interval = Duration::from_secs(60);
    let supervisor = HostOperationSupervisor::new(budgets, None).unwrap();
    let guard = supervisor.begin(HostOperationClass::Quantum).unwrap();
    let worker_supervisor = supervisor.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let state = worker_supervisor.lock().unwrap();
        ready_tx.send(()).unwrap();
        let waited = worker_supervisor
            .shared
            .changed
            .wait_timeout(state, Duration::from_secs(60))
            .unwrap();
        drop(waited);
        done_tx.send(()).unwrap();
    });
    ready_rx.recv().unwrap();

    supervisor
        .update_budgets(0, HostOperationBudgets::default())
        .unwrap();
    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
    assert!(guard.wait_slice().unwrap() <= Duration::from_millis(10));
}

#[test]
fn finite_capacity_is_reclaimed_only_when_guards_are_dropped() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let mut guards = Vec::new();
    for _ in 0..MAX_HOST_WORK_OPERATIONS {
        guards.push(supervisor.begin(HostOperationClass::PageIn).unwrap());
    }
    assert!(matches!(
        supervisor.begin(HostOperationClass::PageIn),
        Err(HostSupervisionError::CapacityExhausted)
    ));
    guards.pop();
    assert!(supervisor.begin(HostOperationClass::PageIn).is_ok());
}

#[test]
fn saturated_work_inventory_retains_two_finite_control_records() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let work = (0..MAX_HOST_WORK_OPERATIONS)
        .map(|_| supervisor.begin(HostOperationClass::PageIn).unwrap())
        .collect::<Vec<_>>();
    let query = supervisor.begin_control(HostOperationClass::Setup).unwrap();
    let containment = supervisor.begin(HostOperationClass::Cleanup).unwrap();

    assert_eq!(query.status().unwrap().class, HostOperationClass::Setup);
    assert!(matches!(
        supervisor.begin_control(HostOperationClass::PageIn),
        Err(HostSupervisionError::InvalidBudget)
    ));
    assert_eq!(
        supervisor.status_snapshot().unwrap().1.len(),
        MAX_HOST_OPERATIONS
    );
    assert!(matches!(
        supervisor.begin(HostOperationClass::Cleanup),
        Err(HostSupervisionError::CapacityExhausted)
    ));
    assert!(work.iter().all(|guard| guard.wait_slice().is_ok()));

    drop(query);
    assert!(supervisor.begin(HostOperationClass::Cleanup).is_ok());
    assert!(containment.wait_slice().is_ok());
}
