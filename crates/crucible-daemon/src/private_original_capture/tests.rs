//! Tests real watcher mechanics without authenticating a PID1 or issuing credit.
//!
//! The internal engine uses actual ordinary original and child supervisors.
//! Its successful controls are not private-origin, prebirth or kernel admission
//! proofs. The used constructor separately refuses these unbound originals.

use std::time::Duration;

use super::*;
use crucible_linux_resource::host_supervision::{
    HOST_OPERATION_CLASS_COUNT, HostOperationBudget, HostOperationState,
};

pub(super) fn budgets(preparation: Duration) -> HostOperationBudgets {
    let mut budgets = HostOperationBudgets {
        classes: [HostOperationBudget::finite(Duration::from_secs(10)); HOST_OPERATION_CLASS_COUNT],
    };
    budgets.classes[HostOperationClass::Preparation as usize] =
        HostOperationBudget::finite(preparation);
    budgets
}

pub(super) fn original(
    preparation: Duration,
) -> (HostOperationSupervisor, Arc<HostOperationGuard>) {
    let owner =
        HostOperationSupervisor::new(budgets(preparation), Some(Duration::from_secs(10))).unwrap();
    let guard = Arc::new(owner.begin(HostOperationClass::Preparation).unwrap());
    (owner, guard)
}

pub(super) fn engine(
    owner: &HostOperationSupervisor,
    original: Arc<HostOperationGuard>,
    child_preparation: Duration,
    cancellation: ExecutionCancellation,
) -> OriginalCaptureWatchdog {
    let child = owner.new_budget_owner(budgets(child_preparation)).unwrap();
    OriginalCaptureWatchdog::start_child(original, child, cancellation).unwrap()
}

#[test]
fn used_constructor_refuses_unbound_original_and_equal_independent_owner() {
    let (owner, guard) = original(Duration::from_secs(10));
    let independent = HostOperationSupervisor::new(budgets(Duration::from_secs(10)), None).unwrap();

    for supplied in [&owner, &independent] {
        assert!(matches!(
            OriginalCaptureWatchdog::start(
                Arc::clone(&guard),
                supplied,
                budgets(Duration::from_secs(10)),
                ExecutionCancellation::default(),
            ),
            Err(OriginalCaptureStartError::Derivation(
                OriginalCaptureSupervisionError::Original(HostSupervisionError::InvalidBudget)
            ))
        ));
    }
    assert!(guard.wait_slice().is_ok());
}

#[test]
fn actual_child_stop_and_repeated_captures_leave_original_running() {
    let (owner, guard) = original(Duration::from_secs(10));
    let binding = owner.outer_cap_binding().unwrap();
    let original_status = guard.status().unwrap();

    for _ in 0..4 {
        let cancellation = ExecutionCancellation::default();
        let mut watcher = engine(
            &owner,
            Arc::clone(&guard),
            Duration::from_secs(10),
            cancellation.clone(),
        );
        let completion = watcher.finish();
        assert!(completion.accepted(), "{completion:?}");
        assert_eq!(watcher.finish(), completion);
        assert!(!cancellation.is_canceled());
        let retained = guard.status().unwrap();
        assert_eq!(retained.operation_id, original_status.operation_id);
        assert_eq!(retained.class, original_status.class);
        assert_eq!(retained.state, HostOperationState::Running);
        assert_eq!(retained.completed_work_units, 0);
        assert!(
            retained.effective_deadline.unwrap().remaining
                <= original_status
                    .effective_deadline
                    .as_ref()
                    .unwrap()
                    .remaining
        );
        assert_eq!(owner.outer_cap_binding().unwrap(), binding);
        assert!(guard.wait_slice().is_ok());
    }
}

#[test]
fn actual_original_cancellation_remains_typed_after_join() {
    let (owner, guard) = original(Duration::from_secs(10));
    let cancellation = ExecutionCancellation::default();
    let observer = cancellation.observer_for_test().unwrap();
    let mut watcher = engine(&owner, guard, Duration::from_secs(10), cancellation);

    owner.cancel().unwrap();
    assert!(observer.wait_for_cancellation(Duration::from_secs(2)));
    let completion = watcher.finish();
    assert!(!completion.accepted());
    assert_eq!(
        completion.original_before,
        Some(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        })
    );
    assert_eq!(completion.original_after, completion.original_before);
    assert!(!completion.join_panicked);
}

#[test]
fn actual_whole_family_expiry_does_not_turn_into_child_or_join_failure() {
    let (owner, guard) = original(Duration::from_millis(40));
    let original_id = guard.status().unwrap().operation_id;
    let cancellation = ExecutionCancellation::default();
    let observer = cancellation.observer_for_test().unwrap();
    let mut watcher = engine(&owner, guard, Duration::from_secs(10), cancellation);

    assert!(observer.wait_for_cancellation(Duration::from_secs(2)));
    let completion = watcher.finish();
    assert!(matches!(
        completion.watcher,
        Some(OriginalCaptureWatcherRefusal::Original(
            HostSupervisionError::DeadlineExpired {
                operation_id,
                class: HostOperationClass::Preparation,
            }
        )) if operation_id == original_id
    ));
    assert!(completion.original_before.is_some());
    assert!(completion.original_after.is_some());
    assert!(!completion.join_panicked);
}

#[test]
fn actual_child_expiry_keeps_original_prep_live_and_first_child_refusal() {
    let (owner, guard) = original(Duration::from_secs(10));
    let cancellation = ExecutionCancellation::default();
    let observer = cancellation.observer_for_test().unwrap();
    let mut watcher = engine(
        &owner,
        Arc::clone(&guard),
        Duration::from_millis(40),
        cancellation,
    );

    assert!(observer.wait_for_cancellation(Duration::from_secs(2)));
    let completion = watcher.finish();
    assert!(matches!(
        completion.watcher,
        Some(OriginalCaptureWatcherRefusal::CaptureWait {
            source: HostSupervisionError::DeadlineExpired {
                class: HostOperationClass::Preparation,
                ..
            },
            original_after: None,
        })
    ));
    assert!(completion.child.is_some());
    assert_eq!(completion.original_before, None);
    assert_eq!(completion.original_after, None);
    assert!(guard.wait_slice().is_ok());
}

#[test]
fn actual_guard_alias_survives_caller_drop_until_watcher_drop() {
    let (owner, guard) = original(Duration::from_secs(10));
    let weak = Arc::downgrade(&guard);
    let watcher = engine(
        &owner,
        guard,
        Duration::from_secs(10),
        ExecutionCancellation::default(),
    );
    assert!(weak.upgrade().is_some());

    drop(watcher);
    assert!(weak.upgrade().is_none());
    assert!(owner.verify_original_live().is_ok());
    // Weak and Arc identity are alias mechanics only, not original paid free.
}

#[test]
fn actual_join_panic_is_not_labeled_deadline_expiration() {
    let (owner, guard) = original(Duration::from_secs(10));
    let child = owner
        .new_budget_owner(budgets(Duration::from_secs(10)))
        .unwrap();
    let cancellation = ExecutionCancellation::default();
    let mut watcher = OriginalCaptureWatchdog {
        operation: child.begin(HostOperationClass::Preparation).unwrap(),
        original: guard,
        stopped: Arc::new(AtomicBool::new(false)),
        refusal: Arc::new(OnceLock::new()),
        cancellation: cancellation.clone(),
        watcher: Some(thread::spawn(|| panic!("actual watcher join control"))),
        completion: None,
    };

    let completion = watcher.finish();
    assert!(completion.join_panicked);
    assert_eq!(completion.original_before, None);
    assert_eq!(completion.original_after, None);
    assert_eq!(completion.child, None);
    assert_eq!(completion.watcher, None);
    assert!(cancellation.is_canceled());
}

#[test]
fn actual_target_geometry_is_reported_without_a_payment_claim() {
    println!(
        "watchdog={} align={} completion={} start_error={} refusal_control={} stopped_control={} original_guard={}",
        size_of::<OriginalCaptureWatchdog>(),
        align_of::<OriginalCaptureWatchdog>(),
        size_of::<OriginalCaptureCompletion>(),
        size_of::<OriginalCaptureStartError>(),
        size_of::<OnceLock<OriginalCaptureWatcherRefusal>>(),
        size_of::<AtomicBool>(),
        size_of::<HostOperationGuard>(),
    );
}

/// Pauses only the real observed-error publication cut in the mechanism test.
pub(super) struct RefusalPublicationCut {
    reached: std::sync::mpsc::SyncSender<()>,
    release: AtomicBool,
}

impl RefusalPublicationCut {
    pub(super) fn release(&self) {
        self.release.store(true, Ordering::Release);
    }

    pub(super) fn pause_before_publication(&self) {
        self.reached.send(()).unwrap();
        while !self.release.load(Ordering::Acquire) {
            thread::yield_now();
        }
    }
}

// Release precedes the watcher's automatic join on any test assertion unwind.
struct PublicationRelease(Arc<RefusalPublicationCut>);

impl Drop for PublicationRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

// crucible-lint: allow rust-allow -- Host monotonic time only bounds the test interlock; it never enters campaign state.
#[allow(clippy::disallowed_methods)]
#[test]
fn observed_sibling_setup_refusal_survives_later_cancel_and_finish() {
    let (owner, guard) = original(Duration::from_secs(10));
    let mut sibling_budgets = budgets(Duration::from_secs(10));
    sibling_budgets.classes[HostOperationClass::Setup as usize] =
        HostOperationBudget::finite(Duration::from_millis(40));
    let sibling = owner.new_budget_owner(sibling_budgets).unwrap();
    let setup = sibling.begin(HostOperationClass::Setup).unwrap();
    let expected = HostSupervisionError::DeadlineExpired {
        operation_id: setup.status().unwrap().operation_id,
        class: HostOperationClass::Setup,
    };
    let child = owner
        .new_budget_owner(budgets(Duration::from_secs(10)))
        .unwrap();
    let (reached, observed) = std::sync::mpsc::sync_channel(1);
    let cut = Arc::new(RefusalPublicationCut {
        reached,
        release: AtomicBool::new(false),
    });
    let mut watcher = OriginalCaptureWatchdog::start_child_observed(
        Arc::clone(&guard),
        child,
        ExecutionCancellation::default(),
        Some(Arc::clone(&cut)),
    )
    .unwrap();
    let _publication_release = PublicationRelease(Arc::clone(&cut));
    let stopped = Arc::clone(&watcher.stopped);

    // The sibling roster is genuinely scanned, while both Preparation guards
    // remain live. Shutdown begins only after that exact Setup error exists.
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(guard.wait_slice().is_ok());
    owner.cancel().unwrap();
    let finish = thread::spawn(move || watcher.finish());
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while !stopped.load(Ordering::Acquire) {
        assert!(
            std::time::Instant::now() < until,
            "finish did not request stop"
        );
        thread::yield_now();
    }
    cut.release();
    let completion = finish.join().unwrap();

    assert_eq!(
        completion.watcher,
        Some(OriginalCaptureWatcherRefusal::CaptureWait {
            source: expected,
            original_after: None,
        })
    );
    assert_eq!(
        completion.original_before,
        Some(HostSupervisionError::Terminal {
            state: HostOperationState::Canceled,
        })
    );
    assert!(!completion.join_panicked);
    // Keep the real sibling roster and its exact Setup authority through join.
    drop(setup);
    drop(sibling);
}
