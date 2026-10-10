//! Exercises actual saved-original joins and retained worker handles.

use super::*;
use crate::executor_pool::original_retirement::OriginalPoolRetirementError;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};

#[test]
fn original_retirement_joins_actual_idle_workers_before_returning() {
    let epoch = DaemonEpoch::from_bytes([0x6a; 16]).expect("epoch");
    let mut pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    );
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .expect("component original");
    let original = supervisor
        .begin(HostOperationClass::Preparation)
        .expect("saved original");

    pool.try_retire_original(&original).expect("physical join");

    assert!(pool.workers.is_empty());
    assert!(pool.service.shared.completion.is_finished());
    assert_eq!(pool.service().report().expect("stopped report").active(), 0);
    assert!(pool.try_retire_original(&original).is_ok());
}

#[test]
fn canceled_original_refuses_before_pool_shutdown_or_handle_removal() {
    let epoch = DaemonEpoch::from_bytes([0x6b; 16]).expect("epoch");
    let mut pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    );
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .expect("component original");
    let original = supervisor
        .begin(HostOperationClass::Preparation)
        .expect("saved original");
    supervisor.cancel().expect("cancel saved original");

    assert!(matches!(
        pool.try_retire_original(&original),
        Err(OriginalPoolRetirementError::Original(_))
    ));
    assert_eq!(pool.workers.len(), 1);
    assert_eq!(
        pool.service.shared.state.load(Ordering::Acquire),
        POOL_RUNNING
    );

    // The fixture explicitly joins its idle worker. This ordinary cleanup is
    // not success or restored permission under the canceled original.
    pool.shutdown_and_join().expect("fixture cleanup");
}

#[test]
fn running_work_refuses_retirement_without_canceling_or_losing_its_owner() {
    let epoch = DaemonEpoch::from_bytes([0x6c; 16]).expect("epoch");
    let state = Arc::new((
        Mutex::new(DelayedCancellationState::default()),
        Condvar::new(),
    ));
    let mut pool = pool(
        epoch,
        vec![DelayedCancellationWorker {
            state: Arc::clone(&state),
        }],
    );
    pool.service()
        .submit_attempt(&request(epoch, 0x6c))
        .expect("actual worker request");
    wait_until(Duration::from_secs(2), || {
        state.0.lock().expect("state").entered
    });
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )
    .expect("finite component original");
    let original = supervisor
        .begin(HostOperationClass::Preparation)
        .expect("saved original");

    assert!(matches!(
        pool.try_retire_original(&original),
        Err(OriginalPoolRetirementError::Occupied { .. })
    ));
    assert_eq!(pool.workers.len(), 1);
    assert!(!pool.workers[0].is_finished());
    assert_eq!(
        pool.service().report().expect("retained report").active(),
        1
    );
    assert_eq!(
        pool.service.shared.state.load(Ordering::Acquire),
        POOL_RUNNING
    );
    assert!(!state.0.lock().expect("state").canceled);

    pool.request_shutdown();
    {
        let mut state = state.0.lock().expect("release fixture");
        state.release = true;
    }
    state.1.notify_all();
    pool.shutdown_and_join()
        .expect("fixture cleanup after release");
}

#[test]
fn retired_pool_drop_does_not_reenter_shutdown_through_a_live_alias_lock() {
    let epoch = DaemonEpoch::from_bytes([0x6d; 16]).expect("epoch");
    let mut pool = pool(
        epoch,
        vec![SequencedFailureWorker {
            calls: Arc::new(AtomicUsize::new(0)),
        }],
    );
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)
        .expect("component original");
    let original = supervisor
        .begin(HostOperationClass::Preparation)
        .expect("saved original");
    pool.try_retire_original(&original)
        .expect("actual joined pool");
    let service = pool.service();
    let lock = service
        .shared
        .executor
        .lock()
        .expect("surviving alias lock");
    let (done, observed) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        drop(pool);
        done.send(()).expect("retirement observed");
    });

    let outcome = observed.recv_timeout(Duration::from_secs(2));
    drop(lock);
    worker.join().expect("fixture body-drop worker");
    assert!(
        outcome.is_ok(),
        "retired body reacquired ordinary shutdown lock"
    );
}
