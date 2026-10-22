//! Component custody controls; no Main, Source or native issuance is modeled.

use super::*;
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use std::sync::atomic::AtomicUsize;

#[derive(Debug, PartialEq, Eq)]
struct CleanupRefusal(u8);

struct Worker {
    fail_once: bool,
    fail_until: Option<Arc<AtomicBool>>,
    dropped: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

impl LocalAttemptWorker for Worker {
    type Error = CleanupRefusal;

    fn execute(&mut self, _: QueuedAttempt) -> crate::AttemptWorkResult<Self::Error> {
        panic!("custody control does not execute a campaign");
    }

    fn try_retire_original(&mut self, _: &HostOperationGuard) -> Result<(), Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if std::mem::take(&mut self.fail_once)
            || self
                .fail_until
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Err(CleanupRefusal(7))
        } else {
            Ok(())
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn thread_exit_keeps_worker_until_explicit_retirement_and_preserves_typed_history()
-> Result<(), Box<dyn std::error::Error>> {
    let dropped = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let prepared = PreparedExecutorWorkers::component(
        vec![Worker {
            fail_once: true,
            fail_until: None,
            dropped: dropped.clone(),
            calls: calls.clone(),
        }],
        0,
    );
    let (mut cells, custody) = prepared.into_cells();
    let startup = WorkerStartup(custody.clone());
    let cell = cells.pop().unwrap();
    let (ready, received) = std::sync::mpsc::sync_channel(1);
    let (release, released) = std::sync::mpsc::sync_channel(1);
    cell.scheduled();
    let thread_cell = cell.clone();
    let handle = thread::spawn(move || {
        let _exit = WorkerBorrowExit(&thread_cell.borrowed);
        let mut state = thread_cell.state.lock().unwrap();
        let _borrow = state.worker.as_mut().unwrap();
        ready.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    custody.retain_thread(handle);
    drop(startup);
    received.recv_timeout(Duration::from_secs(2))?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;

    assert!(matches!(
        custody.verify_retired(),
        Err(WorkerRetirementRefusal::Pending)
    ));
    assert!(matches!(
        custody.try_retire_original(&original),
        Err(WorkerRetirementRefusal::Pending)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    release.send(())?;
    while !custody.threads_finished() {
        thread::park_timeout(original.wait_slice()?.min(Duration::from_millis(1)));
    }
    assert_eq!(dropped.load(Ordering::SeqCst), 0);

    assert!(matches!(
        custody.try_retire_original(&original),
        Err(WorkerRetirementRefusal::Resources)
    ));
    assert_eq!(cell.state.lock().unwrap().first, Some(CleanupRefusal(7)));
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    assert!(matches!(
        custody.try_retire_original(&original),
        Err(WorkerRetirementRefusal::Historical)
    ));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(custody.verify_retired().is_ok());
    assert!(cell.state.lock().unwrap().worker.is_none());
    assert_eq!(cell.state.lock().unwrap().first, Some(CleanupRefusal(7)));
    custody.try_retire_original(&original)?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(custody.threads.lock().unwrap().is_empty());
    Ok(())
}

struct ReentrantWorker {
    directory: Arc<Mutex<Weak<ExecutorWorkerCustody>>>,
    original: Arc<HostOperationGuard>,
    hook_observed_pending: Arc<AtomicBool>,
    drop_observed_pending: Arc<AtomicBool>,
}

impl LocalAttemptWorker for ReentrantWorker {
    type Error = ();

    fn execute(&mut self, _: QueuedAttempt) -> crate::AttemptWorkResult<()> {
        panic!("custody control does not execute a campaign");
    }

    fn try_retire_original(&mut self, original: &HostOperationGuard) -> Result<(), ()> {
        let directory = self.directory.lock().unwrap().upgrade().unwrap();
        self.hook_observed_pending.store(
            matches!(
                directory.try_retire_original(original),
                Err(WorkerRetirementRefusal::Pending)
            ),
            Ordering::SeqCst,
        );
        Ok(())
    }
}

impl Drop for ReentrantWorker {
    fn drop(&mut self) {
        let directory = self.directory.lock().unwrap().upgrade().unwrap();
        self.drop_observed_pending.store(
            matches!(
                directory.try_retire_original(&self.original),
                Err(WorkerRetirementRefusal::Pending)
            ),
            Ordering::SeqCst,
        );
    }
}

#[test]
fn hook_and_actual_destruction_reentry_cannot_release_or_deadlock_the_same_cell()
-> Result<(), Box<dyn std::error::Error>> {
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = Arc::new(supervisor.begin(HostOperationClass::Cleanup)?);
    let directory = Arc::new(Mutex::new(Weak::new()));
    let hook = Arc::new(AtomicBool::new(false));
    let destruction = Arc::new(AtomicBool::new(false));
    let prepared = PreparedExecutorWorkers::component(
        vec![ReentrantWorker {
            directory: directory.clone(),
            original: original.clone(),
            hook_observed_pending: hook.clone(),
            drop_observed_pending: destruction.clone(),
        }],
        0,
    );
    let custody = prepared.custody.clone();
    *directory.lock().unwrap() = Arc::downgrade(&custody);
    drop(prepared);

    custody.try_retire_original(&original)?;
    assert!(hook.load(Ordering::SeqCst));
    assert!(destruction.load(Ordering::SeqCst));
    custody.try_retire_original(&original)?;
    Ok(())
}

#[test]
fn historical_first_body_cannot_hide_a_second_retained_worker()
-> Result<(), Box<dyn std::error::Error>> {
    let dropped = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let second_refuses = Arc::new(AtomicBool::new(true));
    let prepared = PreparedExecutorWorkers::component(
        vec![
            Worker {
                fail_once: true,
                fail_until: None,
                dropped: dropped.clone(),
                calls: calls.clone(),
            },
            Worker {
                fail_once: false,
                fail_until: Some(second_refuses.clone()),
                dropped: dropped.clone(),
                calls: calls.clone(),
            },
        ],
        0,
    );
    let custody = prepared.custody.clone();
    drop(prepared);
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(2)),
    )?;
    let original = supervisor.begin(HostOperationClass::Cleanup)?;

    assert!(matches!(
        custody.try_retire_original(&original),
        Err(WorkerRetirementRefusal::Resources)
    ));
    assert!(matches!(
        custody.try_retire_original(&original),
        Err(WorkerRetirementRefusal::Historical)
    ));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(matches!(
        custody.verify_retired(),
        Err(WorkerRetirementRefusal::Pending)
    ));

    second_refuses.store(false, Ordering::Release);
    assert!(matches!(
        custody.try_retire_original(&original),
        Err(WorkerRetirementRefusal::Historical)
    ));
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert!(custody.verify_retired().is_ok());
    Ok(())
}

#[test]
fn worker_admission_joins_unbuilt_producer_geometry_in_the_same_single_reservation() {
    let producer = 12_345u64;
    let expected = PreparedExecutorWorkers::<Worker>::control_bytes(1, 2)
        .expect("component worker geometry")
        .checked_add(producer)
        .expect("checked total");
    let calls = AtomicUsize::new(0);
    let prepared = PreparedExecutorWorkers::<Worker>::prepare(1, 2, producer, None, |bytes| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(bytes, expected);
        Ok(None)
    })
    .expect("unissued component custody");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        prepared.cells.is_empty(),
        "worker bodies must be constructed later"
    );
    assert!(
        prepared.controls().is_none(),
        "component cannot fabricate Main payment"
    );
    drop(prepared);
}
