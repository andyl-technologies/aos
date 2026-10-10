//! Capacity-one, original readiness and directly held fork-owner controls.

use super::*;
use crate::paged_ram::TransportDeadline;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct StartupQuery {
    calls: AtomicUsize,
    refuse_at: usize,
}

impl StartupQuery {
    fn healthy() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            refuse_at: usize::MAX,
        }
    }
}

impl StartupQuery {
    fn wait_slice(&self) -> Result<Duration, crate::StartupSourceError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call >= self.refuse_at {
            return Err(crate::StartupSourceError::NativeStatus {
                status: -libc::ECANCELED,
            });
        }
        Ok(Duration::from_millis(1))
    }
}

fn work(request: u32) -> LiveFingerprintDigestWork {
    LiveFingerprintDigestWork {
        captured: CapturedFingerprintSample::test_empty(),
        capture_request: request,
    }
}

fn control() -> Arc<FingerprintWorkerControl> {
    Arc::new(FingerprintWorkerControl::new(None))
}

fn wait_blocked(control: &FingerprintWorkerControl, deadline: &TransportDeadline) {
    while control.waiting_producers.load(Ordering::SeqCst) == 0 {
        if deadline.remaining().is_err() {
            control.close();
            panic!("producer did not reach actual capacity wait");
        }
        thread::yield_now();
    }
}

fn worker(control: Arc<FingerprintWorkerControl>) -> LiveFingerprintDigestWorker {
    LiveFingerprintDigestWorker {
        control: Some(control),
        join: None,
        owner_process: std::process::id(),
        fork_workspace: UnsafeCell::new(None),
    }
}

#[test]
fn capacity_one_blocks_then_wakes_producer_without_replacing_first_capture() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let control = control();
    assert!(control.enqueue(work(11)).is_ok());
    let second = Arc::clone(&control);
    let producer = thread::spawn(move || second.enqueue(work(22)));
    wait_blocked(&control, &deadline);

    assert!(!producer.is_finished());
    assert_eq!(control.receive().unwrap().capture_request, 11);
    assert!(producer.join().unwrap().is_ok());
    assert_eq!(control.receive().unwrap().capture_request, 22);
    control.close();
    assert!(control.receive().is_none());
}

#[test]
fn close_drains_pending_capture_and_refuses_new_producer() {
    let control = control();
    assert!(control.enqueue(work(7)).is_ok());
    control.close();

    assert!(control.enqueue(work(8)).is_err());
    assert_eq!(control.receive().unwrap().capture_request, 7);
    assert!(control.receive().is_none());
}

#[test]
fn close_wakes_blocked_producer_without_stealing_pending_capture() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let control = control();
    assert!(control.enqueue(work(7)).is_ok());
    let waiting = Arc::clone(&control);
    let producer = thread::spawn(move || waiting.enqueue(work(8)));
    wait_blocked(&control, &deadline);
    control.close();

    assert!(producer.join().unwrap().is_err());
    assert_eq!(control.receive().unwrap().capture_request, 7);
    assert!(control.receive().is_none());
}

#[test]
fn first_failure_wakes_producer_and_remains_exact_after_later_refusal() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let control = control();
    assert!(control.enqueue(work(3)).is_ok());
    let waiting = Arc::clone(&control);
    let producer = thread::spawn(move || waiting.enqueue(work(4)));
    wait_blocked(&control, &deadline);
    control.refuse(FingerprintWorkerCause::CaptureChanged { request: 91 });
    control.refuse(FingerprintWorkerCause::Panic);

    assert!(producer.join().unwrap().is_err());
    assert!(control.receive().is_none());
    assert!(matches!(
        control.lock().failure,
        Some(FingerprintWorkerCause::CaptureChanged { request: 91 })
    ));
    assert_eq!(control.lock().pending.as_ref().unwrap().capture_request, 3);
}

#[test]
fn original_refusal_before_birth_retains_first_cause_without_a_second_poll() {
    let operation = StartupQuery {
        calls: AtomicUsize::new(0),
        refuse_at: 1,
    };
    let mut failure = None;
    assert!(check_setup_before_birth(&mut || operation.wait_slice(), &mut failure).is_err());
    assert!(matches!(failure.as_ref(),
        Some(crate::StartupSourceError::NativeStatus { status })
            if *status == -libc::ECANCELED));

    assert!(check_setup_before_birth(&mut || operation.wait_slice(), &mut failure).is_err());
    assert_eq!(operation.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn actual_spawn_refuses_original_before_control_mapping_and_registration() {
    let slot = FingerprintSampleSlot::new();
    let quiescence = LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL);
    let before = quiescence.snapshot();
    let query = StartupQuery {
        calls: AtomicUsize::new(0),
        refuse_at: 1,
    };
    let mut failure = None;

    let result = LiveFingerprintDigestWorker::spawn(
        StableFingerprintSlotHandle::new(&slot),
        Arc::clone(&quiescence),
        DeviceDigestWorkspace::test_owner(),
        &mut || query.wait_slice(),
        &mut failure,
    );

    assert!(matches!(result,
        Err(LiveVcpuTimeCallbackError::DeviceDigestWorkspace {
            source: DeviceDigestWorkspaceError::StartupSource {
                source: crate::StartupSourceError::NativeStatus { status },
            },
        }) if status == -libc::ECANCELED));
    assert_eq!(
        failure,
        Some(crate::StartupSourceError::NativeStatus {
            status: -libc::ECANCELED,
        })
    );
    assert_eq!(query.calls.load(Ordering::SeqCst), 1);
    assert_eq!(quiescence.snapshot(), before);
    assert_eq!(slot.snapshot(), None);
}

#[test]
fn earlier_capture_failure_keeps_new_original_status_as_secondary() {
    let control = control();
    control.refuse(FingerprintWorkerCause::CaptureChanged { request: 73 });
    let mut worker = worker(Arc::clone(&control));

    let result = worker.wait_registered(|| {
        Err(crate::StartupSourceError::NativeStatus {
            status: -libc::ETIMEDOUT,
        })
    });

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed { .. })
    ));
    assert!(matches!(
        control.lock().failure,
        Some(FingerprintWorkerCause::CaptureChanged { request: 73 })
    ));
    assert_eq!(
        control.lock().supervision_failure,
        Some(crate::StartupSourceError::NativeStatus {
            status: -libc::ETIMEDOUT
        })
    );
    drop(result);
    drop(control);
    worker.retire().unwrap();
}

#[test]
fn registered_readiness_rechecks_same_original_before_acceptance() {
    let control = control();
    control.lock().registered = true;
    let mut worker = worker(Arc::clone(&control));
    let operation = StartupQuery {
        calls: AtomicUsize::new(0),
        refuse_at: 2,
    };
    let result = worker.wait_registered(|| operation.wait_slice());

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed { .. })
    ));
    assert_eq!(operation.calls.load(Ordering::SeqCst), 2);
    assert!(matches!(control.lock().supervision_failure.as_ref(),
        Some(crate::StartupSourceError::NativeStatus { status })
            if *status == -libc::ECANCELED));
    drop(result);
    drop(control);
    worker.retire().unwrap();
}

#[test]
fn real_registration_failure_never_reports_ready() {
    let quiescence = LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL);
    let registration = quiescence.register_current(WORKER_FINGERPRINT).unwrap();
    let slot = FingerprintSampleSlot::new();
    let operation = StartupQuery::healthy();
    let mut failure = None;
    let mut worker = LiveFingerprintDigestWorker::spawn(
        StableFingerprintSlotHandle::new(&slot),
        Arc::clone(&quiescence),
        DeviceDigestWorkspace::test_owner(),
        &mut || operation.wait_slice(),
        &mut failure,
    )
    .unwrap();
    let result = worker.wait_registered(|| operation.wait_slice());

    assert!(matches!(
        result,
        Err(LiveVcpuTimeCallbackError::FingerprintWorkerFailed { .. })
    ));
    let control = worker.control.as_ref().unwrap();
    assert!(!control.lock().registered);
    assert!(matches!(
        control.lock().failure,
        Some(FingerprintWorkerCause::Registration(_))
    ));
    assert_eq!(slot.snapshot(), None);
    drop(result);
    worker.retire().unwrap();
    drop(registration);
}

#[test]
fn queued_capture_is_independent_of_exclusive_workspace_digest_borrow() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let control = control();
    let workspace = control.workspace();
    let queued = Arc::clone(&control);
    let producer = thread::spawn(move || queued.enqueue(work(19)));

    // The queue producer completes while the exclusive workspace mutex remains
    // held. A single shared digest/queue mutex would fail this finite control.
    while !producer.is_finished() && deadline.remaining().is_ok() {
        thread::yield_now();
    }
    let finished_with_workspace_held = producer.is_finished();
    drop(workspace);
    assert!(producer.join().unwrap().is_ok());
    assert!(finished_with_workspace_held);
    assert_eq!(control.receive().unwrap().capture_request, 19);
}

#[test]
fn fork_hold_refuses_pending_job_then_restores_same_owner_before_release() {
    let workspace = DeviceDigestWorkspace::test_owner();
    let descriptor = workspace.descriptor_number().unwrap();
    let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
    let mut worker = worker(Arc::clone(&control));
    assert!(control.enqueue(work(2)).is_ok());
    // SAFETY: this fixture has no worker/callback actors; the pending check is
    // the concrete additional guard, rather than a forged parked-work receipt.
    assert!(unsafe { worker.hold_workspace_for_fork() }.is_err());
    assert!(control.workspace().is_some());
    drop(control.receive().unwrap());
    // SAFETY: the fixture has no outstanding actor or pending work.
    unsafe { worker.hold_workspace_for_fork() }.unwrap();
    assert!(control.workspace().is_none());
    // SAFETY: complete exclusion remains retained through restoration.
    unsafe { worker.restore_workspace_after_fork() }.unwrap();
    assert_eq!(
        control
            .workspace()
            .as_ref()
            .unwrap()
            .descriptor_number()
            .unwrap(),
        descriptor
    );
    drop(control);
    worker.retire().unwrap();
}

#[test]
fn actual_fork_child_disarms_without_inherited_mutex_or_stale_unmap() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let mut workspace = DeviceDigestWorkspace::test_owner();
    workspace.map().unwrap();
    let address = workspace.bytes().unwrap().as_mut_ptr();
    let descriptor = workspace.descriptor_number().unwrap();
    let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
    let mut worker = worker(Arc::clone(&control));
    // SAFETY: no worker/callback exists and all pending work is absent.
    unsafe { worker.hold_workspace_for_fork() }.unwrap();
    let inherited_lock = control.lock();
    // SAFETY: the child uses only direct inherited ownership and libc syscalls,
    // then _exit. It neither locks copied synchronization nor allocates.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut resident = 0_u8;
        // SAFETY: the saved page-aligned address is inspected without dereference; resident is writable.
        let inspected = unsafe { libc::mincore(address.cast(), 4096, &mut resident) };
        // SAFETY: this is the calling Linux thread's errno, saved immediately.
        let absent_errno = unsafe { *libc::__errno_location() };
        let absent = inspected == -1 && absent_errno == libc::ENOMEM;
        let disarmed = worker.disarm_child_workspace().is_ok();
        // SAFETY: F_GETFD inspects the saved descriptor number without a pointer argument.
        let inspected = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        // SAFETY: preserve the exact inspection cause before another syscall.
        let close_errno = unsafe { *libc::__errno_location() };
        let closed = inspected == -1 && close_errno == libc::EBADF;
        // SAFETY: the fork child exits directly without unwinding inherited Rust owners.
        unsafe { libc::_exit(if absent && disarmed && closed { 0 } else { 71 }) };
    }
    let mut status = 0;
    loop {
        // SAFETY: child is the actual fork result and status is writable for this call.
        let observed = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if observed == child {
            break;
        }
        if deadline.remaining().is_err() {
            // SAFETY: child is this test's actual unreaped fork child; the signal has no pointer argument.
            unsafe { libc::kill(child, libc::SIGKILL) };
            // SAFETY: the same unreaped child is joined into valid writable status storage.
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            panic!("child disarm used inherited synchronization");
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    // SAFETY: F_GETFD only inspects the retained descriptor number without taking ownership.
    assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
    drop(inherited_lock);
    // SAFETY: the parent still holds the same complete exclusion.
    unsafe { worker.restore_workspace_after_fork() }.unwrap();
    assert_eq!(
        control
            .workspace()
            .as_mut()
            .unwrap()
            .bytes()
            .unwrap()
            .as_mut_ptr(),
        address
    );
    drop(control);
    worker.retire().unwrap();
}

#[test]
fn normal_worker_registration_joins_before_workspace_and_control_retire() {
    let slot = FingerprintSampleSlot::new();
    let operation = StartupQuery::healthy();
    let mut failure = None;
    let mut worker = LiveFingerprintDigestWorker::spawn(
        StableFingerprintSlotHandle::new(&slot),
        LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
        DeviceDigestWorkspace::test_owner(),
        &mut || operation.wait_slice(),
        &mut failure,
    )
    .unwrap();
    worker.wait_registered(|| operation.wait_slice()).unwrap();
    assert!(worker.control.as_ref().unwrap().lock().registered);
    assert!(operation.calls.load(Ordering::SeqCst) >= 5);

    worker.retire().unwrap();
    assert!(worker.join.is_none());
    assert!(worker.control.is_none());
    assert!(failure.is_none());
}

#[test]
fn surviving_weak_control_prevents_workspace_close_until_actual_alias_release() {
    let workspace = DeviceDigestWorkspace::test_owner();
    let descriptor = workspace.descriptor_number().unwrap();
    let mut worker = worker(Arc::new(FingerprintWorkerControl::new(Some(workspace))));
    let weak = Arc::downgrade(worker.control.as_ref().unwrap());
    let refused = worker.retire().unwrap_err();

    // SAFETY: F_GETFD only inspects the retained descriptor number without taking ownership.
    assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
    assert!(worker.control.as_ref().unwrap().workspace().is_some());
    drop(refused);
    drop(weak);
    worker.retire().unwrap();
    assert!(worker.control.is_none());
}

#[test]
fn source_control_geometry_reports_objects_without_claiming_native_frames_or_payment() {
    println!(
        "DeviceDigestWorkspace={}",
        std::mem::size_of::<DeviceDigestWorkspace>()
    );
    println!(
        "FingerprintWorkerState={}",
        std::mem::size_of::<FingerprintWorkerState>()
    );
    println!(
        "FingerprintWorkerControl={}",
        std::mem::size_of::<FingerprintWorkerControl>()
    );
    println!(
        "LiveFingerprintDigestWork={}",
        std::mem::size_of::<LiveFingerprintDigestWork>()
    );
    println!(
        "LiveFingerprintDigestWorker={}",
        std::mem::size_of::<LiveFingerprintDigestWorker>()
    );
    println!(
        "FingerprintWorkerCause={}",
        std::mem::size_of::<FingerprintWorkerCause>()
    );
    println!(
        "FingerprintWorkerFailure={}",
        std::mem::size_of::<FingerprintWorkerFailure>()
    );
    println!(
        "MutexState={}",
        std::mem::size_of::<Mutex<FingerprintWorkerState>>()
    );
    println!(
        "MutexWorkspace={}",
        std::mem::size_of::<Mutex<Option<DeviceDigestWorkspace>>>()
    );
    println!("Condvar={}", std::mem::size_of::<Condvar>());
    println!("JoinHandle={}", std::mem::size_of::<JoinHandle<()>>());
    println!(
        "CapturedFingerprintSample={}",
        std::mem::size_of::<CapturedFingerprintSample>()
    );
    println!(
        "OwnedCallbackRuntimeState={}",
        std::mem::size_of::<super::super::super::OwnedCallbackRuntimeState>()
    );
}

#[test]
fn parent_park_workspace_refuses_actual_recursive_control_and_mapping_borrows() {
    let control = control();
    let worker = worker(Arc::clone(&control));
    let state = control
        .state
        .lock()
        .unwrap_or_else(|error| panic!("control borrow: {error}"));
    assert_eq!(
        // SAFETY: this fixture has no digest thread, capture or live mapping. The
        // actual nonblocking borrow must refuse before touching its empty owner.
        unsafe { worker.hold_workspace_for_parent_park() },
        Err(-libc::EBUSY)
    );
    assert_eq!(
        // SAFETY: the same fixture has no concurrent owner or worker access.
        unsafe { worker.restore_workspace_for_parent_park() },
        Err(-libc::EBUSY)
    );
    drop(state);

    let mapping = control
        .workspace
        .lock()
        .unwrap_or_else(|error| panic!("mapping borrow: {error}"));
    assert_eq!(
        // SAFETY: the actual held mapping mutex must refuse without owner mutation.
        unsafe { worker.hold_workspace_for_parent_park() },
        Err(-libc::EBUSY)
    );
    assert_eq!(
        // SAFETY: this is the same exclusive, threadless fixture owner.
        unsafe { worker.restore_workspace_for_parent_park() },
        Err(-libc::EBUSY)
    );
    drop(mapping);
    drop(worker);
}
