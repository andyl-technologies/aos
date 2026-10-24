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

fn enqueue(control: &FingerprintWorkerControl, request: u32) -> Result<(), ()> {
    control.enqueue(&mut Some(CapturedFingerprintSample::test_empty()), request)
}

fn take_received(control: &FingerprintWorkerControl) -> LiveFingerprintDigestWork {
    control.receive().unwrap().take().unwrap()
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
    assert!(enqueue(&control, 11).is_ok());
    let second = Arc::clone(&control);
    let producer = thread::spawn(move || enqueue(&second, 22));
    wait_blocked(&control, &deadline);

    assert!(!producer.is_finished());
    assert_eq!(take_received(&control).capture_request, 11);
    assert!(producer.join().unwrap().is_ok());
    assert_eq!(take_received(&control).capture_request, 22);
    control.close();
    assert!(control.receive().is_none());
}

#[test]
fn close_drains_pending_capture_and_refuses_new_producer() {
    let control = control();
    assert!(enqueue(&control, 7).is_ok());
    control.close();

    assert!(enqueue(&control, 8).is_err());
    assert_eq!(take_received(&control).capture_request, 7);
    assert!(control.receive().is_none());
}

#[test]
fn closed_worker_receipt_preserves_shutdown_and_actual_pending_debt() {
    let control = control();
    assert!(enqueue(&control, 7).is_ok());
    let worker = worker(Arc::clone(&control));

    control.close();
    let snapshot = worker.semantic_receipt_snapshot().unwrap();

    assert!(snapshot.closed);
    assert!(!snapshot.quiet);
    assert_eq!(snapshot.sequence, 1);
    assert_eq!(snapshot.returned, [None; 2]);
    assert_eq!(take_received(&control).capture_request, 7);
    assert!(worker.semantic_receipt_snapshot().unwrap().closed);
}

#[test]
fn close_wakes_blocked_producer_without_stealing_pending_capture() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let control = control();
    assert!(enqueue(&control, 7).is_ok());
    let waiting = Arc::clone(&control);
    let producer = thread::spawn(move || enqueue(&waiting, 8));
    wait_blocked(&control, &deadline);
    control.close();

    assert!(producer.join().unwrap().is_err());
    assert_eq!(take_received(&control).capture_request, 7);
    assert!(control.receive().is_none());
}

#[test]
fn first_failure_wakes_producer_and_remains_exact_after_later_refusal() {
    let deadline = TransportDeadline::new(Duration::from_secs(5)).unwrap();
    let control = control();
    assert!(enqueue(&control, 3).is_ok());
    let waiting = Arc::clone(&control);
    let producer = thread::spawn(move || enqueue(&waiting, 4));
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
    let producer = thread::spawn(move || enqueue(&queued, 19));

    // The queue producer completes while the exclusive workspace mutex remains
    // held. A single shared digest/queue mutex would fail this finite control.
    while !producer.is_finished() && deadline.remaining().is_ok() {
        thread::yield_now();
    }
    let finished_with_workspace_held = producer.is_finished();
    drop(workspace);
    assert!(producer.join().unwrap().is_ok());
    assert!(finished_with_workspace_held);
    assert_eq!(take_received(&control).capture_request, 19);
}

#[test]
fn fork_hold_refuses_pending_job_then_restores_same_owner_before_release() {
    let workspace = DeviceDigestWorkspace::test_owner();
    let descriptor = workspace.descriptor_number().unwrap();
    let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
    let mut worker = worker(Arc::clone(&control));
    assert!(enqueue(&control, 2).is_ok());
    // SAFETY: this fixture has no worker/callback actors; the pending check is
    // the concrete additional guard, rather than a forged parked-work receipt.
    assert!(unsafe { worker.hold_workspace_for_fork() }.is_err());
    assert!(control.workspace().is_some());
    drop(take_received(&control));
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

#[test]
fn completed_publication_and_exact_ack_release_inflight_material() {
    let slot = FingerprintSampleSlot::new();
    let request = slot.request_capture_v1();
    let mut workspace = DeviceDigestWorkspace::test_owner();
    workspace.map().unwrap();
    let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
    assert!(enqueue(&control, request).is_ok());
    control.close();

    LiveFingerprintDigestWorker::run(
        StableFingerprintSlotHandle::new(&slot),
        &LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
        &control,
    );

    assert!(slot.snapshot().is_some());
    assert_eq!(slot.pending_capture_request_v1(), None);
    assert!(control.in_flight().is_none());
    assert!(control.lock().failure.is_none());
    let mut worker = worker(control);
    let receipt = worker.semantic_receipt_snapshot().unwrap();
    assert_eq!(receipt.sequence, 1);
    assert!(receipt.quiet);
    assert_eq!(
        receipt.returned[0],
        Some(CaptureReceipt {
            epoch: 1,
            capture: request,
            sample_completed: true,
            first: 0,
        })
    );
    assert_eq!(receipt.returned[1], None);
    worker.retire().unwrap();
    assert!(worker.control.is_none());
}

#[test]
fn changed_ack_keeps_published_material_and_blocks_retirement_and_fork() {
    let slot = FingerprintSampleSlot::new();
    let request = slot.request_capture_v1();
    let mut workspace = DeviceDigestWorkspace::test_owner();
    workspace.map().unwrap();
    let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
    assert!(enqueue(&control, request.wrapping_add(2)).is_ok());
    control.close();

    LiveFingerprintDigestWorker::run(
        StableFingerprintSlotHandle::new(&slot),
        &LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
        &control,
    );

    assert!(slot.snapshot().is_some());
    assert_eq!(slot.pending_capture_request_v1(), Some(request));
    assert_eq!(
        control.in_flight().as_ref().unwrap().publication,
        MaterialPublication::AcknowledgementAttempted
    );
    let mut worker = worker(control);
    let receipt = worker.semantic_receipt_snapshot().unwrap();
    assert_eq!(receipt.sequence, 1);
    assert!(!receipt.quiet);
    assert_eq!(receipt.returned, [None; 2]);
    // SAFETY: this synchronous fixture has no worker/callback actors.
    assert!(unsafe { worker.hold_workspace_for_fork() }.is_err());
    assert!(worker.retire().is_err());
    assert!(worker.control.as_ref().unwrap().in_flight().is_some());
    assert!(worker.control.as_ref().unwrap().workspace().is_some());
    // Fixture-only disposal: no Source owner or operating loan was constructed.
    drop(worker.control.as_ref().unwrap().in_flight().take());
    worker.retire().unwrap();
}

#[test]
fn publication_refusal_does_not_ack_or_replay_and_keeps_the_received_body() {
    let slot = FingerprintSampleSlot::new();
    let request = slot.request_capture_v1();
    let control = control();
    assert!(enqueue(&control, request).is_ok());
    let mut in_flight = control.receive().unwrap();
    let material = in_flight.as_mut().unwrap();
    let invalid = crucible_qemu_shmem::FingerprintSample {
        vcpu_count: (crucible_qemu_shmem::FINGERPRINT_SAMPLE_MAX_VCPUS + 1) as u32,
        ..crucible_qemu_shmem::FingerprintSample::default()
    };

    assert!(matches!(
        material.publish(&slot, &invalid),
        Err(FingerprintWorkerCause::Publication(_))
    ));
    assert_eq!(material.publication, MaterialPublication::Attempted);
    assert!(matches!(
        material.publish(&slot, &crucible_qemu_shmem::FingerprintSample::default()),
        Err(FingerprintWorkerCause::UnsettledWork)
    ));
    drop(in_flight);

    assert!(control.in_flight().is_some());
    assert_eq!(slot.snapshot(), None);
    assert_eq!(slot.pending_capture_request_v1(), Some(request));
}

#[test]
fn read_failure_keeps_inflight_material_without_publication_or_ack() {
    let slot = FingerprintSampleSlot::new();
    let request = slot.request_capture_v1();
    let mut workspace = DeviceDigestWorkspace::test_owner();
    workspace.map().unwrap();
    let control = Arc::new(FingerprintWorkerControl::new(Some(workspace)));
    assert!(
        control
            .enqueue(
                &mut Some(CapturedFingerprintSample::test_unreadable()),
                request
            )
            .is_ok()
    );
    control.close();

    LiveFingerprintDigestWorker::run(
        StableFingerprintSlotHandle::new(&slot),
        &LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL),
        &control,
    );

    assert!(matches!(
        control.lock().failure,
        Some(FingerprintWorkerCause::Digest(_))
    ));
    assert_eq!(
        control.in_flight().as_ref().unwrap().publication,
        MaterialPublication::NotStarted
    );
    assert_eq!(slot.snapshot(), None);
    assert_eq!(slot.pending_capture_request_v1(), Some(request));
    let mut worker = worker(control);
    assert!(worker.retire().is_err());
    assert!(worker.control.as_ref().unwrap().in_flight().is_some());
    // Explicit local fixture disposal after checking the retained failed path.
    drop(worker.control.as_ref().unwrap().in_flight().take());
    worker.retire().unwrap();
}

#[test]
fn unwind_releases_only_the_borrow_and_keeps_the_received_capture() {
    let control = control();
    assert!(enqueue(&control, 5).is_ok());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _received = control.receive().unwrap();
        panic!("failure after actual queue-to-inflight transfer");
    }));

    assert!(result.is_err());
    assert!(control.in_flight.is_poisoned());
    assert_eq!(control.in_flight().as_ref().unwrap().capture_request, 5);
    assert!(control.lock().pending.is_none());
}

#[test]
fn accepted_queued_or_inflight_capture_blocks_all_transfers_and_retirement() {
    for received in [false, true] {
        let control = Arc::new(FingerprintWorkerControl::new(Some(
            DeviceDigestWorkspace::test_owner(),
        )));
        assert!(enqueue(&control, 91).is_ok());
        if received {
            drop(control.receive().unwrap());
        }
        let mut worker = worker(control);

        // SAFETY: no worker/callback actors exist. The real transfer gates must
        // refuse both accepted states before moving the actual workspace.
        unsafe {
            assert!(worker.hold_workspace_for_fork().is_err());
            assert!(worker.restore_workspace_after_fork().is_err());
            assert!(worker.hold_workspace_for_parent_park().is_err());
            assert!(worker.restore_workspace_for_parent_park().is_err());
        }
        assert!(worker.control.as_ref().unwrap().workspace().is_some());
        assert!(worker.fork_workspace.get_mut().is_none());
        assert!(worker.retire().is_err());
        let retained = worker.control.as_ref().unwrap();
        if received {
            assert_eq!(retained.in_flight().as_ref().unwrap().capture_request, 91);
        } else {
            assert_eq!(
                retained.lock().pending.as_ref().unwrap().capture_request,
                91
            );
        }

        // Explicit local fixture disposal supplies no Source/operation proof.
        drop(retained.lock().pending.take());
        drop(retained.in_flight().take());
        worker.retire().unwrap();
    }
}

#[test]
fn already_held_workspace_cannot_bless_a_retry_with_retained_capture() {
    let control = Arc::new(FingerprintWorkerControl::new(Some(
        DeviceDigestWorkspace::test_owner(),
    )));
    let mut worker = worker(control);
    // SAFETY: this local fixture has no callback or worker actors.
    unsafe { worker.hold_workspace_for_fork() }.unwrap();
    let retained = worker
        .fork_workspace
        .get_mut()
        .as_ref()
        .unwrap()
        .descriptor_number();
    assert!(enqueue(worker.control.as_ref().unwrap(), 64).is_ok());

    // SAFETY: the same actors remain excluded; the concrete queue debt must
    // refuse an already-held retry without returning or replacing its owner.
    assert!(unsafe { worker.hold_workspace_for_fork() }.is_err());
    assert_eq!(
        worker
            .fork_workspace
            .get_mut()
            .as_ref()
            .unwrap()
            .descriptor_number(),
        retained
    );
    assert!(worker.control.as_ref().unwrap().workspace().is_none());
    assert_eq!(
        worker
            .control
            .as_ref()
            .unwrap()
            .lock()
            .pending
            .as_ref()
            .unwrap()
            .capture_request,
        64
    );

    // Local fixture disposal; no Source operation or physical terminal claimed.
    drop(worker.control.as_ref().unwrap().lock().pending.take());
    // SAFETY: exclusion remains and the local captured fixture was disposed.
    unsafe { worker.restore_workspace_after_fork() }.unwrap();
    worker.retire().unwrap();
}

#[test]
fn fork_transfers_refuse_the_borrow_held_at_the_real_pending_park_cut() {
    let control = Arc::new(FingerprintWorkerControl::new(Some(
        DeviceDigestWorkspace::test_owner(),
    )));
    let mut worker = worker(Arc::clone(&control));
    let quiescence = LiveWorkerQuiescence::new(crate::runtime::worker_quiescence::WORKER_ALL);
    assert!(enqueue(&control, 72).is_ok());
    let idle = quiescence.idle(WORKER_FINGERPRINT);
    let received = control.receive().unwrap();
    let held = quiescence.hold();
    assert_eq!(held.pending_mask & WORKER_FINGERPRINT, 0);
    assert_ne!(held.parked_mask & WORKER_FINGERPRINT, 0);
    let pending = idle.received();
    assert_ne!(quiescence.snapshot().pending_mask & WORKER_FINGERPRINT, 0);

    // SAFETY: the fixture has no concurrent callback/worker actors. It retains
    // the actual receive borrow and real held/pending quiescence state that
    // make a blocking fork transfer wait on its own release dependency.
    unsafe {
        assert!(worker.hold_workspace_for_fork().is_err());
        assert!(worker.restore_workspace_after_fork().is_err());
    }
    assert!(worker.fork_workspace.get_mut().is_none());
    assert!(control.workspace().is_some());
    assert_eq!(received.as_ref().unwrap().capture_request, 72);

    drop(received);
    drop(pending);
    quiescence.release();
    // Dispose only this local fixture after proving no transfer consumed it.
    drop(control.in_flight().take());
    drop(control);
    worker.retire().unwrap();
}

#[test]
fn closed_queue_leaves_the_actual_sample_owner_with_its_caller() {
    let control = control();
    let mut sample = Some(CapturedFingerprintSample::test_empty());
    control.close();

    assert!(control.enqueue(&mut sample, 33).is_err());

    assert!(sample.is_some());
    assert!(control.lock().pending.is_none());
    assert!(control.in_flight().is_none());
}
