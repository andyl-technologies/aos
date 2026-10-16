//! Tests control-return ordering with real descriptors and one actual worker.
//!
//! These are component mechanisms, not Main/Source issuance fixtures. Ordinary
//! files model cgroup observations; no authenticated Target admission is minted.

use super::*;
use std::fs;
use std::os::unix::fs::MetadataExt;

fn assert_descriptor_closed(descriptor: RawFd, expected: &fs::Metadata) {
    // Parallel tests may reuse the number, but cannot reopen this private file.
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |observed| {
            (observed.dev(), observed.ino()) != (expected.dev(), expected.ino())
        }),
        "the exact retained file must close before its slot becomes reusable"
    );
}

fn mechanism_state(
    path: &Path,
    capacity: usize,
) -> Result<Arc<DispatcherState>, LinuxQemuCgroupError> {
    let wake = create_cancellation_eventfd(path)?;
    let readiness =
        epoll::create(epoll::CreateFlags::CLOEXEC).map_err(|source| failure(path, source))?;
    epoll::add(
        &readiness,
        &wake,
        epoll::EventData::new_u64(0),
        epoll::EventFlags::IN,
    )
    .map_err(|source| failure(path, source))?;
    Ok(Arc::new(DispatcherState {
        slots: Mutex::new(
            (0..capacity)
                .map(|_| JobSlot {
                    epoch: 0,
                    phase: JobPhase::Idle,
                    control: None,
                    original: None,
                    cancel_requested: false,
                    failure: None,
                    failure_reported: false,
                    facade_live: false,
                    next_retry: None,
                })
                .collect(),
        ),
        running: Mutex::new((0..capacity).map(|_| None).collect()),
        shutdown: AtomicBool::new(false),
        worker_exited: AtomicBool::new(false),
        startup: Mutex::new(None),
        wake,
        readiness,
        _namespace: open_directory(path, "retain dispatcher mechanism namespace")?,
        path: path.to_owned(),
    }))
}

fn mechanism_worker(state: Arc<DispatcherState>, capacity: usize) -> JoinHandle<()> {
    let event_capacity = capacity + 1;
    thread::spawn(move || run(state, event_capacity))
}

#[test]
fn returned_job_reuses_its_slot_only_after_actual_descriptor_close()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let (control, cancellation) =
        super::super::tests::watcher_control_fixture(directory.path(), false)?;
    let descriptor = control.cgroup_events.as_raw_fd();
    let expected = control.cgroup_events.metadata()?;
    {
        let mut slots = state.slots.lock().unwrap();
        let slot = &mut slots[0];
        slot.epoch = 1;
        slot.phase = JobPhase::Returned;
        slot.control = Some(control);
    }
    let job = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };

    let returned = job.retire().unwrap();
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Retiring);
    let observed = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!(
        (observed.dev(), observed.ino()),
        (expected.dev(), expected.ino())
    );
    drop(returned);

    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Idle);
    // Another parallel test may reuse the numeric descriptor. It cannot reopen
    // this private fixture's same inode between these two observations.
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |observed| {
            (observed.dev(), observed.ino()) != (expected.dev(), expected.ino())
        })
    );
    assert_eq!(Arc::strong_count(&state), 1);
    drop(cancellation);
    Ok(())
}

#[test]
// crucible-lint: allow clippy-disallowed-method -- the real worker containment test retains one fixed wall-clock bound.
#[allow(clippy::disallowed_methods)]
fn one_worker_returns_actual_controls_for_sequential_jobs() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let worker_state = Arc::clone(&state);
    let worker = mechanism_worker(worker_state, 1);
    let worker_id = worker.thread().id();
    let end = std::time::Instant::now() + Duration::from_secs(5);

    for epoch in 1..=4 {
        let child = directory.path().join(format!("job-{epoch}"));
        fs::create_dir(&child)?;
        let (control, cancellation) = super::super::tests::watcher_control_fixture(&child, false)?;
        signal_terminal(&control.watcher_state, cancellation.as_raw_fd())?;
        {
            let mut slots = state.slots.lock().unwrap();
            let slot = &mut slots[0];
            assert_eq!(slot.phase, JobPhase::Idle);
            slot.epoch = epoch;
            slot.phase = JobPhase::Queued;
            slot.control = Some(control);
        }
        let job = TargetWatchJob {
            state: Arc::clone(&state),
            epoch,
            index: 0,
            released: false,
        };
        wake(&state.wake)?;
        while !job.is_finished() && std::time::Instant::now() < end {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            job.is_finished(),
            "same worker did not return actual job controls"
        );
        assert_eq!(worker.thread().id(), worker_id);
        assert!(!worker.is_finished());
        drop(job.retire().unwrap());
        assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Idle);
    }

    state.shutdown.store(true, Ordering::Release);
    wake(&state.wake)?;
    while !worker.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        worker.is_finished(),
        "fixed Main worker did not physically stop"
    );
    worker.join().unwrap();
    assert_eq!(Arc::strong_count(&state), 1);
    Ok(())
}

#[test]
// crucible-lint: allow clippy-disallowed-method -- real FD/worker mechanism has one fixed containment deadline.
#[allow(clippy::disallowed_methods)]
fn busy_node_cannot_block_another_nodes_physical_return() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 2)?;
    let worker = mechanism_worker(Arc::clone(&state), 2);
    let end = std::time::Instant::now() + Duration::from_secs(5);
    let first_path = directory.path().join("still-populated");
    let second_path = directory.path().join("already-empty");
    fs::create_dir(&first_path)?;
    fs::create_dir(&second_path)?;
    let (first, first_cancel) = super::super::tests::watcher_control_fixture(&first_path, true)?;
    let (second, second_cancel) =
        super::super::tests::watcher_control_fixture(&second_path, false)?;
    signal_terminal(&first.watcher_state, first_cancel.as_raw_fd())?;
    signal_terminal(&second.watcher_state, second_cancel.as_raw_fd())?;
    {
        let mut slots = state.slots.lock().unwrap();
        for (slot, control) in slots.iter_mut().zip([first, second]) {
            slot.epoch = 1;
            slot.phase = JobPhase::Queued;
            slot.control = Some(control);
        }
    }
    let first = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };
    let second = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 1,
        released: false,
    };
    wake(&state.wake)?;
    while !second.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        second.is_finished(),
        "empty node must return independently of populated node"
    );
    assert!(
        !first.is_finished(),
        "populated node must retain its own controls"
    );
    drop(second.retire().unwrap());
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Running);
    assert_eq!(state.slots.lock().unwrap()[1].phase, JobPhase::Idle);

    fs::write(first_path.join("cgroup.events"), "populated 0\n")?;
    while !first.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        first.is_finished(),
        "first node must retain and later return its exact controls"
    );
    drop(first.retire().unwrap());
    state.shutdown.store(true, Ordering::Release);
    wake(&state.wake)?;
    while !worker.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(worker.is_finished());
    worker.join().unwrap();
    assert_eq!(Arc::strong_count(&state), 1);
    Ok(())
}

#[test]
fn readable_terminal_event_does_not_spin_the_shared_poller()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let (control, cancellation) =
        super::super::tests::watcher_control_fixture(directory.path(), true)?;
    register_target_event(&state, 0, &control)?;
    signal_terminal(&control.watcher_state, cancellation.as_raw_fd())?;
    let mut events = Vec::with_capacity(2);
    let zero = rustix::time::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    epoll::wait(
        &state.readiness,
        rustix::buffer::spare_capacity(&mut events),
        Some(&zero),
    )?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data.u64(), 1);
    // Leave the real cancellation eventfd readable. Only explicit registration
    // of another job may produce new readiness; cleanup retries use their timer.
    for _ in 0..4 {
        events.clear();
        epoll::wait(
            &state.readiness,
            rustix::buffer::spare_capacity(&mut events),
            Some(&zero),
        )?;
        assert!(
            events.is_empty(),
            "sticky terminal signal must not create an immediate retry loop"
        );
    }
    epoll::delete(&state.readiness, &control.cancellation_event)?;
    drop(control);
    drop(cancellation);
    Ok(())
}

#[test]
fn quarantined_failure_is_reported_before_same_control_physical_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let (control, _cancellation) =
        super::super::tests::watcher_control_fixture(directory.path(), false)?;
    let descriptor = control.cgroup_events.as_raw_fd();
    let expected = control.cgroup_events.metadata()?;
    {
        let mut slots = state.slots.lock().unwrap();
        slots[0].epoch = 1;
        slots[0].phase = JobPhase::Quarantined;
        slots[0].control = Some(control);
        slots[0].failure = Some(JobFailure {
            panicked: true,
            ..JobFailure::default()
        });
    }
    let job = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };

    let (job, first) = match job.retire() {
        Err(retained) => retained,
        Ok(_) => panic!("first failed attempt must be reported before physical retry"),
    };
    assert!(first.to_string().contains("panic true"));
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Quarantined);

    let returned = job.retire().unwrap();
    assert_eq!(state.slots.lock().unwrap()[0].phase, JobPhase::Retiring);
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
    drop(returned);

    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].failure.as_ref().unwrap().panicked);
    assert!(slots[0].failure_reported);
    assert_descriptor_closed(descriptor, &expected);
    Ok(())
}

#[test]
fn poisoned_running_cell_returns_its_same_owners_through_explicit_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let (control, _cancellation) =
        super::super::tests::watcher_control_fixture(directory.path(), false)?;
    let descriptor = control.cgroup_events.as_raw_fd();
    let expected = control.cgroup_events.metadata()?;
    {
        let mut slots = state.slots.lock().unwrap();
        slots[0].epoch = 1;
        slots[0].phase = JobPhase::Running;
        state.running.lock().unwrap()[0] = Some(RunningJob {
            epoch: 1,
            control,
            original: None,
            draining: true,
            failure: None,
            next_attempt: None,
        });
    }
    let poisoned = Arc::clone(&state);
    assert!(
        thread::spawn(move || {
            let _held = poisoned.running.lock().unwrap();
            panic!("component worker unwind while retaining actual controls");
        })
        .join()
        .is_err()
    );
    let job = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        index: 0,
        released: false,
    };

    assert!(job.is_finished());
    let (job, first) = match job.retire() {
        Err(retained) => retained,
        Ok(_) => panic!("first failed attempt must be reported before physical retry"),
    };
    assert!(first.to_string().contains("panic true"));
    assert!(state.running.is_poisoned());
    match state.running.lock() {
        Err(poison) => assert!(poison.get_ref()[0].is_none()),
        Ok(_) => panic!("job recovery must not erase containing worker poison"),
    }
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());

    drop(job.retire().unwrap());
    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].failure.as_ref().unwrap().panicked);
    assert!(state.running.is_poisoned());
    assert_descriptor_closed(descriptor, &expected);
    Ok(())
}

#[test]
fn slot_poison_exit_preserves_running_and_queued_controls_for_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 2)?;
    let running_path = directory.path().join("running");
    let queued_path = directory.path().join("queued");
    fs::create_dir(&running_path)?;
    fs::create_dir(&queued_path)?;
    let (running_control, _running_cancel) =
        super::super::tests::watcher_control_fixture(&running_path, false)?;
    let (queued_control, _queued_cancel) =
        super::super::tests::watcher_control_fixture(&queued_path, false)?;
    let descriptors = [
        (
            running_control.cgroup_events.as_raw_fd(),
            running_control.cgroup_events.metadata()?,
        ),
        (
            queued_control.cgroup_events.as_raw_fd(),
            queued_control.cgroup_events.metadata()?,
        ),
    ];
    {
        let mut slots = state.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            slot.epoch = 1;
            slot.facade_live = true;
        }
        slots[0].phase = JobPhase::Running;
        slots[1].phase = JobPhase::Queued;
        slots[1].control = Some(queued_control);
        state.running.lock().unwrap()[0] = Some(RunningJob {
            epoch: 1,
            control: running_control,
            original: None,
            draining: false,
            failure: None,
            next_attempt: None,
        });
    }
    let poisoned = Arc::clone(&state);
    assert!(
        thread::spawn(move || {
            let _held = poisoned.slots.lock().unwrap();
            panic!("component slot-only poison before worker dispatch");
        })
        .join()
        .is_err()
    );

    // This exits normally while holding an unpoisoned running array. Recovery
    // must depend on the actual exit witness, not running mutex poison.
    run(Arc::clone(&state), 3);
    assert!(state.worker_exited.load(Ordering::Acquire));
    assert!(!state.running.is_poisoned());
    for (index, (descriptor, expected)) in descriptors.into_iter().enumerate() {
        let job = TargetWatchJob {
            state: Arc::clone(&state),
            epoch: 1,
            index,
            released: false,
        };
        assert!(job.is_finished());
        let (job, first) = match job.retire() {
            Err(retained) => retained,
            Ok(_) => panic!("worker exit must be reported before physical retry"),
        };
        assert!(first.to_string().contains("Target worker exited"));
        assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
        drop(job.retire().unwrap());
        assert_descriptor_closed(descriptor, &expected);
    }
    assert!(state.running.lock().unwrap().iter().all(Option::is_none));
    let slots = match state.slots.lock() {
        Err(poison) => poison.into_inner(),
        Ok(_) => panic!("individual recovery must retain containing slot poison"),
    };
    assert!(slots.iter().all(|slot| slot.phase == JobPhase::Idle));
    assert!(slots.iter().all(|slot| slot.failure_reported));
    Ok(())
}

#[test]
fn main_dispatcher_revisits_exact_job_after_caller_facade_drop()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;
    let (control, _cancellation) =
        super::super::tests::watcher_control_fixture(directory.path(), false)?;
    let descriptor = control.cgroup_events.as_raw_fd();
    let expected = control.cgroup_events.metadata()?;
    {
        let mut slots = state.slots.lock().unwrap();
        slots[0].epoch = 7;
        slots[0].phase = JobPhase::Quarantined;
        slots[0].facade_live = true;
        slots[0].control = Some(control);
        slots[0].failure = Some(JobFailure {
            panicked: true,
            ..JobFailure::default()
        });
    }
    drop(TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 7,
        index: 0,
        released: false,
    });
    assert!(!state.slots.lock().unwrap()[0].facade_live);
    let mut dispatcher = TargetDispatcher {
        purpose: None,
        capacity: 1,
        state: Some(Arc::clone(&state)),
        worker: None,
        failed: false,
        cleanup: None,
        phase: WorkerPhase::Running,
        worker_panic: Mutex::new(None),
        path: directory.path().to_owned(),
    };

    let first = dispatcher.retry_abandoned_jobs().unwrap_err();
    assert!(first.to_string().contains("panic true"));
    assert_eq!(state.slots.lock().unwrap()[0].epoch, 7);
    assert!(!state.slots.lock().unwrap()[0].facade_live);
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());

    dispatcher.retry_abandoned_jobs()?;
    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].epoch, 7);
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].failure.as_ref().unwrap().panicked);
    assert_descriptor_closed(descriptor, &expected);
    drop(slots);
    // No authenticated Main worker/purpose was issued in this mechanism test.
    drop(dispatcher.state.take());
    Ok(())
}

#[test]
fn abandoned_populated_node_cannot_starve_empty_peer_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 2)?;
    for (index, populated) in [true, false].into_iter().enumerate() {
        let path = directory.path().join(format!("abandoned-{index}"));
        fs::create_dir(&path)?;
        let (control, _cancellation) =
            super::super::tests::watcher_control_fixture(&path, populated)?;
        let mut slots = state.slots.lock().unwrap();
        slots[index].epoch = 1;
        slots[index].phase = JobPhase::Quarantined;
        slots[index].control = Some(control);
        slots[index].failure = Some(JobFailure {
            panicked: true,
            ..JobFailure::default()
        });
    }
    let mut dispatcher = TargetDispatcher {
        purpose: None,
        capacity: 2,
        state: Some(Arc::clone(&state)),
        worker: None,
        failed: false,
        cleanup: None,
        phase: WorkerPhase::Running,
        worker_panic: Mutex::new(None),
        path: directory.path().to_owned(),
    };

    assert!(dispatcher.retry_abandoned_jobs().is_err());
    assert!(
        state
            .slots
            .lock()
            .unwrap()
            .iter()
            .all(|slot| slot.failure_reported)
    );
    assert!(dispatcher.retry_abandoned_jobs().is_err());
    {
        let slots = state.slots.lock().unwrap();
        assert_eq!(slots[0].phase, JobPhase::Quarantined);
        assert!(slots[0].control.is_some());
        assert!(slots[0].next_retry.is_some());
        assert_eq!(slots[1].phase, JobPhase::Idle);
        assert!(slots[1].control.is_none());
    }
    // Model a scheduler timestamp already beyond the next permitted pass;
    // this changes no Cleanup authority or physical empty observation.
    fs::write(
        directory.path().join("abandoned-0/cgroup.events"),
        "populated 0\n",
    )?;
    state.slots.lock().unwrap()[0].next_retry = Some(Instant::now());
    dispatcher.retry_abandoned_jobs()?;
    assert!(
        state
            .slots
            .lock()
            .unwrap()
            .iter()
            .all(|slot| slot.phase == JobPhase::Idle)
    );
    drop(dispatcher.state.take());
    Ok(())
}

#[test]
fn event_buffer_allocation_refusal_is_acknowledged_before_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path(), 1)?;

    // The real Vec rejects this impossible capacity before allocation. This
    // component cut exercises worker startup without issuing Main or Target.
    run(Arc::clone(&state), usize::MAX);

    let startup = state.startup.lock().unwrap();
    assert!(matches!(startup.as_ref(), Some(Err(_))));
    assert!(state.worker_exited.load(Ordering::Acquire));
    let slots = state.slots.lock().unwrap();
    assert_eq!(slots[0].phase, JobPhase::Idle);
    assert!(slots[0].control.is_none());
    assert!(state.running.lock().unwrap().iter().all(Option::is_none));
    Ok(())
}

#[test]
fn actual_join_panic_history_survives_repeated_reports_without_claiming_main_return()
-> Result<(), Box<dyn std::error::Error>> {
    fn requires_send_sync<T: Send + Sync>() {}
    requires_send_sync::<TargetDispatcher>();

    let directory = tempfile::tempdir()?;
    let file = fs::File::create(directory.path().join("panic-history"))?;
    let descriptor = file.as_raw_fd();
    let expected = file.metadata()?;
    let worker = thread::spawn(move || std::panic::panic_any(file));
    let payload = worker
        .join()
        .expect_err("worker really panics with its retained file");
    let mut dispatcher = TargetDispatcher {
        purpose: None,
        capacity: 1,
        state: None,
        worker: None,
        failed: true,
        cleanup: None,
        phase: WorkerPhase::Joined,
        worker_panic: Mutex::new(Some(payload)),
        path: directory.path().to_owned(),
    };
    let retained_file = dispatcher
        .worker_panic()
        .unwrap()
        .downcast_ref::<fs::File>()
        .unwrap();
    assert_eq!(retained_file.as_raw_fd(), descriptor);

    assert!(dispatcher.report_retirement_history().is_err());
    assert!(
        dispatcher.finish().is_err(),
        "no authenticated purpose may be invented"
    );
    assert!(dispatcher.report_retirement_history().is_err());

    let same_file = dispatcher
        .worker_panic()
        .unwrap()
        .downcast_ref::<fs::File>()
        .unwrap();
    assert_eq!(same_file.as_raw_fd(), descriptor);
    assert_eq!(
        (same_file.metadata()?.dev(), same_file.metadata()?.ino()),
        (expected.dev(), expected.ino())
    );
    assert!(
        !dispatcher.is_physically_retired(),
        "actual join alone is not a paid Main return"
    );
    drop(dispatcher);
    assert_descriptor_closed(descriptor, &expected);
    Ok(())
}
