//! Concrete mapped-runtime and registered-worker park companion controls.
//!
//! Startup/original callbacks are explicit fixture models. The gates, mapping,
//! worker registration and resource holds below are the actual implementation;
//! these controls do not issue a native original or module-retirement grant.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::paged_ram::TransportDeadline;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

fn fixture_runtime(fixture: &LiveInstallFixture) -> PluginRuntimeOwner {
    let host = fixture.spawn_host(SETUP_ACK_STATUS_READY);
    let mut reservation = reserve_runtime().unwrap_or_else(|error| panic!("reservation: {error}"));
    reservation.startup_source_model =
        Some(crate::startup_source::test_support::InstallerStartupSourceModel::ready());
    let runtime = install_live_runtime(
        41,
        fixture.args(),
        test_capabilities(),
        &SuccessfulCallbackRegistrar,
        &mut reservation,
    )
    .unwrap_or_else(|error| panic!("fixture install: {error}"));
    join_host(host);
    runtime
}

enum WorkerCommand {
    Pending(Sender<()>),
    Stop,
}

struct ParkedWorker {
    stop: Sender<WorkerCommand>,
    joined: JoinHandle<()>,
}

fn parked_worker(
    workers: Arc<LiveWorkerQuiescence>,
    role: u64,
    deadline: &TransportDeadline,
) -> ParkedWorker {
    let (ready, ready_rx) = mpsc::channel();
    let (stop, stop_rx): (Sender<WorkerCommand>, Receiver<WorkerCommand>) = mpsc::channel();
    let joined = std::thread::spawn(move || {
        let _identity = workers
            .register_current(role)
            .unwrap_or_else(|error| panic!("actual worker registration: {error}"));
        let mut idle = Some(workers.idle(role));
        let mut pending = None;
        ready
            .send(())
            .unwrap_or_else(|error| panic!("ready signal: {error}"));
        while let Ok(command) = stop_rx.recv() {
            match command {
                WorkerCommand::Pending(ready) => {
                    let parked = idle
                        .take()
                        .unwrap_or_else(|| panic!("one real pending transition"));
                    pending = Some(parked.received());
                    let _sent = ready.send(());
                }
                WorkerCommand::Stop => break,
            }
        }
        drop(pending);
        drop(idle);
    });
    ready_rx
        .recv_timeout(
            deadline
                .remaining()
                .unwrap_or_else(|error| panic!("original end: {error}")),
        )
        .unwrap_or_else(|error| panic!("worker should park before original end: {error}"));
    ParkedWorker { stop, joined }
}

fn stop_workers(workers: [ParkedWorker; 2]) {
    for worker in workers {
        let _stopped = worker.stop.send(WorkerCommand::Stop);
        worker
            .joined
            .join()
            .unwrap_or_else(|_| panic!("actual worker should terminate"));
    }
}

#[test]
fn parent_park_owns_actual_runtime_drain_until_explicit_relinquishment() {
    let deadline = TransportDeadline::new(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("fixed original test deadline: {error}"));
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let runtime = fixture_runtime(&fixture);
    let state = runtime._callbacks.state.as_ref();
    let workers = [
        parked_worker(Arc::clone(&state.workers), WORKER_RUN_CONTROL, &deadline),
        parked_worker(Arc::clone(&state.workers), WORKER_TEARDOWN, &deadline),
    ];
    let mut owner = parent_park::ParentParkDrainOwner::retain(state);

    assert_eq!(owner.acquire(|| 0), 0);
    assert_eq!(owner.check(|| 0), 0);
    assert_eq!(owner.statuses(), (0, 0));
    assert!(state.quiescence.release_hot_fork().hot_fork_held);
    assert!(state.workers.release().held);
    assert!(state.quiescence.enter().is_none());
    let rings = state
        .setup
        .mapped_region()
        .hot_fork_ring_io_snapshot()
        .unwrap_or_else(|error| panic!("actual mapped rings: {error}"));
    assert_eq!(rings.ring_count(), rings.held_rings());
    assert!(matches!(
        invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE),
        Err(status) if status == -libc::EBUSY
    ));

    assert!(matches!(
        invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY),
        Err(status) if status == -libc::EBUSY
    ));

    assert_eq!(owner.relinquish(|| 0), 0);
    assert!(state.quiescence.enter().is_some());
    assert!(!state.workers.snapshot().held);
    assert_eq!(owner.relinquish(|| 0), -libc::EALREADY);
    drop(owner);
    stop_workers(workers);
}

#[test]
fn parent_park_refuses_before_hold_and_never_retries_original_birth() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let runtime = fixture_runtime(&fixture);
    let state = runtime._callbacks.state.as_ref();
    let mut owner = parent_park::ParentParkDrainOwner::retain(state);
    let calls = Cell::new(0);

    assert_eq!(
        owner.acquire(|| {
            calls.set(calls.get() + 1);
            -229
        }),
        -229
    );
    assert_eq!(owner.statuses(), (-229, -229));
    assert!(!state.quiescence.parent_hold_owned());
    assert!(!state.workers.snapshot().held);
    assert_eq!(
        owner.acquire(|| panic!("refusal cannot renew acquisition")),
        -libc::EALREADY
    );
    assert_eq!(calls.get(), 2);
}

#[test]
fn parent_park_keeps_callback_cause_and_independent_original_post() {
    let deadline = TransportDeadline::new(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("fixed original test deadline: {error}"));
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let runtime = fixture_runtime(&fixture);
    let state = runtime._callbacks.state.as_ref();
    let workers = [
        parked_worker(Arc::clone(&state.workers), WORKER_RUN_CONTROL, &deadline),
        parked_worker(Arc::clone(&state.workers), WORKER_TEARDOWN, &deadline),
    ];
    let callback = state
        .quiescence
        .enter()
        .unwrap_or_else(|| panic!("actual callback"));
    let mut owner = parent_park::ParentParkDrainOwner::retain(state);
    let calls = Cell::new(0);
    assert_eq!(
        owner.acquire(|| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { 0 } else { -317 }
        }),
        -libc::EBUSY
    );
    assert_eq!(owner.statuses(), (-libc::EBUSY, -317));
    drop(callback);

    assert_eq!(owner.relinquish(|| 0), -libc::EBUSY);
    assert!(state.quiescence.release_hot_fork().hot_fork_held);
    assert!(state.workers.release().held);
    drop(owner);
    assert!(state.quiescence.enter().is_none());
    // This utility explicitly terminates its fixture actors after refusal;
    // it does not model a deployment descendant or native retirement grant.
    stop_workers(workers);
}

#[test]
fn parent_park_arbitration_excludes_legacy_release_before_owner_publication() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let runtime = fixture_runtime(&fixture);
    let state = runtime._callbacks.state.as_ref();
    let held = state
        .setup
        .mapped_region()
        .hold_hot_fork_ring_io()
        .unwrap_or_else(|error| panic!("actual ring hold: {error}"));
    assert_eq!(held.ring_count(), held.held_rings());
    assert!(!state.quiescence.parent_hold_owned());
    let arbitration = state
        .parent_park
        .try_lock()
        .unwrap_or_else(|error| panic!("actual companion arbitration: {error}"));

    assert!(matches!(
        invoke_hot_fork_barrier(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE),
        Err(status) if status == -libc::EBUSY
    ));
    let still_held = state
        .setup
        .mapped_region()
        .hot_fork_ring_io_snapshot()
        .unwrap_or_else(|error| panic!("actual ring snapshot: {error}"));
    assert_eq!(still_held.ring_count(), still_held.held_rings());

    drop(arbitration);
    let released = state
        .setup
        .mapped_region()
        .release_hot_fork_ring_io()
        .unwrap_or_else(|error| panic!("fixture ring release: {error}"));
    assert_eq!(released.held_rings(), 0);
}

#[test]
fn parent_park_registered_userdata_retains_actual_allocation_without_active_hold() {
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let runtime = fixture_runtime(&fixture);
    let state = runtime._callbacks.state.as_ref().get_ref();
    let allocation = std::ptr::from_ref(state).cast_mut();
    let worker_state = Arc::downgrade(&state.workers);
    assert!(!state.parent_park_retained.load(Ordering::Acquire));
    assert!(state.parent_park.try_lock().is_ok());
    // This fixture models an attempted registrar retaining userdata; it does not
    // export a native symbol or register a real process-lifetime callback.
    state
        .parent_park_registration_retained
        .store(true, Ordering::Release);

    drop(runtime);
    assert!(worker_state.upgrade().is_some());

    // SAFETY: this fixture has no actual native registration or retained owner.
    // The sole owning Box was deliberately preserved by the proof's Drop, all
    // runtime threads were joined there, and no runtime reference is used again.
    unsafe { drop(Box::from_raw(allocation)) };
    assert!(worker_state.upgrade().is_none());
}

#[test]
fn parent_park_revalidates_actual_pending_transition_before_any_ring_release() {
    let deadline = TransportDeadline::new(Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("fixed original test deadline: {error}"));
    let _runtime_state = isolate_runtime_state_for_test();
    let fixture = LiveInstallFixture::new();
    let runtime = fixture_runtime(&fixture);
    let state = runtime._callbacks.state.as_ref();
    let workers = [
        parked_worker(Arc::clone(&state.workers), WORKER_RUN_CONTROL, &deadline),
        parked_worker(Arc::clone(&state.workers), WORKER_TEARDOWN, &deadline),
    ];
    let mut owner = parent_park::ParentParkDrainOwner::retain(state);
    assert_eq!(owner.acquire(|| 0), 0);

    assert_eq!(
        owner.relinquish_after_check(
            || 0,
            || {
                let (ready, ready_rx) = mpsc::channel();
                workers[0]
                    .stop
                    .send(WorkerCommand::Pending(ready))
                    .unwrap_or_else(|error| panic!("actual pending command: {error}"));
                ready_rx
                    .recv_timeout(
                        deadline
                            .remaining()
                            .unwrap_or_else(|error| panic!("original end: {error}")),
                    )
                    .unwrap_or_else(|error| panic!("actual received transition: {error}"));
            }
        ),
        -libc::EBUSY
    );
    assert_eq!(state.workers.snapshot().pending_mask, WORKER_RUN_CONTROL);
    let rings = state
        .setup
        .mapped_region()
        .hot_fork_ring_io_snapshot()
        .unwrap_or_else(|error| panic!("actual held rings: {error}"));
    assert_eq!(rings.held_rings(), rings.ring_count());
    assert!(state.quiescence.release_hot_fork().hot_fork_held);
    assert!(state.workers.release().held);
    drop(owner);
    stop_workers(workers);
}
