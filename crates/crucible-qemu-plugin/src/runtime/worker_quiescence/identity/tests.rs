//! Exercises actual actor incarnations and failure-aware private membership.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn parked_actor(
    workers: &Arc<LiveWorkerQuiescence>,
    role: u64,
) -> (mpsc::Sender<()>, thread::JoinHandle<()>) {
    let workers = Arc::clone(workers);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel();
    let actor = thread::spawn(move || {
        let _identity = workers
            .register_current(role)
            .unwrap_or_else(|error| panic!("actor registration failed: {error}"));
        let _parked = workers.idle(role);
        ready_tx
            .send(())
            .unwrap_or_else(|error| panic!("ready send failed: {error}"));
        stop_rx
            .recv()
            .unwrap_or_else(|error| panic!("stop receive failed: {error}"));
    });
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("actor did not park: {error}"));
    (stop_tx, actor)
}

fn stop_actor(actor: (mpsc::Sender<()>, thread::JoinHandle<()>)) {
    actor
        .0
        .send(())
        .unwrap_or_else(|error| panic!("stop send failed: {error}"));
    actor.1.join().unwrap_or_else(|_| panic!("actor panicked"));
}

#[test]
fn real_actor_ids_are_distinct_and_exit_advances_membership() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let control = parked_actor(&workers, WORKER_RUN_CONTROL);
    let teardown = parked_actor(&workers, WORKER_TEARDOWN);
    // A finite scripted supervision receipt permits one ready inspection.
    // Regression cannot turn the fixture into an unbounded polling loop.
    let mut remaining_checks = 1;
    workers
        .wait_initial_ready(|| {
            if remaining_checks == 0 {
                return Err(RamError::Invariant("fixture readiness receipt expired"));
            }
            remaining_checks -= 1;
            Ok(Duration::from_millis(1))
        })
        .unwrap_or_else(|error| panic!("ready admission failed: {error}"));
    let live = workers
        .identity_snapshot()
        .unwrap_or_else(|error| panic!("snapshot failed: {error}"));
    assert_eq!(live.process_id, u64::from(std::process::id()));
    assert_ne!(live.thread_ids[0], 0);
    assert_ne!(live.thread_ids[1], 0);
    assert_ne!(live.thread_ids[0], live.thread_ids[1]);
    assert_eq!(live.thread_ids[2], 0);
    assert!(workers.identities_complete(&live));

    stop_actor(control);
    let exited = workers
        .identity_snapshot()
        .unwrap_or_else(|error| panic!("snapshot failed: {error}"));
    assert_eq!(exited.thread_ids[0], 0);
    assert!(exited.membership_generation > live.membership_generation);
    assert!(!workers.identities_complete(&exited));
    stop_actor(teardown);
}

#[test]
fn duplicate_role_or_tid_latches_failure_without_replacing_incarnation() {
    for second_role in [WORKER_RUN_CONTROL, WORKER_TEARDOWN] {
        let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        let identity = workers
            .register_current(WORKER_RUN_CONTROL)
            .unwrap_or_else(|error| panic!("registration failed: {error}"));
        let before = workers.snapshot();
        assert!(workers.register_current(second_role).is_err());
        let after = workers.snapshot();
        assert_eq!(after.thread_ids, before.thread_ids);
        assert_eq!(after.membership_generation, before.membership_generation);
        assert!(after.identity_failed);
        assert!(workers.identity_snapshot().is_err());
        drop(identity);
    }
}

#[test]
fn zero_undeclared_and_foreign_process_entries_are_refused() {
    for (role, pid, tid) in [
        (WORKER_RUN_CONTROL, u64::from(std::process::id()), 0),
        (WORKER_FINGERPRINT, u64::from(std::process::id()), 1),
        (WORKER_RUN_CONTROL, u64::from(std::process::id()) + 1, 1),
        (0, u64::from(std::process::id()), 1),
    ] {
        let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
        assert!(workers.register_identity(role, pid, tid).is_err());
        assert_eq!(workers.snapshot().thread_ids, [0; 3]);
        assert!(workers.identity_snapshot().is_err());
    }
}

#[test]
fn held_exit_invalidates_the_retained_snapshot() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let control = parked_actor(&workers, WORKER_RUN_CONTROL);
    let teardown = parked_actor(&workers, WORKER_TEARDOWN);
    let held = workers.hold();
    assert!(workers.snapshot_ready(&held));
    stop_actor(control);
    let after = workers.snapshot();
    assert!(after.membership_generation > held.membership_generation);
    assert!(after.identity_failed);
    assert!(!workers.snapshot_ready(&after));
    assert!(workers.identity_snapshot().is_err());
    workers.release();
    stop_actor(teardown);
}

#[test]
fn optional_fingerprint_requires_a_real_third_actor() {
    let workers = LiveWorkerQuiescence::new(WORKER_ALL);
    let control = parked_actor(&workers, WORKER_RUN_CONTROL);
    let teardown = parked_actor(&workers, WORKER_TEARDOWN);
    assert!(!workers.identities_complete(&workers.snapshot()));
    let fingerprint = parked_actor(&workers, WORKER_FINGERPRINT);
    assert!(workers.snapshot_ready(&workers.hold()));
    workers.release();
    stop_actor(control);
    stop_actor(teardown);
    stop_actor(fingerprint);
}

#[test]
fn original_setup_refusal_precedes_readiness_and_preserves_owner() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let control = parked_actor(&workers, WORKER_RUN_CONTROL);
    let teardown = parked_actor(&workers, WORKER_TEARDOWN);
    let before = workers.snapshot();
    let source = RamError::Invariant("original Setup expired");
    let result = workers.wait_initial_ready(|| Err(source.clone()));
    assert_eq!(result, Err(source));
    assert_eq!(workers.snapshot(), before);
    stop_actor(control);
    stop_actor(teardown);
}

#[test]
fn copied_parent_identity_is_cleared_before_fresh_actor_readiness() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    {
        // Models a copied parent tuple; real actors below still self-register.
        let mut copied = workers.lock_state();
        copied.held = true;
        copied.parked_mask = WORKER_REQUIRED;
        copied.process_id = u64::from(std::process::id()) + 1;
        copied.thread_ids = [991, 992, 0];
    }
    workers
        .reset_fork_child_workers()
        .unwrap_or_else(|error| panic!("child reset failed: {error}"));
    assert_eq!(workers.snapshot().thread_ids, [0; 3]);
    assert!(!workers.fork_child_workers_ready());
    let control = parked_actor(&workers, WORKER_RUN_CONTROL);
    assert!(!workers.fork_child_workers_ready());
    let teardown = parked_actor(&workers, WORKER_TEARDOWN);
    assert!(workers.fork_child_workers_ready());
    workers.release();
    stop_actor(control);
    stop_actor(teardown);
}

#[test]
fn exhausted_epoch_refuses_registration_and_publication() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    workers.lock_state().membership_generation = u64::MAX;
    assert!(workers.register_current(WORKER_RUN_CONTROL).is_err());
    assert_eq!(workers.snapshot().thread_ids, [0; 3]);
    assert!(workers.identity_snapshot().is_err());
}

#[test]
fn private_schema_seven_matches_the_native_fixed_layout() {
    use crate::QemuPluginHotForkBarrierStatus;

    assert_eq!(crate::QEMU_PLUGIN_HOT_FORK_BARRIER_STATUS_VERSION, 7);
    assert_eq!(std::mem::size_of::<QemuPluginHotForkBarrierStatus>(), 128);
    assert_eq!(
        std::mem::offset_of!(QemuPluginHotForkBarrierStatus, worker_process_id),
        88
    );
    assert_eq!(
        std::mem::offset_of!(QemuPluginHotForkBarrierStatus, worker_membership_generation),
        96
    );
    assert_eq!(
        std::mem::offset_of!(QemuPluginHotForkBarrierStatus, worker_thread_ids),
        104
    );
}
