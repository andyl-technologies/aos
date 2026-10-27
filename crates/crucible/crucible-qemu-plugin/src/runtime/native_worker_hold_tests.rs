//! Real mutex-contention and poison refusal at the native preparation seam.

// crucible-lint: allow panic-shortcut -- Test-only assertions panic on an unmet custody or codec invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::sync::Barrier;

#[test]
fn foreign_worker_ownership_returns_busy_without_waiting_or_claiming_a_hold() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let locked = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let foreign = Arc::clone(&workers);
    let foreign_locked = Arc::clone(&locked);
    let foreign_release = Arc::clone(&release);
    let owner = std::thread::spawn(move || {
        let _original = foreign.state.lock().unwrap();
        foreign_locked.wait();
        foreign_release.wait();
    });
    locked.wait();

    // The foreign owner cannot release until these nonblocking attempts return.
    assert_eq!(workers.try_hold().unwrap(), None);
    assert_eq!(workers.try_snapshot().unwrap(), None);
    release.wait();
    owner.join().unwrap();

    assert!(!workers.snapshot().held);
    assert!(workers.try_hold().unwrap().unwrap().held);
    assert!(workers.try_snapshot().unwrap().unwrap().held);
}

#[test]
fn poisoned_worker_owner_is_never_adopted_as_an_authenticated_quiescent_cut() {
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    let foreign = Arc::clone(&workers);
    assert!(
        std::thread::spawn(move || {
            let _original = foreign.state.lock().unwrap();
            panic!("test original ownership poison");
        })
        .join()
        .is_err()
    );

    assert!(workers.try_hold().is_err());
    assert!(workers.try_snapshot().is_err());
}
