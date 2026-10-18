//! Checks independent shutdown supervision after a real Rust worker fails.
//!
//! These controls issue no native membership or physical-return certificate.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::paged_ram::source::ObservationOperationError;
use std::cell::RefCell;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

struct FailedWorkerPost<'a> {
    worker: &'a Mutex<Option<JoinHandle<Result<(), RamError>>>>,
    body_retained: &'a AtomicBool,
    refuse: bool,
    checked: AtomicUsize,
}

impl SourceOperation for FailedWorkerPost<'_> {
    fn wait_slice(&self) -> io::Result<Duration> {
        assert!(matches!(
            self.worker.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        if self.body_retained.load(Ordering::Acquire) {
            self.checked.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
        }
        Ok(Duration::from_millis(1))
    }

    fn complete(&self) -> io::Result<()> {
        panic!("a failed worker cannot commit successful Cleanup accounting");
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        self.wait_slice().map_err(Into::into)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        panic!("worker shutdown cannot complete an observation");
    }
}

#[test]
fn worker_error_and_panic_keep_their_cause_and_independent_cleanup_post() {
    for panics in [false, true] {
        for refuse in [false, true] {
            let original = RamError::from(io::Error::from_raw_os_error(libc::EIO));
            let expected = if panics {
                RamError::Invariant("paging worker panicked during shutdown")
            } else {
                original.clone()
            };
            let worker = Mutex::new(Some(std::thread::spawn(move || {
                assert!(!panics, "worker panic control");
                Err(original)
            })));
            let body_retained = AtomicBool::new(false);
            let operation = FailedWorkerPost {
                worker: &worker,
                body_retained: &body_retained,
                refuse,
                checked: AtomicUsize::new(0),
            };
            let worker_failure = RefCell::new(None);
            let cleanup_failure = RefCell::new(None);

            let result = join_stopped_worker(
                &worker,
                &operation,
                |error| {
                    assert!(matches!(
                        worker.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ));
                    *worker_failure.borrow_mut() = Some(error.clone());
                    body_retained.store(true, Ordering::Release);
                },
                |error| {
                    assert!(body_retained.load(Ordering::Acquire));
                    assert!(matches!(
                        worker.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ));
                    *cleanup_failure.borrow_mut() = Some(error.clone());
                },
            );

            assert_eq!(result, Err(expected.clone()));
            assert_eq!(worker_failure.borrow().as_ref(), Some(&expected));
            assert_eq!(operation.checked.load(Ordering::SeqCst), 1);
            let cleanup_failure = cleanup_failure.into_inner();
            if refuse {
                assert!(matches!(
                    cleanup_failure,
                    Some(RamError::Io(error))
                        if error.raw_os_error() == Some(libc::ECANCELED)
                ));
            } else {
                assert!(cleanup_failure.is_none());
            }
            assert!(worker.try_lock().unwrap().is_none());
        }
    }
}
