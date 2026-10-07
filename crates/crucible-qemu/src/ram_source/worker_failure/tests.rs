//! Actual worker-control close before original service credit becomes reusable.

// crucible-lint: allow panic-shortcut -- allocation-order fixtures panic to localize proof failures.
#![allow(clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

mod backend_cause;
mod worker_scope;

static DETACHED_TARGET: AtomicUsize = AtomicUsize::new(0);
static DETACHED_ACCOUNT: AtomicPtr<HostServiceAllocator> = AtomicPtr::new(std::ptr::null_mut());
static DETACHED_OBSERVATION: AtomicU8 = AtomicU8::new(0);

use super::*;
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceError};

#[derive(Clone, Copy)]
struct Watch {
    capture: bool,
    expected: usize,
    target: usize,
    account: *const HostServiceAllocator,
    observation: u8,
}

thread_local! {
    static WATCH: Cell<Watch> = const { Cell::new(Watch {
        capture: false,
        expected: 0,
        target: 0,
        account: std::ptr::null(),
        observation: 0,
    }) };
}

struct ObserverAllocator;

// SAFETY: Every allocation delegates unchanged to System. The observer stores
// integer addresses, never accesses allocation contents, and disarms its probe.
unsafe impl GlobalAlloc for ObserverAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The exact caller layout is forwarded unchanged to System.
        let pointer = unsafe { System.alloc(layout) };
        let _ = WATCH.try_with(|watch| {
            let mut state = watch.get();
            if state.capture && layout.size() == state.expected && layout.align() == 8 {
                state.capture = false;
                state.target = pointer as usize;
                watch.set(state);
            }
        });
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let observed = WATCH
            .try_with(|watch| {
                let mut state = watch.get();
                if state.target != 0 && state.target == pointer as usize {
                    state.target = 0;
                    watch.set(state);
                    Some(state)
                } else {
                    None
                }
            })
            .ok()
            .flatten();

        // SAFETY: The original allocation and layout are delegated exactly once.
        unsafe { System.dealloc(pointer, layout) };
        if DETACHED_TARGET
            .compare_exchange(pointer as usize, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let account = DETACHED_ACCOUNT.load(Ordering::Acquire);
            // SAFETY: The serialized detached-worker fixture keeps this actual
            // allocator borrowed through actual worker join, including panic.
            // The pointer is cleared only after that worker has fully closed.
            let result = unsafe { &*account }.reserve_resources(0, 0, 1);
            let observation = match result {
                Err(HostServiceError::CapacityExhausted) => 1,
                Ok(_) => 2,
                Err(_) => 3,
            };
            DETACHED_OBSERVATION.store(observation, Ordering::Release);
        }
        if let Some(mut state) = observed {
            // SAFETY: Arm borrows this actual allocator throughout synchronous
            // Drop and the probe. Scoped threads cannot outlive that allocator;
            // its pointer never escapes the thread-local observation guard.
            let result = unsafe { &*state.account }.reserve_resources(0, 0, 1);
            state.observation = match result {
                Err(HostServiceError::CapacityExhausted) => 1,
                Ok(_) => 2,
                Err(_) => 3,
            };
            let _ = WATCH.try_with(|watch| watch.set(state));
        }
    }
}

#[global_allocator]
static ALLOCATOR: ObserverAllocator = ObserverAllocator;

fn clear() -> Watch {
    WATCH.with(|watch| {
        watch.replace(Watch {
            capture: false,
            expected: 0,
            target: 0,
            account: std::ptr::null(),
            observation: 0,
        })
    })
}

fn arm(account: &HostServiceAllocator, target: usize) {
    WATCH.with(|watch| {
        watch.set(Watch {
            capture: false,
            expected: 0,
            target,
            account,
            observation: 0,
        })
    });
}

fn failure(account: &HostServiceAllocator) -> (QemuRamWorkerFailure, usize) {
    failure_with_error(account, QemuRamSourceError::Ownership)
}

fn failure_with_error(
    account: &HostServiceAllocator,
    error: QemuRamSourceError,
) -> (QemuRamWorkerFailure, usize) {
    let bytes = account.maximum_resident_bytes();
    let loan = account.reserve_resources(1, 1, bytes).unwrap();
    let expected = QemuRamWorkerFailure::allocation_bytes().unwrap() as usize;
    WATCH.with(|watch| {
        watch.set(Watch {
            capture: true,
            expected,
            target: 0,
            account,
            observation: 0,
        })
    });
    let failure = QemuRamWorkerFailure::new(error, loan);
    let captured = clear();
    assert_ne!(
        captured.target, 0,
        "actual worker Arc extent differs from admission"
    );
    (failure, captured.target)
}

fn verify_closed(account: &HostServiceAllocator) {
    let restored = account
        .reserve_resources(1, 1, account.maximum_resident_bytes())
        .unwrap();
    assert_eq!(restored.tasks(), 1);
    assert_eq!(restored.file_descriptors(), 1);
}

#[test]
fn actual_worker_allocation_closes_before_original_credit_refund() {
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let (failure, target) = failure(&account);
    eprintln!(
        "worker geometry: error={}, body={}, control={}, startup={}, lease={}",
        std::mem::size_of::<QemuRamSourceError>(),
        std::mem::size_of::<WorkerFailureBody>(),
        QemuRamWorkerFailure::allocation_bytes().unwrap(),
        QemuRamWorkerFailure::startup_metadata_bytes().unwrap(),
        HostServiceLease::metadata_bytes(),
    );
    let clone = failure.clone();
    assert_eq!(failure, clone);
    drop(failure);
    assert!(matches!(
        account.reserve_resources(0, 0, 1),
        Err(HostServiceError::CapacityExhausted)
    ));

    arm(&account, target);
    drop(clone);
    let observation = clear().observation;

    assert_eq!(
        observation, 1,
        "worker credit became reusable before actual control free"
    );
    verify_closed(&account);
}

#[test]
fn simultaneous_worker_observers_release_original_credit_once_after_close() {
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let (failure, target) = failure(&account);
    let barrier = std::sync::Barrier::new(8);
    let clones: Vec<_> = (0..8).map(|_| failure.clone()).collect();
    drop(failure);
    let observations = std::thread::scope(|scope| {
        let workers: Vec<_> = clones
            .into_iter()
            .enumerate()
            .map(|(index, clone)| {
                let account = &account;
                let barrier = &barrier;
                scope.spawn(move || {
                    arm(account, target);
                    barrier.wait();
                    if index % 2 == 0 {
                        drop(clone.into_backend_cause());
                    } else {
                        drop(clone);
                    }
                    clear().observation
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });

    assert_eq!(observations.iter().filter(|&&value| value == 1).count(), 1);
    assert!(observations.iter().all(|&value| value <= 1));
    verify_closed(&account);
}

#[test]
fn worker_observer_unwind_closes_control_before_original_refund() {
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let (failure, target) = failure(&account);

    arm(&account, target);
    // The panic destroys the moved owner; no mutable payload is reused afterward.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _observer = failure;
        panic!("intentional worker observer unwind");
    }));
    let observation = clear().observation;

    assert!(result.is_err());
    assert_eq!(observation, 1);
    verify_closed(&account);
}
