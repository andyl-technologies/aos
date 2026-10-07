//! Observes actual lease-control deallocation before its original charge closes.
//!
//! The test allocator watches one exact control allocation per thread. Its
//! public admission probe runs after deallocation, with the watch disarmed.
//! A corrected lease still fills its account and refuses without allocation;
//! the predecessor accepts and allocates a temporary lease as a causal control.

// crucible-lint: allow panic-shortcut -- test fixtures panic to localize admission and allocation-order failures.
#![allow(clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, Barrier};

use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};

#[derive(Clone, Copy)]
struct Watch {
    capture: bool,
    target: usize,
    account: *const HostServiceAllocator,
    observation: u8,
}

thread_local! {
    static WATCH: Cell<Watch> = const { Cell::new(Watch {
        capture: false,
        target: 0,
        account: std::ptr::null(),
        observation: 0,
    }) };
}

struct ObserverAllocator;

// SAFETY: Allocations delegate unchanged to System. Observation is thread-local,
// retains no pointers to allocation contents, and disarms before any probe.
unsafe impl GlobalAlloc for ObserverAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller's exact layout is forwarded to System.
        let pointer = unsafe { System.alloc(layout) };
        let _ = WATCH.try_with(|watch| {
            let mut state = watch.get();
            if state.capture && layout.size() == 48 && layout.align() == 8 {
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

        // SAFETY: The original pointer and layout are delegated exactly once.
        unsafe { System.dealloc(pointer, layout) };

        if let Some(mut state) = observed {
            // SAFETY: Arm borrows this account for a synchronous drop on the
            // same thread. The account outlives that drop and the probe; its
            // pointer never escapes TLS. No allocation contents are accessed.
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

fn clear_watch() -> Watch {
    WATCH.with(|watch| {
        watch.replace(Watch {
            capture: false,
            target: 0,
            account: std::ptr::null(),
            observation: 0,
        })
    })
}

fn captured_lease(account: &HostServiceAllocator) -> (HostServiceLease, usize) {
    WATCH.with(|watch| {
        watch.set(Watch {
            capture: true,
            target: 0,
            account,
            observation: 0,
        })
    });
    let lease = account.reserve_resources(1, 1, 48).unwrap();
    let target = clear_watch().target;
    assert_ne!(target, 0);
    (lease, target)
}

fn arm(account: &HostServiceAllocator, target: usize) {
    WATCH.with(|watch| {
        watch.set(Watch {
            capture: false,
            target,
            account,
            observation: 0,
        })
    });
}

fn verify_refunded(account: &HostServiceAllocator) {
    let replacement = account.reserve_resources(1, 1, 48).unwrap();
    assert_eq!(replacement.tasks(), 1);
    assert_eq!(replacement.file_descriptors(), 1);
    assert_eq!(replacement.resident_bytes(), 48);
    assert_eq!(std::mem::size_of::<HostServiceLease>(), 8);
    assert_eq!(HostServiceLease::metadata_bytes(), 56);
}

#[test]
fn actual_control_closes_before_original_charge_refund() {
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, target) = captured_lease(&account);
    let expected_debug = format!("{lease:?}");
    assert!(expected_debug.starts_with("HostServiceLease { reservation: ServiceReservation {"));

    arm(&account, target);
    drop(lease);
    let observation = clear_watch().observation;

    assert_eq!(
        observation, 1,
        "account refunded before control deallocation"
    );
    verify_refunded(&account);
}

#[test]
fn concurrent_clones_extract_and_refund_exactly_once_after_close() {
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, target) = captured_lease(&account);
    let barrier = Arc::new(Barrier::new(8));
    let borrowers: Vec<_> = (0..8).map(|_| lease.clone()).collect();
    drop(lease);

    let observations = std::thread::scope(|scope| {
        let workers: Vec<_> = borrowers
            .into_iter()
            .map(|borrower| {
                let account = &account;
                let barrier = &barrier;
                scope.spawn(move || {
                    arm(account, target);
                    barrier.wait();
                    drop(borrower);
                    clear_watch().observation
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
    verify_refunded(&account);
}

#[test]
fn unwind_closes_control_before_refunding_original_account() {
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, target) = captured_lease(&account);

    arm(&account, target);
    let result = std::panic::catch_unwind(move || {
        let _borrower = lease;
        panic!("intentional borrower unwind");
    });
    let observation = clear_watch().observation;

    assert!(result.is_err());
    assert_eq!(observation, 1);
    verify_refunded(&account);
}
