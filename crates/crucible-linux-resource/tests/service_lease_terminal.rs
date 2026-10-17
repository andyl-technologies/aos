//! Observes actual lease-control deallocation before its original charge closes.
//!
//! The shared allocator captures the original control's exact extent and layout.
//! Its fixed nonblocking probe retains the same account through all borrower
//! joins. A single physical final close must refuse the original resident byte
//! without allocating, before the complete reservation becomes available again.

// crucible-lint: allow panic-shortcut -- test fixtures panic to localize admission and allocation-order failures.
#![allow(clippy::unwrap_used)]

use std::alloc::Layout;
use std::sync::{Arc, Barrier, Mutex};

use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceError, HostServiceLease,
};
use crucible_linux_resource::test_support::{
    AllocationIdentity, ResidentProbeOutcome, ResidentProbeReport, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

// The process-wide watch belongs to one test through capture, joins, teardown,
// and refund verification. Borrower concurrency within that test is unchanged.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn captured_lease(account: &HostServiceAllocator) -> (HostServiceLease, AllocationIdentity) {
    let control_layout = Layout::from_size_align(48, 8).unwrap();
    let (lease, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(control_layout, || {
            account.reserve_resources(1, 1, 48).unwrap()
        });

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    (lease, identity.unwrap())
}

fn verify_original_refusal(report: ResidentProbeReport) {
    assert_eq!(
        report.outcome,
        ResidentProbeOutcome::Refused(HostServiceError::CapacityExhausted),
        "account refunded before control deallocation"
    );
    assert_eq!(report.counts.allocations, 0);
    assert_eq!(report.counts.reallocations, 0);
    assert!(!report.counts.overflow);
    assert_eq!(report.first_allocation, None);
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
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, target) = captured_lease(&account);
    let expected_debug = format!("{lease:?}");
    assert!(expected_debug.starts_with("HostServiceLease { reservation: ServiceReservation {"));

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || drop(lease))
            .unwrap();

    verify_original_refusal(report);
    verify_refunded(&account);
}

#[test]
fn concurrent_clones_extract_and_refund_exactly_once_after_close() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, target) = captured_lease(&account);
    let barrier = Arc::new(Barrier::new(8));
    let borrowers: Vec<_> = (0..8).map(|_| lease.clone()).collect();
    drop(lease);

    let (joined, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            std::thread::scope(|scope| {
                let workers: Vec<_> = borrowers
                    .into_iter()
                    .map(|borrower| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            barrier.wait();
                            drop(borrower);
                        })
                    })
                    .collect();

                workers
                    .into_iter()
                    .map(|worker| {
                        worker.join().unwrap();
                        1usize
                    })
                    .sum::<usize>()
            })
        })
        .unwrap();

    // One registry claim observes the allocation's one physical final close;
    // joining all eight borrowers precedes watch teardown and refund checks.
    assert_eq!(joined, 8);
    verify_original_refusal(report);
    verify_refunded(&account);
}

#[test]
fn unwind_closes_control_before_refunding_original_account() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 48).unwrap();
    let (lease, target) = captured_lease(&account);

    let (result, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            std::panic::catch_unwind(move || {
                let _borrower = lease;
                panic!("intentional borrower unwind");
            })
        })
        .unwrap();

    assert!(result.is_err());
    verify_original_refusal(report);
    verify_refunded(&account);
}
