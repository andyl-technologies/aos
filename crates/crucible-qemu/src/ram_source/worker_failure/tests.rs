//! Actual worker-control close before original service credit becomes reusable.
//!
//! The sole shared observer captures each original worker control exactly once.
//! One family mutex covers capture, all real borrower joins, probe teardown and
//! refund verification; concurrent borrowers still contend within each action.

// crucible-lint: allow panic-shortcut -- allocation-order fixtures panic to localize proof failures.
#![allow(clippy::unwrap_used)]

use std::sync::atomic::Ordering;

mod backend_cause;
mod worker_scope;

use super::*;
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceError};
use crucible_linux_resource::test_support::{
    AllocationIdentity, ResidentProbeOutcome, ResidentProbeReport, TestAllocationObserver,
};

#[global_allocator]
static ALLOCATOR: TestAllocationObserver = TestAllocationObserver;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn failure(account: &HostServiceAllocator) -> (QemuRamWorkerFailure, AllocationIdentity) {
    failure_with_error(account, QemuRamSourceError::Ownership)
}

fn failure_with_error(
    account: &HostServiceAllocator,
    error: QemuRamSourceError,
) -> (QemuRamWorkerFailure, AllocationIdentity) {
    let bytes = account.maximum_resident_bytes();
    let loan = account.reserve_resources(1, 1, bytes).unwrap();
    captured_failure(error, loan)
}

fn captured_failure(
    error: QemuRamSourceError,
    loan: HostServiceLease,
) -> (QemuRamWorkerFailure, AllocationIdentity) {
    let expected = usize::try_from(QemuRamWorkerFailure::allocation_bytes().unwrap()).unwrap();
    let layout = Layout::from_size_align(expected, 8).unwrap();
    let (failure, identity, counts) =
        TestAllocationObserver::capture_layout_and_count(layout, || {
            QemuRamWorkerFailure::new(error, loan)
        });

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    (failure, identity.unwrap())
}

fn verify_original_refusal(report: ResidentProbeReport) {
    assert_eq!(
        report.outcome,
        ResidentProbeOutcome::Refused(HostServiceError::CapacityExhausted),
        "worker credit became reusable before actual control free"
    );
    assert_eq!(report.counts.allocations, 0);
    assert_eq!(report.counts.reallocations, 0);
    assert!(!report.counts.overflow);
    assert_eq!(report.first_allocation, None);
}

fn verify_closed(account: &HostServiceAllocator) {
    let restored = account
        .reserve_resources(1, 1, account.maximum_resident_bytes())
        .unwrap();
    assert_eq!(restored.tasks(), 1);
    assert_eq!(restored.file_descriptors(), 1);
    assert_eq!(restored.resident_bytes(), account.maximum_resident_bytes());
}

#[test]
fn actual_worker_allocation_closes_before_original_credit_refund() {
    let _serial = TEST_LOCK.lock().unwrap();
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

    let (_, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || drop(clone))
            .unwrap();

    verify_original_refusal(report);
    verify_closed(&account);
}

#[test]
fn simultaneous_worker_observers_release_original_credit_once_after_close() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let (failure, target) = failure(&account);
    let barrier = std::sync::Barrier::new(8);
    let clones: Vec<_> = (0..8).map(|_| failure.clone()).collect();
    drop(failure);

    let (joined, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            std::thread::scope(|scope| {
                let workers: Vec<_> = clones
                    .into_iter()
                    .enumerate()
                    .map(|(index, clone)| {
                        let barrier = &barrier;
                        scope.spawn(move || {
                            barrier.wait();
                            if index % 2 == 0 {
                                drop(clone.into_backend_cause());
                            } else {
                                drop(clone);
                            }
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

    assert_eq!(joined, 8);
    verify_original_refusal(report);
    verify_closed(&account);
}

#[test]
fn worker_observer_unwind_closes_control_before_original_refund() {
    let _serial = TEST_LOCK.lock().unwrap();
    let account = HostServiceAllocator::new(1, 1, 4096).unwrap();
    let (failure, target) = failure(&account);

    let (result, report) =
        TestAllocationObserver::observe_resident_after_free(&account, target, || {
            // The panic destroys the moved owner; no mutable payload is reused.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _observer = failure;
                panic!("intentional worker observer unwind");
            }))
        })
        .unwrap();

    assert!(result.is_err());
    verify_original_refusal(report);
    verify_closed(&account);
}
