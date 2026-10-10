//! Genuine original grants and terminal diagnostic custody for Memory maps.

use super::*;
use crucible_cas::content_store::{
    MemoryBlobBackend, ProviderDiagnosticPermit, ProviderFailureKind,
};
use crucible_cas::owned_decode::ResourceLoan;
use std::error::Error;

#[test]
fn concrete_namespace_and_diagnostic_geometry_is_prepaid() {
    assert_eq!(std::mem::size_of::<QuotaMetadataCredit>(), 24);
    assert_eq!(std::mem::size_of::<MemoryNamespaceCredit>(), 32);
    assert_eq!(
        ResourceLoan::allocation_bytes::<MemoryNamespaceCredit>(),
        48
    );
    assert_eq!(std::mem::size_of::<MemoryDiagnosticStorage>(), 8);
    assert_eq!(
        arc_allocation_bytes::<MemoryDiagnosticStorage>().unwrap(),
        24
    );
    assert_eq!(std::mem::size_of::<ProviderDiagnosticPermit>(), 16);
    assert_eq!(lease_control_bytes().unwrap(), 48);
    assert_eq!(MemoryBlobBackend::map_namespace_bytes(1).unwrap(), 544);
    assert_eq!(MemoryBlobBackend::map_namespace_bytes(64).unwrap(), 8544);
    eprintln!(
        "Memory grant: N1=544 N64=8544 loan_control48 paired_controls96; private pair24(+8), diagnostic_control24, permit16"
    );
}

fn available_metadata(binder: &LinuxProjectQuotaBinder) -> u64 {
    let projects =
        usize::try_from(binder.service.resources.maximum_file_descriptors() / 2).unwrap();
    binder.service.metadata.maximum_resident_bytes()
        - quota_bootstrap_bytes(BinderPublication::Value).unwrap()
        - quota_constructor_bytes(projects).unwrap()
}

#[test]
fn original_paired_namespace_grant_retains_both_accounts_until_loan_close() {
    let binder = config().build().unwrap();
    let available = available_metadata(&binder);
    let bytes = MemoryBlobBackend::map_namespace_bytes(1).unwrap();
    let charged = bytes
        + ResourceLoan::allocation_bytes::<MemoryNamespaceCredit>()
        + 2 * u64::try_from(lease_control_bytes().unwrap()).unwrap();
    assert!(available >= charged);
    let loan = binder.reserve_memory_namespace(bytes).unwrap();

    for account in [&binder.service.resources, &binder.service.metadata] {
        assert!(
            account
                .reserve_resources(0, 0, available - charged + 1)
                .is_err()
        );
    }
    binder.verify_memory_namespace().unwrap();
    drop(loan);

    for account in [&binder.service.resources, &binder.service.metadata] {
        assert!(account.reserve_resources(0, 0, available).is_ok());
    }
}

#[test]
fn unchanged_metadata_allowance_refuses_large_map_and_retains_original_cause() {
    let binder = config().build().unwrap();
    let error = binder
        .reserve_memory_namespace(MemoryBlobBackend::map_namespace_bytes(64).unwrap())
        .err()
        .unwrap();
    let StoreError::ProviderDiagnostic { source } = &error else {
        panic!("expected original funded resource refusal");
    };
    assert_eq!(source.kind(), ProviderFailureKind::Resources);
    assert!(matches!(
        source
            .source()
            .and_then(Error::source)
            .and_then(|cause| cause.downcast_ref::<HostServiceError>()),
        Some(HostServiceError::CapacityExhausted)
    ));
    assert!(matches!(
        binder.verify_memory_namespace(),
        Err(StoreError::Unavailable)
    ));

    drop(error);
    binder.verify_memory_namespace().unwrap();
    let loan = binder
        .reserve_memory_namespace(MemoryBlobBackend::map_namespace_bytes(1).unwrap())
        .unwrap();
    drop(loan);
}

#[test]
fn namespace_mutations_use_original_supervisor_after_preparation_has_completed() {
    let binder = config().build().unwrap();
    let loan = binder
        .reserve_memory_namespace(MemoryBlobBackend::map_namespace_bytes(1).unwrap())
        .unwrap();
    binder.verify_memory_namespace().unwrap();
    binder.service.supervisor.cancel().unwrap();
    let error = binder.verify_memory_namespace().err().unwrap();
    let StoreError::ProviderDiagnostic { source } = &error else {
        panic!("expected original funded supervision refusal");
    };
    assert_eq!(source.kind(), ProviderFailureKind::Supervision);
    assert!(matches!(
        source
            .source()
            .and_then(Error::source)
            .and_then(|cause| cause.downcast_ref::<HostSupervisionError>()),
        Some(HostSupervisionError::Terminal {
            state: crucible_linux_resource::host_supervision::HostOperationState::Canceled
        })
    ));
    drop(error);
    drop(loan);
}

fn large_map_error(binder: &LinuxProjectQuotaBinder) -> StoreError {
    binder
        .reserve_memory_namespace(MemoryBlobBackend::map_namespace_bytes(64).unwrap())
        .err()
        .unwrap()
}

fn capture_error(
    binder: &LinuxProjectQuotaBinder,
) -> (
    StoreError,
    [Option<crucible_linux_resource::test_support::AllocationIdentity>; 3],
) {
    crucible_linux_resource::test_support::TestAllocationObserver::capture_controls(
        [
            std::mem::size_of::<ProviderCause>(),
            arc_allocation_bytes::<MemoryDiagnosticStorage>().unwrap(),
            0,
        ],
        || large_map_error(binder),
    )
}

#[test]
fn source_and_exclusive_storage_close_before_slot_reuse_on_drop_and_unwind() {
    use crucible_linux_resource::test_support::TestAllocationObserver;
    for unwind in [false, true] {
        let binder = config().build().unwrap();
        let available = available_metadata(&binder);
        let expected = [
            Some(binder.service.resources.maximum_resident_bytes() - available),
            Some(binder.service.metadata.maximum_resident_bytes() - available),
        ];
        let (error, identities) = capture_error(&binder);
        assert!(identities[..2].iter().all(Option::is_some));
        let (refusal, counts) = TestAllocationObserver::count(|| binder.verify_memory_namespace());
        assert!(matches!(refusal, Err(StoreError::Unavailable)));
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        let (result, records) = TestAllocationObserver::observe_controls(
            [&binder.service.resources, &binder.service.metadata],
            Some(&binder.service.diagnostic_occupied),
            identities,
            || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let _error = error;
                    if unwind {
                        panic!("intentional original Memory diagnostic unwind");
                    }
                }))
            },
        );
        assert_eq!(result.is_err(), unwind);
        for (index, record) in records[..2].iter().enumerate() {
            let record = record.unwrap();
            assert_eq!(record.before.original_bytes, expected);
            assert_eq!(record.after.original_bytes, expected);
            assert_eq!(record.before.occupied, Some(true));
            assert_eq!(record.after.occupied, Some(true));
            assert_eq!(record.ordinal, (index + 1) as u8);
        }
        assert!(!binder.service.diagnostic_occupied.load(Ordering::Acquire));
        let (healthy, counts) = TestAllocationObserver::count(|| binder.verify_memory_namespace());
        healthy.unwrap();
        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
    }
}

#[test]
fn diagnostic_last_owner_keeps_both_original_grants_through_service_control_close() {
    use crucible_linux_resource::test_support::TestAllocationObserver;
    let (binder, service_control) =
        TestAllocationObserver::capture(arc_allocation_bytes::<QuotaService>().unwrap(), || {
            config().build().unwrap()
        });
    let available = available_metadata(&binder);
    let resident = binder.service.resources.clone();
    let metadata = binder.service.metadata.clone();
    let expected = [
        Some(resident.maximum_resident_bytes() - available),
        Some(metadata.maximum_resident_bytes() - available),
    ];
    let (error, mut identities) = capture_error(&binder);
    identities[2] = service_control;
    assert!(identities.iter().all(Option::is_some));
    drop(binder);

    // The accounts outlive this action independently. No occupancy reference
    // is borrowed from the service whose actual last control closes here.
    let (_, records) =
        TestAllocationObserver::observe_controls([&resident, &metadata], None, identities, || {
            drop(error)
        });
    for (index, record) in records.iter().enumerate() {
        let record = record.unwrap();
        assert_eq!(record.before.original_bytes, expected);
        assert_eq!(record.after.original_bytes, expected);
        assert_eq!(record.before.occupied, None);
        assert_eq!(record.after.occupied, None);
        assert_eq!(record.ordinal, (index + 1) as u8);
    }
    assert!(resident.reserve_resources(0, 0, 1).is_ok());
    assert!(metadata.reserve_resources(0, 0, 1).is_ok());
}

#[test]
fn concurrent_complete_error_owners_close_exclusive_storage_once() {
    use crucible_linux_resource::test_support::TestAllocationObserver;
    let binder = config().build().unwrap();
    let available = available_metadata(&binder);
    let expected = [
        Some(binder.service.resources.maximum_resident_bytes() - available),
        Some(binder.service.metadata.maximum_resident_bytes() - available),
    ];
    assert!(
        expected
            .iter()
            .all(|bytes| matches!(bytes, Some(bytes) if *bytes > 0))
    );
    let (error, identities) = capture_error(&binder);
    assert!(identities[..2].iter().all(Option::is_some));
    // The outer error/thread controls are model fixture storage outside the
    // original diagnostic grant claim. Only its concrete source/storage close
    // is observed; no independent storage alias or Weak owner escapes.
    let error = Arc::new(error);
    let barrier = std::sync::Barrier::new(8);
    let owners: Vec<_> = (0..8).map(|_| error.clone()).collect();
    drop(error);
    let records = std::thread::scope(|scope| {
        let workers: Vec<_> = owners
            .into_iter()
            .map(|owner| {
                let binder = &binder;
                let barrier = &barrier;
                scope.spawn(move || {
                    TestAllocationObserver::observe_controls(
                        [&binder.service.resources, &binder.service.metadata],
                        Some(&binder.service.diagnostic_occupied),
                        identities,
                        || {
                            barrier.wait();
                            drop(owner);
                        },
                    )
                    .1
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        records
            .iter()
            .filter(|records| records[..2].iter().all(Option::is_some))
            .count(),
        1
    );
    let last = records
        .iter()
        .find(|records| records[..2].iter().all(Option::is_some))
        .unwrap();
    for (index, record) in last[..2].iter().enumerate() {
        let record = record.unwrap();
        assert_eq!(record.before.occupied, Some(true));
        assert_eq!(record.after.occupied, Some(true));
        assert_eq!(record.before.original_bytes, expected);
        assert_eq!(record.after.original_bytes, expected);
        assert_eq!(record.ordinal, (index + 1) as u8);
    }
    assert!(!binder.service.diagnostic_occupied.load(Ordering::Acquire));
    binder.verify_memory_namespace().unwrap();
}
