//! Checks the original consumer portion without issuing a Main or native pool.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::TestAllocationObserver;

fn ceiling() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 1 << 20,
        backing_peak_bytes: 1 << 20,
        metadata_bytes: 1 << 20,
        cpu_slots: 2,
        task_slots: 4,
        file_descriptors: 8,
        ..HostResourceVector::default()
    }
}

#[test]
fn consumer_checks_cannot_spend_pool_storage_or_permanent_worker_debt() {
    let layout = checked_layout(ceiling(), 17, 1).unwrap();
    let mut ledger = PoolLedger::new(
        ceiling(),
        layout.capacity,
        layout.controls,
        layout.shared_descriptors,
    )
    .unwrap();
    ledger.reserve_worker_controls(512).unwrap();
    let before = ledger.charged_resources();

    let (results, counts) = TestAllocationObserver::count(|| {
        [0, 16, 17, 18, 512, before.metadata_bytes, u64::MAX]
            .map(|bytes| layout.consumer_controls.require(bytes))
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    for (index, result) in results.iter().enumerate() {
        assert_eq!(result.is_ok(), index < 3);
    }
    assert_eq!(ledger.charged_resources(), before);
    assert_eq!(
        before.metadata_bytes,
        structure_bytes(layout.capacity).unwrap() + 17 + 512,
    );
    assert_eq!(before.resident_peak_bytes, before.metadata_bytes);
    assert_eq!(before.file_descriptors, 1);
    assert!(ledger.reserve_worker_controls(1).is_err());
    assert_eq!(ledger.charged_resources(), before);
}

#[test]
fn absent_consumer_prepayment_refuses_despite_unused_native_headroom() {
    let layout = checked_layout(ceiling(), 0, 1).unwrap();
    let ledger = PoolLedger::new(
        ceiling(),
        layout.capacity,
        layout.controls,
        layout.shared_descriptors,
    )
    .unwrap();
    let before = ledger.charged_resources();
    assert!(before.metadata_bytes > 0);
    assert!(before.metadata_bytes < ceiling().metadata_bytes);

    let (results, counts) = TestAllocationObserver::count(|| {
        [1, before.metadata_bytes, ceiling().metadata_bytes]
            .map(|bytes| layout.consumer_controls.require(bytes))
    });

    assert!(results.iter().all(Result::is_err));
    assert!(results.iter().all(|result| {
        matches!(
            result,
            Err(ServiceBirthError::Policy(std::borrow::Cow::Borrowed(_)))
        )
    }));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(ledger.charged_resources(), before);
}
