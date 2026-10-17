//! Namespace admission, zero-byte object capacity and current caller execution.

use super::checked_tests::account;
use super::tests::{Quota, namespace_binder};
use super::*;
use std::sync::atomic::AtomicBool;

fn namespace(bytes: u64) -> Arc<Quota> {
    Arc::new(Quota {
        resources: crate::content_store::test_resources::FixtureResourceBudget::new(128, bytes),
        closed: AtomicBool::new(false),
    })
}

#[test]
fn ordinary_memory_refuses_checked_ram_before_callbacks() {
    let backend = MemoryBlobBackend::new("ordinary", 4096);
    let (_, original) = account();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    let mut calls = 0;
    let error = backend
        .put_many_if_absent_with_boundary(&original, &[], &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "checked-memory-namespace"
        }
    ));
    let error = backend
        .read_with_boundary(&original, id, None, &mut || {
            calls += 1;
            Ok(())
        })
        .err()
        .unwrap();
    assert!(matches!(
        error,
        StoreError::Unsupported {
            capability: "checked-memory-namespace"
        }
    ));
    assert_eq!(calls, 0);
    assert_eq!(backend.object_count().unwrap(), 0);
}

#[test]
fn finite_namespace_refuses_unaffordable_or_overflowing_capacity_before_charge() {
    let original = namespace(4096);
    assert_eq!(MemoryBlobBackend::map_namespace_bytes(1).unwrap(), 544);
    assert_eq!(MemoryBlobBackend::map_namespace_bytes(64).unwrap(), 8544);
    assert_eq!(MemoryBlobBackend::map_namespace_bytes(256).unwrap(), 31_072);
    assert_eq!(
        MemoryBlobBackend::map_namespace_bytes(8192).unwrap(),
        921_024
    );
    assert!(matches!(
        MemoryBlobBackend::map_namespace_bytes(0),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        MemoryBlobBackend::map_namespace_bytes(u64::MAX),
        Err(StoreError::Quota)
    ));

    assert!(
        MemoryBlobBackend::new_admitted(
            "unaffordable",
            4096,
            64,
            namespace_binder(original.clone())
        )
        .is_err()
    );
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
    original.closed.store(true, Ordering::SeqCst);
    assert!(
        MemoryBlobBackend::new_admitted("closed", 4096, 1, namespace_binder(original.clone()))
            .is_err()
    );
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}

#[test]
fn unique_empty_objects_consume_slots_and_duplicates_do_not() {
    let original = namespace(4096);
    let backend =
        MemoryBlobBackend::new_admitted("finite", 0, 1, namespace_binder(original.clone()))
            .unwrap();
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    let second = ContentId::for_bytes(ObjectKind::Trace, 2, &[]);
    let source = BlobHandle::from_bytes(Vec::new());
    backend.put_if_absent(first, &source).unwrap();
    backend.put_if_absent(first, &source).unwrap();
    assert!(matches!(
        backend.put_if_absent(second, &source),
        Err(StoreError::Quota)
    ));
    assert_eq!(backend.object_count().unwrap(), 1);
    assert_eq!(backend.logical_bytes().unwrap(), 0);

    let (_, caller) = account();
    let receipt = backend
        .put_many_if_absent_with_boundary(&caller, &[(first, source.clone())], &mut || Ok(()))
        .unwrap()
        .accept_with_boundary(&mut || Ok(()))
        .unwrap();
    drop(receipt);
    let error = backend
        .put_many_if_absent_with_boundary(&caller, &[(second, source)], &mut || Ok(()))
        .unwrap_err();
    let StoreError::MemoryScope { source } = error else {
        panic!("missing concrete Memory scope")
    };
    assert!(matches!(source.work_failure(), StoreError::Quota));
    assert_eq!(source.outcome().published_objects, 0);
    assert_eq!(backend.object_count().unwrap(), 1);

    let mut fence = backend.acquire_inventory_fence().unwrap();
    fence.delete_candidate(first).unwrap();
    drop(fence);
    assert_eq!(original.resources.usage().unwrap().1, 544);
    backend
        .put_if_absent(second, &BlobHandle::from_bytes(Vec::new()))
        .unwrap();
    drop(backend);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}

#[test]
fn retained_namespace_credit_is_not_current_read_execution_authority() {
    let original = namespace(4096);
    let backend =
        MemoryBlobBackend::new_admitted("finite", 4096, 2, namespace_binder(original.clone()))
            .unwrap();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[17]);
    let source = BlobHandle::from_bytes(vec![17]);
    backend.put_if_absent(id, &source).unwrap();
    original.closed.store(true, Ordering::SeqCst);

    let (current, caller) = account();
    let handle = backend
        .read_with_boundary(&caller, id, None, &mut || Ok(()))
        .unwrap();
    let bytes = handle
        .read_all_with_boundary(&caller, 4096, &mut || Ok(()))
        .unwrap();
    assert_eq!(&*bytes, &[17]);
    let next = ContentId::for_bytes(ObjectKind::Trace, 2, &[17]);
    assert!(backend.put_if_absent(next, &source).is_err());
    assert_eq!(backend.object_count().unwrap(), 1);

    current.closed.store(true, Ordering::SeqCst);
    assert!(
        backend
            .read_with_boundary(&caller, id, None, &mut || Ok(()))
            .is_err()
    );
}

#[test]
fn namespace_revocation_by_callback_keeps_original_refusal_and_no_insertion() {
    let original = namespace(16_384);
    let backend =
        MemoryBlobBackend::new_admitted("finite", 4096, 64, namespace_binder(original.clone()))
            .unwrap();
    let (_, caller) = account();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    let source = BlobHandle::from_bytes(Vec::new());
    let error = backend
        .put_many_if_absent_with_boundary(&caller, &[(id, source)], &mut || {
            original.closed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
    let StoreError::MemoryScope { source } = error else {
        panic!("missing original namespace failure scope")
    };
    assert!(matches!(
        source.work_failure(),
        StoreError::DecodeAdmission { .. }
    ));
    assert_eq!(source.outcome().published_objects, 0);
    assert_eq!(backend.object_count().unwrap(), 0);
    assert_eq!(original.resources.usage().unwrap().1, 8544);
    drop(source);
    drop(backend);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}

#[test]
fn late_namespace_revocation_after_body_admission_refuses_before_insertion() {
    let original = namespace(16_384);
    let backend =
        MemoryBlobBackend::new_admitted("finite", 4096, 64, namespace_binder(original.clone()))
            .unwrap();
    let (caller_quota, caller) = account();
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    let body_bytes =
        (std::mem::size_of::<MemoryObject>() + 2 * std::mem::size_of::<usize>()) as u64;
    let mut previous_usage = caller_quota.resources.usage().unwrap().1;
    let mut revoked_after_admission = false;

    let error = backend
        .put_many_if_absent_with_boundary(
            &caller,
            &[(id, BlobHandle::from_bytes(Vec::new()))],
            &mut || {
                let usage = caller_quota.resources.usage().unwrap().1;
                // The post-reservation callback runs while the existing map
                // lock is held, unlike all earlier source/lock callbacks.
                if matches!(
                    backend.state.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ) && previous_usage.checked_add(body_bytes) == Some(usage)
                {
                    assert!(!revoked_after_admission);
                    revoked_after_admission = true;
                    original.closed.store(true, Ordering::SeqCst);
                }
                previous_usage = usage;
                Ok(())
            },
        )
        .unwrap_err();

    assert!(revoked_after_admission);
    let StoreError::MemoryScope { source } = error else {
        panic!("missing late original namespace failure scope")
    };
    assert!(matches!(
        source.work_failure(),
        StoreError::DecodeAdmission { .. }
    ));
    assert_eq!(source.outcome().published_objects, 0);
    assert_eq!(source.outcome().accepted_objects, 0);
    assert_eq!(backend.object_count().unwrap(), 0);
    assert_eq!(original.resources.usage().unwrap().1, 8544);

    drop(source);
    drop(backend);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}

#[test]
fn repair_respects_unique_capacity_and_reuses_deleted_slots() {
    let original = namespace(4096);
    let backend =
        MemoryBlobBackend::new_admitted("finite", 0, 1, namespace_binder(original.clone()))
            .unwrap();
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, &[]);
    let second = ContentId::for_bytes(ObjectKind::Trace, 2, &[]);
    let source = BlobHandle::from_bytes(Vec::new());
    let authority = PhysicalRepairAuthority::new();

    let mut fence = backend.acquire_inventory_fence().unwrap();
    fence
        .repair_put_if_absent(&authority, first, &source)
        .unwrap();
    fence
        .repair_put_if_absent(&authority, first, &source)
        .unwrap();
    assert!(matches!(
        fence.repair_put_if_absent(&authority, second, &source),
        Err(StoreError::Quota)
    ));
    fence.delete_candidate(first).unwrap();
    fence
        .repair_put_if_absent(&authority, second, &source)
        .unwrap();
    drop(fence);

    assert_eq!(backend.object_count().unwrap(), 1);
    assert_eq!(backend.logical_bytes().unwrap(), 0);
    assert_eq!(original.resources.usage().unwrap().1, 544);
    drop(backend);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}
