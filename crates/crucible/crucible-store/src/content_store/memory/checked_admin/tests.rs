//! Real Memory maintenance effects, original identity and final output custody.

use super::*;
use crate::content_store::admin::outcome::test_original::assert_closed;
use crate::content_store::memory::checked_tests::account;

fn populated() -> (MemoryBlobBackend, ContentId) {
    let backend = MemoryBlobBackend::new("admin-memory", 1024);
    let bytes = b"checked Memory orphan";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    (backend, id)
}

#[test]
fn owning_outputs_keep_original_credit_after_fence_closes() {
    let (backend, id) = populated();
    let (quota, original) = account();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let summary = fence
        .visit_inventory_with_boundary(&mut |_| Ok(()), &mut || Ok(()))
        .unwrap();
    assert_eq!(summary.objects(), 1);
    let deleted = fence
        .delete_candidates_with_boundary(&[id, id], &mut || Ok(()))
        .unwrap();
    assert_eq!(
        &*deleted,
        &[
            PlannedDeleteDisposition::Deleted,
            PlannedDeleteDisposition::AlreadyAbsent
        ]
    );
    drop(fence);
    assert!(quota.resources.usage().unwrap().1 > baseline.1);
    assert_eq!(summary.objects(), 1);
    assert!(!backend.contains(id).unwrap());
    drop(summary);
    drop(deleted);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
}

#[test]
fn foreign_original_and_first_visitor_refusal_cannot_delete() {
    let (backend, id) = populated();
    let (_, original) = account();
    let (_, foreign) = account();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    {
        let _foreign = foreign.enter();
        assert!(matches!(
            fence.delete_candidates_with_boundary(&[id], &mut || Ok(())),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    let mut visited = 0;
    let failure = fence
        .visit_inventory_with_boundary(
            &mut |_| {
                visited += 1;
                Err(StoreError::Unauthorized)
            },
            &mut || Ok(()),
        )
        .unwrap_err();
    assert!(matches!(
        failure.original_failure(),
        StoreError::Unauthorized
    ));
    assert_eq!(visited, 1);
    assert_closed(&mut fence, id);
    drop(fence);
    assert!(backend.contains(id).unwrap());
}

#[test]
fn refusal_after_actual_deletion_retains_confirmed_prefix_and_credit() {
    let (backend, id) = populated();
    let (quota, original) = account();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let mut checks = 0;
    let failure = fence
        .delete_candidates_with_boundary(&[id], &mut || {
            checks += 1;
            if checks == 3 {
                Err(StoreError::Unauthorized)
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    let StoreError::AdministrativeScope { source } = &failure else {
        panic!("owning deletion failure");
    };
    assert_eq!(source.deleted_objects(), 1);
    assert!(!source.mutation_uncertain());
    assert_closed(&mut fence, id);
    assert!(matches!(source.work_failure(), StoreError::Unauthorized));
    drop(fence);
    assert!(!backend.contains(id).unwrap());
    assert!(quota.resources.usage().unwrap().1 > baseline.1);
    drop(failure);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
}

#[test]
fn initial_denied_boundary_seals_fence_before_any_deletion() {
    let (backend, id) = populated();
    let (_, original) = account();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let error = fence
        .delete_candidates_with_boundary(&[id], &mut || Err(StoreError::Unauthorized))
        .unwrap_err();
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert_closed(&mut fence, id);
    drop(fence);
    assert!(backend.contains(id).unwrap());
}

#[test]
fn visitor_panic_seals_the_same_fence_before_caught_unwind_replay() {
    let (backend, id) = populated();
    let (quota, original) = account();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = fence.visit_inventory_with_boundary(
            &mut |_| panic!("actual public inventory visitor panic"),
            &mut || Ok(()),
        );
    }));
    assert!(panic.is_err());
    assert_closed(&mut fence, id);
    drop(fence);
    assert!(backend.contains(id).unwrap());
    assert_eq!(quota.resources.usage().unwrap(), baseline);
}
