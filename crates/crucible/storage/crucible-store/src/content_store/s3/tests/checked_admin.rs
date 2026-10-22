//! Checked S3 listing, conditional-delete refusal and original output custody.

use super::*;
use crate::content_store::BlobInventoryFence;
use crate::content_store::admin::outcome::test_original::{account, assert_closed};

fn fixture(
    label: &str,
) -> (
    Arc<FakeS3Client>,
    Arc<FakeBlobAdminClient>,
    S3BlobBackend,
    ContentId,
) {
    let ordinary = Arc::new(FakeS3Client::new(StoreS3EndpointId::new(label).unwrap()));
    let admin = Arc::new(FakeBlobAdminClient::new(ordinary.clone()));
    let backend = administrative_backend(ordinary.clone(), admin.clone());
    let bytes = b"checked S3 placement";
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    (ordinary, admin, backend, id)
}

#[test]
fn checked_listing_and_duplicate_deletion_preserve_owned_summary() {
    let (_, _, backend, id) = fixture("checked-S3-admin/custody");
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
    assert!(!backend.contains(id).unwrap());
    assert_eq!(summary.objects(), 1);
    assert!(quota.resources.usage().unwrap().1 > baseline.1);
    drop(summary);
    drop(deleted);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
}

#[test]
fn foreign_original_bad_listing_and_version_conflict_refuse_without_deletion() {
    let (_, admin, backend, id) = fixture("checked-S3-admin/refusal");
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
    admin.malformed_scan.store(true, Ordering::SeqCst);
    let mut visits = 0;
    let error = fence
        .visit_inventory_with_boundary(
            &mut |_| {
                visits += 1;
                Ok(())
            },
            &mut || Ok(()),
        )
        .unwrap_err();
    assert!(matches!(error.original_failure(), StoreError::Incompatible));
    assert_eq!(visits, 0);
    assert_closed(&mut fence, id);
    drop(fence);
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    admin.malformed_scan.store(false, Ordering::SeqCst);
    admin.force_delete_conflict.store(true, Ordering::SeqCst);
    let error = fence
        .delete_candidates_with_boundary(&[id], &mut || Ok(()))
        .unwrap_err();
    let StoreError::AdministrativeScope { source } = &error else {
        panic!("owned version refusal");
    };
    assert_eq!(source.deleted_objects(), 0);
    assert!(!source.mutation_uncertain());
    assert_closed(&mut fence, id);
    drop(fence);
    assert!(backend.contains(id).unwrap());
}

#[test]
fn post_delete_boundary_refusal_keeps_actual_delete_and_first_cause() {
    let (ordinary, _, backend, id) = fixture("checked-S3-admin/post-delete");
    let (_, original) = account();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let key = backend.key(id);
    let error = fence
        .delete_candidates_with_boundary(&[id], &mut || {
            if ordinary
                .objects
                .lock()
                .unwrap()
                .keys()
                .all(|(_, object)| object != &key)
            {
                Err(StoreError::Unauthorized)
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    let StoreError::AdministrativeScope { source } = &error else {
        panic!("owned actual deletion");
    };
    assert_eq!(source.deleted_objects(), 1);
    assert!(!source.mutation_uncertain());
    assert_closed(&mut fence, id);
    assert!(matches!(source.work_failure(), StoreError::Unauthorized));
    drop(fence);
    assert!(!backend.contains(id).unwrap());
}
