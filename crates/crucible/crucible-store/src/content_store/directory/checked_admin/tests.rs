//! Genuine directory operations with the same finite original fixture account.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::ResourceLoan;

struct Quota {
    resources: FixtureResourceBudget,
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.resources.reserve(descriptors, bytes)
    }
}

fn quota() -> Arc<Quota> {
    Arc::new(Quota {
        resources: FixtureResourceBudget::new(8, 4 * 1024 * 1024),
    })
}

#[test]
fn checked_directory_inventory_and_ordered_duplicate_delete_are_durable() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    let bytes = b"genuine checked directory object";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let path = backend.object_path(id);
    let quota = quota();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    assert_eq!(quota.resources.usage().unwrap().0, 4);
    let mut records = Vec::new();
    let summary = fence
        .visit_inventory_with_boundary(
            &mut |record| {
                records.push(record);
                Ok(())
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(summary.objects(), 1);
    assert_eq!(summary.logical_bytes(), bytes.len() as u64);
    assert_eq!(records[0].id(), id);
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
    assert!(!path.exists());
    drop(fence);
    assert_eq!(quota.resources.usage().unwrap().0, 0);
    assert_eq!(summary.objects(), 1);
    drop(summary);
    drop(deleted);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
    let mut ordinary = backend.acquire_inventory_fence().unwrap();
    assert_eq!(
        ordinary.visit_inventory(&mut |_| Ok(())).unwrap().objects(),
        0
    );
}

#[test]
fn checked_directory_refuses_foreign_original_and_stops_after_first_visitor_failure() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    for bytes in [b"first".as_slice(), b"second".as_slice()] {
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
    }
    let original = DecodeBudget::for_store(quota()).unwrap();
    let foreign = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    {
        let _foreign = foreign.enter();
        assert!(matches!(
            fence.visit_inventory_with_boundary(&mut |_| Ok(()), &mut || Ok(())),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    let mut visited = 0;
    let error = fence
        .visit_inventory_with_boundary(
            &mut |_| {
                visited += 1;
                Err(StoreError::Unsupported {
                    capability: "actual-first-visitor-refusal",
                })
            },
            &mut || Ok(()),
        )
        .unwrap_err();
    assert_eq!(visited, 1);
    let StoreError::DirectoryScope { source } = error else {
        panic!("retained directory cause")
    };
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unsupported {
            capability: "actual-first-visitor-refusal"
        })
    ));
    assert!(
        fence
            .visit_inventory_with_boundary(&mut |_| { panic!("failed fence replay") }, &mut || Ok(
                ()
            ))
            .is_err()
    );
}

#[test]
fn checked_directory_refuses_descriptor_exhaustion_before_admin_creation() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _held = original.reserve_descriptors(5).unwrap();
    let _entered = original.enter();
    assert!(
        backend
            .acquire_inventory_fence_with_boundary(&mut || Ok(()))
            .is_err()
    );
    assert!(!root.path().join(INVENTORY_ADMIN_DIRECTORY).exists());
}

#[test]
fn checked_directory_poisoned_boundary_precedes_delete_and_unwind_closes_fence() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    let bytes = b"retained until checked removal";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let path = backend.object_path(id);
    let quota = quota();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let error = fence
        .delete_candidates_with_boundary(&[id], &mut || Err(StoreError::Corrupt { id }))
        .unwrap_err();
    assert!(path.exists());
    drop(error);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _fence = fence;
        panic!("actual fence unwind");
    }));
    assert!(caught.is_err());
    assert_eq!(quota.resources.usage().unwrap(), baseline);
}

#[test]
fn checked_directory_retains_unlink_before_late_refusal_without_claiming_durability() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    let bytes = b"actual unlink before refused sync";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let path = backend.object_path(id);
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let error = fence
        .delete_candidates_with_boundary(&[id], &mut || {
            if path.exists() {
                Ok(())
            } else {
                Err(StoreError::Corrupt { id })
            }
        })
        .unwrap_err();
    let StoreError::DirectoryScope { source } = error else {
        panic!("maintenance cause")
    };
    assert!(
        matches!(source.work_failure(), Some(StoreError::Corrupt { id: found }) if *found == id)
    );
    assert_eq!(
        source.maintenance_outcome(),
        Some(DirectoryMaintenanceOutcome {
            removed_objects: 1,
            durable_candidates: 0,
            durability_uncertain: true,
        })
    );
    assert!(!path.exists());
    assert!(
        fence
            .delete_candidates_with_boundary(&[id], &mut || Ok(()))
            .is_err()
    );
}

#[test]
fn checked_directory_lock_contention_polls_and_returns_original_credits() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    let ordinary = backend.acquire_inventory_fence().unwrap();
    let quota = quota();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut polls = 0;
    let result = backend.acquire_inventory_fence_with_boundary(&mut || {
        polls += 1;
        if polls >= 100 {
            Err(StoreError::Unsupported {
                capability: "actual-lock-wait-refusal",
            })
        } else {
            Ok(())
        }
    });
    let error = match result {
        Ok(_) => panic!("acquired held exclusive lock"),
        Err(error) => error,
    };
    let StoreError::DirectoryScope { source } = error else {
        panic!("lock cause")
    };
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unsupported {
            capability: "actual-lock-wait-refusal"
        })
    ));
    assert_eq!(polls, 101);
    assert!(matches!(
        source.post_boundary_failure(),
        Some(StoreError::Unsupported {
            capability: "actual-lock-wait-refusal"
        })
    ));
    drop(source);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
    drop(ordinary);
}

#[test]
fn checked_directory_validates_entire_inventory_before_returning_fence() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    fs::create_dir(root.path().join("unexpected")).unwrap();
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let result = backend.acquire_inventory_fence_with_boundary(&mut || Ok(()));
    let error = match result {
        Ok(_) => panic!("accepted malformed namespace"),
        Err(error) => error,
    };
    let StoreError::DirectoryScope { source } = error else {
        panic!("inventory cause")
    };
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::InvalidComposition {
            reason: "inventory contains an unknown root directory"
        })
    ));
}

#[test]
fn checked_directory_preserves_first_visitor_error_and_distinct_post_boundary_refusal() {
    let root = tempfile::tempdir().unwrap();
    let backend = DirectoryBlobBackend::new("checked-admin", root.path());
    let bytes = b"observed before later refusal";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let observed = std::cell::Cell::new(false);
    let error = fence
        .visit_inventory_with_boundary(
            &mut |_| {
                observed.set(true);
                Err(StoreError::Corrupt { id })
            },
            &mut || {
                if observed.get() {
                    Err(StoreError::Unsupported {
                        capability: "distinct-later-original-cut",
                    })
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    let StoreError::DirectoryScope { source } = error else {
        panic!("retained complete cause")
    };
    assert!(
        matches!(source.work_failure(), Some(StoreError::Corrupt { id: found }) if *found == id)
    );
    assert!(matches!(
        source.post_boundary_failure(),
        Some(StoreError::Unsupported {
            capability: "distinct-later-original-cut"
        })
    ));
}

#[test]
fn checked_directory_caught_callback_panics_seal_inventory_and_deletion() {
    for stage in ["visitor", "inventory-boundary", "delete-boundary"] {
        let root = tempfile::tempdir().unwrap();
        let backend = DirectoryBlobBackend::new("checked-admin", root.path());
        let bytes = b"retained after a caught directory callback panic";
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
        let object_path = backend.object_path(id);
        let owner = quota();
        let original = DecodeBudget::for_store(owner.clone()).unwrap();
        let baseline = owner.resources.usage().unwrap();
        let _entered = original.enter();
        let mut fence = backend
            .acquire_inventory_fence_with_boundary(&mut || Ok(()))
            .unwrap();

        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if stage == "delete-boundary" {
                let _ = fence.delete_candidates_with_boundary(&[id], &mut || {
                    panic!("actual delete boundary panic")
                });
            } else {
                let _ = fence.visit_inventory_with_boundary(
                    &mut |_| {
                        if stage == "visitor" {
                            panic!("actual directory visitor panic");
                        }
                        Ok(())
                    },
                    &mut || {
                        if stage == "inventory-boundary" {
                            panic!("actual inventory boundary panic");
                        }
                        Ok(())
                    },
                );
            }
        }));
        assert!(caught.is_err());
        assert!(matches!(
            fence.visit_inventory_with_boundary(
                &mut |_| panic!("replayed directory visitor"),
                &mut || panic!("replayed directory boundary")
            ),
            Err(StoreError::Unsupported {
                capability: "failed-directory-inventory-fence"
            })
        ));
        assert!(matches!(
            fence
                .delete_candidates_with_boundary(&[id], &mut || panic!("replayed delete boundary")),
            Err(StoreError::Unsupported {
                capability: "failed-directory-inventory-fence"
            })
        ));
        assert!(object_path.exists());
        drop(fence);
        assert_eq!(owner.resources.usage().unwrap(), baseline);
    }
}
