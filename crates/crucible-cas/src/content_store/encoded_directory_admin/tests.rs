//! Actual encoded placements retain the same finite original through checked GC.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::ResourceLoan;
use std::sync::Arc;

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

fn encrypted(root: &std::path::Path, compressed: bool, key: u8) -> EncryptedDirectoryBlobBackend {
    let key_id = StoreEncryptionKeyId::new("checked-admin-key").unwrap();
    let key = StoreEncryptionKey::new([key; 32]).unwrap();
    if compressed {
        EncryptedDirectoryBlobBackend::new_compressed("encoded", root, 1024 * 1024, key_id, key)
            .unwrap()
    } else {
        EncryptedDirectoryBlobBackend::new("encoded", root, 1024 * 1024, key_id, key).unwrap()
    }
}

fn inventory_and_delete<T: EncodedDirectory + ImmutableBlobBackend + BlobStoreAdmin>(backend: T) {
    let bytes = vec![17; 65536];
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .unwrap();
    let path = backend.directory().object_path(id);
    assert_ne!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
    let quota = quota();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let mut observed = None;
    let summary = fence
        .visit_inventory_with_boundary(
            &mut |record| {
                assert!(observed.replace(record).is_none());
                Ok(())
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(summary.objects(), 1);
    assert_eq!(summary.logical_bytes(), bytes.len() as u64);
    assert_eq!(observed.unwrap().logical_length(), bytes.len() as u64);
    let (ordinary_namespace, ordinary_generation) = {
        assert_eq!(summary.backend(), backend.name());
        (summary.storage_identity(), summary.generation())
    };
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
    assert!(quota.resources.usage().unwrap().1 > baseline.1);
    assert_eq!(summary.storage_identity(), ordinary_namespace);
    assert_eq!(summary.generation(), ordinary_generation);
    drop(summary);
    drop(deleted);
    assert_eq!(quota.resources.usage().unwrap(), baseline);
    let mut ordinary = backend.acquire_inventory_fence().unwrap();
    let empty = ordinary.visit_inventory(&mut |_| Ok(())).unwrap();
    assert_eq!(empty.objects(), 0);
    assert_eq!(empty.storage_identity(), ordinary_namespace);
    assert_ne!(empty.generation(), ordinary_generation);
}

#[test]
fn checked_encoded_inventory_and_deletion_preserve_logical_lengths_and_custody() {
    let compressed = tempfile::tempdir().unwrap();
    inventory_and_delete(
        CompressedDirectoryBlobBackend::new("encoded", compressed.path(), 1024 * 1024).unwrap(),
    );
    for encoding in [false, true] {
        let root = tempfile::tempdir().unwrap();
        inventory_and_delete(encrypted(root.path(), encoding, 42));
    }
}

#[test]
fn checked_encrypted_empty_namespace_key_binding_is_initialized_under_child_fence() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), true, 42);
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    assert!(
        root.path()
            .join(".inventory-admin/encryption-key-v1")
            .is_file()
    );
    drop(fence);
    let wrong_key = encrypted(root.path(), true, 43);
    let error = match wrong_key.acquire_inventory_fence_with_boundary(&mut || Ok(())) {
        Ok(_) => panic!("foreign key accepted"),
        Err(error) => error,
    };
    let StoreError::DirectoryScope { source } = error else {
        panic!("retained directory cause")
    };
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unauthorized)
    ));
}

#[test]
fn checked_encoded_admission_and_boundary_refuse_before_namespace_effects() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), false, 42);
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _held = original.reserve_descriptors(5).unwrap();
    let _entered = original.enter();
    assert!(
        backend
            .acquire_inventory_fence_with_boundary(&mut || Ok(()))
            .is_err()
    );
    assert!(!root.path().join(".inventory-admin").exists());
    drop(_held);
    assert!(
        backend
            .acquire_inventory_fence_with_boundary(&mut || Err(StoreError::Unsupported {
                capability: "authored-boundary-stop"
            }))
            .is_err()
    );
    assert!(!root.path().join(".inventory-admin").exists());
}

#[test]
fn checked_encoded_foreign_account_and_boundary_refusal_leave_actual_object() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), false, 42);
    let bytes = b"not deleted by refused original";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let original = DecodeBudget::for_store(quota()).unwrap();
    let foreign = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    {
        let _foreign = foreign.enter();
        assert!(matches!(
            fence.visit_inventory_with_boundary(&mut |_| panic!("foreign visitor"), &mut || Ok(())),
            Err(StoreError::InvalidComposition { .. })
        ));
    }
    assert!(
        fence
            .delete_candidates_with_boundary(&[id], &mut || Err(StoreError::Unsupported {
                capability: "authored-boundary-stop"
            }))
            .is_err()
    );
    assert!(backend.directory().object_path(id).exists());
}

#[test]
fn checked_encoded_visitor_first_cause_is_retained_and_failed_fence_cannot_replay() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), true, 42);
    for bytes in [b"first".as_slice(), b"second".as_slice()] {
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
    }
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let mut visited = 0;
    let error = fence
        .visit_inventory_with_boundary(
            &mut |_| {
                visited += 1;
                Err(StoreError::Unsupported {
                    capability: "encoded-first-visitor",
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
            capability: "encoded-first-visitor"
        })
    ));
    assert!(
        fence
            .visit_inventory_with_boundary(&mut |_| panic!("failed replay"), &mut || Ok(()))
            .is_err()
    );
}

#[test]
fn checked_encoded_corrupt_header_never_publishes_logical_completion() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), true, 42);
    let bytes = b"header corruption is visible to checked inventory";
    let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
        .unwrap();
    let path = backend.directory().object_path(id);
    let mut encoded = std::fs::read(&path).unwrap();
    encoded[8] ^= 1;
    std::fs::write(&path, encoded).unwrap();
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let error = fence
        .visit_inventory_with_boundary(&mut |_| panic!("corrupt visitor"), &mut || Ok(()))
        .unwrap_err();
    let StoreError::DirectoryScope { source } = error else {
        panic!("retained directory cause")
    };
    assert!(
        matches!(source.work_failure(), Some(StoreError::Corrupt { id: failed }) if *failed == id)
    );
}

#[test]
fn checked_encoded_extra_descriptor_refusal_poison_is_retained_before_replay() {
    let root = tempfile::tempdir().unwrap();
    let backend = CompressedDirectoryBlobBackend::new("encoded", root.path(), 1024 * 1024).unwrap();
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let held = original.reserve_descriptors(4).unwrap();
    let error = fence
        .visit_inventory_with_boundary(&mut |_| panic!("unfunded visitor"), &mut || Ok(()))
        .unwrap_err();
    assert!(matches!(error, StoreError::DirectoryScope { .. }));
    drop(held);
    assert!(
        fence
            .visit_inventory_with_boundary(&mut |_| panic!("refused replay"), &mut || Ok(()))
            .is_err()
    );
}

#[test]
fn checked_encoded_unwind_closes_both_fences_before_original_credit_returns() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), true, 42);
    let quota = quota();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let baseline = quota.resources.usage().unwrap();
    let _entered = original.enter();
    let fence = backend
        .acquire_inventory_fence_with_boundary(&mut || Ok(()))
        .unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _fence = fence;
        panic!("actual encoded fence unwind");
    }));
    assert!(caught.is_err());
    assert_eq!(quota.resources.usage().unwrap(), baseline);
    let _ordinary = backend.acquire_inventory_fence().unwrap();
}

#[test]
fn checked_encrypted_wrong_key_precedes_inventory_state_creation() {
    let root = tempfile::tempdir().unwrap();
    let valid = encrypted(root.path(), false, 42);
    drop(valid.acquire_inventory_fence().unwrap());
    std::fs::remove_file(root.path().join(".inventory-admin/state-v1")).unwrap();
    let wrong = encrypted(root.path(), false, 43);
    let original = DecodeBudget::for_store(quota()).unwrap();
    let _entered = original.enter();
    assert!(
        wrong
            .acquire_inventory_fence_with_boundary(&mut || Ok(()))
            .is_err()
    );
    assert!(
        root.path()
            .join(".inventory-admin/encryption-key-v1")
            .exists()
    );
    assert!(!root.path().join(".inventory-admin/state-v1").exists());
}

#[test]
fn checked_encoded_callback_tls_switch_cannot_change_child_original() {
    let root = tempfile::tempdir().unwrap();
    let backend = encrypted(root.path(), true, 42);
    let owner = quota();
    let foreign_owner = quota();
    let original = DecodeBudget::for_store(owner.clone()).unwrap();
    let foreign = DecodeBudget::for_store(foreign_owner.clone()).unwrap();
    let baseline = owner.resources.usage().unwrap();
    let foreign_baseline = foreign_owner.resources.usage().unwrap();
    let _entered = original.enter();
    let mut switched = None;
    let mut fence = backend
        .acquire_inventory_fence_with_boundary(&mut || {
            if switched.is_none() {
                switched = Some(foreign.enter());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(foreign_owner.resources.usage().unwrap(), foreign_baseline);
    assert_eq!(owner.resources.usage().unwrap().0, 4);
    drop(switched);
    let summary = fence
        .visit_inventory_with_boundary(&mut |_| panic!("empty namespace"), &mut || Ok(()))
        .unwrap();
    assert_eq!(summary.objects(), 0);
    drop(summary);
    drop(fence);
    assert_eq!(owner.resources.usage().unwrap(), baseline);
}

#[test]
fn checked_encoded_caught_callback_panic_seals_fence_before_replay_or_delete() {
    for panic_in_visitor in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let backend = encrypted(root.path(), true, 42);
        let bytes = b"retained after a caught inventory callback panic";
        let id = ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
        let object_path = backend.directory().object_path(id);
        let owner = quota();
        let original = DecodeBudget::for_store(owner.clone()).unwrap();
        let baseline = owner.resources.usage().unwrap();
        let _entered = original.enter();
        let mut fence = backend
            .acquire_inventory_fence_with_boundary(&mut || Ok(()))
            .unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fence.visit_inventory_with_boundary(
                &mut |_| {
                    if panic_in_visitor {
                        panic!("actual encoded visitor panic");
                    }
                    Ok(())
                },
                &mut || {
                    if !panic_in_visitor {
                        panic!("actual pre-child boundary panic");
                    }
                    Ok(())
                },
            )
        }));
        assert!(caught.is_err());
        assert!(matches!(
            fence.visit_inventory_with_boundary(
                &mut |_| panic!("replayed visitor"),
                &mut || panic!("replayed boundary")
            ),
            Err(StoreError::Unsupported {
                capability: "failed-encoded-inventory-fence"
            })
        ));
        assert!(
            fence
                .delete_candidates_with_boundary(&[id], &mut || panic!("replayed delete boundary"))
                .is_err()
        );
        assert!(object_path.exists());
        drop(fence);
        assert_eq!(owner.resources.usage().unwrap(), baseline);
    }
}
