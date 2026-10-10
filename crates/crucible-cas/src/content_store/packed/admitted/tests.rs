//! Checked startup, unchanged pack grammar, and same-original refusal controls.
//!
//! The finite model owns constructor loans and actual descriptors. Its test
//! allocator/authority controls and temporary filesystem are not native quota
//! installation or full enclosing-control funding evidence.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tempfile::TempDir;

struct Quota {
    resources: FixtureResourceBudget,
    open: AtomicBool,
    descriptor_grants: AtomicUsize,
    deny_retained_bytes: AtomicU64,
}

impl Quota {
    fn new(descriptors: u64, bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(descriptors, bytes),
            open: AtomicBool::new(true),
            descriptor_grants: AtomicUsize::new(0),
            deny_retained_bytes: AtomicU64::new(0),
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.open.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unauthorized)
        }
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        if descriptors == 0
            && bytes != 0
            && bytes == self.deny_retained_bytes.load(Ordering::SeqCst)
        {
            return Err(StoreError::Quota);
        }
        let loan = self.resources.reserve(descriptors, bytes)?;
        if descriptors != 0 {
            self.descriptor_grants.fetch_add(1, Ordering::SeqCst);
        }
        Ok(loan)
    }
}

#[test]
fn fresh_checked_startup_writes_exact_existing_empty_index_and_retains_only_constructor_credit() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("fresh/packed");
    let quota = Quota::new(8, 4 * 1024 * 1024);
    let admitted = open("managed", &root, MIN_TARGET_PACK_BYTES, quota.clone(), 24).unwrap();
    let index = admitted.backend.load_index().unwrap();
    assert_eq!(index.header.count, 0);
    assert_eq!(index.header.generation, 0);
    assert!(index.header.last_repack_plan.is_none());
    assert_eq!(
        fs::read(admitted.backend.index_path()).unwrap(),
        index.encoded_bytes()
    );
    let (_, bytes) = quota.resources.usage().unwrap();
    let retained = std::mem::size_of::<BackendAllocation>() as u64
        + 24
        + admitted.backend.name.capacity() as u64
        + admitted.backend.root.capacity() as u64
        + admitted.backend.packs.capacity() as u64
        + admitted.backend.admin.capacity() as u64;
    assert_eq!(quota.resources.usage().unwrap(), (0, retained));
    assert!(bytes > 0);
    drop(admitted);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn closed_original_and_retained_purpose_refusal_precede_first_directory_effect() {
    let temp = TempDir::new().unwrap();
    for closed in [false, true] {
        let root = temp
            .path()
            .join(if closed { "closed" } else { "no-credit" });
        let quota = Quota::new(8, 4 * 1024 * 1024);
        let retained = std::mem::size_of::<BackendAllocation>() as u64
            + 24
            + "managed".len() as u64
            + 3 * root.as_os_str().len() as u64
            + 2
            + PACK_DIRECTORY.len() as u64
            + ADMIN_DIRECTORY.len() as u64;
        quota.deny_retained_bytes.store(retained, Ordering::SeqCst);
        quota.open.store(!closed, Ordering::SeqCst);
        let result = open("managed", &root, MIN_TARGET_PACK_BYTES, quota.clone(), 24);
        if closed {
            assert!(matches!(result, Err(StoreError::Unauthorized)));
        } else {
            assert!(matches!(result, Err(StoreError::Quota)));
        }
        assert!(!root.exists());
        assert_eq!(quota.descriptor_grants.load(Ordering::SeqCst), 0);
        assert_eq!(quota.resources.usage().unwrap(), (0, 0));
    }
}

#[test]
fn invalid_target_retains_old_priority_before_original_authentication() {
    let temp = TempDir::new().unwrap();
    let quota = Quota::new(0, 0);
    quota.open.store(false, Ordering::SeqCst);
    assert!(matches!(
        open("managed", temp.path(), MIN_TARGET_PACK_BYTES - 1, quota, 24),
        Err(StoreError::InvalidComposition { .. })
    ));
}

#[test]
fn descriptor_refusal_keeps_real_retained_fields_until_failed_startup_closes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("packed");
    let quota = Quota::new(0, 4 * 1024 * 1024);
    let result = open("managed", &root, MIN_TARGET_PACK_BYTES, quota.clone(), 24);
    assert!(matches!(result, Err(StoreError::DecodeAdmission { .. })));
    // The returned actual refusal retains its original account control. Free
    // that error before asserting complete recovery, rather than flatten it.
    drop(result);
    assert!(!root.join(ADMIN_DIRECTORY).join(INDEX_FILE).exists());
    assert_eq!(quota.descriptor_grants.load(Ordering::SeqCst), 0);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn long_native_paths_are_prepaid_and_fresh_index_restarts_without_format_changes() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("a".repeat(180)).join("b".repeat(180));
    assert!(root.as_os_str().len() >= 256);
    let quota = Quota::new(8, 4 * 1024 * 1024);
    let first = open("managed", &root, MIN_TARGET_PACK_BYTES, quota.clone(), 24).unwrap();
    let before = fs::read(first.backend.index_path()).unwrap();
    drop(first);
    let second = open("managed", &root, MIN_TARGET_PACK_BYTES, quota.clone(), 24).unwrap();
    assert_eq!(fs::read(second.backend.index_path()).unwrap(), before);
    drop(second);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn restart_authenticates_one_distinct_pack_once_before_all_index_reference_checks() {
    let temp = TempDir::new().unwrap();
    let backend = PackedBlobBackend::open("managed", temp.path(), MIN_TARGET_PACK_BYTES).unwrap();
    let first = b"first";
    let second = b"second";
    let a = ContentId::for_bytes(ObjectKind::Trace, 1, first);
    let b = ContentId::for_bytes(ObjectKind::Trace, 1, second);
    backend
        .put_many_if_absent(&[
            (a, BlobHandle::from_bytes(first.to_vec())),
            (b, BlobHandle::from_bytes(second.to_vec())),
        ])
        .unwrap();
    // Ordinary batch publication writes one pack per source. Repack these two
    // small sources into the existing target's single deterministic group.
    let plan = backend.plan_repack().unwrap();
    backend.apply_repack(&plan).unwrap();
    assert_eq!(backend.load_index().unwrap().header.packs, 1);
    let quota = Quota::new(8, 4 * 1024 * 1024);
    let admitted = open(
        "managed",
        temp.path(),
        MIN_TARGET_PACK_BYTES,
        quota.clone(),
        24,
    )
    .unwrap();
    // Two locks, one index and its existing post-authentication admin sync,
    // then exactly one distinct pack are opened during this restart.
    assert_eq!(quota.descriptor_grants.load(Ordering::SeqCst), 5);
    assert_eq!(admitted.backend.load_index().unwrap().header.count, 2);
    drop(admitted);
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn later_pack_authentication_still_precedes_earlier_index_mismatch() {
    let temp = TempDir::new().unwrap();
    let backend = PackedBlobBackend::open("managed", temp.path(), MIN_TARGET_PACK_BYTES).unwrap();
    for bytes in [b"first".as_slice(), b"second".as_slice()] {
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, bytes);
        backend
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .unwrap();
    }
    let index = backend.load_index().unwrap();
    let mut operation = index_io::Operation {
        original: None,
        boundary: &mut || Ok(()),
    };
    let reader = index.reader(&backend, &mut operation).unwrap();
    let mut cursor = reader.cursor(&mut operation).unwrap();
    let mut update = index_update::Update::new(&index, &backend, &mut operation).unwrap();
    let mut later_pack = None;
    let mut pack_count = 0;
    while let Some((key, value)) = cursor.next(&mut operation).unwrap() {
        if key.0[0] == 0 {
            let mut entry = value.entry().unwrap();
            entry.offset += 1;
            update
                .set(
                    &backend,
                    key,
                    Some(index_format::Value::object(entry)),
                    &mut operation,
                )
                .unwrap();
        } else {
            later_pack = Some(key.pack_id().unwrap());
            pack_count += 1;
        }
    }
    assert_eq!(pack_count, 2);
    drop(cursor);
    drop(reader);
    let later_pack = later_pack.unwrap();
    let replacement = update.finish(&backend, &mut operation).unwrap();
    fs::write(backend.index_path(), replacement.bytes()).unwrap();
    let path = backend.pack_path(later_pack);
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/dev/null", path).unwrap();
    let quota = Quota::new(8, 4 * 1024 * 1024);
    let error = open(
        "managed",
        temp.path(),
        MIN_TARGET_PACK_BYTES,
        quota.clone(),
        24,
    )
    .err()
    .unwrap();
    let StoreError::StreamIo { source, .. } = error else {
        panic!("later symlink failure precedes index mismatch")
    };
    assert_eq!(source.raw_os_error(), Some(40));
    assert_eq!(quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn header_io_classification_does_not_mask_same_named_callback_failure() {
    let temp = tempfile::tempfile().unwrap();
    let quota = Quota::new(8, 4 * 1024 * 1024);
    let original = DecodeBudget::for_store(quota).unwrap();
    let mut output = [0_u8; 1];
    let error = checked_io::read_header_exact_at(&temp, &mut output, 0, &original, &mut || {
        Err(StoreError::StreamIo {
            operation: "read-packed-checked-file",
            source: io::Error::from_raw_os_error(13),
        })
    })
    .unwrap_err();
    assert!(
        matches!(error, StoreError::StreamIo { source, .. } if source.raw_os_error() == Some(13))
    );
    assert!(matches!(
        checked_io::read_header_exact_at(&temp, &mut output, 0, &original, &mut || Ok(())),
        Err(StoreError::Incompatible)
    ));
}
