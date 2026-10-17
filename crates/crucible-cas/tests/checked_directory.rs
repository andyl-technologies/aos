//! Exercises supervised pinned reads and durable conditional file publication.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crucible_cas::content_store::{
    BlobHandle, BlobSource, ByteRange, ContentId, DirectoryBlobBackend, ImmutableBlobBackend,
    ObjectKind, StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};

struct Quota {
    live: AtomicBool,
    used: Arc<AtomicU64>,
}

struct Loan {
    bytes: u64,
    used: Arc<AtomicU64>,
}

impl Drop for Loan {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(8 * 1024 * 1024)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::Unavailable)
        }
    }

    fn reserve_resources(&self, _descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let before = self.used.fetch_add(bytes, Ordering::SeqCst);
        if before + bytes > 8 * 1024 * 1024 {
            self.used.fetch_sub(bytes, Ordering::SeqCst);
            return Err(StoreError::Quota);
        }
        Ok(ResourceLoan::new(Loan {
            bytes,
            used: self.used.clone(),
        }))
    }
}

// crucible-lint: allow panic-shortcut -- fixture setup requires the finite original account before exercising refusals.
#[allow(clippy::expect_used)]
fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota {
        live: AtomicBool::new(true),
        used: Arc::new(AtomicU64::new(0)),
    });
    let account = DecodeBudget::for_store(quota.clone()).expect("original account");
    (quota, account)
}

fn id(bytes: &[u8]) -> ContentId {
    ContentId::for_bytes(ObjectKind::RamExtent, 1, bytes)
}

// crucible-lint: allow panic-shortcut -- the fixture uses only identities emitted by its validated encoder.
#[allow(clippy::expect_used)]
fn object_path(root: &std::path::Path, id: ContentId) -> std::path::PathBuf {
    let encoded = id.encode();
    let digest = encoded.rsplit('.').next().expect("digest");
    root.join("objects").join(&digest[..2]).join(encoded)
}

#[test]
fn publishes_and_reopens_under_saved_original_accounts() {
    let root = tempfile::tempdir().expect("directory");
    let (source_quota, source_account) = account();
    let (caller_quota, caller_account) = account();
    let backend = DirectoryBlobBackend::new_with_physical_quota(
        "directory",
        root.path(),
        source_quota.clone(),
    )
    .expect("managed constructor");
    let bytes = vec![17; 150_000];
    let id = id(&bytes);
    let source = BlobHandle::from_bytes(bytes.clone());
    let receipts = backend
        .put_many_if_absent_with_boundary(&source_account, &[(id, source)], &mut || Ok(()))
        .expect("checked publication")
        .accept_with_boundary(&mut || Ok(()))
        .expect("accept");
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].placements[0].durable);
    drop(receipts);
    let handle = backend
        .read_with_boundary(&source_account, id, None, &mut || Ok(()))
        .expect("lookup");
    let owned = handle
        .read_all_with_boundary(&caller_account, bytes.len() as u64, &mut || Ok(()))
        .expect("checked EOF");
    assert_eq!(&*owned, bytes);
    source_quota.live.store(false, Ordering::SeqCst);
    assert!(
        handle
            .read_all_with_boundary(&caller_account, bytes.len() as u64, &mut || Ok(()))
            .is_err()
    );
    source_quota.live.store(true, Ordering::SeqCst);
    caller_quota.live.store(false, Ordering::SeqCst);
    assert!(
        handle
            .read_all_with_boundary(&caller_account, bytes.len() as u64, &mut || Ok(()))
            .is_err()
    );
}

#[test]
fn completed_source_authorization_keeps_original_file_credit_under_current_caller() {
    let root = tempfile::tempdir().expect("directory");
    let (namespace, namespace_account) = account();
    let (source_authority, source_account) = account();
    let (_, caller) = account();
    let backend =
        DirectoryBlobBackend::new_with_physical_quota("directory", root.path(), namespace.clone())
            .expect("managed constructor");
    let bytes = vec![19; 150_000];
    let object = id(&bytes);
    backend
        .put_many_if_absent_with_boundary(
            &source_account,
            &[(object, BlobHandle::from_bytes(bytes.clone()))],
            &mut || Ok(()),
        )
        .expect("publish")
        .accept_with_boundary(&mut || Ok(()))
        .expect("accept");
    let source = backend
        .read_with_boundary(&source_account, object, None, &mut || Ok(()))
        .expect("lookup under original source authority");
    source_authority.live.store(false, Ordering::SeqCst);
    drop(source_account);

    let mut reader = BlobSource::open_with_boundary(&source, &caller, &mut || Ok(()))
        .expect("current caller opens the retained file");
    drop(source);
    drop(backend);
    drop(namespace_account);
    assert!(source_authority.used.load(Ordering::SeqCst) > 0);

    let mut output = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = reader
            .read_with_boundary(&mut chunk, &mut || Ok(()))
            .expect("current supervised read");
        if count == 0 {
            break;
        }
        output.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(output, bytes);
    assert!(source_authority.used.load(Ordering::SeqCst) > 0);
    drop(reader);
    assert_eq!(source_authority.used.load(Ordering::SeqCst), 0);
}

#[test]
fn namespace_closure_still_refuses_a_live_current_caller() {
    let root = tempfile::tempdir().expect("directory");
    let (namespace, _) = account();
    let (_, source_account) = account();
    let (_, caller) = account();
    let backend =
        DirectoryBlobBackend::new_with_physical_quota("directory", root.path(), namespace.clone())
            .expect("managed constructor");
    let object = id(b"namespace bytes");
    backend
        .put_many_if_absent_with_boundary(
            &source_account,
            &[(object, BlobHandle::from_bytes(b"namespace bytes"))],
            &mut || Ok(()),
        )
        .expect("publish")
        .accept_with_boundary(&mut || Ok(()))
        .expect("accept");
    let source = backend
        .read_with_boundary(&source_account, object, None, &mut || Ok(()))
        .expect("lookup");
    let mut reader =
        BlobSource::open_with_boundary(&source, &caller, &mut || Ok(())).expect("owning reader");
    namespace.live.store(false, Ordering::SeqCst);

    assert!(matches!(
        BlobSource::open_with_boundary(&source, &caller, &mut || Ok(())),
        Err(StoreError::Unavailable)
    ));
    assert!(matches!(
        reader.read_with_boundary(&mut [0; 1], &mut || Ok(())),
        Err(StoreError::Unavailable)
    ));
}

#[test]
fn current_caller_refusal_precedes_effects_and_retains_its_typed_custody() {
    let root = tempfile::tempdir().expect("directory");
    let (namespace, _) = account();
    let (_, source_account) = account();
    let (caller_authority, caller) = account();
    let backend =
        DirectoryBlobBackend::new_with_physical_quota("directory", root.path(), namespace.clone())
            .expect("managed constructor");
    let object = id(b"current caller bytes");
    backend
        .put_many_if_absent_with_boundary(
            &source_account,
            &[(object, BlobHandle::from_bytes(b"current caller bytes"))],
            &mut || Ok(()),
        )
        .expect("publish")
        .accept_with_boundary(&mut || Ok(()))
        .expect("accept");
    let source = backend
        .read_with_boundary(&source_account, object, None, &mut || Ok(()))
        .expect("lookup");
    let namespace_usage = namespace.used.load(Ordering::SeqCst);
    caller_authority.live.store(false, Ordering::SeqCst);
    let mut callbacks = 0;
    let error = match BlobSource::open_with_boundary(&source, &caller, &mut || {
        callbacks += 1;
        Ok(())
    }) {
        Ok(_) => panic!("revoked current caller opened a reader"),
        Err(error) => error,
    };

    assert!(matches!(
        &error,
        StoreError::DecodeAdmission {
            custody: Some(_),
            ..
        }
    ));
    assert_eq!(callbacks, 0);
    assert_eq!(namespace.used.load(Ordering::SeqCst), namespace_usage);
    drop(caller);
    assert!(caller_authority.used.load(Ordering::SeqCst) > 0);
    drop(error);
    assert_eq!(caller_authority.used.load(Ordering::SeqCst), 0);
}

#[test]
fn lookup_pins_file_across_path_replacement() {
    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = b"original pinned bytes";
    let id = id(bytes);
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .expect("publish");
    let handle = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("lookup");
    let path = object_path(root.path(), id);
    let replacement = root.path().join("replacement");
    std::fs::write(&replacement, b"replacement bytes").expect("replacement");
    std::fs::rename(replacement, path).expect("replace pathname");
    assert_eq!(
        &*handle
            .read_all_with_boundary(&original, 100, &mut || Ok(()))
            .expect("pinned read"),
        bytes
    );
    assert!(
        backend
            .read_with_boundary(&original, id, None, &mut || Ok(()))
            .expect("new lookup")
            .read_all_with_boundary(&original, 100, &mut || Ok(()))
            .is_err()
    );
}

#[test]
fn range_authenticates_hidden_suffix_and_failed_reader_cannot_resume() {
    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = vec![5; 180_000];
    let id = id(&bytes);
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes.clone()))],
            &mut || Ok(()),
        )
        .expect("publish");
    let handle = backend
        .read_with_boundary(
            &original,
            id,
            Some(ByteRange::new(70_000, 10).expect("range")),
            &mut || Ok(()),
        )
        .expect("lookup");
    let mut reader =
        BlobSource::open_with_boundary(&handle, &original, &mut || Ok(())).expect("reader");
    assert_eq!(
        reader
            .read_with_boundary(&mut [0; 10], &mut || Ok(()))
            .expect("range bytes"),
        10
    );
    let mut corrupt = bytes;
    corrupt[179_999] ^= 1;
    std::fs::write(object_path(root.path(), id), corrupt).expect("corrupt suffix");
    assert!(matches!(
        reader.read_with_boundary(&mut [0; 1], &mut || Ok(())),
        Err(StoreError::Corrupt { .. })
    ));
    assert!(matches!(
        reader.read_with_boundary(&mut [0; 1], &mut || Ok(())),
        Err(StoreError::Unsupported { .. })
    ));
}

#[test]
fn refusal_after_link_retains_visible_uncertain_outcome_and_cleans_staging() {
    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = b"late boundary";
    let id = id(bytes);
    let path = object_path(root.path(), id);
    let error = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || {
                if path.exists() {
                    Err(StoreError::Unauthorized)
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("refuse immediately after link");
    let StoreError::DirectoryScope { source } = error else {
        panic!("retained Directory scope");
    };
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unauthorized)
    ));
    assert_eq!(source.outcome().published_objects, 1);
    assert_eq!(source.outcome().durable_objects, 0);
    assert!(source.outcome().durability_uncertain);
    assert_eq!(std::fs::read(&path).expect("visible object"), bytes);
    assert_eq!(
        std::fs::read_dir(path.parent().expect("shard"))
            .expect("entries")
            .count(),
        1
    );
}

#[test]
fn accepted_receipt_keeps_actual_durability_on_outer_refusal() {
    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = b"durable before outer refusal";
    let id = id(bytes);
    let receipts = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .expect("publish");
    let error = receipts
        .accept_with_boundary(&mut || Err(StoreError::Unauthorized))
        .expect_err("outer refusal");
    let StoreError::DirectoryScope { source } = error else {
        panic!("retained Directory scope");
    };
    assert_eq!(source.outcome().published_objects, 1);
    assert_eq!(source.outcome().durable_objects, 1);
    assert!(!source.outcome().durability_uncertain);
    assert!(matches!(
        source.work_failure(),
        Some(StoreError::Unauthorized)
    ));
}

#[test]
fn staging_cleanup_preserves_both_original_work_and_cleanup_failures() {
    for fail_work in [false, true] {
        let root = tempfile::tempdir().expect("directory");
        let (_, original) = account();
        let backend = DirectoryBlobBackend::new("directory", root.path());
        let bytes = b"cleanup evidence";
        let id = id(bytes);
        let path = object_path(root.path(), id);
        let shard = path.parent().expect("shard");
        let mut replaced = false;
        let error = backend
            .put_many_if_absent_with_boundary(
                &original,
                &[(id, BlobHandle::from_bytes(bytes))],
                &mut || {
                    if !replaced && (fail_work || path.exists()) && shard.is_dir() {
                        for entry in std::fs::read_dir(shard).expect("entries") {
                            let entry = entry.expect("entry");
                            if entry.file_name().to_string_lossy().starts_with(".staging-") {
                                std::fs::remove_file(entry.path()).expect("remove stage pathname");
                                std::fs::create_dir(entry.path()).expect("replace with directory");
                                replaced = true;
                                break;
                            }
                        }
                    }
                    if replaced && fail_work {
                        Err(StoreError::Unauthorized)
                    } else {
                        Ok(())
                    }
                },
            )
            .expect_err("independent cleanup failure");
        let StoreError::DirectoryScope { source } = error else {
            panic!("Directory scope");
        };
        assert!(matches!(
            source.cleanup_failure(),
            Some(StoreError::Io {
                operation: "remove-object-staging",
                ..
            })
        ));
        if fail_work {
            assert!(matches!(
                source.work_failure(),
                Some(StoreError::Unauthorized)
            ));
            assert_eq!(source.outcome().published_objects, 0);
        } else {
            assert!(source.work_failure().is_none());
            assert_eq!(source.outcome().published_objects, 1);
            assert_eq!(source.outcome().durable_objects, 1);
        }
    }
}

#[test]
fn contended_inventory_lock_polls_the_original_boundary() {
    use rustix::fs::{FlockOperation, flock};

    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let first = b"first";
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id(first), BlobHandle::from_bytes(first))],
            &mut || Ok(()),
        )
        .expect("initialize");
    let lock = std::fs::File::open(root.path().join(".inventory-admin/lock")).expect("lock file");
    flock(&lock, FlockOperation::NonBlockingLockExclusive).expect("hold competing lock");
    let mut checks = 0;
    let error = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id(b"second"), BlobHandle::from_bytes(b"second"))],
            &mut || {
                checks += 1;
                if checks >= 128 {
                    Err(StoreError::Unauthorized)
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("cancel while lock remains held");
    assert_eq!(checks, 128);
    assert!(matches!(error.original_failure(), StoreError::Unauthorized));
    assert!(!object_path(root.path(), id(b"second")).exists());
}

#[test]
fn wrong_source_and_existing_corruption_never_receive_durable_receipts() {
    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = b"expected bytes";
    let id = id(bytes);
    let error = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(b"different bytes"))],
            &mut || Ok(()),
        )
        .expect_err("wrong incoming canonical bytes");
    assert!(matches!(
        error.original_failure(),
        StoreError::Corrupt { .. }
    ));
    assert!(!object_path(root.path(), id).exists());
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .expect("publish valid bytes");
    std::fs::write(object_path(root.path(), id), b"bad").expect("corrupt physical copy");
    let error = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .expect_err("existing content must authenticate");
    assert!(matches!(
        error.original_failure(),
        StoreError::Corrupt { .. }
    ));
}

#[test]
fn typed_io_failure_retains_original_credit_until_error_close() {
    let root = tempfile::tempdir().expect("directory");
    let (quota, original) = account();
    let before = quota.used.load(Ordering::SeqCst);
    std::fs::write(root.path().join(".inventory-admin"), b"not a directory")
        .expect("invalid parent");
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let error = backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id(b"bytes"), BlobHandle::from_bytes(b"bytes"))],
            &mut || Ok(()),
        )
        .expect_err("filesystem failure");
    assert!(quota.used.load(Ordering::SeqCst) > before);
    assert!(matches!(
        error.original_failure(),
        StoreError::Io {
            operation: "create-directory",
            ..
        }
    ));
    drop(error);
    assert_eq!(quota.used.load(Ordering::SeqCst), before);
}

#[test]
fn authenticated_range_cannot_publish_its_parent_identity() {
    let source_root = tempfile::tempdir().expect("source directory");
    let destination_root = tempfile::tempdir().expect("destination directory");
    let (_, original) = account();
    let source = DirectoryBlobBackend::new("source", source_root.path());
    let destination = DirectoryBlobBackend::new("destination", destination_root.path());
    let bytes = b"whole authenticated object";
    let id = id(bytes);
    source
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .expect("source publication");
    let range = source
        .read_with_boundary(
            &original,
            id,
            Some(ByteRange::new(2, 5).expect("range")),
            &mut || Ok(()),
        )
        .expect("authenticated underlying range");
    let error = destination
        .put_many_if_absent_with_boundary(&original, &[(id, range)], &mut || Ok(()))
        .expect_err("range is not its parent canonical object");
    assert!(matches!(
        error.original_failure(),
        StoreError::Corrupt { .. }
    ));
    assert!(!object_path(destination_root.path(), id).exists());
}

#[test]
fn empty_reads_do_not_accept_eof_and_appended_bytes_refuse_completion() {
    use std::io::Write;

    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = b"original bytes";
    let id = id(bytes);
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || Ok(()),
        )
        .expect("publish");
    let handle = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("lookup");
    let mut reader =
        BlobSource::open_with_boundary(&handle, &original, &mut || Ok(())).expect("reader");
    std::fs::OpenOptions::new()
        .append(true)
        .open(object_path(root.path(), id))
        .expect("append handle")
        .write_all(b"x")
        .expect("append corruption");
    assert_eq!(
        reader
            .read_with_boundary(&mut [], &mut || Ok(()))
            .expect("empty read"),
        0
    );
    assert_eq!(
        reader
            .read_with_boundary(&mut [0; 64], &mut || Ok(()))
            .expect("declared bytes"),
        bytes.len()
    );
    assert!(matches!(
        reader.read_with_boundary(&mut [0; 1], &mut || Ok(())),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn callback_scope_replacement_never_switches_original_admission() {
    let root = tempfile::tempdir().expect("directory");
    let (_, original) = account();
    let (unrelated_quota, unrelated) = account();
    unrelated_quota.live.store(false, Ordering::SeqCst);
    let backend = DirectoryBlobBackend::new("directory", root.path());
    let bytes = b"saved original authority";
    let id = id(bytes);
    let mut scope = None;
    backend
        .put_many_if_absent_with_boundary(
            &original,
            &[(id, BlobHandle::from_bytes(bytes))],
            &mut || {
                if scope.is_none() {
                    scope = Some(unrelated.enter());
                }
                Ok(())
            },
        )
        .expect("publication stays in original account");
    let handle = backend
        .read_with_boundary(&original, id, None, &mut || Ok(()))
        .expect("lookup");
    assert_eq!(
        &*handle
            .read_all_with_boundary(&original, 100, &mut || Ok(()))
            .expect("saved source and caller"),
        bytes
    );
    drop(scope);
}
