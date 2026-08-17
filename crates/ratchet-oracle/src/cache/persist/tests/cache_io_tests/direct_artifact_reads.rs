//! Direct typed artifact read-lock tests.

use super::*;

#[test]
fn cache_file_artifact_read_uses_scoped_mapped_files_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"mapped file artifact";
    let index_value = append_file_artifact_blob(&cache, payload);

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let result = cache
        .read_file_artifact(index_value)
        .expect("file artifact reads");
    assert_eq!(result.as_slice(), payload);
    assert_eq!(
        cache.file_pack().mapped_read_count_for_tests(),
        1,
        "direct file-artifact reads should clone through the scoped mapped files pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_read_uses_scoped_mapped_files_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"mapped parse artifact";
    let index_value = append_parse_artifact_blob(&cache, payload);

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let result = cache
        .read_parse_artifact(index_value)
        .expect("parse artifact reads");
    assert_eq!(result.as_slice(), payload);
    assert_eq!(
        cache.file_pack().mapped_read_count_for_tests(),
        1,
        "direct parse-artifact reads should clone through the scoped mapped files pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_read_waits_for_store_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let payload = b"locked file artifact";
    let index_value = append_file_artifact_blob(&cache, payload);
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquired");
    let reader = cache.clone();
    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let reader_barrier = Arc::clone(&barrier);
    let handle = thread::spawn(move || {
        reader_barrier.wait();
        let result = reader.read_file_artifact(index_value);
        tx.send(result).expect("read result sends");
    });

    barrier.wait();
    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "file artifact read should wait while the file store lock is held"
    );
    drop(guard);
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file artifact read completes after lock release")
        .expect("file artifact read succeeds");
    handle.join().expect("reader thread joins");
    assert_eq!(result.as_slice(), payload);
    assert_files_advisory_lock_released(&layout.blob_store_lock_path(PersistBlobStore::Files));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_read_waits_for_store_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let payload = b"locked parse artifact";
    let index_value = append_parse_artifact_blob(&cache, payload);
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquired");
    let reader = cache.clone();
    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let reader_barrier = Arc::clone(&barrier);
    let handle = thread::spawn(move || {
        reader_barrier.wait();
        let result = reader.read_parse_artifact(index_value);
        tx.send(result).expect("read result sends");
    });

    barrier.wait();
    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "parse artifact read should wait while the file store lock is held"
    );
    drop(guard);
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("parse artifact read completes after lock release")
        .expect("parse artifact read succeeds");
    handle.join().expect("reader thread joins");
    assert_eq!(result.as_slice(), payload);
    assert_files_advisory_lock_released(&layout.blob_store_lock_path(PersistBlobStore::Files));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_read_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    poison_files_store_lock(&root);

    let error = cache
        .read_file_artifact(synthetic_file_artifact_value(b"file artifact"))
        .expect_err("poisoned same-root file lock should reject file artifact reads");

    assert!(matches!(
        error,
        PersistBlobPackError::ReadLockPoisoned {
            store: PersistBlobStore::Files
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_read_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    poison_files_store_lock(&root);

    let error = cache
        .read_parse_artifact(synthetic_parse_artifact_value(b"parse artifact"))
        .expect_err("poisoned same-root file lock should reject parse artifact reads");

    assert!(matches!(
        error,
        PersistBlobPackError::ReadLockPoisoned {
            store: PersistBlobStore::Files
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_read_maps_advisory_store_lock_error() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();

    fs::remove_dir_all(layout.locks_dir()).expect("locks directory removes");
    fs::write(layout.locks_dir(), b"not a directory").expect("locks path becomes a file");

    let error = cache
        .read_file_artifact(synthetic_file_artifact_value(b"file artifact"))
        .expect_err("unusable locks path rejects file artifact reads");

    assert!(matches!(
        error,
        PersistBlobPackError::AdvisoryReadLock {
            store: PersistBlobStore::Files,
            ref path,
            ..
        } if path == &layout.blob_store_lock_path(PersistBlobStore::Files)
    ));

    let _ = fs::remove_file(layout.locks_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_read_maps_advisory_store_lock_error() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();

    fs::remove_dir_all(layout.locks_dir()).expect("locks directory removes");
    fs::write(layout.locks_dir(), b"not a directory").expect("locks path becomes a file");

    let error = cache
        .read_parse_artifact(synthetic_parse_artifact_value(b"parse artifact"))
        .expect_err("unusable locks path rejects parse artifact reads");

    assert!(matches!(
        error,
        PersistBlobPackError::AdvisoryReadLock {
            store: PersistBlobStore::Files,
            ref path,
            ..
        } if path == &layout.blob_store_lock_path(PersistBlobStore::Files)
    ));

    let _ = fs::remove_file(layout.locks_dir());
    let _ = fs::remove_dir_all(root);
}

fn append_file_artifact_blob(
    cache: &PersistCache,
    payload: &[u8],
) -> PersistFileArtifactIndexValue {
    let blob_hash = PersistFileBlobHash::for_payload(payload);
    let key = PersistBlobKey::for_file(blob_hash);
    let location = cache.append_blob(key, payload).expect("file blob appends");
    PersistFileArtifactIndexValue::new(blob_hash, location)
}

fn append_parse_artifact_blob(
    cache: &PersistCache,
    payload: &[u8],
) -> PersistParseArtifactIndexValue {
    let blob_hash = PersistFileBlobHash::for_payload(payload);
    let key = PersistBlobKey::for_file(blob_hash);
    let location = cache.append_blob(key, payload).expect("parse blob appends");
    PersistParseArtifactIndexValue::new(blob_hash, location)
}

fn synthetic_file_artifact_value(payload: &[u8]) -> PersistFileArtifactIndexValue {
    PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(payload),
        PersistBlobLocation::new(0, 0),
    )
}

fn synthetic_parse_artifact_value(payload: &[u8]) -> PersistParseArtifactIndexValue {
    PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(payload),
        PersistBlobLocation::new(0, 0),
    )
}

fn poison_files_store_lock(root: &std::path::Path) {
    let poison_cache = PersistCache::open(root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Files)
            .expect("file store lock acquires");
        panic!("poison persistent file blob-pack read lock");
    });
    assert!(poisoner.join().is_err());
}

fn assert_files_advisory_lock_released(path: &std::path::Path) {
    let released_lock = AdvisoryFileLock::try_lock(path, AdvisoryFileLockMode::Exclusive)
        .expect("artifact read advisory lock releases after read");
    drop(released_lock);
}
