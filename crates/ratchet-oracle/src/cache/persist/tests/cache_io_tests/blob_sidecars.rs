//! Blob I/O and sidecar index tests.

mod split;

use super::*;

#[test]
fn cache_blob_indexed_io_updates_index_and_reads_by_key() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"indexed payload";
    let file_payload = b"indexed file payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(file_payload));
    let same_hash_file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload));

    let entry = cache
        .append_blob_indexed(key, payload)
        .expect("indexed blob appends");
    cache
        .append_blob_indexed(file_key, file_payload)
        .expect("indexed file blob appends");

    assert_eq!(entry.key(), key);
    assert_eq!(
        entry.location().record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(entry.location())
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(
        cache
            .read_blob_indexed(file_key)
            .expect("indexed file read succeeds")
            .expect("indexed file blob exists")
            .as_slice(),
        file_payload
    );
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(
        cache
            .read_blob_indexed(same_hash_file_key)
            .expect("other store lookup succeeds"),
        None
    );
    assert_eq!(
        cache.file_pack().mapped_read_count_for_tests(),
        1,
        "indexed misses should not map the selected pack"
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_borrowed_read_uses_scoped_mapped_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"borrowed indexed payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let missing_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"missing payload"),
    );
    cache
        .append_blob_indexed(key, payload)
        .expect("indexed blob appends");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let observed_len = cache
        .with_blob_indexed(key, |mapped| {
            assert_eq!(mapped, payload);
            mapped.len()
        })
        .expect("borrowed indexed blob read succeeds")
        .expect("indexed blob exists");

    assert_eq!(observed_len, payload.len());
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(
        cache
            .with_blob_indexed(missing_key, |_| panic!(
                "indexed miss should not visit payload"
            ))
            .expect("indexed miss succeeds"),
        None
    );
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        1,
        "indexed misses should not map the selected pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_indexed_read_waits_for_store_lock() {
    assert_blob_indexed_read_waits_for_store_lock(
        PersistBlobStore::Values,
        b"locked indexed value payload",
    );
}

#[test]
fn cache_file_blob_indexed_read_waits_for_store_lock() {
    assert_blob_indexed_read_waits_for_store_lock(
        PersistBlobStore::Files,
        b"locked indexed file payload",
    );
}

fn assert_blob_indexed_read_waits_for_store_lock(store: PersistBlobStore, payload: &[u8]) {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let hash = DurableBlake3Hash::for_bytes(payload);
    let key = match store {
        PersistBlobStore::Values => PersistBlobKey::new(PersistBlobStore::Values, hash),
        PersistBlobStore::Files => {
            PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload))
        }
    };
    cache
        .append_blob_indexed(key, payload)
        .expect("indexed blob appends");
    let guard = cache
        .lock_blob_materialization_for_tests(store)
        .expect("store lock acquired");
    let reader = cache.clone();
    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let reader_barrier = Arc::clone(&barrier);
    let handle = thread::spawn(move || {
        reader_barrier.wait();
        let result = reader.read_blob_indexed(key);
        tx.send(result).expect("read result sends");
    });

    barrier.wait();
    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(store));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "indexed read should wait while the store lock is held"
    );
    drop(guard);
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("indexed read completes after lock release")
        .expect("indexed read succeeds")
        .expect("indexed blob exists");
    handle.join().expect("reader thread joins");
    assert_eq!(result.as_slice(), payload);
    let released_lock = AdvisoryFileLock::try_lock(
        layout.blob_store_lock_path(store),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("indexed read advisory lock releases after read");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_read_returns_none_on_miss() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"missing"),
    );

    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("lookup miss succeeds"),
        None
    );
    assert_eq!(
        cache.read_blob_indexed(key).expect("read miss succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_append_rejects_hash_mismatch_before_index_write() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

    let error = cache
        .append_blob_indexed(key, b"payload")
        .expect_err("hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::Append {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_io_rejects_payload_hash_mismatch() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

    let error = cache
        .append_blob(key, b"payload")
        .expect_err("hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_index_records_and_looks_up_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let other_key = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized IR artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );

    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
        .expect("file artifact index entry records");

    assert_eq!(
        cache
            .lookup_file_artifact(key)
            .expect("file artifact lookup succeeds"),
        Some(value)
    );
    assert_eq!(
        cache
            .lookup_file_artifact(other_key)
            .expect("file artifact miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_file_artifact_acquires_advisory_mapping_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"advisory file artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file-artifact record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("file-artifact record completes after same-process lock release")
        .expect("file-artifact record succeeds");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after record");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_file_artifact(key)
            .expect("file artifact lookup succeeds"),
        Some(value)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_lookup_file_artifact_acquires_advisory_mapping_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"lookup advisory file artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
        .expect("file artifact index entry records");
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .lookup_file_artifact(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("file-artifact lookup result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "file-artifact lookup should wait while the mapping lock is held"
    );
    drop(guard);

    let found = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file-artifact lookup completes after same-process lock release")
        .expect("file-artifact lookup succeeds");
    handle.join().expect("worker joins");
    assert_eq!(found, Some(value));
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after lookup");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_index_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for worker in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let source = format!("let x = {worker}; in x");
            let parse_key = test_parse_key(source.as_bytes());
            let realpath = format!("/src/{worker}.nix");
            let file_key = ParseFileKey::for_source(realpath.as_str(), source.as_bytes());
            let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
            let value = PersistFileArtifactIndexValue::new(
                PersistFileBlobHash::for_payload(format!("artifact-{worker}").as_bytes()),
                PersistBlobLocation::new(
                    PERSIST_BLOB_PACK_HEADER_LEN as u64 + worker as u64,
                    worker as u64,
                ),
            );

            worker_barrier.wait();
            worker_cache
                .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
                .expect("file artifact records");
            (key, value)
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }

    for (key, value) in &recorded {
        assert_eq!(
            cache
                .lookup_file_artifact(*key)
                .expect("file artifact lookup succeeds"),
            Some(*value)
        );
    }
    assert_eq!(
        cache
            .file_artifact_index()
            .latest_entries()
            .expect("latest file artifact entries")
            .len(),
        workers
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * workers) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_index_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_file_artifacts_for_tests()
            .expect("file artifact lock acquires");
        panic!("poison persistent file artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let value = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized IR artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    let error = cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, value))
        .expect_err("poisoned same-root file artifact lock should reject writes");

    assert!(matches!(
        error,
        PersistFileArtifactIndexError::WriteLockPoisoned
    ));
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_fixed_record_indexes_compact_to_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"value payload"),
    );
    let file_blob_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"file payload"));
    let value_first = PersistBlobLocation::new(111, 12);
    let value_latest = PersistBlobLocation::new(222, 34);
    let file_first = PersistBlobLocation::new(333, 56);
    let file_latest = PersistBlobLocation::new(444, 78);

    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_first))
        .expect("first value blob index entry appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_latest))
        .expect("latest value blob index entry appends");
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_blob_key, file_first))
        .expect("first file blob index entry appends");
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_blob_key, file_latest))
        .expect("latest file blob index entry appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_artifact_first = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first file artifact"),
        PersistBlobLocation::new(555, 90),
    );
    let file_artifact_latest = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest file artifact"),
        PersistBlobLocation::new(666, 12),
    );
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            file_artifact_first,
        ))
        .expect("first file artifact entry records");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            file_artifact_latest,
        ))
        .expect("latest file artifact entry records");

    let parse_artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let parse_artifact_first = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first parse artifact"),
        PersistBlobLocation::new(777, 34),
    );
    let parse_artifact_latest = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest parse artifact"),
        PersistBlobLocation::new(888, 56),
    );
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            parse_artifact_first,
        ))
        .expect("first parse artifact entry records");
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            parse_artifact_latest,
        ))
        .expect("latest parse artifact entry records");

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        (PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * 2) as u64
    );

    assert_eq!(
        cache
            .compact_blob_index(PersistBlobStore::Values)
            .expect("value index compacts"),
        1
    );
    assert_eq!(
        cache
            .compact_blob_index(PersistBlobStore::Files)
            .expect("file index compacts"),
        1
    );
    assert_eq!(
        cache
            .compact_file_artifact_index()
            .expect("file artifact index compacts"),
        1
    );
    assert_eq!(
        cache
            .compact_parse_artifact_index()
            .expect("parse artifact index compacts"),
        1
    );

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value lookup succeeds"),
        Some(value_latest)
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_blob_key)
            .expect("file lookup succeeds"),
        Some(file_latest)
    );
    assert_eq!(
        cache
            .lookup_file_artifact(file_artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(file_artifact_latest)
    );
    assert_eq!(
        cache
            .lookup_parse_artifact(parse_artifact_key)
            .expect("parse artifact lookup succeeds"),
        Some(parse_artifact_latest)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_compact_file_artifact_index_acquires_advisory_mapping_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let first = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first file artifact"),
        PersistBlobLocation::new(555, 90),
    );
    let latest = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest file artifact"),
        PersistBlobLocation::new(666, 12),
    );
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, first))
        .expect("first file artifact entry records");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(key, latest))
        .expect("latest file artifact entry records");
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_file_artifact_index()
            .map_err(|error| error.to_string());
        tx.send(result)
            .expect("file-artifact compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    drop(guard);

    let retained = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file-artifact compaction completes after same-process lock release")
        .expect("file-artifact compaction succeeds");
    assert_eq!(retained, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after compaction");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_file_artifact(key)
            .expect("file artifact lookup succeeds"),
        Some(latest)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_compact_parse_artifact_index_acquires_advisory_mapping_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let first = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"first parse artifact"),
        PersistBlobLocation::new(777, 34),
    );
    let latest = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest parse artifact"),
        PersistBlobLocation::new(888, 56),
    );
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, first))
        .expect("first parse artifact entry records");
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, latest))
        .expect("latest parse artifact entry records");
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_parse_artifact_index()
            .map_err(|error| error.to_string());
        tx.send(result)
            .expect("parse-artifact compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    drop(guard);

    let retained = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("parse-artifact compaction completes after same-process lock release")
        .expect("parse-artifact compaction succeeds");
    assert_eq!(retained, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after compaction");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_parse_artifact(key)
            .expect("parse artifact lookup succeeds"),
        Some(latest)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_index_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for worker in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let source = format!("let x = {worker}; in x");
            let parse_key = test_parse_key(source.as_bytes());
            let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
            let value = PersistParseArtifactIndexValue::new(
                PersistFileBlobHash::for_payload(format!("parse-artifact-{worker}").as_bytes()),
                PersistBlobLocation::new(
                    PERSIST_BLOB_PACK_HEADER_LEN as u64 + worker as u64,
                    worker as u64,
                ),
            );

            worker_barrier.wait();
            worker_cache
                .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, value))
                .expect("parse artifact records");
            (key, value)
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }

    for (key, value) in &recorded {
        assert_eq!(
            cache
                .lookup_parse_artifact(*key)
                .expect("parse artifact lookup succeeds"),
            Some(*value)
        );
    }
    assert_eq!(
        cache
            .parse_artifact_index()
            .latest_entries()
            .expect("latest parse artifact entries")
            .len(),
        workers
    );
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        (PERSIST_PARSE_ARTIFACT_INDEX_ENTRY_LEN * workers) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_parse_artifact_acquires_advisory_mapping_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"advisory parse artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, value))
            .map_err(|error| error.to_string());
        tx.send(result).expect("parse-artifact record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("parse-artifact record completes after same-process lock release")
        .expect("parse-artifact record succeeds");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after record");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_parse_artifact(key)
            .expect("parse artifact lookup succeeds"),
        Some(value)
    );

    let _ = fs::remove_dir_all(root);
}
