//! Metadata sidecar and node trace tests.

use super::*;

#[test]
fn cache_sidecar_compaction_compacts_all_current_sidecars() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"value payload"),
    );
    let value_latest = PersistBlobLocation::new(222, 34);
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            value_key,
            PersistBlobLocation::new(111, 12),
        ))
        .expect("first value blob index entry appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_latest))
        .expect("latest value blob index entry appends");

    let file_blob_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"file payload"));
    let file_latest = PersistBlobLocation::new(444, 78);
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(
            file_blob_key,
            PersistBlobLocation::new(333, 56),
        ))
        .expect("first file blob index entry appends");
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_blob_key, file_latest))
        .expect("latest file blob index entry appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_artifact_latest = PersistFileArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest file artifact"),
        PersistBlobLocation::new(666, 12),
    );
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            PersistFileArtifactIndexValue::new(
                PersistFileBlobHash::for_payload(b"first file artifact"),
                PersistBlobLocation::new(555, 90),
            ),
        ))
        .expect("first file artifact entry records");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            file_artifact_latest,
        ))
        .expect("latest file artifact entry records");

    let parse_artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let parse_artifact_latest = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"latest parse artifact"),
        PersistBlobLocation::new(888, 56),
    );
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            PersistParseArtifactIndexValue::new(
                PersistFileBlobHash::for_payload(b"first parse artifact"),
                PersistBlobLocation::new(777, 34),
            ),
        ))
        .expect("first parse artifact entry records");
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            parse_artifact_key,
            parse_artifact_latest,
        ))
        .expect("latest parse artifact entry records");

    let node_key = test_impure_input_node_key(b"node");
    let node_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"node value"));
    let node_metadata_latest = PersistNodeMetadataIndexValue::with_materialized_value_hash(
        MaterializationReuse::new(3, 4),
        node_value_hash,
    );
    cache
        .record_node_metadata(PersistNodeMetadataIndexEntry::new(
            node_key,
            PersistNodeMetadataIndexValue::new(MaterializationReuse::new(1, 2)),
        ))
        .expect("first node metadata records");
    cache
        .record_node_metadata(PersistNodeMetadataIndexEntry::new(
            node_key,
            node_metadata_latest,
        ))
        .expect("latest node metadata records");

    let trace_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"trace value"));
    let trace_dependency = test_node_trace_dependency(b"trace dependency");
    let trace_payload = test_node_trace_payload(b"node trace", 1)
        .with_memo_read_dependencies([trace_dependency])
        .expect("trace payload dependency records");
    cache
        .record_node_trace(
            node_key,
            ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale trace")),
            &PersistNodeTracePayload::tombstone(),
        )
        .expect("first node trace records");
    cache
        .record_node_trace(node_key, trace_value_hash, &trace_payload)
        .expect("latest node trace records");
    let trace_log_len_before = fs::metadata(cache.node_trace_log().path())
        .expect("node trace log metadata before compaction")
        .len();

    let compaction = cache.compact_sidecars().expect("sidecars compact");
    assert_eq!(compaction.value_blob_index_entries(), 1);
    assert_eq!(compaction.file_blob_index_entries(), 1);
    assert_eq!(compaction.file_artifact_entries(), 1);
    assert_eq!(compaction.parse_artifact_entries(), 1);
    assert_eq!(compaction.node_metadata_entries(), 1);
    assert_eq!(compaction.node_trace_entries(), 1);
    assert_eq!(compaction.total_entries(), 6);

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
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64
    );
    let trace_log_len_after = fs::metadata(cache.node_trace_log().path())
        .expect("node trace log metadata after compaction")
        .len();
    assert!(
        trace_log_len_after < trace_log_len_before,
        "node trace compaction should rewrite only newest records"
    );
    assert_eq!(
        trace_log_len_after,
        PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN as u64
            + trace_payload.encode().expect("trace payload encodes").len() as u64
    );
    assert_eq!(trace_payload.memo_read_dependencies(), &[trace_dependency]);

    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value blob lookup succeeds"),
        Some(value_latest)
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_blob_key)
            .expect("file blob lookup succeeds"),
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
    assert_eq!(
        cache
            .lookup_node_metadata(node_key)
            .expect("node metadata lookup succeeds"),
        Some(node_metadata_latest)
    );
    assert_eq!(
        cache
            .lookup_node_trace(node_key)
            .expect("node trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            node_key,
            trace_value_hash,
            trace_payload,
        ))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_index_records_and_looks_up_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let value = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3));

    cache
        .record_node_metadata(PersistNodeMetadataIndexEntry::new(key, value))
        .expect("node metadata index entry records");

    assert_eq!(
        cache
            .lookup_node_metadata(key)
            .expect("node metadata lookup succeeds"),
        Some(value)
    );
    assert_eq!(
        cache
            .lookup_node_metadata(other_key)
            .expect("node metadata miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        PERSIST_NODE_METADATA_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_node_metadata_acquires_advisory_metadata_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let key = test_impure_input_node_key(b"input");
    let value = PersistNodeMetadataIndexValue::new(MaterializationReuse::new(2, 3));
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_node_metadata(PersistNodeMetadataIndexEntry::new(key, value))
            .map_err(|error| error.to_string());
        tx.send(result).expect("node metadata record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("node metadata record completes after same-process lock release")
        .expect("node metadata record succeeds");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after record");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_metadata(key)
            .expect("node metadata lookup succeeds"),
        Some(value)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_trace_log_records_and_looks_up_payloads() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let first_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let latest_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"latest value"));
    let first = test_node_trace_payload(b"/src/first", 1);
    let dependency = test_node_trace_dependency(b"latest trace dependency");
    let latest = test_node_trace_payload(b"/src/latest", 2)
        .with_memo_read_dependencies([dependency])
        .expect("latest trace dependency records");

    assert_eq!(
        cache.node_trace_log().path(),
        cache.layout().node_trace_log_path().as_path()
    );
    assert_eq!(
        cache
            .lookup_node_trace(key)
            .expect("empty trace lookup succeeds"),
        None
    );

    cache
        .record_node_trace(key, first_value_hash, &first)
        .expect("first node trace records");
    cache
        .record_node_trace(key, latest_value_hash, &latest)
        .expect("latest node trace records");

    assert_eq!(
        cache
            .lookup_node_trace(key)
            .expect("node trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            key,
            latest_value_hash,
            latest.clone()
        ))
    );
    assert_eq!(latest.memo_read_dependencies(), &[dependency]);
    assert_eq!(
        cache
            .lookup_node_trace(other_key)
            .expect("node trace miss succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        (PERSIST_NODE_TRACE_LOG_RECORD_HEADER_LEN * 2) as u64
            + first.encode().expect("first payload encodes").len() as u64
            + latest.encode().expect("latest payload encodes").len() as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_lookup_node_trace_acquires_advisory_trace_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = test_node_trace_payload(b"input", 1);
    cache
        .record_node_trace(key, value_hash, &payload)
        .expect("node trace records");
    let guard = cache
        .lock_node_traces_for_tests()
        .expect("node trace lock acquires");
    let worker_cache = cache.clone();
    let expected_payload = payload.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .lookup_node_trace(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("node trace lookup result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_traces_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "node trace lookup should wait while the same-root trace lock is held"
    );
    drop(guard);

    let entry = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("node trace lookup completes after same-process lock release")
        .expect("node trace lookup succeeds");
    handle.join().expect("worker joins");
    assert_eq!(
        entry,
        Some(PersistNodeTraceLogEntry::new(
            key,
            value_hash,
            expected_payload
        ))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_lookup_node_trace_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_node_traces_for_tests()
            .expect("node trace lock acquires");
        panic!("poison persistent node trace read lock");
    });
    assert!(poisoner.join().is_err());

    let key = test_impure_input_node_key(b"input");
    let error = cache
        .lookup_node_trace(key)
        .expect_err("poisoned same-root trace lock should reject lookups");

    assert!(matches!(error, PersistNodeTraceLogError::ReadLockPoisoned));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_node_trace_uses_advisory_trace_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_node_traces_for_tests()
        .expect("node trace lock acquires");
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = test_node_trace_payload(b"input", 1);
    let worker_payload = payload.clone();
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_node_trace(key, value_hash, &worker_payload)
            .map_err(|error| error.to_string());
        tx.send(result).expect("node trace record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_traces_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("node trace record completes after same-process lock release")
        .expect("node trace records");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_traces_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node trace advisory lock releases after record");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_trace(key)
            .expect("node trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(key, value_hash, payload))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_node_trace_tombstone_uses_advisory_trace_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = test_node_trace_payload(b"input", 1);

    cache
        .record_node_trace(key, value_hash, &payload)
        .expect("node trace records");
    let guard = cache
        .lock_node_traces_for_tests()
        .expect("node trace lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_node_trace_tombstone(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("node trace tombstone result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_traces_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("node trace tombstone completes after same-process lock release")
        .expect("node trace tombstone records");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_traces_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node trace advisory lock releases after tombstone");
    drop(released_lock);
    let latest = cache
        .lookup_node_trace(key)
        .expect("node trace lookup succeeds")
        .expect("node trace exists");
    assert!(latest.payload().is_tombstone());
    assert_eq!(latest.payload().memo_read_dependencies(), &[]);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_node_trace_maps_advisory_trace_lock_error() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = test_node_trace_payload(b"input", 1);

    fs::remove_dir_all(layout.locks_dir()).expect("locks directory removes");
    fs::write(layout.locks_dir(), b"not a directory").expect("locks path becomes a file");

    let error = cache
        .record_node_trace(key, value_hash, &payload)
        .expect_err("unusable locks path rejects trace writes");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::AdvisoryWriteLock { ref path, .. }
            if path == &layout.node_traces_lock_path()
    ));
    assert_eq!(
        fs::metadata(cache.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        0
    );

    let _ = fs::remove_file(layout.locks_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_lookup_node_trace_maps_advisory_trace_lock_error() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");

    fs::remove_dir_all(layout.locks_dir()).expect("locks directory removes");
    fs::write(layout.locks_dir(), b"not a directory").expect("locks path becomes a file");

    let error = cache
        .lookup_node_trace(key)
        .expect_err("unusable locks path rejects trace lookups");

    assert!(matches!(
        error,
        PersistNodeTraceLogError::AdvisoryReadLock { ref path, .. }
            if path == &layout.node_traces_lock_path()
    ));

    let _ = fs::remove_file(layout.locks_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_trace_log_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for worker in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let subject = format!("input-{worker}");
            let key = test_impure_input_node_key(subject.as_bytes());
            let value_subject = format!("value-{worker}");
            let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(
                value_subject.as_bytes(),
            ));
            let payload = test_node_trace_payload(subject.as_bytes(), worker as u8);

            worker_barrier.wait();
            worker_cache
                .record_node_trace(key, value_hash, &payload)
                .expect("node trace records");
            (key, value_hash, payload)
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }

    for (key, value_hash, payload) in &recorded {
        assert_eq!(
            cache
                .lookup_node_trace(*key)
                .expect("node trace lookup succeeds"),
            Some(PersistNodeTraceLogEntry::new(
                *key,
                *value_hash,
                payload.clone()
            ))
        );
    }
    assert_eq!(
        cache
            .node_trace_log()
            .latest_entries()
            .expect("latest trace entries")
            .len(),
        workers
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_trace_log_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_node_traces_for_tests()
            .expect("node trace lock acquires");
        panic!("poison persistent node trace write lock");
    });
    assert!(poisoner.join().is_err());

    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let payload = test_node_trace_payload(b"input", 1);
    let error = cache
        .record_node_trace(key, value_hash, &payload)
        .expect_err("poisoned same-root trace lock should reject writes");

    assert!(matches!(error, PersistNodeTraceLogError::WriteLockPoisoned));
    assert_eq!(
        fs::metadata(cache.node_trace_log().path())
            .expect("node trace log metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}
