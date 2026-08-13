//! Blob pack advisory lock and poisoned-lock tests.

use super::*;

#[test]
fn cache_blob_index_compaction_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_blob_index(PersistBlobStore::Values)
            .map_err(|error| error.to_string());
        tx.send(result).expect("compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let compacted_entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-index compaction completes after same-process lock release")
        .expect("blob-index compaction succeeds");
    assert_eq!(compacted_entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_compaction_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .compact_blob_index(PersistBlobStore::Values)
        .expect_err("poisoned shared value lock should reject blob-index compaction");

    assert!(matches!(
        error,
        PersistBlobIndexError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .rebuild_blob_index_from_pack(PersistBlobStore::Values)
            .map(|plan| plan.planned_entries().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("rebuild result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let planned_entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-index rebuild completes after same-process lock release")
        .expect("blob-index rebuild succeeds");
    assert_eq!(planned_entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect_err("poisoned shared value lock should reject blob-index rebuild");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_index_entries_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .blob_pack_index_entries(PersistBlobStore::Values)
            .map(|entries| entries.len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("blob-pack scan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-pack scan completes after same-process lock release")
        .expect("blob-pack scan succeeds");
    assert_eq!(entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_latest_blob_pack_index_entries_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .latest_blob_pack_index_entries(PersistBlobStore::Values)
            .map(|entries| entries.len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("latest blob-pack scan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("latest blob-pack scan completes after same-process lock release")
        .expect("latest blob-pack scan succeeds");
    assert_eq!(entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .plan_blob_index_rebuild(PersistBlobStore::Values)
            .map(|plan| plan.planned_entries().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("blob-index plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let planned_entries = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-index plan completes after same-process lock release")
        .expect("blob-index plan succeeds");
    assert_eq!(planned_entries, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_read_blob_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let payload = b"raw value blob payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let location = cache.append_blob(key, payload).expect("value blob appends");
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .read_blob(key, location)
            .map_err(|error| error.to_string());
        tx.send(result).expect("read result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "raw blob read should wait while the same-root store lock is held"
    );
    drop(guard);

    let bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("raw blob read completes after same-process lock release")
        .expect("raw blob read succeeds");
    handle.join().expect("worker joins");
    assert_eq!(bytes.as_slice(), payload);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_read_blob_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value store lock acquires");
        panic!("poison persistent value blob-pack read lock");
    });
    assert!(poisoner.join().is_err());

    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"value payload"),
    );
    let error = cache
        .read_blob(key, PersistBlobLocation::new(0, 0))
        .expect_err("poisoned same-root value lock should reject raw blob reads");

    assert!(matches!(
        error,
        PersistBlobPackError::ReadLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_read_blob_maps_advisory_store_lock_error() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"value payload"),
    );

    fs::remove_dir_all(layout.locks_dir()).expect("locks directory removes");
    fs::write(layout.locks_dir(), b"not a directory").expect("locks path becomes a file");

    let error = cache
        .read_blob(key, PersistBlobLocation::new(0, 0))
        .expect_err("unusable locks path rejects raw blob reads");

    assert!(matches!(
        error,
        PersistBlobPackError::AdvisoryReadLock {
            store: PersistBlobStore::Values,
            ref path,
            ..
        } if path == &layout.blob_store_lock_path(PersistBlobStore::Values)
    ));

    let _ = fs::remove_file(layout.locks_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Values)
            .map(|trim| trim.reclaimed_bytes())
            .map_err(|error| error.to_string());
        tx.send(result).expect("tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let reclaimed_bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("blob-pack tail trim completes after same-process lock release")
        .expect("blob-pack tail trim succeeds");
    assert_eq!(reclaimed_bytes, 0);
    handle.join().expect("worker joins");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let payload = b"rooted file artifact payload";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    let index_value = index_entry.value();
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    let tail_payload = b"unindexed file tail payload";
    let tail_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unindexed file tail appends");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + tail_payload.len() as u64;
    let expected_bytes_after = index_value.location().record_offset()
        + PERSIST_BLOB_RECORD_HEADER_LEN as u64
        + payload.len() as u64;
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map(|trim| {
                (
                    trim.live_entries(),
                    trim.reclaimed_bytes(),
                    trim.bytes_after(),
                )
            })
            .map_err(|error| error.to_string());
        tx.send(result).expect("file tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    drop(guard);

    let (live_entries, reclaimed_bytes, bytes_after) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack tail trim completes after same-process lock release")
        .expect("file blob-pack tail trim succeeds");
    assert_eq!(live_entries, 1);
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(bytes_after, expected_bytes_after);
    handle.join().expect("worker joins");
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("rooted file artifact remains readable")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(tail_key, tail_location).is_err(),
        "unindexed file tail record should be truncated"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_acquires_file_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map(|trim| trim.reclaimed_bytes())
            .map_err(|error| error.to_string());
        tx.send(result).expect("file tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    drop(guard);

    let reclaimed_bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack tail trim completes after file-artifact lock release")
        .expect("file blob-pack tail trim succeeds");
    assert_eq!(reclaimed_bytes, 0);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after tail trim");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_acquires_parse_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .trim_blob_pack_tail(PersistBlobStore::Files)
            .map(|trim| trim.reclaimed_bytes())
            .map_err(|error| error.to_string());
        tx.send(result).expect("file tail-trim result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    drop(guard);

    let reclaimed_bytes = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack tail trim completes after parse-artifact lock release")
        .expect("file blob-pack tail trim succeeds");
    assert_eq!(reclaimed_bytes, 0);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after tail trim");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted value before repack";
    let unrooted_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(unrooted_payload),
    );
    let unrooted_location = cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted value appends");
    let payload = b"indexed value after unrooted prefix";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    cache
        .append_blob_indexed(key, payload)
        .expect("indexed value appends");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_value_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("value repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("value blob-pack repack completes after same-process lock release")
        .expect("value blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed value reads")
            .expect("indexed value exists")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(unrooted_key, unrooted_location).is_err(),
        "unrooted value record should be omitted by repack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted file before repack";
    let unrooted_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(unrooted_payload));
    let unrooted_location = cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"rooted file artifact after unrooted prefix";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_file_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack repack completes after same-process lock release")
        .expect("file blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    let relocated = cache
        .lookup_file_artifact(file_artifact_key)
        .expect("file artifact lookup succeeds")
        .expect("file artifact remains indexed");
    assert_eq!(
        cache
            .read_file_artifact(relocated)
            .expect("relocated file artifact reads")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(unrooted_key, unrooted_location).is_err(),
        "unrooted file record should be omitted by repack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_acquires_file_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted file before file-artifact repack";
    let unrooted_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(unrooted_payload));
    cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"rooted file artifact after advisory prefix";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_file_artifacts_for_tests()
        .expect("file-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_file_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack repack completes after file-artifact lock release")
        .expect("file blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.file_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("file-artifact advisory lock releases after repack");
    drop(released_lock);
    let relocated = cache
        .lookup_file_artifact(file_artifact_key)
        .expect("file artifact lookup succeeds")
        .expect("file artifact remains indexed");
    assert_eq!(
        cache
            .read_file_artifact(relocated)
            .expect("relocated file artifact reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_acquires_parse_artifact_advisory_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let unrooted_payload = b"unrooted file before parse-artifact repack";
    let unrooted_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(unrooted_payload));
    cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let parse_artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let payload = b"rooted parse artifact after advisory prefix";
    let materialized = cache
        .materialize_parse_artifact(parse_key, payload, MaterializationDecision::Materialize)
        .expect("parse artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("parse artifact should materialize");
    cache
        .record_parse_artifact(index_entry)
        .expect("parse artifact mapping records");
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unrooted_payload.len() as u64;
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .repack_file_blob_pack()
            .map(|plan| (plan.reclaimable_bytes(), plan.record_relocations().len()))
            .map_err(|error| error.to_string());
        tx.send(result).expect("file repack result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    drop(guard);

    let (reclaimed_bytes, relocated_records) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("file blob-pack repack completes after parse-artifact lock release")
        .expect("file blob-pack repack succeeds");
    assert_eq!(reclaimed_bytes, expected_reclaimed);
    assert_eq!(relocated_records, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after repack");
    drop(released_lock);
    let relocated = cache
        .lookup_parse_artifact(parse_artifact_key)
        .expect("parse artifact lookup succeeds")
        .expect("parse artifact remains indexed");
    assert_eq!(
        cache
            .read_parse_artifact(relocated)
            .expect("relocated parse artifact reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_reports_poisoned_same_root_blob_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-index write lock acquires");
        panic!("poison persistent value blob-index write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect_err("poisoned shared value lock should reject value pack trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::BlobIndex {
            source: PersistBlobIndexError::WriteLockPoisoned {
                store: PersistBlobStore::Values
            }
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_reports_poisoned_same_root_file_artifact_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_file_artifacts_for_tests()
            .expect("file-artifact write lock acquires");
        panic!("poison persistent file-artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect_err("poisoned shared file-artifact lock should reject file pack trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::FileArtifactIndex {
            source: PersistFileArtifactIndexError::WriteLockPoisoned
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_reports_poisoned_same_root_parse_artifact_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_parse_artifacts_for_tests()
            .expect("parse-artifact write lock acquires");
        panic!("poison persistent parse-artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect_err("poisoned shared parse-artifact lock should reject file pack trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::ParseArtifactIndex {
            source: PersistParseArtifactIndexError::WriteLockPoisoned
        }
    ));

    let _ = fs::remove_dir_all(root);
}
