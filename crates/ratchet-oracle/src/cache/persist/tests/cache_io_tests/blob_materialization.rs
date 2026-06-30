//! Blob materialization and indexed write tests.

use super::*;

#[test]
fn cache_materialization_decision_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

    let result = cache
        .materialize_blob(key, b"payload", MaterializationDecision::KeepInMemory)
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(result.index_entry(key), None);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_decision_appends_when_requested() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );

    let result = cache
        .materialize_blob(key, payload, MaterializationDecision::Materialize)
        .expect("materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
    assert_eq!(
        location.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        result.index_entry(key),
        Some(PersistBlobIndexEntry::new(key, location))
    );
    assert_eq!(
        cache
            .read_blob(key, location)
            .expect("materialized blob reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_raw_blob_borrowed_read_uses_scoped_mapped_payload() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"borrowed raw payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let location = cache.append_blob(key, payload).expect("raw blob appends");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let observed_len = cache
        .with_blob(key, location, |mapped| {
            assert_eq!(mapped, payload);
            mapped.len()
        })
        .expect("borrowed raw blob reads");

    assert_eq!(observed_len, payload.len());
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_append_blob_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let payload = b"raw advisory payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .append_blob(key, payload)
            .map(|location| location.record_offset())
            .map_err(|error| error.to_string());
        tx.send(result).expect("append result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let record_offset = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("raw append completes after same-process lock release")
        .expect("raw append succeeds");
    assert_eq!(record_offset, PERSIST_BLOB_PACK_HEADER_LEN as u64);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.blob_store_lock_path(PersistBlobStore::Values),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("blob advisory lock releases after raw append");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_decision_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

    let result = cache
        .materialize_blob_indexed(key, b"payload", MaterializationDecision::KeepInMemory)
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(result.index_entry(key), None);
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
fn cache_indexed_materialization_decision_appends_and_indexes_when_requested() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );

    let result = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
    assert_eq!(
        result.index_entry(key),
        Some(PersistBlobIndexEntry::new(key, location))
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_reuses_verified_existing_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let first = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("first indexed materialization succeeds");
    let PersistMaterialization::Materialized(first_location) = first else {
        panic!("first materialization should append");
    };
    let pack_len = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    let index_len = fs::metadata(cache.value_index().path())
        .expect("value index metadata")
        .len();

    let second = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("second indexed materialization succeeds");

    assert_eq!(second, PersistMaterialization::Materialized(first_location));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        pack_len
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        index_len
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_single_flights_cloned_cache_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = Arc::new(b"payload".to_vec());
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload.as_slice()),
    );
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let worker_cache = cache.clone();
        let worker_payload = Arc::clone(&payload);
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            let result = worker_cache
                .materialize_blob_indexed(
                    key,
                    worker_payload.as_slice(),
                    MaterializationDecision::Materialize,
                )
                .expect("indexed materialization succeeds");
            let PersistMaterialization::Materialized(location) = result else {
                panic!("materialization should report a location");
            };
            location
        }));
    }

    let mut locations = Vec::new();
    for handle in handles {
        locations.push(handle.join().expect("worker should not panic"));
    }

    let first_location = *locations.first().expect("worker locations exist");
    assert!(locations.iter().all(|location| *location == first_location));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        1
    );
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("value index latest entries"),
        vec![PersistBlobIndexEntry::new(key, first_location)]
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload.as_slice()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_reports_poisoned_shared_clone_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = cache.clone();
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value write lock acquires");
        panic!("poison persistent value write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let error = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect_err("poisoned shared value lock should reject materialization");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
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
fn cache_indexed_materialization_single_flights_independently_opened_cache_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = Arc::new(b"payload".to_vec());
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload.as_slice()),
    );
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_payload = Arc::clone(&payload);
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            let result = worker_cache
                .materialize_blob_indexed(
                    key,
                    worker_payload.as_slice(),
                    MaterializationDecision::Materialize,
                )
                .expect("indexed materialization succeeds");
            let PersistMaterialization::Materialized(location) = result else {
                panic!("materialization should report a location");
            };
            location
        }));
    }

    let mut locations = Vec::new();
    for handle in handles {
        locations.push(handle.join().expect("worker should not panic"));
    }

    let first_location = *locations.first().expect("worker locations exist");
    assert!(locations.iter().all(|location| *location == first_location));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        1
    );
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("value index latest entries"),
        vec![PersistBlobIndexEntry::new(key, first_location)]
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload.as_slice()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_acquires_advisory_store_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let payload = b"advisory indexed payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
            .map(|materialization| {
                matches!(materialization, PersistMaterialization::Materialized(_))
            })
            .map_err(|error| error.to_string());
        tx.send(result).expect("materialization result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    drop(guard);

    let materialized = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("indexed materialization completes after same-process lock release")
        .expect("indexed materialization succeeds");
    assert!(materialized);
    handle.join().expect("worker joins");
    assert!(
        layout
            .blob_store_lock_path(PersistBlobStore::Values)
            .is_file()
    );
    let released_lock = AdvisoryFileLock::try_lock(
        layout.blob_store_lock_path(PersistBlobStore::Values),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("indexed blob advisory lock releases after materialization");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value write lock acquires");
        panic!("poison persistent value write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let error = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect_err("poisoned shared value lock should reject materialization");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
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
fn cache_append_blob_indexed_reports_poisoned_same_root_lock() {
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

    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let error = cache
        .append_blob_indexed(key, payload)
        .expect_err("poisoned shared value lock should reject indexed append");

    assert!(matches!(
        error,
        PersistBlobIndexedWriteError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
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
fn cache_append_blob_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_blob_materialization_for_tests(PersistBlobStore::Values)
            .expect("value blob-pack write lock acquires");
        panic!("poison persistent value blob-pack write lock");
    });
    assert!(poisoner.join().is_err());

    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let error = cache
        .append_blob(key, payload)
        .expect_err("poisoned shared value lock should reject raw append");

    assert!(matches!(
        error,
        PersistBlobPackError::WriteLockPoisoned {
            store: PersistBlobStore::Values
        }
    ));
    assert_eq!(
        cache
            .value_pack()
            .records()
            .expect("value pack records scan")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}
