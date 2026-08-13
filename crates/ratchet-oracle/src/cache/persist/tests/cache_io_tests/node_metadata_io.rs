//! Node trace and metadata write tests.

use super::*;

#[test]
fn cache_compact_node_traces_uses_advisory_trace_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let stale_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale value"));
    let dependency = test_node_trace_dependency(b"latest dependency");
    let payload = test_node_trace_payload(b"input", 1)
        .with_memo_read_dependencies([dependency])
        .expect("latest trace dependency records");
    let stale_payload = test_node_trace_payload(b"stale", 2);

    cache
        .record_node_trace(key, stale_value_hash, &stale_payload)
        .expect("stale node trace records");
    cache
        .record_node_trace(key, value_hash, &payload)
        .expect("latest node trace records");
    let guard = cache
        .lock_node_traces_for_tests()
        .expect("node trace lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_node_traces()
            .map_err(|error| error.to_string());
        tx.send(result).expect("node trace compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_traces_lock_path());
    drop(guard);

    let retained = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("node trace compaction completes after same-process lock release")
        .expect("node traces compact");
    assert_eq!(retained, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_traces_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node trace advisory lock releases after compaction");
    drop(released_lock);
    assert_eq!(
        cache.lookup_node_trace(key).expect("trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(key, value_hash, payload))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_traces_compacts_to_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let other_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"other value"));
    let stale_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"stale value"));
    let dependency = test_node_trace_dependency(b"compact dependency");
    let payload = test_node_trace_payload(b"input", 1)
        .with_memo_read_dependencies([dependency])
        .expect("compact trace dependency records");
    let stale_payload = test_node_trace_payload(b"stale", 2);
    let other_payload = PersistNodeTracePayload::tombstone();

    cache
        .record_node_trace(key, stale_value_hash, &stale_payload)
        .expect("stale trace records");
    cache
        .record_node_trace(other_key, other_value_hash, &other_payload)
        .expect("other trace records");
    cache
        .record_node_trace(key, value_hash, &payload)
        .expect("latest trace records");
    let before_len = fs::metadata(cache.node_trace_log().path())
        .expect("trace log metadata before compaction")
        .len();

    assert_eq!(cache.compact_node_traces().expect("traces compact"), 2);
    assert!(
        fs::metadata(cache.node_trace_log().path())
            .expect("trace log metadata after compaction")
            .len()
            < before_len
    );
    assert_eq!(
        cache.lookup_node_trace(key).expect("trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(key, value_hash, payload))
    );
    assert_eq!(
        cache
            .lookup_node_trace(other_key)
            .expect("other trace lookup succeeds"),
        Some(PersistNodeTraceLogEntry::new(
            other_key,
            other_value_hash,
            other_payload
        ))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_materialization_reuse_records_and_looks_up_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let reuse = MaterializationReuse::new(2, 3);

    cache
        .record_node_materialization_reuse(key, reuse)
        .expect("node reuse records");

    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(reuse)
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(other_key)
            .expect("node reuse miss succeeds"),
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
fn cache_record_node_materialization_reuse_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let key = test_impure_input_node_key(b"input");
    let reuse = MaterializationReuse::new(2, 3);
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_node_materialization_reuse(key, reuse)
            .map_err(|error| error.to_string());
        tx.send(result).expect("node reuse record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("node reuse record completes after same-process lock release")
        .expect("node reuse records");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after reuse record");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(reuse)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_preserves_reuse_and_materialized_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");

    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3)
    );
    assert_eq!(metadata.materialized_value_hash(), Some(value_hash));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(5, 6))
        .expect("node reuse update records");
    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(5, 6)
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_record_node_value_hash_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let reuse = MaterializationReuse::new(2, 3);
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, reuse)
        .expect("node reuse records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_node_materialized_value_hash(key, value_hash)
            .map_err(|error| error.to_string());
        tx.send(result).expect("value hash record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    rx.recv_timeout(Duration::from_secs(5))
        .expect("value hash record completes after same-process lock release")
        .expect("value hash records");
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after value hash record");
    drop(released_lock);
    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(metadata.materialization_reuse(), reuse);
    assert_eq!(metadata.materialized_value_hash(), Some(value_hash));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_clear_materialized_value_hash_preserves_reuse() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 3))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");

    assert!(
        cache
            .clear_node_materialized_value_hash(key)
            .expect("value hash clears")
    );
    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3)
    );
    assert_eq!(metadata.materialized_value_hash(), None);
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        None
    );
    assert!(
        !cache
            .clear_node_materialized_value_hash(key)
            .expect("second value hash clear is a no-op")
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_clear_node_value_hash_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let reuse = MaterializationReuse::new(2, 3);
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, reuse)
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .clear_node_materialized_value_hash(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("value hash clear result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let cleared = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("value hash clear completes after same-process lock release")
        .expect("value hash clears");
    assert!(cleared);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after value hash clear");
    drop(released_lock);
    let metadata = cache
        .lookup_node_metadata(key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(metadata.materialization_reuse(), reuse);
    assert_eq!(metadata.materialized_value_hash(), None);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_current_demand_updates_latest_reuse_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");

    let first = cache
        .record_node_current_demand(key)
        .expect("first demand records");
    assert_eq!(first, MaterializationReuse::new(0, 1));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(7, u64::MAX))
        .expect("saturated reuse records");
    let saturated = cache
        .record_node_current_demand(key)
        .expect("saturating demand records");

    assert_eq!(saturated, MaterializationReuse::new(7, u64::MAX));
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(saturated)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 3) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_current_demand_acquires_advisory_metadata_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let key = test_impure_input_node_key(b"input");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .record_node_current_demand(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("current-demand record result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let recorded = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("current demand completes after same-process lock release")
        .expect("current demand records");
    assert_eq!(recorded, MaterializationReuse::new(0, 1));
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after current demand");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(0, 1))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_current_demand_serializes_independently_opened_same_root_handles() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let workers = 16usize;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let worker_cache = PersistCache::open(&root).expect("worker cache opens");
        let worker_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_cache
                .record_node_current_demand(key)
                .expect("current demand records")
        }));
    }

    let mut recorded = Vec::new();
    for handle in handles {
        recorded.push(handle.join().expect("worker should not panic"));
    }
    recorded.sort_by_key(|reuse| reuse.current_run_demands());

    assert_eq!(
        recorded,
        (1..=workers as u64)
            .map(|current_run_demands| MaterializationReuse::new(0, current_run_demands))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(0, workers as u64))
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * workers) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_node_metadata_for_tests()
            .expect("node metadata lock acquires");
        panic!("poison persistent node metadata write lock");
    });
    assert!(poisoner.join().is_err());

    let key = test_impure_input_node_key(b"input");
    let error = cache
        .record_node_current_demand(key)
        .expect_err("poisoned same-root metadata lock should reject writes");

    assert!(matches!(
        error,
        PersistNodeMetadataIndexError::WriteLockPoisoned
    ));
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}
