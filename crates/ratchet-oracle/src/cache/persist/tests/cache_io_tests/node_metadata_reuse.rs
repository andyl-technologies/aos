//! Node metadata reuse and compaction tests.

use super::*;

#[test]
fn cache_node_materialization_decision_uses_prior_reuse_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let missing = test_impure_input_node_key(b"missing input");
    let profitable = MaterializationCosts::new(100, 10, 20, 30);
    let equal_cost = MaterializationCosts::new(60, 10, 20, 30);

    assert_eq!(
        cache
            .node_materialization_signals(missing, profitable)
            .expect("missing signals build"),
        MaterializationReuse::default().signals(profitable)
    );
    assert_eq!(
        cache
            .node_materialization_decision(missing, profitable)
            .expect("missing decision succeeds"),
        MaterializationDecision::KeepInMemory
    );

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(0, 3))
        .expect("same-run reuse records");
    assert_eq!(
        cache
            .node_materialization_decision(key, profitable)
            .expect("same-run decision succeeds"),
        MaterializationDecision::KeepInMemory,
        "current-run demand must not predict cross-run reuse before advancement"
    );

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(2, 0))
        .expect("prior-run reuse records");
    let metadata_len = fs::metadata(cache.node_metadata_index().path())
        .expect("node metadata index metadata")
        .len();
    let value_pack_len = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    assert_eq!(
        cache
            .node_materialization_signals(key, profitable)
            .expect("prior-run signals build"),
        MaterializationReuse::new(2, 0).signals(profitable)
    );
    assert_eq!(
        cache
            .node_materialization_decision(key, profitable)
            .expect("profitable decision succeeds"),
        MaterializationDecision::Materialize
    );
    assert_eq!(
        cache
            .node_materialization_decision(key, equal_cost)
            .expect("equal-cost decision succeeds"),
        MaterializationDecision::KeepInMemory,
        "prior reuse alone does not materialize when write cost is not lower"
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        metadata_len,
        "decision helpers must not append metadata"
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        value_pack_len,
        "decision helpers must not write payloads"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_materialization_reuse_advances_run_boundaries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let missing = test_impure_input_node_key(b"missing input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    assert_eq!(
        cache
            .advance_node_materialization_reuse_run(missing)
            .expect("missing advance succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        0
    );

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(u64::MAX - 1, 2))
        .expect("reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");
    let advanced = cache
        .advance_node_materialization_reuse_run(key)
        .expect("advance records");

    assert_eq!(advanced, Some(MaterializationReuse::new(u64::MAX, 0)));
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        advanced
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
fn cache_advance_node_reuse_run_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
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
            .advance_node_materialization_reuse_run(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("reuse advance result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let advanced = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reuse advance completes after same-process lock release")
        .expect("reuse advances");
    assert_eq!(advanced, Some(MaterializationReuse::new(3, 0)));
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after reuse advance");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(3, 0))
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_all_node_materialization_reuse_advances_changed_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_key = test_impure_input_node_key(b"first");
    let second_key = test_impure_input_node_key(b"second");
    let third_key = test_impure_input_node_key(b"third");
    let first_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"first value"));
    let third_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"third value"));

    cache
        .record_node_materialization_reuse(first_key, MaterializationReuse::new(1, 2))
        .expect("first reuse records");
    cache
        .record_node_materialization_reuse(second_key, MaterializationReuse::new(9, 0))
        .expect("second reuse records");
    cache
        .record_node_materialization_reuse(first_key, MaterializationReuse::new(4, 5))
        .expect("first latest reuse records");
    cache
        .record_node_materialized_value_hash(first_key, first_hash)
        .expect("first value hash records");
    cache
        .record_node_materialization_reuse(third_key, MaterializationReuse::new(u64::MAX - 1, 3))
        .expect("third reuse records");
    cache
        .record_node_materialized_value_hash(third_key, third_hash)
        .expect("third value hash records");

    let advanced = cache
        .advance_all_node_materialization_reuse_runs()
        .expect("all node reuse advances");

    assert_eq!(advanced.len(), 2);
    assert!(
        advanced
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key())
    );
    assert!(advanced.contains(&PersistNodeMetadataIndexEntry::new(
        first_key,
        PersistNodeMetadataIndexValue::with_materialized_value_hash(
            MaterializationReuse::new(9, 0),
            first_hash
        )
    )));
    assert!(advanced.contains(&PersistNodeMetadataIndexEntry::new(
        third_key,
        PersistNodeMetadataIndexValue::with_materialized_value_hash(
            MaterializationReuse::new(u64::MAX, 0),
            third_hash
        )
    )));
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(second_key)
            .expect("second lookup succeeds"),
        Some(MaterializationReuse::new(9, 0))
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(first_key)
            .expect("first value hash lookup succeeds"),
        Some(first_hash)
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(third_key)
            .expect("third value hash lookup succeeds"),
        Some(third_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 8) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_advance_all_node_reuse_runs_uses_advisory_metadata_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("node reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");
    cache
        .record_node_materialization_reuse(other_key, MaterializationReuse::new(5, 0))
        .expect("other reuse records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .advance_all_node_materialization_reuse_runs()
            .map_err(|error| error.to_string());
        tx.send(result).expect("all reuse advance result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let advanced = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("all reuse advance completes after same-process lock release")
        .expect("all reuse advances");
    assert_eq!(advanced.len(), 1);
    assert!(advanced.contains(&PersistNodeMetadataIndexEntry::new(
        key,
        PersistNodeMetadataIndexValue::with_materialized_value_hash(
            MaterializationReuse::new(3, 0),
            value_hash
        )
    )));
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after all reuse advance");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(3, 0))
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(other_key)
            .expect("other node reuse lookup succeeds"),
        Some(MaterializationReuse::new(5, 0))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_metadata_compacts_to_latest_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = test_impure_input_node_key(b"input");
    let other_key = test_impure_input_node_key(b"other input");
    let value_hash = ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"value"));
    let other_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"other value"));

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("stale reuse records");
    cache
        .record_node_materialization_reuse(other_key, MaterializationReuse::new(3, 4))
        .expect("other reuse records");
    cache
        .record_node_materialized_value_hash(other_key, other_value_hash)
        .expect("other value hash records");
    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(5, 6))
        .expect("latest reuse records");
    cache
        .record_node_materialized_value_hash(key, value_hash)
        .expect("value hash records");

    assert_eq!(cache.compact_node_metadata().expect("metadata compacts"), 2);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(5, 6))
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(other_key)
            .expect("other node reuse lookup succeeds"),
        Some(MaterializationReuse::new(3, 4))
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(key)
            .expect("value hash lookup succeeds"),
        Some(value_hash)
    );
    assert_eq!(
        cache
            .lookup_node_materialized_value_hash(other_key)
            .expect("other value hash lookup succeeds"),
        Some(other_value_hash)
    );
    assert_eq!(
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 2) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_compact_node_metadata_acquires_advisory_metadata_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let key = test_impure_input_node_key(b"input");

    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(1, 2))
        .expect("stale reuse records");
    cache
        .record_node_materialization_reuse(key, MaterializationReuse::new(5, 6))
        .expect("latest reuse records");
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .compact_node_metadata()
            .map_err(|error| error.to_string());
        tx.send(result)
            .expect("node metadata compaction result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    drop(guard);

    let retained = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("node metadata compaction completes after same-process lock release")
        .expect("node metadata compaction succeeds");
    assert_eq!(retained, 1);
    handle.join().expect("worker joins");
    let released_lock = AdvisoryFileLock::try_lock(
        layout.node_metadata_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("node metadata advisory lock releases after compaction");
    drop(released_lock);
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(key)
            .expect("node reuse lookup succeeds"),
        Some(MaterializationReuse::new(5, 6))
    );

    let _ = fs::remove_dir_all(root);
}
