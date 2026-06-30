//! Cached expression materialization and node value root tests.

use super::*;

#[test]
fn cache_cached_expression_payload_materialization_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::context_free_string(b"cached string".to_vec());

    let result = cache
        .materialize_cached_expression_value_indexed(
            &payload,
            MaterializationDecision::KeepInMemory,
        )
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
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
fn cache_cached_expression_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed blob reads")
            .expect("indexed blob exists")
            .as_slice(),
        payload
            .encode_persistent_payload()
            .expect("payload encodes")
            .as_slice()
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("payload loads")
            .expect("payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_load_uses_scoped_mapped_value_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);
    cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("payload materializes");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    cache
        .read_blob_indexed(key)
        .expect("owned indexed read succeeds")
        .expect("owned indexed blob exists");
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        1,
        "owned indexed blob reads should clone through the scoped mapped adapter"
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("payload loads")
            .expect("payload exists"),
        payload
    );
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        2,
        "cached-expression value loads should decode through the scoped mapped adapter"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_borrowed_load_visits_decoded_value_under_scoped_mapping() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let missing_payload = CachedExpressionValue::immediate(Value::int(7)).expect("payload builds");
    let missing_hash = missing_payload.value_hash().expect("payload hashes");
    let value_store_lock_path = cache
        .layout()
        .blob_store_lock_path(PersistBlobStore::Values);
    cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("payload materializes");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let observed_hash = cache
        .with_cached_expression_value_indexed(value_hash, |value| {
            assert_eq!(value, &payload);
            let value_store_guard =
                AdvisoryFileLock::try_lock(&value_store_lock_path, AdvisoryFileLockMode::Exclusive)
                    .expect("decoded-value visitor runs after the value-store lock is released");
            drop(value_store_guard);
            value.value_hash().expect("visited payload hashes")
        })
        .expect("borrowed cached-expression load succeeds")
        .expect("indexed value exists");

    assert_eq!(observed_hash, value_hash);
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(
        cache
            .with_cached_expression_value_indexed(missing_hash, |_| panic!(
                "indexed cached-expression miss should not visit payload"
            ))
            .expect("indexed miss succeeds"),
        None
    );
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        1,
        "cached-expression misses should not map the value pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_load_acquires_value_store_advisory_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("payload materializes");
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Values)
        .expect("value store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .load_cached_expression_value_indexed(value_hash)
            .map_err(|error| error.to_string());
        tx.send(result).expect("payload load result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "indexed cached-expression value loads should wait while the value store lock is held"
    );
    drop(guard);

    let loaded = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("payload load completes after value store lock release")
        .expect("payload loads")
        .expect("payload exists");
    handle.join().expect("worker joins");
    assert_eq!(loaded, payload);
    let released_lock = AdvisoryFileLock::try_lock(
        layout.blob_store_lock_path(PersistBlobStore::Values),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("value-store advisory lock releases after indexed payload load");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_load_rejects_corrupt_mapped_value_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("payload materializes");
    let PersistMaterialization::Materialized(location) = result else {
        panic!("payload should materialize");
    };
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .load_cached_expression_value_indexed(value_hash)
        .expect_err("corrupt mapped value blob is rejected");

    assert!(matches!(
        error,
        PersistCachedExpressionValueIndexedLoadError::Read {
            source: PersistBlobIndexedReadError::Read {
                source: PersistBlobPackError::PayloadHashMismatch { .. },
            },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_materialization_reuses_indexed_value_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let first = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("first payload materializes");
    let PersistMaterialization::Materialized(first_location) = first else {
        panic!("payload should materialize");
    };
    let pack_len = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    let index_len = fs::metadata(cache.value_index().path())
        .expect("value index metadata")
        .len();

    let second = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("second payload materializes");

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
fn cache_empty_list_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::empty_list();
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("empty list payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("empty list payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("empty list payload loads")
            .expect("empty list payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_strict_list_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::strict_list(vec![
        CachedExpressionValue::immediate(Value::int(1)).expect("payload builds"),
        CachedExpressionValue::context_string(b"context element".to_vec(), all_context_kinds()),
        CachedExpressionValue::context_path(
            b"/nix/store/context-list-path".to_vec(),
            all_context_kinds(),
        ),
        CachedExpressionValue::strict_list(vec![
            CachedExpressionValue::empty_list(),
            CachedExpressionValue::empty_attrs(),
        ]),
    ]);
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("strict list payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("strict list payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("strict list payload loads")
            .expect("strict list payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_empty_attrs_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::empty_attrs();
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("empty attrset payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("empty attrset payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("empty attrset payload loads")
            .expect("empty attrset payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_strict_attrs_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::strict_attrs(vec![
        (
            b"b".to_vec(),
            CachedExpressionValue::context_string(b"context value".to_vec(), all_context_kinds()),
        ),
        (
            b"a".to_vec(),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("payload builds"),
                CachedExpressionValue::empty_attrs(),
            ]),
        ),
    ])
    .expect("strict attrset payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("strict attrset payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("strict attrset payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("strict attrset payload loads")
            .expect("strict attrset payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_positioned_attrs_payload_materializes_and_loads_by_value_hash() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_position = AttrPosition::new(0, Span::new(4, 5));
    let second_position = AttrPosition::new(0, Span::new(8, 9));
    let payload = CachedExpressionValue::source_ordered_positioned_attrs(vec![
        (
            b"c".to_vec(),
            Some(first_position),
            CachedExpressionValue::immediate(Value::int(2)).expect("payload builds"),
        ),
        (
            b"b".to_vec(),
            Some(second_position),
            CachedExpressionValue::strict_list(vec![
                CachedExpressionValue::immediate(Value::int(1)).expect("payload builds"),
            ]),
        ),
    ])
    .expect("positioned attrset payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let key = PersistBlobKey::for_value(value_hash);

    let result = cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("positioned attrset payload materializes");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("positioned attrset payload should materialize");
    };
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(location)
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("positioned attrset payload loads")
            .expect("positioned attrset payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_materialization_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let payload = CachedExpressionValue::context_free_string(b"cached string".to_vec());

    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::KeepInMemory,
        )
        .expect("skip succeeds");

    assert_eq!(result, PersistMaterialization::Skipped);
    assert_eq!(
        cache
            .lookup_node_metadata(node_key)
            .expect("node metadata lookup succeeds"),
        None
    );
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
fn cache_cached_expression_node_payload_materializes_and_loads_by_node_key() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");

    cache
        .record_node_materialization_reuse(node_key, MaterializationReuse::new(2, 3))
        .expect("reuse records");
    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");

    assert!(matches!(result, PersistMaterialization::Materialized(_)));
    let metadata = cache
        .lookup_node_metadata(node_key)
        .expect("node metadata lookup succeeds")
        .expect("node metadata exists");
    assert_eq!(
        metadata.materialization_reuse(),
        MaterializationReuse::new(2, 3)
    );
    assert_eq!(metadata.materialized_value_hash(), Some(value_hash));
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("node payload loads")
            .expect("node payload exists"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_node_payload_borrowed_load_visits_decoded_value_under_scoped_mapping() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let missing = test_impure_input_node_key(b"missing");
    let reuse_only = test_impure_input_node_key(b"reuse-only");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let value_store_lock_path = cache
        .layout()
        .blob_store_lock_path(PersistBlobStore::Values);
    let node_metadata_lock_path = cache.layout().node_metadata_lock_path();
    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("node payload materializes");
    cache
        .record_node_materialization_reuse(reuse_only, MaterializationReuse::new(2, 3))
        .expect("reuse-only metadata records");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let observed_hash = cache
        .with_cached_expression_node_value_indexed(node_key, |value| {
            assert_eq!(value, &payload);
            let value_store_guard =
                AdvisoryFileLock::try_lock(&value_store_lock_path, AdvisoryFileLockMode::Exclusive)
                    .expect("node value visitor runs after the value-store lock is released");
            drop(value_store_guard);
            let node_metadata_guard = AdvisoryFileLock::try_lock(
                &node_metadata_lock_path,
                AdvisoryFileLockMode::Exclusive,
            )
            .expect("node value visitor runs after the node-metadata lock is released");
            drop(node_metadata_guard);
            assert_eq!(
                cache
                    .lookup_node_materialized_value_hash(node_key)
                    .expect("node metadata lookup re-enters from visitor"),
                Some(value_hash)
            );
            assert_eq!(
                cache
                    .load_cached_expression_value_indexed(value_hash)
                    .expect("indexed value lookup re-enters from visitor")
                    .expect("indexed value exists"),
                payload
            );
            value.value_hash().expect("visited payload hashes")
        })
        .expect("borrowed node cached-expression load succeeds")
        .expect("node-linked value exists");

    assert_eq!(observed_hash, value_hash);
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        2,
        "node-linked visitors and re-entrant value loads should both use scoped mapped reads"
    );
    assert_eq!(
        cache
            .with_cached_expression_node_value_indexed(missing, |_| {
                panic!("missing node metadata should not visit payload")
            })
            .expect("missing node lookup succeeds"),
        None
    );
    assert_eq!(
        cache
            .with_cached_expression_node_value_indexed(reuse_only, |_| {
                panic!("reuse-only node metadata should not visit payload")
            })
            .expect("reuse-only node lookup succeeds"),
        None
    );
    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        2,
        "node-linked misses should not map the value pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_value_root_plan_acquires_value_store_advisory_lock() {
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
            .plan_node_value_roots()
            .map(|plan| plan.resolved_roots().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("node value-root plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "node value-root planning should wait while the value store lock is held"
    );
    drop(guard);

    let resolved_roots = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("node value-root plan completes after value store lock release")
        .expect("node value-root plan succeeds");
    handle.join().expect("worker joins");
    assert_eq!(resolved_roots, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_value_root_plan_acquires_node_metadata_advisory_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_node_metadata_for_tests()
        .expect("node metadata lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .plan_node_value_roots()
            .map(|plan| plan.resolved_roots().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("node value-root plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.node_metadata_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "node value-root planning should wait while the node metadata lock is held"
    );
    drop(guard);

    let resolved_roots = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("node value-root plan completes after metadata lock release")
        .expect("node value-root plan succeeds");
    handle.join().expect("worker joins");
    assert_eq!(resolved_roots, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_value_root_plan_resolves_latest_metadata_links() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let missing_node_key = test_impure_input_node_key(b"missing node");
    let reuse_only_node_key = test_impure_input_node_key(b"reuse-only node");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let missing_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"missing value"));
    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    let PersistMaterialization::Materialized(location) = result else {
        panic!("node payload should materialize");
    };
    cache
        .record_node_materialized_value_hash(missing_node_key, missing_value_hash)
        .expect("missing value metadata records");
    cache
        .record_node_materialization_reuse(reuse_only_node_key, MaterializationReuse::new(3, 4))
        .expect("reuse-only metadata records");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .plan_node_value_roots()
        .expect("node value root plan builds");
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);

    assert!(plan.repair_needed());
    assert_eq!(plan.resolved_roots().len(), 1);
    let resolved = plan.resolved_roots()[0];
    assert_eq!(resolved.node_key(), node_key);
    assert_eq!(resolved.value_hash(), value_hash);
    assert_eq!(resolved.blob_key(), PersistBlobKey::for_value(value_hash));
    assert_eq!(resolved.location(), location);
    assert_eq!(plan.missing_roots().len(), 1);
    let missing = plan.missing_roots()[0];
    assert_eq!(missing.node_key(), missing_node_key);
    assert_eq!(missing.value_hash(), missing_value_hash);
    assert_eq!(
        missing.blob_key(),
        PersistBlobKey::for_value(missing_value_hash)
    );
    assert!(
        plan.missing_roots()
            .iter()
            .all(|root| root.node_key() != reuse_only_node_key),
        "metadata without a materialized value hash is not a value root"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_node_value_root_plan_rejects_corrupt_indexed_value_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    let PersistMaterialization::Materialized(location) = result else {
        panic!("node payload should materialize");
    };
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let error = cache
        .plan_node_value_roots()
        .expect_err("corrupt value root blocks plan");

    assert!(matches!(
        error,
        PersistNodeValueRootPlanError::Read {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}
