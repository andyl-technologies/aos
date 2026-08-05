//! Split-out `cache_io_tests.rs` test group (split).

use super::*;

#[test]
fn cache_cached_expression_node_payload_load_misses_without_linked_value() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let missing = test_impure_input_node_key(b"missing");
    let reuse_only = test_impure_input_node_key(b"reuse-only");

    cache
        .record_node_materialization_reuse(reuse_only, MaterializationReuse::new(2, 3))
        .expect("reuse records");

    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(missing)
            .expect("missing node lookup succeeds"),
        None
    );
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(reuse_only)
            .expect("reuse-only node lookup succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_load_rejects_noncanonical_indexed_bytes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = noncanonical_context_string_payload();
    let payload_hash = DurableBlake3Hash::for_bytes(&payload);
    let value_hash = ValueHash::from_canonical_value_hash(payload_hash);
    let key = PersistBlobKey::for_value(value_hash);
    cache
        .append_blob_indexed(key, &payload)
        .expect("manual non-canonical blob indexes");

    let error = cache
        .load_cached_expression_value_indexed(value_hash)
        .expect_err("non-canonical indexed payload errors");

    assert!(matches!(
        error,
        PersistCachedExpressionValueIndexedLoadError::Decode {
            source: CachedExpressionValuePayloadError::NonCanonicalStringContext { index: 1 }
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_trace_revalidation_dependency_missing_value_blob_misses_identically() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    // Link the dependency's value hash and trace but never materialize its value
    // blob, so the dependency check reaches the value-blob existence probe.
    cache
        .record_node_materialized_value_hash(dependency_key, dependency_value_hash)
        .expect("dependency value hash records");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut revalidator)
            .expect("missing dependency-blob lookup succeeds"),
        None,
        "a dependency whose value blob is absent misses exactly as the decode path did"
    );
    assert_eq!(
        revalidator.calls(),
        1,
        "the dependency input is revalidated before the absent-blob miss"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_trace_revalidation_verified_node_memo_evicts_on_dependency_write() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let dependency_key = test_impure_input_node_key(b"dependency");
    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/dependency", 7);
    let node_trace = PersistNodeTracePayload::from_cacheable_inputs(std::iter::empty::<
        CacheableInputFingerprint,
    >())
    .expect("node trace builds")
    .with_memo_read_dependency_records([(dependency_key, dependency_value_hash)])
    .expect("node trace dependency records");
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("payload materializes");
    cache
        .record_node_trace(node_key, value_hash, &node_trace)
        .expect("node trace records");
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut matching = StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(
        dependency_input.clone(),
    )]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut matching)
            .expect("initial lookup succeeds"),
        Some(payload),
        "the node and its dependency are a valid hit and the dependency is memoized"
    );

    // Tombstoning the dependency is a status-changing write that must evict the
    // memoized dependency hit, so the next load re-checks and misses.
    cache
        .record_node_trace_tombstone(dependency_key)
        .expect("dependency trace tombstone records");

    let mut after_write =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(node_key, &mut after_write)
            .expect("post-write lookup succeeds"),
        None,
        "a memoized dependency hit must not survive a tombstone write to that dependency"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_trace_revalidation_shared_dependency_verified_once_per_run() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_key = test_impure_input_node_key(b"first dependent");
    let second_key = test_impure_input_node_key(b"second dependent");
    let dependency_key = test_impure_input_node_key(b"shared dependency");
    let first_payload = CachedExpressionValue::immediate(Value::int(1)).expect("first payload");
    let second_payload = CachedExpressionValue::immediate(Value::int(2)).expect("second payload");
    let dependency_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("dependency payload builds");
    let first_value_hash = first_payload.value_hash().expect("first hashes");
    let second_value_hash = second_payload.value_hash().expect("second hashes");
    let dependency_value_hash = dependency_payload
        .value_hash()
        .expect("dependency payload hashes");
    let dependency_input = test_read_file_fingerprint(b"/tmp/shared", 7);
    let dependent_trace = |dependency_hash| {
        PersistNodeTracePayload::from_cacheable_inputs(
            std::iter::empty::<CacheableInputFingerprint>(),
        )
        .expect("dependent trace builds")
        .with_memo_read_dependency_records([(dependency_key, dependency_hash)])
        .expect("dependent trace dependency records")
    };
    let dependency_trace =
        PersistNodeTracePayload::from_cacheable_inputs([dependency_input.clone()])
            .expect("dependency trace builds");

    for (key, payload, value_hash) in [
        (first_key, &first_payload, first_value_hash),
        (second_key, &second_payload, second_value_hash),
    ] {
        cache
            .materialize_cached_expression_node_value_indexed(
                key,
                payload,
                MaterializationDecision::Materialize,
            )
            .expect("dependent payload materializes");
        cache
            .record_node_trace(key, value_hash, &dependent_trace(dependency_value_hash))
            .expect("dependent trace records");
    }
    cache
        .materialize_cached_expression_node_value_indexed(
            dependency_key,
            &dependency_payload,
            MaterializationDecision::Materialize,
        )
        .expect("dependency payload materializes");
    cache
        .record_node_trace(dependency_key, dependency_value_hash, &dependency_trace)
        .expect("dependency trace records");

    let mut revalidator =
        StaticRevalidator::new(vec![ImpureInputFingerprint::Cacheable(dependency_input)]);
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(first_key, &mut revalidator)
            .expect("first dependent lookup succeeds"),
        Some(first_payload)
    );
    assert_eq!(
        cache
            .load_cached_expression_node_value_with_trace_revalidation(second_key, &mut revalidator)
            .expect("second dependent lookup succeeds"),
        Some(second_payload)
    );
    assert_eq!(
        revalidator.calls(),
        1,
        "the shared dependency is verified once per run, not once per dependent"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_decode_verification_knob_round_trips_and_defaults_off() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    assert!(
        !cache.value_decode_verification(),
        "value decode verification is off by default"
    );
    let verifying = PersistCache::open(&root)
        .expect("cache reopens")
        .with_value_decode_verification(true);
    assert!(
        verifying.value_decode_verification(),
        "the verification knob enables the defensive decode path"
    );

    let payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let value_hash = payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(&payload, MaterializationDecision::Materialize)
        .expect("value materializes");

    // Both the trusting default and the verifying handle decode the same value.
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("trusting load succeeds"),
        Some(payload.clone())
    );
    assert_eq!(
        verifying
            .load_cached_expression_value_indexed(value_hash)
            .expect("verifying load succeeds"),
        Some(payload)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_buffered_node_demands_flush_matches_immediate_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let buffered_key = test_impure_input_node_key(b"buffered");
    let immediate_key = test_impure_input_node_key(b"immediate");

    // Three immediate demands establish the reference final counters.
    for _ in 0..3 {
        cache
            .record_node_current_demand(immediate_key)
            .expect("immediate demand records");
    }

    // Buffered demands are coalesced in memory and written nothing until flush.
    for _ in 0..3 {
        cache.buffer_node_current_demand(buffered_key);
    }
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("pre-flush lookup succeeds"),
        None,
        "buffered demand does not touch the sidecar before flush"
    );

    cache
        .flush_buffered_node_demands()
        .expect("demand buffer flush succeeds");
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("buffered lookup succeeds"),
        Some(MaterializationReuse::new(0, 3)),
        "the coalesced flush records the full current-run demand count"
    );
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("buffered lookup succeeds"),
        cache
            .lookup_node_materialization_reuse(immediate_key)
            .expect("immediate lookup succeeds"),
        "buffered flush yields the same final counters as immediate records"
    );

    // A flush with an empty buffer is a no-op.
    cache
        .flush_buffered_node_demands()
        .expect("empty demand buffer flush succeeds");
    assert_eq!(
        cache
            .lookup_node_materialization_reuse(buffered_key)
            .expect("post-empty-flush lookup succeeds"),
        Some(MaterializationReuse::new(0, 3))
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_cached_expression_payload_materialization_signals_drive_writes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = CachedExpressionValue::path(b"/nix/store/source".to_vec());
    let value_hash = payload.value_hash().expect("payload hashes");

    let skipped = cache
        .materialize_cached_expression_value_indexed_with_signals(
            &payload,
            profitable_materialization_signals(false),
        )
        .expect("skip succeeds");
    assert_eq!(skipped, PersistMaterialization::Skipped);
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("missing payload lookup succeeds"),
        None
    );

    let written = cache
        .materialize_cached_expression_value_indexed_with_signals(
            &payload,
            profitable_materialization_signals(true),
        )
        .expect("write succeeds");
    assert!(matches!(written, PersistMaterialization::Materialized(_)));
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
fn cache_cached_expression_node_payload_materialization_signals_drive_writes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = test_impure_input_node_key(b"node");
    let payload = CachedExpressionValue::path(b"/nix/store/source".to_vec());

    let skipped = cache
        .materialize_cached_expression_node_value_indexed_with_signals(
            node_key,
            &payload,
            profitable_materialization_signals(false),
        )
        .expect("skip succeeds");
    assert_eq!(skipped, PersistMaterialization::Skipped);
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("missing node payload lookup succeeds"),
        None
    );

    let written = cache
        .materialize_cached_expression_node_value_indexed_with_signals(
            node_key,
            &payload,
            profitable_materialization_signals(true),
        )
        .expect("write succeeds");
    assert!(matches!(written, PersistMaterialization::Materialized(_)));
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
fn cache_materialization_decision_propagates_append_errors() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

    let error = cache
        .materialize_blob(key, b"payload", MaterializationDecision::Materialize)
        .expect_err("materialization hash mismatch errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_materialization_signals_append_when_threshold_passes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );

    let result = cache
        .materialize_blob_indexed_with_signals(
            key,
            payload,
            profitable_materialization_signals(true),
        )
        .expect("indexed materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
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
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_signals_can_skip_without_hashing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"other payload"),
    );

    let result = cache
        .materialize_blob_with_signals(key, b"payload", profitable_materialization_signals(false))
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
fn cache_materialization_signals_append_when_threshold_passes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );

    let result = cache
        .materialize_blob_with_signals(key, payload, profitable_materialization_signals(true))
        .expect("materialization succeeds");

    let PersistMaterialization::Materialized(location) = result else {
        panic!("materialization should append");
    };
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
