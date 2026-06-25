//! Tests for routed blob I/O and materialization decisions on the cache.

use super::*;

#[test]
fn cache_blob_io_is_routed_by_key_store() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"shared payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let value_key = PersistBlobKey::for_value(hash);
    let file_key = PersistBlobKey::for_file(hash);

    let value_location = cache
        .append_blob(value_key, payload)
        .expect("value blob appends");
    let file_location = cache
        .append_blob(file_key, payload)
        .expect("file blob appends");

    assert_eq!(
        value_location.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        file_location.record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        cache
            .read_blob(value_key, value_location)
            .expect("value blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(
        cache
            .read_blob(file_key, file_location)
            .expect("file blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_io_updates_index_and_reads_by_key() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"indexed payload";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let same_hash_file_key = PersistBlobKey::for_file(key.hash());

    let entry = cache
        .append_blob_indexed(key, payload)
        .expect("indexed blob appends");

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
    assert_eq!(
        cache
            .read_blob_indexed(same_hash_file_key)
            .expect("other store lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexed_read_returns_none_on_miss() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"missing"));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

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
        DurableBlake3Hash::for_bytes(b"serialized IR artifact"),
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
fn cache_node_metadata_index_records_and_looks_up_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
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
fn cache_node_materialization_reuse_records_and_looks_up_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let other_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"other input"));
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
fn cache_node_current_demand_updates_latest_reuse_counters() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));

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
fn cache_node_materialization_reuse_advances_run_boundaries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"input"));
    let missing =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing input"));

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
        fs::metadata(cache.node_metadata_index().path())
            .expect("node metadata index metadata")
            .len(),
        (PERSIST_NODE_METADATA_INDEX_ENTRY_LEN * 2) as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_materialization_decision_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

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
fn cache_indexed_materialization_decision_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

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
fn cache_materialization_decision_propagates_append_errors() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"other payload"));

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
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));

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
