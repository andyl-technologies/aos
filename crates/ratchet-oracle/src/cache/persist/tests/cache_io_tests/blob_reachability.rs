//! Value and file blob reachability planning tests.

use super::*;

#[test]
fn cache_value_blob_reachability_plan_classifies_value_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let node_key = PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"node"));
    let missing_node_key =
        PersistNodeMetadataKey::for_impure_input(DurableBlake3Hash::for_bytes(b"missing node"));
    let node_payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let node_value_hash = node_payload.value_hash().expect("payload hashes");
    let node_result = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &node_payload,
            MaterializationDecision::Materialize,
        )
        .expect("node payload materializes");
    let PersistMaterialization::Materialized(node_location) = node_result else {
        panic!("node payload should materialize");
    };
    let indexed_payload = CachedExpressionValue::immediate(Value::int(7)).expect("payload builds");
    let indexed_value_hash = indexed_payload.value_hash().expect("payload hashes");
    let indexed_result = cache
        .materialize_cached_expression_value_indexed(
            &indexed_payload,
            MaterializationDecision::Materialize,
        )
        .expect("indexed payload materializes");
    let PersistMaterialization::Materialized(indexed_location) = indexed_result else {
        panic!("indexed payload should materialize");
    };
    let unindexed_payload = b"unindexed value payload";
    let unindexed_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(unindexed_payload));
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed value appends");
    let missing_value_hash =
        ValueHash::from_canonical_value_hash(DurableBlake3Hash::for_bytes(b"missing value"));
    cache
        .record_node_materialized_value_hash(missing_node_key, missing_value_hash)
        .expect("missing node value metadata records");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before reachability plan")
        .len();

    let plan = cache
        .plan_value_blob_reachability()
        .expect("value reachability plan builds");

    assert!(plan.repair_needed());
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.node_roots().len(), 1);
    assert_eq!(plan.node_roots()[0].node_key(), node_key);
    assert_eq!(plan.node_roots()[0].value_hash(), node_value_hash);
    assert_eq!(plan.node_roots()[0].location(), node_location);
    assert_eq!(plan.missing_node_roots().len(), 1);
    assert_eq!(plan.missing_node_roots()[0].node_key(), missing_node_key);
    assert_eq!(
        plan.missing_node_roots()[0].value_hash(),
        missing_value_hash
    );
    assert_eq!(
        plan.node_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![node_location]
    );
    assert_eq!(
        plan.indexed_unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![indexed_location]
    );
    assert_eq!(
        plan.unindexed_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![unindexed_location]
    );
    assert_eq!(
        plan.node_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + node_location.payload_len()
    );
    assert_eq!(
        plan.indexed_unrooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + indexed_location.payload_len()
    );
    assert_eq!(
        plan.unindexed_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unindexed_location.payload_len()
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(indexed_value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists"),
        indexed_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_rejects_corrupt_unindexed_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"corrupt unindexed value";
    let key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(payload));
    let location = cache
        .append_blob(key, payload)
        .expect("unindexed value appends");
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
        .plan_value_blob_reachability()
        .expect_err("corrupt unindexed value blocks plan");

    assert!(matches!(
        error,
        PersistValueBlobReachabilityPlanError::Pack {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_rejects_mismatched_value_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let actual_payload = b"actual indexed payload";
    let actual_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(actual_payload));
    let actual_location = cache
        .append_blob(actual_key, actual_payload)
        .expect("actual value appends");
    let expected_key =
        PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"expected indexed payload"));
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(expected_key, actual_location))
        .expect("mismatched value index entry appends");

    let error = cache
        .plan_value_blob_reachability()
        .expect_err("mismatched indexed value root blocks plan");

    assert!(matches!(
        error,
        PersistValueBlobReachabilityPlanError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_reachability_plan_rejects_wrong_store_value_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let file_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"file payload"));
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            file_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("wrong-store value index entry appends");

    let error = cache
        .plan_value_blob_reachability()
        .expect_err("wrong-store indexed value root blocks plan");

    assert!(matches!(
        error,
        PersistValueBlobReachabilityPlanError::WrongStoreEntry {
            actual: PersistBlobStore::Files
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_classifies_file_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"durable file artifact";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes without blob index");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let parse_payload = b"durable parse artifact";
    let parse_materialized = cache
        .materialize_parse_artifact(
            parse_key,
            parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("parse artifact materializes without blob index");
    let parse_entry = parse_materialized
        .index_entry()
        .expect("parse artifact should materialize");
    cache
        .record_parse_artifact(parse_entry)
        .expect("parse artifact mapping records");
    let pending_file_source = b"pending file source";
    let pending_file_key = ParseFileKey::for_source("/src/pending-file.nix", pending_file_source);
    let pending_file_parse_key = test_parse_key(pending_file_source);
    let pending_file_payload = b"pending file artifact";
    let pending_file_materialized = cache
        .materialize_file_artifact(
            &pending_file_key,
            pending_file_parse_key,
            pending_file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");
    let pending_file_entry = pending_file_materialized
        .index_entry()
        .expect("pending file artifact should materialize");
    let pending_parse_key = test_parse_key(b"pending parse source");
    let pending_parse_payload = b"pending parse artifact";
    let pending_parse_materialized = cache
        .materialize_parse_artifact(
            pending_parse_key,
            pending_parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("pending parse artifact materializes");
    let pending_parse_entry = pending_parse_materialized
        .index_entry()
        .expect("pending parse artifact should materialize");
    let indexed_payload = b"indexed file blob only";
    let indexed_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(indexed_payload));
    let indexed_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed file blob appends");
    let unindexed_payload = b"unindexed file blob";
    let unindexed_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(unindexed_payload));
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed file blob appends");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before reachability plan")
        .len();

    let plan = cache
        .plan_file_blob_reachability()
        .expect("file reachability plan builds");

    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.file_artifact_roots().len(), 1);
    assert_eq!(
        plan.file_artifact_roots()[0].source(),
        PersistBlobLiveRootSource::FileArtifactIndex
    );
    assert_eq!(
        plan.file_artifact_roots()[0].location(),
        file_entry.value().location()
    );
    assert_eq!(plan.parse_artifact_roots().len(), 1);
    assert_eq!(
        plan.parse_artifact_roots()[0].source(),
        PersistBlobLiveRootSource::ParseArtifactIndex
    );
    assert_eq!(
        plan.parse_artifact_roots()[0].location(),
        parse_entry.value().location()
    );
    assert_eq!(plan.pending_artifact_roots().len(), 2);
    assert!(plan.pending_artifact_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::PendingFileArtifact
            && root.location() == pending_file_entry.value().location()
    }));
    assert!(plan.pending_artifact_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::PendingParseArtifact
            && root.location() == pending_parse_entry.value().location()
    }));
    assert_eq!(plan.blob_index_roots().len(), 1);
    assert_eq!(
        plan.blob_index_roots()[0].location(),
        indexed_entry.location()
    );
    assert_eq!(
        plan.file_artifact_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![file_entry.value().location()]
    );
    assert_eq!(
        plan.parse_artifact_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![parse_entry.value().location()]
    );
    assert_eq!(
        plan.pending_artifact_rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![
            pending_file_entry.value().location(),
            pending_parse_entry.value().location()
        ]
    );
    assert_eq!(
        plan.indexed_unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![indexed_entry.location()]
    );
    assert_eq!(
        plan.unindexed_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![unindexed_location]
    );
    assert_eq!(
        plan.file_artifact_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + file_payload.len() as u64
    );
    assert_eq!(
        plan.parse_artifact_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + parse_payload.len() as u64
    );
    assert_eq!(
        plan.pending_artifact_rooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + pending_file_payload.len() as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + pending_parse_payload.len() as u64
    );
    assert_eq!(
        plan.indexed_unrooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + indexed_payload.len() as u64
    );
    assert_eq!(
        plan.unindexed_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unindexed_payload.len() as u64
    );
    assert_eq!(
        cache
            .read_file_artifact(file_entry.value())
            .expect("file artifact remains readable")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_parse_artifact(parse_entry.value())
            .expect("parse artifact remains readable")
            .as_slice(),
        parse_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_rejects_corrupt_unindexed_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"corrupt unindexed file";
    let key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(payload));
    let location = cache
        .append_blob(key, payload)
        .expect("unindexed file blob appends");
    let payload_offset = location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.file_pack().path())
        .expect("file pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .plan_file_blob_reachability()
        .expect_err("corrupt unindexed file blocks plan");

    assert!(matches!(
        error,
        PersistFileBlobReachabilityPlanError::Pack {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_rejects_mismatched_file_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let actual_payload = b"actual indexed file";
    let actual_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(actual_payload));
    let actual_location = cache
        .append_blob(actual_key, actual_payload)
        .expect("actual file blob appends");
    let expected_key =
        PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(b"expected indexed file"));
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(expected_key, actual_location))
        .expect("mismatched file index entry appends");

    let error = cache
        .plan_file_blob_reachability()
        .expect_err("mismatched indexed file root blocks plan");

    assert!(matches!(
        error,
        PersistFileBlobReachabilityPlanError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_reachability_plan_rejects_wrong_store_file_index_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_key = PersistBlobKey::for_value(DurableBlake3Hash::for_bytes(b"value payload"));
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(
            value_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("wrong-store file index entry appends");

    let error = cache
        .plan_file_blob_reachability()
        .expect_err("wrong-store indexed file root blocks plan");

    assert!(matches!(
        error,
        PersistFileBlobReachabilityPlanError::WrongStoreEntry {
            actual: PersistBlobStore::Values
        }
    ));

    let _ = fs::remove_dir_all(root);
}
