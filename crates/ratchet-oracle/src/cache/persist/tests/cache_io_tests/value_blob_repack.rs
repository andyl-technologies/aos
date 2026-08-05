//! Value blob repack and stale-index repair tests.

use super::*;

#[test]
fn cache_indexed_materialization_replaces_stale_index_location() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let stale_location = PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0);
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, stale_location))
        .expect("stale index entry appends");

    let result = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization repairs stale location");
    let PersistMaterialization::Materialized(fresh_location) = result else {
        panic!("materialization should append fresh bytes");
    };

    assert_ne!(fresh_location, stale_location);
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(fresh_location)
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
fn cache_indexed_materialization_repairs_wrong_record_pointer_before_compaction() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let other_payload = b"other payload";
    let other_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(other_payload),
    );
    let stale_location = cache
        .append_blob(other_key, other_payload)
        .expect("other blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, stale_location))
        .expect("wrong-record index entry appends");

    let stale_read = cache
        .read_blob_indexed(key)
        .expect_err("wrong-record pointer does not verify for key");
    assert!(matches!(
        stale_read,
        PersistBlobIndexedReadError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));

    let result = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization repairs wrong-record pointer");
    let PersistMaterialization::Materialized(fresh_location) = result else {
        panic!("materialization should append fresh bytes");
    };

    assert_ne!(fresh_location, stale_location);
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("indexed lookup succeeds"),
        Some(fresh_location)
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
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    let pack_len_after_repair = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata")
        .len();
    assert_eq!(
        cache
            .read_blob(other_key, stale_location)
            .expect("stale pack record remains readable before compaction")
            .as_slice(),
        other_payload
    );

    assert_eq!(
        cache
            .compact_blob_index(PersistBlobStore::Values)
            .expect("value index compacts"),
        1
    );

    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        pack_len_after_repair
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("compacted lookup succeeds"),
        Some(fresh_location)
    );
    assert_eq!(
        cache
            .read_blob(other_key, stale_location)
            .expect("unreferenced pack record remains readable")
            .as_slice(),
        other_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_acquires_value_store_advisory_lock() {
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
            .plan_blob_pack_liveness(PersistBlobStore::Values)
            .map(|plan| plan.live_roots().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("liveness plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Values));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "liveness planning should wait while the value store lock is held"
    );
    drop(guard);

    let live_roots = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("liveness plan completes after value store lock release")
        .expect("liveness plan succeeds");
    handle.join().expect("worker joins");
    assert_eq!(live_roots, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_classifies_value_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let duplicate_payload = b"duplicate live payload";
    let duplicate_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(duplicate_payload),
    );
    let stale_duplicate_location = cache
        .append_blob(duplicate_key, duplicate_payload)
        .expect("stale duplicate appends");
    let live_duplicate_entry = cache
        .append_blob_indexed(duplicate_key, duplicate_payload)
        .expect("live duplicate appends and indexes");
    let live_payload = b"later live payload";
    let live_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(live_payload),
    );
    let live_entry = cache
        .append_blob_indexed(live_key, live_payload)
        .expect("later live blob appends and indexes");
    let tail_payload = b"unrooted tail payload";
    let tail_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(tail_payload),
    );
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before liveness plan")
        .len();

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .plan_blob_pack_liveness(PersistBlobStore::Values)
        .expect("value liveness plan builds");
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 4);

    assert_eq!(plan.live_roots().len(), 2);
    assert!(plan.live_roots().iter().all(|root| {
        root.source() == PersistBlobLiveRootSource::BlobIndex
            && root.key().store() == PersistBlobStore::Values
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.key() == duplicate_key && root.location() == live_duplicate_entry.location()
    }));
    assert!(
        plan.live_roots()
            .iter()
            .any(|root| root.key() == live_key && root.location() == live_entry.location())
    );
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![live_duplicate_entry.location(), live_entry.location()]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![stale_duplicate_location, tail_location]
    );
    let duplicate_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + duplicate_payload.len() as u64;
    let live_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + live_payload.len() as u64;
    let tail_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + tail_payload.len() as u64;
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.rooted_record_bytes(), duplicate_bytes + live_bytes);
    assert_eq!(plan.unrooted_record_bytes(), duplicate_bytes + tail_bytes);
    assert_eq!(plan.tail_reclaimable_bytes(), tail_bytes);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after liveness plan")
            .len(),
        bytes_before
    );
    assert_eq!(
        cache
            .read_blob(tail_key, tail_location)
            .expect("liveness planning does not trim tail")
            .as_slice(),
        tail_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_plan_maps_value_live_records_to_compacted_offsets() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted value prefix";
    let prefix_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(prefix_payload),
    );
    let prefix_location = cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let first_payload = b"first live value";
    let first_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(first_payload),
    );
    let first_entry = cache
        .append_blob_indexed(first_key, first_payload)
        .expect("first live value appends and indexes");
    let middle_payload = b"unrooted value middle";
    let middle_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(middle_payload),
    );
    let middle_location = cache
        .append_blob(middle_key, middle_payload)
        .expect("unrooted middle appends");
    let second_payload = b"second live value";
    let second_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(second_payload),
    );
    let second_entry = cache
        .append_blob_indexed(second_key, second_payload)
        .expect("second live value appends and indexes");
    let tail_payload = b"unrooted value tail";
    let tail_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(tail_payload),
    );
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before repack plan")
        .len();

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 4);

    let first_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + first_payload.len() as u64;
    let second_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + second_payload.len() as u64;
    let first_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64,
        first_payload.len() as u64,
    );
    let second_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + first_bytes,
        second_payload.len() as u64,
    );
    assert_eq!(plan.live_roots().len(), 2);
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| {
                (
                    relocation.key(),
                    relocation.old_location(),
                    relocation.new_location(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (first_key, first_entry.location(), first_new),
            (second_key, second_entry.location(), second_new),
        ]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![prefix_location, middle_location, tail_location]
    );
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        plan.bytes_after(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + first_bytes + second_bytes
    );
    assert_eq!(plan.rooted_record_bytes(), first_bytes + second_bytes);
    assert_eq!(
        plan.unrooted_record_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + prefix_payload.len() as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + middle_payload.len() as u64
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + tail_payload.len() as u64
    );
    assert_eq!(
        plan.reclaimable_bytes(),
        plan.bytes_before().saturating_sub(plan.bytes_after())
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after repack plan")
            .len(),
        bytes_before
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_relocates_live_values_and_rewrites_index() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted value prefix";
    let prefix_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(prefix_payload),
    );
    cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let node_key = test_impure_input_node_key(b"node");
    let node_payload = CachedExpressionValue::immediate(Value::int(42)).expect("payload builds");
    let node_value_hash = node_payload.value_hash().expect("payload hashes");
    let node_materialized = cache
        .materialize_cached_expression_node_value_indexed(
            node_key,
            &node_payload,
            MaterializationDecision::Materialize,
        )
        .expect("node value materializes");
    let PersistMaterialization::Materialized(node_old_location) = node_materialized else {
        panic!("node value should materialize");
    };
    let middle_payload = b"unrooted value middle";
    let middle_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(middle_payload),
    );
    cache
        .append_blob(middle_key, middle_payload)
        .expect("unrooted middle appends");
    let indexed_payload =
        CachedExpressionValue::immediate(Value::int(7)).expect("indexed payload builds");
    let indexed_value_hash = indexed_payload
        .value_hash()
        .expect("indexed payload hashes");
    let indexed_materialized = cache
        .materialize_cached_expression_value_indexed(
            &indexed_payload,
            MaterializationDecision::Materialize,
        )
        .expect("indexed value materializes");
    let PersistMaterialization::Materialized(indexed_old_location) = indexed_materialized else {
        panic!("indexed value should materialize");
    };
    let tail_payload = b"unrooted value tail";
    let tail_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(tail_payload),
    );
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before repack")
        .len();

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .repack_value_blob_pack()
        .expect("value blob pack repacks");
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 6);

    assert!(plan.reclaimable_bytes() > 0);
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after repack")
            .len(),
        plan.bytes_after()
    );
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| relocation.old_location())
            .collect::<Vec<_>>(),
        vec![node_old_location, indexed_old_location]
    );
    let node_new_location = plan.record_relocations()[0].new_location();
    let indexed_new_location = plan.record_relocations()[1].new_location();
    assert_ne!(node_old_location, node_new_location);
    assert_ne!(indexed_old_location, indexed_new_location);
    assert!(
        cache
            .read_blob(
                PersistBlobKey::for_value(node_value_hash),
                node_old_location,
            )
            .is_err(),
        "stale pre-repack node-value location should not verify after relocation"
    );
    assert!(
        cache
            .read_blob(
                PersistBlobKey::for_value(indexed_value_hash),
                indexed_old_location,
            )
            .is_err(),
        "stale pre-repack indexed-value location should not verify after relocation"
    );
    assert_eq!(
        cache
            .lookup_blob_location(PersistBlobKey::for_value(node_value_hash))
            .expect("node value index lookup succeeds"),
        Some(node_new_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(PersistBlobKey::for_value(indexed_value_hash))
            .expect("indexed value lookup succeeds"),
        Some(indexed_new_location)
    );
    assert_eq!(
        cache
            .load_cached_expression_node_value_indexed(node_key)
            .expect("node value load succeeds")
            .expect("node value exists"),
        node_payload
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(indexed_value_hash)
            .expect("indexed value load succeeds")
            .expect("indexed value exists"),
        indexed_payload
    );
    assert!(cache.read_blob(tail_key, tail_location).is_err());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_raw_repack_copy_uses_mapped_reads() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_payload = b"raw mapped copy first live value";
    let first_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(first_payload),
    );
    cache
        .append_blob_indexed(first_key, first_payload)
        .expect("first indexed value appends");
    let second_payload = b"raw mapped copy second live value";
    let second_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(second_payload),
    );
    cache
        .append_blob_indexed(second_key, second_payload)
        .expect("second indexed value appends");
    let unrooted_payload = b"raw mapped copy unrooted value";
    let unrooted_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(unrooted_payload),
    );
    cache
        .append_blob(unrooted_key, unrooted_payload)
        .expect("unrooted value appends");

    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    assert_eq!(plan.record_relocations().len(), 2);
    assert_eq!(plan.unrooted_records().len(), 1);
    let mapped_reads_after_plan = cache.value_pack().mapped_read_count_for_tests();
    let tmp_pack_path = cache
        .value_pack()
        .path()
        .with_extension("raw-repack-mapped.tmp");

    let staged_pack = cache
        .value_pack()
        .write_relocated_records_to(&tmp_pack_path, plan.record_relocations())
        .expect("raw relocated copy writes staged pack");

    assert_eq!(
        cache.value_pack().mapped_read_count_for_tests(),
        mapped_reads_after_plan + plan.record_relocations().len()
    );
    for relocation in plan.record_relocations() {
        let key = relocation.key();
        let payload = staged_pack
            .read_blob(relocation.new_location(), key.hash())
            .expect("relocated payload reads from staged pack");
        match key {
            _ if key == first_key => assert_eq!(payload, first_payload),
            _ if key == second_key => assert_eq!(payload, second_payload),
            _ => panic!("unexpected relocated key: {key:?}"),
        }
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_raw_repack_copy_removes_stage_pack_on_corrupt_source() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"raw unrooted value prefix";
    let prefix_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(prefix_payload),
    );
    cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let live_payload = b"raw mapped copy corrupt source";
    let live_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(live_payload),
    );
    let live_entry = cache
        .append_blob_indexed(live_key, live_payload)
        .expect("indexed live value appends");
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    let tmp_pack_path = cache
        .value_pack()
        .path()
        .with_extension("raw-repack-corrupt.tmp");
    fs::write(&tmp_pack_path, b"stale temp").expect("stale temp writes");
    let payload_offset =
        live_entry.location().record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .value_pack()
        .write_relocated_records_to(&tmp_pack_path, plan.record_relocations())
        .expect_err("corrupt source blocks raw repack copy");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    assert!(
        !tmp_pack_path.exists(),
        "failed raw repack copy should remove the staged pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_rejects_source_path_as_stage_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"source path as repack stage";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let entry = cache
        .append_blob_indexed(key, payload)
        .expect("indexed value blob appends");
    let location = entry.location();
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    let source_path = cache.value_pack().path().to_path_buf();

    let error = cache
        .value_pack()
        .write_relocated_records_to(source_path.clone(), plan.record_relocations())
        .expect_err("source path as stage pack errors");

    assert!(matches!(
        error,
        PersistBlobPackError::SourceEqualsTemp {
            source_path: actual_source,
            tmp_path,
        } if actual_source == source_path && tmp_path == source_path
    ));
    assert_eq!(
        cache
            .read_blob(key, location)
            .expect("source pack remains readable"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_mapped_copy_rejects_source_path_as_stage_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"mapped source path as repack stage";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let entry = cache
        .append_blob_indexed(key, payload)
        .expect("indexed value blob appends");
    let location = entry.location();
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    let source_path = cache.value_pack().path().to_path_buf();
    // Alias rejection must return before the mapped read lease is inspected.
    let advisory_guard = AdvisoryFileLock::lock(
        cache.layout().locks_dir().join("mapped-alias-unused.lock"),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("unused advisory lock acquires");

    let error = cache
        .value_pack()
        .write_relocated_records_mapped_to(
            &advisory_guard,
            source_path.clone(),
            plan.record_relocations(),
        )
        .expect_err("source path as mapped stage pack errors");

    assert!(matches!(
        error,
        PersistBlobPackError::SourceEqualsTemp {
            source_path: actual_source,
            tmp_path,
        } if actual_source == source_path && tmp_path == source_path
    ));
    assert_eq!(
        cache
            .read_blob(key, location)
            .expect("source pack remains readable"),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_mapped_copy_removes_stage_pack_on_corrupt_source() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted value prefix";
    let prefix_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(prefix_payload),
    );
    cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let live_payload = b"mapped copy corrupt source";
    let live_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(live_payload),
    );
    let live_entry = cache
        .append_blob_indexed(live_key, live_payload)
        .expect("indexed live value appends");
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Values)
        .expect("value repack plan builds");
    let tmp_pack_path = cache
        .value_pack()
        .path()
        .with_extension("mapped-repack-corrupt.tmp");
    fs::write(&tmp_pack_path, b"stale temp").expect("stale temp writes");
    let payload_offset =
        live_entry.location().record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");
    let advisory_guard = AdvisoryFileLock::lock(
        cache
            .layout()
            .blob_store_lock_path(PersistBlobStore::Values),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("value store advisory lock acquires");

    let error = cache
        .value_pack()
        .write_relocated_records_mapped_to(
            &advisory_guard,
            &tmp_pack_path,
            plan.record_relocations(),
        )
        .expect_err("corrupt source blocks mapped repack copy");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));
    assert!(
        !tmp_pack_path.exists(),
        "failed mapped repack copy should remove the staged pack"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_value_blob_pack_repack_reclaims_all_unrooted_values() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let first_payload = b"first unrooted value";
    let first_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(first_payload),
    );
    cache
        .append_blob(first_key, first_payload)
        .expect("first unrooted value appends");
    let second_payload = b"second unrooted value";
    let second_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(second_payload),
    );
    cache
        .append_blob(second_key, second_payload)
        .expect("second unrooted value appends");

    let plan = cache
        .repack_value_blob_pack()
        .expect("unrooted value pack repacks");

    assert!(plan.live_roots().is_empty());
    assert!(plan.record_relocations().is_empty());
    assert_eq!(plan.unrooted_records().len(), 2);
    assert_eq!(plan.bytes_after(), PERSIST_BLOB_PACK_HEADER_LEN as u64);
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after empty repack")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert!(
        cache
            .value_index()
            .latest_entries()
            .expect("value index snapshots")
            .is_empty()
    );

    let _ = fs::remove_dir_all(root);
}
