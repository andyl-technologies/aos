//! File blob repack and liveness-planning tests.

use super::*;

#[test]
fn cache_file_blob_pack_repack_relocates_artifacts_and_rewrites_sidecars() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted file prefix";
    let prefix_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(prefix_payload));
    cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted file prefix appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_payload = b"durable file artifact";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    let file_old_value = file_entry.value();
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
        .expect("parse artifact materializes");
    let parse_entry = parse_materialized
        .index_entry()
        .expect("parse artifact should materialize");
    let parse_artifact_key = parse_entry.key();
    let parse_old_value = parse_entry.value();
    cache
        .record_parse_artifact(parse_entry)
        .expect("parse artifact mapping records");
    let indexed_payload = b"indexed file blob";
    let indexed_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(indexed_payload));
    let indexed_old_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed file blob appends");
    let tail_payload = b"unrooted file tail";
    let tail_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted file tail appends");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before repack")
        .len();

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .repack_file_blob_pack()
        .expect("file blob pack repacks");
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 8);

    assert!(plan.reclaimable_bytes() > 0);
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after repack")
            .len(),
        plan.bytes_after()
    );
    assert_eq!(
        plan.record_relocations()
            .iter()
            .map(|relocation| relocation.old_location())
            .collect::<Vec<_>>(),
        vec![
            file_old_value.location(),
            parse_old_value.location(),
            indexed_old_entry.location()
        ]
    );
    let file_new_location = plan.record_relocations()[0].new_location();
    let parse_new_location = plan.record_relocations()[1].new_location();
    let indexed_new_location = plan.record_relocations()[2].new_location();
    assert_ne!(file_old_value.location(), file_new_location);
    assert_ne!(parse_old_value.location(), parse_new_location);
    assert_ne!(indexed_old_entry.location(), indexed_new_location);
    assert!(
        cache.read_file_artifact(file_old_value).is_err(),
        "stale pre-repack file-artifact location should not verify after relocation"
    );
    assert!(
        cache.read_parse_artifact(parse_old_value).is_err(),
        "stale pre-repack parse-artifact location should not verify after relocation"
    );
    assert!(
        cache
            .read_blob(indexed_key, indexed_old_entry.location())
            .is_err(),
        "stale pre-repack indexed file-blob location should not verify after relocation"
    );
    assert_eq!(
        cache
            .lookup_file_artifact(file_artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(PersistFileArtifactIndexValue::new(
            file_old_value.blob_hash(),
            file_new_location,
        ))
    );
    assert_eq!(
        cache
            .lookup_parse_artifact(parse_artifact_key)
            .expect("parse artifact lookup succeeds"),
        Some(PersistParseArtifactIndexValue::new(
            parse_old_value.blob_hash(),
            parse_new_location,
        ))
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_old_value.blob_key())
            .expect("file blob index lookup succeeds"),
        Some(file_new_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(parse_old_value.blob_key())
            .expect("parse blob index lookup succeeds"),
        Some(parse_new_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(indexed_key)
            .expect("indexed file blob lookup succeeds"),
        Some(indexed_new_location)
    );
    assert_eq!(
        cache
            .read_file_artifact(PersistFileArtifactIndexValue::new(
                file_old_value.blob_hash(),
                file_new_location,
            ))
            .expect("relocated file artifact reads")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_parse_artifact(PersistParseArtifactIndexValue::new(
                parse_old_value.blob_hash(),
                parse_new_location,
            ))
            .expect("relocated parse artifact reads")
            .as_slice(),
        parse_payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(indexed_key)
            .expect("indexed file blob reads")
            .expect("indexed file blob exists")
            .as_slice(),
        indexed_payload
    );
    assert!(cache.read_blob(tail_key, tail_location).is_err());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_repack_rejects_pending_artifact_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            b"pending file artifact",
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");

    let error = cache
        .repack_file_blob_pack()
        .expect_err("pending roots block file repack");

    assert!(matches!(
        error,
        PersistFileBlobPackRepackError::PendingArtifactRoots { roots: 1 }
    ));
    cache
        .record_file_artifact(
            materialized
                .index_entry()
                .expect("pending file artifact should materialize"),
        )
        .expect("pending file artifact records");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_adapter_repacks_value_and_file_packs() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unrooted_value_payload = b"unrooted value before aggregate repack";
    cache
        .append_blob(
            PersistBlobKey::new(
                PersistBlobStore::Values,
                DurableBlake3Hash::for_bytes(unrooted_value_payload),
            ),
            unrooted_value_payload,
        )
        .expect("unrooted value appends");
    let value_payload = CachedExpressionValue::immediate(Value::int(99)).expect("payload builds");
    let value_hash = value_payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(
            &value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value payload materializes");
    let value_bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before aggregate repack")
        .len();

    let unrooted_file_payload = b"unrooted file before aggregate repack";
    cache
        .append_blob(
            PersistBlobKey::for_file(PersistFileBlobHash::for_payload(unrooted_file_payload)),
            unrooted_file_payload,
        )
        .expect("unrooted file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_payload = b"aggregate file artifact";
    let file_materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let file_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    let file_blob_hash = file_entry.value().blob_hash();
    cache
        .record_file_artifact(file_entry)
        .expect("file artifact mapping records");
    let file_bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before aggregate repack")
        .len();

    let repack = cache.repack_blob_packs().expect("both blob packs repack");

    assert!(repack.value_blob_pack().reclaimable_bytes() > 0);
    assert!(repack.file_blob_pack().reclaimable_bytes() > 0);
    assert_eq!(repack.value_blob_pack().bytes_before(), value_bytes_before);
    assert_eq!(repack.file_blob_pack().bytes_before(), file_bytes_before);
    assert_eq!(
        repack.reclaimed_blob_bytes(),
        repack
            .value_blob_pack()
            .reclaimable_bytes()
            .saturating_add(repack.file_blob_pack().reclaimable_bytes())
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after aggregate repack")
            .len(),
        repack.value_blob_pack().bytes_after()
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after aggregate repack")
            .len(),
        repack.file_blob_pack().bytes_after()
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("value payload loads")
            .expect("value payload exists"),
        value_payload
    );
    let relocated_file_value = cache
        .lookup_file_artifact(file_artifact_key)
        .expect("file artifact lookup succeeds")
        .expect("file artifact exists after repack");
    assert_eq!(relocated_file_value.blob_hash(), file_blob_hash);
    assert_eq!(
        cache
            .read_file_artifact(relocated_file_value)
            .expect("file artifact reads after aggregate repack")
            .as_slice(),
        file_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_adapter_reports_file_pack_error_after_value_repack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unrooted_value_payload = b"unrooted value before aggregate failure";
    cache
        .append_blob(
            PersistBlobKey::new(
                PersistBlobStore::Values,
                DurableBlake3Hash::for_bytes(unrooted_value_payload),
            ),
            unrooted_value_payload,
        )
        .expect("unrooted value appends");
    let value_payload = CachedExpressionValue::immediate(Value::int(100)).expect("payload builds");
    let value_hash = value_payload.value_hash().expect("payload hashes");
    cache
        .materialize_cached_expression_value_indexed(
            &value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value payload materializes");
    let value_bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before aggregate failure")
        .len();

    let source = b"let y = 2; in y";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            b"pending aggregate file artifact",
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");

    let error = cache
        .repack_blob_packs()
        .expect_err("pending file roots block aggregate repack");

    assert!(matches!(
        error,
        PersistBlobPacksRepackError::FileBlobPack {
            source: PersistFileBlobPackRepackError::PendingArtifactRoots { roots: 1 }
        }
    ));
    assert!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after aggregate failure")
            .len()
            < value_bytes_before
    );
    assert_eq!(
        cache
            .load_cached_expression_value_indexed(value_hash)
            .expect("value payload loads")
            .expect("value payload exists"),
        value_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_includes_file_artifact_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted file prefix";
    let prefix_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(prefix_payload));
    let prefix_location = cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"file artifact payload";
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
    let parse_payload = b"parse artifact payload";
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
    let tail_payload = b"unrooted file tail";
    let tail_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(tail_payload));
    let tail_location = cache
        .append_blob(tail_key, tail_payload)
        .expect("unrooted tail appends");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before liveness plan")
        .len();

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("file liveness plan builds");
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 4);

    assert_eq!(
        cache
            .lookup_blob_location(file_entry.value().blob_key())
            .expect("blob index lookup succeeds"),
        None,
        "artifact-only file roots should not require blob-index entries"
    );
    assert_eq!(plan.live_roots().len(), 2);
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::FileArtifactIndex
            && root.location() == file_entry.value().location()
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::ParseArtifactIndex
            && root.location() == parse_entry.value().location()
    }));
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![
            file_entry.value().location(),
            parse_entry.value().location()
        ]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![prefix_location, tail_location]
    );
    let prefix_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + prefix_payload.len() as u64;
    let file_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + file_payload.len() as u64;
    let parse_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + parse_payload.len() as u64;
    let tail_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + tail_payload.len() as u64;
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(plan.rooted_record_bytes(), file_bytes + parse_bytes);
    assert_eq!(plan.unrooted_record_bytes(), prefix_bytes + tail_bytes);
    assert_eq!(plan.tail_reclaimable_bytes(), tail_bytes);
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after liveness plan")
            .len(),
        bytes_before
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
fn cache_blob_pack_liveness_plan_acquires_file_store_advisory_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let guard = cache
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .plan_blob_pack_liveness(PersistBlobStore::Files)
            .map(|plan| plan.live_roots().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("liveness plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "liveness planning should wait while the file store lock is held"
    );
    drop(guard);

    let live_roots = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("liveness plan completes after file store lock release")
        .expect("liveness plan succeeds");
    handle.join().expect("worker joins");
    assert_eq!(live_roots, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_acquires_file_artifact_advisory_lock() {
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
            .plan_blob_pack_liveness(PersistBlobStore::Files)
            .map(|plan| plan.live_roots().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("liveness plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "liveness planning should wait while the file-artifact lock is held"
    );
    drop(guard);

    let live_roots = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("liveness plan completes after file-artifact lock release")
        .expect("liveness plan succeeds");
    handle.join().expect("worker joins");
    assert_eq!(live_roots, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_liveness_plan_acquires_parse_artifact_advisory_lock() {
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
            .plan_blob_pack_liveness(PersistBlobStore::Files)
            .map(|plan| plan.live_roots().len())
            .map_err(|error| error.to_string());
        tx.send(result).expect("liveness plan result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "liveness planning should wait while the parse-artifact lock is held"
    );
    drop(guard);

    let live_roots = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("liveness plan completes after parse-artifact lock release")
        .expect("liveness plan succeeds");
    handle.join().expect("worker joins");
    assert_eq!(live_roots, 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_repack_plan_includes_file_artifact_and_pending_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let prefix_payload = b"unrooted file prefix";
    let prefix_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(prefix_payload));
    let prefix_location = cache
        .append_blob(prefix_key, prefix_payload)
        .expect("unrooted prefix appends");
    let indexed_payload = b"indexed file payload";
    let indexed_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(indexed_payload));
    let indexed_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed file appends");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"file artifact payload";
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
    let pending_parse_payload = b"pending parse artifact payload";
    let pending_parse_materialized = cache
        .materialize_parse_artifact(
            parse_key,
            pending_parse_payload,
            MaterializationDecision::Materialize,
        )
        .expect("pending parse artifact materializes");
    let pending_parse_entry = pending_parse_materialized
        .index_entry()
        .expect("pending parse artifact should materialize");
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before repack plan")
        .len();

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .plan_blob_pack_repack(PersistBlobStore::Files)
        .expect("file repack plan builds");
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 5);

    let indexed_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + indexed_payload.len() as u64;
    let file_bytes = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + file_payload.len() as u64;
    let pending_parse_bytes =
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + pending_parse_payload.len() as u64;
    let indexed_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64,
        indexed_payload.len() as u64,
    );
    let file_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + indexed_bytes,
        file_payload.len() as u64,
    );
    let pending_parse_new = PersistBlobLocation::new(
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + indexed_bytes + file_bytes,
        pending_parse_payload.len() as u64,
    );
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::BlobIndex
            && root.location() == indexed_entry.location()
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::FileArtifactIndex
            && root.location() == file_entry.value().location()
    }));
    assert!(plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::PendingParseArtifact
            && root.location() == pending_parse_entry.value().location()
    }));
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
            (indexed_key, indexed_entry.location(), indexed_new),
            (
                file_entry.value().blob_key(),
                file_entry.value().location(),
                file_new,
            ),
            (
                pending_parse_entry.value().blob_key(),
                pending_parse_entry.value().location(),
                pending_parse_new,
            ),
        ]
    );
    assert_eq!(
        plan.unrooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![prefix_location]
    );
    assert_eq!(plan.bytes_before(), bytes_before);
    assert_eq!(
        plan.bytes_after(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64 + indexed_bytes + file_bytes + pending_parse_bytes
    );
    assert_eq!(plan.unrooted_record_bytes(), {
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + prefix_payload.len() as u64
    });
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after repack plan")
            .len(),
        bytes_before
    );

    let _ = fs::remove_dir_all(root);
}
