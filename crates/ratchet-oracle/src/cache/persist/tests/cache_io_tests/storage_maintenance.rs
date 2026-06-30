//! Storage maintenance and storage repack tests.

use super::*;

#[test]
fn cache_automatic_storage_maintenance_skips_clean_cache() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let policy = PersistStorageMaintenancePolicy::default().with_min_repack_reclaimable_bytes(1);

    let outcome = cache
        .maintain_storage(policy)
        .expect("automatic maintenance runs");

    assert_eq!(outcome.action(), PersistStorageMaintenanceAction::Skip);
    assert_eq!(outcome.plan().policy(), policy);
    assert!(!outcome.plan().blob_index_repair_needed());
    assert_eq!(outcome.plan().repack_reclaimable_bytes(), 0);
    assert!(!outcome.plan().repack_needed());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_automatic_storage_maintenance_repairs_indexes_before_repacking() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"recoverable unindexed value";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    cache
        .append_blob(key, payload)
        .expect("recoverable raw value blob appends");
    let policy = PersistStorageMaintenancePolicy::default().with_min_repack_reclaimable_bytes(1);

    let plan = cache
        .plan_storage_maintenance(policy)
        .expect("automatic maintenance plans");
    assert_eq!(
        plan.action(),
        PersistStorageMaintenanceAction::RepairIndexes
    );
    assert!(plan.blob_index_repair_needed());
    assert!(
        plan.repack_needed(),
        "the raw tail is reclaimable, but repair must win before repack"
    );

    let outcome = cache
        .maintain_storage(policy)
        .expect("automatic maintenance repairs");
    let PersistStorageMaintenanceOutcome::Repaired { plan, maintenance } = outcome else {
        panic!("automatic maintenance should repair the recoverable blob index");
    };
    assert_eq!(
        plan.action(),
        PersistStorageMaintenanceAction::RepairIndexes
    );
    assert!(maintenance.blob_indexes().lookup_repair_needed());
    assert_eq!(maintenance.reclaimed_blob_bytes(), 0);
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("repaired blob is indexed")
            .as_slice(),
        payload
    );

    let second = cache
        .maintain_storage(policy)
        .expect("second automatic maintenance runs");
    assert_eq!(second.action(), PersistStorageMaintenanceAction::Skip);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_automatic_storage_maintenance_repacks_after_reclaim_threshold() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"duplicate indexed value";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    cache
        .append_blob_indexed(key, payload)
        .expect("first value blob appends");
    cache
        .append_blob_indexed(key, payload)
        .expect("duplicate value blob appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before automatic maintenance")
        .len();
    let policy = PersistStorageMaintenancePolicy::default().with_min_repack_reclaimable_bytes(1);

    let plan = cache
        .plan_storage_maintenance(policy)
        .expect("automatic maintenance plans");
    assert_eq!(plan.action(), PersistStorageMaintenanceAction::RepackBlobs);
    assert!(!plan.blob_index_repair_needed());
    assert!(plan.repack_needed());
    assert!(plan.repack_reclaimable_bytes() > 0);

    let outcome = cache
        .maintain_storage(policy)
        .expect("automatic maintenance repacks");
    let PersistStorageMaintenanceOutcome::Repacked {
        plan,
        maintenance,
        repack,
    } = outcome
    else {
        panic!("automatic maintenance should repack duplicate indexed records");
    };
    assert_eq!(plan.action(), PersistStorageMaintenanceAction::RepackBlobs);
    assert!(
        !maintenance.blob_indexes().lookup_repair_needed(),
        "automatic repack still reports its pre-repack repair sweep"
    );
    assert!(repack.reclaimed_blob_bytes() > 0);
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("latest blob remains indexed")
            .as_slice(),
        payload
    );
    let bytes_after = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata after automatic maintenance")
        .len();
    assert!(bytes_after < bytes_before);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_maintenance_compacts_sidecars_rebuilds_indexes_and_trims_tails() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_payload = b"value live payload";
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(value_payload),
    );
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            value_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("stale value blob index entry appends");
    let value_materialized = cache
        .materialize_blob_indexed(
            value_key,
            value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value blob materializes");
    let PersistMaterialization::Materialized(value_location) = value_materialized else {
        panic!("value blob should materialize");
    };
    let value_tail_payload = b"value tail";
    let value_tail_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(value_tail_payload),
    );
    let value_tail_location = cache
        .append_blob(value_tail_key, value_tail_payload)
        .expect("value tail appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_payload = b"file live payload";
    let file_blob_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(file_payload));
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(
            file_blob_key,
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ))
        .expect("stale file blob index entry appends");
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            file_artifact_key,
            PersistFileArtifactIndexValue::new(
                PersistFileBlobHash::for_payload(b"stale file artifact"),
                PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
            ),
        ))
        .expect("stale file artifact entry records");
    let file_materialized = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            file_payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let file_index_entry = file_materialized
        .index_entry()
        .expect("file artifact should materialize");
    let file_index_value = file_index_entry.value();
    let file_tail_payload = b"file tail";
    let file_tail_key =
        PersistBlobKey::for_file(PersistFileBlobHash::for_payload(file_tail_payload));
    let file_tail_location = cache
        .append_blob(file_tail_key, file_tail_payload)
        .expect("file tail appends");
    let value_pack_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before maintenance")
        .len();
    let file_pack_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before maintenance")
        .len();

    let maintenance = cache.compact_storage().expect("storage maintenance runs");

    assert_eq!(maintenance.sidecars().value_blob_index_entries(), 1);
    assert_eq!(maintenance.sidecars().file_blob_index_entries(), 1);
    assert_eq!(maintenance.sidecars().file_artifact_entries(), 1);
    assert_eq!(maintenance.sidecars().parse_artifact_entries(), 0);
    assert_eq!(maintenance.sidecars().node_metadata_entries(), 0);
    assert_eq!(maintenance.sidecars().node_trace_entries(), 0);
    assert_eq!(maintenance.sidecars().total_entries(), 3);
    assert!(maintenance.blob_indexes().lookup_repair_needed());
    assert_eq!(
        maintenance
            .blob_indexes()
            .value_blob_index()
            .missing_entries(),
        &[PersistBlobIndexEntry::new(
            value_tail_key,
            value_tail_location
        )]
    );
    assert_eq!(
        maintenance
            .blob_indexes()
            .file_blob_index()
            .missing_entries(),
        &[PersistBlobIndexEntry::new(
            file_tail_key,
            file_tail_location
        )]
    );
    assert_eq!(
        maintenance.value_blob_pack().bytes_before(),
        value_pack_before
    );
    assert_eq!(maintenance.value_blob_pack().reclaimed_bytes(), 0);
    assert_eq!(
        maintenance.file_blob_pack().bytes_before(),
        file_pack_before
    );
    assert_eq!(maintenance.file_blob_pack().reclaimed_bytes(), 0);
    assert_eq!(
        maintenance.reclaimed_blob_bytes(),
        maintenance.value_blob_pack().reclaimed_bytes()
            + maintenance.file_blob_pack().reclaimed_bytes()
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata after maintenance")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata after maintenance")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata after maintenance")
            .len(),
        PERSIST_FILE_ARTIFACT_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value blob lookup succeeds"),
        Some(value_location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(value_key)
            .expect("indexed value read succeeds")
            .expect("indexed value exists")
            .as_slice(),
        value_payload
    );
    assert_eq!(
        cache
            .read_file_artifact(file_index_value)
            .expect("file artifact remains readable")
            .as_slice(),
        file_payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(value_tail_key)
            .expect("indexed value tail read succeeds")
            .expect("indexed value tail exists")
            .as_slice(),
        value_tail_payload
    );
    assert_eq!(
        cache
            .read_blob_indexed(file_tail_key)
            .expect("indexed file tail read succeeds")
            .expect("indexed file tail exists")
            .as_slice(),
        file_tail_payload
    );

    let value_pack_after = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata after maintenance")
        .len();
    let file_pack_after = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata after maintenance")
        .len();
    let second_maintenance = cache
        .compact_storage()
        .expect("second storage maintenance runs");
    assert!(!second_maintenance.blob_indexes().lookup_repair_needed());
    assert_eq!(
        second_maintenance.value_blob_pack().bytes_before(),
        value_pack_after
    );
    assert_eq!(
        second_maintenance.value_blob_pack().bytes_after(),
        value_pack_after
    );
    assert_eq!(second_maintenance.value_blob_pack().reclaimed_bytes(), 0);
    assert_eq!(
        second_maintenance.file_blob_pack().bytes_before(),
        file_pack_after
    );
    assert_eq!(
        second_maintenance.file_blob_pack().bytes_after(),
        file_pack_after
    );
    assert_eq!(second_maintenance.file_blob_pack().reclaimed_bytes(), 0);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_maintenance_value_rebuild_failure_keeps_sidecar_compaction() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_payload = b"corrupt value payload";
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(value_payload),
    );
    let value_location = cache
        .append_blob_indexed(value_key, value_payload)
        .expect("value blob appends")
        .location();
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_location))
        .expect("duplicate value index entry appends");

    let file_payload = b"file live payload";
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(file_payload));
    let file_location = cache
        .append_blob_indexed(file_key, file_payload)
        .expect("file blob appends")
        .location();
    cache
        .file_index()
        .append_entry(PersistBlobIndexEntry::new(file_key, file_location))
        .expect("duplicate file index entry appends");

    let payload_offset = value_location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");
    let value_pack_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before maintenance")
        .len();
    let file_pack_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before maintenance")
        .len();

    let error = cache
        .compact_storage()
        .expect_err("value rebuild failure aborts storage maintenance");

    assert!(matches!(
        error,
        PersistStorageMaintenanceError::BlobIndexes {
            source: PersistBlobIndexesRebuildError::ValueBlobIndex {
                source: PersistBlobIndexRebuildError::Plan {
                    source: PersistBlobIndexRebuildPlanError::Pack {
                        source: PersistBlobPackError::PayloadHashMismatch { .. },
                    },
                },
            },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata after failed maintenance")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "sidecar compaction should remain committed before value rebuild fails"
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata after failed maintenance")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "later sidecar compactions also run before blob-index rebuilds"
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after failed maintenance")
            .len(),
        value_pack_before,
        "failed value rebuild must not truncate the value pack"
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after failed maintenance")
            .len(),
        file_pack_before,
        "file rebuild and trim should not run after value rebuild fails"
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("compacted value index lookup succeeds"),
        Some(value_location)
    );
    assert_eq!(
        cache
            .read_blob_indexed(file_key)
            .expect("indexed file read succeeds")
            .expect("indexed file remains")
            .as_slice(),
        file_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_maintenance_file_trim_failure_keeps_blob_index_rebuilds() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let value_payload = b"value live payload";
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(value_payload),
    );
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let expected_file_hash = PersistFileBlobHash::for_payload(b"expected file");
    let wrong_file_payload = b"wrong file payload";
    let wrong_file_key =
        PersistBlobKey::for_file(PersistFileBlobHash::for_payload(wrong_file_payload));
    let wrong_file_location = cache
        .append_blob(wrong_file_key, wrong_file_payload)
        .expect("wrong file blob appends");
    cache
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key),
            PersistFileArtifactIndexValue::new(expected_file_hash, wrong_file_location),
        ))
        .expect("wrong file artifact root records");
    let file_pack_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before maintenance")
        .len();

    let error = cache
        .compact_storage()
        .expect_err("file trim failure aborts storage maintenance");

    assert!(matches!(
        error,
        PersistStorageMaintenanceError::FileBlobPack {
            source: PersistBlobPackTrimError::Read {
                source: PersistBlobPackError::RecordHashMismatch { .. },
            },
        }
    ));
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("rebuilt value index lookup succeeds"),
        Some(value_location),
        "value blob-index rebuild should stay committed before file trim fails"
    );
    assert_eq!(
        cache
            .lookup_blob_location(wrong_file_key)
            .expect("rebuilt file index lookup succeeds"),
        Some(wrong_file_location),
        "file blob-index rebuild should stay committed before file trim fails"
    );
    assert_eq!(
        cache
            .read_blob_indexed(value_key)
            .expect("indexed value read succeeds")
            .expect("indexed value remains")
            .as_slice(),
        value_payload
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after failed maintenance")
            .len(),
        file_pack_before,
        "failed file verification must not truncate the file pack"
    );
    assert_eq!(
        cache
            .read_blob(wrong_file_key, wrong_file_location)
            .expect("wrong file record remains after failed trim")
            .as_slice(),
        wrong_file_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_repack_compacts_sidecars_and_repacks_blob_packs() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let unrooted_value_payload = b"unrooted value before storage repack";
    let unrooted_value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(unrooted_value_payload),
    );
    let unrooted_value_location = cache
        .append_blob(unrooted_value_key, unrooted_value_payload)
        .expect("unrooted value appends");
    let value_payload = CachedExpressionValue::immediate(Value::int(101)).expect("payload builds");
    let value_hash = value_payload.value_hash().expect("payload hashes");
    let value_key = PersistBlobKey::for_value(value_hash);
    let value_materialized = cache
        .materialize_cached_expression_value_indexed(
            &value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value payload materializes");
    let PersistMaterialization::Materialized(value_old_location) = value_materialized else {
        panic!("value payload should materialize");
    };
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_old_location))
        .expect("duplicate value index entry appends");

    let unrooted_file_payload = b"unrooted file before storage repack";
    let unrooted_file_key =
        PersistBlobKey::for_file(PersistFileBlobHash::for_payload(unrooted_file_payload));
    let unrooted_file_location = cache
        .append_blob(unrooted_file_key, unrooted_file_payload)
        .expect("unrooted file appends");
    let source = b"let z = 3; in z";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let file_artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let file_payload = b"storage repack file artifact";
    let file_materialized = cache
        .materialize_file_artifact_indexed(
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
    let file_old_location = file_entry.value().location();
    cache
        .record_file_artifact(file_entry)
        .expect("duplicate file artifact mapping records");

    let repack = cache.repack_storage().expect("storage repack runs");

    assert_eq!(repack.sidecars().value_blob_index_entries(), 1);
    assert_eq!(repack.sidecars().file_blob_index_entries(), 1);
    assert_eq!(repack.sidecars().file_artifact_entries(), 1);
    assert_eq!(repack.sidecars().parse_artifact_entries(), 0);
    assert!(repack.blob_packs().value_blob_pack().reclaimable_bytes() > 0);
    assert!(repack.blob_packs().file_blob_pack().reclaimable_bytes() > 0);
    assert_eq!(
        repack.reclaimed_blob_bytes(),
        repack.blob_packs().reclaimed_blob_bytes()
    );
    assert!(
        repack
            .blob_packs()
            .value_blob_pack()
            .record_relocations()
            .iter()
            .any(|relocation| relocation.old_location() == value_old_location)
    );
    assert!(
        repack
            .blob_packs()
            .file_blob_pack()
            .record_relocations()
            .iter()
            .any(|relocation| relocation.old_location() == file_old_location)
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
        .expect("file artifact exists after storage repack");
    assert_eq!(relocated_file_value.blob_hash(), file_blob_hash);
    assert_eq!(
        cache
            .read_file_artifact(relocated_file_value)
            .expect("file artifact reads after storage repack")
            .as_slice(),
        file_payload
    );
    assert!(
        cache
            .read_blob(unrooted_value_key, unrooted_value_location)
            .is_err()
    );
    assert!(
        cache
            .read_blob(unrooted_file_key, unrooted_file_location)
            .is_err()
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after storage repack")
            .len(),
        repack.blob_packs().value_blob_pack().bytes_after()
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata after storage repack")
            .len(),
        repack.blob_packs().file_blob_pack().bytes_after()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_storage_repack_file_failure_keeps_sidecar_compaction_and_value_repack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unrooted_value_payload = b"unrooted value before storage repack failure";
    cache
        .append_blob(
            PersistBlobKey::new(
                PersistBlobStore::Values,
                DurableBlake3Hash::for_bytes(unrooted_value_payload),
            ),
            unrooted_value_payload,
        )
        .expect("unrooted value appends");
    let value_payload = CachedExpressionValue::immediate(Value::int(102)).expect("payload builds");
    let value_hash = value_payload.value_hash().expect("payload hashes");
    let value_key = PersistBlobKey::for_value(value_hash);
    let value_materialized = cache
        .materialize_cached_expression_value_indexed(
            &value_payload,
            MaterializationDecision::Materialize,
        )
        .expect("value payload materializes");
    let PersistMaterialization::Materialized(value_location) = value_materialized else {
        panic!("value payload should materialize");
    };
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(value_key, value_location))
        .expect("duplicate value index entry appends");
    let value_bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before storage repack failure")
        .len();

    let source = b"let pending = true; in pending";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/pending.nix", source);
    cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            b"pending storage repack file artifact",
            MaterializationDecision::Materialize,
        )
        .expect("pending file artifact materializes");

    let error = cache
        .repack_storage()
        .expect_err("pending file roots block storage repack");

    assert!(matches!(
        error,
        PersistStorageRepackError::BlobPacks {
            source: PersistBlobPacksRepackError::FileBlobPack {
                source: PersistFileBlobPackRepackError::PendingArtifactRoots { roots: 1 }
            }
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata after failed storage repack")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "sidecar compaction should remain committed before file repack fails"
    );
    assert!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after failed storage repack")
            .len()
            < value_bytes_before,
        "value pack repack should remain committed before file repack fails"
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
