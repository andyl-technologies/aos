//! Blob pack scans and blob-index rebuild tests.

use super::*;

#[test]
fn cache_blob_io_is_routed_by_key_store() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"shared payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let value_key = PersistBlobKey::new(PersistBlobStore::Values, hash);
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload));

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
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    assert_eq!(
        cache
            .read_blob(value_key, value_location)
            .expect("value blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    assert_eq!(
        cache
            .read_blob(file_key, file_location)
            .expect("file blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 1);
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
fn cache_blob_pack_index_entries_are_store_typed() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_payload = b"value payload";
    let value_hash = DurableBlake3Hash::for_bytes(value_payload);
    let value_key = PersistBlobKey::new(PersistBlobStore::Values, value_hash);
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");
    let file_payload = b"file payload";
    let file_hash = PersistFileBlobHash::for_payload(file_payload);
    let file_key = PersistBlobKey::for_file(file_hash);
    let file_location = cache
        .append_blob(file_key, file_payload)
        .expect("file blob appends");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let value_entries = cache
        .blob_pack_index_entries(PersistBlobStore::Values)
        .expect("value pack scans");
    assert_eq!(
        value_entries,
        vec![PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let file_entries = cache
        .blob_pack_index_entries(PersistBlobStore::Files)
        .expect("file pack scans");
    assert_eq!(
        file_entries,
        vec![PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_index_entries_rejects_corrupt_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"value payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let location = cache.append_blob(key, payload).expect("value blob appends");
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
        .blob_pack_index_entries(PersistBlobStore::Values)
        .expect_err("corrupt value pack scan errors");

    assert!(matches!(
        error,
        PersistBlobPackError::PayloadHashMismatch { .. }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_latest_blob_pack_index_entries_compacts_physical_duplicates() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    assert!(
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Values)
            .expect("empty value pack scans")
            .is_empty()
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);

    let duplicate_payload = b"duplicate payload";
    let duplicate_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(duplicate_payload),
    );
    let first_duplicate = cache
        .append_blob(duplicate_key, duplicate_payload)
        .expect("first duplicate appends");
    let other_payload = b"other payload";
    let other_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(other_payload),
    );
    let other_location = cache
        .append_blob(other_key, other_payload)
        .expect("other blob appends");
    let latest_duplicate = cache
        .append_blob(duplicate_key, duplicate_payload)
        .expect("latest duplicate appends");

    let mut expected = vec![
        PersistBlobIndexEntry::new(duplicate_key, latest_duplicate),
        PersistBlobIndexEntry::new(other_key, other_location),
    ];
    expected.sort_by_key(|entry| entry.key().index_bytes());

    let latest_entries = cache
        .latest_blob_pack_index_entries(PersistBlobStore::Values)
        .expect("latest value pack entries scan");
    assert_eq!(latest_entries, expected);
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 2);
    let physical_entries = cache
        .blob_pack_index_entries(PersistBlobStore::Values)
        .expect("physical value pack entries scan");
    assert_eq!(
        physical_entries,
        vec![
            PersistBlobIndexEntry::new(duplicate_key, first_duplicate),
            PersistBlobIndexEntry::new(other_key, other_location),
            PersistBlobIndexEntry::new(duplicate_key, latest_duplicate),
        ],
        "physical scan should keep duplicates for repair tools that need them"
    );
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 3);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_latest_blob_pack_index_entries_keep_store_namespaces_separate() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"shared payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let value_key = PersistBlobKey::new(PersistBlobStore::Values, hash);
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload));
    let value_location = cache
        .append_blob(value_key, payload)
        .expect("value blob appends");
    let file_location = cache
        .append_blob(file_key, payload)
        .expect("file blob appends");

    assert_eq!(
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Values)
            .expect("latest value pack entries scan"),
        vec![PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        cache
            .latest_blob_pack_index_entries(PersistBlobStore::Files)
            .expect("latest file pack entries scan"),
        vec![PersistBlobIndexEntry::new(file_key, file_location)]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_reports_missing_stale_and_dangling_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let exact_payload = b"exact indexed payload";
    let exact_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(exact_payload),
    );
    let exact_entry = cache
        .append_blob_indexed(exact_key, exact_payload)
        .expect("exact indexed payload appends");

    let stale_payload = b"stale duplicate payload";
    let stale_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(stale_payload),
    );
    let stale_current = cache
        .append_blob(stale_key, stale_payload)
        .expect("first stale blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(stale_key, stale_current))
        .expect("stale sidecar entry records");
    let stale_planned = cache
        .append_blob(stale_key, stale_payload)
        .expect("latest stale blob appends");

    let missing_payload = b"missing sidecar payload";
    let missing_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(missing_payload),
    );
    let missing_location = cache
        .append_blob(missing_key, missing_payload)
        .expect("missing-index blob appends");

    let dangling_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"dangling"),
    );
    let dangling_entry = PersistBlobIndexEntry::new(dangling_key, PersistBlobLocation::new(999, 8));
    cache
        .value_index()
        .append_entry(dangling_entry)
        .expect("dangling sidecar entry records");

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("rebuild plan builds");
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 1);
    let mut planned = vec![
        exact_entry,
        PersistBlobIndexEntry::new(stale_key, stale_planned),
        PersistBlobIndexEntry::new(missing_key, missing_location),
    ];
    planned.sort_by_key(|entry| entry.key().index_bytes());

    assert!(plan.lookup_repair_needed());
    assert_eq!(plan.planned_entries(), planned.as_slice());
    assert_eq!(
        plan.missing_entries(),
        &[PersistBlobIndexEntry::new(missing_key, missing_location)]
    );
    assert_eq!(
        plan.stale_entries(),
        &[PersistBlobIndexStaleEntry::new(
            PersistBlobIndexEntry::new(stale_key, stale_current),
            PersistBlobIndexEntry::new(stale_key, stale_planned),
        )]
    );
    assert_eq!(plan.dangling_entries(), &[dangling_entry]);
    assert_eq!(
        cache
            .lookup_blob_location(stale_key)
            .expect("stale lookup still succeeds"),
        Some(stale_current),
        "planning should not rewrite the sidecar"
    );
    assert_eq!(
        cache
            .lookup_blob_location(missing_key)
            .expect("missing lookup still succeeds"),
        None,
        "planning should not index unindexed physical records"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_keeps_store_namespaces_separate() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"shared namespace payload";
    let hash = DurableBlake3Hash::for_bytes(payload);
    let value_key = PersistBlobKey::new(PersistBlobStore::Values, hash);
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload));
    let value_entry = cache
        .append_blob_indexed(value_key, payload)
        .expect("value indexed payload appends");
    let file_entry = cache
        .append_blob_indexed(file_key, payload)
        .expect("file indexed payload appends");

    let value_plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("value rebuild plan builds");
    let file_plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Files)
        .expect("file rebuild plan builds");

    assert!(!value_plan.lookup_repair_needed());
    assert_eq!(value_plan.planned_entries(), &[value_entry]);
    assert!(value_plan.missing_entries().is_empty());
    assert!(value_plan.stale_entries().is_empty());
    assert!(value_plan.dangling_entries().is_empty());

    assert!(!file_plan.lookup_repair_needed());
    assert_eq!(file_plan.planned_entries(), &[file_entry]);
    assert!(file_plan.missing_entries().is_empty());
    assert!(file_plan.stale_entries().is_empty());
    assert!(file_plan.dangling_entries().is_empty());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_ignores_duplicate_sidecar_history_for_lookup_repair() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"sidecar duplicate payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let planned_location = cache
        .append_blob(key, payload)
        .expect("planned blob appends");
    let older_location = PersistBlobLocation::new(999, 7);
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, older_location))
        .expect("older sidecar entry records");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, planned_location))
        .expect("newest sidecar entry records");

    let plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("rebuild plan builds");

    assert!(!plan.lookup_repair_needed());
    assert_eq!(
        plan.planned_entries(),
        &[PersistBlobIndexEntry::new(key, planned_location)]
    );
    assert!(plan.missing_entries().is_empty());
    assert!(plan.stale_entries().is_empty());
    assert!(plan.dangling_entries().is_empty());
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * 2) as u64,
        "planning should not canonicalize duplicate sidecar history"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_classifies_wrong_store_sidecar_entry_as_dangling() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"value payload";
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let value_location = cache
        .append_blob(value_key, payload)
        .expect("value blob appends");
    let wrong_store_key =
        PersistBlobKey::for_file(PersistFileBlobHash::for_payload(b"wrong store"));
    let wrong_store_entry =
        PersistBlobIndexEntry::new(wrong_store_key, PersistBlobLocation::new(777, 5));
    cache
        .value_index()
        .append_entry(wrong_store_entry)
        .expect("wrong-store sidecar entry records");

    let plan = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect("rebuild plan builds");

    assert!(plan.lookup_repair_needed());
    assert_eq!(
        plan.planned_entries(),
        &[PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        plan.missing_entries(),
        &[PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert!(plan.stale_entries().is_empty());
    assert_eq!(plan.dangling_entries(), &[wrong_store_entry]);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_rejects_corrupt_pack() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"planned corrupt payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let location = cache.append_blob(key, payload).expect("value blob appends");
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
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect_err("corrupt value pack plan errors");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildPlanError::Pack {
            source: PersistBlobPackError::PayloadHashMismatch { .. },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_plan_rejects_malformed_sidecar() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    fs::write(cache.value_index().path(), [0]).expect("malformed index writes");

    let error = cache
        .plan_blob_index_rebuild(PersistBlobStore::Values)
        .expect_err("malformed value index plan errors");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildPlanError::Index {
            source: PersistBlobIndexError::Format {
                source: PersistPackFormatError::ShortBlobIndexEntry { .. },
                ..
            },
        }
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_repairs_missing_stale_and_dangling_entries() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let exact_payload = b"rebuild exact indexed payload";
    let exact_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(exact_payload),
    );
    let exact_entry = cache
        .append_blob_indexed(exact_key, exact_payload)
        .expect("exact indexed payload appends");

    let stale_payload = b"rebuild stale duplicate payload";
    let stale_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(stale_payload),
    );
    let stale_current = cache
        .append_blob(stale_key, stale_payload)
        .expect("first stale blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(stale_key, stale_current))
        .expect("stale sidecar entry records");
    let stale_planned = cache
        .append_blob(stale_key, stale_payload)
        .expect("latest stale blob appends");

    let missing_payload = b"rebuild missing sidecar payload";
    let missing_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(missing_payload),
    );
    let missing_location = cache
        .append_blob(missing_key, missing_payload)
        .expect("missing-index blob appends");

    let dangling_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(b"rebuild dangling"),
    );
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            dangling_key,
            PersistBlobLocation::new(999, 8),
        ))
        .expect("dangling sidecar entry records");

    let plan = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect("blob index rebuilds");
    let mut planned = vec![
        exact_entry,
        PersistBlobIndexEntry::new(stale_key, stale_planned),
        PersistBlobIndexEntry::new(missing_key, missing_location),
    ];
    planned.sort_by_key(|entry| entry.key().index_bytes());

    assert!(plan.lookup_repair_needed());
    assert_eq!(plan.planned_entries(), planned.as_slice());
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("rebuilt value entries scan"),
        planned
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        (PERSIST_BLOB_INDEX_ENTRY_LEN * planned.len()) as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(stale_key)
            .expect("stale lookup succeeds"),
        Some(stale_planned)
    );
    assert_eq!(
        cache
            .lookup_blob_location(missing_key)
            .expect("missing lookup succeeds"),
        Some(missing_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(dangling_key)
            .expect("dangling lookup succeeds"),
        None
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_canonicalizes_duplicate_sidecar_history() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"rebuild duplicate sidecar payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let planned_location = cache
        .append_blob(key, payload)
        .expect("planned blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(
            key,
            PersistBlobLocation::new(999, 7),
        ))
        .expect("older sidecar entry records");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, planned_location))
        .expect("newest sidecar entry records");

    let plan = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect("blob index rebuilds");

    assert!(!plan.lookup_repair_needed());
    assert_eq!(
        plan.planned_entries(),
        &[PersistBlobIndexEntry::new(key, planned_location)]
    );
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );
    assert_eq!(
        cache
            .lookup_blob_location(key)
            .expect("rebuilt lookup succeeds"),
        Some(planned_location)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_repairs_file_store_sidecar() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"file rebuild payload";
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload));
    let file_location = cache
        .append_blob(file_key, payload)
        .expect("file blob appends");
    let wrong_store_entry = PersistBlobIndexEntry::new(
        PersistBlobKey::new(
            PersistBlobStore::Values,
            DurableBlake3Hash::for_bytes(b"wrong store"),
        ),
        PersistBlobLocation::new(777, 5),
    );
    cache
        .file_index()
        .append_entry(wrong_store_entry)
        .expect("wrong-store file sidecar entry records");

    let plan = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Files)
        .expect("file blob index rebuilds");

    assert!(plan.lookup_repair_needed());
    assert_eq!(
        plan.missing_entries(),
        &[PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(plan.dangling_entries(), &[wrong_store_entry]);
    assert_eq!(
        cache
            .file_index()
            .latest_entries()
            .expect("rebuilt file entries scan"),
        vec![PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_key)
            .expect("file lookup succeeds"),
        Some(file_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(wrong_store_entry.key())
            .expect("wrong store lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_index_rebuild_from_pack_rejects_corrupt_pack_without_rewriting_sidecar() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let indexed_payload = b"surviving indexed payload";
    let indexed_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(indexed_payload),
    );
    let indexed_entry = cache
        .append_blob_indexed(indexed_key, indexed_payload)
        .expect("indexed payload appends");
    let corrupt_payload = b"corrupt rebuild payload";
    let corrupt_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(corrupt_payload),
    );
    let corrupt_location = cache
        .append_blob(corrupt_key, corrupt_payload)
        .expect("corrupt-target blob appends");
    let payload_offset = corrupt_location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.value_pack().path())
        .expect("value pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .rebuild_blob_index_from_pack(PersistBlobStore::Values)
        .expect_err("corrupt pack rebuild errors");

    assert!(matches!(
        error,
        PersistBlobIndexRebuildError::Plan {
            source: PersistBlobIndexRebuildPlanError::Pack {
                source: PersistBlobPackError::PayloadHashMismatch { .. },
            },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_index().path())
            .expect("value index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64,
        "failed planning should leave the sidecar unchanged"
    );
    assert_eq!(
        cache
            .value_index()
            .latest_entries()
            .expect("value entries still scan"),
        vec![indexed_entry]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexes_rebuild_from_packs_repairs_value_and_file_sidecars() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_payload = b"all rebuild value payload";
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(value_payload),
    );
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");
    let file_payload = b"all rebuild file payload";
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(file_payload));
    let file_location = cache
        .append_blob(file_key, file_payload)
        .expect("file blob appends");

    let rebuild = cache
        .rebuild_blob_indexes_from_packs()
        .expect("blob indexes rebuild");

    assert!(rebuild.lookup_repair_needed());
    assert_eq!(
        rebuild.value_blob_index().missing_entries(),
        &[PersistBlobIndexEntry::new(value_key, value_location)]
    );
    assert_eq!(
        rebuild.file_blob_index().missing_entries(),
        &[PersistBlobIndexEntry::new(file_key, file_location)]
    );
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value lookup succeeds"),
        Some(value_location)
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_key)
            .expect("file lookup succeeds"),
        Some(file_location)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_indexes_rebuild_from_packs_keeps_value_rebuild_when_file_rebuild_fails() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let value_payload = b"boundary value payload";
    let value_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(value_payload),
    );
    let value_location = cache
        .append_blob(value_key, value_payload)
        .expect("value blob appends");
    let file_payload = b"boundary corrupt file payload";
    let file_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(file_payload));
    let file_location = cache
        .append_blob(file_key, file_payload)
        .expect("file blob appends");
    let file_sentinel_entry = PersistBlobIndexEntry::new(
        PersistBlobKey::new(
            PersistBlobStore::Values,
            DurableBlake3Hash::for_bytes(b"file sentinel"),
        ),
        PersistBlobLocation::new(888, 6),
    );
    cache
        .file_index()
        .append_entry(file_sentinel_entry)
        .expect("file sentinel sidecar entry records");
    let payload_offset = file_location.record_offset() + PERSIST_BLOB_RECORD_HEADER_LEN as u64;
    let mut file = OpenOptions::new()
        .write(true)
        .open(cache.file_pack().path())
        .expect("file pack opens for mutation");
    file.seek(SeekFrom::Start(payload_offset))
        .expect("payload offset seeks");
    file.write_all(b"X").expect("payload corrupts");
    file.flush().expect("payload corruption flushes");

    let error = cache
        .rebuild_blob_indexes_from_packs()
        .expect_err("file rebuild errors");

    assert!(matches!(
        error,
        PersistBlobIndexesRebuildError::FileBlobIndex {
            source: PersistBlobIndexRebuildError::Plan {
                source: PersistBlobIndexRebuildPlanError::Pack {
                    source: PersistBlobPackError::PayloadHashMismatch { .. },
                },
            },
        }
    ));
    assert_eq!(
        cache
            .lookup_blob_location(value_key)
            .expect("value lookup succeeds"),
        Some(value_location),
        "value sidecar rebuild should remain committed after file rebuild failure"
    );
    assert_eq!(
        cache
            .lookup_blob_location(file_key)
            .expect("file lookup succeeds"),
        None,
        "failed file-side planning should not rewrite the file sidecar"
    );
    assert_eq!(
        cache
            .file_index()
            .latest_entries()
            .expect("file sidecar still scans"),
        vec![file_sentinel_entry],
        "failed file-side planning should preserve existing file sidecar entries"
    );

    let _ = fs::remove_dir_all(root);
}
