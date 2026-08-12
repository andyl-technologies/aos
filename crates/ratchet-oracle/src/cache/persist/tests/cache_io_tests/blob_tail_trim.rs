//! Blob pack tail-trim preservation and reclamation tests.

use super::*;

#[test]
fn cache_file_blob_pack_tail_trim_preserves_pending_file_artifact_root() {
    let root = temp_root();
    let writer = PersistCache::open(&root).expect("writer cache opens");
    let maintainer = PersistCache::open(&root).expect("maintainer cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let payload = b"pending file artifact payload";
    let materialized = writer
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    let index_value = index_entry.value();
    let bytes_before = fs::metadata(writer.file_pack().path())
        .expect("file pack metadata before pending trim")
        .len();

    let plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("pending file-artifact liveness plan builds");

    assert_eq!(plan.live_roots().len(), 1);
    assert_eq!(
        plan.live_roots()[0].source(),
        PersistBlobLiveRootSource::PendingFileArtifact
    );
    assert_eq!(plan.live_roots()[0].location(), index_value.location());
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![index_value.location()]
    );
    assert!(plan.unrooted_records().is_empty());
    assert_eq!(plan.tail_reclaimable_bytes(), 0);

    let trim = maintainer
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("pending file-artifact root blocks tail trim");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    writer
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records after trim");
    assert_eq!(
        writer
            .read_file_artifact(index_value)
            .expect("pending file artifact remains readable")
            .as_slice(),
        payload
    );
    let recorded_plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("recorded file-artifact liveness plan builds");
    assert!(recorded_plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::FileArtifactIndex
            && root.location() == index_value.location()
    }));
    assert!(
        !recorded_plan
            .live_roots()
            .iter()
            .any(|root| root.source() == PersistBlobLiveRootSource::PendingFileArtifact)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_blob_pack_tail_trim_preserves_pending_parse_artifact_root() {
    let root = temp_root();
    let writer = PersistCache::open(&root).expect("writer cache opens");
    let maintainer = PersistCache::open(&root).expect("maintainer cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let payload = b"pending parse artifact payload";
    let materialized = writer
        .materialize_parse_artifact(parse_key, payload, MaterializationDecision::Materialize)
        .expect("parse artifact materializes");
    let index_entry = materialized
        .index_entry()
        .expect("parse artifact should materialize");
    let index_value = index_entry.value();
    let bytes_before = fs::metadata(writer.file_pack().path())
        .expect("file pack metadata before pending trim")
        .len();

    let plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("pending parse-artifact liveness plan builds");

    assert_eq!(plan.live_roots().len(), 1);
    assert_eq!(
        plan.live_roots()[0].source(),
        PersistBlobLiveRootSource::PendingParseArtifact
    );
    assert_eq!(plan.live_roots()[0].location(), index_value.location());
    assert_eq!(
        plan.rooted_records()
            .iter()
            .map(|record| record.location())
            .collect::<Vec<_>>(),
        vec![index_value.location()]
    );
    assert!(plan.unrooted_records().is_empty());
    assert_eq!(plan.tail_reclaimable_bytes(), 0);

    let trim = maintainer
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("pending parse-artifact root blocks tail trim");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    writer
        .record_parse_artifact(index_entry)
        .expect("parse artifact mapping records after trim");
    assert_eq!(
        writer
            .read_parse_artifact(index_value)
            .expect("pending parse artifact remains readable")
            .as_slice(),
        payload
    );
    let recorded_plan = maintainer
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("recorded parse-artifact liveness plan builds");
    assert!(recorded_plan.live_roots().iter().any(|root| {
        root.source() == PersistBlobLiveRootSource::ParseArtifactIndex
            && root.location() == index_value.location()
    }));
    assert!(
        !recorded_plan
            .live_roots()
            .iter()
            .any(|root| root.source() == PersistBlobLiveRootSource::PendingParseArtifact)
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_reclaims_unindexed_tail_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"live payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let live = cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization succeeds");
    let PersistMaterialization::Materialized(live_location) = live else {
        panic!("payload should materialize");
    };
    let unindexed_payload = b"unindexed tail payload";
    let unindexed_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(unindexed_payload),
    );
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed tail appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();
    let expected_reclaimed = PERSIST_BLOB_RECORD_HEADER_LEN as u64 + unindexed_payload.len() as u64;

    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 0);
    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect("value pack tail trims");
    assert_eq!(cache.value_pack().mapped_read_count_for_tests(), 3);

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), expected_reclaimed);
    assert_eq!(
        trim.bytes_after(),
        live_location.record_offset()
            + PERSIST_BLOB_RECORD_HEADER_LEN as u64
            + payload.len() as u64
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after trim")
            .len(),
        trim.bytes_after()
    );
    assert_eq!(
        cache
            .read_blob_indexed(key)
            .expect("indexed read succeeds")
            .expect("indexed blob exists")
            .as_slice(),
        payload
    );
    assert!(
        cache.read_blob(unindexed_key, unindexed_location).is_err(),
        "unindexed tail record should be truncated"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_preserves_unindexed_prefix_before_live_record() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let unindexed_payload = b"unindexed prefix payload";
    let unindexed_key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(unindexed_payload),
    );
    let unindexed_location = cache
        .append_blob(unindexed_key, unindexed_payload)
        .expect("unindexed prefix appends");
    let payload = b"live payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    cache
        .materialize_blob_indexed(key, payload, MaterializationDecision::Materialize)
        .expect("indexed materialization succeeds");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect("value pack tail trim no-ops");

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    assert_eq!(
        cache
            .read_blob(unindexed_key, unindexed_location)
            .expect("unindexed prefix remains readable")
            .as_slice(),
        unindexed_payload
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
fn cache_blob_pack_tail_trim_rejects_stale_latest_index_without_truncating() {
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
    let wrong_location = cache
        .append_blob(other_key, other_payload)
        .expect("other blob appends");
    cache
        .value_index()
        .append_entry(PersistBlobIndexEntry::new(key, wrong_location))
        .expect("wrong index entry appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();

    let error = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect_err("stale latest entry blocks tail trim");

    assert!(matches!(
        error,
        PersistBlobPackTrimError::Read {
            source: PersistBlobPackError::RecordHashMismatch { .. },
        }
    ));
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata after failed trim")
            .len(),
        bytes_before
    );
    assert_eq!(
        cache
            .read_blob(other_key, wrong_location)
            .expect("pack record remains after failed trim")
            .as_slice(),
        other_payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_reclaims_empty_root_tail() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload = b"unindexed only payload";
    let key = PersistBlobKey::new(
        PersistBlobStore::Values,
        DurableBlake3Hash::for_bytes(payload),
    );
    let location = cache
        .append_blob(key, payload)
        .expect("unindexed value appends");
    let bytes_before = fs::metadata(cache.value_pack().path())
        .expect("value pack metadata before trim")
        .len();

    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Values)
        .expect("empty-root tail trims");

    assert_eq!(trim.live_entries(), 0);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), PERSIST_BLOB_PACK_HEADER_LEN as u64);
    assert_eq!(
        trim.reclaimed_bytes(),
        PERSIST_BLOB_RECORD_HEADER_LEN as u64 + payload.len() as u64
    );
    assert!(
        cache.read_blob(key, location).is_err(),
        "unindexed value tail should be truncated"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_preserves_file_artifact_index_tail_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let payload = b"file artifact payload";
    let materialized = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes without blob index");
    let index_entry = materialized
        .index_entry()
        .expect("file artifact should materialize");
    let index_value = index_entry.value();
    cache
        .record_file_artifact(index_entry)
        .expect("file artifact mapping records");
    assert_eq!(
        cache
            .lookup_blob_location(index_value.blob_key())
            .expect("blob index lookup succeeds"),
        None,
        "non-indexed artifact materialization should not write blob index roots"
    );
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before trim")
        .len();

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("file pack tail trim preserves artifact root");
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 3);

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("artifact-only file root remains readable")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_blob_pack_tail_trim_preserves_parse_artifact_index_tail_root() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let payload = b"parse artifact payload";
    let materialized = cache
        .materialize_parse_artifact(parse_key, payload, MaterializationDecision::Materialize)
        .expect("parse artifact materializes without blob index");
    let index_entry = materialized
        .index_entry()
        .expect("parse artifact should materialize");
    let index_value = index_entry.value();
    cache
        .record_parse_artifact(index_entry)
        .expect("parse artifact mapping records");
    assert_eq!(
        cache
            .lookup_blob_location(index_value.blob_key())
            .expect("blob index lookup succeeds"),
        None,
        "non-indexed artifact materialization should not write blob index roots"
    );
    let bytes_before = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata before trim")
        .len();

    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 0);
    let trim = cache
        .trim_blob_pack_tail(PersistBlobStore::Files)
        .expect("file pack tail trim preserves parse artifact root");
    assert_eq!(cache.file_pack().mapped_read_count_for_tests(), 3);

    assert_eq!(trim.live_entries(), 1);
    assert_eq!(trim.bytes_before(), bytes_before);
    assert_eq!(trim.bytes_after(), bytes_before);
    assert_eq!(trim.reclaimed_bytes(), 0);
    assert_eq!(
        cache
            .read_parse_artifact(index_value)
            .expect("artifact-only parse root remains readable")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}
