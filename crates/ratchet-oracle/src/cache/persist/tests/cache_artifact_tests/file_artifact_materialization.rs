//! File artifact materialization tests.

use super::*;

#[test]
fn cache_file_artifact_materialization_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            b"serialized IR artifact",
            MaterializationDecision::KeepInMemory,
        )
        .expect("file artifact skip succeeds");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(result.artifact_key(), artifact_key);
    assert_eq!(result.index_value(), None);
    assert_eq!(result.index_entry(), None);
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_materialization_appends_files_blob_when_requested() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"serialized IR artifact";

    let result = cache
        .materialize_file_artifact(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("file artifact materializes");

    let PersistFileArtifactMaterialization::Materialized {
        artifact_key: actual_key,
        index_value,
    } = result
    else {
        panic!("file artifact should materialize");
    };
    assert_eq!(actual_key, artifact_key);
    assert_eq!(result.artifact_key(), artifact_key);
    assert_eq!(result.index_value(), Some(index_value));
    assert_eq!(
        result.index_entry(),
        Some(PersistFileArtifactIndexEntry::new(
            artifact_key,
            index_value
        ))
    );
    assert_eq!(
        index_value.blob_hash(),
        PersistFileBlobHash::for_payload(payload)
    );
    assert_eq!(
        index_value.location().record_offset(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("file artifact blob reads")
            .as_slice(),
        payload
    );
    assert_eq!(
        fs::metadata(cache.value_pack().path())
            .expect("value pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
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
fn cache_indexed_file_artifact_materialization_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            b"serialized IR artifact",
            MaterializationDecision::KeepInMemory,
        )
        .expect("indexed file artifact skip succeeds");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(
        cache
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file blob index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(cache.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_file_artifact_materialization_updates_blob_and_mapping_indexes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"serialized IR artifact";

    let result = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("indexed file artifact materializes");

    let Some(index_entry) = result.index_entry() else {
        panic!("file artifact should materialize");
    };
    let index_value = index_entry.value();
    assert_eq!(index_entry.key(), artifact_key);
    assert_eq!(
        index_value.blob_hash(),
        PersistFileBlobHash::for_payload(payload)
    );
    assert_eq!(
        cache
            .lookup_blob_location(index_value.blob_key())
            .expect("file blob lookup succeeds"),
        Some(index_value.location())
    );
    assert_eq!(
        cache
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(index_value)
    );
    assert_eq!(
        cache
            .read_blob_indexed(index_value.blob_key())
            .expect("indexed file blob reads")
            .expect("indexed file blob exists")
            .as_slice(),
        payload
    );
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("file artifact reads")
            .as_slice(),
        payload
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file blob index metadata")
            .len(),
        PERSIST_BLOB_INDEX_ENTRY_LEN as u64
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
fn cache_indexed_file_artifact_materialization_reuses_indexed_file_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let payload = b"serialized IR artifact";
    let first = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("first indexed file artifact materializes");
    let Some(first_value) = first.index_value() else {
        panic!("file artifact should materialize");
    };
    let pack_len = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata")
        .len();
    let blob_index_len = fs::metadata(cache.file_index().path())
        .expect("file blob index metadata")
        .len();

    let second = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("second indexed file artifact materializes");

    assert_eq!(second.index_value(), Some(first_value));
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        pack_len
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file blob index metadata")
            .len(),
        blob_index_len
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_materialization_reuses_indexed_file_blob() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let payload = b"serialized parse artifact";
    let first = cache
        .materialize_parse_artifact_indexed(
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("first indexed parse artifact materializes");
    let Some(first_value) = first.index_value() else {
        panic!("parse artifact should materialize");
    };
    let pack_len = fs::metadata(cache.file_pack().path())
        .expect("file pack metadata")
        .len();
    let blob_index_len = fs::metadata(cache.file_index().path())
        .expect("file blob index metadata")
        .len();

    let second = cache
        .materialize_parse_artifact_indexed(
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect("second indexed parse artifact materializes");

    assert_eq!(second.index_value(), Some(first_value));
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        pack_len
    );
    assert_eq!(
        fs::metadata(cache.file_index().path())
            .expect("file blob index metadata")
            .len(),
        blob_index_len
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_materialization_signals_can_skip_without_writing() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = cache
        .materialize_file_artifact_with_signals(
            &file_key,
            parse_key,
            b"serialized IR artifact",
            profitable_materialization_signals(false),
        )
        .expect("file artifact skip succeeds");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(
        fs::metadata(cache.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_materialization_signals_append_when_threshold_passes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let payload = b"serialized IR artifact";

    let result = cache
        .materialize_file_artifact_with_signals(
            &file_key,
            parse_key,
            payload,
            profitable_materialization_signals(true),
        )
        .expect("file artifact materializes");

    let Some(index_value) = result.index_value() else {
        panic!("file artifact should materialize");
    };
    assert_eq!(
        cache
            .read_file_artifact(index_value)
            .expect("file artifact blob reads")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_file_artifact_materialization_signals_append_when_threshold_passes() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let payload = b"serialized IR artifact";

    let result = cache
        .materialize_file_artifact_indexed_with_signals(
            &file_key,
            parse_key,
            payload,
            profitable_materialization_signals(true),
        )
        .expect("indexed file artifact materializes");

    let Some(index_value) = result.index_value() else {
        panic!("file artifact should materialize");
    };
    assert_eq!(
        cache
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(index_value)
    );
    assert_eq!(
        cache
            .read_blob_indexed(index_value.blob_key())
            .expect("indexed file blob reads")
            .expect("indexed file blob exists")
            .as_slice(),
        payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_file_artifact_materialization_reports_mapping_index_errors() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let payload = b"serialized IR artifact";
    let blob_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(payload));
    fs::remove_file(cache.file_artifact_index().path()).expect("index file removes");
    fs::create_dir(cache.file_artifact_index().path()).expect("index path becomes directory");

    let error = cache
        .materialize_file_artifact_indexed(
            &file_key,
            parse_key,
            payload,
            MaterializationDecision::Materialize,
        )
        .expect_err("mapping index write errors");

    assert!(matches!(
        error,
        PersistFileArtifactIndexedWriteError::Index {
            source: PersistFileArtifactIndexError::Open { .. },
        }
    ));
    assert!(
        cache
            .lookup_blob_location(blob_key)
            .expect("file blob index lookup succeeds")
            .is_some()
    );

    let _ = fs::remove_dir_all(root);
}
