//! Parse artifact entry materialization tests.

use super::*;

#[test]
fn cache_parse_artifact_entry_materialization_can_skip_missing_entry() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let missing_entry = ParseCacheEntry::new(root.join("missing-entry"));
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = persist
        .materialize_parse_artifact_entry(
            &file_key,
            parse_key,
            &missing_entry,
            MaterializationDecision::KeepInMemory,
        )
        .expect("skip does not read missing entry");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_entry_materialization_appends_bundle_payload() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source("/src/default.nix", source);

    let result = persist
        .materialize_parse_artifact_entry(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");

    let Some(index_value) = result.index_value() else {
        panic!("entry should materialize");
    };
    let payload = persist
        .read_file_artifact(index_value)
        .expect("materialized entry reads");
    let decoded = ParseArtifactBundle::decode(&payload).expect("bundle decodes");
    assert_eq!(decoded, bundle);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_entry_materialization_can_skip_missing_entry() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let missing_entry = ParseCacheEntry::new(root.join("missing-entry"));
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parse_key,
            &missing_entry,
            MaterializationDecision::KeepInMemory,
        )
        .expect("indexed skip does not read missing entry");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(
        persist
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(persist.file_index().path())
            .expect("file blob index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(persist.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_entry_materialization_updates_blob_and_mapping_indexes() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parsed.key);

    let result = persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("indexed entry materializes");

    let Some(index_entry) = result.index_entry() else {
        panic!("entry should materialize");
    };
    let index_value = index_entry.value();
    assert_eq!(index_entry.key(), artifact_key);
    assert_eq!(
        persist
            .lookup_blob_location(index_value.blob_key())
            .expect("file blob lookup succeeds"),
        Some(index_value.location())
    );
    assert_eq!(
        persist
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(index_value)
    );
    let payload = persist
        .read_blob_indexed(index_value.blob_key())
        .expect("indexed file blob reads")
        .expect("indexed file blob exists");
    let decoded = ParseArtifactBundle::decode(&payload).expect("bundle decodes");
    assert_eq!(decoded, bundle);

    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry-indexed"));
    persist
        .hydrate_file_artifact_bundle_from_entry(&file_key, parsed.key, index_entry, &hydrated)
        .expect("indexed entry bundle hydrates");

    assert!(hydrated.is_complete());
    assert_eq!(
        hydrated
            .read_artifact_bundle()
            .expect("hydrated bundle reads"),
        bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_entry_materialization_reports_mapping_index_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let payload = bundle.encode().expect("bundle encodes");
    let blob_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(&payload));
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    fs::remove_file(persist.file_artifact_index().path()).expect("index file removes");
    fs::create_dir(persist.file_artifact_index().path()).expect("index path becomes directory");

    let error = persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect_err("mapping index write errors");

    assert!(matches!(
        error,
        PersistParseArtifactMaterializationError::WriteIndexed {
            source: PersistFileArtifactIndexedWriteError::Index {
                source: PersistFileArtifactIndexError::Open { .. },
            },
        }
    ));
    assert!(
        persist
            .lookup_blob_location(blob_key)
            .expect("file blob index lookup succeeds")
            .is_some()
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_entry_materialization_reports_blob_index_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let payload = bundle.encode().expect("bundle encodes");
    let blob_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(&payload));
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    fs::remove_file(persist.file_index().path()).expect("index file removes");
    fs::create_dir(persist.file_index().path()).expect("index path becomes directory");

    let error = persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect_err("blob index write errors");

    assert!(matches!(
        error,
        PersistParseArtifactMaterializationError::WriteIndexed {
            source: PersistFileArtifactIndexedWriteError::Blob {
                source: PersistBlobIndexedWriteError::Index {
                    source: PersistBlobIndexError::Open { .. },
                },
            },
        }
    ));
    assert_eq!(
        persist
            .lookup_file_artifact(PersistFileArtifactKey::from_parse_file_key(
                &file_key, parsed.key,
            ))
            .expect("file artifact lookup succeeds"),
        None
    );
    assert!(
        persist
            .read_file_artifact(PersistFileArtifactIndexValue::new(
                PersistFileBlobHash::from_durable_hash(blob_key.hash()),
                PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, payload.len() as u64),
            ))
            .expect("unindexed blob remains readable by location")
            .as_slice()
            == payload
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_entry_materialization_signals_can_skip_missing_entry() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let missing_entry = ParseCacheEntry::new(root.join("missing-entry"));
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = persist
        .materialize_parse_artifact_entry_with_signals(
            &file_key,
            parse_key,
            &missing_entry,
            profitable_materialization_signals(false),
        )
        .expect("skip does not read missing entry");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_entry_materialization_signals_can_skip_missing_entry() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let missing_entry = ParseCacheEntry::new(root.join("missing-entry"));
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);

    let result = persist
        .materialize_parse_artifact_entry_indexed_with_signals(
            &file_key,
            parse_key,
            &missing_entry,
            profitable_materialization_signals(false),
        )
        .expect("indexed signal skip does not read missing entry");

    assert_eq!(
        result,
        PersistFileArtifactMaterialization::Skipped { artifact_key }
    );
    assert_eq!(
        persist
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        None
    );
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );
    assert_eq!(
        fs::metadata(persist.file_index().path())
            .expect("file blob index metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(persist.file_artifact_index().path())
            .expect("file artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_indexed_parse_artifact_entry_materialization_signals_append_when_threshold_passes() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parsed.key);

    let result = persist
        .materialize_parse_artifact_entry_indexed_with_signals(
            &file_key,
            parsed.key,
            &parsed.entry,
            profitable_materialization_signals(true),
        )
        .expect("indexed entry materializes");

    let Some(index_value) = result.index_value() else {
        panic!("entry should materialize");
    };
    assert_eq!(
        persist
            .lookup_file_artifact(artifact_key)
            .expect("file artifact lookup succeeds"),
        Some(index_value)
    );
    let payload = persist
        .read_blob_indexed(index_value.blob_key())
        .expect("indexed file blob reads")
        .expect("indexed file blob exists");
    let decoded = ParseArtifactBundle::decode(&payload).expect("bundle decodes");
    assert_eq!(decoded, bundle);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_entry_materialization_signals_append_when_threshold_passes() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source("/src/default.nix", source);

    let result = persist
        .materialize_parse_artifact_entry_with_signals(
            &file_key,
            parsed.key,
            &parsed.entry,
            profitable_materialization_signals(true),
        )
        .expect("entry materializes");

    let Some(index_value) = result.index_value() else {
        panic!("entry should materialize");
    };
    let payload = persist
        .read_file_artifact(index_value)
        .expect("materialized entry reads");
    let decoded = ParseArtifactBundle::decode(&payload).expect("bundle decodes");
    assert_eq!(decoded, bundle);

    let _ = fs::remove_dir_all(root);
}
