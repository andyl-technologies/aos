//! Tests for file-artifact materialization, hydration, and parse-artifact entries.

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
        DurableBlake3Hash::for_bytes(payload)
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
        DurableBlake3Hash::for_bytes(payload)
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
    let blob_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(payload));
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

#[test]
fn cache_file_artifact_hydrates_parse_entry_from_materialized_bundle() {
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
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let materialized = persist
        .materialize_file_artifact(
            &file_key,
            parsed.key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("bundle materializes");
    let Some(index_value) = materialized.index_value() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));

    persist
        .hydrate_file_artifact_bundle(index_value, &hydrated)
        .expect("bundle hydrates");

    assert!(hydrated.is_complete());
    assert_eq!(
        hydrated
            .read_artifact_bundle()
            .expect("hydrated bundle reads"),
        bundle
    );
    let resolved = hydrated
        .read_resolved()
        .expect("hydrated resolved artifact reads");
    assert_eq!(resolved.arena.nodes(), parsed.resolved.arena.nodes());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydration_validates_bundle_before_write() {
    use crate::cache::parse::{ParseCache, ParseCacheMeta};

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
    let meta = bundle.decode_meta().expect("bundle metadata decodes");
    let wrong_meta = ParseCacheMeta::new(
        meta.schema_version,
        meta.source_hint,
        meta.node_count + 1,
        meta.symbol_count,
    );
    let wrong_bundle = bundle_with_meta(&bundle, wrong_meta);
    let payload = wrong_bundle.encode().expect("bundle encodes");
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let materialized = persist
        .materialize_file_artifact(
            &file_key,
            parsed.key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("bundle materializes");
    let Some(index_value) = materialized.index_value() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry"));

    let error = persist
        .hydrate_file_artifact_bundle(index_value, &hydrated)
        .expect_err("invalid bundle metadata fails hydration");

    assert!(matches!(
        error,
        PersistFileArtifactHydrationError::Validate {
            source: ParseCacheError::DecodeMeta { message },
        } if message.contains("node_count")
    ));
    assert!(!hydrated.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydration_rejects_key_mismatch_before_read() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let expected = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let actual = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let index_value = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    let target = ParseCacheEntry::new(root.join("target-entry"));

    let error = persist
        .hydrate_file_artifact_bundle_for_key(&file_key, parse_key, actual, index_value, &target)
        .expect_err("key mismatch errors before read");

    assert!(matches!(
        error,
        PersistFileArtifactHydrationError::KeyMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } if observed_expected == expected && observed_actual == actual
    ));
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydrates_parse_entry_after_key_match() {
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
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let materialized = persist
        .materialize_file_artifact(
            &file_key,
            parsed.key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("bundle materializes");
    let Some(index_value) = materialized.index_value() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-keyed-entry"));

    persist
        .hydrate_file_artifact_bundle_for_key(
            &file_key,
            parsed.key,
            materialized.artifact_key(),
            index_value,
            &hydrated,
        )
        .expect("keyed bundle hydrates");

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
fn cache_file_artifact_hydration_from_entry_rejects_key_mismatch() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let expected = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let actual = PersistFileArtifactKey::for_realpath_bytes(
        b"/src/other.nix",
        file_key.content_hash(),
        parse_key,
    );
    let index_entry = PersistFileArtifactIndexEntry::new(
        actual,
        PersistFileArtifactIndexValue::new(
            DurableBlake3Hash::for_bytes(b"missing artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ),
    );
    let target = ParseCacheEntry::new(root.join("target-entry"));

    let error = persist
        .hydrate_file_artifact_bundle_from_entry(&file_key, parse_key, index_entry, &target)
        .expect_err("entry key mismatch errors before read");

    assert!(matches!(
        error,
        PersistFileArtifactHydrationError::KeyMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } if observed_expected == expected && observed_actual == actual
    ));
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydrates_parse_entry_from_index_entry() {
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
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let materialized = persist
        .materialize_file_artifact(
            &file_key,
            parsed.key,
            &payload,
            MaterializationDecision::Materialize,
        )
        .expect("bundle materializes");
    let Some(index_entry) = materialized.index_entry() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-entry-record"));

    persist
        .hydrate_file_artifact_bundle_from_entry(&file_key, parsed.key, index_entry, &hydrated)
        .expect("entry bundle hydrates");

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
fn cache_file_artifact_hydration_from_index_misses_without_writing() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let target = ParseCacheEntry::new(root.join("missing-hydration-target"));

    let result = persist
        .hydrate_file_artifact_bundle_from_index(&file_key, parse_key, &target)
        .expect("index miss succeeds");

    assert_eq!(result, None);
    assert!(!target.dir().exists());
    assert_eq!(
        fs::metadata(persist.file_pack().path())
            .expect("file pack metadata")
            .len(),
        PERSIST_BLOB_PACK_HEADER_LEN as u64
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydrates_parse_entry_from_index_lookup() {
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
    let materialized = persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    let expected_entry = materialized
        .index_entry()
        .expect("entry should materialize");
    let hydrated = ParseCacheEntry::new(root.join("hydrated-index-lookup"));

    let result = persist
        .hydrate_file_artifact_bundle_from_index(&file_key, parsed.key, &hydrated)
        .expect("indexed entry hydrates");

    assert_eq!(result, Some(expected_entry));
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
fn cache_source_index_hydrates_normal_parse_cache_entry() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let realpath = std::path::Path::new("/src/default.nix");
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source(realpath, source);
    let materialized = persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    let expected_entry = materialized
        .index_entry()
        .expect("entry should materialize");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    let result = persist
        .hydrate_parse_cache_entry_from_source_index(&parse_cache, realpath, source)
        .expect("source-indexed entry hydrates");

    let hydrated = parse_cache.entry_for_source(source);
    assert_eq!(result, Some(expected_entry));
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
fn cache_source_index_misses_when_source_bytes_change() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let changed_source = b"let x = 2; in x";
    let realpath = std::path::Path::new("/src/default.nix");
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(realpath, source);
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");

    let result = persist
        .hydrate_parse_cache_entry_from_source_index(&parse_cache, realpath, changed_source)
        .expect("source-indexed miss succeeds");

    assert_eq!(result, None);
    assert!(!parse_cache.entry_for_source(changed_source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_source_index_misses_when_realpath_changes() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let realpath = std::path::Path::new("/src/default.nix");
    let other_realpath = std::path::Path::new("/src/other.nix");
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(realpath, source);
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    let result = persist
        .hydrate_parse_cache_entry_from_source_index(&parse_cache, other_realpath, source)
        .expect("source-indexed miss succeeds");

    assert_eq!(result, None);
    assert!(!parse_cache.entry_for_source(source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydration_from_index_reports_lookup_errors() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let target = ParseCacheEntry::new(root.join("lookup-error-target"));
    fs::remove_file(persist.file_artifact_index().path()).expect("index file removes");
    fs::create_dir(persist.file_artifact_index().path()).expect("index path becomes directory");

    let error = persist
        .hydrate_file_artifact_bundle_from_index(&file_key, parse_key, &target)
        .expect_err("lookup errors");

    assert!(matches!(
        error,
        PersistFileArtifactIndexedHydrationError::Lookup {
            source: PersistFileArtifactIndexError::Open { .. },
        }
    ));
    assert!(!target.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_artifact_hydration_from_index_reports_hydration_errors() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let source = b"let x = 1; in x";
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    let parse_key = test_parse_key(source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let stale_value = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    let target = ParseCacheEntry::new(root.join("stale-hydration-target"));
    persist
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            artifact_key,
            stale_value,
        ))
        .expect("stale mapping records");

    let error = persist
        .hydrate_file_artifact_bundle_from_index(&file_key, parse_key, &target)
        .expect_err("stale indexed artifact errors");

    assert!(matches!(
        error,
        PersistFileArtifactIndexedHydrationError::Hydrate {
            source: PersistFileArtifactHydrationError::Read { .. },
        }
    ));
    assert!(!target.dir().exists());

    let _ = fs::remove_dir_all(root);
}

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
    let blob_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(&payload));
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
    let blob_key = PersistBlobKey::for_file(DurableBlake3Hash::for_bytes(&payload));
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
                blob_key.hash(),
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
