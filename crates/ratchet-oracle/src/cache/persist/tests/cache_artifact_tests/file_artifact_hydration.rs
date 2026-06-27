//! File artifact hydration tests.

use super::*;

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
fn cache_file_artifact_hydration_rejects_malformed_resolved_before_write() {
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
    let malformed_bundle = bundle_with_resolved(&bundle, b"not a resolved artifact".to_vec());
    let payload = malformed_bundle.encode().expect("bundle encodes");
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
        .expect_err("malformed resolved artifact fails hydration");

    assert!(matches!(
        error,
        PersistFileArtifactHydrationError::Validate {
            source: ParseCacheError::DecodeArtifactBundle { message },
        } if message.contains("resolved.bin")
    ));
    assert!(!hydrated.dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_hydration_rejects_malformed_resolved_before_write() {
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
    let malformed_bundle = bundle_with_resolved(&bundle, b"not a resolved artifact".to_vec());
    let payload = malformed_bundle.encode().expect("bundle encodes");
    let materialized = persist
        .materialize_parse_artifact(parsed.key, &payload, MaterializationDecision::Materialize)
        .expect("bundle materializes");
    let Some(index_value) = materialized.index_value() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-parse-entry"));

    let error = persist
        .hydrate_parse_artifact_bundle(index_value, &hydrated)
        .expect_err("malformed resolved artifact fails hydration");

    assert!(matches!(
        error,
        PersistParseArtifactHydrationError::Validate {
            source: ParseCacheError::DecodeArtifactBundle { message },
        } if message.contains("resolved.bin")
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
