//! Parse artifact index hydration tests.

use super::*;

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
fn cache_parse_index_materializes_parse_cache_entry() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parsed.key);

    let materialized = persist
        .materialize_parse_cache_entry_indexed(
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");

    let PersistParseArtifactMaterialization::Materialized {
        artifact_key: actual_key,
        index_value,
    } = materialized
    else {
        panic!("parse artifact should materialize");
    };
    assert_eq!(actual_key, artifact_key);
    assert_eq!(materialized.artifact_key(), artifact_key);
    assert_eq!(materialized.index_value(), Some(index_value));
    assert_eq!(
        materialized.index_entry(),
        Some(PersistParseArtifactIndexEntry::new(
            artifact_key,
            index_value
        ))
    );
    assert_eq!(
        persist
            .lookup_parse_artifact(artifact_key)
            .expect("parse artifact lookup succeeds"),
        Some(index_value)
    );
    assert_eq!(
        persist
            .read_parse_artifact(index_value)
            .expect("parse artifact reads"),
        parsed
            .entry
            .read_artifact_bundle()
            .expect("bundle reads")
            .encode()
            .expect("bundle encodes")
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_index_rejects_entry_that_does_not_match_parse_key() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let other_source = b"let x = 2; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let other = parse_cache
        .load_or_parse_bytes(other_source, Some("other.nix".to_owned()))
        .expect("other source parses");

    let error = persist
        .materialize_parse_cache_entry_indexed(
            parsed.key,
            &other.entry,
            MaterializationDecision::Materialize,
        )
        .expect_err("mismatched entry should not materialize");

    assert!(matches!(
        error,
        PersistParseArtifactMaterializationError::EntryKeyMismatch {
            expected,
            path,
        } if expected == parsed.key && path == other.entry.dir()
    ));
    assert_eq!(
        persist
            .lookup_parse_artifact(PersistParseArtifactKey::from_parse_cache_key(parsed.key))
            .expect("parse artifact lookup succeeds"),
        None
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
fn cache_parse_index_hydrates_normal_parse_cache_entry() {
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
    let materialized = persist
        .materialize_parse_cache_entry_indexed(
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
        .hydrate_parse_cache_entry_from_parse_index(&parse_cache, source)
        .expect("parse-indexed entry hydrates");

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
fn cache_parse_index_load_returns_cached_parse() {
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
    persist
        .materialize_parse_cache_entry_indexed(
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    let loaded = persist
        .load_parse_cache_bytes_from_index(&parse_cache, source)
        .expect("parse-indexed cache loads")
        .expect("indexed parse hit exists");

    assert!(loaded.hit);
    assert!(loaded.stored);
    assert_eq!(loaded.key, parsed.key);
    assert_eq!(loaded.entry, parse_cache.entry_for_source(source));
    assert_eq!(loaded.resolved.arena.nodes(), parsed.resolved.arena.nodes());
    assert_eq!(
        loaded
            .entry
            .read_artifact_bundle()
            .expect("loaded bundle reads"),
        bundle
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_index_misses_when_source_bytes_change() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let changed_source = b"let x = 2; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    persist
        .materialize_parse_cache_entry_indexed(
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    let result = persist
        .hydrate_parse_cache_entry_from_parse_index(&parse_cache, changed_source)
        .expect("parse-indexed miss succeeds");

    assert_eq!(result, None);
    assert!(!parse_cache.entry_for_source(changed_source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_index_load_reports_hydration_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parse_key = parse_cache.key_for_source(source);
    let artifact_key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let stale_value = PersistParseArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    persist
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(
            artifact_key,
            stale_value,
        ))
        .expect("stale mapping records");

    let error = persist
        .load_parse_cache_bytes_from_index(&parse_cache, source)
        .expect_err("stale indexed artifact errors");

    assert!(matches!(
        error,
        PersistParseBytesIndexedLoadError::Hydrate {
            source: PersistParseArtifactIndexedHydrationError::Hydrate {
                source: PersistParseArtifactHydrationError::Read { .. },
            },
        }
    ));
    assert!(!parse_cache.entry_for_source(source).dir().exists());

    let _ = fs::remove_dir_all(root);
}
