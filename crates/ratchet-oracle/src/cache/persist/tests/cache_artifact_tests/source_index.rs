//! Source index hydration tests.

use super::*;

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
fn cache_source_index_load_returns_cached_parse() {
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
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    let loaded = persist
        .load_parse_cache_source_from_index(&parse_cache, realpath, source)
        .expect("source-indexed parse cache loads")
        .expect("indexed source hit exists");

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
fn cache_source_index_load_misses_without_mapping() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let realpath = std::path::Path::new("/src/default.nix");

    let loaded = persist
        .load_parse_cache_source_from_index(&parse_cache, realpath, source)
        .expect("source-indexed miss succeeds");

    assert!(loaded.is_none());
    assert!(!parse_cache.entry_for_source(source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_source_index_load_reports_hydration_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let realpath = std::path::Path::new("/src/default.nix");
    let parse_key = parse_cache.key_for_source(source);
    let file_key = ParseFileKey::for_source(realpath, source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
    let stale_value = PersistFileArtifactIndexValue::new(
        DurableBlake3Hash::for_bytes(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    persist
        .record_file_artifact(PersistFileArtifactIndexEntry::new(
            artifact_key,
            stale_value,
        ))
        .expect("stale mapping records");

    let error = persist
        .load_parse_cache_source_from_index(&parse_cache, realpath, source)
        .expect_err("stale indexed artifact errors");

    assert!(matches!(
        error,
        PersistParseSourceIndexedLoadError::Hydrate {
            source: PersistFileArtifactIndexedHydrationError::Hydrate {
                source: PersistFileArtifactHydrationError::Read { .. },
            },
        }
    ));
    assert!(!parse_cache.entry_for_source(source).dir().exists());

    let _ = fs::remove_dir_all(root);
}
