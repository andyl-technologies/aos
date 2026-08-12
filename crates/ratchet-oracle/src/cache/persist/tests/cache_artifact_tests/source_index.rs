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
fn cache_source_index_borrowed_load_visits_cached_parse_after_hydration() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let other_realpath = std::path::Path::new("/src/other.nix");
    let realpath = std::path::Path::new("/src/default.nix");
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
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
    let artifact_key = expected_entry.key();
    let files_store_lock_path = persist
        .layout()
        .blob_store_lock_path(PersistBlobStore::Files);
    let file_artifact_lock_path = persist.layout().file_artifact_lock_path();
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let visited_key = persist
        .with_parse_cache_source_from_index(&parse_cache, realpath, source, |cached| {
            assert!(cached.hit);
            assert!(cached.stored);
            assert_eq!(cached.key, parsed.key);
            assert_eq!(cached.entry, parse_cache.entry_for_source(source));
            assert_eq!(cached.resolved.arena.nodes(), parsed.resolved.arena.nodes());
            let files_store_guard =
                AdvisoryFileLock::try_lock(&files_store_lock_path, AdvisoryFileLockMode::Exclusive)
                    .expect("source-index visitor runs after the files-store lock is released");
            drop(files_store_guard);
            let file_artifact_guard = AdvisoryFileLock::try_lock(
                &file_artifact_lock_path,
                AdvisoryFileLockMode::Exclusive,
            )
            .expect("source-index visitor runs after the file-artifact lock is released");
            drop(file_artifact_guard);
            assert_eq!(
                persist
                    .lookup_file_artifact(artifact_key)
                    .expect("file-artifact lookup re-enters from visitor"),
                Some(expected_entry.value())
            );
            cached.key
        })
        .expect("borrowed source-indexed cache load succeeds")
        .expect("indexed source hit exists");

    assert_eq!(visited_key, parsed.key);
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "borrowed source-indexed loads should hydrate through the scoped mapped files pack"
    );
    assert_eq!(
        persist
            .with_parse_cache_source_from_index(&parse_cache, other_realpath, source, |_| {
                panic!("source-indexed misses must not call visitors")
            })
            .expect("borrowed source-indexed miss succeeds"),
        None
    );
    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_source_index_cross_family_load_round_trips_and_domain_separates() {
    use crate::cache::hashing::CacheHashFamily;
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
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
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");

    // The test process family is the BLAKE3 default, so the artifact was stored
    // under BLAKE3. The cross-family load path re-derives its keys under the
    // family it is told to probe: told BLAKE3 it re-derives the exact keys the
    // store used and hits (proving the re-derivation round-trips against the
    // real persist store); told xxh128 it derives domain-separated keys that
    // cannot collide, so it misses — a foreign-family probe never returns a
    // false hit. Populate-and-read under a single non-default family is the same
    // family-agnostic code with the constant swapped, exercised here by the
    // BLAKE3 round-trip.
    let hit = persist
        .load_parse_cache_source_from_index_for_family(
            &parse_cache,
            realpath,
            source,
            CacheHashFamily::Blake3,
        )
        .expect("same-family cross-family load succeeds")
        .expect("same-family probe hits the stored artifact");
    assert!(hit.hit);
    assert_eq!(hit.key, parsed.key);
    assert_eq!(hit.entry, parse_cache.entry_for_source(source));

    fs::remove_dir_all(parse_cache.entry_for_source(source).dir())
        .expect("parse-cache entry removes before the miss probe");

    let miss = persist
        .load_parse_cache_source_from_index_for_family(
            &parse_cache,
            realpath,
            source,
            CacheHashFamily::Xxh128,
        )
        .expect("foreign-family cross-family load succeeds");
    assert!(
        miss.is_none(),
        "an xxh128 probe must not find a BLAKE3-stored artifact",
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
        PersistFileBlobHash::for_payload(b"missing artifact"),
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
