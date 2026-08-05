//! File index hydration tests.

use super::*;

#[test]
fn cache_file_index_hydrates_normal_parse_cache_entry_from_requested_path() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    fs::write(&source_path, source).expect("source writes");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source(&realpath, source);
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
        .hydrate_parse_cache_entry_from_file_index(&parse_cache, &source_path)
        .expect("file-indexed entry hydrates");

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

#[cfg(unix)]
#[test]
fn cache_file_index_hydration_canonicalizes_requested_path() {
    use crate::cache::parse::ParseCache;
    use std::os::unix::fs::symlink;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let link_path = src_dir.join("linked-expr.nix");
    let source = b"let x = 1; in x";
    fs::write(&source_path, source).expect("source writes");
    symlink(&source_path, &link_path).expect("symlink creates");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(&realpath, source);
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
        .hydrate_parse_cache_entry_from_file_index(&parse_cache, &link_path)
        .expect("file-indexed symlink entry hydrates");

    assert_eq!(result, Some(expected_entry));
    assert!(parse_cache.entry_for_source(source).is_complete());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_misses_when_file_content_changes() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    let changed_source = b"let x = 2; in x";
    fs::write(&source_path, source).expect("source writes");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(&realpath, source);
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");
    fs::write(&source_path, changed_source).expect("changed source writes");

    let result = persist
        .hydrate_parse_cache_entry_from_file_index(&parse_cache, &source_path)
        .expect("file-indexed miss succeeds");

    assert_eq!(result, None);
    assert!(!parse_cache.entry_for_source(source).dir().exists());
    assert!(!parse_cache.entry_for_source(changed_source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_hydration_reports_source_prep_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let missing_path = root.join("missing.nix");

    let error = persist
        .hydrate_parse_cache_entry_from_file_index(&parse_cache, &missing_path)
        .expect_err("missing source errors");

    assert!(matches!(
        error,
        PersistParseFileIndexedHydrationError::CanonicalizeSource { path, .. }
            if path == missing_path
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_hydration_reports_read_source_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source_path = root.join("source-directory.nix");
    fs::create_dir(&source_path).expect("source directory creates");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");

    let error = persist
        .hydrate_parse_cache_entry_from_file_index(&parse_cache, &realpath)
        .expect_err("removed source read errors");

    assert!(matches!(
        error,
        PersistParseFileIndexedHydrationError::ReadSource { path, .. } if path == realpath
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_load_returns_cached_parse_from_requested_path() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    fs::write(&source_path, source).expect("source writes");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let bundle = parsed
        .entry
        .read_artifact_bundle()
        .expect("artifact bundle reads");
    let file_key = ParseFileKey::for_source(&realpath, source);
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
        .load_parse_cache_file_from_index(&parse_cache, &source_path)
        .expect("file-indexed parse cache loads")
        .expect("indexed file hit exists");

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
fn cache_file_index_borrowed_load_visits_cached_parse_after_hydration() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    let changed_source = b"let x = 2; in x";
    fs::write(&source_path, source).expect("source writes");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(&realpath, source);
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
        .with_parse_cache_file_from_index(&parse_cache, &source_path, |cached| {
            assert!(cached.hit);
            assert!(cached.stored);
            assert_eq!(cached.key, parsed.key);
            assert_eq!(cached.entry, parse_cache.entry_for_source(source));
            assert_eq!(cached.resolved.arena.nodes(), parsed.resolved.arena.nodes());
            let files_store_guard =
                AdvisoryFileLock::try_lock(&files_store_lock_path, AdvisoryFileLockMode::Exclusive)
                    .expect("file-index visitor runs after the files-store lock is released");
            drop(files_store_guard);
            let file_artifact_guard = AdvisoryFileLock::try_lock(
                &file_artifact_lock_path,
                AdvisoryFileLockMode::Exclusive,
            )
            .expect("file-index visitor runs after the file-artifact lock is released");
            drop(file_artifact_guard);
            assert_eq!(
                persist
                    .lookup_file_artifact(artifact_key)
                    .expect("file-artifact lookup re-enters from visitor"),
                Some(expected_entry.value())
            );
            cached.key
        })
        .expect("borrowed file-indexed cache load succeeds")
        .expect("indexed file hit exists");

    assert_eq!(visited_key, parsed.key);
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "borrowed file-indexed loads should hydrate through the scoped mapped files pack"
    );
    fs::write(&source_path, changed_source).expect("changed source writes");
    assert_eq!(
        persist
            .with_parse_cache_file_from_index(&parse_cache, &source_path, |_| {
                panic!("file-indexed misses must not call visitors")
            })
            .expect("borrowed file-indexed miss succeeds"),
        None
    );
    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 1);

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn cache_file_index_load_canonicalizes_requested_path() {
    use crate::cache::parse::ParseCache;
    use std::os::unix::fs::symlink;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let link_path = src_dir.join("linked-expr.nix");
    let source = b"let x = 1; in x";
    fs::write(&source_path, source).expect("source writes");
    symlink(&source_path, &link_path).expect("symlink creates");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(&realpath, source);
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
        .load_parse_cache_file_from_index(&parse_cache, &link_path)
        .expect("file-indexed parse cache loads")
        .expect("indexed file hit exists");

    assert!(loaded.hit);
    assert_eq!(loaded.key, parsed.key);
    assert!(loaded.entry.is_complete());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_load_misses_without_mapping() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    fs::write(&source_path, source).expect("source writes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));

    let loaded = persist
        .load_parse_cache_file_from_index(&parse_cache, &source_path)
        .expect("file-indexed miss succeeds");

    assert!(loaded.is_none());
    assert!(!parse_cache.entry_for_source(source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_load_misses_when_file_content_changes() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    let changed_source = b"let x = 2; in x";
    fs::write(&source_path, source).expect("source writes");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some(realpath.to_string_lossy().into_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source(&realpath, source);
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    fs::remove_dir_all(parsed.entry.dir()).expect("parse-cache entry removes");
    fs::write(&source_path, changed_source).expect("changed source writes");

    let loaded = persist
        .load_parse_cache_file_from_index(&parse_cache, &source_path)
        .expect("file-indexed miss succeeds");

    assert!(loaded.is_none());
    assert!(!parse_cache.entry_for_source(source).dir().exists());
    assert!(!parse_cache.entry_for_source(changed_source).dir().exists());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_load_reports_source_prep_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let missing_path = root.join("missing.nix");

    let error = persist
        .load_parse_cache_file_from_index(&parse_cache, &missing_path)
        .expect_err("missing source errors");

    assert!(matches!(
        error,
        PersistParseFileIndexedLoadError::CanonicalizeSource { path, .. }
            if path == missing_path
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_load_reports_read_source_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let source_path = root.join("source-directory.nix");
    fs::create_dir(&source_path).expect("source directory creates");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");

    let error = persist
        .load_parse_cache_file_from_index(&parse_cache, &realpath)
        .expect_err("directory source read errors");

    assert!(matches!(
        error,
        PersistParseFileIndexedLoadError::ReadSource { path, .. } if path == realpath
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_file_index_load_reports_hydration_errors() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let src_dir = root.join("src");
    fs::create_dir_all(&src_dir).expect("source dir creates");
    let source_path = src_dir.join("expr.nix");
    let source = b"let x = 1; in x";
    fs::write(&source_path, source).expect("source writes");
    let realpath = fs::canonicalize(&source_path).expect("source canonicalizes");
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let parse_cache = ParseCache::new(root.join("parse"));
    let parse_key = parse_cache.key_for_source(source);
    let file_key = ParseFileKey::for_source(&realpath, source);
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
        .load_parse_cache_file_from_index(&parse_cache, &source_path)
        .expect_err("stale indexed artifact errors");

    assert!(matches!(
        error,
        PersistParseFileIndexedLoadError::Hydrate {
            source: PersistFileArtifactIndexedHydrationError::Hydrate {
                source: PersistFileArtifactHydrationError::Read { .. },
            },
        }
    ));
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

    // A directory at the index path surfaces as a lookup failure. The specific
    // index-error variant is implementation-dependent now that the redundant
    // per-op index ensure/create-open was hoisted to cache open (the scan opens
    // the corrupt path directly and fails at open or length validation), so this
    // asserts the lookup-error class rather than the exact open variant.
    assert!(matches!(
        error,
        PersistFileArtifactIndexedHydrationError::Lookup { .. }
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
        PersistFileBlobHash::for_payload(b"missing artifact"),
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
