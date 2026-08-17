//! File artifact hydration tests.

mod split;

use super::*;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    persist
        .hydrate_file_artifact_bundle(index_value, &hydrated)
        .expect("bundle hydrates");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "direct file-artifact hydration should decode through the scoped mapped files pack"
    );

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
fn cache_file_artifact_borrowed_bundle_visit_decodes_after_scoped_mapping() {
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
    let meta = bundle.decode_meta().expect("bundle metadata decodes");
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
    let files_store_lock_path = persist
        .layout()
        .blob_store_lock_path(PersistBlobStore::Files);

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let observed_node_count = persist
        .with_file_artifact_bundle(index_value, |observed| {
            assert_eq!(observed, &bundle);
            let files_store_guard =
                AdvisoryFileLock::try_lock(&files_store_lock_path, AdvisoryFileLockMode::Exclusive)
                    .expect("file-artifact visitor runs after the files-store lock is released");
            drop(files_store_guard);
            assert_eq!(
                persist
                    .read_file_artifact(index_value)
                    .expect("same-root file-artifact read can re-enter from visitor"),
                payload
            );
            observed
                .decode_meta()
                .expect("visited bundle metadata decodes")
                .node_count
        })
        .expect("bundle visit succeeds");

    assert_eq!(observed_node_count, meta.node_count);
    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 2);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_borrowed_bundle_visit_decodes_after_scoped_mapping() {
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
    let meta = bundle.decode_meta().expect("bundle metadata decodes");
    let payload = bundle.encode().expect("bundle encodes");
    let materialized = persist
        .materialize_parse_artifact(parsed.key, &payload, MaterializationDecision::Materialize)
        .expect("bundle materializes");
    let Some(index_value) = materialized.index_value() else {
        panic!("bundle should materialize");
    };
    let files_store_lock_path = persist
        .layout()
        .blob_store_lock_path(PersistBlobStore::Files);

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let observed_symbol_count = persist
        .with_parse_artifact_bundle(index_value, |observed| {
            assert_eq!(observed, &bundle);
            let files_store_guard =
                AdvisoryFileLock::try_lock(&files_store_lock_path, AdvisoryFileLockMode::Exclusive)
                    .expect("parse-artifact visitor runs after the files-store lock is released");
            drop(files_store_guard);
            assert_eq!(
                persist
                    .read_parse_artifact(index_value)
                    .expect("same-root parse-artifact read can re-enter from visitor"),
                payload
            );
            observed
                .decode_meta()
                .expect("visited bundle metadata decodes")
                .symbol_count
        })
        .expect("bundle visit succeeds");

    assert_eq!(observed_symbol_count, meta.symbol_count);
    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 2);

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let error = persist
        .hydrate_file_artifact_bundle(index_value, &hydrated)
        .expect_err("invalid bundle metadata fails hydration");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "invalid direct file-artifact hydration should still decode through the mapped pack"
    );

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let error = persist
        .hydrate_file_artifact_bundle(index_value, &hydrated)
        .expect_err("malformed resolved artifact fails hydration");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "malformed direct file-artifact hydration should still decode through the mapped pack"
    );

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let error = persist
        .hydrate_parse_artifact_bundle(index_value, &hydrated)
        .expect_err("malformed resolved artifact fails hydration");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "parse-artifact hydration should decode through the scoped mapped files pack"
    );

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
fn cache_parse_artifact_hydrates_parse_entry_after_key_match() {
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
    let materialized = persist
        .materialize_parse_artifact(parsed.key, &payload, MaterializationDecision::Materialize)
        .expect("bundle materializes");
    let Some(index_value) = materialized.index_value() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-keyed-parse-entry"));

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    persist
        .hydrate_parse_artifact_bundle_for_key(
            parsed.key,
            materialized.artifact_key(),
            index_value,
            &hydrated,
        )
        .expect("keyed parse bundle hydrates");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "keyed parse-artifact hydration should decode through the scoped mapped files pack"
    );

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
fn cache_parse_artifact_hydration_rejects_key_mismatch_before_locking_files() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let parse_key = test_parse_key(b"let x = 1; in x");
    let expected = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let actual = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let y = 2; in y"));
    let index_value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    let target = ParseCacheEntry::new(root.join("target-keyed-parse-entry"));
    let guard = persist
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquired");
    let worker = persist.clone();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result =
            worker.hydrate_parse_artifact_bundle_for_key(parse_key, actual, index_value, &target);
        tx.send(result).expect("hydration result sends");
    });

    let error = match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result.expect_err("key mismatch errors before files lock"),
        Err(error) => {
            drop(guard);
            handle
                .join()
                .expect("hydration thread joins after lock release");
            panic!("parse key mismatch tried to take the files store lock: {error}");
        }
    };
    drop(guard);
    handle.join().expect("hydration thread joins");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "parse key mismatch should fail before mapping the files pack"
    );

    assert!(matches!(
        error,
        PersistParseArtifactHydrationError::KeyMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } if observed_expected == expected && observed_actual == actual
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_hydration_from_entry_rejects_key_mismatch() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let parse_key = test_parse_key(b"let x = 1; in x");
    let expected = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let actual = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let y = 2; in y"));
    let index_entry = PersistParseArtifactIndexEntry::new(
        actual,
        PersistParseArtifactIndexValue::new(
            PersistFileBlobHash::for_payload(b"missing artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ),
    );
    let target = ParseCacheEntry::new(root.join("target-parse-entry"));

    let error = persist
        .hydrate_parse_artifact_bundle_from_entry(parse_key, index_entry, &target)
        .expect_err("parse entry key mismatch errors before read");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "parse entry key mismatch should fail before mapping the files pack"
    );

    assert!(matches!(
        error,
        PersistParseArtifactHydrationError::KeyMismatch {
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
fn cache_parse_artifact_hydration_from_entry_rejects_key_mismatch_before_locking_files() {
    let root = temp_root();
    let persist = PersistCache::open(&root).expect("cache opens");
    let parse_key = test_parse_key(b"let x = 1; in x");
    let expected = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let actual = PersistParseArtifactKey::from_parse_cache_key(test_parse_key(b"let y = 2; in y"));
    let index_entry = PersistParseArtifactIndexEntry::new(
        actual,
        PersistParseArtifactIndexValue::new(
            PersistFileBlobHash::for_payload(b"missing artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ),
    );
    let target = ParseCacheEntry::new(root.join("target-entry-parse-entry"));
    let guard = persist
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquired");
    let worker = persist.clone();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result =
            worker.hydrate_parse_artifact_bundle_from_entry(parse_key, index_entry, &target);
        tx.send(result).expect("hydration result sends");
    });

    let error = match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result.expect_err("entry key mismatch errors before files lock"),
        Err(error) => {
            drop(guard);
            handle
                .join()
                .expect("hydration thread joins after lock release");
            panic!("parse entry key mismatch tried to take the files store lock: {error}");
        }
    };
    drop(guard);
    handle.join().expect("hydration thread joins");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "parse entry key mismatch should fail before mapping the files pack"
    );

    assert!(matches!(
        error,
        PersistParseArtifactHydrationError::KeyMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } if observed_expected == expected && observed_actual == actual
    ));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_hydrates_parse_entry_from_index_entry() {
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
    let materialized = persist
        .materialize_parse_artifact(parsed.key, &payload, MaterializationDecision::Materialize)
        .expect("bundle materializes");
    let Some(index_entry) = materialized.index_entry() else {
        panic!("bundle should materialize");
    };
    let hydrated = ParseCacheEntry::new(root.join("hydrated-parse-entry-record"));

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    persist
        .hydrate_parse_artifact_bundle_from_entry(parsed.key, index_entry, &hydrated)
        .expect("parse entry bundle hydrates");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "entry-shaped parse-artifact hydration should decode through the scoped mapped files pack"
    );

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
        PersistFileBlobHash::for_payload(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    let target = ParseCacheEntry::new(root.join("target-entry"));

    let error = persist
        .hydrate_file_artifact_bundle_for_key(&file_key, parse_key, actual, index_value, &target)
        .expect_err("key mismatch errors before read");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "key mismatch should fail before mapping the files pack"
    );

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
fn cache_file_artifact_hydration_rejects_key_mismatch_before_locking_files() {
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
        PersistFileBlobHash::for_payload(b"missing artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
    );
    let target = ParseCacheEntry::new(root.join("target-keyed-entry"));
    let guard = persist
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquired");
    let worker = persist.clone();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = worker.hydrate_file_artifact_bundle_for_key(
            &file_key,
            parse_key,
            actual,
            index_value,
            &target,
        );
        tx.send(result).expect("hydration result sends");
    });

    let error = match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result.expect_err("key mismatch errors before files lock"),
        Err(error) => {
            drop(guard);
            handle
                .join()
                .expect("hydration thread joins after lock release");
            panic!("file key mismatch tried to take the files store lock: {error}");
        }
    };
    drop(guard);
    handle.join().expect("hydration thread joins");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "file key mismatch should fail before mapping the files pack"
    );

    assert!(matches!(
        error,
        PersistFileArtifactHydrationError::KeyMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } if observed_expected == expected && observed_actual == actual
    ));

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    persist
        .hydrate_file_artifact_bundle_for_key(
            &file_key,
            parsed.key,
            materialized.artifact_key(),
            index_value,
            &hydrated,
        )
        .expect("keyed bundle hydrates");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "keyed file-artifact hydration should decode through the scoped mapped files pack"
    );

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
            PersistFileBlobHash::for_payload(b"missing artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ),
    );
    let target = ParseCacheEntry::new(root.join("target-entry"));

    let error = persist
        .hydrate_file_artifact_bundle_from_entry(&file_key, parse_key, index_entry, &target)
        .expect_err("entry key mismatch errors before read");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "entry key mismatch should fail before mapping the files pack"
    );

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
fn cache_file_artifact_hydration_from_entry_rejects_key_mismatch_before_locking_files() {
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
            PersistFileBlobHash::for_payload(b"missing artifact"),
            PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 0),
        ),
    );
    let target = ParseCacheEntry::new(root.join("target-entry-record"));
    let guard = persist
        .lock_blob_materialization_for_tests(PersistBlobStore::Files)
        .expect("file store lock acquired");
    let worker = persist.clone();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = worker.hydrate_file_artifact_bundle_from_entry(
            &file_key,
            parse_key,
            index_entry,
            &target,
        );
        tx.send(result).expect("hydration result sends");
    });

    let error = match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result.expect_err("entry key mismatch errors before files lock"),
        Err(error) => {
            drop(guard);
            handle
                .join()
                .expect("hydration thread joins after lock release");
            panic!("file entry key mismatch tried to take the files store lock: {error}");
        }
    };
    drop(guard);
    handle.join().expect("hydration thread joins");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        0,
        "file entry key mismatch should fail before mapping the files pack"
    );

    assert!(matches!(
        error,
        PersistFileArtifactHydrationError::KeyMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } if observed_expected == expected && observed_actual == actual
    ));

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    persist
        .hydrate_file_artifact_bundle_from_entry(&file_key, parsed.key, index_entry, &hydrated)
        .expect("entry bundle hydrates");
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "entry-shaped file-artifact hydration should decode through the scoped mapped files pack"
    );

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
