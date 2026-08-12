//! Split-out `blob_sidecars.rs` test group (split).

use super::*;

#[test]
fn cache_lookup_parse_artifact_acquires_advisory_mapping_lock_before_same_process_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let layout = cache.layout().clone();
    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"lookup advisory parse artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, value))
        .expect("parse artifact index entry records");
    let guard = cache
        .lock_parse_artifacts_for_tests()
        .expect("parse-artifact lock acquires");
    let worker_cache = cache.clone();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let result = worker_cache
            .lookup_parse_artifact(key)
            .map_err(|error| error.to_string());
        tx.send(result).expect("parse-artifact lookup result sends");
    });

    wait_until_advisory_try_lock_blocks(&layout.parse_artifact_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "parse-artifact lookup should wait while the mapping lock is held"
    );
    drop(guard);

    let found = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("parse-artifact lookup completes after same-process lock release")
        .expect("parse-artifact lookup succeeds");
    handle.join().expect("worker joins");
    assert_eq!(found, Some(value));
    let released_lock = AdvisoryFileLock::try_lock(
        layout.parse_artifact_lock_path(),
        AdvisoryFileLockMode::Exclusive,
    )
    .expect("parse-artifact advisory lock releases after lookup");
    drop(released_lock);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn cache_parse_artifact_index_reports_poisoned_same_root_lock() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let poison_cache = PersistCache::open(&root).expect("second cache opens");
    let poisoner = thread::spawn(move || {
        let _guard = poison_cache
            .lock_parse_artifacts_for_tests()
            .expect("parse artifact lock acquires");
        panic!("poison persistent parse artifact write lock");
    });
    assert!(poisoner.join().is_err());

    let source = b"let x = 1; in x";
    let parse_key = test_parse_key(source);
    let key = PersistParseArtifactKey::from_parse_cache_key(parse_key);
    let value = PersistParseArtifactIndexValue::new(
        PersistFileBlobHash::for_payload(b"serialized parse artifact"),
        PersistBlobLocation::new(PERSIST_BLOB_PACK_HEADER_LEN as u64, 22),
    );
    let error = cache
        .record_parse_artifact(PersistParseArtifactIndexEntry::new(key, value))
        .expect_err("poisoned same-root parse artifact lock should reject writes");

    assert!(matches!(
        error,
        PersistParseArtifactIndexError::WriteLockPoisoned
    ));
    assert_eq!(
        fs::metadata(cache.parse_artifact_index().path())
            .expect("parse artifact index metadata")
            .len(),
        0
    );

    let _ = fs::remove_dir_all(root);
}
