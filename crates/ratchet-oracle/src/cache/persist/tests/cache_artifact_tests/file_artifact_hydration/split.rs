//! Split-out `file_artifact_hydration.rs` test group (split).

use super::*;

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

    assert_eq!(persist.file_pack().mapped_read_count_for_tests(), 0);
    let result = persist
        .hydrate_file_artifact_bundle_from_index(&file_key, parsed.key, &hydrated)
        .expect("indexed entry hydrates");

    assert_eq!(result, Some(expected_entry));
    assert_eq!(
        persist.file_pack().mapped_read_count_for_tests(),
        1,
        "indexed file-artifact hydration should decode through the scoped mapped files pack"
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
fn cache_file_artifact_index_hydration_acquires_advisory_locks_before_mapping_lock() {
    use crate::cache::parse::ParseCache;

    let root = temp_root();
    let persist = PersistCache::open(root.join("persist")).expect("cache opens");
    let layout = persist.layout().clone();
    let parse_cache = ParseCache::new(root.join("parse"));
    let source = b"let x = 1; in x";
    let parsed = parse_cache
        .load_or_parse_bytes(source, Some("expr.nix".to_owned()))
        .expect("source parses");
    let file_key = ParseFileKey::for_source("/src/default.nix", source);
    persist
        .materialize_parse_artifact_entry_indexed(
            &file_key,
            parsed.key,
            &parsed.entry,
            MaterializationDecision::Materialize,
        )
        .expect("entry materializes");
    let guard = persist
        .lock_file_artifacts_for_tests()
        .expect("file-artifact mapping lock acquired");
    let worker = persist.clone();
    let target_dir = root.join("hydrated-index-locked");
    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);
    let handle = thread::spawn(move || {
        worker_barrier.wait();
        let target = ParseCacheEntry::new(target_dir);
        let result = worker
            .hydrate_file_artifact_bundle_from_index(&file_key, parsed.key, &target)
            .map(|entry| (entry.is_some(), target.is_complete()));
        tx.send(result).expect("hydration result sends");
    });

    barrier.wait();
    wait_until_advisory_try_lock_blocks(&layout.blob_store_lock_path(PersistBlobStore::Files));
    wait_until_advisory_try_lock_blocks(&layout.file_artifact_lock_path());
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "indexed file-artifact hydration should wait on the mapping lock"
    );
    drop(guard);
    let (hydrated, complete) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("hydration completes after mapping lock release")
        .expect("hydration succeeds");
    handle.join().expect("hydration thread joins");
    assert!(hydrated);
    assert!(complete);

    let _ = fs::remove_dir_all(root);
}
