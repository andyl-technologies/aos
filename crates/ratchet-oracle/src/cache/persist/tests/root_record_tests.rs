//! Tests for the durable root-instantiation record payload and store.

use super::*;
use crate::cache::{CacheableInputFingerprint, ImpureInputFingerprint};

fn cacheable(path: &[u8], contents: &[u8]) -> CacheableInputFingerprint {
    ImpureInputFingerprint::read_file(path, contents)
        .expect("read-file fingerprint builds")
        .as_cacheable()
        .expect("read-file fingerprint is cacheable")
        .clone()
}

fn sample_closure() -> BTreeMap<PathBuf, Vec<u8>> {
    let mut closure = BTreeMap::new();
    closure.insert(
        PathBuf::from("/nix/store/root.drv"),
        b"Derive([],[],[],\"\",[],[])root".to_vec(),
    );
    closure.insert(
        PathBuf::from("/nix/store/dep.drv"),
        b"Derive([],[],[],\"\",[],[])dep".to_vec(),
    );
    closure
}

fn sample_key(byte: u8) -> PersistRootRecordKey {
    PersistRootRecordKey::from_digest([byte; 32])
}

#[test]
fn root_record_payload_round_trips() {
    let inputs = vec![cacheable(b"/a", b"one"), cacheable(b"/b", b"two")];
    let entries = vec![
        (
            b"/nix/store/root.drv".to_vec(),
            PersistFileBlobHash::for_payload(b"root"),
        ),
        (
            b"/nix/store/dep.drv".to_vec(),
            PersistFileBlobHash::for_payload(b"dep"),
        ),
    ];
    let record = RootInstantiationRecord::new(b"/nix/store/root.drv".to_vec(), entries, inputs, 7);

    let bytes = record.encode().expect("record encodes");
    let decoded = RootInstantiationRecord::decode(&bytes).expect("record decodes");

    assert_eq!(record, decoded);
    assert_eq!(decoded.run_id(), 7);
    assert_eq!(decoded.root_drv(), b"/nix/store/root.drv");
    assert_eq!(decoded.entries().len(), 2);
    assert_eq!(decoded.inputs().len(), 2);
}

#[test]
fn root_record_payload_rejects_bad_magic() {
    let record = RootInstantiationRecord::new(b"/root".to_vec(), Vec::new(), Vec::new(), 0);
    let mut bytes = record.encode().expect("record encodes");
    bytes[0] ^= 0xff;
    assert!(RootInstantiationRecord::decode(&bytes).is_err());
}

#[test]
fn root_record_payload_rejects_truncation() {
    let record = RootInstantiationRecord::new(b"/root".to_vec(), Vec::new(), Vec::new(), 0);
    let bytes = record.encode().expect("record encodes");
    assert!(RootInstantiationRecord::decode(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn store_and_load_round_trips_closure_and_inputs() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let closure = sample_closure();
    let inputs = vec![cacheable(b"/a", b"one"), cacheable(b"/b", b"two")];

    cache
        .store_root_instantiation(sample_key(1), b"/nix/store/root.drv", &closure, &inputs, 42)
        .expect("record stores");

    let loaded = cache
        .load_root_instantiation(sample_key(1))
        .expect("record loads")
        .expect("record is present");

    assert_eq!(loaded.root(), Path::new("/nix/store/root.drv"));
    assert_eq!(loaded.closure(), &closure);
    assert_eq!(loaded.inputs(), inputs.as_slice());
    assert_eq!(loaded.run_id(), 42);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_misses_for_unknown_key() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    cache
        .store_root_instantiation(sample_key(1), b"/root.drv", &sample_closure(), &[], 0)
        .expect("record stores");

    assert!(
        cache
            .load_root_instantiation(sample_key(2))
            .expect("lookup succeeds")
            .is_none(),
        "an unrelated key must miss"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn newest_record_for_a_key_wins() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    let mut first = BTreeMap::new();
    first.insert(PathBuf::from("/nix/store/a.drv"), b"first".to_vec());
    cache
        .store_root_instantiation(sample_key(3), b"/nix/store/a.drv", &first, &[], 1)
        .expect("first stores");

    let mut second = BTreeMap::new();
    second.insert(PathBuf::from("/nix/store/b.drv"), b"second".to_vec());
    cache
        .store_root_instantiation(sample_key(3), b"/nix/store/b.drv", &second, &[], 2)
        .expect("second stores");

    let loaded = cache
        .load_root_instantiation(sample_key(3))
        .expect("record loads")
        .expect("record is present");
    assert_eq!(loaded.root(), Path::new("/nix/store/b.drv"));
    assert_eq!(loaded.closure(), &second);
    assert_eq!(loaded.run_id(), 2);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn file_pack_repack_preserves_root_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    // Unrooted bytes ahead of the record's blobs give the repack reclaimable
    // space, forcing every later rooted record to relocate downward. Before
    // root-record blob liveness was wired into maintenance, this relocation
    // stranded the roots/ sidecar's embedded locations and every stored root
    // record stopped hydrating (the MEMO-2 regression this test pins).
    let garbage = b"unrooted leading garbage";
    let garbage_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(garbage));
    cache
        .append_blob(garbage_key, garbage)
        .expect("unrooted garbage appends");

    let closure = sample_closure();
    let inputs = vec![cacheable(b"/a", b"one")];
    cache
        .store_root_instantiation(sample_key(6), b"/nix/store/root.drv", &closure, &inputs, 9)
        .expect("record stores");

    let plan = cache
        .repack_file_blob_pack()
        .expect("file blob pack repacks");
    assert!(
        plan.reclaimable_bytes() > 0,
        "the repack must actually relocate records for this regression to bite"
    );

    let loaded = cache
        .load_root_instantiation(sample_key(6))
        .expect("record loads after repack")
        .expect("record survives repack");
    assert_eq!(loaded.root(), Path::new("/nix/store/root.drv"));
    assert_eq!(loaded.closure(), &closure);
    assert_eq!(loaded.inputs(), inputs.as_slice());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn storage_maintenance_preserves_root_records() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");

    // A raw (unindexed) copy of a payload that is later properly indexed
    // leaves a repair-clean plan with reclaimable unrooted bytes, which is
    // exactly the shape that drives `maintain_storage` into its repack branch.
    let duplicate = b"duplicated payload";
    let duplicate_key = PersistBlobKey::for_file(PersistFileBlobHash::for_payload(duplicate));
    cache
        .append_blob(duplicate_key, duplicate)
        .expect("raw duplicate appends");
    cache
        .append_blob_indexed(duplicate_key, duplicate)
        .expect("indexed duplicate appends");

    let closure = sample_closure();
    cache
        .store_root_instantiation(sample_key(7), b"/nix/store/root.drv", &closure, &[], 3)
        .expect("record stores");

    let policy =
        PersistStorageMaintenancePolicy::default().with_min_repack_reclaimable_bytes(1);
    let outcome = cache
        .maintain_storage(policy)
        .expect("automatic maintenance runs");
    assert!(
        matches!(outcome, PersistStorageMaintenanceOutcome::Repacked { .. }),
        "the fixture must drive the repack branch, got {outcome:?}"
    );

    let loaded = cache
        .load_root_instantiation(sample_key(7))
        .expect("record loads after maintenance")
        .expect("record survives maintenance");
    assert_eq!(loaded.closure(), &closure);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_heals_a_stale_indexed_record_location() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let closure = sample_closure();
    cache
        .store_root_instantiation(sample_key(8), b"/nix/store/root.drv", &closure, &[], 1)
        .expect("record stores");

    // Simulate a roots/ entry written before root-record relocation support:
    // same record blob hash, bogus embedded pack location. The newest entry
    // wins lookups, so the load must fall back to the authoritative blob
    // index instead of failing on the stale offset.
    let index = PersistRootRecordIndex::open(cache.layout().root_record_index_path())
        .expect("root record index opens");
    let current = index
        .lookup(sample_key(8))
        .expect("index lookup succeeds")
        .expect("entry exists");
    let stale_location = PersistBlobLocation::new(
        current.location().record_offset() + 13,
        current.location().payload_len(),
    );
    index
        .append_entry(PersistRootRecordIndexEntry::new(
            sample_key(8),
            PersistRootRecordIndexValue::new(current.blob_hash(), stale_location),
        ))
        .expect("stale entry appends");

    let loaded = cache
        .load_root_instantiation(sample_key(8))
        .expect("record loads despite the stale location")
        .expect("record hydrates through the blob index");
    assert_eq!(loaded.closure(), &closure);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn liveness_plan_attributes_root_record_roots() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let closure = sample_closure();
    cache
        .store_root_instantiation(sample_key(9), b"/nix/store/root.drv", &closure, &[], 1)
        .expect("record stores");

    let plan = cache
        .plan_blob_pack_liveness(PersistBlobStore::Files)
        .expect("liveness plan builds");
    let root_record_roots = plan
        .live_roots()
        .iter()
        .filter(|live| live.source() == PersistBlobLiveRootSource::RootRecordIndex)
        .count();
    // One root for the encoded record blob plus one per closure entry.
    assert_eq!(root_record_roots, 1 + closure.len());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn identical_closures_dedupe_blob_storage() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let closure = sample_closure();

    cache
        .store_root_instantiation(sample_key(4), b"/nix/store/root.drv", &closure, &[], 0)
        .expect("first stores");
    let pack_len_after_first = fs::metadata(cache.layout().file_packfile_path())
        .expect("files pack exists")
        .len();

    // Re-storing an identical closure under a different key must reuse the
    // existing content-addressed blobs and not grow the pack by their size.
    cache
        .store_root_instantiation(sample_key(5), b"/nix/store/root.drv", &closure, &[], 0)
        .expect("second stores");
    let pack_len_after_second = fs::metadata(cache.layout().file_packfile_path())
        .expect("files pack exists")
        .len();

    let closure_bytes: u64 = closure.values().map(|bytes| bytes.len() as u64).sum();
    assert!(
        pack_len_after_second < pack_len_after_first + closure_bytes,
        "re-storing an identical closure must dedupe its blobs (before={pack_len_after_first}, after={pack_len_after_second}, closure_bytes={closure_bytes})"
    );

    let _ = fs::remove_dir_all(root);
}
