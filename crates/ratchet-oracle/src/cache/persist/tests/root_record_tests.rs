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
