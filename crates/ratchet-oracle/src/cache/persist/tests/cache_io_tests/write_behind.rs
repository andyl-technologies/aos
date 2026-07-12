//! Tests for the VALUES-store write-behind buffer (RFC-0007 §3.2(b)).

use super::*;

/// Builds a content-addressed VALUES-store key for `payload`.
fn value_key(payload: &[u8]) -> PersistBlobKey {
    PersistBlobKey::for_value(ValueHash::from_canonical_value_hash(
        DurableBlake3Hash::for_bytes(payload),
    ))
}

#[test]
fn write_behind_buffers_values_then_flushes_and_reads_back() {
    let root = temp_root();
    let cache = PersistCache::open(&root)
        .expect("cache opens")
        .with_write_behind_values(true);

    let payloads: [&[u8]; 3] = [b"first value payload", b"second value", b"third value blob"];
    let keys: Vec<_> = payloads.iter().map(|p| value_key(p)).collect();

    for (key, payload) in keys.iter().zip(payloads) {
        let entry = cache
            .ensure_blob_indexed(*key, payload)
            .expect("value buffers");
        assert_eq!(entry.key(), *key);
        // Buffered records are not durable yet: the on-disk index misses.
        assert!(
            cache
                .lookup_blob_location(*key)
                .expect("lookup succeeds")
                .is_none(),
            "a buffered value must not be on disk before flush"
        );
    }
    assert!(!cache.write_behind_buffer_is_empty());

    cache
        .flush_buffered_value_blobs()
        .expect("value buffer flushes");
    assert!(cache.write_behind_buffer_is_empty());

    // After flush every value is durable and reads back byte-for-byte.
    for (key, payload) in keys.iter().zip(payloads) {
        assert!(
            cache
                .lookup_blob_location(*key)
                .expect("lookup succeeds")
                .is_some(),
            "a flushed value must be indexed"
        );
        let read = cache
            .read_blob_indexed(*key)
            .expect("read succeeds")
            .expect("value present");
        assert_eq!(read, payload);
    }
    assert_eq!(cache.write_behind_buffered_miss_recompute(), 0);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_behind_dedups_within_the_buffer() {
    let root = temp_root();
    let cache = PersistCache::open(&root)
        .expect("cache opens")
        .with_write_behind_values(true);
    let payload: &[u8] = b"a repeatedly materialized value";
    let key = value_key(payload);

    cache.ensure_blob_indexed(key, payload).expect("first buffers");
    // A within-run re-materialization of an already-buffered value must not
    // double-append; it is counted as a buffered-miss recompute.
    cache
        .ensure_blob_indexed(key, payload)
        .expect("second dedups");
    assert_eq!(cache.write_behind_buffered_miss_recompute(), 1);

    cache
        .flush_buffered_value_blobs()
        .expect("value buffer flushes");
    // Exactly one durable record for the key (dedup held).
    let mapped = cache
        .read_blob_indexed(key)
        .expect("read succeeds")
        .expect("value present");
    assert_eq!(mapped, payload);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_before_flush_loses_the_buffer_as_a_clean_miss() {
    // Kill-test window 1: a crash after buffering but before the run-boundary
    // flush. `mem::forget` skips the Drop safety-net flush, standing in for a
    // process killed with records still buffered. A fresh open sees nothing on
    // disk — a clean miss (re-eval), never a corrupt or partial record.
    let root = temp_root();
    let payload: &[u8] = b"value buffered then lost to a crash";
    let key = value_key(payload);
    {
        let cache = PersistCache::open(&root)
            .expect("cache opens")
            .with_write_behind_values(true);
        cache.ensure_blob_indexed(key, payload).expect("value buffers");
        assert!(!cache.write_behind_buffer_is_empty());
        // Simulate a crash: drop the handle without running its flush.
        std::mem::forget(cache);
    }
    let reopened = PersistCache::open(&root).expect("cache reopens");
    assert!(
        reopened
            .lookup_blob_location(key)
            .expect("lookup succeeds")
            .is_none(),
        "an unflushed buffered value must be absent after a crash (a clean miss)"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn torn_tail_from_a_mid_flush_crash_is_never_wrong_bytes() {
    // Kill-test window 2: a crash mid-flush leaves a torn tail. Truncating into
    // the last flushed record models the partial write. The reader must reject
    // the torn record (hash/length verification) rather than return wrong bytes;
    // earlier intact records still read.
    let root = temp_root();
    let first: &[u8] = b"first intact value in the flush batch";
    let torn: &[u8] = b"second value whose tail a crash truncates";
    let first_key = value_key(first);
    let torn_key = value_key(torn);
    let pack_path = {
        let cache = PersistCache::open(&root)
            .expect("cache opens")
            .with_write_behind_values(true);
        cache.ensure_blob_indexed(first_key, first).expect("first buffers");
        cache.ensure_blob_indexed(torn_key, torn).expect("torn buffers");
        cache
            .flush_buffered_value_blobs()
            .expect("value buffer flushes");
        cache.layout().value_packfile_path()
    };
    // Truncate a few bytes off the tail: the last record's payload window now
    // overruns the file.
    let len = fs::metadata(&pack_path).expect("pack exists").len();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&pack_path)
        .expect("pack opens for truncate");
    file.set_len(len - 5).expect("pack truncates");
    drop(file);

    let reopened = PersistCache::open(&root).expect("cache reopens");
    // The intact earlier record still reads back byte-for-byte.
    assert_eq!(
        reopened
            .read_blob_indexed(first_key)
            .expect("first read succeeds")
            .expect("first present"),
        first
    );
    // The torn record never yields wrong bytes: it is either a clean miss or a
    // read error, never a payload that mishashes.
    match reopened.read_blob_indexed(torn_key) {
        Ok(None) | Err(_) => {}
        Ok(Some(bytes)) => assert_eq!(bytes, torn, "a torn record must never return wrong bytes"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn buffered_and_synchronous_writers_on_one_root_coexist() {
    // Interleave: two handles on the same cache root — one write-behind, one
    // synchronous — write distinct values that both reach disk. The flush takes
    // the same values-store write lock every synchronous write and repack take,
    // so concurrent writers are serialized by the existing (cross-process)
    // flock; this checks the two paths coexist without dropping either record.
    let root = temp_root();
    let buffered_payload: &[u8] = b"a value written through the buffer";
    let sync_payload: &[u8] = b"a value written synchronously";
    let buffered_key = value_key(buffered_payload);
    let sync_key = value_key(sync_payload);

    let buffering = PersistCache::open(&root)
        .expect("buffering handle opens")
        .with_write_behind_values(true);
    let synchronous = PersistCache::open(&root).expect("synchronous handle opens");

    buffering
        .ensure_blob_indexed(buffered_key, buffered_payload)
        .expect("buffered value buffers");
    // The synchronous handle writes to disk immediately, interleaved with the
    // still-buffered record.
    synchronous
        .ensure_blob_indexed(sync_key, sync_payload)
        .expect("synchronous value writes");
    buffering
        .flush_buffered_value_blobs()
        .expect("buffered value flushes");

    let reader = PersistCache::open(&root).expect("reader opens");
    assert_eq!(
        reader
            .read_blob_indexed(buffered_key)
            .expect("buffered read succeeds")
            .expect("buffered present"),
        buffered_payload
    );
    assert_eq!(
        reader
            .read_blob_indexed(sync_key)
            .expect("synchronous read succeeds")
            .expect("synchronous present"),
        sync_payload
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_behind_batches_root_instantiation_closure_blobs() {
    // store_root_instantiation batches its closure-blob loop when write-behind is
    // on; the record still round-trips (blobs durable before the root record).
    let root = temp_root();
    let cache = PersistCache::open(&root)
        .expect("cache opens")
        .with_write_behind_values(true);
    let key = PersistRootRecordKey::from_digest([42; 32]);
    let mut closure = BTreeMap::new();
    closure.insert(
        PathBuf::from("/nix/store/root.drv"),
        b"Derive([],[],[],\"\",[],[])root".to_vec(),
    );
    closure.insert(
        PathBuf::from("/nix/store/dep.drv"),
        b"Derive([],[],[],\"\",[],[])dep".to_vec(),
    );
    cache
        .store_root_instantiation(key, b"/nix/store/root.drv", &closure, &[], 7)
        .expect("root instantiation stores");
    let loaded = cache
        .load_root_instantiation(key)
        .expect("root loads")
        .expect("root present");
    assert_eq!(loaded.root(), Path::new("/nix/store/root.drv"));
    assert_eq!(loaded.closure(), &closure);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_behind_off_by_default_writes_through() {
    let root = temp_root();
    let cache = PersistCache::open(&root).expect("cache opens");
    let payload: &[u8] = b"synchronous value";
    let key = value_key(payload);

    cache
        .ensure_blob_indexed(key, payload)
        .expect("value writes through");
    // With write-behind off the value is durable immediately (no flush needed).
    assert!(
        cache
            .lookup_blob_location(key)
            .expect("lookup succeeds")
            .is_some(),
        "a synchronous value must be on disk immediately"
    );
    assert!(cache.write_behind_buffer_is_empty());
    let _ = fs::remove_dir_all(root);
}
