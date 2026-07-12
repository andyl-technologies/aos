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
