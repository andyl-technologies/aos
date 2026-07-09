//! Shared flat-store publication and resolution tests.

use std::ptr::NonNull;
use std::sync::Arc;
use std::thread;

use super::*;
use crate::value::HeapObject;

fn store() -> SharedFlatObjectStore<String> {
    SharedFlatObjectStore::with_capacity(4096)
}

#[test]
fn publish_then_resolve_round_trips_header_and_payload() {
    let store = store();
    let ptr = store
        .publish(FlatObjectKind::String, 0xfeed, 5, "hello".to_owned())
        .expect("publish succeeds");

    let object = store
        .resolve(ptr, FlatObjectKind::String)
        .expect("published slot resolves");
    assert_eq!(object.kind(), Some(FlatObjectKind::String));
    assert_eq!(object.structural_hash(), 0xfeed);
    assert_eq!(object.payload(), "hello");
    assert_eq!(store.len(), 1);
    assert_eq!(store.payload_bytes(), 5);
}

#[test]
fn resolve_rejects_kind_mismatch_and_unknown_addresses() {
    let store = store();
    let ptr = store
        .publish(FlatObjectKind::Path, 1, 4, "/nix".to_owned())
        .expect("publish succeeds");

    assert!(store.resolve(ptr, FlatObjectKind::String).is_none());
    assert!(store.resolve_any(ptr).is_some());

    let bogus = NonNull::new(0x10usize as *mut HeapObject).expect("nonnull");
    assert!(store.resolve_any(bogus).is_none());

    // Interior (unaligned-to-slot) addresses inside the level do not resolve.
    let interior = NonNull::new((ptr.as_ptr() as usize + 1) as *mut HeapObject).expect("nonnull");
    assert!(store.resolve_any(interior).is_none());
}

#[test]
fn addresses_stay_stable_across_level_growth() {
    let store = store();
    let mut published = Vec::new();
    for index in 0..2048usize {
        let ptr = store
            .publish(FlatObjectKind::String, index as u64, 1, index.to_string())
            .expect("publish succeeds");
        published.push((index, ptr));
    }
    for (index, ptr) in published {
        let object = store
            .resolve(ptr, FlatObjectKind::String)
            .expect("published slot resolves");
        assert_eq!(object.structural_hash(), index as u64);
        assert_eq!(object.payload(), &index.to_string());
    }
    assert_eq!(store.len(), 2048);
}

#[test]
fn capacity_exhaustion_fails_loudly() {
    let store = SharedFlatObjectStore::<String>::with_capacity(1);
    // The minimum store still holds one level-0 chunk.
    for index in 0..CHUNK_LEN {
        store
            .publish(FlatObjectKind::String, index as u64, 0, String::new())
            .expect("in-capacity publish succeeds");
    }
    let error = store
        .publish(FlatObjectKind::String, 0, 0, String::new())
        .expect_err("over-capacity publish fails");
    assert_eq!(
        error,
        SharedFlatObjectError::CapacityExhausted {
            capacity: CHUNK_LEN
        }
    );
}

#[test]
fn iter_yields_every_published_object_with_its_address() {
    let store = store();
    let first = store
        .publish(FlatObjectKind::String, 7, 1, "a".to_owned())
        .expect("publish succeeds");
    let second = store
        .publish(FlatObjectKind::Path, 8, 1, "b".to_owned())
        .expect("publish succeeds");

    let entries: Vec<(usize, u64)> = store
        .iter()
        .map(|(address, object)| (address, object.structural_hash()))
        .collect();
    assert_eq!(
        entries,
        vec![
            (first.as_ptr() as usize, 7),
            (second.as_ptr() as usize, 8)
        ]
    );
}

#[test]
fn cross_thread_readers_observe_published_objects() {
    let store = Arc::new(store());
    let ptr = store
        .publish(FlatObjectKind::String, 42, 6, "shared".to_owned())
        .expect("publish succeeds");
    let address = ptr.as_ptr() as usize;

    let readers: Vec<_> = (0..4)
        .map(|_| {
            let store = Arc::clone(&store);
            thread::spawn(move || {
                let ptr = NonNull::new(address as *mut HeapObject).expect("nonnull");
                let object = store
                    .resolve(ptr, FlatObjectKind::String)
                    .expect("cross-thread resolve succeeds");
                assert_eq!(object.payload(), "shared");
                assert_eq!(object.structural_hash(), 42);
            })
        })
        .collect();
    for reader in readers {
        reader.join().expect("reader thread succeeds");
    }
}

#[test]
fn attrs_kind_publishes_and_resolves_across_threads() {
    let store: Arc<SharedFlatObjectStore<(u32, Vec<u64>)>> =
        Arc::new(SharedFlatObjectStore::with_capacity(64));
    let ptr = store
        .publish(FlatObjectKind::Attrs, 0xdef, 16, (42, vec![7, 9]))
        .expect("publish succeeds");
    let address = ptr.as_ptr() as usize;

    let reader = Arc::clone(&store);
    thread::spawn(move || {
        let ptr = NonNull::new(address as *mut HeapObject).expect("non-null");
        let object = reader
            .resolve(ptr, FlatObjectKind::Attrs)
            .expect("published attrs resolve cross-thread");
        assert_eq!(object.kind(), Some(FlatObjectKind::Attrs));
        assert_eq!(object.structural_hash(), 0xdef);
        assert_eq!(object.payload().0, 42);
        assert_eq!(object.payload().1, [7, 9]);
        assert!(reader.resolve(ptr, FlatObjectKind::List).is_none());
    })
    .join()
    .expect("reader thread joins");
}
