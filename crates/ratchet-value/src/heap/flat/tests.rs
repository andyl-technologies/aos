//! Unit tests for the flat-object store.

use std::cell::Cell;
use std::ptr::NonNull;
use std::rc::Rc;

use super::*;

/// A payload with drop glue, so leaks and double drops are observable.
#[derive(Debug)]
struct Payload {
    text: String,
    drops: Rc<Cell<usize>>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn payload(text: &str, drops: &Rc<Cell<usize>>) -> Payload {
    Payload {
        text: text.to_string(),
        drops: Rc::clone(drops),
    }
}

#[test]
fn alloc_and_resolve_round_trip_header_and_payload() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(FlatObjectKind::String, 0xfeed, 7, payload("hello", &drops))
        .expect("allocation succeeds");

    let object = store
        .resolve(allocation.ptr, FlatObjectKind::String)
        .expect("resolution succeeds");
    assert_eq!(object.payload().text, "hello");
    assert_eq!(object.structural_hash(), 0xfeed);
    assert_eq!(object.kind(), FlatObjectKind::String);
    assert_eq!(object.last_touch_epoch(), 7);
    object.touch(9);
    assert_eq!(object.last_touch_epoch(), 9);
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}

#[test]
fn resolution_rejects_wrong_kind_with_the_actual_kind() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(FlatObjectKind::Path, 1, 0, payload("/nix/store/x", &drops))
        .expect("allocation succeeds");

    let error = store
        .resolve(allocation.ptr, FlatObjectKind::String)
        .expect_err("kind mismatch is rejected");
    assert_eq!(
        error,
        FlatObjectError::KindMismatch {
            expected: FlatObjectKind::String,
            actual: FlatObjectKind::Path,
            address: allocation.ptr.as_ptr() as usize,
        }
    );
    assert_eq!(store.kind_of(allocation.ptr), Some(FlatObjectKind::Path));
}

#[test]
fn foreign_addresses_fail_without_a_memory_access() {
    let drops = Rc::new(Cell::new(0));
    let mut store: FlatObjectStore<Payload> = FlatObjectStore::new();
    let dangling = NonNull::<HeapObject>::dangling();
    let error = store
        .resolve(dangling, FlatObjectKind::String)
        .expect_err("dangling address is rejected");
    assert_eq!(
        error,
        FlatObjectError::UnknownAddress {
            address: dangling.as_ptr() as usize,
        }
    );

    // A live allocation in a *different* store is outside this store's
    // regions and fails the membership check.
    let mut other = FlatObjectStore::new();
    let foreign = other
        .alloc(FlatObjectKind::String, 2, 0, payload("other", &drops))
        .expect("allocation succeeds");
    store
        .alloc(FlatObjectKind::String, 3, 0, payload("own", &drops))
        .expect("allocation succeeds");
    let error = store
        .resolve(foreign.ptr, FlatObjectKind::String)
        .expect_err("foreign-store address is rejected");
    assert_eq!(
        error,
        FlatObjectError::UnknownAddress {
            address: foreign.ptr.as_ptr() as usize,
        }
    );
}

#[test]
fn interior_in_region_addresses_fail_the_magic_check() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(FlatObjectKind::String, 4, 0, payload("padding", &drops))
        .expect("allocation succeeds");

    // One word past the object start is in-region and word-aligned but does
    // not carry the magic header, so it fails loudly.
    let interior = (allocation.ptr.as_ptr() as usize) + 8;
    let interior_ptr =
        NonNull::new(interior as *mut HeapObject).expect("interior address is non-null");
    let error = store
        .resolve(interior_ptr, FlatObjectKind::String)
        .expect_err("interior address is rejected");
    assert_eq!(error, FlatObjectError::UnknownAddress { address: interior });
}

#[test]
fn iteration_yields_every_object_in_allocation_order() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let first = store
        .alloc(FlatObjectKind::String, 10, 1, payload("a", &drops))
        .expect("allocation succeeds");
    let second = store
        .alloc(FlatObjectKind::Path, 20, 2, payload("b", &drops))
        .expect("allocation succeeds");

    let entries: Vec<_> = store.iter().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].ptr(), first.ptr);
    assert_eq!(entries[0].object().structural_hash(), 10);
    assert_eq!(entries[0].object().kind(), FlatObjectKind::String);
    assert!(entries[0].size_bytes() >= std::mem::size_of::<FlatObject<Payload>>());
    assert_eq!(entries[1].ptr(), second.ptr);
    assert_eq!(entries[1].object().payload().text, "b");
    assert_eq!(entries[1].object().kind(), FlatObjectKind::Path);
}

#[test]
fn dropping_the_store_runs_payload_drop_glue_exactly_once() {
    let drops = Rc::new(Cell::new(0));
    {
        let mut store = FlatObjectStore::new();
        for index in 0..64 {
            store
                .alloc(
                    FlatObjectKind::String,
                    index,
                    0,
                    payload(&format!("value-{index}"), &drops),
                )
                .expect("allocation succeeds");
        }
        assert_eq!(drops.get(), 0);
    }
    assert_eq!(drops.get(), 64);
}

#[test]
fn addresses_stay_stable_across_chunk_growth() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::with_initial_chunk_bytes(256).expect("store creates");
    let mut allocated = Vec::new();
    for index in 0..256 {
        let text = format!("stable-{index}");
        let allocation = store
            .alloc(FlatObjectKind::String, index, 0, payload(&text, &drops))
            .expect("allocation succeeds");
        allocated.push((allocation.ptr, text));
    }
    assert!(store.arena_stats().chunks > 1, "growth crossed a chunk");
    for (ptr, text) in &allocated {
        let object = store
            .resolve(*ptr, FlatObjectKind::String)
            .expect("resolution succeeds");
        assert_eq!(&object.payload().text, text);
    }
}
