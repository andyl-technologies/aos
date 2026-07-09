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

/// A payload holding an inline-bytes witness, with observable drop glue.
#[derive(Debug)]
struct BytesPayload {
    bytes: FlatBytes,
    drops: Rc<Cell<usize>>,
}

impl Drop for BytesPayload {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn trailing_bytes_are_written_inline_and_resolve_by_witness() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let source = b"inline bytes behind the payload".to_vec();
    let allocation = store
        .alloc_with_trailing_bytes(FlatObjectKind::String, 0xbeef, 3, &source, |bytes| {
            BytesPayload {
                bytes,
                drops: Rc::clone(&drops),
            }
        })
        .expect("allocation succeeds");

    let object = store
        .resolve(allocation.ptr, FlatObjectKind::String)
        .expect("resolution succeeds");
    assert_eq!(object.payload().bytes.as_slice(), source.as_slice());
    assert_eq!(object.payload().bytes.len(), source.len());
    assert!(!object.payload().bytes.is_empty());
    assert_eq!(object.structural_hash(), 0xbeef);

    // The inline bytes live inside this allocation's reservation, directly
    // after the payload struct.
    let bytes_address = object.payload().bytes.as_slice().as_ptr() as usize;
    let object_start = allocation.ptr.as_ptr() as usize;
    assert_eq!(
        bytes_address,
        object_start + std::mem::size_of::<FlatObject<BytesPayload>>()
    );
    assert!(allocation.allocation.reserved_size >= source.len());

    drop(store);
    assert_eq!(drops.get(), 1, "payload drop glue ran exactly once");
}

#[test]
fn trailing_bytes_allocations_interleave_with_plain_allocations() {
    let drops = Rc::new(Cell::new(0));
    let mut store: FlatObjectStore<BytesPayload> =
        FlatObjectStore::with_initial_chunk_bytes(256).expect("store creates");
    let mut allocated = Vec::new();
    for index in 0..128usize {
        let source = format!("payload-{index}").into_bytes();
        let allocation = store
            .alloc_with_trailing_bytes(
                FlatObjectKind::String,
                index as u64,
                0,
                &source,
                |bytes| BytesPayload {
                    bytes,
                    drops: Rc::clone(&drops),
                },
            )
            .expect("allocation succeeds");
        allocated.push((allocation.ptr, source));
    }
    assert!(store.arena_stats().chunks > 1, "growth crossed a chunk");
    for (ptr, source) in &allocated {
        let object = store
            .resolve(*ptr, FlatObjectKind::String)
            .expect("resolution succeeds");
        assert_eq!(object.payload().bytes.as_slice(), source.as_slice());
    }
}

#[test]
fn empty_trailing_bytes_produce_an_empty_witness() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc_with_trailing_bytes(FlatObjectKind::Path, 5, 0, &[], |bytes| BytesPayload {
            bytes,
            drops: Rc::clone(&drops),
        })
        .expect("allocation succeeds");
    let object = store
        .resolve(allocation.ptr, FlatObjectKind::Path)
        .expect("resolution succeeds");
    assert!(object.payload().bytes.is_empty());
    assert_eq!(object.payload().bytes.as_slice(), &[] as &[u8]);
}

#[test]
fn list_kind_allocates_and_resolves_mutably() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(FlatObjectKind::List, 0xabc, 1, payload("spine", &drops))
        .expect("allocation succeeds");

    let object = store
        .resolve(allocation.ptr, FlatObjectKind::List)
        .expect("resolution succeeds");
    assert_eq!(object.kind(), FlatObjectKind::List);
    assert_eq!(object.payload().text, "spine");

    // The writeback door rewrites the payload in place under `&mut self`.
    {
        let payload = store
            .resolve_mut(allocation.ptr, FlatObjectKind::List)
            .expect("mutable resolution succeeds");
        payload.text = "rewritten".to_string();
    }
    let object = store
        .resolve(allocation.ptr, FlatObjectKind::List)
        .expect("resolution succeeds");
    assert_eq!(object.payload().text, "rewritten");
    assert_eq!(
        object.structural_hash(),
        0xabc,
        "payload rewrite leaves the header intact"
    );

    let error = store
        .resolve_mut(allocation.ptr, FlatObjectKind::String)
        .expect_err("kind mismatch is rejected mutably too");
    assert_eq!(
        error,
        FlatObjectError::KindMismatch {
            expected: FlatObjectKind::String,
            actual: FlatObjectKind::List,
            address: allocation.ptr.as_ptr() as usize,
        }
    );

    drop(store);
    // The original payload was overwritten (dropping it) and the replacement
    // dropped with the store: the assignment through `resolve_mut` only
    // replaced the `text` field, so exactly one payload drop runs.
    assert_eq!(drops.get(), 1);
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

/// A metadata-leading composite payload approximating the evaluator's
/// FV-2 flat attrs payload: fixed metadata words followed by entry storage.
#[derive(Debug)]
struct MetadataPayload {
    shape: u32,
    entries: Vec<u64>,
    drops: Rc<Cell<usize>>,
}

impl Drop for MetadataPayload {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn attrs_kind_allocates_and_resolves_mutably_with_stable_metadata() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(
            FlatObjectKind::Attrs,
            0xdef,
            1,
            MetadataPayload {
                shape: 42,
                entries: vec![7, 9],
                drops: Rc::clone(&drops),
            },
        )
        .expect("allocation succeeds");

    let object = store
        .resolve(allocation.ptr, FlatObjectKind::Attrs)
        .expect("resolution succeeds");
    assert_eq!(object.kind(), FlatObjectKind::Attrs);
    assert_eq!(object.payload().shape, 42);
    assert_eq!(object.payload().entries, [7, 9]);

    // The writeback door rewrites entry storage in place under `&mut self`;
    // the metadata words and the header stay intact.
    {
        let payload = store
            .resolve_mut(allocation.ptr, FlatObjectKind::Attrs)
            .expect("mutable resolution succeeds");
        payload.entries[1] = 11;
    }
    let object = store
        .resolve(allocation.ptr, FlatObjectKind::Attrs)
        .expect("resolution succeeds");
    assert_eq!(object.payload().shape, 42);
    assert_eq!(object.payload().entries, [7, 11]);
    assert_eq!(
        object.structural_hash(),
        0xdef,
        "entry rewrite leaves the header intact"
    );

    let error = store
        .resolve(allocation.ptr, FlatObjectKind::List)
        .expect_err("kind mismatch is rejected");
    assert_eq!(
        error,
        FlatObjectError::KindMismatch {
            expected: FlatObjectKind::List,
            actual: FlatObjectKind::Attrs,
            address: allocation.ptr.as_ptr() as usize,
        }
    );

    drop(store);
    assert_eq!(drops.get(), 1);
}

#[test]
fn pop_region_drops_popped_payloads_and_keeps_the_retained_prefix() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let retained = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("retained", &drops))
        .expect("retained allocation succeeds");
    let mark = store.region_mark();
    let popped_a = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("popped-a", &drops))
        .expect("popped allocation succeeds");
    let popped_b = store
        .alloc(FlatObjectKind::Lambda, 0, 0, payload("popped-b", &drops))
        .expect("popped allocation succeeds");
    assert_eq!(store.len(), 3);

    let report = store.pop_region(mark).expect("pop succeeds");
    assert_eq!(report.popped_entries(), 2);
    assert_eq!(store.len(), 1);
    assert_eq!(drops.get(), 2, "popped payloads drop exactly once");

    // The retained object still resolves; the popped addresses fail loudly
    // through the wiped header magic (they stay inside the retained chunk's
    // membership region).
    let object = store
        .resolve(retained.ptr, FlatObjectKind::Thunk)
        .expect("retained object resolves");
    assert_eq!(object.payload().text, "retained");
    for stale in [popped_a.ptr, popped_b.ptr] {
        let error = store
            .resolve(stale, FlatObjectKind::Thunk)
            .map(|object| object.kind())
            .expect_err("stale popped address fails loudly");
        assert_eq!(
            error,
            FlatObjectError::UnknownAddress {
                address: stale.as_ptr() as usize,
            }
        );
    }

    drop(store);
    assert_eq!(drops.get(), 3, "no double drop at store teardown");
}

#[test]
fn pop_region_allows_address_reuse_by_later_allocations() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    // Anchor the chunk below the marker: the pop then rewinds the retained
    // chunk's bump cursor instead of dropping the whole chunk, so the next
    // allocation deterministically reuses the popped address (a dropped
    // chunk's replacement mapping has no stable address, on any platform).
    store
        .alloc(FlatObjectKind::Primop, 0, 0, payload("anchor", &drops))
        .expect("anchor allocation succeeds");
    let mark = store.region_mark();
    let first = store
        .alloc(FlatObjectKind::Primop, 0, 0, payload("first", &drops))
        .expect("allocation succeeds");
    store.pop_region(mark).expect("pop succeeds");

    let second = store
        .alloc(FlatObjectKind::Primop, 0, 0, payload("second", &drops))
        .expect("reallocation succeeds");
    assert_eq!(
        first.ptr, second.ptr,
        "the bump cursor rewound, so the address is reused"
    );
    let object = store
        .resolve(second.ptr, FlatObjectKind::Primop)
        .expect("new object resolves");
    assert_eq!(object.payload().text, "second");
}

#[test]
fn pop_region_rejects_stale_marks_before_dropping_anything() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let mark = store.region_mark();
    store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("live", &drops))
        .expect("allocation succeeds");
    let inner = store.region_mark();
    store.pop_region(mark).expect("outer pop succeeds");

    // The inner mark now describes a longer registry than the store has;
    // rejection happens before any payload drop.
    let error = store.pop_region(inner).expect_err("stale mark is rejected");
    assert_eq!(
        error,
        FlatObjectError::InvalidRegionMark {
            marked_entries: 1,
            current_entries: 0,
        }
    );
    assert_eq!(drops.get(), 1, "only the outer pop dropped a payload");
}

#[test]
fn worker_kinds_round_trip_through_kind_words() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    for kind in [
        FlatObjectKind::Thunk,
        FlatObjectKind::Lambda,
        FlatObjectKind::Primop,
    ] {
        let allocation = store
            .alloc(kind, 0, 0, payload("closure", &drops))
            .expect("allocation succeeds");
        assert_eq!(store.kind_of(allocation.ptr), Some(kind));
        let object = store.resolve(allocation.ptr, kind).expect("resolves");
        assert_eq!(object.kind(), kind);
    }
}
