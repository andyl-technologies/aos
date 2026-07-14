//! Unit tests for the flat-object store.

use std::cell::Cell;
use std::ptr::NonNull;
use std::rc::Rc;

use super::*;
use crate::value::Value;

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
fn structural_hash_header_can_be_repaired_in_place() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(FlatObjectKind::List, 7, 0, payload("list", &drops))
        .expect("allocation succeeds");

    store
        .update_structural_hash(allocation.ptr, FlatObjectKind::List, 19)
        .expect("header hash updates");

    let object = store
        .resolve(allocation.ptr, FlatObjectKind::List)
        .expect("updated object resolves");
    assert_eq!(object.structural_hash(), 19);
    assert_eq!(object.payload().text, "list");
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
            .alloc_with_trailing_bytes(FlatObjectKind::String, index as u64, 0, &source, |bytes| {
                BytesPayload {
                    bytes,
                    drops: Rc::clone(&drops),
                }
            })
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

#[test]
fn flat_arena_growth_stops_at_the_measured_four_mibibyte_ceiling() {
    let arena = SharedFlatStoreArena::with_initial_chunk_bytes(INITIAL_CHUNK_BYTES)
        .expect("chunked compatibility arena creates");
    assert!(!arena.uses_reservation());
    let sizes = [
        INITIAL_CHUNK_BYTES,
        INITIAL_CHUNK_BYTES * 2,
        INITIAL_CHUNK_BYTES * 4,
        MAX_CHUNK_BYTES,
        MAX_CHUNK_BYTES,
    ];
    for size in sizes {
        arena
            .alloc_raw(size, MAX_ALIGN, FlatObjectKind::String)
            .expect("flat arena allocation succeeds");
    }

    let stats = arena.stats();
    assert_eq!(stats.chunks, sizes.len());
    assert_eq!(stats.used_bytes, sizes.iter().sum());
    assert_eq!(stats.reserved_bytes, sizes.iter().sum());
    assert_eq!(MAX_CHUNK_BYTES, 4 << 20);
}

#[cfg(all(unix, target_pointer_width = "64"))]
#[test]
fn production_shared_arena_places_disjoint_kinds_in_one_reservation() {
    let drops = Rc::new(Cell::new(0));
    let arena = SharedFlatStoreArena::new();
    assert!(arena.uses_reservation());
    let mut strings = FlatObjectStore::with_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::String]),
    );
    let mut lists =
        FlatObjectStore::with_shared_arena(arena.clone(), FlatKindSet::of(&[FlatObjectKind::List]));
    let mut closures = FlatObjectStore::with_rewindable_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::Thunk]),
    )
    .expect("reservation exposes one rewindable lane");
    let string = strings
        .alloc(FlatObjectKind::String, 1, 0, payload("string", &drops))
        .expect("string allocates");
    let list = lists
        .alloc(FlatObjectKind::List, 2, 0, payload("list", &drops))
        .expect("list allocates");
    let closure_mark = closures.region_mark().expect("closure lane marks");
    let closure = closures
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            3,
            0,
            &[Value::int(7)],
            payload("closure", &drops),
        )
        .expect("closure allocates")
        .allocation;

    let string_index = arena
        .index_for_pointer(string.ptr)
        .expect("string has compressed index");
    let list_index = arena
        .index_for_pointer(list.ptr)
        .expect("list has compressed index");
    let closure_index = arena
        .index_for_pointer(closure.ptr)
        .expect("closure has compressed index");
    assert_ne!(string_index, list_index);
    assert!(list_index < closure_index);
    let reservation = arena.reservation_stats().expect("reservation stats exist");
    assert_eq!(
        reservation.virtual_reserved_bytes as u64,
        crate::heap::CANDIDATE_C_ADDRESS_SPACE_BYTES
    );
    assert_eq!(arena.stats().chunks, 1);
    assert_eq!(arena.stats().used_bytes, reservation.used_bytes);
    assert_eq!(
        arena.permanent_stats().used_bytes,
        reservation.low_used_bytes
    );
    assert_eq!(
        closures.arena_stats().used_bytes,
        reservation.high_used_bytes
    );
    assert!(
        closures
            .value_tail(closure.ptr, FlatObjectKind::Thunk)
            .is_ok()
    );

    let pop = closures
        .pop_region(closure_mark)
        .expect("closure lane pops");
    assert_eq!(pop.popped_entries(), 1);
    assert!(pop.arena_report().used_bytes_released() > 0);
    assert!(arena.index_for_pointer(closure.ptr).is_none());
    assert_eq!(
        strings
            .resolve(string.ptr, FlatObjectKind::String)
            .expect("low-lane string survives")
            .payload()
            .text,
        "string"
    );
    drop(closures);
    assert!(
        FlatObjectStore::<Payload>::with_rewindable_shared_arena(
            arena,
            FlatKindSet::of(&[FlatObjectKind::Thunk]),
        )
        .is_some()
    );
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

mod part_1;
