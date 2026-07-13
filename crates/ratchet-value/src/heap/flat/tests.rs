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
    assert_eq!(arena.permanent_stats().used_bytes, reservation.low_used_bytes);
    assert_eq!(closures.arena_stats().used_bytes, reservation.high_used_bytes);
    assert!(closures.value_tail(closure.ptr, FlatObjectKind::Thunk).is_ok());

    let pop = closures.pop_region(closure_mark).expect("closure lane pops");
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
    assert!(FlatObjectStore::<Payload>::with_rewindable_shared_arena(
        arena,
        FlatKindSet::of(&[FlatObjectKind::Thunk]),
    )
    .is_some());
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
    let mark = store.region_mark().expect("owned-arena mark");
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
    let mark = store.region_mark().expect("owned-arena mark");
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
    let mark = store.region_mark().expect("owned-arena mark");
    store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("live", &drops))
        .expect("allocation succeeds");
    let inner = store.region_mark().expect("owned-arena mark");
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

/// A payload holding typed inline-array witnesses, with observable drop glue.
#[derive(Debug)]
struct ArraysPayload {
    words: FlatSlice<u64>,
    slots: FlatSlice<u32>,
    drops: Rc<Cell<usize>>,
}

impl Drop for ArraysPayload {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn trailing_arrays_are_written_inline_and_resolve_by_witness() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let words: Vec<u64> = (0..37).map(|i| i * 3).collect();
    let slots: Vec<u32> = (0..37).rev().collect();
    let mut tail = FlatTailLayout::new();
    tail.add_slice::<u64>(words.len()).expect("layout fits");
    tail.add_slice::<u32>(slots.len()).expect("layout fits");
    let allocation = store
        .alloc_with_trailing(
            FlatObjectKind::Attrs,
            flat_aux_for_len(words.len()),
            0xdead,
            2,
            tail,
            |writer| {
                Ok(ArraysPayload {
                    words: writer.write_slice(&words)?,
                    slots: writer.write_slice(&slots)?,
                    drops: Rc::clone(&drops),
                })
            },
        )
        .expect("allocation succeeds");

    let object = store
        .resolve(allocation.ptr, FlatObjectKind::Attrs)
        .expect("resolution succeeds");
    assert_eq!(object.payload().words.as_slice(), words.as_slice());
    assert_eq!(object.payload().slots.as_slice(), slots.as_slice());
    assert_eq!(object.aux(), 37);
    assert_eq!(object.structural_hash(), 0xdead);

    // Both runs live inside this allocation's reservation, after the payload
    // struct, in write order at word alignment.
    let object_start = allocation.ptr.as_ptr() as usize;
    let words_address = object.payload().words.as_slice().as_ptr() as usize;
    let slots_address = object.payload().slots.as_slice().as_ptr() as usize;
    assert_eq!(
        words_address,
        object_start + std::mem::size_of::<FlatObject<ArraysPayload>>()
    );
    assert_eq!(words_address % 8, 0);
    assert_eq!(slots_address, words_address + 37 * 8);

    drop(store);
    assert_eq!(drops.get(), 1, "payload drop glue ran exactly once");
}

#[test]
fn registry_backed_value_tail_resolves_and_mutates_exclusively() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let tail_allocation = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(1), Value::int(2)],
            payload("closure", &drops),
        )
        .expect("allocation succeeds");
    let allocation = tail_allocation.allocation;

    let (object, values) = store
        .resolve_with_value_tail(allocation.ptr, FlatObjectKind::Thunk)
        .expect("shared resolution succeeds");
    assert_eq!(object.payload().text, "closure");
    let values = values.expect("value tail is registered");
    assert!(values[0].raw_eq(Value::int(1)));
    assert!(values[1].raw_eq(Value::int(2)));
    let (fast_object, fast_value) = store
        .value_tail_get_at(allocation.store_index, allocation.ptr, 2, 1)
        .expect("registry-index fast path resolves");
    assert_eq!(fast_object.payload().text, "closure");
    assert!(fast_value.is_some_and(|value| value.raw_eq(Value::int(2))));
    let handle = tail_allocation.handle.expect("allocation signs a handle");
    assert_eq!(handle.len(), 2);
    let handle_value = store
        .value_tail_get_handle(allocation.ptr, handle, 1)
        .expect("prevalidated handle resolves");
    assert!(handle_value.is_some_and(|value| value.raw_eq(Value::int(2))));
    let other = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(5), Value::int(6)],
            payload("other-closure", &drops),
        )
        .expect("second allocation succeeds");
    assert!(
        store
            .value_tail_get_handle(other.allocation.ptr, handle, 0)
            .is_err(),
        "the handle rejects another allocation's pointer"
    );
    assert!(
        store
            .resolve_value_tail_at(allocation.store_index, allocation.ptr, 1)
            .is_err(),
        "the fast path rejects a mismatched signed length"
    );

    let (payload, values) = store
        .resolve_mut_with_value_tail_handle(allocation.ptr, handle, FlatObjectKind::Thunk)
        .expect("prevalidated exclusive resolution succeeds");
    assert_eq!(payload.text, "closure");
    values.copy_from_slice(&[Value::int(3), Value::int(4)]);

    let values = store
        .value_tail(allocation.ptr, FlatObjectKind::Thunk)
        .expect("tail resolves")
        .expect("tail remains registered");
    assert!(values[0].raw_eq(Value::int(3)));
    assert!(values[1].raw_eq(Value::int(4)));
    assert!(store.retire_value_tail(allocation.ptr));
    assert!(
        store
            .value_tail_get_handle(allocation.ptr, handle, 0)
            .is_err(),
        "retirement invalidates the prevalidated read handle"
    );
    assert!(
        store
            .resolve_mut_with_value_tail_handle(allocation.ptr, handle, FlatObjectKind::Thunk)
            .is_err(),
        "retirement invalidates the prevalidated write handle"
    );
}

#[test]
fn value_tail_allocation_keeps_wide_runs_without_a_compact_handle() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let values = [Value::null(); 16];
    let tail_allocation = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &values,
            payload("wide-closure", &drops),
        )
        .expect("wide value-tail allocation succeeds");
    assert!(tail_allocation.handle.is_none());
    let resolved = store
        .value_tail(tail_allocation.allocation.ptr, FlatObjectKind::Thunk)
        .expect("wide value tail resolves")
        .expect("wide value tail remains registered");
    assert_eq!(resolved.len(), values.len());
}

#[test]
fn trailing_array_overflow_of_the_planned_layout_is_rejected() {
    let drops = Rc::new(Cell::new(0));
    let mut store: FlatObjectStore<ArraysPayload> = FlatObjectStore::new();
    let mut tail = FlatTailLayout::new();
    tail.add_slice::<u64>(1).expect("layout fits");
    let error = store
        .alloc_with_trailing(FlatObjectKind::Attrs, 0, 0, 0, tail, |writer| {
            let words = writer.write_slice(&[1u64, 2, 3])?;
            Ok(ArraysPayload {
                words,
                slots: writer.write_slice(&[] as &[u32])?,
                drops: Rc::clone(&drops),
            })
        })
        .expect_err("under-planned tail is rejected");
    assert_eq!(error, FlatObjectError::Arena(ArenaError::SizeOverflow));
    assert!(store.is_empty(), "no object was registered");
}

#[test]
fn header_aux_saturates_at_the_field_ceiling() {
    assert_eq!(flat_aux_for_len(0), 0);
    assert_eq!(flat_aux_for_len(7), 7);
    assert_eq!(
        flat_aux_for_len(FLAT_AUX_SATURATED as usize),
        FLAT_AUX_SATURATED
    );
    assert_eq!(flat_aux_for_len(usize::MAX), FLAT_AUX_SATURATED);

    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let plain = store
        .alloc(FlatObjectKind::String, 1, 0, payload("aux-0", &drops))
        .expect("allocation succeeds");
    let object = store
        .resolve(plain.ptr, FlatObjectKind::String)
        .expect("resolution succeeds");
    assert_eq!(object.aux(), 0, "plain allocations carry a zero aux field");

    let tagged = store
        .alloc_with_aux(FlatObjectKind::List, u32::MAX, 2, 0, payload("aux-max", &drops))
        .expect("allocation succeeds");
    let object = store
        .resolve(tagged.ptr, FlatObjectKind::List)
        .expect("resolution succeeds");
    assert_eq!(object.aux(), FLAT_AUX_SATURATED, "oversized aux saturates");
    assert_eq!(object.kind(), FlatObjectKind::List, "aux bits leave the kind intact");
}

#[test]
fn shared_arena_stores_interleave_with_disjoint_kind_sets() {
    let drops = Rc::new(Cell::new(0));
    let arena = SharedFlatStoreArena::new();
    let mut strings: FlatObjectStore<Payload> = FlatObjectStore::with_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::String, FlatObjectKind::Path]),
    );
    let mut lists: FlatObjectStore<Payload> =
        FlatObjectStore::with_shared_arena(arena.clone(), FlatKindSet::of(&[FlatObjectKind::List]));

    let string = strings
        .alloc(FlatObjectKind::String, 1, 0, payload("s", &drops))
        .expect("string allocates");
    let list = lists
        .alloc(FlatObjectKind::List, 2, 0, payload("l", &drops))
        .expect("list allocates");

    // Primary resolution works through each owning store.
    assert_eq!(
        strings
            .resolve(string.ptr, FlatObjectKind::String)
            .expect("string resolves")
            .payload()
            .text,
        "s"
    );
    assert_eq!(
        lists
            .resolve(list.ptr, FlatObjectKind::List)
            .expect("list resolves")
            .payload()
            .text,
        "l"
    );

    // Cross-store kind probes see the foreign object's kind (both stores'
    // membership index covers the shared chunks) ...
    assert_eq!(strings.kind_of(list.ptr), Some(FlatObjectKind::List));
    assert_eq!(lists.kind_of(string.ptr), Some(FlatObjectKind::String));

    // ... but typed resolution of a foreign kind is rejected before any cast,
    // even with the "right" expected kind for the object.
    let error = strings
        .resolve(list.ptr, FlatObjectKind::List)
        .expect_err("foreign kind is rejected");
    assert_eq!(
        error,
        FlatObjectError::KindNotAllowed {
            kind: FlatObjectKind::List,
        }
    );
    let error = strings
        .resolve(list.ptr, FlatObjectKind::String)
        .expect_err("foreign object is a kind mismatch");
    assert_eq!(
        error,
        FlatObjectError::KindMismatch {
            expected: FlatObjectKind::String,
            actual: FlatObjectKind::List,
            address: list.ptr.as_ptr() as usize,
        }
    );

    // Disallowed kinds are rejected at the allocation door too.
    let error = strings
        .alloc(FlatObjectKind::List, 3, 0, payload("nope", &drops))
        .expect_err("disallowed kind is rejected");
    assert_eq!(
        error,
        FlatObjectError::KindNotAllowed {
            kind: FlatObjectKind::List,
        }
    );

    // Region marks and pops are unsupported over the shared arena.
    let error = strings
        .region_mark()
        .expect_err("shared-arena marks are rejected");
    assert_eq!(error, FlatObjectError::SharedArenaRegionUnsupported);

    // The shared arena reports one set of chunks for both stores.
    assert_eq!(strings.arena_stats().chunks, lists.arena_stats().chunks);
    assert_eq!(arena.stats().chunks, strings.arena_stats().chunks);

    // Dropping one store keeps the other store's objects mapped and intact;
    // its payload drop glue runs immediately.
    drop(strings);
    // Two drops so far: the rejected "nope" payload (dropped normally at the
    // allocation door) and the dropped store's "s" payload.
    assert_eq!(drops.get(), 2, "dropped store ran its payload drop glue");
    assert_eq!(
        lists
            .resolve(list.ptr, FlatObjectKind::List)
            .expect("list still resolves")
            .payload()
            .text,
        "l"
    );
    drop(lists);
    assert_eq!(drops.get(), 3);
}

#[test]
fn shared_arena_advice_is_reported_once_through_the_handle() {
    let arena = SharedFlatStoreArena::new();
    let store: FlatObjectStore<Payload> = FlatObjectStore::with_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::String]),
    );
    assert_eq!(store.supported_unused_tail_advice_bytes(), 0);
    let report = store.advise_unused_tail(crate::heap::advice::MemoryAdviceKind::Dead);
    assert_eq!(report.requested_bytes(), 0);
    // The handle carries the real advice door.
    let _ = arena.advise_unused_tail(crate::heap::advice::MemoryAdviceKind::Dead);
    assert!(arena.supported_unused_tail_advice_bytes() <= arena.stats().mapped_bytes);
}
