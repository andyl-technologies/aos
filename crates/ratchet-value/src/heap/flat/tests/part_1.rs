//! Split-out flat-store tests (part_1). See parent module.
use super::*;

#[derive(Debug)]
struct LargeMovePayload {
    edge: usize,
    bytes: [u8; 8192],
    drops: Rc<Cell<usize>>,
}

impl Drop for LargeMovePayload {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn plain_relocation_moves_ownership_and_tombstones_the_source() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let source = store
        .alloc(
            FlatObjectKind::Primop,
            0xfeed_beef,
            17,
            payload("moved", &drops),
        )
        .expect("plain object allocates");

    let moved = store
        .relocate_plain_with(source.ptr, FlatObjectKind::Primop, |payload| {
            payload.text.make_ascii_uppercase();
        })
        .expect("plain object rewrites and relocates");

    assert_eq!(moved.source, source.ptr);
    assert_ne!(moved.destination.ptr, source.ptr);
    assert_eq!(moved.destination.store_index, 1);
    assert_eq!(store.len(), 2, "the source registry coordinate remains");
    assert_eq!(store.live_len(), 1, "only the destination stays live");
    assert_eq!(
        store
            .resolve(source.ptr, FlatObjectKind::Primop)
            .expect_err("the source header was wiped"),
        FlatObjectError::UnknownAddress {
            address: source.ptr.as_ptr() as usize,
        }
    );

    let destination = store
        .resolve(moved.destination.ptr, FlatObjectKind::Primop)
        .expect("the destination resolves");
    assert_eq!(destination.payload().text, "MOVED");
    assert_eq!(destination.structural_hash(), 0xfeed_beef);
    assert_eq!(destination.last_touch_epoch(), 17);
    assert_eq!(drops.get(), 0, "relocation transfers rather than drops");

    drop(store);
    assert_eq!(drops.get(), 1, "the moved payload is dropped exactly once");
}

#[test]
fn relocation_rejects_inline_tail_without_changing_the_source() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let source = store
        .alloc_with_trailing_bytes(FlatObjectKind::String, 41, 3, b"inline", |_| {
            payload("retained", &drops)
        })
        .expect("tailed object allocates");

    let error = store
        .relocate_plain(source.ptr, FlatObjectKind::String)
        .expect_err("a self-relative inline tail requires a kind-specific mover");
    assert!(matches!(
        error,
        FlatObjectError::RelocationRequiresPlainObject { address, .. }
            if address == source.ptr.as_ptr() as usize
    ));
    assert_eq!(store.len(), 1, "rejection does not reserve a registry slot");
    assert_eq!(store.live_len(), 1);
    let retained = store
        .resolve(source.ptr, FlatObjectKind::String)
        .expect("the rejected source remains intact");
    assert_eq!(retained.payload().text, "retained");
    assert_eq!(retained.structural_hash(), 41);
    assert_eq!(retained.last_touch_epoch(), 3);

    drop(store);
    assert_eq!(drops.get(), 1);
}

#[test]
fn shared_plain_relocation_releases_only_source_owned_pages() {
    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        return;
    }
    let mut store = FlatObjectStore::<[u8; 8192]>::with_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::String]),
    );
    let source = store
        .alloc(FlatObjectKind::String, 7, 0, [0x5a; 8192])
        .expect("large plain source allocates");
    let moved = store
        .relocate_plain(source.ptr, FlatObjectKind::String)
        .expect("large plain source relocates");

    let report = arena
        .advise_zero_liveness_pages()
        .expect("reservation page accounting is available")
        .expect("retired source-page scan succeeds");
    assert!(
        report.candidate_pages() >= 2,
        "full pages owned only by the moved source become reclaimable"
    );
    let destination = store
        .resolve(moved.destination.ptr, FlatObjectKind::String)
        .expect("destination remains live after source-page advice");
    assert_eq!(
        destination.payload()[0],
        0x5a,
        "advice excludes destination-intersecting pages"
    );
    assert_eq!(destination.payload()[8191], 0x5a);
}

#[test]
fn cross_domain_relocation_rewrites_and_transfers_ownership() {
    let source_arena = SharedFlatStoreArena::new();
    let destination_arena = SharedFlatStoreArena::new();
    if !source_arena.uses_reservation() || !destination_arena.uses_reservation() {
        return;
    }
    assert_ne!(
        source_arena.arena_domain_id(),
        destination_arena.arena_domain_id(),
        "independent Candidate-C reservations have distinct domains"
    );

    let kinds = FlatKindSet::of(&[FlatObjectKind::Primop]);
    let drops = Rc::new(Cell::new(0));
    let mut source_store = FlatObjectStore::with_shared_arena(source_arena.clone(), kinds.clone());
    let mut destination_store =
        FlatObjectStore::with_shared_arena(destination_arena.clone(), kinds);
    let source = source_store
        .alloc(
            FlatObjectKind::Primop,
            0xdecaf,
            23,
            LargeMovePayload {
                edge: 41,
                bytes: [0xa5; 8192],
                drops: Rc::clone(&drops),
            },
        )
        .expect("large plain source allocates");

    let moved = source_store
        .relocate_plain_to_with(
            &mut destination_store,
            source.ptr,
            FlatObjectKind::Primop,
            |payload| payload.edge = 99,
        )
        .expect("cross-domain relocation commits");
    assert_eq!(source_store.len(), 1);
    assert_eq!(source_store.live_len(), 0);
    assert_eq!(destination_store.len(), 1);
    assert_eq!(destination_store.live_len(), 1);
    assert_eq!(drops.get(), 0, "movement does not drop the payload");

    let source_advice = source_arena
        .advise_zero_liveness_pages()
        .expect("source reservation tracks page liveness")
        .expect("source dead-page scan succeeds");
    assert!(
        source_advice.candidate_pages() >= 2,
        "the retired large source contributes reclaimable pages"
    );
    let destination = destination_store
        .resolve(moved.destination.ptr, FlatObjectKind::Primop)
        .expect("destination resolves in its independent arena");
    assert_eq!(destination.payload().edge, 99);
    assert_eq!(destination.payload().bytes[0], 0xa5);
    assert_eq!(destination.payload().bytes[8191], 0xa5);
    assert_eq!(destination.structural_hash(), 0xdecaf);
    assert_eq!(destination.last_touch_epoch(), 23);

    drop(source_store);
    assert_eq!(drops.get(), 0, "the tombstoned source owns no payload");
    drop(destination_store);
    assert_eq!(
        drops.get(),
        1,
        "the destination drops ownership exactly once"
    );
}

#[test]
fn cross_store_relocation_failure_precedes_source_mutation() {
    let drops = Rc::new(Cell::new(0));
    let rewritten = Cell::new(false);
    let mut source_store = FlatObjectStore::new();
    let destination_arena = SharedFlatStoreArena::new();
    let mut destination_store = FlatObjectStore::with_shared_arena(
        destination_arena,
        FlatKindSet::of(&[FlatObjectKind::String]),
    );
    let source = source_store
        .alloc(FlatObjectKind::Primop, 73, 5, payload("unchanged", &drops))
        .expect("source allocates");

    let error = source_store
        .relocate_plain_to_with(
            &mut destination_store,
            source.ptr,
            FlatObjectKind::Primop,
            |_| rewritten.set(true),
        )
        .expect_err("destination rejects the source kind");
    assert_eq!(
        error,
        FlatObjectError::KindNotAllowed {
            kind: FlatObjectKind::Primop,
        }
    );
    assert!(!rewritten.get(), "preflight failure skips the callback");
    assert_eq!(destination_store.len(), 0);
    let retained = source_store
        .resolve(source.ptr, FlatObjectKind::Primop)
        .expect("source remains live");
    assert_eq!(retained.payload().text, "unchanged");
    assert_eq!(retained.structural_hash(), 73);
    assert_eq!(retained.last_touch_epoch(), 5);
    drop(source_store);
    assert_eq!(drops.get(), 1);
}

#[test]
fn cross_store_relocation_rejects_shared_physical_backing() {
    let arena = SharedFlatStoreArena::new();
    let kinds = FlatKindSet::of(&[FlatObjectKind::Primop]);
    let drops = Rc::new(Cell::new(0));
    let mut source_store = FlatObjectStore::with_shared_arena(arena.clone(), kinds.clone());
    let mut destination_store = FlatObjectStore::with_shared_arena(arena, kinds);
    let source = source_store
        .alloc(FlatObjectKind::Primop, 11, 0, payload("live", &drops))
        .expect("source allocates");

    let error = source_store
        .relocate_plain_to(&mut destination_store, source.ptr, FlatObjectKind::Primop)
        .expect_err("aliased physical backing is rejected");
    assert_eq!(
        error,
        FlatObjectError::RelocationRequiresDistinctBacking {
            address: source.ptr.as_ptr() as usize,
        }
    );
    assert_eq!(source_store.live_len(), 1);
    assert_eq!(destination_store.len(), 0);
    drop(source_store);
    assert_eq!(drops.get(), 1);
}

#[test]
fn shared_page_advice_waits_until_every_intersecting_object_retires() {
    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        return;
    }
    let mut store = FlatObjectStore::<()>::with_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::String]),
    );
    let bytes = vec![0x5a; 8192];
    let allocation = store
        .alloc_with_trailing_bytes(FlatObjectKind::String, 0, 0, &bytes, |_| ())
        .expect("multi-page object allocates");

    let live = arena
        .advise_zero_liveness_pages()
        .expect("reservation page accounting is available")
        .expect("live-page scan succeeds");
    assert_eq!(
        live.candidate_pages(),
        0,
        "an intersecting live object pins every full used page"
    );

    store
        .retire(allocation.ptr, FlatObjectKind::String)
        .expect("multi-page object retires");
    let retired = arena
        .advise_zero_liveness_pages()
        .expect("reservation page accounting remains available")
        .expect("retired-page scan succeeds");
    assert!(
        retired.candidate_pages() >= 2,
        "whole pages become safely reclaimable only after payload drop"
    );
}

#[test]
fn headerless_block_keeps_its_pages_live() {
    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        return;
    }
    let mut lane =
        HeaderlessFlatLane::<[u8; 4096]>::with_block_slots(arena.clone(), FlatObjectKind::Thunk, 2)
            .expect("headerless lane geometry is valid");
    lane.alloc([7; 4096])
        .expect("headerless allocation succeeds");

    let report = arena
        .advise_zero_liveness_pages()
        .expect("reservation page accounting is available")
        .expect("live-page scan succeeds");
    assert_eq!(
        report.candidate_pages(),
        0,
        "the whole raw fixed-lane block stays pinned"
    );
}

#[test]
fn high_lane_rewind_never_exposes_reused_live_pages_as_zero() {
    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        return;
    }
    let mut store = FlatObjectStore::<()>::with_rewindable_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::Thunk]),
    )
    .expect("reservation supports a rewindable store");
    let mark = store.region_mark().expect("high-lane mark is valid");
    let bytes = vec![0xa5; 8192];
    store
        .alloc_with_trailing_bytes(FlatObjectKind::Thunk, 0, 0, &bytes, |_| ())
        .expect("first high-lane object allocates");
    store.pop_region(mark).expect("high lane rewinds");
    store
        .alloc_with_trailing_bytes(FlatObjectKind::Thunk, 0, 0, &bytes, |_| ())
        .expect("replacement object reuses the high lane");

    let report = arena
        .advise_zero_liveness_pages()
        .expect("reservation page accounting is available")
        .expect("live-page scan succeeds");
    assert_eq!(
        report.candidate_pages(),
        0,
        "reused pages are counted before the replacement object escapes"
    );
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
fn retire_drops_exactly_once_and_hides_the_tombstone_from_iteration() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let retained = store
        .alloc(FlatObjectKind::String, 0, 0, payload("retained", &drops))
        .expect("retained allocation succeeds");
    let retired = store
        .alloc(FlatObjectKind::Path, 0, 0, payload("retired", &drops))
        .expect("retired allocation succeeds");

    store
        .retire(retired.ptr, FlatObjectKind::Path)
        .expect("exact allocation retires");
    assert_eq!(drops.get(), 1, "retirement drops the payload once");
    assert_eq!(store.len(), 2, "the stable registry slot remains present");
    assert_eq!(store.live_len(), 1);
    assert_eq!(
        store.iter().map(FlatStoredObject::ptr).collect::<Vec<_>>(),
        [retained.ptr],
        "iteration omits tombstones"
    );
    assert_eq!(
        store
            .resolve(retired.ptr, FlatObjectKind::Path)
            .expect_err("the wiped header rejects stale resolution"),
        FlatObjectError::UnknownAddress {
            address: retired.ptr.as_ptr() as usize,
        }
    );
    assert_eq!(
        store
            .retire(retired.ptr, FlatObjectKind::Path)
            .expect_err("a tombstone cannot be retired twice"),
        FlatObjectError::UnknownAddress {
            address: retired.ptr.as_ptr() as usize,
        }
    );

    drop(store);
    assert_eq!(
        drops.get(),
        2,
        "store teardown drops only the retained payload"
    );
}

#[test]
fn selected_retirement_validates_all_entries_before_infallible_commit() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let first = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("first", &drops))
        .expect("first allocation succeeds");
    let retained = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("retained", &drops))
        .expect("retained allocation succeeds");
    let second = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("second", &drops))
        .expect("second allocation succeeds");

    let retirement = store
        .prepare_retire_live_subset([first.ptr, second.ptr])
        .expect("selected entries validate");
    assert_eq!(retirement.commit(), 2);

    assert_eq!(drops.get(), 2);
    assert_eq!(store.len(), 3);
    assert_eq!(store.live_len(), 1);
    assert_eq!(
        store
            .resolve(retained.ptr, FlatObjectKind::Thunk)
            .expect("unselected entry remains live")
            .payload()
            .text,
        "retained"
    );
    assert!(store.resolve(first.ptr, FlatObjectKind::Thunk).is_err());
    assert!(store.resolve(second.ptr, FlatObjectKind::Thunk).is_err());
}

#[test]
fn selected_retirement_rejects_duplicates_without_mutation() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let allocation = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("live", &drops))
        .expect("allocation succeeds");

    assert!(
        store
            .prepare_retire_live_subset([allocation.ptr, allocation.ptr])
            .is_err()
    );
    assert_eq!(drops.get(), 0);
    assert_eq!(store.len(), 1);
    assert!(store.resolve(allocation.ptr, FlatObjectKind::Thunk).is_ok());
}

#[test]
fn retire_invalidates_tail_handle_without_reusing_its_registry_index() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let retired = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(1)],
            payload("retired", &drops),
        )
        .expect("tail allocation succeeds");
    let stale = retired.handle.expect("compact handle is available");

    store
        .retire(retired.allocation.ptr, FlatObjectKind::Thunk)
        .expect("tail owner retires");
    assert_eq!(drops.get(), 1);
    assert_eq!(store.value_tail_handle_owner(stale), None);
    assert!(
        store.resolve_value_tail_handle_owner(stale).is_err(),
        "the tombstone rejects stale tail resolution"
    );

    let later = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(2)],
            payload("later", &drops),
        )
        .expect("later tail allocation succeeds");
    assert_eq!(
        later.allocation.store_index,
        retired.allocation.store_index + 1,
        "new allocations append after tombstoned registry slots"
    );
    assert!(
        store.resolve_value_tail_handle_owner(stale).is_err(),
        "a later allocation cannot revive the stale coordinate"
    );
    let current = later.handle.expect("later compact handle is available");
    let (_, _, values) = store
        .resolve_value_tail_handle_owner(current)
        .expect("the later coordinate resolves");
    assert!(values[0].raw_eq(Value::int(2)));

    drop(store);
    assert_eq!(drops.get(), 2, "each payload drops exactly once");
}

#[test]
fn complete_retirement_reset_reuses_index_without_reviving_tail_handle() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let old = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(1)],
            payload("old", &drops),
        )
        .expect("old tail allocation succeeds");
    let stale = old.handle.expect("old compact handle is available");

    let retirement = store
        .prepare_retire_all_live()
        .expect("complete store validates");
    assert_eq!(retirement.commit_and_reset(), 1);
    assert_eq!(store.len(), 0);
    assert_eq!(store.live_len(), 0);
    assert_eq!(drops.get(), 1);

    let replacement = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(2)],
            payload("replacement", &drops),
        )
        .expect("replacement tail allocation succeeds");
    assert_eq!(replacement.allocation.store_index, 0);
    assert!(
        store.resolve_value_tail_handle_owner(stale).is_err(),
        "monotonic generation rejects the stale reused registry index"
    );
    let current = replacement
        .handle
        .expect("replacement compact handle is available");
    assert_ne!(current, stale);
    let (_, _, values) = store
        .resolve_value_tail_handle_owner(current)
        .expect("replacement handle resolves");
    assert!(values[0].raw_eq(Value::int(2)));
}

#[test]
fn pop_region_skips_retired_tombstones_in_its_suffix() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    let retained = store
        .alloc(FlatObjectKind::Primop, 0, 0, payload("retained", &drops))
        .expect("retained allocation succeeds");
    let mark = store.region_mark().expect("owned-arena mark");
    let retired = store
        .alloc(FlatObjectKind::Thunk, 0, 0, payload("retired", &drops))
        .expect("suffix allocation succeeds");
    store
        .retire(retired.ptr, FlatObjectKind::Thunk)
        .expect("suffix allocation retires");

    let report = store.pop_region(mark).expect("region pop succeeds");
    assert_eq!(
        report.popped_entries(),
        0,
        "the tombstone has no payload left to drop"
    );
    assert_eq!(drops.get(), 1, "region pop does not drop it again");
    assert_eq!(store.len(), 1);
    assert_eq!(store.live_len(), 1);
    assert_eq!(
        store
            .resolve(retained.ptr, FlatObjectKind::Primop)
            .expect("retained prefix remains live")
            .payload()
            .text,
        "retained"
    );

    drop(store);
    assert_eq!(drops.get(), 2, "the retained payload drops at teardown");
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
fn value_tail_handle_generation_rejects_reused_registry_slot() {
    let drops = Rc::new(Cell::new(0));
    let mut store = FlatObjectStore::new();
    store
        .alloc(FlatObjectKind::Primop, 0, 0, payload("anchor", &drops))
        .expect("anchor allocation succeeds");
    let mark = store.region_mark().expect("owned-arena mark");
    let first = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(1)],
            payload("first", &drops),
        )
        .expect("first tail allocation succeeds");
    let stale = first.handle.expect("first allocation signs a handle");
    store.pop_region(mark).expect("pop succeeds");

    let second = store
        .alloc_with_value_tail(
            FlatObjectKind::Thunk,
            0,
            0,
            &[Value::int(2)],
            payload("second", &drops),
        )
        .expect("second tail allocation succeeds");
    let current = second.handle.expect("second allocation signs a handle");
    assert_eq!(
        first.allocation.store_index, second.allocation.store_index,
        "the registry slot is reused"
    );
    assert_eq!(
        first.allocation.ptr, second.allocation.ptr,
        "the arena address is reused"
    );
    assert!(
        store.resolve_value_tail_handle_owner(stale).is_err(),
        "the old generation cannot alias the replacement tail"
    );
    let (_, _, values) = store
        .resolve_value_tail_handle_owner(current)
        .expect("the replacement generation resolves");
    assert!(values[0].raw_eq(Value::int(2)));
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
        FlatObjectKind::ThunkHead,
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

/// A Drop-free, `Arc`-free payload holding one inline-array witness — safe to
/// dump and reload for the serialize-and-patch survival test.
#[cfg(feature = "candidate_c_value")]
#[derive(Debug)]
struct RebasePayload {
    words: FlatSlice<u64>,
}

/// Stage B / decision 6 (RFC-0007 doc 31 §1): a `FlatSlice` witness inlined in a
/// reservation survives a heap-image dump + reload when its interior pointer is
/// rebased by `new_base − old_base` on restore — the serialize-and-patch path
/// that replaces the reverted make-address-free approach.
#[cfg(feature = "candidate_c_value")]
#[test]
fn flat_slice_witness_survives_a_snapshot_via_rebase() {
    use crate::heap::reservation_base;
    use crate::heap::snapshot::{HeapImage, capture_reservation, restore_reservation};

    let arena = SharedFlatStoreArena::new();
    if !arena.uses_reservation() {
        return; // the chunked fallback is not snapshottable
    }
    let mut store = FlatObjectStore::with_shared_arena(
        arena.clone(),
        FlatKindSet::of(&[FlatObjectKind::Attrs]),
    );
    let words: Vec<u64> = (0..29).map(|i| i * 11 + 3).collect();
    let mut tail = FlatTailLayout::new();
    tail.add_slice::<u64>(words.len()).expect("layout fits");
    let allocation = store
        .alloc_with_trailing(
            FlatObjectKind::Attrs,
            flat_aux_for_len(words.len()),
            0xb17e,
            1,
            tail,
            |writer| {
                Ok(RebasePayload {
                    words: writer.write_slice(&words)?,
                })
            },
        )
        .expect("allocation succeeds");

    let domain = arena.arena_domain_id().expect("reservation-backed");
    let index = arena
        .index_for_pointer(allocation.ptr)
        .expect("has an index");
    let old_base = reservation_base(domain).expect("domain registered");

    let image = capture_reservation(&arena).expect("captures the reservation");
    let bytes = image.to_bytes();
    drop(store);
    drop(arena);

    let reloaded = HeapImage::from_bytes(&bytes).expect("parses the image");
    let restored = restore_reservation(&reloaded).expect("restores the reservation");
    let new_base = reservation_base(domain).expect("domain re-registered");
    let delta = new_base as isize - old_base as isize;

    let mut store2: FlatObjectStore<RebasePayload> = FlatObjectStore::with_shared_arena(
        restored.clone(),
        FlatKindSet::of(&[FlatObjectKind::Attrs]),
    );
    store2.adopt_shared_regions();
    let ptr2 = restored
        .pointer_for_index(index)
        .expect("index resolves in the restored arena");

    // The witness copied verbatim still holds `old_base + run_offset`; patch it.
    store2
        .resolve_mut(ptr2, FlatObjectKind::Attrs)
        .expect("resolves for rebase")
        .words
        .rebase(delta);

    let object = store2
        .resolve(ptr2, FlatObjectKind::Attrs)
        .expect("resolves after rebase");
    assert_eq!(object.payload().words.as_slice(), words.as_slice());
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
    let (handle_owner, handle_object, handle_values) = store
        .resolve_value_tail_handle_owner(handle)
        .expect("the handle identifies its owner");
    assert_eq!(handle_owner, allocation.ptr);
    assert_eq!(handle_object.payload().text, "closure");
    assert!(handle_values[0].raw_eq(Value::int(1)));
    let ownerless_value = store
        .value_tail_get_handle_owner(handle, 1)
        .expect("ownerless prevalidated handle resolves");
    assert!(ownerless_value.is_some_and(|value| value.raw_eq(Value::int(2))));
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
        store.resolve_value_tail_handle_owner(handle).is_err(),
        "retirement invalidates owner recovery"
    );
    assert!(
        store
            .value_tail_get_handle_owner(handle, handle.len())
            .is_err(),
        "a stale handle fails before an out-of-range read can return None"
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
        .alloc_with_aux(
            FlatObjectKind::List,
            u32::MAX,
            2,
            0,
            payload("aux-max", &drops),
        )
        .expect("allocation succeeds");
    let object = store
        .resolve(tagged.ptr, FlatObjectKind::List)
        .expect("resolution succeeds");
    assert_eq!(object.aux(), FLAT_AUX_SATURATED, "oversized aux saturates");
    assert_eq!(
        object.kind(),
        FlatObjectKind::List,
        "aux bits leave the kind intact"
    );
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
