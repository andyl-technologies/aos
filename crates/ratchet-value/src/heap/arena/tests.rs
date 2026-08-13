//! Tier-A bump-arena unit tests, moved from `arena.rs`'s inline test mod
//! under the RFC-0007 §2 file-size cap (verbatim, dedented one level).

use super::*;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn arena_handles_are_send_sync_for_worker_handoff() {
    assert_send_sync::<BumpArena>();
    assert_send_sync::<ThreadLocalBumpArena>();
}

#[test]
fn empty_arena_has_no_chunks() {
    let arena = BumpArena::new();
    assert!(arena.is_empty());
    assert_eq!(arena.stats(), ArenaStats::default());
}

#[test]
fn empty_arena_advice_reports_no_chunk_tails() {
    let arena = BumpArena::new();
    let report = arena.advise_unused_tail(MemoryAdviceKind::Dead);

    assert_eq!(arena.supported_unused_tail_advice_bytes(), 0);
    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.chunks(), 0);
    assert_eq!(report.requested_bytes(), 0);
    assert_eq!(report.applied(), 0);
    assert_eq!(report.unsupported(), 0);
    assert_eq!(report.empty_ranges(), 0);
    assert_eq!(report.rejected(), 0);
}

#[test]
fn custom_initial_chunk_size_is_word_rounded() {
    let mut arena = BumpArena::with_initial_chunk_bytes(9).expect("arena creates");
    let allocation = arena
        .aos_alloc_raw(1, 1, 7)
        .expect("raw allocation succeeds");
    assert_eq!(allocation.reserved_size, WORD_BYTES);
    let stats = arena.stats();
    assert_eq!(stats.reserved_bytes, 16);
    assert!(stats.mapped_bytes >= system_page_size().expect("page size"));
}

#[test]
fn unused_tail_advice_excludes_live_prefix_and_preserves_accounting() {
    let page_size = system_page_size().expect("page size");
    let chunk_bytes = page_size.checked_mul(2).expect("two pages fit");
    let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes).expect("arena creates");
    let first = arena
        .aos_alloc_raw(1, 1, 7)
        .expect("first allocation succeeds");
    let stats_before = arena.stats();
    let supported_tail_advice_bytes = arena.supported_unused_tail_advice_bytes();

    let report = arena.advise_unused_tail(MemoryAdviceKind::Dead);

    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.chunks(), 1);
    assert_eq!(
        report.requested_bytes(),
        stats_before.mapped_bytes - stats_before.used_bytes
    );
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        1
    );
    #[cfg(target_os = "linux")]
    assert_eq!(report.applied(), 1);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(report.unsupported(), 1);
    #[cfg(target_os = "linux")]
    assert!(supported_tail_advice_bytes > 0);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(supported_tail_advice_bytes, 0);
    assert!(supported_tail_advice_bytes <= report.requested_bytes());
    assert_eq!(arena.stats(), stats_before);

    let second = arena
        .aos_alloc_raw(page_size, 1, 8)
        .expect("advised tail remains allocatable");
    assert!(second.ptr.as_ptr() as usize > first.ptr.as_ptr() as usize);
}

#[test]
fn region_pop_rewinds_current_chunk_and_advises_dead_range() {
    let page_size = system_page_size().expect("page size");
    let chunk_bytes = page_size.checked_mul(3).expect("three pages fit");
    let mut arena = BumpArena::with_initial_chunk_bytes(chunk_bytes).expect("arena creates");
    arena
        .aos_alloc_raw(page_size, 8, 1)
        .expect("prefix allocation succeeds");
    let mark = arena.region_mark();
    let dead = arena
        .aos_alloc_raw(page_size, 8, 2)
        .expect("region allocation succeeds");
    let before = arena.stats();

    // SAFETY: the test never observes `dead` after popping the region, and
    // no typed side table exists for this raw arena allocation.
    let report = unsafe { arena.pop_region_to_mark(mark) }.expect("region pop succeeds");

    assert_eq!(report.before_stats(), before);
    assert_eq!(report.after_stats(), arena.stats());
    assert_eq!(report.after_stats().chunks, 1);
    assert_eq!(report.after_stats().used_bytes, page_size);
    assert_eq!(report.used_bytes_released(), page_size);
    assert_eq!(report.released_mapped_bytes(), 0);
    assert_eq!(report.dead_range_bytes(), page_size);
    match report.dead_range_outcome() {
        MemoryAdviceOutcome::Applied {
            kind: MemoryAdviceKind::Dead,
        }
        | MemoryAdviceOutcome::Unsupported {
            kind: MemoryAdviceKind::Dead,
        }
        | MemoryAdviceOutcome::EmptyRange {
            kind: MemoryAdviceKind::Dead,
        }
        | MemoryAdviceOutcome::Rejected {
            kind: MemoryAdviceKind::Dead,
            ..
        } => {}
        other => panic!("unexpected dead-range advice outcome: {other:?}"),
    }

    let reused = arena
        .aos_alloc_raw(page_size, 8, 3)
        .expect("rewound space is reusable");
    assert_eq!(reused.ptr, dead.ptr);
}

#[test]
fn region_pop_drops_later_chunks_and_restores_growth_state() {
    let mut arena = BumpArena::with_initial_chunk_bytes(16).expect("arena creates");
    arena
        .aos_alloc_raw(16, 8, 1)
        .expect("first chunk allocation succeeds");
    let mark = arena.region_mark();
    arena
        .aos_alloc_raw(24, 8, 2)
        .expect("second chunk allocation succeeds");
    let before = arena.stats();
    assert_eq!(before.chunks, 2);
    assert_eq!(before.reserved_bytes, 48);

    // SAFETY: the allocation in the second chunk is not used after this
    // point, so the marker describes a dead suffix of the arena.
    let report = unsafe { arena.pop_region_to_mark(mark) }.expect("region pop succeeds");

    assert_eq!(report.before_stats(), before);
    assert_eq!(report.after_stats().chunks, 1);
    assert_eq!(report.after_stats().reserved_bytes, 16);
    assert_eq!(report.after_stats().used_bytes, 16);
    assert_eq!(report.used_bytes_released(), 24);
    assert!(report.released_mapped_bytes() >= 32);
    assert_eq!(report.dead_range_bytes(), 0);
    assert_eq!(
        report.dead_range_outcome(),
        MemoryAdviceOutcome::EmptyRange {
            kind: MemoryAdviceKind::Dead,
        }
    );

    arena
        .aos_alloc_raw(24, 8, 3)
        .expect("post-pop allocation succeeds");
    let after_reuse = arena.stats();
    assert_eq!(after_reuse.chunks, 2);
    assert_eq!(
        after_reuse.reserved_bytes, 48,
        "region pop restores next chunk growth to the marker state"
    );
}

#[test]
fn invalid_region_mark_is_rejected_without_side_effects() {
    let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
    arena.aos_alloc_raw(8, 8, 1).expect("allocation succeeds");
    let before = arena.stats();
    let invalid = ArenaRegionMark {
        chunk_count: 1,
        cursor: before.used_bytes + 8,
        next_chunk_bytes: 64,
    };

    // SAFETY: this intentionally invalid marker must be rejected before any
    // arena mutation can invalidate allocations.
    let invalid_pop = unsafe { arena.pop_region_to_mark(invalid) };
    assert_eq!(invalid_pop, Err(ArenaError::InvalidRegionMark));
    assert_eq!(arena.stats(), before);
}

#[test]
fn subpage_unused_tail_has_no_supported_advice_bytes() {
    let mut arena = BumpArena::with_initial_chunk_bytes(128).expect("arena creates");
    arena.aos_alloc_raw(1, 1, 7).expect("allocation succeeds");

    assert_eq!(arena.supported_unused_tail_advice_bytes(), 0);
}

#[test]
fn allocations_are_aligned_and_monotonic_within_a_chunk() {
    let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
    let first = arena
        .aos_alloc_raw(1, 1, 1)
        .expect("first allocation succeeds");
    let second = arena
        .aos_alloc_raw(9, 8, 2)
        .expect("second allocation succeeds");

    let first_addr = first.ptr.as_ptr() as usize;
    let second_addr = second.ptr.as_ptr() as usize;
    assert_eq!(first_addr % 8, 0);
    assert_eq!(second_addr % 8, 0);
    assert!(second_addr > first_addr);
    assert_eq!(first.reserved_size, WORD_BYTES);
    assert_eq!(second.reserved_size, 16);
    assert_eq!(arena.stats().chunks, 1);
    assert_eq!(arena.stats().used_bytes, 24);
}

#[test]
fn arena_grows_geometrically_when_chunks_fill() {
    let mut arena = BumpArena::with_initial_chunk_bytes(16).expect("arena creates");
    let _first = arena
        .aos_alloc_raw(16, 8, 1)
        .expect("first allocation fills first chunk");
    let _second = arena
        .aos_alloc_raw(24, 8, 2)
        .expect("second allocation gets larger chunk");
    let stats = arena.stats();
    assert_eq!(stats.chunks, 2);
    assert_eq!(stats.reserved_bytes, 48);
    assert_eq!(stats.used_bytes, 40);
}

#[test]
fn oversized_allocation_gets_a_dedicated_chunk() {
    let mut arena = BumpArena::with_initial_chunk_bytes(16).expect("arena creates");
    let allocation = arena
        .aos_alloc_raw(80, 8, 1)
        .expect("large allocation succeeds");
    let stats = arena.stats();
    assert_eq!(allocation.reserved_size, 80);
    assert_eq!(stats.chunks, 1);
    assert_eq!(stats.reserved_bytes, 80);
    assert!(stats.mapped_bytes >= stats.reserved_bytes);
    assert_eq!(stats.used_bytes, 80);
}

#[test]
fn entrypoint_layouts_are_stable() {
    let mut arena = BumpArena::with_initial_chunk_bytes(512).expect("arena creates");
    let thunk = arena.aos_alloc_thunk().expect("thunk allocates");
    assert_eq!(thunk.kind, HeapObjectKind::Thunk);
    assert_eq!(thunk.requested_size, THUNK_BYTES);

    let lambda = arena.aos_alloc_lambda().expect("lambda allocates");
    assert_eq!(lambda.kind, HeapObjectKind::Lambda);
    assert_eq!(lambda.requested_size, LAMBDA_BYTES);

    let attrs = arena.aos_alloc_attrs(42, 3).expect("attrset allocates");
    assert_eq!(
        attrs.kind,
        HeapObjectKind::Attrs {
            shape: 42,
            slots: 3,
        }
    );
    assert_eq!(
        attrs.requested_size,
        OBJECT_HEADER_BYTES + 3 * mem::size_of::<Value>()
    );

    let cons = arena.aos_alloc_cons().expect("cons allocates");
    assert_eq!(cons.kind, HeapObjectKind::Cons);
    assert_eq!(cons.requested_size, CONS_BYTES);

    let list = arena.aos_alloc_list(4).expect("list allocates");
    assert_eq!(list.kind, HeapObjectKind::List { len: 4 });
    assert_eq!(
        list.requested_size,
        LIST_ELEMENTS_OFFSET_BYTES + 4 * mem::size_of::<Value>()
    );

    let string = arena.aos_alloc_string(11).expect("string allocates");
    assert_eq!(string.kind, HeapObjectKind::String { len: 11 });
    assert_eq!(string.requested_size, OBJECT_HEADER_BYTES + 11);
}

#[test]
fn invalid_alignment_is_rejected() {
    let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
    assert_eq!(
        arena.aos_alloc_raw(8, 0, 1),
        Err(ArenaError::InvalidAlignment { align: 0 })
    );
    assert_eq!(
        arena.aos_alloc_raw(8, 3, 1),
        Err(ArenaError::InvalidAlignment { align: 3 })
    );
    assert_eq!(
        arena.aos_alloc_raw(8, 16, 1),
        Err(ArenaError::InvalidAlignment { align: 16 })
    );
}

#[test]
fn oversized_list_length_is_rejected_without_side_effects() {
    let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
    let too_long = (u32::MAX as usize)
        .checked_add(1)
        .expect("test platform can represent u32::MAX + 1");

    assert_eq!(
        arena.aos_alloc_list(too_long),
        Err(ArenaError::SizeOverflow)
    );
    assert!(arena.is_empty());
}

#[test]
fn impossible_chunk_allocation_is_reported_without_side_effects() {
    let oversized = (isize::MAX as usize)
        .checked_add(1)
        .expect("test platform has addressable usize range beyond isize");
    let mut arena = BumpArena::with_initial_chunk_bytes(oversized).expect("arena creates");

    assert_eq!(
        arena.aos_alloc_raw(1, 1, 1),
        Err(ArenaError::AllocationFailed { bytes: oversized })
    );
    assert!(arena.is_empty());
}

#[test]
fn zero_sized_raw_allocation_gets_one_word_handle() {
    let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
    let allocation = arena
        .aos_alloc_raw(0, 8, 1)
        .expect("zero-sized raw allocation succeeds");
    assert_eq!(allocation.requested_size, 0);
    assert_eq!(allocation.reserved_size, WORD_BYTES);
    assert_eq!(arena.stats().used_bytes, WORD_BYTES);
}

#[test]
fn thread_local_arena_is_independent_per_worker() {
    ThreadLocalBumpArena::reset_current();
    let main_addr = ThreadLocalBumpArena::with_current(|arena| {
        arena
            .aos_alloc_raw(8, 8, 1)
            .expect("main allocation succeeds")
            .ptr
            .as_ptr() as usize
    });
    let main_stats = ThreadLocalBumpArena::with_current(|arena| arena.stats());

    let worker = std::thread::spawn(|| {
        ThreadLocalBumpArena::reset_current();
        let before = ThreadLocalBumpArena::with_current(|arena| arena.stats());
        let addr = ThreadLocalBumpArena::with_current(|arena| {
            arena
                .aos_alloc_raw(8, 8, 2)
                .expect("worker allocation succeeds")
                .ptr
                .as_ptr() as usize
        });
        let after = ThreadLocalBumpArena::with_current(|arena| arena.stats());
        ThreadLocalBumpArena::reset_current();
        (before, after, addr)
    })
    .join()
    .expect("worker thread joins");

    assert_eq!(main_stats.chunks, 1);
    assert_eq!(worker.0, ArenaStats::default());
    assert_eq!(worker.1.chunks, 1);
    assert_ne!(main_addr, worker.2);
    ThreadLocalBumpArena::reset_current();
}
