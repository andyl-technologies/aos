//! Evaluator-heap unit tests, part 2 of 16 (RFC-0007 §2 split, #9).
//!
//! Move-only item-boundary split of the `tests.rs` inline body; each
//! test keeps its `#[cfg]`/doc prefix. No test changed.

#![allow(unused_imports)]

use super::super::*;
use super::*;


#[test]
fn worker_region_epoch_overflow_rotates_region_owner() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let owner = heap.region_owner;
    heap.worker_region_epoch = u64::MAX;

    heap.advance_worker_region_epoch();

    assert_ne!(heap.region_owner, owner);
    assert_eq!(heap.worker_region_epoch, 0);
    assert_eq!(heap.worker_allocator_epoch, 0);
}


#[test]
fn worker_allocator_epoch_overflow_rotates_region_owner() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let owner = heap.region_owner;
    heap.worker_allocator_epoch = u64::MAX;

    heap.advance_worker_allocator_epoch();

    assert_ne!(heap.region_owner, owner);
    assert_eq!(heap.worker_allocator_epoch, 0);
    assert_eq!(heap.worker_region_epoch, 0);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn thunk_resolve_write_barrier_records_permanent_to_young_forced_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    let forced = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("forced lambda allocates");
    set_allocation_domain(&mut heap, source, HeapAllocationDomain::PermanentShared);
    let source_thunk = heap.clone_thunk(source).expect("source thunk exists");
    let crate::eval::ForceClaim::Claimed(guard) =
        source_thunk.cell().begin_force().expect("claim succeeds")
    else {
        panic!("new thunk should be claimable");
    };
    let mut remembered_set = RememberedSet::new();
    let mut barrier = heap
        .thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            source,
            &mut remembered_set,
        )
        .expect("barrier creates");

    let published = guard
        .finish_with_barrier(forced, &mut barrier)
        .expect("barrier allows publish");

    let edge = RememberedEdge::new(gc_address(source), gc_address(forced));
    assert!(published.raw_eq(forced));
    assert_eq!(barrier.tier(), GenerationalGcTier::DaemonGenerational);
    assert_eq!(barrier.source(), edge.source());
    assert_eq!(barrier.source_generation(), HeapGeneration::Permanent);
    assert_eq!(
        barrier.last_action(),
        Some(ThunkResolveWriteBarrier::Remember { edge })
    );
    assert_eq!(barrier.remembered_set().edges(), &[edge]);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn thunk_resolve_write_barrier_marks_card_for_permanent_to_young_forced_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    let forced = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("forced lambda allocates");
    set_allocation_domain(&mut heap, source, HeapAllocationDomain::PermanentShared);
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();
    let mut barrier = heap
        .thunk_resolve_write_barrier_with_card_table(
            GenerationalGcTier::DaemonGenerational,
            source,
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier creates");

    let action = barrier
        .record(forced)
        .expect("barrier records edge and card");

    let edge = RememberedEdge::new(gc_address(source), gc_address(forced));
    assert_eq!(action, ThunkResolveWriteBarrier::Remember { edge });
    assert_eq!(barrier.remembered_set().edges(), &[edge]);
    let card_table = barrier.card_table().expect("card table is attached");
    assert_eq!(card_table.len(), 1);
    assert_eq!(card_table.dirty_cards()[0].source(), edge.source());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn thunk_resolve_write_barrier_skips_inline_forced_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    set_allocation_domain(&mut heap, source, HeapAllocationDomain::PermanentShared);
    let mut remembered_set = RememberedSet::new();
    let mut barrier = heap
        .thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            source,
            &mut remembered_set,
        )
        .expect("barrier creates");

    let action = barrier
        .record(Value::int(7))
        .expect("inline value needs no edge");

    assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
    assert_eq!(
        barrier.last_action(),
        Some(ThunkResolveWriteBarrier::NotRequired)
    );
    assert!(barrier.remembered_set().is_empty());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn thunk_resolve_write_barrier_skips_external_forced_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("source thunk allocates");
    let external =
        Value::external(NonNull::<HeapObject>::dangling()).expect("external pointer builds");
    set_allocation_domain(&mut heap, source, HeapAllocationDomain::PermanentShared);
    let mut remembered_set = RememberedSet::new();
    let mut barrier = heap
        .thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            source,
            &mut remembered_set,
        )
        .expect("barrier creates");

    let action = barrier
        .record(external)
        .expect("external value needs no edge");

    assert_eq!(action, ThunkResolveWriteBarrier::NotRequired);
    assert_eq!(
        barrier.last_action(),
        Some(ThunkResolveWriteBarrier::NotRequired)
    );
    assert!(barrier.remembered_set().is_empty());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn thunk_resolve_write_barrier_records_its_source_when_guard_is_mispaired() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let barrier_source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("barrier source thunk allocates");
    let forced_source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("forced source thunk allocates");
    let forced = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(4),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("forced lambda allocates");
    set_allocation_domain(
        &mut heap,
        barrier_source,
        HeapAllocationDomain::PermanentShared,
    );
    set_allocation_domain(
        &mut heap,
        forced_source,
        HeapAllocationDomain::PermanentShared,
    );
    let forced_thunk = heap
        .clone_thunk(forced_source)
        .expect("forced thunk exists");
    let crate::eval::ForceClaim::Claimed(guard) =
        forced_thunk.cell().begin_force().expect("claim succeeds")
    else {
        panic!("new thunk should be claimable");
    };
    let mut remembered_set = RememberedSet::new();
    let mut barrier = heap
        .thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            barrier_source,
            &mut remembered_set,
        )
        .expect("barrier creates");

    let published = guard
        .finish_with_barrier(forced, &mut barrier)
        .expect("barrier allows publish");

    let edge = RememberedEdge::new(gc_address(barrier_source), gc_address(forced));
    assert!(published.raw_eq(forced));
    assert_ne!(barrier.source(), gc_address(forced_source));
    assert_eq!(
        barrier.last_action(),
        Some(ThunkResolveWriteBarrier::Remember { edge })
    );
    assert_eq!(barrier.remembered_set().edges(), &[edge]);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn thunk_resolve_write_barrier_rejects_non_thunk_sources() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lambda allocates");
    let mut remembered_set = RememberedSet::new();

    let error = heap
        .thunk_resolve_write_barrier(
            GenerationalGcTier::DaemonGenerational,
            source,
            &mut remembered_set,
        )
        .expect_err("non-thunk source is rejected");

    assert_eq!(
        error,
        EvalHeapError::ThunkResolveBarrierSourceNotThunk {
            actual: ValueTag::Lambda
        }
    );
    assert!(remembered_set.is_empty());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn allocates_string_values_and_recovers_contents() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(64).expect("heap creates");
    let value = heap
        .alloc_string(NixString::from_bytes(b"hello".to_vec()))
        .expect("string allocates");

    assert_eq!(value.tag(), ValueTag::String);
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_string(value).expect("string exists").bytes(),
        b"hello"
    );
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cold_hash_consed_bytes_follow_permanent_record_touches() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"cold".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);

    assert_eq!(heap.access_epoch(), 1);
    assert_eq!(heap.cold_hash_consed_bytes(0), string_size);
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    assert_eq!(heap.access_epoch(), 2);
    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
    assert_eq!(heap.cold_hash_consed_bytes(2), 0);

    assert_eq!(
        heap.get_string(string).expect("string exists").bytes(),
        b"cold"
    );

    assert_eq!(heap.access_epoch(), 3);
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);

    heap.alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second thunk allocates");

    assert_eq!(heap.access_epoch(), 4);
    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cold_hash_consed_values_snapshot_does_not_refresh_touch_epoch() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"snapshot-cold".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    let values = heap
        .cold_hash_consed_values(1)
        .expect("cold values snapshot succeeds");

    assert_eq!(values.len(), 1);
    assert!(values[0].value().raw_eq(string));
    assert_eq!(values[0].size_bytes(), string_size);
    assert_eq!(values[0].idle_epochs(), 1);
    assert_eq!(
        heap.cold_hash_consed_bytes(1),
        string_size,
        "snapshotting must not make the cold value hot"
    );

    assert_eq!(
        heap.get_string(string).expect("string exists").bytes(),
        b"snapshot-cold"
    );
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn hash_cons_reuse_refreshes_cold_hash_consed_touch_epoch() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("first string allocates");
    let string_size = record_layout_size(&heap, first);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);

    let records_before = heap.len();
    let second = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("matching string reuses hash-consed value");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), records_before);
    assert_eq!(heap.access_epoch(), 3);
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cold_hash_consed_advice_reports_selected_records_without_reclaiming() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"advise-cold".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    let report = heap.advise_cold_hash_consed_values(1);

    assert_eq!(report.kind(), MemoryAdviceKind::Cold);
    assert_eq!(report.min_idle_epochs(), 1);
    assert_eq!(report.records(), 1);
    assert_eq!(report.requested_bytes(), string_size);
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        report.records()
    );
    assert_eq!(
        heap.cold_hash_consed_bytes(1),
        string_size,
        "advice is non-destructive and does not refresh coldness"
    );

    heap.get_string(string)
        .expect("string read refreshes touch");

    let hot_report = heap.advise_cold_hash_consed_values(1);
    assert_eq!(hot_report.kind(), MemoryAdviceKind::Cold);
    assert_eq!(hot_report.min_idle_epochs(), 1);
    assert_eq!(hot_report.records(), 0);
    assert_eq!(hot_report.requested_bytes(), 0);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn evict_hash_consed_advice_reports_selected_records_without_removing_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"advise-evict".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    let report = heap.advise_evict_hash_consed_values(1);

    assert_eq!(report.kind(), MemoryAdviceKind::Evict);
    assert_eq!(report.min_idle_epochs(), 1);
    assert_eq!(report.records(), 1);
    assert_eq!(report.requested_bytes(), string_size);
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        report.records()
    );
    assert_eq!(
        heap.cold_hash_consed_bytes(1),
        string_size,
        "eviction advice is non-destructive and does not refresh coldness"
    );

    heap.get_string(string)
        .expect("string read refreshes touch");

    let hot_report = heap.advise_evict_hash_consed_values(1);
    assert_eq!(hot_report.kind(), MemoryAdviceKind::Evict);
    assert_eq!(hot_report.min_idle_epochs(), 1);
    assert_eq!(hot_report.records(), 0);
    assert_eq!(hot_report.requested_bytes(), 0);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cheap_memory_range_advice_combines_tails_and_cold_hash_consed_hints() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"combined-cold".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);

    let report = heap.advise_cheap_memory_ranges(1);
    let unused_tails = report.unused_tails();
    let cold_hash_consed = report.cold_hash_consed();

    assert_eq!(unused_tails.kind(), MemoryAdviceKind::Dead);
    assert_eq!(unused_tails.chunks(), 2);
    assert_eq!(unused_tails.requested_bytes(), unused_tail_bytes);
    assert_eq!(
        unused_tails.applied()
            + unused_tails.unsupported()
            + unused_tails.empty_ranges()
            + unused_tails.rejected(),
        unused_tails.chunks()
    );
    assert_eq!(cold_hash_consed.kind(), MemoryAdviceKind::Cold);
    assert_eq!(cold_hash_consed.min_idle_epochs(), 1);
    assert_eq!(cold_hash_consed.records(), 1);
    assert_eq!(cold_hash_consed.requested_bytes(), string_size);
    assert_eq!(
        cold_hash_consed.applied()
            + cold_hash_consed.unsupported()
            + cold_hash_consed.empty_ranges()
            + cold_hash_consed.rejected(),
        cold_hash_consed.records()
    );
    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
    assert_eq!(heap.last_memory_budget_action(), None);

    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");
    heap.set_memory_budget(budget);
    heap.alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("budgeted thunk allocates");
    let poll_count = heap.memory_budget_poll_count();
    let previous_action = heap
        .last_memory_budget_action()
        .expect("budgeted allocation records an action");

    heap.advise_cheap_memory_ranges(1);

    assert_eq!(heap.memory_budget_poll_count(), poll_count);
    assert_eq!(heap.last_memory_budget_action(), Some(previous_action));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn whole_heap_memory_budget_classification_includes_both_allocation_domains() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("test resident bytes fit");
    assert!(worker_stats.mapped_bytes > 0);
    assert!(permanent_stats.mapped_bytes > 0);

    assert_eq!(
        heap.memory_budget_sample(7, 11),
        HeapMemorySample::new(resident_bytes, 7, 11)
    );

    let loose_budget =
        HeapMemoryBudget::new(resident_bytes.checked_mul(2).expect("budget doubles"))
            .expect("budget is non-zero");
    let continue_decision = heap.classify_memory_budget(loose_budget, 0, 0);
    assert_eq!(continue_decision.budget(), loose_budget);
    assert_eq!(
        continue_decision.sample(),
        HeapMemorySample::new(resident_bytes, 0, 0)
    );
    assert_eq!(
        continue_decision.resident_source(),
        EvalHeapResidentMemorySource::ArenaMappedBytes
    );
    assert_eq!(continue_decision.worker_stats(), worker_stats);
    assert_eq!(continue_decision.permanent_stats(), permanent_stats);
    assert_eq!(
        continue_decision.response(),
        HeapMemoryBudgetResponse::ContinueTierA {
            headroom_bytes: loose_budget.soft_limit_bytes() - resident_bytes,
            projected_resident_bytes: resident_bytes,
        }
    );
    assert!(!continue_decision.requires_runtime_action());
    assert!(!continue_decision.requests_tier_b());

    let spill_budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");
    let spill_reclaim_bytes = resident_bytes - spill_budget.soft_limit_bytes();
    let spill_decision = heap.classify_memory_budget(spill_budget, 0, spill_reclaim_bytes);
    assert_eq!(
        spill_decision.sample(),
        HeapMemorySample::new(resident_bytes, 0, spill_reclaim_bytes)
    );
    assert_eq!(
        spill_decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes: spill_reclaim_bytes,
            available_reclaim_bytes: spill_reclaim_bytes,
            projected_resident_bytes: spill_budget.soft_limit_bytes(),
        }
    );
    assert!(spill_decision.requires_runtime_action());
    assert!(!spill_decision.requests_tier_b());

    let tier_b_budget = HeapMemoryBudget::new(resident_bytes / 2).expect("budget is non-zero");
    let tier_b_decision = heap.classify_memory_budget(tier_b_budget, 0, 0);
    assert_eq!(
        tier_b_decision.response(),
        HeapMemoryBudgetResponse::InstallTierB {
            desired_reclaim_bytes: resident_bytes - tier_b_budget.soft_limit_bytes(),
            available_reclaim_bytes: 0,
            projected_resident_bytes: resident_bytes,
            over_budget_bytes: resident_bytes - tier_b_budget.max_resident_bytes(),
        }
    );
    assert!(tier_b_decision.requires_runtime_action());
    assert!(tier_b_decision.requests_tier_b());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn tier_b_admission_plan_maps_worker_records_to_old_generation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let worker = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    // Since FV-2 no allocation path creates a permanent record (strings,
    // paths, lists, and attrsets are all flat), so the fixture manufactures
    // one: a worker record flipped to the permanent-shared domain.
    let permanent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("permanent-fixture thunk allocates");
    heap.set_allocation_domain_for_test(permanent, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();

    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");

    assert_eq!(plan.worker_stats(), worker_stats);
    assert_eq!(plan.permanent_stats(), permanent_stats);
    assert_eq!(plan.worker_records(), 1);
    assert_eq!(plan.permanent_shared_records(), 1);
    assert_eq!(plan.record_count(), heap.len());
    assert_eq!(plan.records().len(), heap.len());

    let worker_record = plan
        .records()
        .iter()
        .find(|record| record.address() == gc_address(worker))
        .expect("worker record is planned");
    assert_eq!(
        worker_record.allocation_domain(),
        HeapAllocationDomain::Worker
    );
    assert_eq!(worker_record.current_generation(), HeapGeneration::Young);
    assert_eq!(worker_record.admitted_generation(), HeapGeneration::Old);
    assert!(worker_record.needs_generation_rewrite());

    let permanent_record = plan
        .records()
        .iter()
        .find(|record| record.address() == gc_address(permanent))
        .expect("permanent record is planned");
    assert_eq!(
        permanent_record.allocation_domain(),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        permanent_record.current_generation(),
        HeapGeneration::Permanent
    );
    assert_eq!(
        permanent_record.admitted_generation(),
        HeapGeneration::Permanent
    );
    assert!(!permanent_record.needs_generation_rewrite());

    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Young);
    assert_eq!(heap_generation(&heap, permanent), HeapGeneration::Permanent);
    assert_eq!(
        allocation_domain(&heap, worker),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        allocation_domain(&heap, permanent),
        HeapAllocationDomain::PermanentShared
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn tier_b_admission_plan_keeps_existing_old_worker_generation_stable() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let worker = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    set_heap_generation(&mut heap, worker, HeapGeneration::Old);

    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");

    let worker_record = plan
        .records()
        .iter()
        .find(|record| record.address() == gc_address(worker))
        .expect("worker record is planned");
    assert_eq!(worker_record.current_generation(), HeapGeneration::Old);
    assert_eq!(worker_record.admitted_generation(), HeapGeneration::Old);
    assert!(!worker_record.needs_generation_rewrite());
    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Old);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn tier_b_admission_application_rewrites_worker_records_to_old_generation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let worker = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    // Since FV-2 no allocation path creates a permanent record (strings,
    // paths, lists, and attrsets are all flat), so the fixture manufactures
    // one: a worker record flipped to the permanent-shared domain.
    let permanent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("permanent-fixture thunk allocates");
    heap.set_allocation_domain_for_test(permanent, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");

    let report = heap
        .apply_tier_b_admission_plan(&plan)
        .expect("admission application succeeds");

    assert_eq!(report.worker_records(), 1);
    assert_eq!(report.permanent_shared_records(), 1);
    assert_eq!(report.generation_rewrites(), 1);
    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Old);
    assert_eq!(heap_generation(&heap, permanent), HeapGeneration::Permanent);
    assert_eq!(
        allocation_domain(&heap, worker),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        allocation_domain(&heap, permanent),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(heap.arena_stats(), worker_stats);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats);
}
