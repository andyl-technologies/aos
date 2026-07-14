//! Evaluator-heap unit tests, part 1 of 16 (RFC-0007 §2 split, #9).
//!
//! Move-only item-boundary split of the `tests.rs` inline body; each
//! test keeps its `#[cfg]`/doc prefix. No test changed.

#![allow(unused_imports)]

use super::super::*;
use super::*;

#[test]
fn default_heap_uses_tier_a_runtime_allocator() {
    let heap = EvalHeap::new();

    assert_eq!(heap.allocator_tier(), RuntimeAllocatorTier::TierAOneShot);
    assert_eq!(
        heap.permanent_allocator_tier(),
        RuntimeAllocatorTier::PermanentShared
    );
    assert!(heap.allocator_gc_stress_policy().is_disabled());
    assert!(heap.permanent_allocator_gc_stress_policy().is_disabled());
    assert_eq!(
        heap.allocation_safepoints(),
        AllocationSafepointState::default()
    );
    assert_eq!(
        heap.permanent_allocation_safepoints(),
        AllocationSafepointState::default()
    );
    assert_eq!(heap.memory_budget(), None);
    assert_eq!(
        heap.resident_memory_mode(),
        EvalHeapResidentMemoryMode::ArenaMappedBytes
    );
    assert_eq!(heap.memory_budget_poll_count(), 0);
    assert_eq!(heap.last_memory_budget_action(), None);
    assert_eq!(heap.access_epoch(), 0);
    assert_eq!(heap.cold_hash_consed_bytes(0), 0);
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn gc_stress_policy_installs_across_heap_allocation_domains() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());

    assert_eq!(
        heap.allocator_gc_stress_policy(),
        GcStressPolicy::every_safepoint()
    );
    assert_eq!(
        heap.permanent_allocator_gc_stress_policy(),
        GcStressPolicy::every_safepoint()
    );

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"root".to_vec()))
        .expect("string allocates");

    assert_eq!(
        heap.allocation_safepoints()
            .last()
            .expect("worker safepoint")
            .gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    assert_eq!(
        heap.permanent_allocation_safepoints()
            .last()
            .expect("permanent safepoint")
            .gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn heap_records_store_generation_separately_from_allocation_domain() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let permanent = heap
        .alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("string allocates");
    let worker = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    assert_eq!(
        allocation_domain(&heap, permanent),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(heap_generation(&heap, permanent), HeapGeneration::Permanent);
    assert_eq!(
        allocation_domain(&heap, worker),
        HeapAllocationDomain::Worker
    );
    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Young);

    heap.set_allocation_domain_for_test(worker, HeapAllocationDomain::PermanentShared)
        .expect("test helper updates domain");

    assert_eq!(
        allocation_domain(&heap, worker),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Permanent);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_allocator_reset_preserves_permanent_records_when_worker_domain_is_idle() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("string allocates");
    let permanent_stats_before = heap.permanent_arena_stats();

    let report = heap
        .reset_worker_allocator_if_idle()
        .expect("worker reset is safe without worker records");

    assert_eq!(report.dropped_worker_stats(), ArenaStats::default());
    assert_eq!(report.worker_stats_after(), ArenaStats::default());
    assert_eq!(report.permanent_stats(), permanent_stats_before);
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats(), permanent_stats_before);
    assert_eq!(
        heap.get_string(value)
            .expect("permanent string survives")
            .bytes(),
        b"permanent"
    );
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );

    let reused = heap
        .alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("hash-consed string remains reusable");
    assert!(reused.raw_eq(value));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_allocator_reset_rejects_live_worker_domain_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("string allocates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let worker_stats_before = heap.arena_stats();
    let permanent_stats_before = heap.permanent_arena_stats();

    let error = heap
        .reset_worker_allocator_if_idle()
        .expect_err("live worker records reject reset");

    assert_eq!(error, EvalHeapError::WorkerResetLiveRecords { records: 1 });
    assert_eq!(heap.arena_stats(), worker_stats_before);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats_before);
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_allocator_reset_rejects_permanent_container_with_worker_child() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let container = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");

    let error = heap
        .reset_worker_allocator_if_idle()
        .expect_err("worker child rejects reset");

    assert_eq!(error, EvalHeapError::WorkerResetLiveRecords { records: 1 });
    assert_eq!(
        allocation_domain(&heap, container),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        allocation_domain(&heap, child),
        HeapAllocationDomain::Worker
    );
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_reclaims_disconnected_worker_suffix() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let retained = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("retained thunk allocates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let first = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("first region lambda allocates");
    let second = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(5),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("second region lambda allocates");
    let stats_before_pop = heap.arena_stats();
    let safepoints_before_pop = heap.allocation_safepoints();

    let report = heap
        .pop_worker_region_if_disconnected(mark)
        .expect("disconnected worker suffix pops");

    assert_eq!(report.reclaimed_records(), 2);
    assert_eq!(report.records_after(), mark.records());
    assert_eq!(report.arena_report().before_stats(), stats_before_pop);
    assert!(report.arena_report().used_bytes_released() > 0);
    assert!(heap.arena_stats().used_bytes < stats_before_pop.used_bytes);
    assert_eq!(heap.allocation_safepoints().count(), 1);
    assert_ne!(heap.allocation_safepoints(), safepoints_before_pop);
    assert!(heap.get_thunk(retained).is_ok());
    assert!(matches!(
        heap.get_lambda(first),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
    assert!(matches!(
        heap.get_lambda(second),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_plan_pop_cancels_until_region_plan_permits() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let retained = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("retained thunk allocates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let temporary = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("temporary lambda allocates");
    let stats_before_skip = heap.arena_stats();
    let safepoints_before_skip = heap.allocation_safepoints();
    let conservative_plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::conservative(),
    );

    let skipped = heap
        .pop_worker_region_if_plan_permits(mark, conservative_plan)
        .expect("non-pop region plan cancels the mark");

    assert_eq!(skipped, None);
    assert_eq!(heap.arena_stats(), stats_before_skip);
    assert_eq!(heap.allocation_safepoints(), safepoints_before_skip);
    assert!(heap.get_thunk(retained).is_ok());
    assert!(heap.get_lambda(temporary).is_ok());

    let lexical_plan = RegionPlan::classify(
        RegionRuntimeTier::OneShotArena,
        AllocationRegionFacts::lexical_no_escape(),
    );
    let error = heap
        .pop_worker_region_if_plan_permits(mark, lexical_plan)
        .expect_err("cancelled marker cannot be reused");
    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopStaleMark {
            reason: "worker region mark is not innermost",
            marker_records: mark.typed_objects(),
            current_records: heap.len(),
        }
    );

    let lexical_mark = heap
        .worker_region_mark()
        .expect("fresh region mark records");
    let temporary_after_plan = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(5),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("temporary lambda after plan allocates");
    let report = heap
        .pop_worker_region_if_plan_permits(lexical_mark, lexical_plan)
        .expect("lexical no-escape plan routes to region pop")
        .expect("lexical no-escape plan permits early pop");

    assert_eq!(report.reclaimed_records(), 1);
    assert_eq!(report.records_after(), lexical_mark.records());
    assert!(heap.get_thunk(retained).is_ok());
    assert!(heap.get_lambda(temporary).is_ok());
    assert!(matches!(
        heap.get_lambda(temporary_after_plan),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_cancel_mark_retires_innermost_without_reclaiming() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let outer = heap
        .worker_region_mark()
        .expect("outer region mark records");
    let outer_value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("outer value allocates");
    let inner = heap
        .worker_region_mark()
        .expect("inner region mark records");
    let inner_value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(4),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("inner value allocates");
    let stats_before_cancel = heap.arena_stats();
    let safepoints_before_cancel = heap.allocation_safepoints();

    heap.cancel_worker_region_mark(inner)
        .expect("innermost marker cancels");

    assert_eq!(heap.arena_stats(), stats_before_cancel);
    assert_eq!(heap.allocation_safepoints(), safepoints_before_cancel);
    assert!(heap.get_lambda(outer_value).is_ok());
    assert!(heap.get_lambda(inner_value).is_ok());
    assert!(matches!(
        heap.cancel_worker_region_mark(inner),
        Err(EvalHeapError::WorkerRegionPopStaleMark {
            reason: "worker region mark is not innermost",
            ..
        })
    ));

    let outer_report = heap
        .pop_worker_region_if_disconnected(outer)
        .expect("outer marker remains valid after inner cancel");
    assert_eq!(outer_report.reclaimed_records(), 2);
    assert_eq!(outer_report.records_after(), outer.records());
    assert!(matches!(
        heap.get_lambda(outer_value),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
    assert!(matches!(
        heap.get_lambda(inner_value),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_rejects_permanent_records_above_marker() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // Domain flipping is a record-table concept: FV-3 worker closures are
    // flat (and always worker-domain), so this fixture uses the Tier-B B2
    // proving ground's record placement.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mark = heap.worker_region_mark().expect("region mark records");
    // Since FV-2 no allocation path creates a permanent record (strings,
    // paths, lists, and attrsets are all flat), so the fixture manufactures
    // one: a worker record flipped to the permanent-shared domain.
    let permanent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    heap.set_allocation_domain_for_test(permanent, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let stats_before = heap.arena_stats();
    let permanent_stats_before = heap.permanent_arena_stats();

    let error = heap
        .pop_worker_region_if_disconnected(mark)
        .expect_err("permanent suffix record rejects worker region pop");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopNonWorkerRecords { records: 1 }
    );
    assert_eq!(heap.arena_stats(), stats_before);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats_before);
    assert!(heap.get_thunk(permanent).is_ok());
}


/// Flat strings (FV-1) live outside the record table and the worker arena, so
/// allocating one above a worker-region marker no longer blocks the pop; the
/// pop rewinds only worker storage and the string stays resolvable.
// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_ignores_flat_strings_above_marker() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let string = heap
        .alloc_string(NixString::from_bytes(b"flat-permanent".to_vec()))
        .expect("string allocates");

    heap.pop_worker_region_if_disconnected(mark)
        .expect("flat strings above the marker do not block the pop");

    assert_eq!(
        heap.get_string(string).expect("string remains").bytes(),
        b"flat-permanent"
    );
}


/// Flat attrsets (FV-2) live outside the record table and the worker arena;
/// an attrset with no worker edges above a worker-region marker no longer
/// blocks the pop, and the attrset stays resolvable.
// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_ignores_flat_attrs_above_marker() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let attrs = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("attrset allocates");

    heap.pop_worker_region_if_disconnected(mark)
        .expect("edge-free flat attrsets above the marker do not block the pop");

    assert_eq!(
        heap.get_attrs(attrs)
            .expect("attrset remains")
            .entries_by_symbol()
            .first()
            .expect("entry remains")
            .value
            .as_int(),
        Ok(7)
    );
}


/// A flat attrset is a retained source (FV-2 GC coupling 2): an entry value
/// pointing into the reclaimed suffix rejects the pop exactly as a retained
/// record edge did before flattening.
// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_rejects_flat_attrs_edge_into_suffix() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let suffix_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("suffix thunk allocates above marker");
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let attrs = heap
        .alloc_attrs(
            0,
            FlatAttrs::new(vec![AttrEntry::new(key, suffix_thunk)], &symbols)
                .expect("attrset builds"),
        )
        .expect("attrset allocates");
    let stats_before = heap.arena_stats();

    let error = heap
        .pop_worker_region_if_disconnected(mark)
        .expect_err("flat attrset edge into the suffix rejects the pop");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopRetainedEdge {
            source_address: gc_address(attrs),
            edge_source: HeapEdgeSource::AttrBinding {
                shape: 0,
                slot: 0,
                key,
            },
            target_address: gc_address(suffix_thunk),
        }
    );
    assert_eq!(heap.arena_stats(), stats_before);
    assert!(heap.get_thunk(suffix_thunk).is_ok());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_rejects_retained_edge_into_suffix() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    let retained = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("retained thunk allocates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let forced = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("forced value allocates above marker");
    // Publish through the record's own serial cell: inline `ThunkCellSlot`
    // storage makes `clone_thunk` deep-copy the cell, so forcing a clone would
    // leave the heap record suspended and hide the cached-result edge under test.
    let retained_cell = heap
        .test_share_thunk_cell(retained)
        .expect("retained thunk exists");
    let crate::eval::ForceClaim::Claimed(guard) =
        retained_cell.begin_force().expect("claim succeeds")
    else {
        panic!("retained thunk should be claimable");
    };
    guard
        .finish(forced)
        .expect("forced result publishes into retained thunk");
    let stats_before = heap.arena_stats();

    let error = heap
        .pop_worker_region_if_disconnected(mark)
        .expect_err("retained edge rejects worker region pop");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopRetainedEdge {
            source_address: gc_address(retained),
            edge_source: HeapEdgeSource::ThunkCachedResult,
            target_address: gc_address(forced),
        }
    );
    assert_eq!(heap.arena_stats(), stats_before);
    assert!(heap.get_lambda(forced).is_ok());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_rejects_marker_from_another_heap() {
    let mut other_heap = EvalHeap::with_initial_chunk_bytes(128).expect("other heap creates");
    let foreign_mark = other_heap
        .worker_region_mark()
        .expect("foreign region mark records");
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lambda allocates");
    let stats_before = heap.arena_stats();

    let error = heap
        .pop_worker_region_if_disconnected(foreign_mark)
        .expect_err("foreign marker rejects region pop");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopStaleMark {
            reason: "marker was captured from another heap",
            marker_records: foreign_mark.records(),
            current_records: heap.len(),
        }
    );
    assert_eq!(heap.arena_stats(), stats_before);
    assert!(heap.get_lambda(value).is_ok());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_rejects_marker_after_worker_epoch_change() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let mark = heap.worker_region_mark().expect("region mark records");
    heap.reset_worker_allocator_if_idle()
        .expect("empty worker reset succeeds");
    let value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lambda allocates after reset");
    let stats_before = heap.arena_stats();

    let error = heap
        .pop_worker_region_if_disconnected(mark)
        .expect_err("epoch-stale marker rejects region pop");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopStaleMark {
            reason: "worker allocator epoch changed",
            marker_records: mark.records(),
            current_records: heap.len(),
        }
    );
    assert_eq!(heap.arena_stats(), stats_before);
    assert!(heap.get_lambda(value).is_ok());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_preserves_outer_lifo_mark_after_inner_pop() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let outer = heap
        .worker_region_mark()
        .expect("outer region mark records");
    let outer_value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("outer value allocates");
    let inner = heap
        .worker_region_mark()
        .expect("inner region mark records");
    let inner_value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(4),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("inner value allocates");

    let inner_report = heap
        .pop_worker_region_if_disconnected(inner)
        .expect("inner region pops");
    assert_eq!(inner_report.reclaimed_records(), 1);
    assert!(heap.get_lambda(outer_value).is_ok());
    assert!(matches!(
        heap.get_lambda(inner_value),
        Err(EvalHeapError::UnknownPointer { .. })
    ));

    let outer_report = heap
        .pop_worker_region_if_disconnected(outer)
        .expect("outer marker remains valid after inner pop");
    assert_eq!(outer_report.reclaimed_records(), 1);
    assert_eq!(outer_report.records_after(), outer.records());
    assert!(matches!(
        heap.get_lambda(outer_value),
        Err(EvalHeapError::UnknownPointer { .. })
    ));
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_rejects_outer_mark_while_inner_mark_is_active() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let outer = heap
        .worker_region_mark()
        .expect("outer region mark records");
    let outer_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("outer value allocates");
    let _inner = heap
        .worker_region_mark()
        .expect("inner region mark records");
    let inner_value = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("inner value allocates");
    let stats_before = heap.arena_stats();

    let error = heap
        .pop_worker_region_if_disconnected(outer)
        .expect_err("outer marker is not innermost");

    assert_eq!(
        error,
        EvalHeapError::WorkerRegionPopStaleMark {
            reason: "worker region mark is not innermost",
            marker_records: outer.records(),
            current_records: heap.len(),
        }
    );
    assert_eq!(heap.arena_stats(), stats_before);
    assert!(heap.get_thunk(outer_value).is_ok());
    assert!(heap.get_lambda(inner_value).is_ok());
}


// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn worker_region_pop_invalidates_existing_collector_poll_scan_epoch() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let retained = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("retained thunk allocates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let reclaimed = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(3),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("reclaimed lambda allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, retained)
        .expect("retained root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll scan records");

    heap.pop_worker_region_if_disconnected(mark)
        .expect("disconnected suffix pops");
    let replacement = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(5),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("replacement lambda allocates after pop");

    assert!(
        reclaimed.raw_eq(replacement),
        "rewound bump slot is reused by the replacement allocation"
    );
    assert!(heap.get_lambda(replacement).is_ok());
    assert_eq!(scan.heap_records(), heap.len());
    let remembered_set = RememberedSet::new();
    assert_eq!(
        heap.plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("region pop makes poll scan stale"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "worker region epoch changed",
            expected_records: scan.heap_records(),
            actual_records: heap.len(),
        }
    );
}
