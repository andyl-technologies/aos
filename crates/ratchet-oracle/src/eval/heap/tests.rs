//! Unit tests for the typed evaluator heap registry.

use super::super::ThunkState;
use super::*;
use crate::attrs::{AttrEntry, AttrPosition};
use crate::eval::{EvalFrame, EvalWithScope};
use crate::heap::{
    AllocationRegionFacts, GcCardTable, GcHeapAddress, GenerationalGcError, GenerationalGcTier,
    HeapGeneration, HeapMemoryBudget, HeapMemoryBudgetResponse, HeapMemorySample, MemoryAdviceKind,
    MinorGcDestinationBases, MinorGcForwardingSlot, MinorGcObjectByteCopyBuffer, MinorGcPlan,
    MinorGcPromotionPolicy, MinorGcRelocationPlan, MinorGcSurvivorAction, NurseryObjectAge,
    NurseryObjectLayout, ProcessResidentMemorySource, RegionPlan, RegionRuntimeTier,
    RememberedEdge, RememberedSet, ResolvedValueGeneration, ThunkResolveWriteBarrier,
};
use crate::runtime::alloc::{AllocationGcPollReason, RuntimeAllocationEntryPoint};
use crate::runtime::builtins::lookup_builtin;
use crate::string::{ContextElement, StringContext};
use crate::syntax::SymbolTable;

mod errors;

fn attrs_with_one_entry() -> FlatAttrs {
    attrs_with_value(Value::int(7))
}

fn attrs_with_value(value: Value) -> FlatAttrs {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    FlatAttrs::new(vec![AttrEntry::new(key, value)], &symbols).expect("attrset builds")
}

fn attrs_with_ordered_entries(first: &[u8], second: &[u8]) -> FlatAttrs {
    let mut symbols = SymbolTable::new();
    let a = symbols.intern(b"a").expect("a symbol interns");
    let b = symbols.intern(b"b").expect("b symbol interns");
    let key = |name: &[u8]| match name {
        b"a" => a,
        b"b" => b,
        _ => unreachable!("test helper accepts only a/b keys"),
    };
    FlatAttrs::new(
        vec![
            AttrEntry::new(key(first), Value::int(i64::from(first[0]))),
            AttrEntry::new(key(second), Value::int(i64::from(second[0]))),
        ],
        &symbols,
    )
    .expect("attrset builds")
}

fn allocation_domain(heap: &EvalHeap, value: Value) -> HeapAllocationDomain {
    heap.allocation_domain(value)
        .expect("heap record has an allocation domain")
}

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointers are valid GC addresses")
}

fn static_gc_address(address_bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(address_bits).expect("test address is a valid GC address")
}

fn replace_list_record(heap: &mut EvalHeap, value: Value, list: NixList) {
    let address = gc_address(value);
    let record = heap
        .records
        .iter_mut()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
        .expect("heap record exists");
    record.object = HeapObjectValue::List(list);
}

fn set_allocation_domain(heap: &mut EvalHeap, value: Value, domain: HeapAllocationDomain) {
    let address = gc_address(value);
    let record = heap
        .records
        .iter_mut()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
        .expect("heap record exists");
    record.allocation_domain = domain;
}

fn record_layout_size(heap: &EvalHeap, value: Value) -> usize {
    let address = gc_address(value);
    heap.records
        .iter()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
        .expect("heap record exists")
        .layout
        .size_bytes
}

fn record_layout_align(heap: &EvalHeap, value: Value) -> usize {
    let address = gc_address(value);
    heap.records
        .iter()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
        .expect("heap record exists")
        .layout
        .align
}

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
            marker_records: mark.records(),
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

#[test]
fn worker_region_pop_rejects_permanent_records_above_marker() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let mark = heap.worker_region_mark().expect("region mark records");
    let permanent = heap
        .alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
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
    assert_eq!(
        heap.get_string(permanent)
            .expect("permanent record remains")
            .bytes(),
        b"permanent"
    );
}

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
    let retained_thunk = heap.clone_thunk(retained).expect("retained thunk exists");
    let crate::eval::ForceClaim::Claimed(guard) =
        retained_thunk.cell().begin_force().expect("claim succeeds")
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

#[test]
fn thunk_resolve_write_barrier_records_permanent_to_young_forced_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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

#[test]
fn thunk_resolve_write_barrier_marks_card_for_permanent_to_young_forced_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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

#[test]
fn thunk_resolve_write_barrier_skips_inline_forced_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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

#[test]
fn thunk_resolve_write_barrier_skips_external_forced_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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

#[test]
fn thunk_resolve_write_barrier_records_its_source_when_guard_is_mispaired() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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

#[test]
fn cold_hash_consed_estimate_flows_into_opt_in_budget_classification() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"spillable".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");
    let decision = heap.classify_memory_budget_with_cold_hash_consed_estimate(budget, 13, 1);

    assert_eq!(
        decision.sample(),
        HeapMemorySample::new(resident_bytes, 13, string_size)
    );
    assert_eq!(
        decision.resident_source(),
        EvalHeapResidentMemorySource::ArenaMappedBytes
    );
    assert_eq!(decision.worker_stats(), worker_stats);
    assert_eq!(decision.permanent_stats(), permanent_stats);
}

#[test]
fn whole_heap_unused_tail_advice_reports_both_allocation_domains() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();

    let report = heap.advise_unused_tails(MemoryAdviceKind::Dead);

    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.worker().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.permanent().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.worker().chunks(), 1);
    assert_eq!(report.permanent().chunks(), 1);
    assert_eq!(report.chunks(), 2);
    assert_eq!(
        report.requested_bytes(),
        report.worker().requested_bytes() + report.permanent().requested_bytes()
    );
    assert_eq!(
        report.requested_bytes(),
        (worker_stats.mapped_bytes - worker_stats.used_bytes)
            + (permanent_stats.mapped_bytes - permanent_stats.used_bytes)
    );
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        2
    );
    assert_eq!(heap.arena_stats(), worker_stats);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats);
}

#[test]
fn memory_budget_action_continues_without_advice_below_soft_limit() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let resident_bytes = heap
        .arena_stats()
        .mapped_bytes
        .checked_add(heap.permanent_arena_stats().mapped_bytes)
        .expect("resident bytes fit");
    let budget = HeapMemoryBudget::new(resident_bytes.checked_mul(2).expect("budget doubles"))
        .expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    assert!(matches!(
        action,
        EvalHeapMemoryBudgetAction::ContinueTierA { .. }
    ));
    assert_eq!(action.advice_report(), None);
    assert!(!action.requests_tier_b());
    assert_eq!(
        action.decision().response(),
        HeapMemoryBudgetResponse::ContinueTierA {
            headroom_bytes: budget.soft_limit_bytes() - resident_bytes,
            projected_resident_bytes: resident_bytes,
        }
    );
}

#[test]
fn memory_budget_action_does_not_credit_subpage_or_unsupported_tail_advice() {
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
        .expect("resident bytes fit");
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);
    assert_eq!(heap.supported_unused_tail_advice_bytes(), 0);
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    let EvalHeapMemoryBudgetAction::AdviseUnusedTails { decision, report } = action else {
        panic!("near-budget response should still attempt unused-tail advice");
    };
    assert_eq!(decision.sample().dead_arena_bytes(), 0);
    assert_eq!(decision.sample().cold_hash_consed_bytes(), 0);
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes: resident_bytes - budget.soft_limit_bytes(),
            available_reclaim_bytes: 0,
            projected_resident_bytes: resident_bytes,
        }
    );
    assert_eq!(action.advice_report(), Some(report));
    assert_eq!(report.requested_bytes(), unused_tail_bytes);
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        2
    );
}

#[test]
fn cheap_memory_budget_plan_credits_cold_hash_consed_estimate_as_planning_metadata() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"spillable".to_vec()))
        .expect("permanent string allocates");
    let cold_hash_consed_bytes = record_layout_size(&heap, string);
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = heap
        .arena_stats()
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    assert_eq!(heap.supported_unused_tail_advice_bytes(), 0);
    assert!(resident_bytes > cold_hash_consed_bytes);
    let budget =
        HeapMemoryBudget::new(resident_bytes - cold_hash_consed_bytes).expect("budget is non-zero");

    let unused_tail_action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);
    assert!(matches!(
        unused_tail_action,
        EvalHeapMemoryBudgetAction::RequestTierB { .. }
    ));
    assert_eq!(
        unused_tail_action
            .decision()
            .sample()
            .cold_hash_consed_bytes(),
        0
    );

    let plan = heap.plan_memory_budget_with_cheap_memory_advice(budget, 0);

    let decision = plan.decision();
    let report = plan
        .cheap_advice_report()
        .expect("cold-aware spill planning records cheap advice telemetry");
    assert_eq!(
        decision.sample(),
        HeapMemorySample::new(resident_bytes, 0, cold_hash_consed_bytes)
    );
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes: resident_bytes - budget.soft_limit_bytes(),
            available_reclaim_bytes: cold_hash_consed_bytes,
            projected_resident_bytes: budget.max_resident_bytes(),
        }
    );
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Evict);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert_eq!(report.cold_hash_consed().records(), 1);
    assert_eq!(
        report.cold_hash_consed().requested_bytes(),
        cold_hash_consed_bytes
    );
}

#[test]
fn cheap_memory_budget_plan_uses_pageout_advice_before_tier_b_request() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"tier-b-pageout".to_vec()))
        .expect("permanent string allocates");
    let cold_hash_consed_bytes = record_layout_size(&heap, string);
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let supported_tail_advice_bytes = heap.supported_unused_tail_advice_bytes();
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    let plan = heap.plan_memory_budget_with_cheap_memory_advice(budget, 0);

    let decision = plan.decision();
    let report = plan
        .cheap_advice_report()
        .expect("tier-b budget planning records advice telemetry");
    let desired_reclaim_bytes = resident_bytes - budget.soft_limit_bytes();
    let available_reclaim_bytes = supported_tail_advice_bytes + cold_hash_consed_bytes;
    let projected_resident_bytes = resident_bytes - available_reclaim_bytes;
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::InstallTierB {
            desired_reclaim_bytes,
            available_reclaim_bytes,
            projected_resident_bytes,
            over_budget_bytes: projected_resident_bytes - budget.max_resident_bytes(),
        }
    );
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Evict);
    assert_eq!(report.cold_hash_consed().records(), 1);
    assert_eq!(
        report.cold_hash_consed().requested_bytes(),
        cold_hash_consed_bytes
    );
    assert_eq!(
        heap.cold_hash_consed_bytes(0),
        cold_hash_consed_bytes,
        "pageout advice preserves typed heap records"
    );
}

#[test]
fn cheap_memory_budget_plan_continues_without_advice_below_soft_limit() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    heap.alloc_string(NixString::from_bytes(b"cold-but-under-budget".to_vec()))
        .expect("permanent string allocates");
    let resident_bytes = heap
        .arena_stats()
        .mapped_bytes
        .checked_add(heap.permanent_arena_stats().mapped_bytes)
        .expect("resident bytes fit");
    let budget = HeapMemoryBudget::new(resident_bytes.checked_mul(2).expect("budget doubles"))
        .expect("budget is non-zero");

    let plan = heap.plan_memory_budget_with_cheap_memory_advice(budget, 0);

    assert_eq!(plan.cheap_advice_report(), None);
    assert_eq!(
        plan.decision().response(),
        HeapMemoryBudgetResponse::ContinueTierA {
            headroom_bytes: budget.soft_limit_bytes() - resident_bytes,
            projected_resident_bytes: resident_bytes,
        }
    );
}

#[test]
fn memory_budget_action_advises_unused_tails_for_spill_response() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);
    let supported_tail_advice_bytes = heap.supported_unused_tail_advice_bytes();
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    let EvalHeapMemoryBudgetAction::AdviseUnusedTails { decision, report } = action else {
        panic!("spill response should advise unused tails");
    };
    assert_eq!(
        decision.sample().dead_arena_bytes(),
        supported_tail_advice_bytes
    );
    assert_eq!(decision.sample().cold_hash_consed_bytes(), 0);
    let desired_reclaim_bytes = resident_bytes - budget.soft_limit_bytes();
    let reclaim_bytes = desired_reclaim_bytes.min(supported_tail_advice_bytes);
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes,
            available_reclaim_bytes: supported_tail_advice_bytes,
            projected_resident_bytes: resident_bytes - reclaim_bytes,
        }
    );
    assert_eq!(action.advice_report(), Some(report));
    assert!(!action.requests_tier_b());
    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.chunks(), 2);
    assert_eq!(report.requested_bytes(), unused_tail_bytes);
    assert!(supported_tail_advice_bytes <= report.requested_bytes());
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        2
    );
    assert_eq!(heap.arena_stats(), worker_stats);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats);
}

#[test]
fn memory_budget_action_advises_unused_tails_before_tier_b_request() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);
    let supported_tail_advice_bytes = heap.supported_unused_tail_advice_bytes();
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    let EvalHeapMemoryBudgetAction::RequestTierB { decision, report } = action else {
        panic!("over-budget response should request Tier B");
    };
    assert_eq!(
        decision.sample().dead_arena_bytes(),
        supported_tail_advice_bytes
    );
    assert_eq!(decision.sample().cold_hash_consed_bytes(), 0);
    let desired_reclaim_bytes = resident_bytes - budget.soft_limit_bytes();
    let reclaim_bytes = desired_reclaim_bytes.min(supported_tail_advice_bytes);
    let projected_resident_bytes = resident_bytes - reclaim_bytes;
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::InstallTierB {
            desired_reclaim_bytes,
            available_reclaim_bytes: supported_tail_advice_bytes,
            projected_resident_bytes,
            over_budget_bytes: projected_resident_bytes - budget.max_resident_bytes(),
        }
    );
    assert_eq!(action.advice_report(), Some(report));
    assert!(action.requests_tier_b());
    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.chunks(), 2);
    assert_eq!(report.requested_bytes(), unused_tail_bytes);
    assert!(supported_tail_advice_bytes <= report.requested_bytes());
}

#[test]
fn configured_heap_memory_budget_polls_successful_allocations() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    heap.set_memory_budget(budget);

    assert_eq!(heap.memory_budget(), Some(budget));
    assert_eq!(
        heap.resident_memory_mode(),
        EvalHeapResidentMemoryMode::ArenaMappedBytes
    );
    assert_eq!(heap.memory_budget_poll_count(), 0);
    assert_eq!(heap.last_memory_budget_action(), None);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");

    assert_eq!(heap.memory_budget_poll_count(), 1);
    let action = heap
        .last_memory_budget_action()
        .expect("configured budget polls after allocation");
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().resident_source(),
        EvalHeapResidentMemorySource::ArenaMappedBytes
    );
    assert_eq!(action.decision().worker_stats(), heap.arena_stats());
    assert_eq!(
        action.decision().permanent_stats(),
        heap.permanent_arena_stats()
    );
    assert!(action.requests_tier_b());

    heap.set_memory_budget(budget);
    assert_eq!(
        heap.last_memory_budget_action(),
        None,
        "reconfiguring the budget clears stale action metadata"
    );
    let first = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("first permanent string allocates");
    assert_eq!(heap.memory_budget_poll_count(), 2);
    let string_action = heap
        .last_memory_budget_action()
        .expect("permanent allocation records an action");
    assert_eq!(
        string_action.decision().sample().cold_hash_consed_bytes(),
        0,
        "automatic polling stays on the conservative unused-tail response"
    );
    let second = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("matching permanent string reuses the consed value");
    assert!(first.raw_eq(second));
    assert_eq!(
        heap.memory_budget_poll_count(),
        2,
        "hash-cons reuse is not an allocation safepoint"
    );

    heap.clear_memory_budget();
    assert_eq!(heap.memory_budget(), None);
    assert_eq!(heap.last_memory_budget_action(), None);
    heap.alloc_lambda(EvalLambda::new(
        IrId::new(2),
        IrId::new(3),
        FrameId::new(0),
        EvalEnv::default(),
    ))
    .expect("lambda allocates with budget polling disabled");
    assert_eq!(heap.memory_budget_poll_count(), 2);
}

#[test]
fn process_resident_memory_mode_reports_live_or_mapped_source() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    heap.set_memory_budget(budget);
    heap.set_resident_memory_mode(EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback);
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");

    assert_eq!(
        heap.resident_memory_mode(),
        EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback
    );
    let action = heap
        .last_memory_budget_action()
        .expect("configured budget polls after allocation");
    match action.decision().resident_source() {
        EvalHeapResidentMemorySource::ArenaMappedBytes => {}
        EvalHeapResidentMemorySource::ProcessResidentSet(source) => {
            assert!(matches!(
                source,
                ProcessResidentMemorySource::LinuxProcSelfStatm
                    | ProcessResidentMemorySource::DarwinMachTaskBasicInfo
            ));
        }
    }
    assert!(action.requests_tier_b());
}

#[test]
fn multiple_string_values_keep_distinct_heap_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(b"first".to_vec()))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(b"second".to_vec()))
        .expect("second string allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
    assert_eq!(
        heap.get_string(first).expect("first exists").bytes(),
        b"first"
    );
    assert_eq!(
        heap.get_string(second).expect("second exists").bytes(),
        b"second"
    );
}

#[test]
fn identical_string_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_string(second)
            .expect("second string exists")
            .bytes(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg"
    );
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, second),
        HeapAllocationDomain::PermanentShared
    );
}

#[test]
fn hash_consed_heap_records_share_cached_captured_value_hashes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured string",
    ));

    assert!(first.raw_eq(second));
    assert_eq!(heap.cached_captured_value_hash(first), Ok(None));
    assert_eq!(heap.cached_captured_value_hash(second), Ok(None));

    heap.cache_captured_value_hash(first, hash)
        .expect("captured hash caches");

    assert_eq!(heap.cached_captured_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_captured_value_hash(second), Ok(Some(hash)));
    assert_eq!(heap.cached_captured_value_hash(list), Ok(None));
}

#[test]
fn hash_consed_heap_records_share_cached_value_hashes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let hash = ValueHash::from_context_free_string_bytes(
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg",
    );

    assert!(first.raw_eq(second));
    assert_eq!(heap.cached_value_hash(first), Ok(None));
    assert_eq!(heap.cached_value_hash(second), Ok(None));

    assert_eq!(
        heap.cache_value_hash(first, hash)
            .expect("value hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );

    assert_eq!(heap.cached_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(second), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(list), Ok(None));

    assert_eq!(
        heap.cache_value_hash(second, hash)
            .expect("alias accepts same value hash"),
        HeapValueHashCacheUpdate::AlreadyPresent
    );
    let other_hash = ValueHash::from_context_free_string_bytes(b"other");
    assert_eq!(
        heap.cache_value_hash(second, other_hash),
        Err(EvalHeapError::ValueHashMismatch {
            existing: hash,
            attempted: other_hash,
        })
    );
    assert_eq!(heap.cached_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(second), Ok(Some(hash)));
}

#[test]
fn cached_value_hash_lookups_refresh_cold_hash_consed_touch_epoch() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let value = heap
        .alloc_string(NixString::from_bytes(b"cache-key".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, value);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
    assert_eq!(heap.cached_value_hash(value), Ok(None));
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);

    heap.alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second thunk allocates");

    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
    assert_eq!(
        heap.cache_value_hash(
            value,
            ValueHash::from_context_free_string_bytes(b"cache-key")
        )
        .expect("value hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);
}

#[test]
fn cached_value_hashes_reject_mismatched_rewrites() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let value = heap
        .alloc_string(NixString::from_bytes(b"value".to_vec()))
        .expect("string allocates");
    let first_hash = ValueHash::from_context_free_string_bytes(b"value");
    let second_hash = ValueHash::from_context_free_string_bytes(b"other");

    assert_eq!(
        heap.cache_value_hash(value, first_hash)
            .expect("first hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );
    assert_eq!(
        heap.cache_value_hash(value, first_hash)
            .expect("same hash is accepted"),
        HeapValueHashCacheUpdate::AlreadyPresent
    );
    assert_eq!(
        heap.cache_value_hash(value, second_hash),
        Err(EvalHeapError::ValueHashMismatch {
            existing: first_hash,
            attempted: second_hash,
        })
    );
    assert_eq!(heap.cached_value_hash(value), Ok(Some(first_hash)));
}

#[test]
fn captured_value_hash_cache_rejects_unsupported_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured",
    ));
    let expected_int = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Int,
    });
    let expected_thunk = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Thunk,
    });

    assert_eq!(
        heap.cached_captured_value_hash(Value::int(1)),
        Err(expected_int.clone())
    );
    assert_eq!(
        heap.cache_captured_value_hash(Value::int(1), hash),
        Err(expected_int)
    );
    assert_eq!(
        heap.cached_captured_value_hash(thunk),
        Err(expected_thunk.clone())
    );
    assert_eq!(
        heap.cache_captured_value_hash(thunk, hash),
        Err(expected_thunk)
    );
}

#[test]
fn value_hash_cache_rejects_unsupported_values() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let hash = ValueHash::from_context_free_string_bytes(b"value");
    let expected_int = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Int,
    });
    let expected_thunk = EvalHeapError::Value(ValueError::Type {
        expected: "string, path, list, or attrs",
        actual: ValueTag::Thunk,
    });

    assert_eq!(
        heap.cached_value_hash(Value::int(1)),
        Err(expected_int.clone())
    );
    assert_eq!(
        heap.cache_value_hash(Value::int(1), hash),
        Err(expected_int)
    );
    assert_eq!(heap.cached_value_hash(thunk), Err(expected_thunk.clone()));
    assert_eq!(heap.cache_value_hash(thunk, hash), Err(expected_thunk));
}

#[test]
fn captured_value_hash_cache_validates_heap_ownership_and_record_type() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap.alloc_list(NixList::empty()).expect("list allocates");
    let list_ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled_string = Value::string(list_ptr).expect("same pointer can carry string tag");
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
        .expect("foreign string allocates");
    let foreign_ptr = foreign.as_string_ptr().expect("foreign pointer");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured",
    ));
    let mismatch = EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, list_ptr);
    let unknown = EvalHeapError::unknown(ValueTag::String, foreign_ptr);

    assert_eq!(
        heap.cached_captured_value_hash(mislabeled_string),
        Err(mismatch.clone())
    );
    assert_eq!(
        heap.cache_captured_value_hash(mislabeled_string, hash),
        Err(mismatch)
    );
    assert_eq!(
        heap.cached_captured_value_hash(foreign),
        Err(unknown.clone())
    );
    assert_eq!(heap.cache_captured_value_hash(foreign, hash), Err(unknown));
}

#[test]
fn value_hash_cache_validates_heap_ownership_and_record_type() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap.alloc_list(NixList::empty()).expect("list allocates");
    let list_ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled_string = Value::string(list_ptr).expect("same pointer can carry string tag");
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
        .expect("foreign string allocates");
    let foreign_ptr = foreign.as_string_ptr().expect("foreign pointer");
    let hash = ValueHash::from_context_free_string_bytes(b"value");
    let mismatch = EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, list_ptr);
    let unknown = EvalHeapError::unknown(ValueTag::String, foreign_ptr);

    assert_eq!(
        heap.cached_value_hash(mislabeled_string),
        Err(mismatch.clone())
    );
    assert_eq!(
        heap.cache_value_hash(mislabeled_string, hash),
        Err(mismatch)
    );
    assert_eq!(heap.cached_value_hash(foreign), Err(unknown.clone()));
    assert_eq!(heap.cache_value_hash(foreign, hash), Err(unknown));
}

#[test]
fn identical_string_bytes_with_different_contexts_do_not_collapse() {
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/source".to_vec()).expect("context builds"),
    )
    .expect("singleton context allocates");
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let context_free = heap
        .alloc_string(NixString::from_bytes(b"/nix/store/pkg".to_vec()))
        .expect("context-free string allocates");
    let context_bearing = heap
        .alloc_string(NixString::new(b"/nix/store/pkg".to_vec(), context))
        .expect("context-bearing string allocates");

    assert_eq!(context_free.tag(), ValueTag::String);
    assert_eq!(context_bearing.tag(), ValueTag::String);
    assert_ne!(context_free.payload_bits(), context_bearing.payload_bits());
    assert_eq!(heap.len(), 2);
    assert!(
        !heap
            .get_string(context_free)
            .expect("context-free string exists")
            .has_context()
    );
    assert!(
        heap.get_string(context_bearing)
            .expect("context-bearing string exists")
            .has_context()
    );
}

#[test]
fn allocates_path_values_and_recovers_bytes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_path(NixString::from_bytes(b"/tmp/source".to_vec()))
        .expect("path allocates");

    assert_eq!(value.tag(), ValueTag::Path);
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_path(value).expect("path exists").bytes(),
        b"/tmp/source"
    );
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

#[test]
fn identical_path_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_path(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec(),
        ))
        .expect("first path allocates");
    let second = heap
        .alloc_path(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec(),
        ))
        .expect("second path allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_path(second).expect("second path exists").bytes(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source"
    );
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, second),
        HeapAllocationDomain::PermanentShared
    );
}

#[test]
fn string_and_path_cons_tables_are_separate() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let bytes = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source".to_vec();
    let string = heap
        .alloc_string(NixString::from_bytes(bytes.clone()))
        .expect("string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(bytes))
        .expect("path allocates");

    assert_eq!(string.tag(), ValueTag::String);
    assert_eq!(path.tag(), ValueTag::Path);
    assert_ne!(string.payload_bits(), path.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn allocates_list_values_and_recovers_spine() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");

    assert_eq!(value.tag(), ValueTag::List);
    assert_eq!(heap.len(), 1);
    let list = heap.get_list(value).expect("list exists");
    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first element").as_int(), Ok(1));
    assert_eq!(list.get(1).expect("second element").as_bool(), Ok(true));
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

#[test]
fn identical_list_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("second list allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    let list = heap.get_list(second).expect("second list exists");
    assert_eq!(list.len(), 2);
    assert_eq!(list.get(0).expect("first element").as_int(), Ok(1));
    assert_eq!(list.get(1).expect("second element").as_bool(), Ok(true));
}

#[test]
fn list_values_with_different_elements_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![Value::int(2)]))
        .expect("second list allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn list_values_with_same_thunk_identity_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let first = heap
        .alloc_list(NixList::new(vec![thunk]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![thunk]))
        .expect("second list allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 2);
}

#[test]
fn permanent_container_records_can_reference_worker_domain_children() {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"child").expect("child symbol interns");
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");
    let list = heap
        .alloc_list(NixList::new(vec![thunk]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(
            7,
            FlatAttrs::new(vec![AttrEntry::new(key, thunk)], &symbols).expect("attrs build"),
        )
        .expect("attrs allocate");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, list)
        .expect("list root records");
    roots
        .try_push_value_stack(1, attrs)
        .expect("attrs root records");

    assert_eq!(
        allocation_domain(&heap, thunk),
        HeapAllocationDomain::Worker
    );
    assert_eq!(
        allocation_domain(&heap, list),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(
        allocation_domain(&heap, attrs),
        HeapAllocationDomain::PermanentShared
    );

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let list_edges = object_for(&scan, list).edges();
    assert_eq!(list_edges.len(), 1);
    assert_eq!(
        list_edges[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert!(list_edges[0].value().raw_eq(thunk));

    let attrs_edges = object_for(&scan, attrs).edges();
    assert_eq!(attrs_edges.len(), 1);
    assert_eq!(
        attrs_edges[0].source(),
        &HeapEdgeSource::AttrBinding {
            shape: 7,
            slot: 0,
            key,
        }
    );
    assert!(attrs_edges[0].value().raw_eq(thunk));
    assert!(object_for(&scan, thunk).edges().is_empty());
}

#[test]
fn list_values_with_distinct_thunk_identities_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("first thunk allocates");
    let second_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("second thunk allocates");
    let first = heap
        .alloc_list(NixList::new(vec![first_thunk]))
        .expect("first list allocates");
    let second = heap
        .alloc_list(NixList::new(vec![second_thunk]))
        .expect("second list allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 4);
}

#[test]
fn allocates_thunk_values_and_recovers_body() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let body = IrId::new(7);
    let value = heap
        .alloc_thunk(EvalThunk::new(body))
        .expect("thunk allocates");

    assert_eq!(value.tag(), ValueTag::Thunk);
    assert_eq!(heap.len(), 1);
    let thunk = heap.get_thunk(value).expect("thunk exists");
    assert_eq!(thunk.body(), Some(body));
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
    assert_eq!(heap.arena_stats().chunks, 1);
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::Worker
    );
}

#[test]
fn allocates_apply_thunk_values_and_recovers_work() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(1),
            Span::new(0, 1),
            Value::int(7),
            EvalModuleId::ROOT,
            IrId::new(2),
            Value::bool(true),
        ))
        .expect("thunk allocates");

    assert_eq!(value.tag(), ValueTag::Thunk);
    assert_eq!(heap.len(), 1);
    let thunk = heap.get_thunk(value).expect("thunk exists");
    assert_eq!(thunk.body(), None);
    assert!(matches!(thunk.kind(), EvalThunkKind::Apply { .. }));
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn allocates_lambda_values_and_recovers_closure() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let pattern = IrId::new(3);
    let body = IrId::new(7);
    let frame = FrameId::new(1);
    let value = heap
        .alloc_lambda(EvalLambda::new(pattern, body, frame, EvalEnv::default()))
        .expect("lambda allocates");

    assert_eq!(value.tag(), ValueTag::Lambda);
    assert_eq!(heap.len(), 1);
    let lambda = heap.get_lambda(value).expect("lambda exists");
    assert_eq!(lambda.pattern(), pattern);
    assert_eq!(lambda.body(), body);
    assert_eq!(lambda.frame(), frame);
    assert!(lambda.env().frames().is_empty());
    assert_eq!(heap.arena_stats().chunks, 1);
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::Worker
    );
}

#[test]
fn allocates_primop_values_and_recovers_record() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let argument = EvalPrimOpArg::new(IrId::new(2), Span::new(4, 8), Value::int(3));
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![argument],
        ))
        .expect("primop allocates");

    assert_eq!(value.tag(), ValueTag::Primop);
    assert_eq!(heap.len(), 1);
    let primop = heap.get_primop(value).expect("primop exists");
    assert_eq!(primop.builtin(), Some(builtin));
    assert_eq!(primop.symbol(), symbol);
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].id(), IrId::new(2));
    assert_eq!(primop.args()[0].span(), Span::new(4, 8));
    assert!(primop.args()[0].value().raw_eq(Value::int(3)));
    assert_eq!(heap.arena_stats().chunks, 1);
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::Worker
    );
}

#[test]
fn lambdas_primops_and_thunks_are_not_hash_consed() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let argument = EvalPrimOpArg::new(IrId::new(2), Span::new(4, 8), Value::int(3));
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");

    let first_lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(7),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("first lambda allocates");
    let second_lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(7),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("second lambda allocates");
    let first_primop = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![argument],
        ))
        .expect("first primop allocates");
    let second_primop = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![argument],
        ))
        .expect("second primop allocates");
    let first_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("first thunk allocates");
    let second_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("second thunk allocates");

    assert_ne!(first_lambda.payload_bits(), second_lambda.payload_bits());
    assert_ne!(first_primop.payload_bits(), second_primop.payload_bits());
    assert_ne!(first_thunk.payload_bits(), second_thunk.payload_bits());
    assert_eq!(heap.len(), 6);
    assert!(
        heap.records
            .iter()
            .all(|record| record.structural_hash.is_none()),
        "effectful heap records must not participate in structural consing"
    );
    assert!(
        heap.records
            .iter()
            .all(|record| record.allocation_domain == HeapAllocationDomain::Worker),
        "effectful heap records must stay in the worker allocation domain"
    );
    assert_eq!(heap.permanent_arena_stats(), ArenaStats::default());
}

#[test]
fn public_primop_constructors_keep_symbol_only_records() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let argument = EvalPrimOpArg::new(IrId::new(2), Span::new(4, 8), Value::int(3));

    let empty = EvalPrimOp::new(symbol);
    assert_eq!(empty.builtin(), None);
    assert_eq!(empty.symbol(), symbol);
    assert!(empty.args().is_empty());

    let partial = EvalPrimOp::with_args(symbol, vec![argument]);
    assert_eq!(partial.builtin(), None);
    assert_eq!(partial.symbol(), symbol);
    assert_eq!(partial.args().len(), 1);
}

#[test]
fn allocates_attr_values_and_recovers_entries() {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, Value::int(7))], &symbols).expect("attrs build");
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap.alloc_attrs(42, attrs).expect("attrs allocate");

    assert_eq!(value.tag(), ValueTag::Attrs);
    assert_eq!(heap.len(), 1);
    let attrs = heap.get_attrs(value).expect("attrs exist");
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs.get(key).expect("name exists").as_int(), Ok(7));
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

#[test]
fn identical_attr_values_with_same_shape_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("second attrs allocate");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    let attrs = heap.get_attrs(second).expect("second attrs exist");
    assert_eq!(attrs.len(), 1);
}

#[test]
fn attr_values_with_different_shapes_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(1, attrs_with_one_entry())
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(2, attrs_with_one_entry())
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn attr_values_with_different_binding_values_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let first = heap
        .alloc_attrs(0, attrs_with_value(Value::int(7)))
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(0, attrs_with_value(Value::int(8)))
        .expect("second attrs allocate");
    assert_ne!(first.payload_bits(), second.payload_bits());

    let first_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("first thunk allocates");
    let second_thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("second thunk allocates");
    let first_attrs = heap
        .alloc_attrs(0, attrs_with_value(first_thunk))
        .expect("first thunk attrs allocate");
    let second_attrs = heap
        .alloc_attrs(0, attrs_with_value(second_thunk))
        .expect("second thunk attrs allocate");

    assert_ne!(first_attrs.payload_bits(), second_attrs.payload_bits());
    assert_eq!(heap.len(), 6);
}

#[test]
fn attr_values_with_different_source_order_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_attrs(0, attrs_with_ordered_entries(b"a", b"b"))
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(0, attrs_with_ordered_entries(b"b", b"a"))
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn attr_values_with_different_positions_do_not_collapse() {
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let first_attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            key,
            Value::int(7),
            AttrPosition::new(0, Span::new(0, 1)),
        )],
        &symbols,
    )
    .expect("first attrs build");
    let second_attrs = FlatAttrs::new(
        vec![AttrEntry::with_position(
            key,
            Value::int(7),
            AttrPosition::new(0, Span::new(1, 2)),
        )],
        &symbols,
    )
    .expect("second attrs build");
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(0, first_attrs)
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs(0, second_attrs)
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
}

#[test]
fn mixed_heap_object_types_keep_distinct_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"name".to_vec()))
        .expect("string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(b"/tmp/name".to_vec()))
        .expect("path allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(7)]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(9, attrs_with_one_entry())
        .expect("attrs allocate");
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let primop = heap
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("primop allocates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("thunk allocates");

    assert_ne!(string.payload_bits(), path.payload_bits());
    assert_ne!(string.payload_bits(), list.payload_bits());
    assert_ne!(string.payload_bits(), attrs.payload_bits());
    assert_ne!(string.payload_bits(), primop.payload_bits());
    assert_ne!(string.payload_bits(), thunk.payload_bits());
    assert_ne!(path.payload_bits(), list.payload_bits());
    assert_ne!(path.payload_bits(), attrs.payload_bits());
    assert_ne!(path.payload_bits(), primop.payload_bits());
    assert_ne!(path.payload_bits(), thunk.payload_bits());
    assert_ne!(list.payload_bits(), attrs.payload_bits());
    assert_ne!(list.payload_bits(), primop.payload_bits());
    assert_ne!(list.payload_bits(), thunk.payload_bits());
    assert_ne!(attrs.payload_bits(), primop.payload_bits());
    assert_ne!(attrs.payload_bits(), thunk.payload_bits());
    assert_ne!(primop.payload_bits(), thunk.payload_bits());
    assert_eq!(heap.len(), 6);
    assert_eq!(
        heap.get_string(string).expect("string exists").bytes(),
        b"name"
    );
    assert_eq!(
        heap.get_path(path).expect("path exists").bytes(),
        b"/tmp/name"
    );
    assert_eq!(
        heap.get_list(list)
            .expect("list exists")
            .get(0)
            .expect("first element")
            .as_int(),
        Ok(7)
    );
    assert_eq!(heap.get_attrs(attrs).expect("attrs exist").len(), 1);
    assert_eq!(
        heap.get_primop(primop).expect("primop exists").symbol(),
        symbol
    );
    assert_eq!(
        heap.get_thunk(thunk).expect("thunk exists").body(),
        Some(IrId::new(3))
    );
}

#[test]
fn preserves_context_bearing_strings() {
    let context = StringContext::singleton(
        ContextElement::opaque_path(b"/nix/store/source".to_vec()).expect("context builds"),
    )
    .expect("singleton context allocates");
    let string = NixString::new(b"payload".to_vec(), context);
    let mut heap = EvalHeap::new();
    let value = heap.alloc_string(string).expect("string allocates");
    let stored = heap.get_string(value).expect("string exists");

    assert_eq!(stored.bytes(), b"payload");
    assert!(stored.has_context());
    assert_eq!(stored.context().len(), 1);
    assert_eq!(stored.context().elements()[0].path(), b"/nix/store/source");
}

#[test]
fn rejects_string_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
        .expect("foreign string allocates");
    let ptr = foreign.as_string_ptr().expect("foreign is a string");
    let error = heap
        .get_string(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::String, ptr));
}

#[test]
fn rejects_path_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_path(NixString::from_bytes(b"/tmp/foreign".to_vec()))
        .expect("foreign path allocates");
    let ptr = foreign.as_path_ptr().expect("foreign is a path");
    let error = heap
        .get_path(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Path, ptr));
}

#[test]
fn rejects_list_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("foreign list allocates");
    let ptr = foreign.as_list_ptr().expect("foreign is a list");
    let error = heap
        .get_list(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::List, ptr));
}

#[test]
fn rejects_attr_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_attrs(0, attrs_with_one_entry())
        .expect("foreign attrs allocate");
    let ptr = foreign.as_attrs_ptr().expect("foreign is an attrset");
    let error = heap
        .get_attrs(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Attrs, ptr));
}

#[test]
fn rejects_thunk_values_from_another_live_heap() {
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("foreign thunk allocates");
    let ptr = foreign.as_thunk_ptr().expect("foreign is a thunk");
    let error = heap
        .get_thunk(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Thunk, ptr));
}

#[test]
fn rejects_primop_values_from_another_live_heap() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let heap = EvalHeap::new();
    let mut other = EvalHeap::new();
    let foreign = other
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("foreign primop allocates");
    let ptr = foreign.as_primop_ptr().expect("foreign is a primop");
    let error = heap
        .get_primop(foreign)
        .expect_err("foreign pointer is not in this heap");

    assert_eq!(error, EvalHeapError::unknown(ValueTag::Primop, ptr));
}

#[test]
fn rejects_wrong_value_tags_for_string_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_string(Value::int(1))
        .expect_err("integer is not a string");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "string",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_path_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_path(Value::int(1))
        .expect_err("integer is not a path");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "path",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_list_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_list(Value::int(1))
        .expect_err("integer is not a list");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "list",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_thunk_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_thunk(Value::int(1))
        .expect_err("integer is not a thunk");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "thunk",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_primop_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_primop(Value::int(1))
        .expect_err("integer is not a primop");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "primop",
            actual: ValueTag::Int,
        })
    );
}

#[test]
fn rejects_wrong_value_tags_for_attrs_lookup() {
    let heap = EvalHeap::new();
    let error = heap
        .get_attrs(Value::int(1))
        .expect_err("integer is not an attrset");

    assert_eq!(
        error,
        EvalHeapError::Value(ValueError::Type {
            expected: "attrs",
            actual: ValueTag::Int,
        })
    );
}

fn object_for(scan: &PreciseHeapScan, value: Value) -> &HeapObjectScan {
    scan.objects()
        .iter()
        .find(|object| object.value().raw_eq(value))
        .expect("object is scanned")
}

#[test]
fn precise_root_scan_filters_inline_values_and_walks_typed_fields() {
    let mut symbols = SymbolTable::new();
    let child_key = symbols.intern(b"child").expect("child symbol interns");
    let inline_key = symbols.intern(b"inline").expect("inline symbol interns");
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let leaf = heap
        .alloc_string(NixString::from_bytes(b"leaf".to_vec()))
        .expect("leaf string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), leaf]))
        .expect("list allocates");
    let attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(inline_key, Value::bool(true)),
            AttrEntry::new(child_key, list),
        ],
        &symbols,
    )
    .expect("attrs build");
    let root = heap.alloc_attrs(17, attrs).expect("attrs allocate");
    let mut roots = EvalRootSet::new();

    assert!(
        !roots
            .try_push_value_stack(0, Value::int(99))
            .expect("inline root ignored")
    );
    assert!(
        !roots
            .try_push_stack_map(1, 2, StackMapSlot::Stack { offset: -16 }, Value::null(),)
            .expect("inline stack-map value ignored")
    );
    assert!(
        roots
            .try_push_value_stack(1, root)
            .expect("heap root records")
    );

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");

    assert_eq!(scan.roots().len(), 1);
    assert_eq!(scan.objects().len(), 3);
    assert!(scan.objects()[0].value().raw_eq(root));
    assert!(scan.objects()[1].value().raw_eq(list));
    assert!(scan.objects()[2].value().raw_eq(leaf));

    let root_edges = object_for(&scan, root).edges();
    assert_eq!(root_edges.len(), 1);
    assert_eq!(
        root_edges[0].source(),
        &HeapEdgeSource::AttrBinding {
            shape: 17,
            slot: 0,
            key: child_key,
        }
    );
    assert!(root_edges[0].value().raw_eq(list));

    let list_edges = object_for(&scan, list).edges();
    assert_eq!(list_edges.len(), 1);
    assert_eq!(
        list_edges[0].source(),
        &HeapEdgeSource::ListElement { index: 1 }
    );
    assert!(list_edges[0].value().raw_eq(leaf));
    assert!(object_for(&scan, leaf).edges().is_empty());
}

#[test]
fn collector_poll_root_scan_pairs_poll_request_with_precise_heap_graph() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let leaf = heap
        .alloc_string(NixString::from_bytes(b"leaf".to_vec()))
        .expect("leaf string allocates");
    let root = heap
        .alloc_list(NixList::new(vec![Value::int(1), leaf]))
        .expect("list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("heap root records");

    let snapshot = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");

    assert_eq!(snapshot.poll(), poll);
    assert_eq!(snapshot.heap_records(), heap.len());
    assert_eq!(
        snapshot.allocation_safepoints(),
        heap.allocation_safepoints()
    );
    assert_eq!(
        snapshot.permanent_allocation_safepoints(),
        heap.permanent_allocation_safepoints()
    );
    assert_eq!(snapshot.scan().roots().len(), 1);
    assert_eq!(snapshot.scan().objects().len(), 2);
    assert!(snapshot.scan().objects()[0].value().raw_eq(root));
    assert!(snapshot.scan().objects()[1].value().raw_eq(leaf));
    assert_eq!(
        snapshot.poll().reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert_eq!(
        snapshot.poll().entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocList
    );
}

#[test]
fn collector_poll_minor_gc_plan_tracks_worker_survivor_frontier() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let sibling = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("sibling thunk allocates");
    let frame = EvalFrame::new(2).expect("frame allocates");
    frame.set(0, child).expect("slot writes");
    frame.set(1, sibling).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            env,
        ))
        .expect("lambda allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, lambda)
        .expect("lambda root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();

    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");

    assert_eq!(planned.poll(), poll);
    assert_eq!(
        planned.roots(),
        &[ResolvedValueGeneration::Heap {
            address: gc_address(lambda),
            generation: HeapGeneration::Young,
        }]
    );
    assert_eq!(planned.nursery_objects().len(), 3);
    assert_eq!(planned.nursery_fields().len(), 3);
    let lambda_fields = planned
        .nursery_fields()
        .iter()
        .find(|fields| fields.address() == gc_address(lambda))
        .expect("lambda field metadata records");
    assert_eq!(lambda_fields.fields().len(), 2);
    assert_eq!(
        lambda_fields.fields()[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Lambda,
            frame: 0,
            slot: 0,
        }
    );
    assert_eq!(
        lambda_fields.fields()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        lambda_fields.fields()[1].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Lambda,
            frame: 0,
            slot: 1,
        }
    );
    assert_eq!(
        lambda_fields.fields()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(sibling),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(planned.plan().survivors().len(), 3);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(lambda));
    assert_eq!(planned.plan().survivors()[1].address(), gc_address(child));
    assert_eq!(planned.plan().survivors()[2].address(), gc_address(sibling));
    assert_eq!(planned.reference_slots().len(), 3);
    assert_eq!(
        planned.reference_slots()[0].source(),
        &AllocationCollectorPollReferenceSource::Root {
            source: EvalRootSource::ValueStack { slot: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(lambda),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::NurseryField {
            object: gc_address(lambda),
            field_index: 0,
            source: HeapEdgeSource::CapturedEnv {
                owner: CapturedRootOwner::Lambda,
                frame: 0,
                slot: 0,
            },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        planned.reference_slots()[2].source(),
        &AllocationCollectorPollReferenceSource::NurseryField {
            object: gc_address(lambda),
            field_index: 1,
            source: HeapEdgeSource::CapturedEnv {
                owner: CapturedRootOwner::Lambda,
                frame: 0,
                slot: 1,
            },
        }
    );
    assert_eq!(
        planned.reference_slots()[2].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(sibling),
            generation: HeapGeneration::Young,
        }
    );

    let nursery_layouts = [
        NurseryObjectLayout::new(gc_address(lambda), 16, 8),
        NurseryObjectLayout::new(gc_address(child), 16, 8),
        NurseryObjectLayout::new(gc_address(sibling), 16, 8),
    ];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan builds");
    assert_eq!(destinations.allocation_plan().nursery_bytes(), 48);
    assert_eq!(destinations.allocation_plan().old_bytes(), 0);
    assert_eq!(destinations.placement_plan().nursery_reserved_bytes(), 48);
    assert_eq!(destinations.placement_plan().old_reserved_bytes(), 0);
    assert_eq!(destinations.destinations().len(), 3);
    let lambda_destination = destinations.destinations()[0].destination();
    let child_destination = destinations.destinations()[1].destination();
    let sibling_destination = destinations.destinations()[2].destination();
    assert_eq!(lambda_destination, static_gc_address(0x1000_0000));
    assert_eq!(child_destination, static_gc_address(0x1000_0010));
    assert_eq!(sibling_destination, static_gc_address(0x1000_0020));
    let relocation_destinations = destinations.destinations();
    let relocation_plan =
        MinorGcRelocationPlan::from_minor_gc_plan(planned.plan(), relocation_destinations)
            .expect("relocation plan builds");
    let rewrite_plan = planned
        .reference_rewrite_plan(&relocation_plan)
        .expect("reference rewrite plan builds");
    assert_eq!(rewrite_plan.rewrites().len(), 3);
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 0);
    assert_eq!(rewrite_plan.rewrites()[0].source(), gc_address(lambda));
    assert_eq!(rewrite_plan.rewrites()[0].destination(), lambda_destination);
    assert_eq!(rewrite_plan.rewrites()[1].slot(), 1);
    assert_eq!(rewrite_plan.rewrites()[1].source(), gc_address(child));
    assert_eq!(rewrite_plan.rewrites()[1].destination(), child_destination);
    assert_eq!(rewrite_plan.rewrites()[2].slot(), 2);
    assert_eq!(rewrite_plan.rewrites()[2].source(), gc_address(sibling));
    assert_eq!(
        rewrite_plan.rewrites()[2].destination(),
        sibling_destination
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    assert_eq!(commit.reference_slots(), planned.reference_slots());
    assert_eq!(commit.commit_plan().object_copies().copies().len(), 3);
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].source(),
        gc_address(lambda)
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination(),
        lambda_destination
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[1].source(),
        gc_address(child)
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[1].destination(),
        child_destination
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[2].source(),
        gc_address(sibling)
    );
    assert_eq!(
        commit.commit_plan().object_copies().copies()[2].destination(),
        sibling_destination
    );
    assert_eq!(
        commit.commit_plan().forwarding_pointers().pointers().len(),
        3
    );
    assert_eq!(
        commit
            .forwarding_slot_buffer()
            .expect("forwarding slot buffer derives"),
        vec![
            MinorGcForwardingSlot::new(gc_address(lambda)),
            MinorGcForwardingSlot::new(gc_address(child)),
            MinorGcForwardingSlot::new(gc_address(sibling)),
        ]
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites(),
        rewrite_plan.rewrites()
    );
    assert!(commit.commit_plan().remembered_set_refresh().is_empty());
    assert_eq!(
        commit.commit_plan().next_remembered_set().epoch(),
        remembered_set
            .epoch()
            .checked_next()
            .expect("epoch advances")
    );
    assert!(commit.commit_plan().next_remembered_set().is_empty());

    let short_commit = planned
        .commit_plan(&destinations)
        .expect("short-buffer commit plan builds");
    let mut no_object_byte_copies: Vec<MinorGcObjectByteCopyBuffer<'_>> = Vec::new();
    let mut no_forwarding_slots = Vec::new();
    let mut short_references = [planned.reference_slots()[0].value()];
    let mut short_remembered_set = remembered_set.clone();
    assert_eq!(
        short_commit
            .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
                &mut no_object_byte_copies,
                &mut no_forwarding_slots,
                &mut short_references,
                &mut short_remembered_set,
            ))
            .expect_err("short reference buffer is rejected before lower-level buffers"),
        EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
            expected: planned.reference_slots().len(),
            actual: short_references.len(),
        }
    );
    assert_eq!(short_references, [planned.reference_slots()[0].value()]);
    assert_eq!(short_remembered_set, remembered_set);

    let occupied_commit = planned
        .commit_plan(&destinations)
        .expect("occupied-slot commit plan builds");
    let occupied_lambda_source_bytes = [9u8; 16];
    let occupied_child_source_bytes = [8u8; 16];
    let occupied_sibling_source_bytes = [7u8; 16];
    let mut occupied_lambda_destination_bytes = [0u8; 16];
    let mut occupied_child_destination_bytes = [0u8; 16];
    let mut occupied_sibling_destination_bytes = [0u8; 16];
    let mut occupied_object_byte_copies = [
        MinorGcObjectByteCopyBuffer::new(
            gc_address(lambda),
            lambda_destination,
            &occupied_lambda_source_bytes,
            &mut occupied_lambda_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(child),
            child_destination,
            &occupied_child_source_bytes,
            &mut occupied_child_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(sibling),
            sibling_destination,
            &occupied_sibling_source_bytes,
            &mut occupied_sibling_destination_bytes,
        ),
    ];
    let occupied_forwarded_value = ResolvedValueGeneration::Heap {
        address: lambda_destination,
        generation: HeapGeneration::Young,
    };
    let mut occupied_forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(lambda), occupied_forwarded_value),
        MinorGcForwardingSlot::new(gc_address(child)),
        MinorGcForwardingSlot::new(gc_address(sibling)),
    ];
    let mut occupied_references = planned.reference_values().collect::<Vec<_>>();
    let mut occupied_remembered_set = remembered_set.clone();
    assert_eq!(
        occupied_commit
            .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
                &mut occupied_object_byte_copies,
                &mut occupied_forwarding_slots,
                &mut occupied_references,
                &mut occupied_remembered_set,
            ))
            .expect_err("occupied forwarding slot is rejected"),
        EvalHeapError::GenerationalGc(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
            index: 0,
            address: gc_address(lambda),
            actual: occupied_forwarded_value,
        })
    );
    assert_eq!(occupied_lambda_destination_bytes, [0u8; 16]);
    assert_eq!(occupied_child_destination_bytes, [0u8; 16]);
    assert_eq!(occupied_sibling_destination_bytes, [0u8; 16]);
    assert_eq!(
        occupied_forwarding_slots[0].forwarded_value(),
        Some(occupied_forwarded_value)
    );
    assert!(occupied_forwarding_slots[1].is_empty());
    assert!(occupied_forwarding_slots[2].is_empty());
    assert_eq!(
        occupied_references,
        planned.reference_values().collect::<Vec<_>>()
    );
    assert_eq!(occupied_remembered_set, remembered_set);

    let expected_next_remembered_set = commit.commit_plan().next_remembered_set().clone();
    let lambda_source_bytes = [1u8; 16];
    let child_source_bytes = [2u8; 16];
    let sibling_source_bytes = [3u8; 16];
    let mut lambda_destination_bytes = [0u8; 16];
    let mut child_destination_bytes = [0u8; 16];
    let mut sibling_destination_bytes = [0u8; 16];
    let mut object_byte_copies = [
        MinorGcObjectByteCopyBuffer::new(
            gc_address(lambda),
            lambda_destination,
            &lambda_source_bytes,
            &mut lambda_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(child),
            child_destination,
            &child_source_bytes,
            &mut child_destination_bytes,
        ),
        MinorGcObjectByteCopyBuffer::new(
            gc_address(sibling),
            sibling_destination,
            &sibling_source_bytes,
            &mut sibling_destination_bytes,
        ),
    ];
    let mut forwarding_slots = commit
        .forwarding_slot_buffer()
        .expect("success forwarding slot buffer derives");
    let mut references = planned.reference_values().collect::<Vec<_>>();
    let mut commit_remembered_set = remembered_set.clone();

    let report = commit
        .apply_to_buffers_with_report(AllocationCollectorPollMinorGcCommitBuffers::new(
            &mut object_byte_copies,
            &mut forwarding_slots,
            &mut references,
            &mut commit_remembered_set,
        ))
        .expect("collector-poll commit buffers apply");

    assert_eq!(report.object_copies(), 3);
    assert_eq!(report.copied_to_nursery(), 3);
    assert_eq!(report.promoted_to_old(), 0);
    assert_eq!(report.forwarding_pointers(), 3);
    assert_eq!(report.reference_rewrites(), 3);
    assert_eq!(report.remembered_set_source_epoch(), remembered_set.epoch());
    assert_eq!(
        report.remembered_set_next_epoch(),
        remembered_set
            .epoch()
            .checked_next()
            .expect("epoch advances")
    );
    assert_eq!(report.remembered_set_source_edges(), 0);
    assert_eq!(report.remembered_set_published_edges(), 0);
    assert_eq!(lambda_destination_bytes, lambda_source_bytes);
    assert_eq!(child_destination_bytes, child_source_bytes);
    assert_eq!(sibling_destination_bytes, sibling_source_bytes);
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: lambda_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        forwarding_slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        forwarding_slots[2].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: sibling_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        references,
        vec![
            ResolvedValueGeneration::Heap {
                address: lambda_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: child_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: sibling_destination,
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(commit_remembered_set, expected_next_remembered_set);
}

#[test]
fn collector_poll_minor_gc_keeps_hash_consed_roots_out_of_survivor_frontier() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("thunk allocates");
    let lambda = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lambda allocates");
    let primop = heap
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("primop allocates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"hash-consed".to_vec()))
        .expect("string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(b"/nix/store/source".to_vec()))
        .expect("path allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(9, attrs_with_value(Value::int(3)))
        .expect("attrs allocates");
    let expected_cold_hash_consed_bytes = record_layout_size(&heap, string)
        + record_layout_size(&heap, path)
        + record_layout_size(&heap, list)
        + record_layout_size(&heap, attrs);
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    for (slot, value) in [string, path, list, attrs].into_iter().enumerate() {
        roots
            .try_push_value_stack(slot, value)
            .expect("hash-consed root records");
    }
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();

    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");

    assert_eq!(
        [string, path, list, attrs].map(|value| allocation_domain(&heap, value)),
        [HeapAllocationDomain::PermanentShared; 4]
    );
    assert_eq!(
        [thunk, lambda, primop].map(|value| allocation_domain(&heap, value)),
        [HeapAllocationDomain::Worker; 3]
    );
    assert_eq!(
        heap.cold_hash_consed_bytes(0),
        expected_cold_hash_consed_bytes
    );
    assert_eq!(
        planned.roots(),
        &[
            ResolvedValueGeneration::Heap {
                address: gc_address(string),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(path),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(list),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(attrs),
                generation: HeapGeneration::Permanent,
            },
        ]
    );
    assert!(planned.plan().survivors().is_empty());
    assert_eq!(planned.nursery_objects().len(), 3);
    assert!(
        planned
            .nursery_objects()
            .iter()
            .any(|object| object.address() == gc_address(thunk))
    );
    assert!(
        planned
            .nursery_objects()
            .iter()
            .any(|object| object.address() == gc_address(lambda))
    );
    assert!(
        planned
            .nursery_objects()
            .iter()
            .any(|object| object.address() == gc_address(primop))
    );
    assert_eq!(planned.reference_slots().len(), 4);
    assert!(planned.reference_slots().iter().all(|slot| matches!(
        slot.value(),
        ResolvedValueGeneration::Heap {
            generation: HeapGeneration::Permanent,
            ..
        }
    )));
}

#[test]
fn collector_poll_minor_gc_commit_plan_rejects_foreign_destination_plan() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("second thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let remembered_set = RememberedSet::new();
    let mut first_roots = EvalRootSet::new();
    first_roots
        .try_push_value_stack(0, first)
        .expect("first root records");
    let first_scan = heap
        .scan_collector_poll_roots(poll, &first_roots)
        .expect("first collector-poll root scan succeeds");
    let first_plan = heap
        .plan_collector_poll_minor_gc(
            &first_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("first minor-GC plan builds");

    let mut second_roots = EvalRootSet::new();
    second_roots
        .try_push_value_stack(0, second)
        .expect("second root records");
    let second_scan = heap
        .scan_collector_poll_roots(poll, &second_roots)
        .expect("second collector-poll root scan succeeds");
    let second_plan = heap
        .plan_collector_poll_minor_gc(
            &second_scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("second minor-GC plan builds");
    let second_layouts = [NurseryObjectLayout::new(gc_address(second), 16, 8)];
    let second_destinations = second_plan
        .relocation_destination_plan(
            &second_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("second destination plan builds");

    assert_eq!(
        first_plan
            .commit_plan(&second_destinations)
            .expect_err("foreign destination plan is rejected"),
        GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
            expected: gc_address(first),
            actual: gc_address(second),
        }
    );
}

#[test]
fn collector_poll_minor_gc_commit_plan_rejects_destination_plan_with_foreign_action() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let copy_plan = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("copy minor-GC plan builds");
    let promote_plan = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(0),
        )
        .expect("promote minor-GC plan builds");
    let copy_layouts = [NurseryObjectLayout::new(gc_address(child), 16, 8)];
    let copy_destinations = copy_plan
        .relocation_destination_plan(
            &copy_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("copy destination plan builds");

    assert_eq!(
        promote_plan
            .commit_plan(&copy_destinations)
            .expect_err("foreign-action destination plan is rejected"),
        GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
            address: gc_address(child),
            expected: MinorGcSurvivorAction::PromoteToOld,
            actual: MinorGcSurvivorAction::CopyToNursery,
        }
    );
}

#[test]
fn collector_poll_minor_gc_relocation_destinations_derive_layouts_from_heap_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");

    let base = static_gc_address(0x1000_0000);
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(base, static_gc_address(0x2000_0000)),
        )
        .expect("destination plan derives heap layouts");
    let expected_thunk_bytes = std::mem::size_of::<u64>() * 3;
    let expected_align = std::mem::align_of::<u64>();

    assert_eq!(
        destinations.allocation_plan().nursery_bytes(),
        expected_thunk_bytes
    );
    assert_eq!(destinations.allocation_plan().old_bytes(), 0);
    assert_eq!(
        destinations.placement_plan().nursery_reserved_bytes(),
        expected_thunk_bytes
    );
    assert_eq!(destinations.destinations()[0].destination(), base);
    assert_eq!(
        destinations.placement_plan().placements()[0].align(),
        expected_align
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds from derived layouts");
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].size_bytes(),
        expected_thunk_bytes
    );
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    assert_eq!(byte_copy_plan.len(), 1);
    assert!(!byte_copy_plan.is_empty());
    assert_eq!(byte_copy_plan.copy_to_nursery_count(), 1);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 0);
    assert_eq!(byte_copy_plan.copy_to_nursery_bytes(), expected_thunk_bytes);
    assert_eq!(byte_copy_plan.promote_to_old_bytes(), 0);
    let byte_copy = &byte_copy_plan.requests()[0];
    assert_eq!(byte_copy.source(), gc_address(child));
    assert_eq!(byte_copy.destination(), base);
    assert_eq!(byte_copy.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(byte_copy.destination_generation(), HeapGeneration::Young);
    assert_eq!(byte_copy.size_bytes(), expected_thunk_bytes);
    assert_eq!(byte_copy.align(), expected_align);
    assert_eq!(
        byte_copy_plan
            .copy_to_nursery_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![*byte_copy]
    );
    assert_eq!(
        byte_copy_plan
            .promote_to_old_requests()
            .copied()
            .collect::<Vec<_>>(),
        Vec::new()
    );
}

#[test]
fn collector_poll_minor_gc_object_byte_copy_plan_partitions_mixed_actions() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let first_copy = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first copied thunk allocates");
    let promote = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("promoted thunk allocates");
    let second_copy = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("second copied thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let first_copy_address = gc_address(first_copy);
    let promote_address = gc_address(promote);
    let second_copy_address = gc_address(second_copy);
    let roots = vec![
        ResolvedValueGeneration::young(first_copy_address),
        ResolvedValueGeneration::young(promote_address),
        ResolvedValueGeneration::young(second_copy_address),
    ];
    let nursery_objects = vec![
        NurseryObjectAge::new(first_copy_address, 0),
        NurseryObjectAge::new(promote_address, 1),
        NurseryObjectAge::new(second_copy_address, 0),
    ];
    let remembered_set = RememberedSet::new();
    let plan = MinorGcPlan::from_roots_and_remembered(
        roots.iter().copied(),
        remembered_set.snapshot(),
        remembered_set.epoch(),
        &nursery_objects,
        MinorGcPromotionPolicy::new(2),
    )
    .expect("mixed-action minor-GC plan builds");
    let planned = AllocationCollectorPollMinorGcPlan::from_parts_for_test(
        poll,
        heap.records.len(),
        heap.region_owner,
        heap.worker_region_epoch,
        heap.allocation_safepoints(),
        heap.permanent_allocation_safepoints(),
        remembered_set,
        roots,
        nursery_objects,
        Vec::new(),
        Vec::new(),
        plan,
    );
    let first_copy_size = record_layout_size(&heap, first_copy);
    let promote_size = record_layout_size(&heap, promote);
    let second_copy_size = record_layout_size(&heap, second_copy);
    let nursery_layouts = [
        NurseryObjectLayout::new(
            first_copy_address,
            first_copy_size,
            record_layout_align(&heap, first_copy),
        ),
        NurseryObjectLayout::new(
            promote_address,
            promote_size,
            record_layout_align(&heap, promote),
        ),
        NurseryObjectLayout::new(
            second_copy_address,
            second_copy_size,
            record_layout_align(&heap, second_copy),
        ),
    ];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("mixed-action destination plan builds");
    let commit = planned
        .commit_plan(&destinations)
        .expect("mixed-action commit plan builds");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("mixed-action object byte-copy plan derives");

    assert_eq!(byte_copy_plan.len(), 3);
    assert_eq!(byte_copy_plan.copy_to_nursery_count(), 2);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 1);
    assert_eq!(
        byte_copy_plan.copy_to_nursery_bytes(),
        first_copy_size + second_copy_size
    );
    assert_eq!(byte_copy_plan.promote_to_old_bytes(), promote_size);
    assert_eq!(
        byte_copy_plan
            .requests()
            .iter()
            .map(AllocationCollectorPollObjectByteCopyRequest::action)
            .collect::<Vec<_>>(),
        vec![
            MinorGcSurvivorAction::CopyToNursery,
            MinorGcSurvivorAction::PromoteToOld,
            MinorGcSurvivorAction::CopyToNursery,
        ]
    );
    let requests = byte_copy_plan.requests();
    assert_eq!(
        requests
            .iter()
            .map(AllocationCollectorPollObjectByteCopyRequest::source)
            .collect::<Vec<_>>(),
        vec![first_copy_address, promote_address, second_copy_address]
    );
    assert_eq!(requests[0].destination_generation(), HeapGeneration::Young);
    assert_eq!(requests[1].destination_generation(), HeapGeneration::Old);
    assert_eq!(requests[2].destination_generation(), HeapGeneration::Young);
    assert_eq!(
        byte_copy_plan
            .copy_to_nursery_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![requests[0], requests[2]]
    );
    assert_eq!(
        byte_copy_plan
            .promote_to_old_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![requests[1]]
    );
}

#[test]
fn collector_poll_minor_gc_relocation_destinations_reject_post_plan_allocation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let expected_records = planned.heap_records();

    heap.alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("post-plan thunk allocates");

    assert_eq!(
        heap.plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect_err("post-plan allocation is rejected"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "heap record count changed since minor-GC planning",
            expected_records,
            actual_records: expected_records + 1,
        }
    );
}

#[test]
fn collector_poll_minor_gc_object_byte_copy_plan_rejects_post_commit_allocation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let expected_records = commit.heap_records();

    heap.alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("post-commit thunk allocates");

    assert_eq!(
        heap.collector_poll_minor_gc_object_byte_copy_plan(&commit)
            .expect_err("post-commit allocation is rejected"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "heap record count changed since minor-GC commit planning",
            expected_records,
            actual_records: expected_records + 1,
        }
    );
}

#[test]
fn collector_poll_minor_gc_object_byte_copy_plan_rejects_stale_source_layout() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_0000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let expected_size = commit.commit_plan().object_copies().copies()[0].size_bytes();
    let expected_align = commit.commit_plan().object_copies().copies()[0].align();
    let actual_size = expected_size + 8;
    let child_address = gc_address(child);
    let record = heap
        .records
        .iter_mut()
        .find(|record| record.ptr.as_ptr() as usize == child_address.address_bits())
        .expect("child record exists");
    record.layout.size_bytes = actual_size;

    assert_eq!(
        heap.collector_poll_minor_gc_object_byte_copy_plan(&commit)
            .expect_err("stale source layout is rejected"),
        EvalHeapError::CollectorPollObjectByteCopyLayoutMismatch {
            address: child_address,
            expected_size,
            actual_size,
            expected_align,
            actual_align: expected_align,
        }
    );
}

#[test]
fn collector_poll_minor_gc_destination_plan_uses_old_base_for_promotions() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(0),
        )
        .expect("minor-GC plan builds");

    let old_base = static_gc_address(0x3000_0000);
    let nursery_layouts = [NurseryObjectLayout::new(gc_address(child), 24, 8)];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(static_gc_address(0x1000_0000), old_base),
        )
        .expect("destination plan builds");

    assert_eq!(destinations.allocation_plan().nursery_bytes(), 0);
    assert_eq!(destinations.allocation_plan().old_bytes(), 24);
    assert_eq!(destinations.placement_plan().nursery_reserved_bytes(), 0);
    assert_eq!(destinations.placement_plan().old_reserved_bytes(), 24);
    assert_eq!(destinations.destinations().len(), 1);
    assert_eq!(destinations.destinations()[0].destination(), old_base);
    let relocation_plan = destinations
        .relocation_destinations()
        .relocation_plan(planned.plan())
        .expect("relocation plan rebuilds");
    assert_eq!(
        relocation_plan.relocations()[0].destination_generation(),
        HeapGeneration::Old
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    assert_eq!(
        commit.commit_plan().object_copies().copies()[0].destination_generation(),
        HeapGeneration::Old
    );
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("promoted object byte-copy plan derives");
    assert_eq!(byte_copy_plan.len(), 1);
    assert_eq!(byte_copy_plan.copy_to_nursery_count(), 0);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 1);
    assert_eq!(byte_copy_plan.copy_to_nursery_bytes(), 0);
    assert_eq!(byte_copy_plan.promote_to_old_bytes(), 24);
    let byte_copy = &byte_copy_plan.requests()[0];
    assert_eq!(byte_copy.source(), gc_address(child));
    assert_eq!(byte_copy.destination(), old_base);
    assert_eq!(byte_copy.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(byte_copy.destination_generation(), HeapGeneration::Old);
    assert_eq!(byte_copy.size_bytes(), 24);
    assert_eq!(byte_copy.align(), 8);
    assert_eq!(
        byte_copy_plan
            .copy_to_nursery_requests()
            .copied()
            .collect::<Vec<_>>(),
        Vec::new()
    );
    assert_eq!(
        byte_copy_plan
            .promote_to_old_requests()
            .copied()
            .collect::<Vec<_>>(),
        vec![*byte_copy]
    );
    let mut forwarding_slots = commit
        .forwarding_slot_buffer()
        .expect("promoted forwarding slot buffer derives");
    assert_eq!(
        forwarding_slots,
        vec![MinorGcForwardingSlot::new(gc_address(child))]
    );
    commit
        .commit_plan()
        .forwarding_pointers()
        .install_into_slots(&mut forwarding_slots)
        .expect("promoted forwarding slot installs");
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: old_base,
            generation: HeapGeneration::Old,
        })
    );
}

#[test]
fn collector_poll_minor_gc_plan_rejects_unremembered_permanent_to_worker_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("missing remembered edge is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollRememberedEdge {
            source_address: gc_address(root),
            target_address: gc_address(child),
        }
    );
}

#[test]
fn collector_poll_minor_gc_plan_uses_remembered_permanent_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");

    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");

    assert_eq!(
        planned.roots(),
        &[ResolvedValueGeneration::Heap {
            address: gc_address(root),
            generation: HeapGeneration::Permanent,
        }]
    );
    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(planned.reference_slots().len(), 2);
    assert_eq!(
        planned.reference_slots()[0].source(),
        &AllocationCollectorPollReferenceSource::Root {
            source: EvalRootSource::ValueStack { slot: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(root),
            generation: HeapGeneration::Permanent,
        }
    );
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: RememberedEdge::new(gc_address(root), gc_address(child)),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );

    let nursery_layouts = [NurseryObjectLayout::new(gc_address(child), 16, 8)];
    let destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan builds");
    assert_eq!(destinations.allocation_plan().nursery_bytes(), 16);
    assert_eq!(destinations.allocation_plan().old_bytes(), 0);
    assert_eq!(destinations.placement_plan().nursery_reserved_bytes(), 16);
    assert_eq!(destinations.placement_plan().old_reserved_bytes(), 0);
    assert_eq!(destinations.destinations().len(), 1);
    let child_destination = destinations.destinations()[0].destination();
    assert_eq!(child_destination, static_gc_address(0x1000_2000));
    let relocation_destinations = destinations.destinations();
    let relocation_plan =
        MinorGcRelocationPlan::from_minor_gc_plan(planned.plan(), relocation_destinations)
            .expect("relocation plan builds");
    let rewrite_plan = planned
        .reference_rewrite_plan(&relocation_plan)
        .expect("reference rewrite plan builds");
    assert_eq!(rewrite_plan.rewrites().len(), 1);
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 1);
    assert_eq!(rewrite_plan.rewrites()[0].source(), gc_address(child));
    assert_eq!(rewrite_plan.rewrites()[0].destination(), child_destination);

    assert_eq!(planned.remembered_set(), &remembered_set);
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    assert_eq!(commit.reference_slots(), planned.reference_slots());
    assert_eq!(
        commit.commit_plan().remembered_set_refresh().refreshes()[0].retained_edge(),
        Some(RememberedEdge::new(gc_address(root), child_destination))
    );
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[RememberedEdge::new(gc_address(root), child_destination)]
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    assert!(!writeback_plan.is_empty());
    let writeback = &writeback_plan.writebacks()[0];
    assert_eq!(writeback.slot(), 1);
    assert_eq!(writeback.validation_object(), gc_address(root));
    assert_eq!(writeback.writeback_object(), gc_address(root));
    assert_eq!(writeback.field_index(), 0);
    assert_eq!(
        writeback.source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        writeback.expected(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let mismatch_commit = planned
        .commit_plan(&destinations)
        .expect("reference-mismatch commit plan builds");
    let mismatch_child_source_bytes = [5u8; 16];
    let mut mismatch_child_destination_bytes = [0u8; 16];
    let mut mismatch_object_byte_copies = [MinorGcObjectByteCopyBuffer::new(
        gc_address(child),
        child_destination,
        &mismatch_child_source_bytes,
        &mut mismatch_child_destination_bytes,
    )];
    let mut mismatch_forwarding_slots = mismatch_commit
        .forwarding_slot_buffer()
        .expect("mismatch forwarding slot buffer derives");
    let mut mismatch_references = planned.reference_values().collect::<Vec<_>>();
    let expected_root_reference = mismatch_references[0];
    mismatch_references[0] = ResolvedValueGeneration::Inline;
    let mut mismatch_remembered_set = remembered_set.clone();
    assert_eq!(
        mismatch_commit
            .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
                &mut mismatch_object_byte_copies,
                &mut mismatch_forwarding_slots,
                &mut mismatch_references,
                &mut mismatch_remembered_set,
            ))
            .expect_err("same-length reference mismatch is rejected"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: expected_root_reference,
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(mismatch_child_destination_bytes, [0u8; 16]);
    assert!(mismatch_forwarding_slots[0].is_empty());
    assert_eq!(
        mismatch_references,
        vec![
            ResolvedValueGeneration::Inline,
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(mismatch_remembered_set, remembered_set);

    let expected_next_remembered_set = commit.commit_plan().next_remembered_set().clone();
    let child_source_bytes = [4u8; 16];
    let mut child_destination_bytes = [0u8; 16];
    let mut object_byte_copies = [MinorGcObjectByteCopyBuffer::new(
        gc_address(child),
        child_destination,
        &child_source_bytes,
        &mut child_destination_bytes,
    )];
    let mut forwarding_slots = commit
        .forwarding_slot_buffer()
        .expect("remembered-edge forwarding slot buffer derives");
    let mut references = planned.reference_values().collect::<Vec<_>>();
    let mut commit_remembered_set = remembered_set.clone();

    commit
        .apply_to_buffers(AllocationCollectorPollMinorGcCommitBuffers::new(
            &mut object_byte_copies,
            &mut forwarding_slots,
            &mut references,
            &mut commit_remembered_set,
        ))
        .expect("remembered-edge commit buffers apply");

    assert_eq!(child_destination_bytes, child_source_bytes);
    assert_eq!(
        forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        references,
        vec![
            ResolvedValueGeneration::Heap {
                address: gc_address(root),
                generation: HeapGeneration::Permanent,
            },
            ResolvedValueGeneration::Heap {
                address: child_destination,
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(commit_remembered_set, expected_next_remembered_set);
}

#[test]
fn collector_poll_minor_gc_card_table_plan_requires_dirty_remembered_source_card() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let edge = RememberedEdge::new(gc_address(root), gc_address(child));
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(edge)
        .expect("remembered edge records");
    let card_table = GcCardTable::default();

    let error = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("missing dirty source card is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollDirtyCard {
            source_address: edge.source(),
            target_address: edge.target(),
            card_index: card_table.snapshot().card_index_for_source(edge.source()),
        }
    );
}

#[test]
fn collector_poll_minor_gc_card_table_plan_accepts_dirty_remembered_source_card() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let edge = RememberedEdge::new(gc_address(root), gc_address(child));
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(edge)
        .expect("remembered edge records");
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(edge.source())
        .expect("remembered source card marks");

    let planned = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("dirty card admits remembered edge");

    assert_eq!(planned.remembered_set(), &remembered_set);
    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), edge.target());
    assert_eq!(planned.reference_slots().len(), 2);
}

#[test]
fn collector_poll_minor_gc_card_table_plan_rejects_dirty_unremembered_non_survivor_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, permanent_parent)
        .expect("permanent parent root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(gc_address(permanent_parent))
        .expect("permanent parent card marks");

    let error = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("dirty unremembered non-survivor edge is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollRememberedEdge {
            source_address: gc_address(permanent_parent),
            target_address: gc_address(child),
        }
    );
}

#[test]
fn collector_poll_minor_gc_card_table_rescan_publishes_dirty_survivor_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();
    card_table
        .mark_source(gc_address(permanent_parent))
        .expect("permanent parent card marks");

    let planned = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("dirty card admits already-surviving unremembered edge");

    assert_eq!(planned.remembered_set(), &remembered_set);
    assert_eq!(
        planned
            .card_table()
            .expect("card-table-aware plan records dirty cards")
            .dirty_cards(),
        card_table.dirty_cards()
    );
    let old_parent_fields = planned
        .old_fields()
        .iter()
        .find(|fields| fields.address() == gc_address(permanent_parent))
        .expect("permanent parent fields are captured");
    assert_eq!(old_parent_fields.generation(), HeapGeneration::Permanent);
    assert_eq!(old_parent_fields.fields().len(), 1);
    assert_eq!(
        old_parent_fields.fields()[0].source(),
        &HeapEdgeSource::ListElement { index: 0 }
    );
    assert_eq!(
        old_parent_fields.fields()[0].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(planned.reference_slots().len(), 1);

    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan includes dirty old-field rescan");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();

    assert!(commit.commit_plan().remembered_set_refresh().is_empty());
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[RememberedEdge::new(
            gc_address(permanent_parent),
            child_destination,
        )]
    );
    let mut published_remembered_set = remembered_set.clone();
    commit
        .commit_plan()
        .clone()
        .publish_next_remembered_set(&mut published_remembered_set)
        .expect("empty source remembered set publishes rescan edge");
    assert_eq!(
        published_remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(permanent_parent),
            child_destination,
        )]
    );
}

#[test]
fn collector_poll_minor_gc_writeback_plans_filter_mixed_root_and_heap_rewrites() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(
            gc_address(permanent_parent),
            gc_address(child),
        ))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();

    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 1);
    assert_eq!(root_writeback_plan.writebacks()[0].slot(), 0);
    assert_eq!(
        root_writeback_plan.writebacks()[0].source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        root_writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let heap_writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives");
    assert_eq!(heap_writeback_plan.len(), 1);
    assert_eq!(heap_writeback_plan.writebacks()[0].slot(), 1);
    assert_eq!(
        heap_writeback_plan.writebacks()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        heap_writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let reference_writeback_plan = heap
        .collector_poll_minor_gc_reference_writeback_plan(&commit)
        .expect("combined reference writeback plan derives");
    assert_eq!(reference_writeback_plan.len(), 2);
    assert!(!reference_writeback_plan.is_empty());
    assert_eq!(reference_writeback_plan.root_writebacks().len(), 1);
    assert_eq!(
        reference_writeback_plan.root_writebacks().writebacks()[0].slot(),
        0
    );
    assert_eq!(reference_writeback_plan.heap_field_writebacks().len(), 1);
    assert_eq!(
        reference_writeback_plan
            .heap_field_writebacks()
            .writebacks()[0]
            .slot(),
        1
    );

    let mut stale_root_slots = [AllocationCollectorPollRootWritebackSlot::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let mut stale_heap_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(permanent_parent),
        gc_address(permanent_parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Inline,
    )];
    let unchanged_stale_root_slots = stale_root_slots.clone();
    let unchanged_stale_heap_slots = stale_heap_slots.clone();
    assert_eq!(
        reference_writeback_plan
            .apply_to_slots(&mut stale_root_slots, &mut stale_heap_slots)
            .expect_err("stale heap field rejects combined writeback"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_root_slots, unchanged_stale_root_slots);
    assert_eq!(stale_heap_slots, unchanged_stale_heap_slots);

    let mut stale_root_slots = [AllocationCollectorPollRootWritebackSlot::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Inline,
    )];
    let mut stale_heap_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(permanent_parent),
        gc_address(permanent_parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let unchanged_stale_root_slots = stale_root_slots.clone();
    let unchanged_stale_heap_slots = stale_heap_slots.clone();
    assert_eq!(
        reference_writeback_plan
            .apply_to_slots(&mut stale_root_slots, &mut stale_heap_slots)
            .expect_err("stale root rejects combined writeback"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_root_slots, unchanged_stale_root_slots);
    assert_eq!(stale_heap_slots, unchanged_stale_heap_slots);

    let mut root_slots = [AllocationCollectorPollRootWritebackSlot::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let mut heap_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(permanent_parent),
        gc_address(permanent_parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let report = reference_writeback_plan
        .apply_to_slots(&mut root_slots, &mut heap_slots)
        .expect("combined reference writebacks apply");
    assert_eq!(report.root_writebacks(), 1);
    assert_eq!(report.heap_field_writebacks(), 1);
    assert_eq!(report.writebacks(), 2);
    assert_eq!(
        root_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap_slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );

    let reference_buffer = heap
        .collector_poll_minor_gc_reference_buffer(
            &commit,
            &[AllocationCollectorPollRootReferenceValue::new(
                EvalRootSource::ValueStack { slot: 0 },
                ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
            )],
        )
        .expect("mixed reference buffer derives");
    assert_eq!(
        reference_buffer,
        vec![
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ]
    );
}

#[test]
fn collector_poll_minor_gc_root_writeback_plan_applies_caller_owned_slots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("second thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, first)
        .expect("first root records");
    roots
        .try_push_value_stack(1, second)
        .expect("second root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 2);
    let first_destination = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(first))
        .expect("first survivor copy is planned")
        .destination();
    let second_destination = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(second))
        .expect("second survivor copy is planned")
        .destination();

    let mut no_slots = Vec::new();
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut no_slots)
            .expect_err("short root writeback buffer rejects"),
        EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
            expected: 2,
            actual: 0,
        }
    );

    let mut stale_slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            ResolvedValueGeneration::Inline,
        ),
    ];
    let unchanged_stale_slots = stale_slots.clone();
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut stale_slots)
            .expect_err("stale second root rejects"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_slots, unchanged_stale_slots);

    let mut wrong_source_slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 2 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut wrong_source_slots)
            .expect_err("wrong root source rejects"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 0,
            expected: EvalRootSource::ValueStack { slot: 0 },
            actual: EvalRootSource::ValueStack { slot: 2 },
        }
    );

    let mut later_wrong_source_slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 2 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    let unchanged_later_wrong_source_slots = later_wrong_source_slots.clone();
    assert_eq!(
        root_writeback_plan
            .apply_to_slots(&mut later_wrong_source_slots)
            .expect_err("later wrong root source rejects"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 1,
            expected: EvalRootSource::ValueStack { slot: 1 },
            actual: EvalRootSource::ValueStack { slot: 2 },
        }
    );
    assert_eq!(later_wrong_source_slots, unchanged_later_wrong_source_slots);

    let mut slots = [
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollRootWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    let report = root_writeback_plan
        .apply_to_slots(&mut slots)
        .expect("root writebacks apply");
    assert_eq!(report.writebacks(), 2);
    assert_eq!(
        slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: first_destination,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        slots[1].value(),
        ResolvedValueGeneration::Heap {
            address: second_destination,
            generation: HeapGeneration::Young,
        }
    );
}

#[test]
fn collector_poll_minor_gc_root_writeback_plan_filters_stack_map_roots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let stack_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("stack-map thunk allocates");
    let register_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(13)))
        .expect("register thunk allocates");
    let value_stack_value = heap
        .alloc_thunk(EvalThunk::new(IrId::new(17)))
        .expect("value-stack thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_stack_map(44, 7, StackMapSlot::Stack { offset: -24 }, stack_value)
        .expect("stack-map stack root records");
    roots
        .try_push_stack_map(
            44,
            7,
            StackMapSlot::Register { dwarf_reg: 3 },
            register_value,
        )
        .expect("stack-map register root records");
    roots
        .try_push_value_stack(9, value_stack_value)
        .expect("value-stack root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");

    assert_eq!(root_writeback_plan.len(), 3);
    assert_eq!(root_writeback_plan.stack_map_writeback_count(), 2);
    assert_eq!(
        root_writeback_plan
            .stack_map_writebacks()
            .map(AllocationCollectorPollRootWriteback::slot)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        root_writeback_plan.writebacks()[0].source(),
        &EvalRootSource::StackMap {
            frame: 44,
            safepoint: 7,
            slot: StackMapSlot::Stack { offset: -24 },
        }
    );
    assert_eq!(
        root_writeback_plan.writebacks()[1].source(),
        &EvalRootSource::StackMap {
            frame: 44,
            safepoint: 7,
            slot: StackMapSlot::Register { dwarf_reg: 3 },
        }
    );
    assert_eq!(
        root_writeback_plan.writebacks()[2].source(),
        &EvalRootSource::ValueStack { slot: 9 }
    );

    let mut slots = root_writeback_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollRootWritebackSlot::new(
                writeback.source().clone(),
                writeback.expected(),
            )
        })
        .collect::<Vec<_>>();
    let report = root_writeback_plan
        .apply_to_slots(&mut slots)
        .expect("root writebacks apply");
    assert_eq!(report.writebacks(), 3);
    for (slot, writeback) in slots.iter().zip(root_writeback_plan.writebacks()) {
        assert_eq!(slot.source(), writeback.source());
        assert_eq!(slot.value(), writeback.replacement());
    }
}

#[test]
fn collector_poll_minor_gc_plan_expands_remembered_edge_to_concrete_source_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child, child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("list root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");

    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");

    assert_eq!(planned.reference_slots().len(), 3);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: RememberedEdge::new(gc_address(root), gc_address(child)),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[2].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: RememberedEdge::new(gc_address(root), gc_address(child)),
            field_index: 1,
            source: HeapEdgeSource::ListElement { index: 1 },
        }
    );

    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let relocation_plan = destinations
        .relocation_destinations()
        .relocation_plan(planned.plan())
        .expect("relocation plan rebuilds");
    let rewrite_plan = planned
        .reference_rewrite_plan(&relocation_plan)
        .expect("reference rewrite plan builds");
    assert_eq!(rewrite_plan.rewrites().len(), 2);
    assert_eq!(rewrite_plan.rewrites()[0].slot(), 1);
    assert_eq!(rewrite_plan.rewrites()[1].slot(), 2);
}

#[test]
fn collector_poll_minor_gc_plan_rejects_stale_remembered_edge_without_source_field() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_string(NixString::from_bytes(b"root".to_vec()))
        .expect("permanent string allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, root)
        .expect("string root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");

    assert_eq!(
        heap.plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("stale remembered edge is rejected"),
        EvalHeapError::StaleCollectorPollRememberedEdge {
            source_address: gc_address(root),
            target_address: gc_address(child),
        }
    );
}

#[test]
fn collector_poll_minor_gc_heap_field_reference_buffer_reads_remembered_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");

    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 0);
    assert!(root_writeback_plan.is_empty());
    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_reference_buffer(&commit)
            .expect("heap-field references derive"),
        vec![ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }]
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();
    let mut short_slots = Vec::new();
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut short_slots)
            .expect_err("short heap-field writeback buffer rejects"),
        EvalHeapError::CollectorPollHeapFieldWritebackSlotLengthMismatch {
            expected: 1,
            actual: 0,
        }
    );
    let mut object_mismatch_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(child),
        gc_address(root),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut object_mismatch_slots)
            .expect_err("wrong heap-field objects reject"),
        EvalHeapError::CollectorPollHeapFieldWritebackSlotObjectMismatch {
            index: 0,
            expected_validation_object: gc_address(root),
            actual_validation_object: gc_address(child),
            expected_writeback_object: gc_address(root),
            actual_writeback_object: gc_address(root),
        }
    );
    let mut field_mismatch_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(root),
        gc_address(root),
        1,
        HeapEdgeSource::ListElement { index: 1 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut field_mismatch_slots)
            .expect_err("wrong heap-field label rejects"),
        EvalHeapError::CollectorPollHeapFieldWritebackSlotFieldMismatch {
            index: 0,
            expected_field_index: 0,
            actual_field_index: 1,
            expected_source: HeapEdgeSource::ListElement { index: 0 },
            actual_source: HeapEdgeSource::ListElement { index: 1 },
        }
    );
    let mut stale_value_slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(root),
        gc_address(root),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Inline,
    )];
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut stale_value_slots)
            .expect_err("stale heap-field value rejects"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );

    let mut slots = [AllocationCollectorPollHeapFieldWritebackSlot::new(
        gc_address(root),
        gc_address(root),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    )];
    let report = writeback_plan
        .apply_to_slots(&mut slots)
        .expect("heap-field writebacks apply");
    assert_eq!(report.writebacks(), 1);
    assert_eq!(
        slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );
}

#[test]
fn collector_poll_minor_gc_heap_field_writeback_plan_rejects_stale_same_label_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let sibling = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("sibling thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");

    replace_list_record(&mut heap, root, NixList::new(vec![sibling]));

    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_writeback_plan(&commit)
            .expect_err("same-label value drift rejects writeback plan"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Heap {
                address: gc_address(sibling),
                generation: HeapGeneration::Young,
            },
        }
    );
}

#[test]
fn collector_poll_minor_gc_heap_field_writeback_plan_uses_promoted_nursery_owner() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let grandchild = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("grandchild thunk allocates");
    let child = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(7),
            grandchild,
            IrAttrPathId::new(0),
        ))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(0),
        )
        .expect("promoting minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x3000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let child_copy = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(child))
        .expect("child survivor copy is planned");
    let grandchild_copy = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(grandchild))
        .expect("grandchild survivor copy is planned");
    assert_eq!(child_copy.destination_generation(), HeapGeneration::Old);
    assert_eq!(
        grandchild_copy.destination_generation(),
        HeapGeneration::Old
    );

    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("promoted heap-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 2);
    let nursery_writeback = &writeback_plan.writebacks()[1];
    assert_eq!(nursery_writeback.slot(), 1);
    assert_eq!(nursery_writeback.validation_object(), gc_address(child));
    assert_eq!(
        nursery_writeback.writeback_object(),
        child_copy.destination()
    );
    assert_eq!(
        nursery_writeback.source(),
        &HeapEdgeSource::ThunkSelectReceiver
    );
    assert_eq!(
        nursery_writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: grandchild_copy.destination(),
            generation: HeapGeneration::Old,
        }
    );

    let mut stale_slots = [
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(root),
            gc_address(root),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(child),
            child_copy.destination(),
            0,
            HeapEdgeSource::ThunkSelectReceiver,
            ResolvedValueGeneration::Inline,
        ),
    ];
    let unchanged_stale_slots = stale_slots.clone();
    assert_eq!(
        writeback_plan
            .apply_to_slots(&mut stale_slots)
            .expect_err("stale copied nursery field rejects"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(grandchild),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(stale_slots, unchanged_stale_slots);

    let mut slots = [
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(root),
            gc_address(root),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
        ),
        AllocationCollectorPollHeapFieldWritebackSlot::new(
            gc_address(child),
            child_copy.destination(),
            0,
            HeapEdgeSource::ThunkSelectReceiver,
            ResolvedValueGeneration::Heap {
                address: gc_address(grandchild),
                generation: HeapGeneration::Young,
            },
        ),
    ];
    let report = writeback_plan
        .apply_to_slots(&mut slots)
        .expect("heap-field writebacks apply");
    assert_eq!(report.writebacks(), 2);
    assert_eq!(
        slots[0].value(),
        ResolvedValueGeneration::Heap {
            address: child_copy.destination(),
            generation: HeapGeneration::Old,
        }
    );
    assert_eq!(
        slots[1].value(),
        ResolvedValueGeneration::Heap {
            address: grandchild_copy.destination(),
            generation: HeapGeneration::Old,
        }
    );
}

#[test]
fn collector_poll_minor_gc_heap_field_reference_buffer_rejects_root_slots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();
    let root_reference_value = AllocationCollectorPollRootReferenceValue::new(
        EvalRootSource::ValueStack { slot: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        },
    );

    let root_writeback_plan = commit
        .root_writeback_plan()
        .expect("root writeback plan derives");
    assert_eq!(root_writeback_plan.len(), 1);
    assert!(!root_writeback_plan.is_empty());
    let root_writeback = &root_writeback_plan.writebacks()[0];
    assert_eq!(root_writeback.slot(), 0);
    assert_eq!(
        root_writeback.source(),
        &EvalRootSource::ValueStack { slot: 0 }
    );
    assert_eq!(
        root_writeback.expected(),
        ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        root_writeback.replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            std::slice::from_ref(&root_reference_value),
        )
        .expect("root-only reference buffer derives"),
        vec![ResolvedValueGeneration::Heap {
            address: gc_address(child),
            generation: HeapGeneration::Young,
        }]
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(&commit, &[])
            .expect_err("missing root value is rejected"),
        EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
            expected: 1,
            actual: 0,
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            &[
                root_reference_value.clone(),
                AllocationCollectorPollRootReferenceValue::new(
                    EvalRootSource::ValueStack { slot: 1 },
                    ResolvedValueGeneration::Inline,
                ),
            ],
        )
        .expect_err("extra root value is rejected"),
        EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
            expected: 1,
            actual: 2,
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            &[AllocationCollectorPollRootReferenceValue::new(
                EvalRootSource::ValueStack { slot: 1 },
                ResolvedValueGeneration::Heap {
                    address: gc_address(child),
                    generation: HeapGeneration::Young,
                },
            )],
        )
        .expect_err("wrong root source is rejected"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 0,
            expected: EvalRootSource::ValueStack { slot: 0 },
            actual: EvalRootSource::ValueStack { slot: 1 },
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_reference_buffer(
            &commit,
            &[AllocationCollectorPollRootReferenceValue::new(
                EvalRootSource::ValueStack { slot: 0 },
                ResolvedValueGeneration::Inline,
            )],
        )
        .expect_err("stale root value is rejected"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 0,
            expected: ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            },
            actual: ResolvedValueGeneration::Inline,
        }
    );

    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_reference_buffer(&commit)
            .expect_err("root slots still need external storage"),
        EvalHeapError::CollectorPollReferenceSlotNotHeapBacked {
            index: 0,
            root_source: EvalRootSource::ValueStack { slot: 0 },
        }
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("root-only rewrite has no heap-field writebacks");
    assert!(writeback_plan.is_empty());
    assert_eq!(writeback_plan.len(), 0);
}

#[test]
fn collector_poll_minor_gc_heap_field_reference_buffer_rejects_stale_nursery_field_label() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let grandchild = heap
        .alloc_thunk(EvalThunk::new(IrId::new(11)))
        .expect("grandchild thunk allocates");
    let child = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(7),
            grandchild,
            IrAttrPathId::new(0),
        ))
        .expect("child thunk allocates");
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let roots = EvalRootSet::new();
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(RememberedEdge::new(gc_address(root), gc_address(child)))
        .expect("remembered edge records");
    let planned = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("minor-GC plan builds");
    let destinations = heap
        .plan_collector_poll_minor_gc_relocation_destinations(
            &planned,
            MinorGcDestinationBases::new(
                static_gc_address(0x1000_2000),
                static_gc_address(0x2000_0000),
            ),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let child_destination = commit
        .commit_plan()
        .object_copies()
        .copies()
        .iter()
        .find(|copy| copy.source() == gc_address(child))
        .expect("child survivor copy is planned")
        .destination();
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("heap-field writeback plan derives before field changes");
    assert_eq!(writeback_plan.len(), 2);
    let nursery_writeback = &writeback_plan.writebacks()[1];
    assert_eq!(nursery_writeback.slot(), 1);
    assert_eq!(nursery_writeback.validation_object(), gc_address(child));
    assert_eq!(nursery_writeback.writeback_object(), child_destination);
    assert_eq!(
        nursery_writeback.source(),
        &HeapEdgeSource::ThunkSelectReceiver
    );

    let child_thunk = heap.clone_thunk(child).expect("child thunk clones");
    let claim = child_thunk
        .cell()
        .begin_force()
        .expect("force claim begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("child thunk should be claimable");
    };
    guard.finish(grandchild).expect("child thunk forced");

    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_reference_buffer(&commit)
            .expect_err("stale nursery field label is rejected"),
        EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
            index: 1,
            expected: HeapEdgeSource::ThunkSelectReceiver,
            actual: Some(HeapEdgeSource::ThunkCachedResult),
        }
    );
    assert_eq!(
        heap.collector_poll_minor_gc_heap_field_writeback_plan(&commit)
            .expect_err("stale nursery field label rejects writeback plan"),
        EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
            index: 1,
            expected: HeapEdgeSource::ThunkSelectReceiver,
            actual: Some(HeapEdgeSource::ThunkCachedResult),
        }
    );
}

#[test]
fn collector_poll_minor_gc_plan_rejects_unremembered_permanent_edge_outside_root_graph() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let root = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("root thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent list allocates");
    let poll = heap
        .permanent_allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots.try_push_value_stack(0, root).expect("root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("missing remembered edge is rejected");

    assert_eq!(
        error,
        EvalHeapError::MissingCollectorPollRememberedEdge {
            source_address: gc_address(permanent_parent),
            target_address: gc_address(child),
        }
    );
}

#[test]
fn collector_poll_minor_gc_plan_rejects_stale_heap_graph_snapshot() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let forced = heap
        .alloc_string(NixString::from_bytes(b"forced".to_vec()))
        .expect("forced value allocates");
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_force_continuation(0, thunk)
        .expect("thunk root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    let claim = thunk_record.cell().begin_force().expect("claim succeeds");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new thunk should be claimable");
    };
    guard.finish(forced).expect("thunk publishes forced value");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("stale snapshot is rejected");

    assert_eq!(
        error,
        EvalHeapError::CollectorPollScanStaleObject {
            address: gc_address(thunk),
        }
    );
}

#[test]
fn collector_poll_minor_gc_plan_rejects_heap_growth_after_scan() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let thunk = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_force_continuation(0, thunk)
        .expect("thunk root records");
    let scan = heap
        .scan_collector_poll_roots(poll, &roots)
        .expect("collector-poll root scan succeeds");
    let snapshot_records = scan.heap_records();
    heap.alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("later thunk allocates");
    let remembered_set = RememberedSet::new();

    let error = heap
        .plan_collector_poll_minor_gc(
            &scan,
            remembered_set.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("heap growth after scan is rejected");

    assert_eq!(
        error,
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "heap record count changed",
            expected_records: snapshot_records,
            actual_records: heap.len(),
        }
    );
}

#[test]
fn precise_root_scan_tracks_thunk_state_instead_of_stale_captures() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let captured = heap
        .alloc_string(NixString::from_bytes(b"captured".to_vec()))
        .expect("captured string allocates");
    let forced = heap
        .alloc_string(NixString::from_bytes(b"forced".to_vec()))
        .expect("forced string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let thunk = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(9), env))
        .expect("thunk allocates");
    let mut roots = EvalRootSet::new();
    assert!(
        roots
            .try_push_force_continuation(0, thunk)
            .expect("thunk root records")
    );

    let suspended_scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let suspended_edges = object_for(&suspended_scan, thunk).edges();
    assert_eq!(suspended_edges.len(), 1);
    assert_eq!(
        suspended_edges[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        }
    );
    assert!(suspended_edges[0].value().raw_eq(captured));

    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    let claim = thunk_record.cell().begin_force().expect("claim succeeds");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new thunk should be claimable");
    };
    guard.finish(forced).expect("thunk publishes forced value");

    let forced_scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let forced_edges = object_for(&forced_scan, thunk).edges();
    assert_eq!(forced_edges.len(), 1);
    assert_eq!(forced_edges[0].source(), &HeapEdgeSource::ThunkCachedResult);
    assert!(forced_edges[0].value().raw_eq(forced));
    assert!(object_for(&forced_scan, forced).edges().is_empty());
    assert!(
        forced_scan
            .objects()
            .iter()
            .all(|object| !object.value().raw_eq(captured))
    );
}

#[test]
fn precise_root_scan_reports_lambda_captured_scopes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    let lexical = heap
        .alloc_string(NixString::from_bytes(b"lexical".to_vec()))
        .expect("lexical string allocates");
    let with_scope = heap
        .alloc_string(NixString::from_bytes(b"with".to_vec()))
        .expect("with string allocates");
    let scoped_global = heap
        .alloc_string(NixString::from_bytes(b"global".to_vec()))
        .expect("global string allocates");
    let frame = EvalFrame::new(2).expect("frame allocates");
    frame.set(0, lexical).expect("slot writes");
    frame.set(1, Value::int(9)).expect("inline slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(3),
        with_scope,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[scoped_global]).expect("global env captures");
    let lambda = heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(1),
            IrId::new(2),
            FrameId::new(0),
            env,
            with_env,
            scoped_globals,
        ))
        .expect("lambda allocates");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, lambda)
        .expect("lambda root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, lambda).edges();

    assert_eq!(edges.len(), 3);
    assert!(
        edges.iter().any(|edge| {
            edge.source()
                == &HeapEdgeSource::CapturedEnv {
                    owner: CapturedRootOwner::Lambda,
                    frame: 0,
                    slot: 0,
                }
                && edge.value().raw_eq(lexical)
        }),
        "lexical heap slot is reported"
    );
    assert!(
        edges.iter().any(|edge| {
            edge.source()
                == &HeapEdgeSource::CapturedWithScope {
                    owner: CapturedRootOwner::Lambda,
                    index: 0,
                }
                && edge.value().raw_eq(with_scope)
        }),
        "with-scope heap value is reported"
    );
    assert!(
        edges.iter().any(|edge| {
            edge.source()
                == &HeapEdgeSource::CapturedScopedGlobal {
                    owner: CapturedRootOwner::Lambda,
                    index: 0,
                }
                && edge.value().raw_eq(scoped_global)
        }),
        "scoped-global heap value is reported"
    );
}

#[test]
fn precise_root_scan_reports_primop_heap_arguments() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let argument_value = heap
        .alloc_string(NixString::from_bytes(b"arg".to_vec()))
        .expect("argument string allocates");
    let primop = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![
                EvalPrimOpArg::new(IrId::new(1), Span::new(0, 1), Value::int(1)),
                EvalPrimOpArg::new(IrId::new(2), Span::new(1, 2), argument_value),
            ],
        ))
        .expect("primop allocates");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_primop_argument(0, primop)
        .expect("primop root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, primop).edges();

    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0].source(),
        &HeapEdgeSource::PrimopArgument { index: 1 }
    );
    assert!(edges[0].value().raw_eq(argument_value));
}

#[test]
fn precise_root_scan_reports_suspended_thunk_capture_variants() {
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    let function_value = heap
        .alloc_string(NixString::from_bytes(b"function".to_vec()))
        .expect("function string allocates");
    let argument_value = heap
        .alloc_string(NixString::from_bytes(b"argument".to_vec()))
        .expect("argument string allocates");
    let first_argument_value = heap
        .alloc_string(NixString::from_bytes(b"first".to_vec()))
        .expect("first string allocates");
    let second_argument_value = heap
        .alloc_string(NixString::from_bytes(b"second".to_vec()))
        .expect("second string allocates");
    let receiver = heap
        .alloc_string(NixString::from_bytes(b"receiver".to_vec()))
        .expect("receiver string allocates");
    let apply = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(1),
            Span::new(0, 1),
            function_value,
            EvalModuleId::ROOT,
            IrId::new(2),
            argument_value,
        ))
        .expect("apply thunk allocates");
    let apply2 = heap
        .alloc_thunk(EvalThunk::apply2(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(1, 2),
            function_value,
            EvalModuleId::ROOT,
            IrId::new(4),
            Span::new(2, 3),
            first_argument_value,
            EvalModuleId::ROOT,
            IrId::new(5),
            second_argument_value,
        ))
        .expect("apply2 thunk allocates");
    let select = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(6),
            receiver,
            IrAttrPathId::new(0),
        ))
        .expect("select thunk allocates");
    let builtin_attr = heap
        .alloc_thunk(EvalThunk::builtin_attr(symbol, builtin))
        .expect("builtin attr thunk allocates");
    let mut roots = EvalRootSet::new();
    for (index, value) in [apply, apply2, select, builtin_attr]
        .into_iter()
        .enumerate()
    {
        roots
            .try_push_value_stack(index, value)
            .expect("thunk root records");
    }

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let apply_edges = object_for(&scan, apply).edges();
    assert_eq!(apply_edges.len(), 2);
    assert!(
        apply_edges
            .iter()
            .any(|edge| edge.source() == &HeapEdgeSource::ThunkApplyFunction
                && edge.value().raw_eq(function_value))
    );
    assert!(
        apply_edges
            .iter()
            .any(|edge| edge.source() == &HeapEdgeSource::ThunkApplyArgument
                && edge.value().raw_eq(argument_value))
    );

    let apply2_edges = object_for(&scan, apply2).edges();
    assert_eq!(apply2_edges.len(), 3);
    assert!(
        apply2_edges
            .iter()
            .any(|edge| edge.source() == &HeapEdgeSource::ThunkApply2Function
                && edge.value().raw_eq(function_value))
    );
    assert!(apply2_edges.iter().any(|edge| edge.source()
        == &HeapEdgeSource::ThunkApply2FirstArgument
        && edge.value().raw_eq(first_argument_value)));
    assert!(apply2_edges.iter().any(|edge| edge.source()
        == &HeapEdgeSource::ThunkApply2SecondArgument
        && edge.value().raw_eq(second_argument_value)));

    let select_edges = object_for(&scan, select).edges();
    assert_eq!(select_edges.len(), 1);
    assert_eq!(
        select_edges[0].source(),
        &HeapEdgeSource::ThunkSelectReceiver
    );
    assert!(select_edges[0].value().raw_eq(receiver));
    assert!(object_for(&scan, builtin_attr).edges().is_empty());
}

#[test]
fn precise_root_scan_reports_blackholed_thunk_captures() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let captured = heap
        .alloc_string(NixString::from_bytes(b"captured".to_vec()))
        .expect("captured string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let thunk = heap
        .alloc_thunk(EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(9), env))
        .expect("thunk allocates");
    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    let claim = thunk_record.cell().begin_force().expect("claim succeeds");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new thunk should be claimable");
    };
    let mut roots = EvalRootSet::new();
    roots
        .try_push_force_continuation(0, thunk)
        .expect("thunk root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, thunk).edges();

    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        }
    );
    assert!(edges[0].value().raw_eq(captured));
    guard.abort().expect("claim aborts");
}

#[test]
fn precise_root_scan_ignores_external_heap_values_owned_elsewhere() {
    let external =
        Value::external(NonNull::<HeapObject>::dangling()).expect("external pointer builds");
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap
        .alloc_list(NixList::new(vec![external]))
        .expect("list allocates");
    let mut roots = EvalRootSet::new();

    assert!(
        !roots
            .try_push_value_stack(0, external)
            .expect("external root ignored")
    );
    roots
        .try_push_value_stack(1, list)
        .expect("list root records");

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");

    assert_eq!(scan.roots().len(), 1);
    assert_eq!(scan.objects().len(), 1);
    assert!(object_for(&scan, list).edges().is_empty());
}

#[test]
fn interned_root_set_enumerates_hash_consed_permanent_roots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"interned".to_vec()))
        .expect("string allocates");
    let second_string = heap
        .alloc_string(NixString::from_bytes(b"interned-second".to_vec()))
        .expect("second string allocates");
    let path = heap
        .alloc_path(NixString::from_bytes(b"/tmp/interned".to_vec()))
        .expect("path allocates");
    let list = heap
        .alloc_list(NixList::new(vec![string]))
        .expect("list allocates");
    let attrs = heap
        .alloc_attrs(0, attrs_with_value(list))
        .expect("attrs allocate");

    let roots = heap.interned_root_set().expect("interned roots collect");
    let repeated_roots = heap.interned_root_set().expect("interned roots repeat");
    let sources: Vec<_> = roots.roots().iter().map(EvalRoot::source).collect();

    assert_eq!(roots.roots(), repeated_roots.roots());
    assert_eq!(roots.len(), 5);
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::String,
        index: 1,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::Path,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::List,
        index: 0,
    }));
    assert!(sources.contains(&&EvalRootSource::Interned {
        table: InternedRootTable::Attrs,
        index: 0,
    }));

    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(string))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(second_string))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(path))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(list))
    );
    assert!(
        scan.objects()
            .iter()
            .any(|object| object.value().raw_eq(attrs))
    );
}

#[test]
fn precise_root_scan_validates_duplicate_address_tags_before_deduping() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1)]))
        .expect("list allocates");
    let ptr = list.as_list_ptr().expect("list pointer");
    let mislabeled = Value::string(ptr).expect("same pointer can carry another heap tag");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, list)
        .expect("list root records");
    roots
        .try_push_value_stack(1, mislabeled)
        .expect("mislabeled root records");

    let error = heap
        .scan_precise_roots(&roots)
        .expect_err("mislabeled duplicate is rejected");

    assert_eq!(
        error,
        EvalHeapError::record_type_mismatch(ValueTag::String, ValueTag::List, ptr)
    );
}
