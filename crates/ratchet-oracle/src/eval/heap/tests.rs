//! Unit tests for the typed evaluator heap registry.

use super::super::ThunkState;
use super::*;
use crate::attrs::{AttrEntry, AttrPosition, repr::AttrSetReprKind, shape::ShapeId};
use crate::eval::thunk_cas::ParallelThunkWorkerId;
use crate::eval::tree_walk::{TreeWalkError, TreeWalkErrorKind};
use crate::eval::{EvalFrame, EvalWithScope, TreeWalkParallelThunkWait};
use crate::heap::{
    AllocationRegionFacts, GcCardTable, GcHeapAddress, GenerationalGcError, GenerationalGcTier,
    HeapGeneration, HeapMemoryBudget, HeapMemoryBudgetResponse, HeapMemorySample, MemoryAdviceKind,
    MinorGcDestinationBases, MinorGcForwardingSlot, MinorGcObjectByteCopyBuffer,
    MinorGcOwnedDestinationStorage, MinorGcPlan, MinorGcPromotionPolicy,
    MinorGcRelocationDestination, MinorGcRelocationPlan, MinorGcSourceObjectBytes,
    MinorGcSurvivorAction, NurseryObjectAge, NurseryObjectLayout, ProcessResidentMemorySource,
    RegionPlan, RegionRuntimeTier, RememberedEdge, RememberedSet, ResolvedValueGeneration,
    ThunkResolveWriteBarrier,
};
use crate::runtime::alloc::{AllocationGcPollReason, RuntimeAllocationEntryPoint};
use crate::runtime::builtins::lookup_builtin;
use crate::string::{ContextElement, StringContext};
use crate::syntax::{Span, SymbolTable};

mod errors;
mod gc;

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

fn heap_generation(heap: &EvalHeap, value: Value) -> HeapGeneration {
    heap.generation(value)
        .expect("heap record has a heap generation")
}

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointers are valid GC addresses")
}

fn worker(raw: u64) -> ParallelThunkWorkerId {
    ParallelThunkWorkerId::new(raw).expect("test worker id is encodable")
}

fn tree_walk_error(raw: u32) -> TreeWalkError {
    TreeWalkError::new(
        TreeWalkErrorKind::DivisionByZero { id: IrId::new(raw) },
        Span::new(raw, raw.saturating_add(1)),
    )
}

fn publish_parallel_payload(thunk: &EvalThunk, value: Value) {
    let parallel = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell is attached");
    let TreeWalkParallelThunkWait::Claimed(guard) = parallel
        .claim_or_wait_for_result(worker(1))
        .expect("parallel payload cell claims")
    else {
        panic!("parallel payload cell should start suspended");
    };
    guard
        .publish_value(value)
        .expect("parallel payload publishes");
}

fn assert_parallel_payload(thunk: &EvalThunk, expected: Value) {
    let actual = thunk
        .parallel_payload_cell()
        .expect("parallel payload cell is attached")
        .terminal_result()
        .expect("parallel terminal result is present")
        .expect("parallel terminal result is forced");
    assert!(actual.raw_eq(expected));
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Suspended));
}

fn static_gc_address(address_bits: usize) -> GcHeapAddress {
    GcHeapAddress::new(address_bits).expect("test address is a valid GC address")
}

fn replace_list_record(heap: &mut EvalHeap, value: Value, list: NixList) {
    let ptr = value.as_list_ptr().expect("value is a list");
    // Flat lists (doc 30 FV-1) have no record; rewrite the flat payload
    // through the store's exclusive writeback door. The bypass deliberately
    // skips hash-cons admission, exactly as the record rewrite did.
    if heap.shared.is_none() {
        *heap
            .flat_lists
            .resolve_mut(ptr, crate::heap::flat::FlatObjectKind::List)
            .expect("flat list exists") = list;
        return;
    }
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
    // Flat values (doc 30 FV-1) are permanent-shared by construction and
    // carry no record to rewrite; requesting their intrinsic domain is a
    // fixture no-op, anything else is a test bug.
    if heap.shared.is_none()
        && matches!(
            value.tag(),
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        )
    {
        assert_eq!(
            domain,
            HeapAllocationDomain::PermanentShared,
            "flat values are permanently PermanentShared"
        );
        return;
    }
    let record = heap
        .records
        .iter_mut()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
        .expect("heap record exists");
    record.allocation_domain = domain;
    record.generation = initial_generation_for_allocation_domain(domain);
}

fn set_heap_generation(heap: &mut EvalHeap, value: Value, generation: HeapGeneration) {
    let address = gc_address(value);
    if heap.shared.is_none()
        && matches!(
            value.tag(),
            ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
        )
    {
        assert_eq!(
            generation,
            HeapGeneration::Permanent,
            "flat values are permanently Permanent"
        );
        return;
    }
    let record = heap
        .records
        .iter_mut()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
        .expect("heap record exists");
    record.generation = generation;
}

fn record_layout_size(heap: &EvalHeap, value: Value) -> usize {
    let address = gc_address(value);
    if let Some(record) = heap
        .records
        .iter()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
    {
        return record.layout.size_bytes;
    }
    if let Some(entry) = heap
        .flat
        .iter()
        .find(|entry| entry.ptr().as_ptr() as usize == address.address_bits())
    {
        return entry.size_bytes();
    }
    if let Some(entry) = heap
        .flat_lists
        .iter()
        .find(|entry| entry.ptr().as_ptr() as usize == address.address_bits())
    {
        return entry.size_bytes();
    }
    heap.flat_attrs
        .iter()
        .find(|entry| entry.ptr().as_ptr() as usize == address.address_bits())
        .expect("heap record exists")
        .size_bytes()
}

fn record_layout_align(heap: &EvalHeap, value: Value) -> usize {
    let address = gc_address(value);
    if let Some(record) = heap
        .records
        .iter()
        .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
    {
        return record.layout.align;
    }
    // Flat objects (doc 30 FV-1) are placed at the arena word alignment.
    std::mem::align_of::<u64>()
}

fn object_copy_request_for_values(
    heap: &EvalHeap,
    source: Value,
    destination: Value,
    action: MinorGcSurvivorAction,
) -> AllocationCollectorPollObjectByteCopyRequest {
    AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        action,
        match action {
            MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
            MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
        },
        record_layout_size(heap, source),
        record_layout_align(heap, source),
    )
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

#[test]
fn tier_b_admission_application_rejects_stale_worker_stats_before_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let worker = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");
    let expected_stats = plan.worker_stats();

    heap.alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second worker thunk allocates");
    let actual_stats = heap.arena_stats();
    let error = heap
        .apply_tier_b_admission_plan(&plan)
        .expect_err("stale worker accounting is rejected");

    assert_eq!(
        error,
        EvalHeapError::TierBAdmissionStaleArenaStats {
            domain: "worker",
            expected: expected_stats,
            actual: actual_stats,
        }
    );
    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Young);
}

#[test]
fn tier_b_admission_application_rejects_stale_record_generation_before_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("first worker thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second worker thunk allocates");
    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");
    set_heap_generation(&mut heap, second, HeapGeneration::Old);

    let error = heap
        .apply_tier_b_admission_plan(&plan)
        .expect_err("stale generation is rejected");

    assert_eq!(
        error,
        EvalHeapError::TierBAdmissionStaleRecordGeneration {
            index: 1,
            address: gc_address(second),
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
        }
    );
    assert_eq!(heap_generation(&heap, first), HeapGeneration::Young);
    assert_eq!(heap_generation(&heap, second), HeapGeneration::Old);
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
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
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
    let metadata = heap
        .get_attrs_metadata(value)
        .expect("attr metadata exists");
    assert_eq!(metadata.shape(), 42);
    assert_eq!(metadata.projected_shape(), None);
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, value),
        HeapAllocationDomain::PermanentShared
    );
}

#[test]
fn allocates_attr_values_with_explicit_repr_metadata() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_attrs_with_repr_metadata(42, AttrSetReprKind::Hamt, attrs_with_one_entry())
        .expect("attrs allocate");

    let metadata = heap
        .get_attrs_metadata(value)
        .expect("attr metadata exists");
    assert_eq!(metadata.shape(), 42);
    assert_eq!(metadata.projected_shape(), None);
    assert_eq!(metadata.repr(), AttrSetReprKind::Hamt);
}

#[test]
fn allocates_attr_values_with_projected_shape_metadata() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let value = heap
        .alloc_attrs_with_projected_shape_metadata(
            42,
            AttrSetReprKind::Flat,
            Some(ShapeId::new(7)),
            attrs_with_one_entry(),
        )
        .expect("attrs allocate");

    let metadata = heap
        .get_attrs_metadata(value)
        .expect("attr metadata exists");
    assert_eq!(metadata.shape(), 42);
    assert_eq!(metadata.projected_shape(), Some(ShapeId::new(7)));
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
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
fn attr_values_with_different_repr_metadata_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs(42, attrs_with_one_entry())
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs_with_repr_metadata(42, AttrSetReprKind::Hamt, attrs_with_one_entry())
        .expect("second attrs allocate");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
    assert_eq!(
        heap.get_attrs_metadata(first)
            .expect("first metadata exists")
            .repr(),
        AttrSetReprKind::Flat
    );
    assert_eq!(
        heap.get_attrs_metadata(second)
            .expect("second metadata exists")
            .repr(),
        AttrSetReprKind::Hamt
    );
}

#[test]
fn attr_values_with_different_projected_shape_metadata_do_not_collapse() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_attrs_with_projected_shape_metadata(
            42,
            AttrSetReprKind::Flat,
            Some(ShapeId::new(1)),
            attrs_with_one_entry(),
        )
        .expect("first attrs allocate");
    let second = heap
        .alloc_attrs_with_projected_shape_metadata(
            42,
            AttrSetReprKind::Flat,
            Some(ShapeId::new(2)),
            attrs_with_one_entry(),
        )
        .expect("second attrs allocate");

    assert!(!first.raw_eq(second));
    assert_eq!(heap.len(), 2);
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

    let mut owned_destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(destinations.placement_plan())
            .expect("owned destination storage allocates");
    let owned_destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            owned_destination_storage.destination_bases(),
        )
        .expect("owned-storage destination plan builds");
    let owned_lambda_destination = owned_destinations.destinations()[0].destination();
    let owned_child_destination = owned_destinations.destinations()[1].destination();
    let owned_sibling_destination = owned_destinations.destinations()[2].destination();
    let owned_commit = planned
        .commit_plan(&owned_destinations)
        .expect("owned-storage commit plan builds");
    let owned_source_bytes = [
        MinorGcSourceObjectBytes::new(gc_address(lambda), &lambda_source_bytes),
        MinorGcSourceObjectBytes::new(gc_address(child), &child_source_bytes),
        MinorGcSourceObjectBytes::new(gc_address(sibling), &sibling_source_bytes),
    ];
    let mut owned_forwarding_slots = owned_commit
        .forwarding_slot_buffer()
        .expect("owned forwarding slot buffer derives");
    let mut owned_references = planned.reference_values().collect::<Vec<_>>();
    let mut owned_remembered_set = remembered_set.clone();
    let expected_owned_next_remembered_set =
        owned_commit.commit_plan().next_remembered_set().clone();
    let mut owned_card_table = GcCardTable::new(0x1000).expect("owned card table builds");
    owned_card_table
        .mark_source(gc_address(lambda))
        .expect("owned card marks");

    let owned_report = owned_commit
        .apply_to_owned_destination_storage_with_report(
            AllocationCollectorPollMinorGcOwnedCommitBuffers::with_card_table(
                &mut owned_destination_storage,
                &owned_source_bytes,
                &mut owned_forwarding_slots,
                &mut owned_references,
                &mut owned_remembered_set,
                &mut owned_card_table,
            ),
        )
        .expect("collector-poll owned destination storage applies");

    assert_eq!(owned_report.object_copies(), 3);
    assert_eq!(owned_report.copied_to_nursery(), 3);
    assert_eq!(owned_report.promoted_to_old(), 0);
    assert_eq!(owned_report.card_table_dirty_cards_cleared(), 1);
    let mut expected_owned_nursery_bytes = Vec::new();
    expected_owned_nursery_bytes.extend_from_slice(&lambda_source_bytes);
    expected_owned_nursery_bytes.extend_from_slice(&child_source_bytes);
    expected_owned_nursery_bytes.extend_from_slice(&sibling_source_bytes);
    assert_eq!(
        owned_destination_storage.nursery_destination_bytes(),
        expected_owned_nursery_bytes.as_slice()
    );
    assert!(owned_destination_storage.old_destination_bytes().is_empty());
    assert_eq!(
        owned_forwarding_slots[0].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: owned_lambda_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        owned_forwarding_slots[1].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: owned_child_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        owned_forwarding_slots[2].forwarded_value(),
        Some(ResolvedValueGeneration::Heap {
            address: owned_sibling_destination,
            generation: HeapGeneration::Young,
        })
    );
    assert_eq!(
        owned_references,
        vec![
            ResolvedValueGeneration::Heap {
                address: owned_lambda_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: owned_child_destination,
                generation: HeapGeneration::Young,
            },
            ResolvedValueGeneration::Heap {
                address: owned_sibling_destination,
                generation: HeapGeneration::Young,
            },
        ]
    );
    assert_eq!(owned_remembered_set, expected_owned_next_remembered_set);
    assert!(owned_card_table.is_empty());

    let mut stale_destination_storage =
        MinorGcOwnedDestinationStorage::from_placement_plan(destinations.placement_plan())
            .expect("stale owned destination storage allocates");
    let stale_destinations = planned
        .relocation_destination_plan(
            &nursery_layouts,
            stale_destination_storage.destination_bases(),
        )
        .expect("stale owned-storage destination plan builds");
    let stale_commit = planned
        .commit_plan(&stale_destinations)
        .expect("stale owned-storage commit plan builds");
    let mut stale_forwarding_slots = stale_commit
        .forwarding_slot_buffer()
        .expect("stale forwarding slot buffer derives");
    let mut stale_references = planned.reference_values().collect::<Vec<_>>();
    let expected_stale_reference = stale_references[1];
    stale_references[1] = ResolvedValueGeneration::Inline;
    let mut stale_remembered_set = remembered_set.clone();
    let unchanged_stale_references = stale_references.clone();

    assert_eq!(
        stale_commit
            .apply_to_owned_destination_storage(
                AllocationCollectorPollMinorGcOwnedCommitBuffers::new(
                    &mut stale_destination_storage,
                    &owned_source_bytes,
                    &mut stale_forwarding_slots,
                    &mut stale_references,
                    &mut stale_remembered_set,
                )
            )
            .expect_err("stale reference buffer is rejected before owned storage mutates"),
        EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index: 1,
            expected: expected_stale_reference,
            actual: ResolvedValueGeneration::Inline,
        }
    );
    assert_eq!(
        stale_destination_storage.nursery_destination_bytes(),
        vec![0u8; expected_owned_nursery_bytes.len()].as_slice()
    );
    assert!(stale_forwarding_slots.iter().all(|slot| slot.is_empty()));
    assert_eq!(stale_references, unchanged_stale_references);
    assert_eq!(stale_remembered_set, remembered_set);
}

#[test]
fn collector_poll_minor_gc_forwarding_install_writes_valid_slots() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("second thunk allocates");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let second_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(second), second_forwarded),
    ];

    let report = heap
        .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
        .expect("forwarding slots install");
    let forwarding_values = heap
        .minor_gc_forwarding_values()
        .expect("forwarding values snapshot builds");

    assert_eq!(report.forwarding_pointers(), 2);
    assert_eq!(forwarding_values.len(), 2);
    assert_eq!(forwarding_values[0].source(), gc_address(first));
    assert_eq!(forwarding_values[0].forwarded_value(), first_forwarded);
    assert_eq!(forwarding_values[1].source(), gc_address(second));
    assert_eq!(forwarding_values[1].forwarded_value(), second_forwarded);
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        Some(first_forwarded)
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(second))
            .expect("second forwarding source remains known"),
        Some(second_forwarded)
    );
}

#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_empty_slot_without_partial_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("second thunk allocates");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::new(gc_address(second)),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("empty second forwarding slot is rejected"),
        EvalHeapError::CollectorPollForwardingSlotEmpty {
            index: 1,
            address: gc_address(second),
        }
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(second))
            .expect("second forwarding source remains known"),
        None
    );
}

#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_duplicate_source_without_partial_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let duplicate_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), duplicate_forwarded),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("duplicate forwarding source is rejected"),
        EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
            index: 1,
            address: gc_address(first),
        }
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
}

#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_permanent_source_without_partial_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    // Since FV-2 no allocation path creates a permanent record (strings,
    // paths, lists, and attrsets are all flat), so the fixture manufactures
    // one: a worker record flipped to the permanent-shared domain.
    let permanent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("permanent-fixture thunk allocates");
    heap.set_allocation_domain_for_test(permanent, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let permanent_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(permanent), permanent_forwarded),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("permanent forwarding source is rejected"),
        EvalHeapError::GenerationalGc(GenerationalGcError::StaleNurseryObjectLayout {
            address: gc_address(permanent),
        })
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(permanent))
            .expect("permanent forwarding source remains known"),
        None
    );
}

#[test]
fn collector_poll_minor_gc_forwarding_install_rejects_occupied_later_slot_without_partial_mutation()
{
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("second thunk allocates");
    let first_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0000),
        generation: HeapGeneration::Young,
    };
    let second_initial_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0010),
        generation: HeapGeneration::Young,
    };
    let second_retry_forwarded = ResolvedValueGeneration::Heap {
        address: static_gc_address(0x1000_0020),
        generation: HeapGeneration::Young,
    };
    heap.install_collector_poll_minor_gc_forwarding_slots(&[
        MinorGcForwardingSlot::with_forwarded_value(gc_address(second), second_initial_forwarded),
    ])
    .expect("initial second forwarding slot installs");
    let forwarding_slots = [
        MinorGcForwardingSlot::with_forwarded_value(gc_address(first), first_forwarded),
        MinorGcForwardingSlot::with_forwarded_value(gc_address(second), second_retry_forwarded),
    ];

    assert_eq!(
        heap.install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)
            .expect_err("occupied second forwarding source is rejected"),
        EvalHeapError::GenerationalGc(GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
            index: 1,
            address: gc_address(second),
            actual: second_initial_forwarded,
        })
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(first))
            .expect("first forwarding source remains known"),
        None
    );
    assert_eq!(
        heap.minor_gc_forwarding_value_at(gc_address(second))
            .expect("second forwarding source remains known"),
        Some(second_initial_forwarded)
    );
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
fn collector_poll_minor_gc_explicit_relocation_destinations_accept_noncontiguous_addresses() {
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
    let first_destination = static_gc_address(0x5000_0000);
    let second_destination = static_gc_address(0x3000_0000);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(gc_address(second), second_destination),
        MinorGcRelocationDestination::new(gc_address(first), first_destination),
    ];

    let destinations = heap
        .plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect("explicit destinations plan");

    assert_eq!(destinations.destinations().len(), 2);
    assert_eq!(
        destinations.destinations()[0],
        MinorGcRelocationDestination::new(gc_address(first), first_destination)
    );
    assert_eq!(
        destinations.destinations()[1],
        MinorGcRelocationDestination::new(gc_address(second), second_destination)
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan accepts explicit destinations");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    assert_eq!(
        byte_copy_plan
            .requests()
            .iter()
            .map(AllocationCollectorPollObjectByteCopyRequest::destination)
            .collect::<Vec<_>>(),
        vec![first_destination, second_destination]
    );
}

#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_duplicate_destination() {
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
    let destination = static_gc_address(0x5000_0000);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(gc_address(first), destination),
        MinorGcRelocationDestination::new(gc_address(second), destination),
    ];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("duplicate explicit destination rejects"),
        EvalHeapError::GenerationalGc(GenerationalGcError::DuplicateMinorGcRelocationDestination {
            address: destination,
        })
    );
}

#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_overlapping_ranges() {
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
    let first_destination = static_gc_address(0x5000_0000);
    let second_destination = static_gc_address(0x5000_0008);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(gc_address(first), first_destination),
        MinorGcRelocationDestination::new(gc_address(second), second_destination),
    ];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("overlapping explicit destination ranges reject"),
        EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: first_destination,
                second_generation: HeapGeneration::Young,
                second: second_destination,
            }
        )
    );
}

#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_cross_generation_overlap() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let copy = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("copied thunk allocates");
    let promote = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("promoted thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let copy_address = gc_address(copy);
    let promote_address = gc_address(promote);
    let roots = vec![
        ResolvedValueGeneration::young(copy_address),
        ResolvedValueGeneration::young(promote_address),
    ];
    let nursery_objects = vec![
        NurseryObjectAge::new(copy_address, 0),
        NurseryObjectAge::new(promote_address, 1),
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
    let copy_destination = static_gc_address(0x5000_0000);
    let promote_destination = static_gc_address(0x5000_0008);
    let explicit_destinations = [
        MinorGcRelocationDestination::new(copy_address, copy_destination),
        MinorGcRelocationDestination::new(promote_address, promote_destination),
    ];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("cross-generation explicit destination ranges reject"),
        EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcObjectCopyDestinationRangeOverlap {
                first_generation: HeapGeneration::Young,
                first: copy_destination,
                second_generation: HeapGeneration::Old,
                second: promote_destination,
            }
        )
    );
}

#[test]
fn collector_poll_minor_gc_explicit_relocation_destinations_reject_source_range_overlap() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
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
    let child_address = gc_address(child);
    let destination = static_gc_address(child_address.address_bits() + 8);
    let explicit_destinations = [MinorGcRelocationDestination::new(
        child_address,
        destination,
    )];

    assert_eq!(
        heap.plan_collector_poll_minor_gc_explicit_relocation_destinations(
            &planned,
            &explicit_destinations,
        )
        .expect_err("from-space interior explicit destination rejects"),
        EvalHeapError::GenerationalGc(
            GenerationalGcError::MinorGcObjectCopyDestinationSourceRangeOverlap {
                source_address: child_address,
                destination,
            }
        )
    );
}

#[test]
fn collector_poll_minor_gc_reserved_destination_records_bind_existing_heap_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let child_address = gc_address(child);
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");

    assert_eq!(reservations.len(), 1);
    assert!(!reservations.is_empty());
    let reservation = reservations.reservations()[0];
    assert_eq!(reservation.source(), child_address);
    assert_eq!(reservation.tag(), ValueTag::Thunk);
    assert_eq!(
        gc_address(reservation.destination_value()),
        reservation.destination()
    );
    assert_eq!(
        heap_generation(&heap, reservation.destination_value()),
        HeapGeneration::Young
    );
    assert_eq!(
        allocation_domain(&heap, reservation.destination_value()),
        HeapAllocationDomain::Worker
    );

    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("destination reservation requests a collector poll");
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
        .plan_collector_poll_minor_gc_reserved_relocation_destinations(&planned, &reservations)
        .expect("reserved destinations plan");

    assert_eq!(destinations.destinations().len(), 1);
    assert_eq!(destinations.destinations()[0].source(), child_address);
    assert_eq!(
        destinations.destinations()[0].destination(),
        reservation.destination()
    );
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan accepts reserved destination");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    assert_eq!(byte_copy_plan.len(), 1);
    let request = byte_copy_plan.requests()[0];
    assert_eq!(request.source(), child_address);
    assert_eq!(request.destination(), reservation.destination());
    assert_eq!(request.action(), MinorGcSurvivorAction::CopyToNursery);
    assert_eq!(request.destination_generation(), HeapGeneration::Young);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Thunk),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&byte_copy_plan)
        .expect("paired body/generation writes apply");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.body_write_report().copied_to_nursery(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(
        heap_generation(&heap, reservation.destination_value()),
        HeapGeneration::Young
    );
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Thunk)
        .expect("destination body is bound to source body");
}

#[test]
fn collector_poll_minor_gc_reserved_destination_records_support_promotions() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let child_address = gc_address(child);
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");
    let reservation = reservations.reservations()[0];
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("destination reservation requests a collector poll");
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
    let destinations = heap
        .plan_collector_poll_minor_gc_reserved_relocation_destinations(&planned, &reservations)
        .expect("reserved destinations plan");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan accepts reserved destination");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");

    assert_eq!(byte_copy_plan.len(), 1);
    assert_eq!(byte_copy_plan.promote_to_old_count(), 1);
    let request = byte_copy_plan.requests()[0];
    assert_eq!(request.source(), child_address);
    assert_eq!(request.destination(), reservation.destination());
    assert_eq!(request.action(), MinorGcSurvivorAction::PromoteToOld);
    assert_eq!(request.destination_generation(), HeapGeneration::Old);

    let report = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&byte_copy_plan)
        .expect("paired body/generation writes apply");

    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    assert_eq!(
        heap_generation(&heap, reservation.destination_value()),
        HeapGeneration::Old
    );
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Thunk)
        .expect("promoted destination body is bound to source body");
}

#[test]
fn collector_poll_minor_gc_reserved_destination_records_ignore_dead_young_reservations() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let live = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("live thunk allocates");
    let dead = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("dead thunk allocates");
    let live_address = gc_address(live);
    let dead_address = gc_address(dead);
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");
    let live_reservation = reservations
        .reservations()
        .iter()
        .copied()
        .find(|reservation| reservation.source() == live_address)
        .expect("live source has a reservation");
    let dead_reservation = reservations
        .reservations()
        .iter()
        .copied()
        .find(|reservation| reservation.source() == dead_address)
        .expect("dead source has a reservation");

    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("destination reservation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, live)
        .expect("live root records");
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
        .plan_collector_poll_minor_gc_reserved_relocation_destinations(&planned, &reservations)
        .expect("reserved destinations plan");

    assert_eq!(reservations.len(), 2);
    assert_eq!(destinations.destinations().len(), 1);
    assert_eq!(
        destinations.destinations()[0],
        MinorGcRelocationDestination::new(live_address, live_reservation.destination())
    );
    assert_ne!(
        destinations.destinations()[0].destination(),
        dead_reservation.destination()
    );
}

#[test]
fn collector_poll_minor_gc_reserved_destination_records_reject_stale_reservation_snapshot() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    let reservations = heap
        .reserve_current_young_minor_gc_destination_records()
        .expect("destination records reserve");
    let sibling = heap
        .alloc_thunk(EvalThunk::new(IrId::new(9)))
        .expect("post-reservation sibling allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("post-reservation allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, child)
        .expect("child root records");
    roots
        .try_push_value_stack(1, sibling)
        .expect("sibling root records");
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
        heap.plan_collector_poll_minor_gc_reserved_relocation_destinations(
            &planned,
            &reservations,
        )
        .expect_err("stale reservations reject"),
        EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation heap record count differs from minor-GC plan",
            expected_records: planned.heap_records(),
            actual_records: reservations.heap_records(),
        }
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
fn collector_poll_minor_gc_object_generation_writes_update_existing_destination_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    // Since FV-2 no allocation path creates a permanent record, so the
    // destination fixture manufactures one: a worker record flipped to the
    // permanent-shared domain.
    let destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("destination fixture thunk allocates");
    heap.set_allocation_domain_for_test(destination, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("source thunk allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, source)
        .expect("source root records");
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
            MinorGcDestinationBases::new(gc_address(destination), static_gc_address(0x2000_0000)),
        )
        .expect("destination plan derives heap layouts");
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan builds");
    let byte_copy_plan = heap
        .collector_poll_minor_gc_object_byte_copy_plan(&commit)
        .expect("object byte-copy plan derives");
    let generation_write_plan = byte_copy_plan
        .object_generation_write_plan()
        .expect("generation write plan derives");

    assert_eq!(generation_write_plan.len(), 1);
    assert!(!generation_write_plan.is_empty());
    assert_eq!(generation_write_plan.report().objects(), 1);
    assert_eq!(generation_write_plan.report().copied_to_nursery(), 1);
    assert_eq!(generation_write_plan.report().promoted_to_old(), 0);
    assert_eq!(
        generation_write_plan.report().payload_bytes(),
        record_layout_size(&heap, source)
    );
    assert_eq!(
        generation_write_plan.writes()[0].source(),
        gc_address(source)
    );
    assert_eq!(
        generation_write_plan.writes()[0].destination(),
        gc_address(destination)
    );
    assert_eq!(
        generation_write_plan.writes()[0].action(),
        MinorGcSurvivorAction::CopyToNursery
    );
    assert_eq!(
        generation_write_plan.writes()[0].generation(),
        HeapGeneration::Young
    );
    assert_eq!(
        heap_generation(&heap, destination),
        HeapGeneration::Permanent
    );

    let report = heap
        .apply_collector_poll_minor_gc_object_generation_writes(&generation_write_plan)
        .expect("generation writes apply");

    assert_eq!(report, generation_write_plan.report());
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert_eq!(
        allocation_domain(&heap, destination),
        HeapAllocationDomain::PermanentShared
    );
    assert_eq!(heap_generation(&heap, source), HeapGeneration::Young);
}

#[test]
fn collector_poll_minor_gc_object_body_writes_bind_existing_destination_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, source),
        record_layout_align(&heap, source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);

    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = heap
        .apply_collector_poll_minor_gc_object_body_writes(&plan)
        .expect("object body writes apply");

    assert_eq!(report.objects(), 1);
    assert_eq!(report.copied_to_nursery(), 1);
    assert_eq!(report.promoted_to_old(), 0);
    assert_eq!(report.payload_bytes(), record_layout_size(&heap, source));
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda)
        .expect("destination record body is bound to the source body");
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert_eq!(heap_generation(&heap, source), HeapGeneration::Young);
}

#[test]
fn collector_poll_minor_gc_object_body_and_generation_writes_bind_body_and_promote_destination() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        record_layout_size(&heap, source),
        record_layout_align(&heap, source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let report = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&plan)
        .expect("paired body/generation writes apply");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda)
        .expect("destination body is bound to source body");
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Old);
    assert_eq!(heap_generation(&heap, source), HeapGeneration::Young);
}

#[test]
fn collector_poll_minor_gc_object_body_and_generation_writes_validate_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(7),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(source),
        gc_address(destination),
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        record_layout_size(&heap, source),
        record_layout_align(&heap, source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![request]);

    let report = heap
        .validate_collector_poll_minor_gc_object_body_and_generation_writes(&plan)
        .expect("paired body/generation writes validate");

    assert_eq!(report.body_write_report().objects(), 1);
    assert_eq!(report.body_write_report().promoted_to_old(), 1);
    assert_eq!(report.generation_write_report().objects(), 1);
    assert_eq!(report.generation_write_report().promoted_to_old(), 1);
    assert_eq!(heap_generation(&heap, destination), HeapGeneration::Young);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

#[test]
fn collector_poll_minor_gc_object_body_and_generation_writes_reject_duplicate_destination_without_mutation()
 {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("first source lambda allocates");
    let second_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("second source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let first_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(first_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, first_source),
        record_layout_align(&heap, first_source),
    );
    let second_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(second_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, second_source),
        record_layout_align(&heap, second_source),
    );
    let plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        first_request,
        second_request,
    ]);
    let generation_before = heap_generation(&heap, destination);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(first_request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));

    let err = heap
        .apply_collector_poll_minor_gc_object_body_and_generation_writes(&plan)
        .expect_err("duplicate destination is rejected before mutation");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 1,
            source_address,
            existing_source_address,
            destination: actual_destination,
        } if source_address == gc_address(second_source)
            && existing_source_address == gc_address(first_source)
            && actual_destination == gc_address(destination)
    ));
    assert_eq!(heap_generation(&heap, destination), generation_before);
    assert!(matches!(
        heap.validate_collector_poll_minor_gc_object_body_binding(first_request, ValueTag::Lambda),
        Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
            reason: "destination record body does not match source record body",
            ..
        })
    ));
}

#[test]
fn collector_poll_minor_gc_object_body_writes_reject_malformed_plan_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("first source lambda allocates");
    let second_source = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(8),
            FrameId::new(9),
            EvalEnv::default(),
        ))
        .expect("second source lambda allocates");
    let destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("destination lambda allocates");
    let first_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(first_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, first_source),
        record_layout_align(&heap, first_source),
    );
    let second_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(second_source),
        gc_address(destination),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, second_source),
        record_layout_align(&heap, second_source),
    );
    let duplicate_destination_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
            first_request,
            second_request,
        ]);

    let err = heap
        .apply_collector_poll_minor_gc_object_body_writes(&duplicate_destination_plan)
        .expect_err("duplicate destination rejects body writes");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 1,
            source_address: gc_address(second_source),
            existing_source_address: gc_address(first_source),
            destination: gc_address(destination),
        }
    );
    assert_eq!(
        heap.get_lambda(destination)
            .expect("destination remains a lambda")
            .pattern(),
        IrId::new(0)
    );

    let destination_is_source_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        gc_address(first_source),
        gc_address(first_source),
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        record_layout_size(&heap, first_source),
        record_layout_align(&heap, first_source),
    );
    let destination_is_source_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
            destination_is_source_request,
        ]);

    let err = heap
        .apply_collector_poll_minor_gc_object_body_writes(&destination_is_source_plan)
        .expect_err("destination matching source rejects body writes");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDestinationIsSource {
            source_address: gc_address(first_source),
        }
    );
    assert_eq!(
        heap.get_lambda(first_source)
            .expect("source remains a lambda")
            .pattern(),
        IrId::new(1)
    );
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_reject_flat_list_writeback_objects() {
    // Lists are flat and permanent since FV-1, so they are never minor-GC
    // survivors: a copied heap-field write naming a flat list as its
    // relocated writeback object must fail loudly without mutation.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");
    let parent_destination = heap
        .alloc_list(NixList::new(vec![Value::int(0)]))
        .expect("parent destination list allocates");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect_err("flat-list copied writeback object is rejected");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollSurvivorAddress {
            address: gc_address(parent),
        }
    );
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(list.get(0).expect("original element exists").raw_eq(child));
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_bound_thunk_select_receiver() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let receiver = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("receiver thunk allocates");
    let receiver_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("receiver destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(3),
            receiver,
            IrAttrPathId::new(0),
        ))
        .expect("parent select thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::select(
            EvalModuleId::ROOT,
            IrId::new(3),
            Value::int(0),
            IrAttrPathId::new(0),
        ))
        .expect("parent destination thunk allocates");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let receiver_request = object_copy_request_for_values(
        &heap,
        receiver,
        receiver_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        receiver_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::ThunkSelectReceiver,
        ResolvedValueGeneration::Heap {
            address: gc_address(receiver_destination),
            generation: HeapGeneration::Old,
        },
        receiver_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied thunk select receiver write applies");

    assert_eq!(report.fields(), 1);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, parent_destination)
        .expect("destination thunk root records");
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, parent_destination).edges();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].source(), &HeapEdgeSource::ThunkSelectReceiver);
    assert!(edges[0].value().raw_eq(receiver_destination));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_merge_same_flat_list_fields() {
    // Two direct writes against the SAME flat list must merge through one
    // staged spine (doc 30 FV-1 coupling (c)): the second write sees the
    // first write's staged element, and one commit publishes both.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("first child lambda allocates");
    let second_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("second child lambda allocates");
    let first_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("first destination lambda allocates");
    let second_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("second destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![first_child, second_child]))
        .expect("parent list allocates");

    let first_request = object_copy_request_for_values(
        &heap,
        first_child,
        first_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let second_request = object_copy_request_for_values(
        &heap,
        second_child,
        second_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        first_request,
        second_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let writes = [
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: gc_address(first_destination),
                generation: HeapGeneration::Old,
            },
            first_request,
        ),
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            1,
            HeapEdgeSource::ListElement { index: 1 },
            ResolvedValueGeneration::Heap {
                address: gc_address(second_destination),
                generation: HeapGeneration::Old,
            },
            second_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&writes)
        .expect("merged flat list field writes apply");

    assert_eq!(report.fields(), 2);
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("first rewritten element exists")
            .raw_eq(first_destination)
    );
    assert!(
        list.get(1)
            .expect("second rewritten element exists")
            .raw_eq(second_destination)
    );
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Permanent);
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_reject_flat_attrs_writeback_objects() {
    // Attrsets are flat and permanent since FV-2, so they are never minor-GC
    // survivors: a copied heap-field write naming a flat attrset as its
    // relocated writeback object must fail loudly without mutation.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent_attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, child)], &symbols).expect("attrs build");
    let parent_destination_attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, Value::int(0))], &symbols)
            .expect("destination attrs build");
    let parent = heap
        .alloc_attrs(0, parent_attrs)
        .expect("parent attrs allocate");
    let parent_destination = heap
        .alloc_attrs(0, parent_destination_attrs)
        .expect("parent destination attrs allocate");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::AttrBinding {
            shape: 0,
            slot: 0,
            key,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect_err("flat-attrs copied writeback object is rejected");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollSurvivorAddress {
            address: gc_address(parent),
        }
    );
    let attrs = heap.get_attrs(parent).expect("parent attrs remain typed");
    assert!(attrs.get(key).expect("original binding exists").raw_eq(child));
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_bound_primop_args() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), child)],
        ))
        .expect("parent primop allocates");
    let parent_destination = heap
        .alloc_primop(EvalPrimOp::new(symbol))
        .expect("parent destination primop allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        child_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied primop argument write applies");

    assert_eq!(report.fields(), 1);
    let primop = heap
        .get_primop(parent_destination)
        .expect("destination primop remains typed");
    assert_eq!(primop.builtin(), Some(builtin));
    assert_eq!(primop.symbol(), symbol);
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].id(), IrId::new(7));
    assert_eq!(primop.args()[0].span(), Span::new(9, 12));
    assert!(primop.args()[0].value().raw_eq(child_destination));
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_lambda_capture_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let lexical_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lexical child lambda allocates");
    let with_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("with child lambda allocates");
    let global_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("global child lambda allocates");
    let with_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("with destination lambda allocates");
    let global_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("global destination lambda allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(8),
        with_child,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[global_child]).expect("scoped globals capture");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, lexical_child).expect("lexical slot writes");
    let env = EvalEnv::capture(&[frame]).expect("lexical env captures");
    let parent = heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(5),
            IrId::new(6),
            FrameId::new(7),
            env,
            with_env,
            scoped_globals,
        ))
        .expect("parent lambda allocates");
    let parent_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("parent destination lambda allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let with_request = object_copy_request_for_values(
        &heap,
        with_child,
        with_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let global_request = object_copy_request_for_values(
        &heap,
        global_child,
        global_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        with_request,
        global_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let writes = [
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            gc_address(parent_destination),
            1,
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(with_destination),
                generation: HeapGeneration::Old,
            },
            with_request,
            parent_request,
        ),
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            gc_address(parent_destination),
            2,
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(global_destination),
                generation: HeapGeneration::Old,
            },
            global_request,
            parent_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&writes)
        .expect("copied lambda capture field writes apply");

    assert_eq!(report.fields(), 2);
    let lambda = heap
        .get_lambda(parent_destination)
        .expect("destination lambda remains typed");
    assert_eq!(lambda.pattern(), IrId::new(5));
    assert_eq!(lambda.body(), IrId::new(6));
    assert_eq!(lambda.frame(), FrameId::new(7));
    assert_eq!(lambda.env().frames().len(), 1);
    assert!(
        lambda.env().frames()[0]
            .get(0)
            .expect("lexical slot reads")
            .raw_eq(lexical_child)
    );
    assert_eq!(lambda.with_scope_env().scopes().len(), 1);
    assert_eq!(lambda.with_scope_env().scopes()[0].scope(), IrId::new(8));
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(with_destination)
    );
    assert_eq!(lambda.scoped_global_env().scopes().len(), 1);
    assert!(lambda.scoped_global_env().scopes()[0].raw_eq(global_destination));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_worker_domain_flat_lists() {
    // Lists are flat and permanent since FV-1: a direct write that claims a
    // list is worker-domain (the pre-FV-1 "old worker list" shape) must fail
    // the generation gate loudly without mutating the flat payload.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("worker-domain flat-list write is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object: gc_address(parent),
            expected: HeapGeneration::Old,
            actual: HeapGeneration::Permanent,
        }
    );
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(list.get(0).expect("original element exists").raw_eq(child));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_merge_same_flat_attrs_fields() {
    // Two direct writes against the SAME flat attrset must merge through one
    // staged entry storage (doc 30 FV-2 coupling (c)): the second write sees
    // the first write's staged entry, and one commit publishes both.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let first_key = symbols.intern(b"alpha").expect("alpha interns");
    let second_key = symbols.intern(b"beta").expect("beta interns");
    let first_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("first child lambda allocates");
    let second_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("second child lambda allocates");
    let first_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("first destination lambda allocates");
    let second_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("second destination lambda allocates");
    let parent_attrs = FlatAttrs::new(
        vec![
            AttrEntry::new(first_key, first_child),
            AttrEntry::new(second_key, second_child),
        ],
        &symbols,
    )
    .expect("attrs build");
    let parent = heap
        .alloc_attrs(0, parent_attrs)
        .expect("parent attrs allocate");

    let first_request = object_copy_request_for_values(
        &heap,
        first_child,
        first_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let second_request = object_copy_request_for_values(
        &heap,
        second_child,
        second_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        first_request,
        second_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let writes = [
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            0,
            HeapEdgeSource::AttrBinding {
                shape: 0,
                slot: 0,
                key: first_key,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(first_destination),
                generation: HeapGeneration::Old,
            },
            first_request,
        ),
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::PermanentShared,
            gc_address(parent),
            1,
            HeapEdgeSource::AttrBinding {
                shape: 0,
                slot: 1,
                key: second_key,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(second_destination),
                generation: HeapGeneration::Old,
            },
            second_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&writes)
        .expect("merged flat attrs field writes apply");

    assert_eq!(report.fields(), 2);
    let attrs = heap.get_attrs(parent).expect("parent attrs remain typed");
    assert!(
        attrs
            .get(first_key)
            .expect("first rewritten binding exists")
            .raw_eq(first_destination)
    );
    assert!(
        attrs
            .get(second_key)
            .expect("second rewritten binding exists")
            .raw_eq(second_destination)
    );
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Permanent);
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_worker_domain_flat_attrs() {
    // Attrsets are flat and permanent since FV-2: a direct write that claims
    // an attrset is worker-domain (the pre-FV-2 "old worker attrs" shape)
    // must fail the generation gate loudly without mutating the flat payload.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let key = symbols.intern(b"name").expect("symbol interns");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent_attrs =
        FlatAttrs::new(vec![AttrEntry::new(key, child)], &symbols).expect("attrs build");
    let parent = heap
        .alloc_attrs(0, parent_attrs)
        .expect("parent attrs allocate");

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::AttrBinding {
            shape: 0,
            slot: 0,
            key,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("worker-domain flat-attrs write is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
            allocation_domain: HeapAllocationDomain::Worker,
            writeback_object: gc_address(parent),
            expected: HeapGeneration::Old,
            actual: HeapGeneration::Permanent,
        }
    );
    let attrs = heap.get_attrs(parent).expect("parent attrs remain typed");
    assert!(attrs.get(key).expect("original binding exists").raw_eq(child));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_old_primop_args() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), child)],
        ))
        .expect("parent primop allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct old primop argument write applies");

    assert_eq!(report.fields(), 1);
    let primop = heap
        .get_primop(parent)
        .expect("parent primop remains typed");
    assert_eq!(primop.builtin(), Some(builtin));
    assert_eq!(primop.symbol(), symbol);
    assert_eq!(primop.args().len(), 1);
    assert_eq!(primop.args()[0].id(), IrId::new(7));
    assert_eq!(primop.args()[0].span(), Span::new(9, 12));
    assert!(primop.args()[0].value().raw_eq(child_destination));
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Old);
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_old_lambda_capture_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let lexical_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lexical child lambda allocates");
    let with_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("with child lambda allocates");
    let global_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("global child lambda allocates");
    let with_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("with destination lambda allocates");
    let global_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("global destination lambda allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(8),
        with_child,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[global_child]).expect("scoped globals capture");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, lexical_child).expect("lexical slot writes");
    let env = EvalEnv::capture(&[frame]).expect("lexical env captures");
    let parent = heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(5),
            IrId::new(6),
            FrameId::new(7),
            env,
            with_env,
            scoped_globals,
        ))
        .expect("parent lambda allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let with_request = object_copy_request_for_values(
        &heap,
        with_child,
        with_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let global_request = object_copy_request_for_values(
        &heap,
        global_child,
        global_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        with_request,
        global_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generations write");
    let writes = [
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            1,
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(with_destination),
                generation: HeapGeneration::Old,
            },
            with_request,
        ),
        AllocationCollectorPollDirectHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            2,
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(global_destination),
                generation: HeapGeneration::Old,
            },
            global_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&writes)
        .expect("direct old lambda capture field writes apply");

    assert_eq!(report.fields(), 2);
    let lambda = heap
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert_eq!(lambda.pattern(), IrId::new(5));
    assert_eq!(lambda.body(), IrId::new(6));
    assert_eq!(lambda.frame(), FrameId::new(7));
    assert_eq!(lambda.env().frames().len(), 1);
    assert!(
        lambda.env().frames()[0]
            .get(0)
            .expect("lexical slot reads")
            .raw_eq(lexical_child)
    );
    assert_eq!(lambda.with_scope_env().scopes().len(), 1);
    assert_eq!(lambda.with_scope_env().scopes()[0].scope(), IrId::new(8));
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(with_destination)
    );
    assert_eq!(lambda.scoped_global_env().scopes().len(), 1);
    assert!(lambda.scoped_global_env().scopes()[0].raw_eq(global_destination));
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Old);
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_stale_field_value_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let stale_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("stale child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![stale_child]))
        .expect("parent list allocates");

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("stale old field is rejected");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
            writeback_object,
            field_index: 0,
            field_source,
            expected,
            actual,
        } if writeback_object == gc_address(parent)
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && expected == (ResolvedValueGeneration::Heap {
                address: gc_address(child),
                generation: HeapGeneration::Young,
            })
            && actual == (ResolvedValueGeneration::Heap {
                address: gc_address(stale_child),
                generation: HeapGeneration::Young,
            })
    ));
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("original element exists")
            .raw_eq(stale_child)
    );
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_permanent_list_fields() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::PermanentShared);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Old,
        },
        child_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("permanent list field write applies");

    assert_eq!(report.fields(), 1);
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("rewritten element exists")
            .raw_eq(child_destination)
    );
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Permanent);
}

#[test]
fn collector_poll_minor_gc_heap_field_writes_merge_mixed_same_record_fields() {
    // Lists are flat since FV-1, so a partially applied builtin carries the
    // mixed copied+direct writes against one record.
    let mut heap = EvalHeap::with_initial_chunk_bytes(2048).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let first_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("first child lambda allocates");
    let second_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("second child lambda allocates");
    let first_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(3),
            IrId::new(3),
            FrameId::new(3),
            EvalEnv::default(),
        ))
        .expect("first destination lambda allocates");
    let second_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(4),
            IrId::new(4),
            FrameId::new(4),
            EvalEnv::default(),
        ))
        .expect("second destination lambda allocates");
    let copied_source_parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![
                EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), first_child),
                EvalPrimOpArg::new(IrId::new(8), Span::new(13, 16), second_child),
            ],
        ))
        .expect("copied source parent primop allocates");
    let parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![
                EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), first_child),
                EvalPrimOpArg::new(IrId::new(8), Span::new(13, 16), second_child),
            ],
        ))
        .expect("parent primop allocates");
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let parent_request = object_copy_request_for_values(
        &heap,
        copied_source_parent,
        parent,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let first_request = object_copy_request_for_values(
        &heap,
        first_child,
        first_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let second_request = object_copy_request_for_values(
        &heap,
        second_child,
        second_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        first_request,
        second_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let copied_write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(copied_source_parent),
        gc_address(parent),
        1,
        HeapEdgeSource::PrimopArgument { index: 1 },
        ResolvedValueGeneration::Heap {
            address: gc_address(second_destination),
            generation: HeapGeneration::Old,
        },
        second_request,
        parent_request,
    );
    let direct_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(first_destination),
            generation: HeapGeneration::Old,
        },
        first_request,
    );

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes(&[copied_write], &[direct_write])
        .expect("mixed same-record heap field writes apply");

    assert_eq!(copied_report.fields(), 1);
    assert_eq!(direct_report.fields(), 1);
    let primop = heap
        .get_primop(parent)
        .expect("parent primop remains typed");
    assert!(primop.args()[0].value().raw_eq(first_destination));
    assert!(primop.args()[1].value().raw_eq(second_destination));
}

#[test]
fn collector_poll_minor_gc_heap_field_writes_reject_cross_branch_malformed_request_set() {
    let mut heap = EvalHeap::new();
    let parent_source = static_gc_address(0x1000_0000);
    let parent_destination = static_gc_address(0x2000_0000);
    let copied_child = static_gc_address(0x3000_0000);
    let direct_child = static_gc_address(0x4000_0000);
    let shared_child_destination = static_gc_address(0x5000_0000);
    let parent_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        parent_source,
        parent_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        16,
        8,
    );
    let copied_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        copied_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let direct_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        direct_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let copied_write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        parent_source,
        parent_destination,
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: shared_child_destination,
            generation: HeapGeneration::Old,
        },
        copied_child_request,
        parent_request,
    );
    let direct_write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        parent_destination,
        1,
        HeapEdgeSource::ListElement { index: 1 },
        ResolvedValueGeneration::Heap {
            address: shared_child_destination,
            generation: HeapGeneration::Old,
        },
        direct_child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_heap_field_writes(&[copied_write], &[direct_write])
        .expect_err("cross-branch duplicate destination rejects before heap mutation");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 2,
            source_address: direct_child,
            existing_source_address: copied_child,
            destination: shared_child_destination,
        }
    );
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_young_replacements_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("direct old-to-young field write is rejected");

    assert!(matches!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteYoungReplacementUnsupported {
            writeback_object,
            field_index: 0,
            field_source,
            replacement,
            generation: HeapGeneration::Young,
        } if writeback_object == gc_address(parent)
            && field_source == (HeapEdgeSource::ListElement { index: 0 })
            && replacement == gc_address(child_destination)
    ));
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(list.get(0).expect("original element exists").raw_eq(child));
}

#[test]
fn collector_poll_minor_gc_heap_field_writes_publish_barrier_for_direct_young_replacement() {
    // Lists are flat since FV-1, so an old worker primop carries the direct
    // old-to-young write whose barrier must publish.
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let mut symbols = SymbolTable::new();
    let symbol = symbols.intern(b"length").expect("symbol interns");
    let builtin = lookup_builtin(b"length").expect("length builtin is registered");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_primop(EvalPrimOp::registered_with_args(
            symbol,
            builtin,
            vec![EvalPrimOpArg::new(IrId::new(7), Span::new(9, 12), child)],
        ))
        .expect("parent primop allocates");
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::PrimopArgument { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[write],
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier-aware direct old-to-young write applies");

    assert_eq!(copied_report.fields(), 0);
    assert_eq!(direct_report.fields(), 1);
    let primop = heap
        .get_primop(parent)
        .expect("parent primop remains typed");
    assert!(primop.args()[0].value().raw_eq(child_destination));
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(parent),
            gc_address(child_destination)
        )]
    );
    assert!(card_table.snapshot().covers_source(gc_address(parent)));
}

#[test]
fn collector_poll_minor_gc_heap_field_writes_publish_barrier_for_permanent_young_replacement() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let parent = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("parent list allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::PermanentShared);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::PermanentShared,
        gc_address(parent),
        0,
        HeapEdgeSource::ListElement { index: 0 },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[write],
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier-aware permanent-to-young write applies");

    assert_eq!(copied_report.fields(), 0);
    assert_eq!(direct_report.fields(), 1);
    let list = heap.get_list(parent).expect("parent list remains typed");
    assert!(
        list.get(0)
            .expect("rewritten element exists")
            .raw_eq(child_destination)
    );
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(parent),
            gc_address(child_destination)
        )]
    );
    assert!(card_table.snapshot().covers_source(gc_address(parent)));
    assert_eq!(heap_generation(&heap, parent), HeapGeneration::Permanent);
}

#[test]
fn collector_poll_minor_gc_heap_field_writes_publish_lambda_capture_barrier() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let lexical_child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(0),
            IrId::new(0),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("lexical child lambda allocates");
    let child = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("child lambda allocates");
    let child_destination = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(2),
            IrId::new(2),
            FrameId::new(2),
            EvalEnv::default(),
        ))
        .expect("child destination lambda allocates");
    let with_env =
        EvalWithEnv::capture(&[EvalWithScope::new(EvalModuleId::ROOT, IrId::new(8), child)])
            .expect("with env captures");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, lexical_child).expect("lexical slot writes");
    let env = EvalEnv::capture(&[frame]).expect("lexical env captures");
    let parent = heap
        .alloc_lambda(EvalLambda::with_captures(
            EvalModuleId::ROOT,
            IrId::new(5),
            IrId::new(6),
            FrameId::new(7),
            env,
            with_env,
            EvalScopedGlobalEnv::default(),
        ))
        .expect("parent lambda allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let child_request = object_copy_request_for_values(
        &heap,
        child,
        child_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![child_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        1,
        HeapEdgeSource::CapturedWithScope {
            owner: CapturedRootOwner::Lambda,
            index: 0,
        },
        ResolvedValueGeneration::Heap {
            address: gc_address(child_destination),
            generation: HeapGeneration::Young,
        },
        child_request,
    );
    let mut remembered_set = RememberedSet::new();
    let mut card_table = GcCardTable::default();

    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            &[],
            &[write],
            &mut remembered_set,
            &mut card_table,
        )
        .expect("barrier-aware direct old-to-young lambda capture write applies");

    assert_eq!(copied_report.fields(), 0);
    assert_eq!(direct_report.fields(), 1);
    let lambda = heap
        .get_lambda(parent)
        .expect("parent lambda remains typed");
    assert_eq!(lambda.env().frames().len(), 1);
    assert!(
        lambda.env().frames()[0]
            .get(0)
            .expect("lexical slot reads")
            .raw_eq(lexical_child)
    );
    assert_eq!(lambda.with_scope_env().scopes().len(), 1);
    assert_eq!(lambda.with_scope_env().scopes()[0].scope(), IrId::new(8));
    assert!(
        lambda.with_scope_env().scopes()[0]
            .value()
            .raw_eq(child_destination)
    );
    assert_eq!(
        remembered_set.edges(),
        &[RememberedEdge::new(
            gc_address(parent),
            gc_address(child_destination)
        )]
    );
    assert!(card_table.snapshot().covers_source(gc_address(parent)));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_suspended_thunk_apply_argument() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(2),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("function lambda allocates");
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("argument thunk allocates");
    let argument_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("argument destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(5),
            Span::new(0, 1),
            function,
            EvalModuleId::ROOT,
            IrId::new(6),
            argument,
        ))
        .expect("parent apply thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![argument_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        1,
        HeapEdgeSource::ThunkApplyArgument,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct thunk apply argument write applies");

    assert_eq!(report.fields(), 1);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, parent)
        .expect("apply thunk root records");
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, parent).edges();
    assert_eq!(edges.len(), 2);
    assert!(edges.iter().any(|edge| {
        edge.source() == &HeapEdgeSource::ThunkApplyFunction && edge.value().raw_eq(function)
    }));
    assert!(edges.iter().any(|edge| {
        edge.source() == &HeapEdgeSource::ThunkApplyArgument
            && edge.value().raw_eq(argument_destination)
    }));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_preserve_parallel_payload_on_suspended_thunk_write()
 {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("argument thunk allocates");
    let argument_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("argument destination thunk allocates");
    let payload = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("parallel payload thunk allocates");
    let parent = heap
        .alloc_thunk(
            EvalThunk::apply(
                EvalModuleId::ROOT,
                IrId::new(4),
                Span::new(0, 1),
                Value::int(1),
                EvalModuleId::ROOT,
                IrId::new(5),
                argument,
            )
            .with_parallel_payload_cell(tree_walk_error(99), None),
        )
        .expect("parent apply thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    publish_parallel_payload(&parent_thunk, payload);

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![argument_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkApplyArgument,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct thunk apply argument write applies");

    assert_eq!(report.fields(), 1);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk still clones");
    let EvalThunkKind::Apply { argument_value, .. } = parent_thunk.kind() else {
        panic!("parent remains an apply thunk");
    };
    assert!(argument_value.raw_eq(argument_destination));
    assert_parallel_payload(&parent_thunk, payload);
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_suspended_thunk_captures() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let with_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("with child thunk allocates");
    let global_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("global child thunk allocates");
    let with_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("with destination thunk allocates");
    let global_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("global destination thunk allocates");
    let with_env = EvalWithEnv::capture(&[EvalWithScope::new(
        EvalModuleId::ROOT,
        IrId::new(5),
        with_child,
    )])
    .expect("with env captures");
    let scoped_globals =
        EvalScopedGlobalEnv::capture(&[global_child]).expect("scoped globals capture");
    let parent = heap
        .alloc_thunk(EvalThunk::with_captures(
            EvalModuleId::ROOT,
            IrId::new(6),
            EvalEnv::default(),
            with_env,
            scoped_globals,
        ))
        .expect("parent thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::with_captures(
            EvalModuleId::ROOT,
            IrId::new(6),
            EvalEnv::default(),
            EvalWithEnv::default(),
            EvalScopedGlobalEnv::default(),
        ))
        .expect("parent destination thunk allocates");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let with_request = object_copy_request_for_values(
        &heap,
        with_child,
        with_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let global_request = object_copy_request_for_values(
        &heap,
        global_child,
        global_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        with_request,
        global_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let writes = [
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            gc_address(parent_destination),
            0,
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(with_destination),
                generation: HeapGeneration::Old,
            },
            with_request,
            parent_request,
        ),
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            gc_address(parent),
            gc_address(parent_destination),
            1,
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index: 0,
            },
            ResolvedValueGeneration::Heap {
                address: gc_address(global_destination),
                generation: HeapGeneration::Old,
            },
            global_request,
            parent_request,
        ),
    ];

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&writes)
        .expect("copied thunk capture writes apply");

    assert_eq!(report.fields(), 2);
    let mut roots = EvalRootSet::new();
    roots
        .try_push_value_stack(0, parent_destination)
        .expect("destination thunk root records");
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");
    let edges = object_for(&scan, parent_destination).edges();
    assert_eq!(edges.len(), 2);
    assert!(edges.iter().any(|edge| {
        edge.source()
            == &HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index: 0,
            }
            && edge.value().raw_eq(with_destination)
    }));
    assert!(edges.iter().any(|edge| {
        edge.source()
            == &HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index: 0,
            }
            && edge.value().raw_eq(global_destination)
    }));
}

fn assert_forced_apply_thunk_cached_result(
    thunk: &EvalThunk,
    function: Value,
    argument: Value,
    cached: Value,
) {
    assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));
    assert!(
        thunk
            .cell()
            .cached_value()
            .expect("cached value reads")
            .expect("forced cached result exists")
            .raw_eq(cached)
    );
    let EvalThunkKind::Apply {
        function_value,
        argument_value,
        ..
    } = thunk.kind()
    else {
        panic!("forced parent thunk should preserve apply metadata");
    };
    assert!(function_value.raw_eq(function));
    assert!(argument_value.raw_eq(argument));
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_forced_thunk_cached_result() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(10),
            IrId::new(11),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("function lambda allocates");
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(12)))
        .expect("argument thunk allocates");
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("forced result thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("forced destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            function,
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("parent destination thunk allocates");
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };
    guard.finish(forced).expect("forced result publishes");

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        forced_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::ThunkCachedResult,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied forced cached-result write applies");

    assert_eq!(report.fields(), 1);
    let parent_destination_thunk = heap
        .clone_thunk(parent_destination)
        .expect("destination parent thunk clones");
    assert_forced_apply_thunk_cached_result(
        &parent_destination_thunk,
        function,
        argument,
        forced_destination,
    );
    let parent_thunk = heap
        .clone_thunk(parent)
        .expect("source parent thunk clones");
    assert_forced_apply_thunk_cached_result(&parent_thunk, function, argument, forced);
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_blackholed_thunk_field() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("argument thunk allocates");
    let argument_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("argument destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            Value::int(1),
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![argument_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkApplyArgument,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("blackholed thunk writes remain unsupported");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
            writeback_object: gc_address(parent),
            field_index: 0,
            field_source: HeapEdgeSource::ThunkApplyArgument,
        }
    );
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Blackhole));
    guard.abort().expect("claim aborts");
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_reject_blackholed_thunk_cached_result() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("argument thunk allocates");
    let argument_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("argument destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            Value::int(1),
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };

    let argument_request = object_copy_request_for_values(
        &heap,
        argument,
        argument_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkCachedResult,
        ResolvedValueGeneration::Heap {
            address: gc_address(argument_destination),
            generation: HeapGeneration::Old,
        },
        argument_request,
    );

    let err = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect_err("blackholed cached-result field is not a current live slot");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
            index: 0,
            expected: HeapEdgeSource::ThunkCachedResult,
            actual: Some(HeapEdgeSource::ThunkApplyArgument),
        }
    );
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Blackhole));
    assert!(matches!(parent_thunk.cell().cached_value(), Ok(None)));
    guard.abort().expect("claim aborts");
    assert_eq!(parent_thunk.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_forced_thunk_cached_result() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let function = heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(10),
            IrId::new(11),
            FrameId::new(1),
            EvalEnv::default(),
        ))
        .expect("function lambda allocates");
    let argument = heap
        .alloc_thunk(EvalThunk::new(IrId::new(12)))
        .expect("argument thunk allocates");
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("forced result thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("forced destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::apply(
            EvalModuleId::ROOT,
            IrId::new(3),
            Span::new(0, 1),
            function,
            EvalModuleId::ROOT,
            IrId::new(4),
            argument,
        ))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    let claim = parent_thunk.cell().begin_force().expect("force begins");
    let crate::eval::thunk::ForceClaim::Claimed(guard) = claim else {
        panic!("new parent thunk should be claimable");
    };
    guard.finish(forced).expect("forced result publishes");

    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![forced_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkCachedResult,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("forced cached-result rewrite applies");

    assert_eq!(report.fields(), 1);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk still clones");
    assert_forced_apply_thunk_cached_result(&parent_thunk, function, argument, forced_destination);
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_rewrite_parallel_thunk_payload() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("parallel payload thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("parallel payload destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)).with_parallel_payload_cell(tree_walk_error(99), None))
        .expect("parent thunk allocates");
    let parent_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(4)))
        .expect("parent destination thunk allocates");
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    publish_parallel_payload(&parent_thunk, forced);

    let parent_request = object_copy_request_for_values(
        &heap,
        parent,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
    );
    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan = AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![
        parent_request,
        forced_request,
    ]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("object bodies bind");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("destination generations write");
    let write = AllocationCollectorPollCopiedHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        gc_address(parent_destination),
        0,
        HeapEdgeSource::ThunkParallelPayloadValue,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
        parent_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&[write])
        .expect("copied parallel payload write applies");

    assert_eq!(report.fields(), 1);
    let parent_destination_thunk = heap
        .clone_thunk(parent_destination)
        .expect("destination parent thunk clones");
    assert_parallel_payload(&parent_destination_thunk, forced_destination);
    let parent_thunk = heap
        .clone_thunk(parent)
        .expect("source parent thunk still clones");
    assert_parallel_payload(&parent_thunk, forced);
}

#[test]
fn collector_poll_minor_gc_direct_heap_field_writes_rewrite_parallel_thunk_payload() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let forced = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("parallel payload thunk allocates");
    let forced_destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("parallel payload destination thunk allocates");
    let parent = heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)).with_parallel_payload_cell(tree_walk_error(99), None))
        .expect("parent thunk allocates");
    set_allocation_domain(&mut heap, parent, HeapAllocationDomain::Worker);
    set_heap_generation(&mut heap, parent, HeapGeneration::Old);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk clones");
    publish_parallel_payload(&parent_thunk, forced);

    let forced_request = object_copy_request_for_values(
        &heap,
        forced,
        forced_destination,
        MinorGcSurvivorAction::PromoteToOld,
    );
    let copy_plan =
        AllocationCollectorPollObjectByteCopyPlan::from_requests_for_test(vec![forced_request]);
    heap.apply_collector_poll_minor_gc_object_body_writes(&copy_plan)
        .expect("replacement body binds");
    let generation_plan = copy_plan
        .object_generation_write_plan()
        .expect("generation write plan builds");
    heap.apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("replacement generation writes");
    let write = AllocationCollectorPollDirectHeapFieldWrite::new(
        HeapAllocationDomain::Worker,
        gc_address(parent),
        0,
        HeapEdgeSource::ThunkParallelPayloadValue,
        ResolvedValueGeneration::Heap {
            address: gc_address(forced_destination),
            generation: HeapGeneration::Old,
        },
        forced_request,
    );

    let report = heap
        .apply_collector_poll_minor_gc_direct_heap_field_writes(&[write])
        .expect("direct parallel payload write applies");

    assert_eq!(report.fields(), 1);
    let parent_thunk = heap.clone_thunk(parent).expect("parent thunk still clones");
    assert_parallel_payload(&parent_thunk, forced_destination);
}

#[test]
fn collector_poll_minor_gc_copied_heap_field_writes_reject_malformed_copy_request_set() {
    let mut heap = EvalHeap::new();
    let parent_source = static_gc_address(0x1000_0000);
    let parent_destination = static_gc_address(0x2000_0000);
    let first_child = static_gc_address(0x3000_0000);
    let second_child = static_gc_address(0x4000_0000);
    let shared_child_destination = static_gc_address(0x5000_0000);
    let parent_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        parent_source,
        parent_destination,
        MinorGcSurvivorAction::CopyToNursery,
        HeapGeneration::Young,
        16,
        8,
    );
    let first_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        first_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let second_child_request = AllocationCollectorPollObjectByteCopyRequest::for_test(
        second_child,
        shared_child_destination,
        MinorGcSurvivorAction::PromoteToOld,
        HeapGeneration::Old,
        24,
        8,
    );
    let writes = [
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            parent_source,
            parent_destination,
            0,
            HeapEdgeSource::ListElement { index: 0 },
            ResolvedValueGeneration::Heap {
                address: shared_child_destination,
                generation: HeapGeneration::Old,
            },
            first_child_request,
            parent_request,
        ),
        AllocationCollectorPollCopiedHeapFieldWrite::new(
            HeapAllocationDomain::Worker,
            parent_source,
            parent_destination,
            1,
            HeapEdgeSource::ListElement { index: 1 },
            ResolvedValueGeneration::Heap {
                address: shared_child_destination,
                generation: HeapGeneration::Old,
            },
            second_child_request,
            parent_request,
        ),
    ];

    let err = heap
        .apply_collector_poll_minor_gc_copied_heap_field_writes(&writes)
        .expect_err("malformed object-copy request set rejects before mutation");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
            index: 2,
            source_address: second_child,
            existing_source_address: first_child,
            destination: shared_child_destination,
        }
    );
}

#[test]
fn collector_poll_minor_gc_object_generation_writes_reject_unknown_destination_without_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    // Since FV-2 no allocation path creates a permanent record, so the
    // destination fixture manufactures one: a worker record flipped to the
    // permanent-shared domain.
    let destination = heap
        .alloc_thunk(EvalThunk::new(IrId::new(90)))
        .expect("destination fixture thunk allocates");
    heap.set_allocation_domain_for_test(destination, HeapAllocationDomain::PermanentShared)
        .expect("record domain flips to permanent-shared");
    let first_source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("first source thunk allocates");
    let second_source = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("second source thunk allocates");
    let missing_destination = static_gc_address(0x3000_0000);
    let plan = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            gc_address(first_source),
            gc_address(destination),
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            gc_address(second_source),
            missing_destination,
            MinorGcSurvivorAction::PromoteToOld,
            HeapGeneration::Old,
            24,
            8,
        ),
    ])
    .expect("test generation write plan builds");

    assert_eq!(
        heap_generation(&heap, destination),
        HeapGeneration::Permanent
    );
    let err = heap
        .apply_collector_poll_minor_gc_object_generation_writes(&plan)
        .expect_err("unknown destination rejects generation writes");

    assert_eq!(
        err,
        EvalHeapError::UnknownCollectorPollObjectGenerationDestination {
            destination: missing_destination
        }
    );
    assert_eq!(
        heap_generation(&heap, destination),
        HeapGeneration::Permanent
    );
}

#[test]
fn collector_poll_minor_gc_object_generation_write_plan_rejects_generation_action_mismatch() {
    let source = static_gc_address(0x1000_0000);
    let destination = static_gc_address(0x2000_0000);
    let err = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            source,
            destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Old,
            24,
            8,
        ),
    ])
    .expect_err("generation/action mismatch is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteGenerationMismatch {
            source_address: source,
            destination,
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
            action: MinorGcSurvivorAction::CopyToNursery,
        }
    );
}

#[test]
fn collector_poll_minor_gc_object_generation_write_plan_rejects_destination_source_overlap() {
    let first_source = static_gc_address(0x1000_0000);
    let second_source = static_gc_address(0x2000_0000);
    let first_destination = static_gc_address(0x3000_0000);
    let second_destination = static_gc_address(0x4000_0000);

    let err = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            first_source,
            first_destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            second_source,
            first_source,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
    ])
    .expect_err("destination matching an earlier source is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
            index: 1,
            source_address: second_source,
            existing_source_address: first_source,
            destination: first_source,
        }
    );

    let err = AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            first_source,
            second_source,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            second_source,
            second_destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            24,
            8,
        ),
    ])
    .expect_err("earlier destination matching a later source is rejected");

    assert_eq!(
        err,
        EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
            index: 1,
            source_address: first_source,
            existing_source_address: second_source,
            destination: second_source,
        }
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
fn collector_poll_minor_gc_card_table_plan_adds_dirty_unremembered_survivor_edge() {
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

    let planned = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect("dirty unremembered edge enters the survivor frontier");

    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(planned.reference_slots().len(), 2);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::DirtyOldField {
            object: gc_address(permanent_parent),
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
        .expect("commit plan includes dirty old-field survivor");
    let child_destination = commit.commit_plan().object_copies().copies()[0].destination();

    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites().len(),
        1
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites()[0].slot(),
        1
    );
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[RememberedEdge::new(
            gc_address(permanent_parent),
            child_destination,
        )]
    );
    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("dirty old-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    assert_eq!(writeback_plan.writebacks()[0].slot(), 1);
    assert_eq!(
        writeback_plan.writebacks()[0].validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        writeback_plan.writebacks()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(writeback_plan.writebacks()[0].field_index(), 0);
    assert_eq!(
        writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: child_destination,
            generation: HeapGeneration::Young,
        }
    );
}

#[test]
fn collector_poll_minor_gc_card_table_plan_promotes_dirty_unremembered_survivor_edge() {
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

    let planned = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(0),
        )
        .expect("dirty unremembered edge enters the survivor frontier");

    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert_eq!(
        planned.plan().survivors()[0].action(),
        MinorGcSurvivorAction::PromoteToOld
    );
    assert_eq!(planned.reference_slots().len(), 2);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::DirtyOldField {
            object: gc_address(permanent_parent),
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );

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
        .expect("commit plan includes promoted dirty old-field survivor");
    let copy = &commit.commit_plan().object_copies().copies()[0];

    assert_eq!(copy.source(), gc_address(child));
    assert_eq!(copy.destination_generation(), HeapGeneration::Old);
    assert_eq!(commit.commit_plan().next_remembered_set().edges(), &[]);
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites().len(),
        1
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites()[0].slot(),
        1
    );
    assert_eq!(
        commit.commit_plan().reference_rewrites().rewrites()[0].replacement(),
        copy.relocated_value()
    );

    let writeback_plan = heap
        .collector_poll_minor_gc_heap_field_writeback_plan(&commit)
        .expect("promoted dirty old-field writeback plan derives");
    assert_eq!(writeback_plan.len(), 1);
    assert_eq!(writeback_plan.writebacks()[0].slot(), 1);
    assert_eq!(
        writeback_plan.writebacks()[0].validation_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        writeback_plan.writebacks()[0].writeback_object(),
        gc_address(permanent_parent)
    );
    assert_eq!(
        writeback_plan.writebacks()[0].replacement(),
        ResolvedValueGeneration::Heap {
            address: copy.destination(),
            generation: HeapGeneration::Old,
        }
    );
}

#[test]
fn collector_poll_minor_gc_card_table_plan_preserves_remembered_order_before_dirty_edges() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let remembered_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("remembered child thunk allocates");
    let dirty_child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(8)))
        .expect("dirty child thunk allocates");
    let permanent_parent = heap
        .alloc_list(NixList::new(vec![remembered_child, dirty_child]))
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
    let remembered_edge =
        RememberedEdge::new(gc_address(permanent_parent), gc_address(remembered_child));
    let mut remembered_set = RememberedSet::new();
    remembered_set
        .record(remembered_edge)
        .expect("remembered edge records");
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
        .expect("dirty edge appends after remembered frontier");

    assert_eq!(planned.plan().survivors().len(), 2);
    assert_eq!(
        planned.plan().survivors()[0].address(),
        gc_address(remembered_child)
    );
    assert_eq!(
        planned.plan().survivors()[1].address(),
        gc_address(dirty_child)
    );
    assert_eq!(planned.reference_slots().len(), 3);
    assert_eq!(
        planned.reference_slots()[1].source(),
        &AllocationCollectorPollReferenceSource::RememberedEdge {
            edge: remembered_edge,
            field_index: 0,
            source: HeapEdgeSource::ListElement { index: 0 },
        }
    );
    assert_eq!(
        planned.reference_slots()[1].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(remembered_child),
            generation: HeapGeneration::Young,
        }
    );
    assert_eq!(
        planned.reference_slots()[2].source(),
        &AllocationCollectorPollReferenceSource::DirtyOldField {
            object: gc_address(permanent_parent),
            field_index: 1,
            source: HeapEdgeSource::ListElement { index: 1 },
        }
    );
    assert_eq!(
        planned.reference_slots()[2].value(),
        ResolvedValueGeneration::Heap {
            address: gc_address(dirty_child),
            generation: HeapGeneration::Young,
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
    let commit = planned
        .commit_plan(&destinations)
        .expect("commit plan preserves frontier order");
    let remembered_destination = commit.commit_plan().object_copies().copies()[0].destination();
    let dirty_destination = commit.commit_plan().object_copies().copies()[1].destination();
    let rewrites = commit.commit_plan().reference_rewrites().rewrites();

    assert_eq!(rewrites.len(), 2);
    assert_eq!(rewrites[0].slot(), 1);
    assert_eq!(rewrites[1].slot(), 2);
    assert_eq!(
        commit.commit_plan().next_remembered_set().edges(),
        &[
            RememberedEdge::new(gc_address(permanent_parent), remembered_destination),
            RememberedEdge::new(gc_address(permanent_parent), dirty_destination),
        ]
    );
}

#[test]
fn collector_poll_minor_gc_card_table_plan_rejects_clean_unremembered_source_card() {
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
    let card_table = GcCardTable::default();

    let error = heap
        .plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set.snapshot(),
            card_table.snapshot(),
            remembered_set.epoch(),
            MinorGcPromotionPolicy::new(2),
        )
        .expect_err("clean unremembered source card is rejected");

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
    assert_eq!(planned.reference_slots().len(), 2);

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

    let mut no_value_slots = Vec::new();
    assert_eq!(
        root_writeback_plan
            .apply_to_value_slots(&mut no_value_slots)
            .expect_err("short typed root writeback buffer rejects"),
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

    let mut later_wrong_source_value_slots = [
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            first,
        ),
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 2 },
            second,
        ),
    ];
    let unchanged_later_wrong_source_value_slots = later_wrong_source_value_slots.clone();
    assert_eq!(
        root_writeback_plan
            .apply_to_value_slots(&mut later_wrong_source_value_slots)
            .expect_err("later wrong typed root source rejects"),
        EvalHeapError::CollectorPollRootReferenceSourceMismatch {
            index: 1,
            expected: EvalRootSource::ValueStack { slot: 1 },
            actual: EvalRootSource::ValueStack { slot: 2 },
        }
    );
    assert_eq!(
        later_wrong_source_value_slots,
        unchanged_later_wrong_source_value_slots
    );

    let mut stale_value_slots = [
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 0 },
            first,
        ),
        AllocationCollectorPollRootValueWritebackSlot::new(
            EvalRootSource::ValueStack { slot: 1 },
            first,
        ),
    ];
    let unchanged_stale_value_slots = stale_value_slots.clone();
    let expected_second_value = root_writeback_plan.writebacks()[1]
        .expected_value()
        .expect("second expected value rebuilds");
    assert_eq!(
        root_writeback_plan
            .apply_to_value_slots(&mut stale_value_slots)
            .expect_err("stale typed second root rejects"),
        EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
            index: 1,
            expected_tag: expected_second_value.tag(),
            expected_payload: expected_second_value.payload_bits(),
            actual_tag: first.tag(),
            actual_payload: first.payload_bits(),
        }
    );
    assert_eq!(stale_value_slots, unchanged_stale_value_slots);

    let mut value_slots = root_writeback_plan
        .writebacks()
        .iter()
        .map(|writeback| {
            AllocationCollectorPollRootValueWritebackSlot::new(
                writeback.source().clone(),
                writeback
                    .expected_value()
                    .expect("expected typed value rebuilds"),
            )
        })
        .collect::<Vec<_>>();
    let value_report = root_writeback_plan
        .apply_to_value_slots(&mut value_slots)
        .expect("typed root writebacks apply");
    assert_eq!(value_report.writebacks(), 2);
    for (slot, writeback) in value_slots.iter().zip(root_writeback_plan.writebacks()) {
        assert!(
            slot.value().raw_eq(
                writeback
                    .replacement_value()
                    .expect("replacement typed value rebuilds")
            )
        );
    }
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
    for writeback in root_writeback_plan.writebacks() {
        assert_eq!(writeback.expected_tag(), ValueTag::Thunk);
        assert_eq!(writeback.replacement_tag(), ValueTag::Thunk);
        let ResolvedValueGeneration::Heap {
            address: expected_address,
            ..
        } = writeback.expected()
        else {
            panic!("expected root writeback value should be heap-backed");
        };
        let ResolvedValueGeneration::Heap {
            address: replacement_address,
            ..
        } = writeback.replacement()
        else {
            panic!("replacement root writeback value should be heap-backed");
        };
        let expected_value = writeback.expected_value().expect("expected value rebuilds");
        let replacement_value = writeback
            .replacement_value()
            .expect("replacement value rebuilds");
        assert!(
            expected_value.raw_eq(
                Value::heap(
                    ValueTag::Thunk,
                    NonNull::new(expected_address.address_bits() as *mut HeapObject)
                        .expect("expected address is non-null"),
                )
                .expect("expected raw value rebuilds")
            )
        );
        assert!(
            replacement_value.raw_eq(
                Value::heap(
                    ValueTag::Thunk,
                    NonNull::new(replacement_address.address_bits() as *mut HeapObject)
                        .expect("replacement address is non-null"),
                )
                .expect("replacement raw value rebuilds")
            )
        );
    }

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
    // A permanent record-backed value with no heap field pointing at the
    // child (strings are flat since FV-1, so a list stands in).
    let root = heap
        .alloc_list(NixList::new(vec![Value::int(3)]))
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
fn collector_poll_minor_gc_plan_uses_remembered_old_edge() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    heap.set_gc_stress_policy(GcStressPolicy::every_safepoint());
    let child = heap
        .alloc_thunk(EvalThunk::new(IrId::new(7)))
        .expect("child thunk allocates");
    // Lists are flat and permanent since FV-1; a permanent source is the
    // remaining non-young remembered-edge source shape a list can take.
    let root = heap
        .alloc_list(NixList::new(vec![child]))
        .expect("permanent flat list allocates");
    let poll = heap
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("worker allocation requests a collector poll");
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
        .expect("old remembered edge is accepted");

    assert_eq!(planned.plan().survivors().len(), 1);
    assert_eq!(planned.plan().survivors()[0].address(), gc_address(child));
    assert!(planned.reference_slots().iter().any(|slot| {
        slot.source()
            == &AllocationCollectorPollReferenceSource::RememberedEdge {
                edge: RememberedEdge::new(gc_address(root), gc_address(child)),
                field_index: 0,
                source: HeapEdgeSource::ListElement { index: 0 },
            }
    }));
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
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
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
fn precise_root_scan_reports_parallel_thunk_payload_value() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let captured = heap
        .alloc_string(NixString::from_bytes(b"captured".to_vec()))
        .expect("captured string allocates");
    let payload = heap
        .alloc_string(NixString::from_bytes(b"parallel".to_vec()))
        .expect("parallel payload string allocates");
    let frame = EvalFrame::new(1).expect("frame allocates");
    frame.set(0, captured).expect("slot writes");
    let env = EvalEnv::capture(&[frame]).expect("env captures");
    let thunk = heap
        .alloc_thunk(
            EvalThunk::with_env(EvalModuleId::ROOT, IrId::new(9), env)
                .with_parallel_payload_cell(tree_walk_error(99), None),
        )
        .expect("thunk allocates");
    let thunk_record = heap.clone_thunk(thunk).expect("thunk handle clones");
    publish_parallel_payload(&thunk_record, payload);

    let mut roots = EvalRootSet::new();
    assert!(
        roots
            .try_push_force_continuation(0, thunk)
            .expect("thunk root records")
    );
    let scan = heap.scan_precise_roots(&roots).expect("scan succeeds");

    let edges = object_for(&scan, thunk).edges();
    assert_eq!(edges.len(), 2);
    assert_eq!(
        edges[0].source(),
        &HeapEdgeSource::CapturedEnv {
            owner: CapturedRootOwner::Thunk,
            frame: 0,
            slot: 0,
        }
    );
    assert!(edges[0].value().raw_eq(captured));
    assert_eq!(
        edges[1].source(),
        &HeapEdgeSource::ThunkParallelPayloadValue
    );
    assert!(edges[1].value().raw_eq(payload));
    assert!(object_for(&scan, payload).edges().is_empty());
    assert_eq!(thunk_record.cell().state(), Ok(ThunkState::Suspended));
}

#[test]
fn precise_root_scan_reports_lambda_captured_scopes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(1024).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
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
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
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
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
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
            Span::new(3, 4),
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
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
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
