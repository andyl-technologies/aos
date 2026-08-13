//! Unit tests for the typed evaluator heap registry.

// Some tests here are gated off under the Candidate-C variant (non-reservation
// heap geometry / fake pointers), leaving shared helpers unused on that carrier
// only; the baseline still uses them.
#![cfg_attr(feature = "candidate_c_value", allow(dead_code))]

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

mod environment_writeback;
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

fn object_for(scan: &PreciseHeapScan, value: Value) -> &HeapObjectScan {
    scan.objects()
        .iter()
        .find(|object| object.value().raw_eq(value))
        .expect("object is scanned")
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

mod part_1;
mod part_10;
mod part_11;
mod part_12;
mod part_13;
mod part_14;
mod part_15;
mod part_16;
mod part_2;
mod part_3;
mod part_4;
mod part_5;
mod part_6;
mod part_7;
mod part_8;
mod part_9;
