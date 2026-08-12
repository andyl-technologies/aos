//! Thunk and strictness tests for tree-walk attr evaluation.

// Some tests here are gated off under the Candidate-C variant (non-reservation
// heap geometry / fake pointers), leaving shared helpers unused on that carrier
// only; the baseline still uses them.
#![cfg_attr(feature = "candidate_c_value", allow(dead_code))]

use super::*;
mod part_1;
mod part_2;
mod part_3;
mod part_4;
use crate::attrs::repr::AttrSetReprKind;
use crate::attrs::telemetry::{HistogramBucket, ShapeMultiplicityBucket};
use crate::eval::heap::EvalThunkForceStorageMode;
use crate::heap::{GcHeapAddress, HeapGeneration};
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};

fn gc_address(value: Value) -> GcHeapAddress {
    GcHeapAddress::new(value.as_heap_ptr().expect("value is heap-backed").as_ptr() as usize)
        .expect("heap pointer is a valid GC address")
}

fn heap_record_forwarding_slot_count(heap: &EvalHeap, values: &[Value]) -> usize {
    values
        .iter()
        .filter(|value| {
            heap.minor_gc_forwarding_value_at(gc_address(**value))
                .expect("forwarding slot lookup succeeds")
                .is_some()
        })
        .count()
}

fn first_thunk_alloc_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .position(|node| node.kind == IrKind::ThunkAlloc)
        .map(|index| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        .expect("test IR contains a thunk allocation")
}

fn first_inherit_select_thunk_alloc_id(ir: &Ir) -> IrId {
    ir.arena
        .nodes()
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            let IrData::Node(body) = node.data else {
                return None;
            };
            let body = ir.arena.node(body)?;
            (node.kind == IrKind::ThunkAlloc && body.kind == IrKind::Select)
                .then(|| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        })
        .expect("test IR contains an inherited select thunk")
}

fn mark_all_thunk_allocs_strict(ir: &mut Ir) {
    let thunk_ids: Vec<IrId> = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (node.kind == IrKind::ThunkAlloc)
                .then(|| IrId::new(u32::try_from(index).expect("test IR node id fits in u32")))
        })
        .collect();
    for id in thunk_ids {
        *ir.facts.get_mut(id).expect("thunk fact exists") = crate::compile::ExprFacts {
            strictness: crate::compile::Strictness::DemandedBeforeEffect,
            cardinality: crate::compile::Cardinality::Many,
            escape: crate::compile::Escape::Escapes,
        };
    }
}
