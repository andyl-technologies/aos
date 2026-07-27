//! Allocation-aware primitives used by precise heap graph scans.

use std::collections::{HashSet, VecDeque};
use std::ptr::NonNull;

use super::{EvalHeapError, HeapEdge, HeapEdgeSource, HeapObjectScan};
use crate::value::{HeapObject, Value, ValueTag};

const WORKLIST_TABLE: &str = "worklist";
const VISITED_TABLE: &str = "visited";
const OBJECTS_TABLE: &str = "objects";
const EDGES_TABLE: &str = "edges";

/// Representation-neutral identity used to deduplicate one precise scan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum PreciseScanIdentity {
    /// A native address owned by an ordinary evaluator store.
    Native(usize),
    /// A canonical Candidate-C word owned by a registry-free packed lane.
    Packed(u64),
}

pub(super) fn push_heap_edge(
    edges: &mut Vec<HeapEdge>,
    source: HeapEdgeSource,
    value: Value,
) -> Result<(), EvalHeapError> {
    if !is_scannable_eval_heap_value(value) {
        return Ok(());
    }
    let entries = edges
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow { table: EDGES_TABLE })?;
    edges
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: EDGES_TABLE,
            entries,
        })?;
    edges.push(HeapEdge::new(source, value));
    Ok(())
}

pub(super) fn push_worklist(
    worklist: &mut VecDeque<Value>,
    value: Value,
) -> Result<(), EvalHeapError> {
    let entries = worklist
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: WORKLIST_TABLE,
        })?;
    worklist
        .try_reserve(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: WORKLIST_TABLE,
            entries,
        })?;
    worklist.push_back(value);
    Ok(())
}

pub(super) fn push_visited(
    visited: &mut HashSet<PreciseScanIdentity>,
    identity: PreciseScanIdentity,
) -> Result<bool, EvalHeapError> {
    if visited.contains(&identity) {
        return Ok(false);
    }
    let entries = visited
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: VISITED_TABLE,
        })?;
    visited
        .try_reserve(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: VISITED_TABLE,
            entries,
        })?;
    Ok(visited.insert(identity))
}

pub(super) fn push_object_scan(
    objects: &mut Vec<HeapObjectScan>,
    object: HeapObjectScan,
) -> Result<(), EvalHeapError> {
    let entries = objects
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: OBJECTS_TABLE,
        })?;
    objects
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: OBJECTS_TABLE,
            entries,
        })?;
    objects.push(object);
    Ok(())
}

pub(super) fn is_scannable_eval_heap_value(value: Value) -> bool {
    if matches!(
        value.tag(),
        ValueTag::String
            | ValueTag::Path
            | ValueTag::List
            | ValueTag::Attrs
            | ValueTag::Lambda
            | ValueTag::Primop
            | ValueTag::Thunk
    ) {
        return true;
    }
    #[cfg(feature = "candidate_c_value")]
    {
        matches!(
            value.word().kind(),
            crate::value::compressed::CompressedValueKind::BoxedInt
                | crate::value::compressed::CompressedValueKind::BoxedFloat
        )
    }
    #[cfg(not(feature = "candidate_c_value"))]
    {
        false
    }
}

pub(super) fn heap_ptr(value: Value) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
    let tag = value.tag();
    let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
    Ok((tag, ptr))
}
