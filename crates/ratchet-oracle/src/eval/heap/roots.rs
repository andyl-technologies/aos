//! Precise root and field scanning for the tree-walk evaluator heap.
//!
//! The moving collector needs exact `Value` roots, not a conservative stack
//! scan. This module records explicit mutator roots and scans typed heap records
//! through their evaluator-side layouts: lists expose element slots, attrsets
//! expose shape-qualified bindings, closures expose captured environments,
//! primops expose captured lazy arguments, and thunks expose either suspended
//! work captures or their forced result depending on the thunk state.
//!
//! Scans return copied [`Value`] handles; commit plans can validate and rewrite
//! explicitly bound caller-owned slots. The production evaluator can build
//! safepoint root sets for its explicit tree-walk state, but arbitrary Rust
//! locals still need explicit registration before they are collector-visible.

use std::collections::{HashSet, VecDeque};
use std::ptr::NonNull;
use std::sync::Arc;

use super::environment_writeback::{
    EnvironmentWritebackStage, validate_captured_environment_source,
};
use super::root_scan::{
    heap_ptr, is_scannable_eval_heap_value, push_heap_edge, push_object_scan, push_visited,
    push_worklist,
};
use super::structural_writeback::StructuralWritebackStage;
use super::*;
use crate::eval::EvalWithScope;
use crate::eval::thunk::{ForceError, ThunkResolveBarrier, ThunkState};
use crate::eval::thunk_payload::{ParallelThunkPayloadError, TreeWalkParallelThunkCell};
use crate::heap::{
    GcCardTable, GcCardTableSnapshot, GcHeapAddress, GenerationalGcError, GenerationalGcTier,
    HeapGeneration, MinorGcCommitBuffers, MinorGcCommitPlan, MinorGcCommitReport,
    MinorGcDestinationAllocationPlan, MinorGcDestinationBases, MinorGcDestinationPlacementPlan,
    MinorGcForwardingPointerPlan, MinorGcForwardingSlot, MinorGcObjectByteCopyBuffer,
    MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcOldFieldRescanPlan, MinorGcOldObjectFields,
    MinorGcOwnedCommitBuffers, MinorGcOwnedDestinationStorage, MinorGcPlan, MinorGcPromotionPolicy,
    MinorGcReferenceRewrite, MinorGcReferenceRewritePlan, MinorGcRelocationDestination,
    MinorGcRelocationDestinationPlan, MinorGcRelocationPlan, MinorGcRememberedSetRefreshPlan,
    MinorGcSourceObjectBytes, MinorGcSurvivorAction, NurseryObjectAge, NurseryObjectFields,
    NurseryObjectLayout, RememberedEdge, RememberedSet, RememberedSetEpoch, RememberedSetSnapshot,
    ResolvedValueGeneration, ThunkResolveWrite, ThunkResolveWriteBarrier,
    record_thunk_resolve_write_barrier, record_thunk_resolve_write_barrier_with_card_table,
};
use crate::runtime::alloc::{AllocationCollectorPoll, AllocationSafepointState};
use thiserror::Error;

mod stack_map_writeback;

const ROOTS_TABLE: &str = "roots";
const WORKLIST_TABLE: &str = "worklist";
const MINOR_GC_ROOTS_TABLE: &str = "minor-GC roots";
const MINOR_GC_NURSERY_OBJECTS_TABLE: &str = "minor-GC nursery objects";
const MINOR_GC_NURSERY_FIELDS_TABLE: &str = "minor-GC nursery fields";
const MINOR_GC_NURSERY_FIELD_VALUES_TABLE: &str = "minor-GC nursery field values";
const MINOR_GC_OLD_FIELDS_TABLE: &str = "minor-GC old fields";
const MINOR_GC_OLD_FIELD_VALUES_TABLE: &str = "minor-GC old field values";
const MINOR_GC_NURSERY_LAYOUTS_TABLE: &str = "minor-GC nursery layouts";
const MINOR_GC_REFERENCE_SLOTS_TABLE: &str = "minor-GC reference slots";
const MINOR_GC_OBJECT_BYTE_COPY_REQUESTS_TABLE: &str = "minor-GC object byte-copy requests";
const MINOR_GC_OBJECT_BODY_WRITES_TABLE: &str = "minor-GC object body writes";
const MINOR_GC_OBJECT_GENERATION_WRITES_TABLE: &str = "minor-GC object generation writes";
const MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE: &str = "minor-GC forwarding slot buffer";
const MINOR_GC_FORWARDING_VALUES_TABLE: &str = "minor-GC forwarding values";
const MINOR_GC_REFERENCE_BUFFER_TABLE: &str = "minor-GC reference buffer";
const MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE: &str = "minor-GC heap field writebacks";
const MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE: &str = "minor-GC copied heap field writes";
pub(super) const MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE: &str =
    "minor-GC direct heap field writes";
const MINOR_GC_ROOT_WRITEBACKS_TABLE: &str = "minor-GC root writebacks";
const MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE: &str =
    "minor-GC destination record reservations";

mod commit_plan_types;
mod edge_scan_ops;
mod field_write_helpers;
mod forwarding_ops;
mod heap_field_write_ops;
mod heap_field_writeback_types;
mod object_write_ops;
mod object_write_types;
mod poll_plan_types;
mod poll_scan_ops;
mod poll_snapshot_ops;
mod root_types;
mod root_writeback_types;
mod staged_write_ops;

// Glob re-exports: each child's items keep resolving at the pre-split
// `heap::roots::*` paths (heap/mod.rs's existing `pub use roots::{...}` and
// `pub(crate) use roots::{...}` lists), and sibling children resolve one
// another's `pub(super)` items through `use super::*`.
pub use commit_plan_types::*;
pub use heap_field_writeback_types::*;
pub use object_write_types::*;
pub use poll_plan_types::*;
pub use root_types::*;
pub use root_writeback_types::*;

// Path-explicit re-exports for heap-module consumers that import through
// `roots::{...}` (the writeback stagers): these items are heap-internal, not
// public API, so the glob re-exports above cannot carry them.
pub(in crate::eval::heap) use object_write_types::{
    CollectorPollCopiedHeapFieldWrite, CollectorPollDirectHeapFieldWrite,
};

// Private glob imports: the moved `pub(super)` items (formerly private to
// this file) re-enter this module's namespace so every sibling child keeps
// resolving them through `use super::*`.
#[allow(unused_imports)]
use commit_plan_types::*;
#[allow(unused_imports)]
use field_write_helpers::*;
#[allow(unused_imports)]
use heap_field_writeback_types::*;
#[allow(unused_imports)]
use object_write_types::*;
#[allow(unused_imports)]
use poll_plan_types::*;
#[allow(unused_imports)]
use poll_snapshot_ops::*;
#[allow(unused_imports)]
use root_types::*;
#[allow(unused_imports)]
use root_writeback_types::*;
