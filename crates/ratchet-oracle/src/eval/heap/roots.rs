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

use super::*;
use super::environment_writeback::{
    EnvironmentWritebackStage, validate_captured_environment_source,
};
use super::root_scan::{
    heap_ptr, is_scannable_eval_heap_value, push_heap_edge, push_object_scan, push_visited,
    push_worklist,
};
use super::structural_writeback::StructuralWritebackStage;
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

/// A write-barrier adapter for publishing a forced thunk result.
///
/// This adapter records edges from the source thunk captured at construction
/// time. Callers must pass it only to the [`crate::eval::thunk::ForceGuard`]
/// that owns the same source thunk; the guard API does not re-check that
/// pairing before publication.
#[derive(Debug)]
pub struct EvalHeapThunkResolveBarrier<'a> {
    heap: &'a EvalHeap,
    tier: GenerationalGcTier,
    source: GcHeapAddress,
    source_generation: HeapGeneration,
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
    last_action: Option<ThunkResolveWriteBarrier>,
}

impl EvalHeapThunkResolveBarrier<'_> {
    /// Returns the generational tier this barrier evaluates against.
    pub const fn tier(&self) -> GenerationalGcTier {
        self.tier
    }

    /// Returns the thunk object whose cached-result slot is being written.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the source thunk's current generation.
    pub const fn source_generation(&self) -> HeapGeneration {
        self.source_generation
    }

    /// Returns the most recent lower-level barrier action recorded by this adapter.
    pub const fn last_action(&self) -> Option<ThunkResolveWriteBarrier> {
        self.last_action
    }

    /// Returns the caller-owned remembered set borrowed by this barrier adapter.
    pub fn remembered_set(&self) -> &RememberedSet {
        self.remembered_set
    }

    /// Returns the caller-owned card table borrowed by this barrier adapter, if any.
    pub fn card_table(&self) -> Option<&GcCardTable> {
        self.card_table.as_deref()
    }

    /// Records the write barrier for publishing `value` into the source thunk.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `value` is heap-backed but does not belong to
    /// this heap, if the value's heap tag disagrees with the side table, or if the
    /// lower-level remembered set or attached card table cannot record a required
    /// old-to-young edge/card mark.
    pub fn record(&mut self, value: Value) -> Result<ThunkResolveWriteBarrier, EvalHeapError> {
        let value = self
            .heap
            .resolved_generation_for_thunk_resolve_value(value)?;
        let write = ThunkResolveWrite::new(self.source, self.source_generation, value);
        let action = match self.card_table.as_deref_mut() {
            Some(card_table) => record_thunk_resolve_write_barrier_with_card_table(
                self.tier,
                write,
                self.remembered_set,
                card_table,
            ),
            None => record_thunk_resolve_write_barrier(self.tier, write, self.remembered_set),
        }
        .map_err(EvalHeapError::GenerationalGc)?;
        self.last_action = Some(action);
        Ok(action)
    }
}

impl ThunkResolveBarrier for EvalHeapThunkResolveBarrier<'_> {
    fn before_publish_forced(&mut self, value: Value) -> Result<(), ForceError> {
        self.record(value)
            .map(|_| ())
            .map_err(|_| ForceError::WriteBarrierRejected {
                reason: "evaluator heap thunk resolve write barrier failed",
            })
    }
}

/// A precise root slot and the heap value stored in it.
#[derive(Clone, Debug)]
pub struct EvalRoot {
    source: EvalRootSource,
    value: Value,
}

impl EvalRoot {
    const fn new(source: EvalRootSource, value: Value) -> Self {
        Self { source, value }
    }

    /// Returns where the root was found.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the heap value stored in the root slot.
    pub const fn value(&self) -> Value {
        self.value
    }
}

impl PartialEq for EvalRoot {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.value.raw_eq(other.value)
    }
}

impl Eq for EvalRoot {}

/// The mutator location that made a value a root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvalRootSource {
    /// A value stack slot in the tree-walk evaluator.
    ValueStack {
        /// The slot index in the active value stack.
        slot: usize,
    },
    /// A slot in the tree-walk evaluator's active lexical frame stack.
    TreeWalkFrame {
        /// The active frame index, ordered outermost to innermost.
        frame: usize,
        /// The slot index inside the frame.
        slot: usize,
    },
    /// A copied value in the active flat lexical capture base.
    TreeWalkFlatCapture {
        /// The capture-plan index in canonical coordinate order.
        index: usize,
    },
    /// The flat closure object owning the active inline capture base.
    TreeWalkFlatCaptureOwner,
    /// A slot in a tree-walk lexical frame stack suspended by nested
    /// evaluation.
    SuspendedTreeWalkFrame {
        /// The suspended evaluator context depth, with zero nearest the active
        /// evaluation.
        depth: usize,
        /// The suspended frame index, ordered outermost to innermost.
        frame: usize,
        /// The slot index inside the suspended frame.
        slot: usize,
    },
    /// A copied value in a suspended flat lexical capture base.
    SuspendedTreeWalkFlatCapture {
        /// The suspended evaluator context depth, with zero nearest the active
        /// evaluation.
        depth: usize,
        /// The capture-plan index in canonical coordinate order.
        index: usize,
    },
    /// The flat closure object owning a suspended inline capture base.
    SuspendedTreeWalkFlatCaptureOwner {
        /// The suspended evaluator context depth, with zero nearest active.
        depth: usize,
    },
    /// An active dynamic `with` scope in the tree-walk evaluator.
    WithScope {
        /// The active with-scope depth, ordered outermost to innermost.
        depth: usize,
    },
    /// A dynamic `with` scope suspended by nested tree-walk evaluation.
    SuspendedWithScope {
        /// The suspended evaluator context depth, with zero nearest the active
        /// evaluation.
        depth: usize,
        /// The suspended with-scope depth, ordered outermost to innermost.
        scope_depth: usize,
    },
    /// An active scoped-import global in the tree-walk evaluator.
    ScopedGlobal {
        /// The active scoped-global depth, ordered outermost to innermost.
        depth: usize,
    },
    /// A scoped-import global suspended by nested tree-walk evaluation.
    SuspendedScopedGlobal {
        /// The suspended evaluator context depth, with zero nearest the active
        /// evaluation.
        depth: usize,
        /// The suspended scoped-global depth, ordered outermost to innermost.
        scope_depth: usize,
    },
    /// An in-flight force continuation root.
    ForceContinuation {
        /// The continuation depth, with zero nearest the active force.
        depth: usize,
    },
    /// A primop argument slot spilled at a safepoint.
    PrimopArgument {
        /// The argument index in application order.
        index: usize,
    },
    /// A first-class primop argument active in the tree-walk evaluator.
    TreeWalkPrimopArgument {
        /// The active primop-call depth, with zero nearest the active call.
        call_depth: usize,
        /// The argument index in application order for that call.
        index: usize,
    },
    /// A permanent hash-cons table entry, sorted by structural hash.
    Interned {
        /// The table that owns the permanent root.
        table: InternedRootTable,
        /// The stable table-local index after sorting committed entries.
        index: usize,
    },
    /// A heap value retained by the in-process import cache.
    ImportCache {
        /// The stable ready-entry index after sorting cache paths.
        index: usize,
    },
    /// A compiled-frame stack-map entry.
    StackMap {
        /// The compiled frame identifier supplied by the JIT tier.
        frame: u64,
        /// The safepoint identifier within the compiled frame.
        safepoint: u32,
        /// The stack-map slot that contains the value.
        slot: StackMapSlot,
    },
}

/// A permanent hash-cons table that owns root values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternedRootTable {
    /// Interned string values.
    String,
    /// Interned path values.
    Path,
    /// Interned list values.
    List,
    /// Interned attrset values.
    Attrs,
}

/// A compiled-frame stack-map slot that contains a live `Value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackMapSlot {
    /// A stack slot addressed relative to the frame base.
    Stack {
        /// The byte offset from the frame base.
        offset: i32,
    },
    /// A machine register identified by its DWARF register number.
    Register {
        /// The DWARF register number for the live value.
        dwarf_reg: u16,
    },
}

/// A collection of explicit roots for one safepoint scan.
#[derive(Clone, Debug, Default)]
pub struct EvalRootSet {
    roots: Vec<EvalRoot>,
}

impl EvalRootSet {
    /// Creates an empty root set.
    pub const fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Returns the roots in insertion order.
    pub fn roots(&self) -> &[EvalRoot] {
        &self.roots
    }

    /// Returns the number of heap roots recorded.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Returns whether the set contains no heap roots.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Records a tree-walk value stack slot when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_value_stack(
        &mut self,
        slot: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::ValueStack { slot }, value)
    }

    /// Records an active tree-walk lexical frame slot when it contains a heap
    /// value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_tree_walk_frame(
        &mut self,
        frame: usize,
        slot: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::TreeWalkFrame { frame, slot }, value)
    }

    /// Records a copied value in the active flat lexical capture base.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_tree_walk_flat_capture(
        &mut self,
        index: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::TreeWalkFlatCapture { index }, value)
    }

    /// Records the flat closure owning the active inline capture base.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set cannot grow.
    pub fn try_push_tree_walk_flat_capture_owner(
        &mut self,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::TreeWalkFlatCaptureOwner, value)
    }

    /// Records a suspended tree-walk lexical frame slot when it contains a heap
    /// value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_suspended_tree_walk_frame(
        &mut self,
        depth: usize,
        frame: usize,
        slot: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::SuspendedTreeWalkFrame { depth, frame, slot },
            value,
        )
    }

    /// Records a copied value in a suspended flat lexical capture base.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_suspended_tree_walk_flat_capture(
        &mut self,
        depth: usize,
        index: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::SuspendedTreeWalkFlatCapture { depth, index },
            value,
        )
    }

    /// Records the flat closure owning a suspended inline capture base.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set cannot grow.
    pub fn try_push_suspended_tree_walk_flat_capture_owner(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::SuspendedTreeWalkFlatCaptureOwner { depth },
            value,
        )
    }

    /// Records an active dynamic `with` scope when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_with_scope(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::WithScope { depth }, value)
    }

    /// Records a suspended dynamic `with` scope when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_suspended_with_scope(
        &mut self,
        depth: usize,
        scope_depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::SuspendedWithScope { depth, scope_depth },
            value,
        )
    }

    /// Records an active scoped-import global when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_scoped_global(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::ScopedGlobal { depth }, value)
    }

    /// Records a suspended scoped-import global when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_suspended_scoped_global(
        &mut self,
        depth: usize,
        scope_depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::SuspendedScopedGlobal { depth, scope_depth },
            value,
        )
    }

    /// Records an in-flight force continuation when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_force_continuation(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::ForceContinuation { depth }, value)
    }

    /// Records a primop argument root when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_primop_argument(
        &mut self,
        index: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::PrimopArgument { index }, value)
    }

    /// Records an active tree-walk first-class primop argument when it contains
    /// a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_tree_walk_primop_argument(
        &mut self,
        call_depth: usize,
        index: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index },
            value,
        )
    }

    /// Records a permanent hash-cons table root when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_interned(
        &mut self,
        table: InternedRootTable,
        index: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::Interned { table, index }, value)
    }

    /// Records an import-cache root when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_import_cache(
        &mut self,
        index: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::ImportCache { index }, value)
    }

    /// Records a compiled-frame stack-map root when it contains a heap value.
    ///
    /// Returns `true` when the value was recorded, and `false` when the value is
    /// inline and therefore not a GC root.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_push_stack_map(
        &mut self,
        frame: u64,
        safepoint: u32,
        slot: StackMapSlot,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::StackMap {
                frame,
                safepoint,
                slot,
            },
            value,
        )
    }

    /// Appends roots from another root set, preserving insertion order.
    ///
    /// Inline values are filtered again, so this method is safe to use with
    /// root sets built by another component that may later gain broader source
    /// labels.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn try_extend(&mut self, other: &EvalRootSet) -> Result<(), EvalRootSetError> {
        for root in other.roots() {
            self.try_push_heap_root(root.source().clone(), root.value())?;
        }
        Ok(())
    }

    fn try_push_heap_root(
        &mut self,
        source: EvalRootSource,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        if !is_scannable_eval_heap_value(value) {
            return Ok(false);
        }
        let roots = self
            .roots
            .len()
            .checked_add(1)
            .ok_or(EvalRootSetError::LengthOverflow)?;
        self.roots
            .try_reserve_exact(1)
            .map_err(|_| EvalRootSetError::AllocationFailed { roots })?;
        self.roots.push(EvalRoot::new(source, value));
        Ok(true)
    }
}

/// A root-set construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalRootSetError {
    /// The root count overflowed.
    #[error("root set length overflow")]
    LengthOverflow,
    /// The root vector could not reserve storage.
    #[error("failed to reserve {roots} roots")]
    AllocationFailed {
        /// The requested root capacity.
        roots: usize,
    },
}

/// The kind of heap object that owns captured environment slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturedRootOwner {
    /// A user lambda closure.
    Lambda,
    /// A suspended thunk.
    Thunk,
}

/// A precise object field that contains a heap value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeapEdgeSource {
    /// A list element.
    ListElement {
        /// The list element index.
        index: usize,
    },
    /// An attrset binding value.
    AttrBinding {
        /// The attrset shape id.
        shape: u32,
        /// The symbol-sorted attr slot.
        slot: usize,
        /// The binding key.
        key: Symbol,
    },
    /// A captured lexical environment slot.
    CapturedEnv {
        /// The heap object kind that owns the capture.
        owner: CapturedRootOwner,
        /// The captured frame index, ordered outermost to innermost.
        frame: usize,
        /// The slot index inside the captured frame.
        slot: usize,
    },
    /// A copied value in a flat lexical capture plan.
    CapturedFlatEnv {
        /// The heap object kind that owns the capture.
        owner: CapturedRootOwner,
        /// The capture-plan index in canonical coordinate order.
        index: usize,
    },
    /// The flat closure object that owns an inherited inline capture.
    CapturedFlatEnvOwner {
        /// The heap object kind that retains the owning closure.
        owner: CapturedRootOwner,
    },
    /// A captured dynamic `with` scope.
    CapturedWithScope {
        /// The heap object kind that owns the capture.
        owner: CapturedRootOwner,
        /// The captured with-scope index.
        index: usize,
    },
    /// A captured scoped-import global scope.
    CapturedScopedGlobal {
        /// The heap object kind that owns the capture.
        owner: CapturedRootOwner,
        /// The captured scoped-global index.
        index: usize,
    },
    /// A captured builtin argument.
    PrimopArgument {
        /// The argument index in application order.
        index: usize,
    },
    /// The forced function value captured by an application thunk.
    ThunkApplyFunction,
    /// The lazy argument value captured by an application thunk.
    ThunkApplyArgument,
    /// The forced function value captured by a two-argument application thunk.
    ThunkApply2Function,
    /// The first lazy argument captured by a two-argument application thunk.
    ThunkApply2FirstArgument,
    /// The second lazy argument captured by a two-argument application thunk.
    ThunkApply2SecondArgument,
    /// The receiver value captured by a static selection thunk.
    ThunkSelectReceiver,
    /// The cached WHNF result of a forced thunk.
    ThunkCachedResult,
    /// The successful terminal value stored in a parallel payload cell.
    ThunkParallelPayloadValue,
}

/// A precise object field edge.
#[derive(Clone, Debug)]
pub struct HeapEdge {
    source: HeapEdgeSource,
    value: Value,
}

impl HeapEdge {
    pub(super) fn new(source: HeapEdgeSource, value: Value) -> Self {
        Self { source, value }
    }

    /// Returns the object field that owns the edge.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the heap value stored in the field.
    pub const fn value(&self) -> Value {
        self.value
    }
}

impl PartialEq for HeapEdge {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.value.raw_eq(other.value)
    }
}

impl Eq for HeapEdge {}

/// A scanned heap object and its precise outgoing heap edges.
#[derive(Clone, Debug)]
pub struct HeapObjectScan {
    value: Value,
    edges: Vec<HeapEdge>,
}

impl HeapObjectScan {
    fn new(value: Value, edges: Vec<HeapEdge>) -> Self {
        Self { value, edges }
    }

    /// Returns the heap value that names this object.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the runtime tag for this object.
    pub const fn tag(&self) -> ValueTag {
        self.value.tag()
    }

    /// Returns the precise outgoing heap edges.
    pub fn edges(&self) -> &[HeapEdge] {
        &self.edges
    }
}

impl PartialEq for HeapObjectScan {
    fn eq(&self, other: &Self) -> bool {
        self.value.raw_eq(other.value) && self.edges == other.edges
    }
}

impl Eq for HeapObjectScan {}

/// The precise heap graph reachable from an explicit root set.
#[derive(Clone, Debug, Default)]
pub struct PreciseHeapScan {
    roots: Vec<EvalRoot>,
    objects: Vec<HeapObjectScan>,
}

impl PreciseHeapScan {
    fn with_root_capacity(roots: usize) -> Result<Self, EvalHeapError> {
        let mut scan = Self::default();
        scan.roots.try_reserve_exact(roots).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: ROOTS_TABLE,
                entries: roots,
            }
        })?;
        Ok(scan)
    }

    /// Returns the explicit roots supplied by the safepoint scan.
    pub fn roots(&self) -> &[EvalRoot] {
        &self.roots
    }

    /// Returns scanned objects in deterministic worklist order.
    pub fn objects(&self) -> &[HeapObjectScan] {
        &self.objects
    }
}

impl PartialEq for PreciseHeapScan {
    fn eq(&self, other: &Self) -> bool {
        self.roots == other.roots && self.objects == other.objects
    }
}

impl Eq for PreciseHeapScan {}

/// A collector-poll request paired with a precise heap graph snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollScan {
    poll: AllocationCollectorPoll,
    scan: PreciseHeapScan,
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
}

impl AllocationCollectorPollScan {
    fn new(
        poll: AllocationCollectorPoll,
        scan: PreciseHeapScan,
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
    ) -> Self {
        Self {
            poll,
            scan,
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
        }
    }

    /// Returns the allocation safepoint collector-poll request.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the precise heap graph reachable at the poll safepoint.
    pub const fn scan(&self) -> &PreciseHeapScan {
        &self.scan
    }

    /// Returns the typed heap record count captured with this scan.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured with this scan.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured with this scan.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns worker allocation-safepoint state captured with this scan.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns permanent allocation-safepoint state captured with this scan.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }
}

/// Owned precise field metadata for one young object in a collector-poll plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollNurseryFields {
    address: GcHeapAddress,
    fields: Vec<AllocationCollectorPollNurseryField>,
    field_values: Vec<ResolvedValueGeneration>,
}

impl AllocationCollectorPollNurseryFields {
    fn new(
        address: GcHeapAddress,
        fields: Vec<AllocationCollectorPollNurseryField>,
    ) -> Result<Self, EvalHeapError> {
        let mut field_values = Vec::new();
        field_values.try_reserve_exact(fields.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_NURSERY_FIELD_VALUES_TABLE,
                entries: fields.len(),
            }
        })?;
        for field in &fields {
            field_values.push(field.value());
        }
        Ok(Self {
            address,
            fields,
            field_values,
        })
    }

    /// Returns the young object whose fields were scanned.
    pub const fn address(&self) -> GcHeapAddress {
        self.address
    }

    /// Returns the object's precise outgoing fields.
    pub fn fields(&self) -> &[AllocationCollectorPollNurseryField] {
        &self.fields
    }

    fn field_values(&self) -> &[ResolvedValueGeneration] {
        &self.field_values
    }
}

/// One precise outgoing field copied from a young object for minor-GC planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollNurseryField {
    source: HeapEdgeSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollNurseryField {
    fn new(source: HeapEdgeSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the object-field label from the typed heap scanner.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the heap value copied from the field.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// Owned precise field metadata for one old or permanent object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollOldFields {
    address: GcHeapAddress,
    generation: HeapGeneration,
    fields: Vec<AllocationCollectorPollOldField>,
    field_values: Vec<ResolvedValueGeneration>,
}

impl AllocationCollectorPollOldFields {
    fn new(
        address: GcHeapAddress,
        generation: HeapGeneration,
        fields: Vec<AllocationCollectorPollOldField>,
    ) -> Result<Self, EvalHeapError> {
        let mut field_values = Vec::new();
        field_values.try_reserve_exact(fields.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OLD_FIELD_VALUES_TABLE,
                entries: fields.len(),
            }
        })?;
        for field in &fields {
            field_values.push(field.value());
        }
        Ok(Self {
            address,
            generation,
            fields,
            field_values,
        })
    }

    /// Returns the old or permanent object whose fields were scanned.
    pub const fn address(&self) -> GcHeapAddress {
        self.address
    }

    /// Returns the generation that owns this object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object's precise outgoing fields.
    pub fn fields(&self) -> &[AllocationCollectorPollOldField] {
        &self.fields
    }

    fn field_values(&self) -> &[ResolvedValueGeneration] {
        &self.field_values
    }
}

/// One precise outgoing field copied from an old or permanent object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollOldField {
    source: HeapEdgeSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollOldField {
    fn new(source: HeapEdgeSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the object-field label from the typed heap scanner.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the heap value copied from the field.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// The copied root or field location represented by a collector-poll reference slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllocationCollectorPollReferenceSource {
    /// A copied explicit root slot from the poll scan.
    Root {
        /// The root location reported by the tree-walk scanner.
        source: EvalRootSource,
    },
    /// A copied remembered-set edge target.
    RememberedEdge {
        /// The remembered old-or-permanent to young edge.
        edge: RememberedEdge,
        /// The source object's precise field index in scanner order.
        field_index: usize,
        /// The precise source-field label on the remembered edge source object.
        source: HeapEdgeSource,
    },
    /// A copied dirty old/permanent field discovered from the card table.
    DirtyOldField {
        /// The dirty old or permanent source object.
        object: GcHeapAddress,
        /// The field index in the source object's precise field order.
        field_index: usize,
        /// The precise source-field label on the dirty old object.
        source: HeapEdgeSource,
    },
    /// A copied precise field from a planned young survivor.
    NurseryField {
        /// The survivor object whose field was copied.
        object: GcHeapAddress,
        /// The field index in the object's precise nursery-field order.
        field_index: usize,
        /// The object-field label from the typed heap scanner.
        source: HeapEdgeSource,
    },
}

/// One copied root or field reference that can feed reference-rewrite planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollReferenceSlot {
    source: AllocationCollectorPollReferenceSource,
    value: ResolvedValueGeneration,
    value_tag: Option<ValueTag>,
}

impl AllocationCollectorPollReferenceSlot {
    fn new(
        source: AllocationCollectorPollReferenceSource,
        value: ResolvedValueGeneration,
        value_tag: Option<ValueTag>,
    ) -> Self {
        Self {
            source,
            value,
            value_tag,
        }
    }

    /// Returns the copied root or field location represented by this slot.
    pub const fn source(&self) -> &AllocationCollectorPollReferenceSource {
        &self.source
    }

    fn is_root(&self) -> bool {
        matches!(
            self.source,
            AllocationCollectorPollReferenceSource::Root { .. }
        )
    }

    /// Returns the reference value copied from the slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }

    /// Returns the heap value tag copied from the slot, when available.
    ///
    /// Root-backed slots are copied from live [`Value`] roots and carry their
    /// original tag so later live-root writeback code can reconstruct a typed
    /// replacement value. Field-backed slots currently carry generation metadata
    /// only; live field mutation remains a later collector integration step.
    pub const fn value_tag(&self) -> Option<ValueTag> {
        self.value_tag
    }
}

/// A collector-poll snapshot converted into minor-GC planner inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcPlan {
    poll: AllocationCollectorPoll,
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
    remembered_set: RememberedSet,
    card_table: Option<GcCardTable>,
    roots: Vec<ResolvedValueGeneration>,
    nursery_objects: Vec<NurseryObjectAge>,
    nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
    old_fields: Vec<AllocationCollectorPollOldFields>,
    reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
    plan: MinorGcPlan,
}

impl AllocationCollectorPollMinorGcPlan {
    fn new(
        poll: AllocationCollectorPoll,
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
        remembered_set: RememberedSet,
        card_table: Option<GcCardTable>,
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
        old_fields: Vec<AllocationCollectorPollOldFields>,
        reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
        plan: MinorGcPlan,
    ) -> Self {
        Self {
            poll,
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
            remembered_set,
            card_table,
            roots,
            nursery_objects,
            nursery_fields,
            old_fields,
            reference_slots,
            plan,
        }
    }

    #[cfg(test)]
    pub(super) fn from_parts_for_test(
        poll: AllocationCollectorPoll,
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
        remembered_set: RememberedSet,
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
        reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
        plan: MinorGcPlan,
    ) -> Self {
        Self::new(
            poll,
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
            remembered_set,
            None,
            roots,
            nursery_objects,
            nursery_fields,
            Vec::new(),
            reference_slots,
            plan,
        )
    }

    /// Returns the allocation safepoint collector-poll request.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the typed heap record count captured when this plan was built.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured by this plan.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured by this plan.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns the worker allocation-safepoint state captured by this plan.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns the permanent allocation-safepoint state captured by this plan.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }

    /// Returns the remembered-set snapshot consumed by this minor-GC plan.
    pub const fn remembered_set(&self) -> &RememberedSet {
        &self.remembered_set
    }

    /// Returns the owned dirty-card snapshot captured by card-table-aware planning.
    pub const fn card_table(&self) -> Option<&GcCardTable> {
        self.card_table.as_ref()
    }

    /// Returns the root values supplied to the minor-GC planner.
    pub fn roots(&self) -> &[ResolvedValueGeneration] {
        &self.roots
    }

    /// Returns generated age metadata for current young oracle-heap objects.
    pub fn nursery_objects(&self) -> &[NurseryObjectAge] {
        &self.nursery_objects
    }

    /// Returns generated field metadata for current young oracle-heap objects.
    pub fn nursery_fields(&self) -> &[AllocationCollectorPollNurseryFields] {
        &self.nursery_fields
    }

    /// Returns generated field metadata for current old/permanent oracle objects.
    pub fn old_fields(&self) -> &[AllocationCollectorPollOldFields] {
        &self.old_fields
    }

    /// Returns the copied root and field references in rewrite-slot order.
    pub fn reference_slots(&self) -> &[AllocationCollectorPollReferenceSlot] {
        &self.reference_slots
    }

    /// Returns reference values in rewrite-slot order.
    pub fn reference_values(&self) -> impl Iterator<Item = ResolvedValueGeneration> + '_ {
        self.reference_slots.iter().map(|slot| slot.value())
    }

    /// Builds a minor-GC reference-rewrite plan from this poll plan.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any young reference in this plan does
    /// not have a relocation entry or if the rewrite plan cannot reserve
    /// storage.
    pub fn reference_rewrite_plan(
        &self,
        relocation_plan: &MinorGcRelocationPlan,
    ) -> Result<MinorGcReferenceRewritePlan, GenerationalGcError> {
        MinorGcReferenceRewritePlan::from_references(relocation_plan, self.reference_values())
    }

    /// Builds materialized relocation destinations for this poll plan.
    ///
    /// The returned wrapper keeps destination-allocation requirements, aligned
    /// placement offsets, and materialized relocation destinations together for
    /// callers that need to inspect or validate each step before building
    /// commit metadata. This still does not allocate destination storage or
    /// choose the semispace base addresses itself.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if nursery layout metadata does not match
    /// this plan, if allocation or placement metadata cannot reserve storage or
    /// overflows, or if materialized destinations from `bases` are invalid for
    /// this plan.
    pub fn relocation_destination_plan(
        &self,
        nursery_layouts: &[NurseryObjectLayout],
        bases: MinorGcDestinationBases,
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, GenerationalGcError> {
        let allocation_plan =
            MinorGcDestinationAllocationPlan::from_minor_gc_plan(&self.plan, nursery_layouts)?;
        let placement_plan =
            MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)?;
        let relocation_destinations = MinorGcRelocationDestinationPlan::from_placement_plan(
            &self.plan,
            &placement_plan,
            bases,
        )?;
        Ok(AllocationCollectorPollMinorGcRelocationDestinations {
            allocation_plan,
            placement_plan,
            relocation_destinations,
        })
    }

    /// Builds materialized relocation destinations from explicit addresses.
    ///
    /// This is the non-contiguous counterpart to
    /// [`Self::relocation_destination_plan`]. It still derives allocation and
    /// placement metadata from `nursery_layouts`, but validates a caller-supplied
    /// destination table rather than materializing addresses from generation
    /// bases. The resulting wrapper keeps the canonical survivor-frontier
    /// destination order beside the same allocation and placement metadata used
    /// by later commit planning.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if nursery layout metadata does not match
    /// this plan, if allocation or placement metadata cannot reserve storage or
    /// overflows, if explicit destinations do not form a valid relocation map, or
    /// if any destination violates the source object's required alignment or
    /// overlaps another planned destination or live source range.
    pub fn explicit_relocation_destination_plan(
        &self,
        nursery_layouts: &[NurseryObjectLayout],
        destinations: &[MinorGcRelocationDestination],
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, GenerationalGcError> {
        let allocation_plan =
            MinorGcDestinationAllocationPlan::from_minor_gc_plan(&self.plan, nursery_layouts)?;
        let placement_plan =
            MinorGcDestinationPlacementPlan::from_allocation_plan(&allocation_plan)?;
        let relocation_destinations =
            MinorGcRelocationDestinationPlan::from_destinations(&self.plan, destinations)?;
        let relocation_plan = relocation_destinations.relocation_plan(&self.plan)?;
        let _ = object_copy_plan_from_destination_placements(&relocation_plan, &placement_plan)?;
        Ok(AllocationCollectorPollMinorGcRelocationDestinations {
            allocation_plan,
            placement_plan,
            relocation_destinations,
        })
    }

    /// Builds ordered minor-GC commit metadata for this poll plan.
    ///
    /// The returned value keeps this plan's copied reference-slot labels next to
    /// the validated lower-level commit plan and the allocation-state snapshot
    /// used by later heap-backed buffer derivation. It still does not own mutable
    /// evaluator roots, object fields, object bytes, forwarding slots, or
    /// remembered-set storage. For card-table-aware plans, dirty old/permanent
    /// field reference slots participate in reference rewriting and dirty
    /// old-field rescans are folded into the precomputed next remembered set.
    /// The destination wrapper must preserve this poll plan's survivor count,
    /// source order, and copy/promote actions.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if destination placements or relocation
    /// destinations do not match this poll plan, if any subplan cannot reserve
    /// storage or detects byte-size overflow, if the remembered-set refresh or
    /// dirty old-field rescan cannot be built, or if the subplans are not
    /// mutually consistent.
    pub fn commit_plan(
        &self,
        relocation_destinations: &AllocationCollectorPollMinorGcRelocationDestinations,
    ) -> Result<AllocationCollectorPollMinorGcCommitPlan<'_>, GenerationalGcError> {
        validate_destination_placements_match_plan(
            &self.plan,
            relocation_destinations.placement_plan(),
        )?;
        let relocation_plan = relocation_destinations
            .relocation_destinations()
            .relocation_plan(&self.plan)?;
        let object_copies = object_copy_plan_from_destination_placements(
            &relocation_plan,
            relocation_destinations.placement_plan(),
        )?;
        let forwarding_pointers =
            MinorGcForwardingPointerPlan::from_object_copy_plan(&object_copies)?;
        let reference_rewrites = self.reference_rewrite_plan(&relocation_plan)?;
        let remembered_set_refresh = MinorGcRememberedSetRefreshPlan::from_snapshot(
            self.remembered_set.snapshot(),
            &relocation_plan,
        )?;
        let commit_plan = match &self.card_table {
            Some(card_table) => {
                let old_field_views = old_field_views(&self.old_fields)?;
                let old_field_rescan = MinorGcOldFieldRescanPlan::from_dirty_cards(
                    card_table.snapshot(),
                    &old_field_views,
                    &relocation_plan,
                )?;
                MinorGcCommitPlan::from_parts_with_old_field_rescan(
                    object_copies,
                    forwarding_pointers,
                    reference_rewrites,
                    remembered_set_refresh,
                    &old_field_rescan,
                )?
            }
            None => MinorGcCommitPlan::from_parts(
                object_copies,
                forwarding_pointers,
                reference_rewrites,
                remembered_set_refresh,
            )?,
        };
        Ok(AllocationCollectorPollMinorGcCommitPlan {
            reference_slots: &self.reference_slots,
            heap_records: self.heap_records,
            worker_region_owner: self.worker_region_owner,
            worker_region_epoch: self.worker_region_epoch,
            allocation_safepoints: self.allocation_safepoints,
            permanent_allocation_safepoints: self.permanent_allocation_safepoints,
            commit_plan,
        })
    }

    /// Returns the planned young-generation survivor frontier.
    pub const fn plan(&self) -> &MinorGcPlan {
        &self.plan
    }
}

/// Materialized relocation destinations for an allocation-poll minor-GC plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcRelocationDestinations {
    allocation_plan: MinorGcDestinationAllocationPlan,
    placement_plan: MinorGcDestinationPlacementPlan,
    relocation_destinations: MinorGcRelocationDestinationPlan,
}

impl AllocationCollectorPollMinorGcRelocationDestinations {
    /// Returns destination allocation requirements in survivor-frontier order.
    pub const fn allocation_plan(&self) -> &MinorGcDestinationAllocationPlan {
        &self.allocation_plan
    }

    /// Returns aligned destination placements in survivor-frontier order.
    pub const fn placement_plan(&self) -> &MinorGcDestinationPlacementPlan {
        &self.placement_plan
    }

    /// Consumes this wrapper and returns the aligned destination placements.
    pub fn into_placement_plan(self) -> MinorGcDestinationPlacementPlan {
        self.placement_plan
    }

    /// Returns the materialized relocation-destination plan.
    pub const fn relocation_destinations(&self) -> &MinorGcRelocationDestinationPlan {
        &self.relocation_destinations
    }

    /// Returns materialized relocation destinations in survivor-frontier order.
    pub fn destinations(&self) -> &[MinorGcRelocationDestination] {
        self.relocation_destinations.destinations()
    }
}

/// A heap-record destination reserved before a collector-poll minor-GC plan.
#[derive(Clone, Copy, Debug)]
pub struct AllocationCollectorPollMinorGcDestinationRecordReservation {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    destination_value: Value,
    tag: ValueTag,
}

impl AllocationCollectorPollMinorGcDestinationRecordReservation {
    const fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        destination_value: Value,
        tag: ValueTag,
    ) -> Self {
        Self {
            source,
            destination,
            destination_value,
            tag,
        }
    }

    /// Returns the young source object the destination was reserved for.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the reserved destination object address.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the heap value for the reserved destination record.
    pub const fn destination_value(self) -> Value {
        self.destination_value
    }

    /// Returns the source heap tag copied by this destination reservation.
    pub const fn tag(self) -> ValueTag {
        self.tag
    }
}

impl PartialEq for AllocationCollectorPollMinorGcDestinationRecordReservation {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.destination == other.destination
            && self.destination_value.raw_eq(other.destination_value)
            && self.tag == other.tag
    }
}

impl Eq for AllocationCollectorPollMinorGcDestinationRecordReservation {}

/// Destination records reserved for the current young heap before a poll scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcDestinationRecordReservations {
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
    reservations: Vec<AllocationCollectorPollMinorGcDestinationRecordReservation>,
}

impl AllocationCollectorPollMinorGcDestinationRecordReservations {
    fn new(
        heap_records: usize,
        worker_region_owner: u64,
        worker_region_epoch: u64,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
        reservations: Vec<AllocationCollectorPollMinorGcDestinationRecordReservation>,
    ) -> Self {
        Self {
            heap_records,
            worker_region_owner,
            worker_region_epoch,
            allocation_safepoints,
            permanent_allocation_safepoints,
            reservations,
        }
    }

    /// Returns the heap record count after destination reservation.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured after destination reservation.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured after destination reservation.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns the worker allocation-safepoint state captured after reservation.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns the permanent allocation-safepoint state captured after reservation.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }

    /// Returns the reserved source-to-destination records.
    pub fn reservations(&self) -> &[AllocationCollectorPollMinorGcDestinationRecordReservation] {
        &self.reservations
    }

    /// Returns how many destination records were reserved.
    pub fn len(&self) -> usize {
        self.reservations.len()
    }

    /// Returns whether no destination records were reserved.
    pub fn is_empty(&self) -> bool {
        self.reservations.is_empty()
    }
}

fn validate_destination_placements_match_plan(
    plan: &MinorGcPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<(), GenerationalGcError> {
    let survivors = plan.survivors();
    let placements = placement_plan.placements();
    if survivors.len() != placements.len() {
        return Err(
            GenerationalGcError::MinorGcRelocationDestinationPlacementLengthMismatch {
                survivors: survivors.len(),
                placements: placements.len(),
            },
        );
    }

    for (survivor, placement) in survivors.iter().zip(placements) {
        if survivor.address() != placement.source() {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationPlacementSourceMismatch {
                    expected: survivor.address(),
                    actual: placement.source(),
                },
            );
        }
        if survivor.action() != placement.action() {
            return Err(
                GenerationalGcError::MinorGcRelocationDestinationPlacementActionMismatch {
                    address: survivor.address(),
                    expected: survivor.action(),
                    actual: placement.action(),
                },
            );
        }
    }

    Ok(())
}

fn object_copy_plan_from_destination_placements(
    relocation_plan: &MinorGcRelocationPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<MinorGcObjectCopyPlan, GenerationalGcError> {
    let mut nursery_layouts = Vec::new();
    nursery_layouts
        .try_reserve_exact(placement_plan.len())
        .map_err(|_| GenerationalGcError::MinorGcObjectCopyAllocationFailed {
            copies: placement_plan.len(),
        })?;
    for placement in placement_plan.placements() {
        nursery_layouts.push(NurseryObjectLayout::new(
            placement.source(),
            placement.size_bytes(),
            placement.align(),
        ));
    }
    MinorGcObjectCopyPlan::from_relocation_plan(relocation_plan, &nursery_layouts)
}

fn validate_object_byte_copy_record_layout(
    copy: MinorGcObjectCopy,
    record: &HeapRecord,
) -> Result<(), EvalHeapError> {
    if !heap_record_layout_matches(record.layout, copy.size_bytes(), copy.align()) {
        return Err(EvalHeapError::CollectorPollObjectByteCopyLayoutMismatch {
            address: copy.source(),
            expected_size: copy.size_bytes(),
            actual_size: record.layout.size_bytes,
            expected_align: copy.align(),
            actual_align: record.layout.align,
        });
    }
    Ok(())
}

fn validate_object_byte_copy_request_source_record_layout(
    request: AllocationCollectorPollObjectByteCopyRequest,
    record: &HeapRecord,
) -> Result<(), EvalHeapError> {
    if !heap_record_layout_matches(record.layout, request.size_bytes(), request.align()) {
        return Err(EvalHeapError::CollectorPollObjectByteCopyLayoutMismatch {
            address: request.source(),
            expected_size: request.size_bytes(),
            actual_size: record.layout.size_bytes,
            expected_align: request.align(),
            actual_align: record.layout.align,
        });
    }
    Ok(())
}

fn validate_object_body_write_destination_record_layout(
    request: AllocationCollectorPollObjectByteCopyRequest,
    record: &HeapRecord,
) -> Result<(), EvalHeapError> {
    if !heap_record_layout_matches(record.layout, request.size_bytes(), request.align()) {
        return Err(EvalHeapError::CollectorPollObjectBodyWriteLayoutMismatch {
            address: request.destination(),
            expected_size: request.size_bytes(),
            actual_size: record.layout.size_bytes,
            expected_align: request.align(),
            actual_align: record.layout.align,
        });
    }
    Ok(())
}

const fn heap_record_layout_matches(
    layout: HeapRecordLayout,
    size_bytes: usize,
    align: usize,
) -> bool {
    layout.size_bytes == size_bytes && layout.align == align
}

/// Commit metadata for an allocation-poll minor-GC plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcCommitPlan<'a> {
    reference_slots: &'a [AllocationCollectorPollReferenceSlot],
    heap_records: usize,
    worker_region_owner: u64,
    worker_region_epoch: u64,
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
    commit_plan: MinorGcCommitPlan,
}

impl<'a> AllocationCollectorPollMinorGcCommitPlan<'a> {
    /// Returns the copied reference-slot labels used by the rewrite plan.
    pub const fn reference_slots(&self) -> &'a [AllocationCollectorPollReferenceSlot] {
        self.reference_slots
    }

    /// Returns the ordered lower-level minor-GC commit plan.
    pub const fn commit_plan(&self) -> &MinorGcCommitPlan {
        &self.commit_plan
    }

    /// Returns the typed heap record count captured when this commit was planned.
    pub const fn heap_records(&self) -> usize {
        self.heap_records
    }

    /// Returns the heap-region owner captured when this commit was planned.
    pub const fn worker_region_owner(&self) -> u64 {
        self.worker_region_owner
    }

    /// Returns the worker-region epoch captured when this commit was planned.
    pub const fn worker_region_epoch(&self) -> u64 {
        self.worker_region_epoch
    }

    /// Returns the worker allocation-safepoint state captured by this commit.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocation_safepoints
    }

    /// Returns the permanent allocation-safepoint state captured by this commit.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocation_safepoints
    }

    /// Derives empty forwarding slots for caller-owned commit application.
    ///
    /// Slots are emitted in the lower-level forwarding-pointer order, using each
    /// pointer's from-space source address. The returned buffer is caller-owned
    /// and suitable for the forwarding-slot slice passed to
    /// [`AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding-slot storage cannot be reserved.
    pub fn forwarding_slot_buffer(&self) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
        let pointers = self.commit_plan.forwarding_pointers().pointers();
        let mut slots = Vec::new();
        slots.try_reserve_exact(pointers.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries: pointers.len(),
            }
        })?;
        for pointer in pointers {
            slots.push(MinorGcForwardingSlot::new(pointer.source()));
        }
        Ok(slots)
    }

    /// Derives writeback metadata for root-backed minor-GC rewrites.
    ///
    /// The returned plan contains only copied tree-walk/JIT root slots that the
    /// lower-level commit plan will rewrite. Heap-field slots are skipped because
    /// [`EvalHeap::collector_poll_minor_gc_heap_field_writeback_plan`] binds those
    /// to typed heap fields. This remains metadata only: it does not own or mutate
    /// live value-stack, frame, continuation, import-cache, or stack-map storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if writeback storage cannot be reserved, if a
    /// lower-level rewrite slot is out of bounds for the copied reference labels,
    /// if a copied root slot no longer matches its lower-level rewrite source,
    /// or if a root-backed copied slot is missing the value tag needed for later
    /// typed `Value` reconstruction.
    pub fn root_writeback_plan(
        &self,
    ) -> Result<AllocationCollectorPollRootWritebackPlan, EvalHeapError> {
        let rewrites = self.commit_plan.reference_rewrites().rewrites();
        let mut writebacks = Vec::new();

        for rewrite in rewrites {
            let slot_index = rewrite.slot();
            let slot =
                self.reference_slot_for_rewrite(slot_index, MINOR_GC_ROOT_WRITEBACKS_TABLE)?;
            let AllocationCollectorPollReferenceSource::Root { source } = slot.source() else {
                continue;
            };
            let expected = validate_reference_slot_matches_rewrite(slot_index, slot, *rewrite)?;
            let value_tag = slot.value_tag().ok_or(
                EvalHeapError::CollectorPollRootWritebackMissingValueTag {
                    index: slot_index,
                    root_source: source.clone(),
                },
            )?;
            let entries =
                writebacks
                    .len()
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_ROOT_WRITEBACKS_TABLE,
                    })?;
            writebacks.try_reserve_exact(1).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_ROOT_WRITEBACKS_TABLE,
                    entries,
                }
            })?;
            writebacks.push(AllocationCollectorPollRootWriteback::new(
                slot_index,
                source.clone(),
                expected,
                value_tag,
                rewrite.replacement(),
                value_tag,
            ));
        }

        Ok(AllocationCollectorPollRootWritebackPlan::new(writebacks))
    }

    /// Applies this allocation-poll commit plan to caller-owned buffers.
    ///
    /// The allocation-poll layer first checks that the caller supplied the same
    /// reference values captured with the copied poll reference labels. It then
    /// delegates byte-copy buffers, forwarding slots, reference values,
    /// remembered-set state, and any optional card-table buffer to the
    /// lower-level validated commit plan. This remains a caller-buffer bridge
    /// and does not bind those buffers to live evaluator roots, heap-object
    /// fields, object headers, live card-table storage, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// buffer no longer matches the validated minor-GC commit plan.
    pub fn apply_to_buffers(
        self,
        buffers: AllocationCollectorPollMinorGcCommitBuffers<'_, '_>,
    ) -> Result<(), EvalHeapError> {
        self.apply_to_buffers_with_report(buffers).map(|_| ())
    }

    /// Applies this allocation-poll commit plan and reports committed counts.
    ///
    /// This has the same reference-label validation and lower-level commit
    /// order as [`Self::apply_to_buffers`], but returns the lower-level
    /// [`MinorGcCommitReport`] after all caller-owned buffers have been
    /// mutated. The report describes the validated buffer commit only; this
    /// method still does not mutate live evaluator roots, heap fields, object
    /// headers, live card-table storage, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// buffer no longer matches the validated minor-GC commit plan.
    pub fn apply_to_buffers_with_report(
        self,
        buffers: AllocationCollectorPollMinorGcCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, EvalHeapError> {
        let AllocationCollectorPollMinorGcCommitBuffers {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        self.validate_commit_references(references)?;

        let lower_buffers = match card_table {
            Some(card_table) => MinorGcCommitBuffers::with_card_table(
                object_byte_copies,
                forwarding_slots,
                references,
                remembered_set,
                card_table,
            ),
            None => MinorGcCommitBuffers::new(
                object_byte_copies,
                forwarding_slots,
                references,
                remembered_set,
            ),
        };
        self.commit_plan
            .apply_to_buffers_with_report(lower_buffers)
            .map_err(EvalHeapError::from)
    }

    /// Applies this allocation-poll commit plan to owned destination storage.
    ///
    /// The allocation-poll layer first checks that the caller supplied the same
    /// reference values captured with the copied poll reference labels. It then
    /// delegates owned destination storage, source bytes, forwarding slots,
    /// reference values, remembered-set state, and any optional card-table
    /// buffer to the lower-level validated commit plan. This remains an
    /// owned-buffer bridge and does not bind storage to live evaluator roots,
    /// heap-object fields, object headers, live card-table storage, or semispace
    /// pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// state no longer matches the validated minor-GC commit plan.
    pub fn apply_to_owned_destination_storage(
        self,
        buffers: AllocationCollectorPollMinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<(), EvalHeapError> {
        self.apply_to_owned_destination_storage_with_report(buffers)
            .map(|_| ())
    }

    /// Applies this allocation-poll commit plan to owned storage and reports counts.
    ///
    /// This has the same reference-label validation and lower-level commit order
    /// as [`Self::apply_to_owned_destination_storage`], but returns the
    /// lower-level [`MinorGcCommitReport`] after all owned storage and metadata
    /// buffers have been mutated.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the reference buffer no longer matches the
    /// copied allocation-poll reference labels, or if any lower-level commit
    /// state no longer matches the validated minor-GC commit plan.
    pub fn apply_to_owned_destination_storage_with_report(
        self,
        buffers: AllocationCollectorPollMinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, EvalHeapError> {
        let AllocationCollectorPollMinorGcOwnedCommitBuffers {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        self.validate_commit_references(references)?;

        let lower_buffers = match card_table {
            Some(card_table) => MinorGcOwnedCommitBuffers::with_card_table(
                destination_storage,
                source_bytes,
                forwarding_slots,
                references,
                remembered_set,
                card_table,
            ),
            None => MinorGcOwnedCommitBuffers::new(
                destination_storage,
                source_bytes,
                forwarding_slots,
                references,
                remembered_set,
            ),
        };
        self.commit_plan
            .apply_to_owned_destination_storage_with_report(lower_buffers)
            .map_err(EvalHeapError::from)
    }

    fn validate_commit_references(
        &self,
        references: &[ResolvedValueGeneration],
    ) -> Result<(), EvalHeapError> {
        if references.len() != self.reference_slots.len() {
            return Err(
                EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                    expected: self.reference_slots.len(),
                    actual: references.len(),
                },
            );
        }
        for (index, (slot, actual)) in self
            .reference_slots
            .iter()
            .zip(references.iter().copied())
            .enumerate()
        {
            let expected = slot.value();
            if actual != expected {
                return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                    index,
                    expected,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn reference_slot_for_rewrite(
        &self,
        slot_index: usize,
        table: &'static str,
    ) -> Result<&AllocationCollectorPollReferenceSlot, EvalHeapError> {
        let Some(slot) = self.reference_slots.get(slot_index) else {
            let expected = slot_index
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow { table })?;
            return Err(
                EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                    expected,
                    actual: self.reference_slots.len(),
                },
            );
        };
        Ok(slot)
    }
}

/// One object byte-copy request derived from an allocation-poll commit plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectByteCopyRequest {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    destination_generation: HeapGeneration,
    size_bytes: usize,
    align: usize,
}

impl AllocationCollectorPollObjectByteCopyRequest {
    const fn from_copy(copy: MinorGcObjectCopy) -> Self {
        Self {
            source: copy.source(),
            destination: copy.destination(),
            action: copy.action(),
            destination_generation: copy.destination_generation(),
            size_bytes: copy.size_bytes(),
            align: copy.align(),
        }
    }

    #[cfg(test)]
    /// Creates object byte-copy metadata for tests that exercise sealed reports.
    pub(crate) const fn for_test(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        destination_generation: HeapGeneration,
        size_bytes: usize,
        align: usize,
    ) -> Self {
        Self {
            source,
            destination,
            action,
            destination_generation,
            size_bytes,
            align,
        }
    }

    /// Returns the current young-generation source object address.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination address that should receive copied bytes.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this copy keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that will own the destination object.
    pub const fn destination_generation(&self) -> HeapGeneration {
        self.destination_generation
    }

    /// Returns the byte length callers must bind for source and destination.
    pub const fn size_bytes(&self) -> usize {
        self.size_bytes
    }

    /// Returns the required destination alignment in bytes.
    pub const fn align(&self) -> usize {
        self.align
    }
}

/// Object byte-copy requests in lower-level commit order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectByteCopyPlan {
    requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
}

impl AllocationCollectorPollObjectByteCopyPlan {
    fn new(requests: Vec<AllocationCollectorPollObjectByteCopyRequest>) -> Self {
        Self { requests }
    }

    /// Creates an object byte-copy plan from already-derived copy requests.
    ///
    /// This constructor preserves the caller's commit order. The returned plan
    /// still validates duplicate, overlap, generation, and layout invariants when
    /// it is lowered into a concrete generation or object-body writer.
    pub(crate) fn from_requests(
        requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
    ) -> Self {
        Self::new(requests)
    }

    #[cfg(test)]
    pub(crate) fn from_requests_for_test(
        requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
    ) -> Self {
        Self::new(requests)
    }

    /// Returns object byte-copy requests in commit order.
    pub fn requests(&self) -> &[AllocationCollectorPollObjectByteCopyRequest] {
        &self.requests
    }

    /// Returns requests copied into the next nursery in commit order.
    pub fn copy_to_nursery_requests(
        &self,
    ) -> impl Iterator<Item = &AllocationCollectorPollObjectByteCopyRequest> {
        self.requests
            .iter()
            .filter(|request| request.action() == MinorGcSurvivorAction::CopyToNursery)
    }

    /// Returns requests promoted into old generation in commit order.
    pub fn promote_to_old_requests(
        &self,
    ) -> impl Iterator<Item = &AllocationCollectorPollObjectByteCopyRequest> {
        self.requests
            .iter()
            .filter(|request| request.action() == MinorGcSurvivorAction::PromoteToOld)
    }

    /// Returns the number of requests copied into the next nursery.
    pub fn copy_to_nursery_count(&self) -> usize {
        self.copy_to_nursery_requests().count()
    }

    /// Returns the number of requests promoted into old generation.
    pub fn promote_to_old_count(&self) -> usize {
        self.promote_to_old_requests().count()
    }

    /// Returns total requested nursery destination bytes.
    pub fn copy_to_nursery_bytes(&self) -> usize {
        self.copy_to_nursery_requests()
            .fold(0usize, |total, request| {
                total.saturating_add(request.size_bytes())
            })
    }

    /// Returns total requested old-generation destination bytes.
    pub fn promote_to_old_bytes(&self) -> usize {
        self.promote_to_old_requests()
            .fold(0usize, |total, request| {
                total.saturating_add(request.size_bytes())
            })
    }

    /// Returns the number of object byte-copy requests.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Returns whether no object bytes need copying.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Builds heap-record generation writes for this object-copy plan.
    ///
    /// The returned plan contains only metadata. Applying it still requires an
    /// [`EvalHeap`] whose destination addresses already resolve to heap records.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if request storage cannot be reserved, if a
    /// request's destination generation disagrees with its survivor action, if
    /// requests contain duplicate source or destination identities, or if a
    /// destination overlaps any survivor source.
    pub fn object_generation_write_plan(
        &self,
    ) -> Result<AllocationCollectorPollObjectGenerationWritePlan, EvalHeapError> {
        AllocationCollectorPollObjectGenerationWritePlan::from_requests(&self.requests)
    }
}

/// A summary of heap-record object-body writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectBodyWriteReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl AllocationCollectorPollObjectBodyWriteReport {
    fn record(&mut self, request: AllocationCollectorPollObjectByteCopyRequest) {
        self.objects = self.objects.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(request.size_bytes());
        match request.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many destination heap-record bodies are covered.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many body-write requests target next-nursery destinations.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many body-write requests target promoted old-generation destinations.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total copied-object payload bytes covered by the report.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// A summary of paired object-body and object-generation writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectBodyAndGenerationWriteReport {
    body_write_report: AllocationCollectorPollObjectBodyWriteReport,
    generation_write_report: AllocationCollectorPollObjectGenerationWriteReport,
}

impl AllocationCollectorPollObjectBodyAndGenerationWriteReport {
    const fn new(
        body_write_report: AllocationCollectorPollObjectBodyWriteReport,
        generation_write_report: AllocationCollectorPollObjectGenerationWriteReport,
    ) -> Self {
        Self {
            body_write_report,
            generation_write_report,
        }
    }

    /// Returns the object-body write report.
    pub const fn body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.body_write_report
    }

    /// Returns the object-generation write report.
    pub const fn generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.generation_write_report
    }
}

struct CollectorPollObjectBodyWrite {
    destination_index: usize,
    object: HeapObjectValue,
    layout: HeapRecordLayout,
    structural_hash: Option<HotXxh3Hash>,
    value_hash: Option<ValueHash>,
    captured_value_hash: Option<ValueHash>,
}

struct CollectorPollCopiedHeapFieldWrite {
    record_index: usize,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement: Value,
    base_object: Option<HeapObjectValue>,
}

pub(super) struct CollectorPollDirectHeapFieldWrite {
    target: HeapFieldWriteTarget,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement: Value,
    remembered_edge: Option<RememberedEdge>,
}

/// The staged destination of one direct heap-field write.
///
/// Records stage by table index (the pre-FV-1 shape); flat lists (doc 30
/// FV-1) and flat attrsets (FV-2) have no record and stage by their stable
/// flat-store address, whose commit goes through the flat store's exclusive
/// `resolve_mut` door.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeapFieldWriteTarget {
    /// A record-table object, staged by record index.
    Record(usize),
    /// A flat list object, staged by its stable heap address.
    FlatList(NonNull<HeapObject>),
    /// A flat attrset object, staged by its stable heap address.
    FlatAttrs(NonNull<HeapObject>),
}

/// Staged live heap writes for a tree-walk minor-GC publication.
pub(crate) struct AllocationCollectorPollLiveHeapFieldWriteStage {
    object_body_writes: Vec<CollectorPollObjectBodyWrite>,
    object_generation_writes: Vec<(usize, HeapGeneration)>,
    staged_heap_field_writes: Vec<(usize, HeapObjectValue)>,
    staged_flat_list_writes: Vec<(NonNull<HeapObject>, NixList)>,
    staged_flat_attrs_writes: Vec<(NonNull<HeapObject>, FlatAttrs)>,
    staged_environment_writes: EnvironmentWritebackStage,
    staged_structural_writebacks: StructuralWritebackStage,
    staged_barriers: Option<(RememberedSet, GcCardTable)>,
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    copied_report: AllocationCollectorPollCopiedHeapFieldWriteReport,
    direct_report: AllocationCollectorPollDirectHeapFieldWriteReport,
}

impl AllocationCollectorPollLiveHeapFieldWriteStage {
    /// Returns the paired object-body and generation write report.
    pub(crate) const fn object_body_and_generation_write_report(
        &self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the copied heap-field write report.
    pub(crate) const fn copied_report(&self) -> AllocationCollectorPollCopiedHeapFieldWriteReport {
        self.copied_report
    }

    /// Returns the direct heap-field write report.
    pub(crate) const fn direct_report(&self) -> AllocationCollectorPollDirectHeapFieldWriteReport {
        self.direct_report
    }

    /// Returns how many live heap fields are staged for rewrite.
    pub(crate) const fn live_heap_field_writebacks(&self) -> usize {
        self.copied_report
            .fields()
            .saturating_add(self.direct_report.fields())
    }
}

/// Staged side-table forwarding writes for a tree-walk minor-GC publication.
pub(crate) struct AllocationCollectorPollForwardingInstallStage {
    planned: Vec<(usize, GcHeapAddress, ResolvedValueGeneration)>,
}

impl AllocationCollectorPollForwardingInstallStage {
    /// Returns the forwarding installation report for this staged write.
    pub(crate) fn report(&self) -> AllocationCollectorPollForwardingInstallReport {
        AllocationCollectorPollForwardingInstallReport {
            forwarding_pointers: self.planned.len(),
        }
    }
}

enum RecordOwnedHeapFieldWriteObjectError {
    UnsupportedSource,
    Attr(AttrError),
    Environment(EvalEnvError),
    Thunk(ForceError),
    ParallelThunkPayload(ParallelThunkPayloadError),
}

/// A summary of heap-record object-generation writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectGenerationWriteReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl AllocationCollectorPollObjectGenerationWriteReport {
    fn record(&mut self, write: &AllocationCollectorPollObjectGenerationWrite) {
        self.objects = self.objects.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.request().size_bytes());
        match write.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many destination heap records are covered.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many requests kept destinations in the young generation.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many requests promoted destinations to the old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total copied-object payload bytes covered by the report.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One planned heap-record generation write for a relocated object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectGenerationWrite {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
}

impl AllocationCollectorPollObjectGenerationWrite {
    fn from_request(request: AllocationCollectorPollObjectByteCopyRequest) -> Self {
        Self {
            source: request.source(),
            destination: request.destination(),
            action: request.action(),
            generation: request.destination_generation(),
            request,
        }
    }

    /// Returns the from-space survivor source object.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object whose heap record should be written.
    pub const fn destination(self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination stays young or is promoted.
    pub const fn action(self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation to write to the destination heap record.
    pub const fn generation(self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that produced this generation write.
    pub const fn request(self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }
}

/// Heap-record generation writes derived from object-copy requests.
///
/// The plan is valid for destination records that have already been bound into
/// the evaluator heap side table. It does not allocate destination records, bind
/// object bytes to heap storage, rewrite references, or manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollObjectGenerationWritePlan {
    report: AllocationCollectorPollObjectGenerationWriteReport,
    writes: Vec<AllocationCollectorPollObjectGenerationWrite>,
}

impl AllocationCollectorPollObjectGenerationWritePlan {
    fn new(writes: Vec<AllocationCollectorPollObjectGenerationWrite>) -> Self {
        let mut report = AllocationCollectorPollObjectGenerationWriteReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    fn from_requests(
        requests: &[AllocationCollectorPollObjectByteCopyRequest],
    ) -> Result<Self, EvalHeapError> {
        let mut writes = Vec::new();
        writes.try_reserve_exact(requests.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
                entries: requests.len(),
            }
        })?;

        for (index, request) in requests.iter().copied().enumerate() {
            validate_object_generation_write_request(index, request, &writes)?;
            writes.push(AllocationCollectorPollObjectGenerationWrite::from_request(
                request,
            ));
        }

        Ok(Self::new(writes))
    }

    #[cfg(test)]
    pub(crate) fn from_requests_for_test(
        requests: Vec<AllocationCollectorPollObjectByteCopyRequest>,
    ) -> Result<Self, EvalHeapError> {
        Self::from_requests(&requests)
    }

    /// Returns whether this plan has no heap-record generation writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many heap-record generation writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the planned writes.
    pub const fn report(&self) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.report
    }

    /// Returns the planned heap-record generation writes.
    pub fn writes(&self) -> &[AllocationCollectorPollObjectGenerationWrite] {
        &self.writes
    }
}

const fn generation_for_destination_action(action: MinorGcSurvivorAction) -> HeapGeneration {
    match action {
        MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
        MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
    }
}

fn validate_object_byte_copy_request_destination_generation(
    request: AllocationCollectorPollObjectByteCopyRequest,
) -> Result<HeapGeneration, EvalHeapError> {
    let expected = generation_for_destination_action(request.action());
    let actual = request.destination_generation();
    if actual != expected {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteGenerationMismatch {
                source_address: request.source(),
                destination: request.destination(),
                expected,
                actual,
                action: request.action(),
            },
        );
    }
    Ok(expected)
}

fn validate_collector_poll_minor_gc_copied_heap_field_write_request_invariants(
    writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    let entries = writes
        .len()
        .checked_mul(2)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
        })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
            entries,
        })?;

    for write in writes {
        push_unique_heap_field_write_request(&mut requests, write.writeback_object_request());
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }

    let _ =
        AllocationCollectorPollObjectByteCopyPlan::new(requests).object_generation_write_plan()?;
    Ok(())
}

fn validate_collector_poll_minor_gc_direct_heap_field_write_request_invariants(
    writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    let mut requests = Vec::new();
    requests.try_reserve_exact(writes.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
            entries: writes.len(),
        }
    })?;

    for write in writes {
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }

    let _ =
        AllocationCollectorPollObjectByteCopyPlan::new(requests).object_generation_write_plan()?;
    Ok(())
}

fn validate_collector_poll_minor_gc_heap_field_write_request_invariants(
    copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    let copied_entries =
        copied_writes
            .len()
            .checked_mul(2)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            })?;
    let entries = copied_entries.checked_add(direct_writes.len()).ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
        },
    )?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            entries,
        })?;

    for write in copied_writes {
        push_unique_heap_field_write_request(&mut requests, write.writeback_object_request());
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }
    for write in direct_writes {
        push_unique_heap_field_write_request(&mut requests, write.replacement_request());
    }

    let _ =
        AllocationCollectorPollObjectByteCopyPlan::new(requests).object_generation_write_plan()?;
    Ok(())
}

fn push_unique_heap_field_write_request(
    requests: &mut Vec<AllocationCollectorPollObjectByteCopyRequest>,
    request: AllocationCollectorPollObjectByteCopyRequest,
) {
    if !requests.iter().any(|existing| *existing == request) {
        requests.push(request);
    }
}

fn validate_object_generation_write_request(
    index: usize,
    request: AllocationCollectorPollObjectByteCopyRequest,
    writes: &[AllocationCollectorPollObjectGenerationWrite],
) -> Result<(), EvalHeapError> {
    let _ = validate_object_byte_copy_request_destination_generation(request)?;
    if request.source() == request.destination() {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDestinationIsSource {
                source_address: request.source(),
            },
        );
    }
    if writes
        .iter()
        .any(|write| write.source() == request.source())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDuplicateSource {
                index,
                source_address: request.source(),
            },
        );
    }
    if let Some(existing) = writes
        .iter()
        .find(|write| write.destination() == request.destination())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDuplicateDestination {
                index,
                source_address: request.source(),
                existing_source_address: existing.source(),
                destination: request.destination(),
            },
        );
    }
    if let Some(existing) = writes
        .iter()
        .find(|write| write.source() == request.destination())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
                index,
                source_address: request.source(),
                existing_source_address: existing.source(),
                destination: request.destination(),
            },
        );
    }
    if let Some(existing) = writes
        .iter()
        .find(|write| write.destination() == request.source())
    {
        return Err(
            EvalHeapError::CollectorPollObjectGenerationWriteDestinationOverlapsSource {
                index,
                source_address: existing.source(),
                existing_source_address: request.source(),
                destination: existing.destination(),
            },
        );
    }

    Ok(())
}

/// A summary of live evaluator heap forwarding values installed for minor GC.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollForwardingInstallReport {
    forwarding_pointers: usize,
}

impl AllocationCollectorPollForwardingInstallReport {
    /// Returns the number of evaluator heap forwarding values installed.
    pub const fn forwarding_pointers(self) -> usize {
        self.forwarding_pointers
    }
}

/// One live side-table forwarding value installed on an evaluator heap record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollForwardingValue {
    source: GcHeapAddress,
    forwarded_value: ResolvedValueGeneration,
}

impl AllocationCollectorPollForwardingValue {
    const fn new(source: GcHeapAddress, forwarded_value: ResolvedValueGeneration) -> Self {
        Self {
            source,
            forwarded_value,
        }
    }

    /// Returns the from-space object that owns the forwarding cell.
    pub const fn source(self) -> GcHeapAddress {
        self.source
    }

    /// Returns the forwarding metadata installed for the source object.
    pub const fn forwarded_value(self) -> ResolvedValueGeneration {
        self.forwarded_value
    }
}

/// One root-backed reference that must be rewritten after minor GC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWriteback {
    slot: usize,
    source: EvalRootSource,
    expected: ResolvedValueGeneration,
    expected_tag: ValueTag,
    replacement: ResolvedValueGeneration,
    replacement_tag: ValueTag,
}

impl AllocationCollectorPollRootWriteback {
    fn new(
        slot: usize,
        source: EvalRootSource,
        expected: ResolvedValueGeneration,
        expected_tag: ValueTag,
        replacement: ResolvedValueGeneration,
        replacement_tag: ValueTag,
    ) -> Self {
        Self {
            slot,
            source,
            expected,
            expected_tag,
            replacement,
            replacement_tag,
        }
    }

    /// Returns the copied reference slot that produced this writeback.
    pub const fn slot(&self) -> usize {
        self.slot
    }

    /// Returns the copied tree-walk/JIT root source to rewrite.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the young from-space value expected in the root slot.
    pub const fn expected(&self) -> ResolvedValueGeneration {
        self.expected
    }

    /// Returns the heap tag expected in the root slot.
    pub const fn expected_tag(&self) -> ValueTag {
        self.expected_tag
    }

    /// Returns the relocated value that must replace [`Self::expected`].
    pub const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }

    /// Returns the heap tag for [`Self::replacement`].
    ///
    /// Minor-GC relocation preserves the object type, so this tag matches
    /// [`Self::expected_tag`]. It is carried explicitly for future live
    /// tree-walk/JIT root-slot mutation, where address plus generation is not
    /// enough to reconstruct a typed [`Value`].
    pub const fn replacement_tag(&self) -> ValueTag {
        self.replacement_tag
    }

    /// Reconstructs the typed young from-space value expected in the root slot.
    ///
    /// This validates the value word's tag/address shape only. It does not
    /// prove that the source object remains live in an [`EvalHeap`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the expected value is no longer heap-backed
    /// metadata or if its address is not valid for a typed evaluator heap
    /// pointer.
    pub fn expected_value(&self) -> Result<Value, EvalHeapError> {
        value_for_resolved_generation(self.expected_tag, self.expected)
    }

    /// Reconstructs the typed relocated value that should replace the root slot.
    ///
    /// This validates the value word's tag/address shape only. It does not bind
    /// the value to live semispace storage or install it into a root slot.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the replacement value is no longer
    /// heap-backed metadata or if its address is not valid for a typed evaluator
    /// heap pointer.
    pub fn replacement_value(&self) -> Result<Value, EvalHeapError> {
        value_for_resolved_generation(self.replacement_tag, self.replacement)
    }
}

/// Root writebacks derived from an allocation-poll minor-GC commit plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWritebackPlan {
    writebacks: Vec<AllocationCollectorPollRootWriteback>,
}

impl AllocationCollectorPollRootWritebackPlan {
    fn new(writebacks: Vec<AllocationCollectorPollRootWriteback>) -> Self {
        Self { writebacks }
    }

    /// Returns planned root writebacks in reference-rewrite order.
    pub fn writebacks(&self) -> &[AllocationCollectorPollRootWriteback] {
        &self.writebacks
    }

    /// Returns planned writebacks for compiled stack-map roots.
    ///
    /// The iterator preserves reference-rewrite order and filters only
    /// [`EvalRootSource::StackMap`] entries. It is metadata for a later JIT
    /// stack-map writer; applying the returned entries still requires
    /// caller-owned slots and does not mutate compiled frames.
    pub fn stack_map_writebacks(
        &self,
    ) -> impl Iterator<Item = &AllocationCollectorPollRootWriteback> {
        self.writebacks
            .iter()
            .filter(|writeback| matches!(writeback.source(), EvalRootSource::StackMap { .. }))
    }

    /// Returns the number of compiled stack-map root writebacks.
    pub fn stack_map_writeback_count(&self) -> usize {
        self.stack_map_writebacks().count()
    }

    /// Returns the number of root writebacks.
    pub fn len(&self) -> usize {
        self.writebacks.len()
    }

    /// Returns whether there are no root writebacks.
    pub fn is_empty(&self) -> bool {
        self.writebacks.is_empty()
    }

    /// Applies planned root writebacks to caller-owned root slots.
    ///
    /// The supplied slots must match this plan's root writeback count and order.
    /// Each slot must name the copied root source and still contain the expected
    /// young from-space value. The method validates every slot before rewriting
    /// any slot, so validation failures leave the caller-owned buffer unchanged.
    /// This mutates only the supplied buffer; it does not bind to active
    /// tree-walk value stacks, frames, import caches, or JIT stack maps.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the supplied slot count differs from the
    /// plan, if a slot names a different copied root source, or if a slot no
    /// longer contains the expected young from-space value.
    pub fn apply_to_slots(
        &self,
        slots: &mut [AllocationCollectorPollRootWritebackSlot],
    ) -> Result<AllocationCollectorPollRootWritebackReport, EvalHeapError> {
        validate_root_writeback_slots(self, slots)?;
        apply_root_writeback_slots(self, slots);

        Ok(AllocationCollectorPollRootWritebackReport {
            writebacks: self.writebacks.len(),
        })
    }

    /// Applies planned root writebacks to caller-owned typed value slots.
    ///
    /// The supplied slots must match this plan's root writeback count and order.
    /// Each slot must name the copied root source and still contain the exact
    /// raw [`Value`] reconstructed by [`AllocationCollectorPollRootWriteback::expected_value`].
    /// The method validates every slot before rewriting any slot, so validation
    /// failures leave the caller-owned buffer unchanged. This mutates only the
    /// supplied buffer; it does not bind to active tree-walk value stacks,
    /// frames, import caches, or JIT stack maps.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the supplied slot count differs from the
    /// plan, if a slot names a different copied root source, if a planned
    /// expected or replacement value cannot be reconstructed from root-writeback
    /// metadata, or if a caller-owned value no longer contains the expected raw
    /// value.
    pub fn apply_to_value_slots(
        &self,
        slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
    ) -> Result<AllocationCollectorPollRootWritebackReport, EvalHeapError> {
        validate_root_value_writeback_slots(self, slots)?;
        apply_root_value_writeback_slots(self, slots)?;

        Ok(AllocationCollectorPollRootWritebackReport {
            writebacks: self.writebacks.len(),
        })
    }
}

fn validate_root_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<(), EvalHeapError> {
    if slots.len() != plan.writebacks.len() {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected: plan.writebacks.len(),
                actual: slots.len(),
            },
        );
    }

    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter()) {
        if slot.source() != writeback.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index: writeback.slot(),
                expected: writeback.source().clone(),
                actual: slot.source().clone(),
            });
        }
        let actual = slot.value();
        if actual != writeback.expected() {
            return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: writeback.slot(),
                expected: writeback.expected(),
                actual,
            });
        }
    }

    Ok(())
}

fn apply_root_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &mut [AllocationCollectorPollRootWritebackSlot],
) {
    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter_mut()) {
        slot.value = writeback.replacement();
    }
}

fn validate_root_value_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<(), EvalHeapError> {
    if slots.len() != plan.writebacks.len() {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected: plan.writebacks.len(),
                actual: slots.len(),
            },
        );
    }

    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter()) {
        if slot.source() != writeback.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index: writeback.slot(),
                expected: writeback.source().clone(),
                actual: slot.source().clone(),
            });
        }
        let expected = writeback.expected_value()?;
        let actual = slot.value();
        if !actual.raw_eq(expected) {
            return Err(root_value_writeback_slot_mismatch(
                writeback.slot(),
                expected,
                actual,
            ));
        }
        let _ = writeback.replacement_value()?;
    }

    Ok(())
}

fn apply_root_value_writeback_slots(
    plan: &AllocationCollectorPollRootWritebackPlan,
    slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
) -> Result<(), EvalHeapError> {
    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter_mut()) {
        slot.value = writeback.replacement_value()?;
    }
    Ok(())
}

fn root_value_writeback_slot_mismatch(
    index: usize,
    expected: Value,
    actual: Value,
) -> EvalHeapError {
    EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
        index,
        expected_tag: expected.tag(),
        expected_payload: expected.payload_bits(),
        actual_tag: actual.tag(),
        actual_payload: actual.payload_bits(),
    }
}

/// Caller-owned mutable storage for one root writeback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWritebackSlot {
    source: EvalRootSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollRootWritebackSlot {
    /// Creates a caller-owned root slot value for writeback application.
    pub fn new(source: EvalRootSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the copied tree-walk/JIT root source represented by this slot.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current heap-generation value in this slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// Caller-owned mutable typed storage for one root writeback.
///
/// Equality compares copied root sources and raw [`Value`] representations; it
/// is not evaluator-level Nix semantic equality.
#[derive(Clone, Debug)]
pub struct AllocationCollectorPollRootValueWritebackSlot {
    source: EvalRootSource,
    value: Value,
}

impl AllocationCollectorPollRootValueWritebackSlot {
    /// Creates a caller-owned typed root slot for writeback application.
    pub fn new(source: EvalRootSource, value: Value) -> Self {
        Self { source, value }
    }

    /// Returns the copied tree-walk/JIT root source represented by this slot.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current typed evaluator value in this slot.
    pub const fn value(&self) -> Value {
        self.value
    }
}

impl PartialEq for AllocationCollectorPollRootValueWritebackSlot {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.value.raw_eq(other.value)
    }
}

impl Eq for AllocationCollectorPollRootValueWritebackSlot {}

/// A summary of caller-owned root slots rewritten by a writeback plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWritebackReport {
    writebacks: usize,
}

impl AllocationCollectorPollRootWritebackReport {
    /// Returns the number of caller-owned root slots rewritten.
    pub const fn writebacks(self) -> usize {
        self.writebacks
    }
}

/// Complete root and heap-field reference writebacks for one minor-GC commit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollReferenceWritebackPlan {
    root_writebacks: AllocationCollectorPollRootWritebackPlan,
    heap_field_writebacks: AllocationCollectorPollHeapFieldWritebackPlan,
}

impl AllocationCollectorPollReferenceWritebackPlan {
    fn new(
        root_writebacks: AllocationCollectorPollRootWritebackPlan,
        heap_field_writebacks: AllocationCollectorPollHeapFieldWritebackPlan,
    ) -> Self {
        Self {
            root_writebacks,
            heap_field_writebacks,
        }
    }

    /// Returns writebacks for externally owned root slots.
    pub const fn root_writebacks(&self) -> &AllocationCollectorPollRootWritebackPlan {
        &self.root_writebacks
    }

    /// Returns writebacks for evaluator-owned heap fields.
    pub const fn heap_field_writebacks(&self) -> &AllocationCollectorPollHeapFieldWritebackPlan {
        &self.heap_field_writebacks
    }

    /// Returns the total number of planned reference writebacks.
    pub fn len(&self) -> usize {
        self.root_writebacks.len() + self.heap_field_writebacks.len()
    }

    /// Returns whether there are no reference writebacks.
    pub fn is_empty(&self) -> bool {
        self.root_writebacks.is_empty() && self.heap_field_writebacks.is_empty()
    }

    /// Applies root and heap-field writebacks to caller-owned slot buffers.
    ///
    /// Both partitions are validated before either partition is rewritten. This
    /// prevents a stale heap-field slot from partially rewriting root slots, and
    /// vice versa. The method mutates only the supplied buffers; it does not bind
    /// to active tree-walk/JIT roots, live evaluator object fields, object bytes,
    /// object headers, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if either caller-owned slot buffer no longer
    /// matches its derived writeback plan.
    pub fn apply_to_slots(
        &self,
        root_slots: &mut [AllocationCollectorPollRootWritebackSlot],
        heap_field_slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
    ) -> Result<AllocationCollectorPollReferenceWritebackReport, EvalHeapError> {
        validate_root_writeback_slots(&self.root_writebacks, root_slots)?;
        validate_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots)?;

        apply_root_writeback_slots(&self.root_writebacks, root_slots);
        apply_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots);

        Ok(AllocationCollectorPollReferenceWritebackReport {
            root_writebacks: self.root_writebacks.len(),
            heap_field_writebacks: self.heap_field_writebacks.len(),
        })
    }

    /// Applies typed root and heap-field writebacks to caller-owned buffers.
    ///
    /// This is the typed-root variant of [`Self::apply_to_slots`]. Root slots
    /// contain concrete [`Value`] handles so tree-walk callers can preserve heap
    /// tags while heap-field slots continue to carry generation-style metadata.
    /// Both partitions are validated before either partition is rewritten.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if either caller-owned slot buffer no longer
    /// matches its derived writeback plan, or if a planned root replacement
    /// cannot be reconstructed as a typed [`Value`].
    pub fn apply_to_value_and_heap_field_slots(
        &self,
        root_slots: &mut [AllocationCollectorPollRootValueWritebackSlot],
        heap_field_slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
    ) -> Result<AllocationCollectorPollReferenceWritebackReport, EvalHeapError> {
        validate_root_value_writeback_slots(&self.root_writebacks, root_slots)?;
        validate_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots)?;

        apply_root_value_writeback_slots(&self.root_writebacks, root_slots)?;
        apply_heap_field_writeback_slots(&self.heap_field_writebacks, heap_field_slots);

        Ok(AllocationCollectorPollReferenceWritebackReport {
            root_writebacks: self.root_writebacks.len(),
            heap_field_writebacks: self.heap_field_writebacks.len(),
        })
    }
}

/// A summary of caller-owned reference slots rewritten by a combined plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollReferenceWritebackReport {
    root_writebacks: usize,
    heap_field_writebacks: usize,
}

impl AllocationCollectorPollReferenceWritebackReport {
    /// Returns the number of caller-owned root slots rewritten.
    pub const fn root_writebacks(self) -> usize {
        self.root_writebacks
    }

    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn heap_field_writebacks(self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the total number of caller-owned reference slots rewritten.
    pub const fn writebacks(self) -> usize {
        self.root_writebacks + self.heap_field_writebacks
    }
}

/// A caller-supplied current value for one copied root reference slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootReferenceValue {
    source: EvalRootSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollRootReferenceValue {
    /// Creates a current root value for the copied root slot named by `source`.
    pub fn new(source: EvalRootSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
    }

    /// Returns the copied root source this value belongs to.
    pub const fn source(&self) -> &EvalRootSource {
        &self.source
    }

    /// Returns the current value read from the root source.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// One heap-field-backed reference that must be rewritten after minor GC.
///
/// Remembered-source and dirty old fields are validated and rewritten in the
/// same old/permanent object. Nursery fields are validated against the current
/// from-space object but name the relocated destination object that a mutating
/// collector would update after copying bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWriteback {
    slot: usize,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    expected: ResolvedValueGeneration,
    replacement: ResolvedValueGeneration,
}

impl AllocationCollectorPollHeapFieldWriteback {
    fn new(
        slot: usize,
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        expected: ResolvedValueGeneration,
        replacement: ResolvedValueGeneration,
    ) -> Self {
        Self {
            slot,
            validation_object,
            writeback_object,
            field_index,
            source,
            expected,
            replacement,
        }
    }

    /// Returns the copied reference slot that produced this writeback.
    pub const fn slot(&self) -> usize {
        self.slot
    }

    /// Returns the current heap object read to validate the saved field label.
    pub const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    /// Returns the object whose field must receive [`Self::replacement`].
    ///
    /// This matches [`Self::validation_object`] for remembered-source and dirty
    /// old fields, and names the relocated object for copied nursery fields.
    pub const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    /// Returns the field index in the validation object's precise scanner order.
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the precise source label expected on the validation object.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the young from-space value expected in the field.
    pub const fn expected(&self) -> ResolvedValueGeneration {
        self.expected
    }

    /// Returns the relocated value that must replace [`Self::expected`].
    pub const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }
}

/// Heap-field writebacks derived from an allocation-poll minor-GC commit plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWritebackPlan {
    writebacks: Vec<AllocationCollectorPollHeapFieldWriteback>,
}

impl AllocationCollectorPollHeapFieldWritebackPlan {
    fn new(writebacks: Vec<AllocationCollectorPollHeapFieldWriteback>) -> Self {
        Self { writebacks }
    }

    /// Returns planned heap-field writebacks in reference-rewrite order.
    pub fn writebacks(&self) -> &[AllocationCollectorPollHeapFieldWriteback] {
        &self.writebacks
    }

    /// Returns the number of heap-field writebacks.
    pub fn len(&self) -> usize {
        self.writebacks.len()
    }

    /// Returns whether there are no heap-field writebacks.
    pub fn is_empty(&self) -> bool {
        self.writebacks.is_empty()
    }

    /// Applies planned heap-field writebacks to caller-owned field slots.
    ///
    /// The supplied slots must match this plan's heap-field writeback count and
    /// order. Each slot must name the validation object, writeback object, field
    /// index, copied field source label, and expected young from-space value.
    /// The method validates every slot before rewriting any slot, so validation
    /// failures leave the caller-owned buffer unchanged. This mutates only the
    /// supplied buffer; it does not bind to live evaluator object fields,
    /// copied object bytes, object headers, or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the supplied slot count differs from the
    /// plan, if a slot names a different object, field index, or field source,
    /// or if a slot no longer contains the expected young from-space value.
    pub fn apply_to_slots(
        &self,
        slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
    ) -> Result<AllocationCollectorPollHeapFieldWritebackReport, EvalHeapError> {
        validate_heap_field_writeback_slots(self, slots)?;
        apply_heap_field_writeback_slots(self, slots);

        Ok(AllocationCollectorPollHeapFieldWritebackReport {
            writebacks: self.writebacks.len(),
        })
    }
}

fn validate_heap_field_writeback_slots(
    plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<(), EvalHeapError> {
    if slots.len() != plan.writebacks.len() {
        return Err(
            EvalHeapError::CollectorPollHeapFieldWritebackSlotLengthMismatch {
                expected: plan.writebacks.len(),
                actual: slots.len(),
            },
        );
    }

    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter()) {
        if slot.validation_object() != writeback.validation_object()
            || slot.writeback_object() != writeback.writeback_object()
        {
            return Err(
                EvalHeapError::CollectorPollHeapFieldWritebackSlotObjectMismatch {
                    index: writeback.slot(),
                    expected_validation_object: writeback.validation_object(),
                    actual_validation_object: slot.validation_object(),
                    expected_writeback_object: writeback.writeback_object(),
                    actual_writeback_object: slot.writeback_object(),
                },
            );
        }
        if slot.field_index() != writeback.field_index() || slot.source() != writeback.source() {
            return Err(
                EvalHeapError::CollectorPollHeapFieldWritebackSlotFieldMismatch {
                    index: writeback.slot(),
                    expected_field_index: writeback.field_index(),
                    actual_field_index: slot.field_index(),
                    expected_source: writeback.source().clone(),
                    actual_source: slot.source().clone(),
                },
            );
        }
        let actual = slot.value();
        if actual != writeback.expected() {
            return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                index: writeback.slot(),
                expected: writeback.expected(),
                actual,
            });
        }
    }

    Ok(())
}

fn apply_heap_field_writeback_slots(
    plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    slots: &mut [AllocationCollectorPollHeapFieldWritebackSlot],
) {
    for (writeback, slot) in plan.writebacks.iter().zip(slots.iter_mut()) {
        slot.value = writeback.replacement();
    }
}

fn object_copy_request_for_reference_writeback(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    index: usize,
    expected: ResolvedValueGeneration,
    replacement: ResolvedValueGeneration,
) -> Result<AllocationCollectorPollObjectByteCopyRequest, EvalHeapError> {
    let ResolvedValueGeneration::Heap {
        address: source, ..
    } = expected
    else {
        return Err(
            EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
                index,
                expected,
                replacement,
            },
        );
    };
    let ResolvedValueGeneration::Heap {
        address: destination,
        ..
    } = replacement
    else {
        return Err(
            EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
                index,
                expected,
                replacement,
            },
        );
    };

    object_copy_request_for_reference_writeback_address(
        object_body_plan,
        index,
        source,
        destination,
    )
    .map_err(
        |_| EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
            index,
            expected,
            replacement,
        },
    )
}

fn object_copy_request_for_reference_writeback_address(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    index: usize,
    source: GcHeapAddress,
    destination: GcHeapAddress,
) -> Result<AllocationCollectorPollObjectByteCopyRequest, EvalHeapError> {
    object_body_plan
        .requests()
        .iter()
        .copied()
        .find(|request| request.source() == source && request.destination() == destination)
        .ok_or(
            EvalHeapError::CollectorPollReferenceWritebackObjectCopyRequestMissing {
                index,
                expected: ResolvedValueGeneration::Heap {
                    address: source,
                    generation: HeapGeneration::Young,
                },
                replacement: ResolvedValueGeneration::Heap {
                    address: destination,
                    generation: HeapGeneration::Young,
                },
            },
        )
}

fn validate_collector_poll_minor_gc_reference_writeback_direct_destination_aliases(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<(), EvalHeapError> {
    for write in direct_writes {
        if object_body_plan
            .requests()
            .iter()
            .any(|request| request.destination() == write.writeback_object())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveReferenceWritebackDestinationAliasesDirectWriteback {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    destination: write.writeback_object(),
                },
            );
        }
    }

    Ok(())
}

/// Caller-owned mutable storage for one heap-field writeback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWritebackSlot {
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    value: ResolvedValueGeneration,
}

impl AllocationCollectorPollHeapFieldWritebackSlot {
    /// Creates a caller-owned heap-field slot value for writeback application.
    pub fn new(
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        value: ResolvedValueGeneration,
    ) -> Self {
        Self {
            validation_object,
            writeback_object,
            field_index,
            source,
            value,
        }
    }

    /// Returns the heap object used to validate the copied field label.
    pub const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    /// Returns the heap object whose copied field slot is rewritten.
    pub const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    /// Returns the precise field index represented by this slot.
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the copied field source label represented by this slot.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the current heap-generation value in this slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// A summary of caller-owned heap fields rewritten by a writeback plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocationCollectorPollHeapFieldWritebackReport {
    writebacks: usize,
}

impl AllocationCollectorPollHeapFieldWritebackReport {
    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn writebacks(self) -> usize {
        self.writebacks
    }
}

/// One copied-object heap field that can be rewritten in evaluator storage.
///
/// The write targets a relocated copy of a nursery object. It deliberately does
/// not describe same-object old/permanent field writes because those require a
/// separate policy for mutating hash-consed and interior-shared records. The
/// destination object is expected to be an already-bound collector-owned scratch
/// record; this side table still cannot prove semispace ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollCopiedHeapFieldWrite {
    allocation_domain: HeapAllocationDomain,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement: ResolvedValueGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    writeback_object_request: AllocationCollectorPollObjectByteCopyRequest,
}

impl AllocationCollectorPollCopiedHeapFieldWrite {
    pub(crate) fn new(
        allocation_domain: HeapAllocationDomain,
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        replacement: ResolvedValueGeneration,
        replacement_request: AllocationCollectorPollObjectByteCopyRequest,
        writeback_object_request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Self {
        Self {
            allocation_domain,
            validation_object,
            writeback_object,
            field_index,
            source,
            replacement,
            replacement_request,
            writeback_object_request,
        }
    }

    const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    const fn field_index(&self) -> usize {
        self.field_index
    }

    const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }

    const fn replacement_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.replacement_request
    }

    const fn writeback_object_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.writeback_object_request
    }
}

/// A record-owned old or permanent heap field rewritten in place after minor GC.
///
/// The write targets an existing old-generation worker record or a
/// permanent-shared record. The strict direct writer accepts only promoted-old
/// replacement destinations; the combined card-table-aware writer additionally
/// accepts copied-young replacement destinations after staging a
/// remembered-set/card-table update. Shared lexical environment frame slots and
/// thunk fields remain outside this direct writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollDirectHeapFieldWrite {
    allocation_domain: HeapAllocationDomain,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement: ResolvedValueGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
}

impl AllocationCollectorPollDirectHeapFieldWrite {
    pub(crate) fn new(
        allocation_domain: HeapAllocationDomain,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        replacement: ResolvedValueGeneration,
        replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Self {
        Self {
            allocation_domain,
            writeback_object,
            field_index,
            source,
            replacement,
            replacement_request,
        }
    }

    const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    const fn field_index(&self) -> usize {
        self.field_index
    }

    const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
    }

    const fn replacement_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.replacement_request
    }
}

/// A summary of copied-object heap fields rewritten in evaluator storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollCopiedHeapFieldWriteReport {
    fields: usize,
}

impl AllocationCollectorPollCopiedHeapFieldWriteReport {
    fn record(&mut self) {
        self.fields = self.fields.saturating_add(1);
    }

    /// Returns the number of copied heap fields rewritten.
    pub(crate) const fn fields(self) -> usize {
        self.fields
    }
}

/// A summary of direct old-generation heap fields rewritten in evaluator storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AllocationCollectorPollDirectHeapFieldWriteReport {
    fields: usize,
}

impl AllocationCollectorPollDirectHeapFieldWriteReport {
    fn record(&mut self) {
        self.fields = self.fields.saturating_add(1);
    }

    /// Returns the number of direct heap fields rewritten.
    pub(crate) const fn fields(self) -> usize {
        self.fields
    }
}

/// Caller-owned buffers for applying an allocation-poll minor-GC commit plan.
pub struct AllocationCollectorPollMinorGcCommitBuffers<'a, 'bytes> {
    object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> AllocationCollectorPollMinorGcCommitBuffers<'a, 'bytes> {
    /// Creates caller-owned buffers for an allocation-poll commit application.
    pub fn new(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates caller-owned buffers plus a card table to clear after commit.
    pub fn with_card_table(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

/// Caller-owned destination storage and metadata for an allocation-poll commit plan.
pub struct AllocationCollectorPollMinorGcOwnedCommitBuffers<'a, 'bytes> {
    destination_storage: &'a mut MinorGcOwnedDestinationStorage,
    source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> AllocationCollectorPollMinorGcOwnedCommitBuffers<'a, 'bytes> {
    /// Creates owned destination storage and metadata for an allocation-poll commit.
    pub fn new(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates owned destination storage and metadata plus a card table to clear.
    pub fn with_card_table(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

impl EvalHeap {
    /// Creates a thunk-resolution write barrier for a source thunk.
    ///
    /// The returned adapter can be passed to
    /// [`crate::eval::thunk::ForceGuard::finish_with_barrier`] so the safe
    /// tree-walk thunk publication path records the same
    /// old-or-permanent to young edge that the future daemon collector needs.
    /// The adapter is source-specific: callers must pair it with the force guard
    /// for `source_thunk`, because the guard does not inspect the adapter's
    /// captured source address.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::ThunkResolveBarrierSourceNotThunk`] if
    /// `source_thunk` is not tagged as a thunk. Returns [`EvalHeapError`] if the
    /// source thunk does not belong to this heap, or if its runtime tag disagrees
    /// with the heap side table.
    pub fn thunk_resolve_write_barrier<'a>(
        &'a self,
        tier: GenerationalGcTier,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
    ) -> Result<EvalHeapThunkResolveBarrier<'a>, EvalHeapError> {
        self.thunk_resolve_write_barrier_with_optional_card_table(
            tier,
            source_thunk,
            remembered_set,
            None,
        )
    }

    /// Creates a card-table-aware thunk-resolution write barrier adapter.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::ThunkResolveBarrierSourceNotThunk`] if
    /// `source_thunk` is not tagged as a thunk. Returns [`EvalHeapError`] if the
    /// source thunk does not belong to this heap, or if its runtime tag disagrees
    /// with the heap side table.
    pub fn thunk_resolve_write_barrier_with_card_table<'a>(
        &'a self,
        tier: GenerationalGcTier,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Result<EvalHeapThunkResolveBarrier<'a>, EvalHeapError> {
        self.thunk_resolve_write_barrier_with_optional_card_table(
            tier,
            source_thunk,
            remembered_set,
            Some(card_table),
        )
    }

    fn thunk_resolve_write_barrier_with_optional_card_table<'a>(
        &'a self,
        tier: GenerationalGcTier,
        source_thunk: Value,
        remembered_set: &'a mut RememberedSet,
        card_table: Option<&'a mut GcCardTable>,
    ) -> Result<EvalHeapThunkResolveBarrier<'a>, EvalHeapError> {
        if source_thunk.tag() != ValueTag::Thunk {
            return Err(EvalHeapError::ThunkResolveBarrierSourceNotThunk {
                actual: source_thunk.tag(),
            });
        }
        let source_record = self.record_for_scannable_value(source_thunk)?;
        Ok(EvalHeapThunkResolveBarrier {
            heap: self,
            tier,
            source: gc_address_for_record(source_record)?,
            source_generation: generation_for_record(source_record),
            remembered_set,
            card_table,
            last_action: None,
        })
    }

    /// Returns permanent roots held by the heap's hash-cons tables.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if the root set length overflows or storage
    /// for another root cannot be reserved.
    pub fn interned_root_set(&self) -> Result<EvalRootSet, EvalRootSetError> {
        let mut roots = EvalRootSet::new();
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::String,
            self.string_cons.committed_entries(),
        )?;
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::Path,
            self.path_cons.committed_entries(),
        )?;
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::List,
            self.list_cons.committed_entries(),
        )?;
        self.push_interned_table_roots(
            &mut roots,
            InternedRootTable::Attrs,
            self.attrs_cons.committed_entries(),
        )?;
        Ok(roots)
    }

    /// Scans the heap graph reachable from explicit roots.
    ///
    /// Only evaluator-owned heap tags are accepted into [`EvalRootSet`], and
    /// only evaluator-owned child fields are emitted as edges. Inline integers,
    /// floats, booleans, nulls, and opaque external pointers are deliberately
    /// skipped so the collector does not retain by bit-pattern coincidence or
    /// chase heap handles owned by another runtime.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if a root or edge points
    /// outside this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if a
    /// value tag disagrees with the heap side-table record. Returns
    /// [`EvalHeapError::Environment`] if a captured frame cannot be read, and
    /// [`EvalHeapError::Thunk`] if a thunk state word is invalid. Returns a
    /// root-scan allocation error if scanner side tables cannot be reserved.
    pub fn scan_precise_roots(
        &self,
        root_set: &EvalRootSet,
    ) -> Result<PreciseHeapScan, EvalHeapError> {
        let mut scan = PreciseHeapScan::with_root_capacity(root_set.len())?;
        let mut worklist = VecDeque::new();
        worklist.try_reserve(root_set.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: WORKLIST_TABLE,
                entries: root_set.len(),
            }
        })?;
        let mut visited = HashSet::new();

        for root in root_set.roots() {
            scan.roots.push(root.clone());
            push_worklist(&mut worklist, root.value())?;
        }

        while let Some(value) = worklist.pop_front() {
            let (tag, ptr) = heap_ptr(value)?;
            let address = ptr.as_ptr() as usize;
            // Flat strings/paths (doc 30 FV-1) are edge-free leaf objects
            // outside the record table; validate them through the flat store
            // and emit the same empty-edge object scan a string record
            // produced before flattening.
            if self.shared.is_none() && matches!(tag, ValueTag::String | ValueTag::Path) {
                self.flat_verify(tag, ptr)?;
                if !push_visited(&mut visited, address)? {
                    continue;
                }
                push_object_scan(&mut scan.objects, HeapObjectScan::new(value, Vec::new()))?;
                continue;
            }
            // Flat lists (doc 30 FV-1) carry edges in their element spine:
            // synthesize the same `ListElement`-labelled edges a record scan
            // produced and keep traversing through them.
            if self.shared.is_none() && tag == ValueTag::List {
                let edges = self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?;
                if !push_visited(&mut visited, address)? {
                    continue;
                }
                for edge in &edges {
                    push_worklist(&mut worklist, edge.value())?;
                }
                push_object_scan(&mut scan.objects, HeapObjectScan::new(value, edges))?;
                continue;
            }
            // Flat attrsets (doc 30 FV-2) carry edges in their entry values:
            // synthesize the same `AttrBinding`-labelled edges a record scan
            // produced and keep traversing through them.
            if self.shared.is_none() && tag == ValueTag::Attrs {
                let edges = self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?;
                if !push_visited(&mut visited, address)? {
                    continue;
                }
                for edge in &edges {
                    push_worklist(&mut worklist, edge.value())?;
                }
                push_object_scan(&mut scan.objects, HeapObjectScan::new(value, edges))?;
                continue;
            }
            let record = self.record_or_unknown(tag, ptr)?;
            let actual = record.object.tag();
            if actual != tag {
                return Err(EvalHeapError::record_type_mismatch(tag, actual, ptr));
            }
            if !push_visited(&mut visited, address)? {
                continue;
            }

            let edges = self.scan_record_edges(record)?;
            for edge in &edges {
                push_worklist(&mut worklist, edge.value())?;
            }
            push_object_scan(&mut scan.objects, HeapObjectScan::new(value, edges))?;
        }

        Ok(scan)
    }

    /// Builds the precise heap graph for an allocation collector-poll request.
    ///
    /// This is a pre-collector snapshot: it validates and scans the supplied
    /// explicit roots, then pairs the resulting graph with the allocation
    /// safepoint poll request that triggered the scan. It does not invoke a
    /// collector, relocate objects, or retain mutable relocation slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if precise root scanning fails.
    pub fn scan_collector_poll_roots(
        &self,
        poll: AllocationCollectorPoll,
        root_set: &EvalRootSet,
    ) -> Result<AllocationCollectorPollScan, EvalHeapError> {
        let scan = self.scan_precise_roots(root_set)?;
        Ok(AllocationCollectorPollScan::new(
            poll,
            scan,
            self.scannable_object_count(),
            self.region_owner,
            self.worker_region_epoch,
            self.allocation_safepoints(),
            self.permanent_allocation_safepoints(),
        ))
    }

    /// Converts a collector-poll heap graph snapshot into a minor-GC plan.
    ///
    /// Worker-domain records are treated as current young-generation objects.
    /// Permanent shared records are treated as permanent objects. Remembered-set
    /// snapshots may carry old-worker or permanent-shared source edges to young
    /// targets, while permanent graph edges must be remembered explicitly. The
    /// method validates that the copied poll scan still matches current heap
    /// record edges before using current worker-domain field metadata for
    /// transitive minor-GC planning.
    ///
    /// This remains a planning bridge: it does not retain mutable root slots,
    /// rewrite fields, install forwarding pointers, or move object bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the poll scan is stale, if a remembered-set
    /// edge references an unknown object or is not old/permanent-to-young, if a
    /// visible permanent-to-young edge is missing from the remembered set, if
    /// copying the remembered-set snapshot cannot reserve storage, or if the
    /// minor-GC planner rejects the generated roots, age metadata, or field
    /// metadata.
    pub fn plan_collector_poll_minor_gc(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.plan_collector_poll_minor_gc_with_optional_card_table(
            poll_scan,
            remembered_set,
            None,
            collection_epoch,
            promotion_policy,
        )
    }

    /// Converts a collector-poll heap graph snapshot into a card-table-aware
    /// minor-GC plan.
    ///
    /// This performs the same planning work as [`Self::plan_collector_poll_minor_gc`]
    /// and additionally verifies that every remembered edge's source object is
    /// covered by the supplied dirty-card snapshot. It also captures an owned
    /// dirty-card snapshot and current old/permanent field metadata. Dirty
    /// old/permanent fields whose edge is absent from the remembered set seed the
    /// survivor frontier and get heap-backed reference slots for later rewrite
    /// metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::plan_collector_poll_minor_gc`]. Also returns
    /// [`EvalHeapError::MissingCollectorPollDirtyCard`] when a remembered edge
    /// is not covered by the dirty-card snapshot, or
    /// [`EvalHeapError::MissingCollectorPollRememberedEdge`] when an unremembered
    /// permanent-to-young edge is not covered by a dirty source card.
    pub fn plan_collector_poll_minor_gc_with_card_table(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: GcCardTableSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.plan_collector_poll_minor_gc_with_optional_card_table(
            poll_scan,
            remembered_set,
            Some(card_table),
            collection_epoch,
            promotion_policy,
        )
    }

    fn plan_collector_poll_minor_gc_with_optional_card_table(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: Option<GcCardTableSnapshot<'_>>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.validate_collector_poll_snapshot_allocation_state(poll_scan)?;
        self.validate_collector_poll_scan_is_current(poll_scan)?;
        self.validate_remembered_set_snapshot(remembered_set)?;
        if let Some(card_table) = card_table {
            self.validate_card_table_snapshot(remembered_set, card_table)?;
        }
        let roots = self.minor_gc_roots_for_poll_scan(poll_scan)?;
        let nursery_objects = self.current_nursery_objects()?;
        let nursery_fields = self.current_nursery_fields()?;
        let old_fields = self.current_old_fields()?;
        let remembered_set_for_plan = match card_table {
            Some(card_table) => Some(remembered_set_with_dirty_old_field_edges(
                remembered_set,
                card_table,
                &old_fields,
            )?),
            None => None,
        };
        let frontier_remembered_set = remembered_set_for_plan
            .as_ref()
            .map_or(remembered_set, RememberedSet::snapshot);
        let nursery_field_views = nursery_field_views(&nursery_fields)?;
        let plan = MinorGcPlan::from_roots_remembered_and_fields(
            roots.iter().copied(),
            frontier_remembered_set,
            collection_epoch,
            &nursery_objects,
            &nursery_field_views,
            promotion_policy,
        )?;
        match card_table {
            Some(card_table) => self
                .validate_current_permanent_edges_are_remembered_or_dirty_survivors(
                    remembered_set,
                    card_table,
                    &plan,
                )?,
            None => self.validate_current_permanent_edges_are_remembered(remembered_set)?,
        }
        let reference_slots = self.minor_gc_reference_slots_for_plan(
            poll_scan,
            remembered_set,
            card_table,
            &plan,
            &nursery_fields,
            &old_fields,
        )?;
        let card_table = match card_table {
            Some(card_table) => Some(owned_card_table_from_snapshot(card_table)?),
            None => None,
        };

        Ok(AllocationCollectorPollMinorGcPlan::new(
            poll_scan.poll(),
            poll_scan.heap_records(),
            poll_scan.worker_region_owner(),
            poll_scan.worker_region_epoch(),
            poll_scan.allocation_safepoints(),
            poll_scan.permanent_allocation_safepoints(),
            remembered_set_from_snapshot(remembered_set)?,
            card_table,
            roots,
            nursery_objects,
            nursery_fields,
            old_fields,
            reference_slots,
            plan,
        ))
    }

    /// Reserves scratch destination records for current young worker objects.
    ///
    /// This must run before the collector-poll scan and minor-GC plan that will
    /// consume the reservations. It records each current young worker-domain
    /// record's tag, allocates a fresh tag-compatible placeholder record,
    /// records the source-to-destination address mapping, and captures the
    /// post-reservation heap snapshot. A later call to
    /// [`Self::plan_collector_poll_minor_gc_reserved_relocation_destinations`]
    /// filters these reservations to the actual survivor frontier.
    ///
    /// Reserved records carry placeholder side-table bodies only to satisfy
    /// typed heap-record invariants before publication. The existing
    /// object-body/generation writer must still validate and install the planned
    /// relocated body before any root or field can publish the destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if reservation metadata cannot be allocated, if a
    /// current young record has no destination-record allocator, if a destination
    /// record allocation fails, or if a reserved destination value cannot be
    /// converted back into a heap address.
    pub fn reserve_current_young_minor_gc_destination_records(
        &mut self,
    ) -> Result<AllocationCollectorPollMinorGcDestinationRecordReservations, EvalHeapError> {
        let mut sources = Vec::new();
        for record in &self.records {
            if record.allocation_domain != HeapAllocationDomain::Worker
                || generation_for_record(record) != HeapGeneration::Young
                || record.is_retired()
            {
                continue;
            }

            let entries =
                sources
                    .len()
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                    })?;
            sources
                .try_reserve_exact(1)
                .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                    entries,
                })?;
            sources.push((gc_address_for_record(record)?, record.object.tag()));
        }

        let mut reservations = Vec::new();
        reservations.try_reserve_exact(sources.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                entries: sources.len(),
            }
        })?;

        for (source, tag) in sources {
            let destination_value = self.alloc_minor_gc_destination_record_like(source, tag)?;
            reservations.push(
                AllocationCollectorPollMinorGcDestinationRecordReservation::new(
                    source,
                    gc_address_for_value(destination_value)?,
                    destination_value,
                    tag,
                ),
            );
        }

        Ok(
            AllocationCollectorPollMinorGcDestinationRecordReservations::new(
                self.scannable_object_count(),
                self.region_owner,
                self.worker_region_epoch,
                self.allocation_safepoints(),
                self.permanent_allocation_safepoints(),
                reservations,
            ),
        )
    }

    /// Builds relocation destinations for a collector-poll minor-GC plan from
    /// current heap-record layout metadata.
    ///
    /// The helper rejects allocations after the minor-GC plan was built, derives
    /// one [`NurseryObjectLayout`] per planned survivor from the side table's
    /// recorded allocation size and alignment, then delegates destination
    /// allocation, placement, and materialization to the poll plan. It still does
    /// not reserve semispace pages, allocate destination objects, copy bytes, or
    /// update live evaluator slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after planning, if a planned survivor no longer belongs to
    /// this heap, if survivor-layout storage cannot be reserved, or if the
    /// lower-level relocation-destination planner rejects the derived layouts or
    /// destination bases.
    pub fn plan_collector_poll_minor_gc_relocation_destinations(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
        bases: MinorGcDestinationBases,
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, EvalHeapError> {
        self.validate_collector_poll_plan_allocation_state(plan)?;
        let nursery_layouts = self.nursery_layouts_for_minor_gc_plan(plan.plan())?;
        Ok(plan.relocation_destination_plan(&nursery_layouts, bases)?)
    }

    /// Builds relocation destinations from caller-supplied addresses.
    ///
    /// This helper has the same heap snapshot and survivor-layout validation as
    /// [`Self::plan_collector_poll_minor_gc_relocation_destinations`], but it
    /// accepts explicit destination addresses instead of contiguous
    /// generation-space bases. It is intended for future destination-record
    /// allocation code that obtains concrete heap addresses before commit
    /// metadata is built. It still does not allocate destination records, reserve
    /// semispace pages, copy bytes, or update live evaluator slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after planning, if a planned survivor no longer belongs to
    /// this heap, if survivor-layout storage cannot be reserved, if the explicit
    /// destination table is not a valid relocation map for `plan`, or if any
    /// destination address violates the source object's required alignment,
    /// overlaps another destination range, or overlaps a live source range.
    pub fn plan_collector_poll_minor_gc_explicit_relocation_destinations(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
        destinations: &[MinorGcRelocationDestination],
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, EvalHeapError> {
        self.validate_collector_poll_plan_allocation_state(plan)?;
        let nursery_layouts = self.nursery_layouts_for_minor_gc_plan(plan.plan())?;
        Ok(plan.explicit_relocation_destination_plan(&nursery_layouts, destinations)?)
    }

    /// Builds relocation destinations from pre-reserved destination records.
    ///
    /// `reservations` must come from
    /// [`Self::reserve_current_young_minor_gc_destination_records`] and `plan`
    /// must be built after that reservation without intervening heap allocation.
    /// Only reservations for actual survivors are consumed; reserved records for
    /// dead young objects remain ordinary unreferenced heap records.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `plan` is stale for the current heap, if
    /// `reservations` were captured for a different heap snapshot, if a survivor
    /// has no reserved destination record, if source or destination records no
    /// longer match their reservation metadata, or if the lower-level explicit
    /// relocation planner rejects the resulting destination table.
    pub fn plan_collector_poll_minor_gc_reserved_relocation_destinations(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
        reservations: &AllocationCollectorPollMinorGcDestinationRecordReservations,
    ) -> Result<AllocationCollectorPollMinorGcRelocationDestinations, EvalHeapError> {
        self.validate_collector_poll_plan_allocation_state(plan)?;
        validate_destination_reservation_snapshot_matches_plan(plan, reservations)?;
        let nursery_layouts = self.nursery_layouts_for_minor_gc_plan(plan.plan())?;
        let mut destinations = Vec::new();
        destinations
            .try_reserve_exact(plan.plan().survivors().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DESTINATION_RECORD_RESERVATIONS_TABLE,
                entries: plan.plan().survivors().len(),
            })?;

        for survivor in plan.plan().survivors() {
            let reservation = reservations
                .reservations()
                .iter()
                .copied()
                .find(|reservation| reservation.source() == survivor.address())
                .ok_or(
                    EvalHeapError::CollectorPollMinorGcDestinationReservationMissing {
                        source_address: survivor.address(),
                    },
                )?;
            self.validate_minor_gc_destination_record_reservation(reservation)?;
            destinations.push(MinorGcRelocationDestination::new(
                survivor.address(),
                reservation.destination(),
            ));
        }

        Ok(plan.explicit_relocation_destination_plan(&nursery_layouts, &destinations)?)
    }

    /// Derives object byte-copy requests for caller-owned copy buffers.
    ///
    /// Each request is validated against the current heap side table before it is
    /// returned: the source object must still belong to the young worker domain
    /// and must still have the size and alignment captured by the lower-level
    /// object-copy plan. The returned plan does not expose raw heap bytes or
    /// allocate destination storage; it only describes the source/destination,
    /// length, and alignment that a future storage owner must bind to
    /// [`MinorGcObjectByteCopyBuffer`] values.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if request storage cannot be reserved,
    /// if a planned source object no longer belongs to the young worker domain, or
    /// if the current source-record layout no longer matches the commit plan.
    pub fn collector_poll_minor_gc_object_byte_copy_plan(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let copies = commit_plan.commit_plan().object_copies().copies();
        let mut requests = Vec::new();
        requests.try_reserve_exact(copies.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_BYTE_COPY_REQUESTS_TABLE,
                entries: copies.len(),
            }
        })?;
        for copy in copies {
            let record = self.record_for_minor_gc_survivor(copy.source())?;
            validate_object_byte_copy_record_layout(*copy, record)?;
            requests.push(AllocationCollectorPollObjectByteCopyRequest::from_copy(
                *copy,
            ));
        }
        Ok(AllocationCollectorPollObjectByteCopyPlan::new(requests))
    }

    /// Applies heap-record generation writes for relocated destinations.
    ///
    /// Each source must still be a current young survivor, and each destination
    /// address must already belong to a heap record in this evaluator side
    /// table. The full plan is validated before any record generation is
    /// changed, so an unknown source or destination leaves all records
    /// unchanged. This only writes generation metadata on existing heap records;
    /// it does not allocate destination records, bind object bytes to heap
    /// storage, rewrite references, install forwarding headers, publish
    /// remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if planned scratch storage cannot be reserved,
    /// if a source is unknown or no longer young, or if a destination address
    /// does not belong to this heap.
    pub fn apply_collector_poll_minor_gc_object_generation_writes(
        &mut self,
        plan: &AllocationCollectorPollObjectGenerationWritePlan,
    ) -> Result<AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError> {
        let planned = self.stage_collector_poll_minor_gc_object_generation_writes(plan)?;
        let report = plan.report();
        self.commit_collector_poll_minor_gc_object_generation_writes(planned);
        Ok(report)
    }

    fn stage_collector_poll_minor_gc_object_generation_writes(
        &self,
        plan: &AllocationCollectorPollObjectGenerationWritePlan,
    ) -> Result<Vec<(usize, HeapGeneration)>, EvalHeapError> {
        let mut planned = Vec::new();
        planned
            .try_reserve_exact(plan.writes().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
                entries: plan.writes().len(),
            })?;

        for write in plan.writes().iter().copied() {
            let _ = self.record_index_for_minor_gc_survivor(write.source())?;
            let Some(destination_index) = self
                .records
                .index_of_address(write.destination().address_bits())
            else {
                return Err(
                    EvalHeapError::UnknownCollectorPollObjectGenerationDestination {
                        destination: write.destination(),
                    },
                );
            };
            planned.push((destination_index, write.generation()));
        }

        Ok(planned)
    }

    fn commit_collector_poll_minor_gc_object_generation_writes(
        &mut self,
        planned: Vec<(usize, HeapGeneration)>,
    ) {
        for (destination_index, generation) in planned {
            self.records[destination_index].generation = generation;
        }
    }

    /// Applies heap-record object-body writes for relocated destinations.
    ///
    /// The object-copy plan must also satisfy the same global invariants as a
    /// heap-record generation write plan: destination generation must agree with
    /// survivor action, sources and destinations must be unique, destinations must
    /// not be sources, and destinations must not overlap another survivor source.
    /// Each source must still be a current young survivor with the layout captured
    /// by the object-copy request, and each destination address must already
    /// belong to a heap record with the same layout. The full plan is validated
    /// before any destination body is changed, so an unknown source, unknown
    /// destination, duplicate/overlapping copy identity, or stale layout leaves all
    /// records unchanged. This writes the typed evaluator object body and
    /// body-owned cache metadata on existing heap records; it assumes callers pass
    /// unaliased collector-owned destination records because this side table does
    /// not yet model semispace ownership. It does not allocate destination records,
    /// write generation metadata, rewrite references, install forwarding headers,
    /// publish remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the object-copy plan violates generation-write
    /// identity invariants, if planned scratch storage cannot be reserved, if a
    /// source is unknown or no longer young, if a source or destination layout no
    /// longer matches the object-copy request, or if a destination address does not
    /// belong to this heap.
    pub fn apply_collector_poll_minor_gc_object_body_writes(
        &mut self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<AllocationCollectorPollObjectBodyWriteReport, EvalHeapError> {
        let (planned, report) = self.stage_collector_poll_minor_gc_object_body_writes(plan)?;
        self.commit_collector_poll_minor_gc_object_body_writes(planned);
        Ok(report)
    }

    /// Validates paired heap-record body and generation writes without mutation.
    ///
    /// This stages the same object-body and generation writes as
    /// [`Self::apply_collector_poll_minor_gc_object_body_and_generation_writes`],
    /// then drops the staged writes instead of committing them. It is intended as
    /// a commit-orchestration preflight for callers that need to prove the
    /// existing-destination heap records can accept relocated object bodies and
    /// generation metadata before starting a larger mutation sequence. It does
    /// not allocate destination records, rewrite references, install forwarding
    /// headers, publish remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::apply_collector_poll_minor_gc_object_body_and_generation_writes`].
    /// Whether this returns `Ok` or `Err`, heap-record object bodies and
    /// generation metadata are left unchanged.
    pub fn validate_collector_poll_minor_gc_object_body_and_generation_writes(
        &self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let generation_plan = plan.object_generation_write_plan()?;
        let (_body_writes, body_write_report) =
            self.stage_collector_poll_minor_gc_object_body_writes(plan)?;
        let _generation_writes =
            self.stage_collector_poll_minor_gc_object_generation_writes(&generation_plan)?;
        let generation_write_report = generation_plan.report();

        Ok(
            AllocationCollectorPollObjectBodyAndGenerationWriteReport::new(
                body_write_report,
                generation_write_report,
            ),
        )
    }

    /// Applies paired heap-record body and generation writes for relocated destinations.
    ///
    /// This validates the same invariants as
    /// [`Self::apply_collector_poll_minor_gc_object_body_writes`] and
    /// [`Self::apply_collector_poll_minor_gc_object_generation_writes`] before
    /// mutating either object bodies or generation metadata. It only applies writes
    /// to destination records that already exist in this evaluator heap side table;
    /// it does not allocate destination records, rewrite references, install
    /// forwarding headers, publish remembered sets, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the object-copy plan violates generation-write
    /// identity invariants, if planned scratch storage cannot be reserved, if a
    /// source is unknown or no longer young, if a source or destination layout no
    /// longer matches the object-copy request, or if a destination address does not
    /// belong to this heap. When an error is returned, neither object bodies nor
    /// generation metadata are changed.
    pub fn apply_collector_poll_minor_gc_object_body_and_generation_writes(
        &mut self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let generation_plan = plan.object_generation_write_plan()?;
        let (body_writes, body_write_report) =
            self.stage_collector_poll_minor_gc_object_body_writes(plan)?;
        let generation_writes =
            self.stage_collector_poll_minor_gc_object_generation_writes(&generation_plan)?;
        let generation_write_report = generation_plan.report();

        self.commit_collector_poll_minor_gc_object_body_writes(body_writes);
        self.commit_collector_poll_minor_gc_object_generation_writes(generation_writes);

        Ok(
            AllocationCollectorPollObjectBodyAndGenerationWriteReport::new(
                body_write_report,
                generation_write_report,
            ),
        )
    }

    fn stage_collector_poll_minor_gc_object_body_writes(
        &self,
        plan: &AllocationCollectorPollObjectByteCopyPlan,
    ) -> Result<
        (
            Vec<CollectorPollObjectBodyWrite>,
            AllocationCollectorPollObjectBodyWriteReport,
        ),
        EvalHeapError,
    > {
        let _ = plan.object_generation_write_plan()?;
        let mut planned = Vec::new();
        planned
            .try_reserve_exact(plan.requests().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OBJECT_BODY_WRITES_TABLE,
                entries: plan.requests().len(),
            })?;

        let mut report = AllocationCollectorPollObjectBodyWriteReport::default();
        for request in plan.requests().iter().copied() {
            let source_index = self.record_index_for_minor_gc_survivor(request.source())?;
            validate_object_byte_copy_request_source_record_layout(
                request,
                &self.records[source_index],
            )?;
            let Some(destination_index) = self
                .records
                .index_of_address(request.destination().address_bits())
            else {
                return Err(EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                    destination: request.destination(),
                });
            };
            validate_object_body_write_destination_record_layout(
                request,
                &self.records[destination_index],
            )?;

            let source = &self.records[source_index];
            let source_address = source.ptr.as_ptr() as usize;
            planned.push(CollectorPollObjectBodyWrite {
                destination_index,
                object: source.object.clone(),
                layout: source.layout,
                structural_hash: source.structural_hash,
                value_hash: self.records.cold_value_hash(source_address),
                captured_value_hash: self.records.cold_captured_value_hash(source_address),
            });
            report.record(request);
        }

        Ok((planned, report))
    }

    fn commit_collector_poll_minor_gc_object_body_writes(
        &mut self,
        planned: Vec<CollectorPollObjectBodyWrite>,
    ) {
        for write in planned {
            let address = self.records[write.destination_index].ptr.as_ptr() as usize;
            let destination = &mut self.records[write.destination_index];
            destination.object = write.object;
            destination.layout = write.layout;
            destination.structural_hash = write.structural_hash;
            self.records.set_cold_value_hash(address, write.value_hash);
            self.records
                .set_cold_captured_value_hash(address, write.captured_value_hash);
        }
    }

    /// Creates object-copy metadata for existing test heap records.
    ///
    /// The request uses the source record's current layout and the destination
    /// implied by `action`, so tests can exercise object-body writers without
    /// reaching into heap record internals.
    #[cfg(test)]
    pub(crate) fn collector_poll_minor_gc_object_byte_copy_request_for_test(
        &self,
        source: Value,
        destination: Value,
        action: MinorGcSurvivorAction,
    ) -> Result<AllocationCollectorPollObjectByteCopyRequest, EvalHeapError> {
        let source_record = self.record_for_scannable_value(source)?;
        let destination_record = self.record_for_scannable_value(destination)?;
        Ok(AllocationCollectorPollObjectByteCopyRequest::for_test(
            gc_address_for_record(source_record)?,
            gc_address_for_record(destination_record)?,
            action,
            generation_for_destination_action(action),
            source_record.layout.size_bytes,
            source_record.layout.align,
        ))
    }

    /// Validates that a relocated destination heap record has a bound object body.
    ///
    /// The source must still be a young survivor, source and destination layouts
    /// must match the object-copy request, both records must carry `tag`, and the
    /// destination body must be representation-equivalent to the source body. This
    /// is the side-table body binding check used by narrow live-root writeback
    /// applicators after [`Self::apply_collector_poll_minor_gc_object_body_writes`]
    /// has installed destination bodies.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if either heap record is missing, if the source is
    /// no longer young, if either layout is stale, if a record tag disagrees with
    /// `tag`, or if the destination object body does not match the source body.
    pub fn validate_collector_poll_minor_gc_object_body_binding(
        &self,
        request: AllocationCollectorPollObjectByteCopyRequest,
        tag: ValueTag,
    ) -> Result<(), EvalHeapError> {
        let source_index = self.record_index_for_minor_gc_survivor(request.source())?;
        let source = &self.records[source_index];
        validate_object_byte_copy_request_source_record_layout(request, source)?;
        if source.object.tag() != tag {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: request.source(),
                destination: request.destination(),
                reason: "source record tag does not match root writeback tag",
            });
        }

        let Some(destination) = self
            .records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == request.destination().address_bits())
        else {
            return Err(EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: request.destination(),
            });
        };
        validate_object_body_write_destination_record_layout(request, destination)?;
        if destination.object.tag() != tag {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: request.source(),
                destination: request.destination(),
                reason: "destination record tag does not match root writeback tag",
            });
        }
        if !heap_object_value_raw_eq(&source.object, &destination.object) {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: request.source(),
                destination: request.destination(),
                reason: "destination record body does not match source record body",
            });
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn apply_collector_poll_minor_gc_copied_heap_field_writes(
        &mut self,
        writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    ) -> Result<AllocationCollectorPollCopiedHeapFieldWriteReport, EvalHeapError> {
        let (planned, report) =
            self.plan_collector_poll_minor_gc_copied_heap_field_writes(writes)?;
        let (staged, staged_environment) =
            self.stage_collector_poll_minor_gc_copied_heap_field_writes(&planned)?;
        let staged_structural = self.stage_structural_writebacks(&staged, &[], &[])?;
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged);
        staged_environment.commit();
        self.commit_structural_writebacks(staged_structural);

        Ok(report)
    }

    fn plan_collector_poll_minor_gc_copied_heap_field_writes(
        &self,
        writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    ) -> Result<
        (
            Vec<CollectorPollCopiedHeapFieldWrite>,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_copied_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollCopiedHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| copied_heap_field_write_identity_matches(existing, write))
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                        index,
                        allocation_domain: write.allocation_domain(),
                        writeback_object: write.writeback_object(),
                        field_index: write.field_index(),
                        field_source: write.source().clone(),
                    },
                );
            }
            planned.push(self.plan_collector_poll_minor_gc_copied_heap_field_write(write)?);
            report.record();
        }

        Ok((planned, report))
    }

    fn plan_collector_poll_minor_gc_copied_heap_field_write(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<CollectorPollCopiedHeapFieldWrite, EvalHeapError> {
        self.validate_copied_heap_field_write_requests(write)?;

        let writeback_request = write.writeback_object_request();
        let writeback_tag = self.object_body_binding_tag(writeback_request)?;
        self.validate_collector_poll_minor_gc_object_body_binding(
            writeback_request,
            writeback_tag,
        )?;
        self.validate_copied_heap_field_writeback_generation(write)?;

        let record_index = self.record_index_for_reference_slot_object(write.writeback_object())?;
        let record = &self.records[record_index];
        let edges = self.scan_record_edges(record)?;
        let Some(edge) = edges.get(write.field_index()) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: None,
            });
        };
        if edge.source() != write.source() {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: Some(edge.source().clone()),
            });
        }

        let expected = ResolvedValueGeneration::Heap {
            address: write.replacement_request().source(),
            generation: HeapGeneration::Young,
        };
        let actual = self.resolved_generation_for_value(edge.value())?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollCopiedHeapFieldWriteValueMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    expected,
                    actual,
                },
            );
        }

        let replacement_tag = edge.value().tag();
        self.validate_collector_poll_minor_gc_object_body_binding(
            write.replacement_request(),
            replacement_tag,
        )?;
        self.validate_copied_heap_field_replacement_generation(write)?;
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        validate_copied_heap_field_write_object_source(&record.object, write)?;

        Ok(CollectorPollCopiedHeapFieldWrite {
            record_index,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            base_object: None,
        })
    }

    fn plan_collector_poll_minor_gc_copied_heap_field_writes_for_live_destinations(
        &self,
        writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    ) -> Result<
        (
            Vec<CollectorPollCopiedHeapFieldWrite>,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_copied_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollCopiedHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| copied_heap_field_write_identity_matches(existing, write))
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                        index,
                        allocation_domain: write.allocation_domain(),
                        writeback_object: write.writeback_object(),
                        field_index: write.field_index(),
                        field_source: write.source().clone(),
                    },
                );
            }
            planned.push(
                self.plan_collector_poll_minor_gc_copied_heap_field_write_for_live_destination(
                    write,
                )?,
            );
            report.record();
        }

        Ok((planned, report))
    }

    fn plan_collector_poll_minor_gc_copied_heap_field_write_for_live_destination(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<CollectorPollCopiedHeapFieldWrite, EvalHeapError> {
        self.validate_copied_heap_field_write_requests(write)?;

        let destination_index =
            self.record_index_for_reference_slot_object(write.writeback_object())?;
        let validation_index =
            self.record_index_for_reference_slot_object(write.validation_object())?;
        let record = &self.records[validation_index];
        let edges = self.scan_record_edges(record)?;
        let Some(edge) = edges.get(write.field_index()) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: None,
            });
        };
        if edge.source() != write.source() {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: Some(edge.source().clone()),
            });
        }

        let expected = ResolvedValueGeneration::Heap {
            address: write.replacement_request().source(),
            generation: HeapGeneration::Young,
        };
        let actual = self.resolved_generation_for_value(edge.value())?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollCopiedHeapFieldWriteValueMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    expected,
                    actual,
                },
            );
        }

        let replacement_tag = edge.value().tag();
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        validate_copied_heap_field_write_object_source(&record.object, write)?;

        Ok(CollectorPollCopiedHeapFieldWrite {
            record_index: destination_index,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            base_object: Some(record.object.clone()),
        })
    }

    #[cfg(test)]
    fn stage_collector_poll_minor_gc_copied_heap_field_writes(
        &self,
        writes: &[CollectorPollCopiedHeapFieldWrite],
    ) -> Result<(Vec<(usize, HeapObjectValue)>, EnvironmentWritebackStage), EvalHeapError> {
        let mut staged: Vec<(usize, HeapObjectValue)> = Vec::new();
        staged.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;
        let mut staged_environment = EnvironmentWritebackStage::try_new(writes.len()).map_err(
            |_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            },
        )?;

        self.stage_collector_poll_minor_gc_copied_heap_field_writes_into(
            writes,
            &mut staged,
            &mut staged_environment,
            writes.len(),
        )?;

        Ok((staged, staged_environment))
    }

    fn stage_collector_poll_minor_gc_copied_heap_field_writes_into(
        &self,
        writes: &[CollectorPollCopiedHeapFieldWrite],
        staged: &mut Vec<(usize, HeapObjectValue)>,
        staged_environment: &mut EnvironmentWritebackStage,
        entries: usize,
    ) -> Result<(), EvalHeapError> {
        for write in writes {
            let object = self
                .staged_collector_poll_minor_gc_heap_field_write_object_mut_with_base(
                    staged,
                    write.record_index,
                    write.base_object.as_ref(),
                    MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                    entries,
                )?;
            stage_record_owned_heap_field_write(
                object,
                &write.source,
                write.replacement,
                staged_environment,
            )
            .map_err(|error| copied_heap_field_write_object_error(write, error))?;
        }

        Ok(())
    }

    fn validate_copied_heap_field_write_requests(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let writeback_request = write.writeback_object_request();
        if writeback_request.source() != write.validation_object() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
                    allocation_domain: write.allocation_domain(),
                    validation_object: write.validation_object(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    actual_source: writeback_request.source(),
                },
            );
        }
        if writeback_request.destination() != write.writeback_object() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestDestinationMismatch {
                    allocation_domain: write.allocation_domain(),
                    validation_object: write.validation_object(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    request_destination: writeback_request.destination(),
                },
            );
        }
        let _ = validate_object_byte_copy_request_destination_generation(writeback_request)?;

        let replacement_request = write.replacement_request();
        let ResolvedValueGeneration::Heap {
            address: replacement,
            generation,
        } = write.replacement()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    value: write.replacement(),
                },
            );
        };
        if replacement_request.destination() != replacement {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteReplacementRequestDestinationMismatch {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    binding_replacement: replacement,
                    request_destination: replacement_request.destination(),
                },
            );
        }
        let expected_generation =
            validate_object_byte_copy_request_destination_generation(replacement_request)?;
        if generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    expected: expected_generation,
                    actual: generation,
                    action: replacement_request.action(),
                },
            );
        }
        Ok(())
    }

    fn validate_copied_heap_field_writeback_generation(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let expected = write.writeback_object_request().destination_generation();
        let actual =
            self.generation_for_address(write.writeback_object(), "heap-field writeback object")?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollCopiedHeapFieldWriteObjectGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    expected,
                    actual,
                },
            );
        }
        Ok(())
    }

    fn validate_copied_heap_field_replacement_generation(
        &self,
        write: &AllocationCollectorPollCopiedHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let ResolvedValueGeneration::Heap {
            address: replacement,
            generation: expected,
        } = write.replacement()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    value: write.replacement(),
                },
            );
        };
        let actual = self.generation_for_address(replacement, "heap-field replacement")?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollCopiedHeapFieldWriteReplacementGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    expected,
                    actual,
                },
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn apply_collector_poll_minor_gc_direct_heap_field_writes(
        &mut self,
        writes: &[AllocationCollectorPollDirectHeapFieldWrite],
    ) -> Result<AllocationCollectorPollDirectHeapFieldWriteReport, EvalHeapError> {
        let (planned, report) =
            self.plan_collector_poll_minor_gc_direct_heap_field_writes(writes, false)?;
        let (
            staged,
            staged_flat_lists,
            staged_flat_attrs,
            staged_environment,
            staged_structural,
        ) =
            self.stage_collector_poll_minor_gc_direct_heap_field_writes(&planned)?;
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged);
        self.commit_collector_poll_minor_gc_staged_flat_list_writes(staged_flat_lists);
        self.commit_collector_poll_minor_gc_staged_flat_attrs_writes(staged_flat_attrs);
        staged_environment.commit();
        self.commit_structural_writebacks(staged_structural);

        Ok(report)
    }

    #[cfg(test)]
    pub(crate) fn apply_collector_poll_minor_gc_heap_field_writes(
        &mut self,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
    ) -> Result<
        (
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        self.apply_collector_poll_minor_gc_heap_field_writes_with_optional_barriers(
            copied_writes,
            direct_writes,
            None,
        )
    }

    pub(crate) fn apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
        &mut self,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> Result<
        (
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        self.apply_collector_poll_minor_gc_heap_field_writes_with_optional_barriers(
            copied_writes,
            direct_writes,
            Some((remembered_set, card_table)),
        )
    }

    pub(crate) fn apply_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
        &mut self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> Result<
        (
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        let staged = self.stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            object_body_plan,
            copied_writes,
            direct_writes,
            remembered_set,
            card_table,
        )?;
        Ok(
            self.commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
                staged,
                remembered_set,
                card_table,
            ),
        )
    }

    pub(crate) fn validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
        &self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &RememberedSet,
        card_table: &GcCardTable,
    ) -> Result<
        (
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        let staged = self.stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            object_body_plan,
            copied_writes,
            direct_writes,
            remembered_set,
            card_table,
        )?;

        Ok((
            staged.object_body_and_generation_write_report(),
            staged.copied_report(),
            staged.direct_report(),
        ))
    }

    /// Stages live object, field, remembered-set, and card-table writes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if object-body, generation, field, or barrier
    /// staging fails. The evaluator heap and supplied side tables are left
    /// unchanged when an error is returned.
    pub(crate) fn stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
        &self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        remembered_set: &RememberedSet,
        card_table: &GcCardTable,
    ) -> Result<AllocationCollectorPollLiveHeapFieldWriteStage, EvalHeapError> {
        validate_collector_poll_minor_gc_heap_field_write_request_invariants(
            copied_writes,
            direct_writes,
        )?;
        let generation_plan = object_body_plan.object_generation_write_plan()?;
        let (object_body_writes, body_write_report) =
            self.stage_collector_poll_minor_gc_object_body_writes(object_body_plan)?;
        let object_generation_writes =
            self.stage_collector_poll_minor_gc_object_generation_writes(&generation_plan)?;
        let generation_write_report = generation_plan.report();
        let (planned_copied, copied_report) = self
            .plan_collector_poll_minor_gc_copied_heap_field_writes_for_live_destinations(
                copied_writes,
            )?;
        let (planned_direct, direct_report) = self
            .plan_collector_poll_minor_gc_direct_heap_field_writes_for_live_destinations(
                direct_writes,
                true,
            )?;
        let entries = copied_writes.len().checked_add(direct_writes.len()).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            },
        )?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(entries)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            })?;
        let mut staged_flat_lists: Vec<(NonNull<HeapObject>, NixList)> = Vec::new();
        let mut staged_flat_attrs: Vec<(NonNull<HeapObject>, FlatAttrs)> = Vec::new();
        let mut staged_environment = EnvironmentWritebackStage::try_new(entries).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            }
        })?;
        self.stage_collector_poll_minor_gc_copied_heap_field_writes_into(
            &planned_copied,
            &mut staged,
            &mut staged_environment,
            entries,
        )?;
        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &planned_direct,
            &mut staged,
            &mut staged_flat_lists,
            &mut staged_flat_attrs,
            &mut staged_environment,
            entries,
        )?;
        let staged_structural_writebacks = self.stage_structural_writebacks(
            &staged,
            &staged_flat_lists,
            &staged_flat_attrs,
        )?;
        let staged_barriers = self.stage_collector_poll_minor_gc_direct_heap_field_write_barriers(
            &planned_direct,
            remembered_set,
            card_table,
        )?;

        Ok(AllocationCollectorPollLiveHeapFieldWriteStage {
            object_body_writes,
            object_generation_writes,
            staged_heap_field_writes: staged,
            staged_flat_list_writes: staged_flat_lists,
            staged_flat_attrs_writes: staged_flat_attrs,
            staged_environment_writes: staged_environment,
            staged_structural_writebacks,
            staged_barriers,
            object_body_and_generation_write_report:
                AllocationCollectorPollObjectBodyAndGenerationWriteReport::new(
                    body_write_report,
                    generation_write_report,
                ),
            copied_report,
            direct_report,
        })
    }

    /// Commits prevalidated live heap-field writes and staged side-table changes.
    pub(crate) fn commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
        &mut self,
        staged: AllocationCollectorPollLiveHeapFieldWriteStage,
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> (
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        AllocationCollectorPollCopiedHeapFieldWriteReport,
        AllocationCollectorPollDirectHeapFieldWriteReport,
    ) {
        let AllocationCollectorPollLiveHeapFieldWriteStage {
            object_body_writes,
            object_generation_writes,
            staged_heap_field_writes,
            staged_flat_list_writes,
            staged_flat_attrs_writes,
            staged_environment_writes,
            staged_structural_writebacks,
            staged_barriers,
            object_body_and_generation_write_report,
            copied_report,
            direct_report,
        } = staged;

        self.commit_collector_poll_minor_gc_object_body_writes(object_body_writes);
        self.commit_collector_poll_minor_gc_object_generation_writes(object_generation_writes);
        if let Some((staged_remembered_set, staged_card_table)) = staged_barriers {
            *remembered_set = staged_remembered_set;
            *card_table = staged_card_table;
        }
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged_heap_field_writes);
        self.commit_collector_poll_minor_gc_staged_flat_list_writes(staged_flat_list_writes);
        self.commit_collector_poll_minor_gc_staged_flat_attrs_writes(staged_flat_attrs_writes);
        staged_environment_writes.commit();
        self.commit_structural_writebacks(staged_structural_writebacks);

        (
            object_body_and_generation_write_report,
            copied_report,
            direct_report,
        )
    }

    fn apply_collector_poll_minor_gc_heap_field_writes_with_optional_barriers(
        &mut self,
        copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
        direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        barrier_targets: Option<(&mut RememberedSet, &mut GcCardTable)>,
    ) -> Result<
        (
            AllocationCollectorPollCopiedHeapFieldWriteReport,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_heap_field_write_request_invariants(
            copied_writes,
            direct_writes,
        )?;
        let allow_young_direct_replacements = barrier_targets.is_some();
        let (planned_copied, copied_report) =
            self.plan_collector_poll_minor_gc_copied_heap_field_writes(copied_writes)?;
        let (planned_direct, direct_report) = self
            .plan_collector_poll_minor_gc_direct_heap_field_writes(
                direct_writes,
                allow_young_direct_replacements,
            )?;

        let entries = copied_writes.len().checked_add(direct_writes.len()).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
            },
        )?;
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(entries)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            })?;
        let mut staged_flat_lists: Vec<(NonNull<HeapObject>, NixList)> = Vec::new();
        let mut staged_flat_attrs: Vec<(NonNull<HeapObject>, FlatAttrs)> = Vec::new();
        let mut staged_environment = EnvironmentWritebackStage::try_new(entries).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries,
            }
        })?;
        self.stage_collector_poll_minor_gc_copied_heap_field_writes_into(
            &planned_copied,
            &mut staged,
            &mut staged_environment,
            entries,
        )?;
        self.stage_collector_poll_minor_gc_direct_heap_field_writes_into(
            &planned_direct,
            &mut staged,
            &mut staged_flat_lists,
            &mut staged_flat_attrs,
            &mut staged_environment,
            entries,
        )?;
        let staged_structural = self.stage_structural_writebacks(
            &staged,
            &staged_flat_lists,
            &staged_flat_attrs,
        )?;

        if let Some((remembered_set, card_table)) = barrier_targets {
            self.record_collector_poll_minor_gc_direct_heap_field_write_barriers(
                &planned_direct,
                remembered_set,
                card_table,
            )?;
        }
        self.commit_collector_poll_minor_gc_staged_heap_field_writes(staged);
        self.commit_collector_poll_minor_gc_staged_flat_list_writes(staged_flat_lists);
        self.commit_collector_poll_minor_gc_staged_flat_attrs_writes(staged_flat_attrs);
        staged_environment.commit();
        self.commit_structural_writebacks(staged_structural);

        Ok((copied_report, direct_report))
    }

    fn plan_collector_poll_minor_gc_direct_heap_field_writes(
        &self,
        writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        allow_young_replacements: bool,
    ) -> Result<
        (
            Vec<CollectorPollDirectHeapFieldWrite>,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_direct_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollDirectHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| direct_heap_field_write_identity_matches(existing, write))
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                        index,
                        allocation_domain: write.allocation_domain(),
                        writeback_object: write.writeback_object(),
                        field_index: write.field_index(),
                        field_source: write.source().clone(),
                    },
                );
            }
            planned.push(self.plan_collector_poll_minor_gc_direct_heap_field_write(
                write,
                allow_young_replacements,
            )?);
            report.record();
        }

        Ok((planned, report))
    }

    fn plan_collector_poll_minor_gc_direct_heap_field_write(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        allow_young_replacements: bool,
    ) -> Result<CollectorPollDirectHeapFieldWrite, EvalHeapError> {
        self.validate_direct_heap_field_write_requests(write, allow_young_replacements)?;

        let target = self.heap_field_write_target_for_reference_slot_object(write.writeback_object())?;
        let edges = match target {
            HeapFieldWriteTarget::Record(record_index) => {
                let record = &self.records[record_index];
                self.validate_direct_heap_field_writeback_generation(write, record)?;
                self.scan_record_edges(record)?
            }
            HeapFieldWriteTarget::FlatList(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?
            }
        };
        let Some(edge) = edges.get(write.field_index()) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: None,
            });
        };
        if edge.source() != write.source() {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: Some(edge.source().clone()),
            });
        }

        let expected = ResolvedValueGeneration::Heap {
            address: write.replacement_request().source(),
            generation: HeapGeneration::Young,
        };
        let actual = self.resolved_generation_for_value(edge.value())?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    expected,
                    actual,
                },
            );
        }

        let replacement_tag = edge.value().tag();
        self.validate_collector_poll_minor_gc_object_body_binding(
            write.replacement_request(),
            replacement_tag,
        )?;
        self.validate_direct_heap_field_replacement_generation(write)?;
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        match target {
            HeapFieldWriteTarget::Record(record_index) => {
                validate_direct_heap_field_write_object_source(
                    &self.records[record_index].object,
                    write,
                )?;
            }
            HeapFieldWriteTarget::FlatList(_) => {
                validate_flat_list_direct_heap_field_write_source(write)?;
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                validate_flat_attrs_direct_heap_field_write_source(
                    self.flat_attrs_payload(ptr)?,
                    write,
                )?;
            }
        }
        let remembered_edge = match write.replacement() {
            ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } => Some(RememberedEdge::new(write.writeback_object(), target)),
            ResolvedValueGeneration::Inline | ResolvedValueGeneration::Heap { .. } => None,
        };

        Ok(CollectorPollDirectHeapFieldWrite {
            target,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            remembered_edge,
        })
    }

    /// Resolves a direct heap-field writeback object to its staged target.
    fn heap_field_write_target_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<HeapFieldWriteTarget, EvalHeapError> {
        if let Some(index) = self.records.index_of_address(address.address_bits()) {
            return Ok(HeapFieldWriteTarget::Record(index));
        }
        if let Some(ptr) = NonNull::new(address.address_bits() as *mut HeapObject) {
            if self.flat_lists.kind_of(ptr).is_some() {
                return Ok(HeapFieldWriteTarget::FlatList(ptr));
            }
            if self.flat_attrs.kind_of(ptr).is_some() {
                return Ok(HeapFieldWriteTarget::FlatAttrs(ptr));
            }
        }
        Err(EvalHeapError::UnknownCollectorPollReferenceSlotAddress { address })
    }

    /// Generation/domain validation for a flat direct writeback target.
    ///
    /// The flat analog of `validate_direct_heap_field_writeback_generation`:
    /// flat lists and attrsets are permanent-shared by construction.
    fn validate_flat_direct_heap_field_writeback_generation(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let expected = expected_direct_heap_field_write_generation(write.allocation_domain());
        let actual = HeapGeneration::Permanent;
        if write.allocation_domain() != HeapAllocationDomain::PermanentShared
            || actual != expected
        {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    expected,
                    actual,
                },
            );
        }

        Ok(())
    }

    fn plan_collector_poll_minor_gc_direct_heap_field_writes_for_live_destinations(
        &self,
        writes: &[AllocationCollectorPollDirectHeapFieldWrite],
        allow_young_replacements: bool,
    ) -> Result<
        (
            Vec<CollectorPollDirectHeapFieldWrite>,
            AllocationCollectorPollDirectHeapFieldWriteReport,
        ),
        EvalHeapError,
    > {
        validate_collector_poll_minor_gc_direct_heap_field_write_request_invariants(writes)?;

        let mut planned = Vec::new();
        planned.try_reserve_exact(writes.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writes.len(),
            }
        })?;

        let mut report = AllocationCollectorPollDirectHeapFieldWriteReport::default();
        for (index, write) in writes.iter().enumerate() {
            if writes[..index]
                .iter()
                .any(|existing| direct_heap_field_write_identity_matches(existing, write))
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                        index,
                        allocation_domain: write.allocation_domain(),
                        writeback_object: write.writeback_object(),
                        field_index: write.field_index(),
                        field_source: write.source().clone(),
                    },
                );
            }
            planned.push(
                self.plan_collector_poll_minor_gc_direct_heap_field_write_for_live_destination(
                    write,
                    allow_young_replacements,
                )?,
            );
            report.record();
        }

        Ok((planned, report))
    }

    fn plan_collector_poll_minor_gc_direct_heap_field_write_for_live_destination(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        allow_young_replacements: bool,
    ) -> Result<CollectorPollDirectHeapFieldWrite, EvalHeapError> {
        self.validate_direct_heap_field_write_requests(write, allow_young_replacements)?;

        let target = self.heap_field_write_target_for_reference_slot_object(write.writeback_object())?;
        let edges = match target {
            HeapFieldWriteTarget::Record(record_index) => {
                let record = &self.records[record_index];
                self.validate_direct_heap_field_writeback_generation(write, record)?;
                self.scan_record_edges(record)?
            }
            HeapFieldWriteTarget::FlatList(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                self.validate_flat_direct_heap_field_writeback_generation(write)?;
                self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?
            }
        };
        let Some(edge) = edges.get(write.field_index()) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: None,
            });
        };
        if edge.source() != write.source() {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index: write.field_index(),
                expected: write.source().clone(),
                actual: Some(edge.source().clone()),
            });
        }

        let expected = ResolvedValueGeneration::Heap {
            address: write.replacement_request().source(),
            generation: HeapGeneration::Young,
        };
        let actual = self.resolved_generation_for_value(edge.value())?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteValueMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    expected,
                    actual,
                },
            );
        }

        let replacement_tag = edge.value().tag();
        let replacement_value =
            value_for_resolved_generation(replacement_tag, write.replacement())?;
        match target {
            HeapFieldWriteTarget::Record(record_index) => {
                validate_direct_heap_field_write_object_source(
                    &self.records[record_index].object,
                    write,
                )?;
            }
            HeapFieldWriteTarget::FlatList(_) => {
                validate_flat_list_direct_heap_field_write_source(write)?;
            }
            HeapFieldWriteTarget::FlatAttrs(ptr) => {
                validate_flat_attrs_direct_heap_field_write_source(
                    self.flat_attrs_payload(ptr)?,
                    write,
                )?;
            }
        }
        let remembered_edge = match write.replacement() {
            ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } => Some(RememberedEdge::new(write.writeback_object(), target)),
            ResolvedValueGeneration::Inline | ResolvedValueGeneration::Heap { .. } => None,
        };

        Ok(CollectorPollDirectHeapFieldWrite {
            target,
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            source: write.source().clone(),
            replacement: replacement_value,
            remembered_edge,
        })
    }

    pub(super) fn stage_collector_poll_minor_gc_direct_heap_field_writes_into(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
        staged: &mut Vec<(usize, HeapObjectValue)>,
        staged_flat_lists: &mut Vec<(NonNull<HeapObject>, NixList)>,
        staged_flat_attrs: &mut Vec<(NonNull<HeapObject>, FlatAttrs)>,
        staged_environment: &mut EnvironmentWritebackStage,
        entries: usize,
    ) -> Result<(), EvalHeapError> {
        for write in writes {
            match write.target {
                HeapFieldWriteTarget::Record(record_index) => {
                    let object = self.staged_collector_poll_minor_gc_heap_field_write_object_mut(
                        staged,
                        record_index,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    stage_record_owned_heap_field_write(
                        object,
                        &write.source,
                        write.replacement,
                        staged_environment,
                    )
                    .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                }
                HeapFieldWriteTarget::FlatList(ptr) => {
                    let list = self.staged_flat_list_heap_field_write_object_mut(
                        staged_flat_lists,
                        ptr,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    *list = flat_list_heap_field_write_object(list, &write.source, write.replacement)
                        .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                }
                HeapFieldWriteTarget::FlatAttrs(ptr) => {
                    let metadata = self.flat_attrs_payload(ptr)?.metadata;
                    let attrs = self.staged_flat_attrs_heap_field_write_object_mut(
                        staged_flat_attrs,
                        ptr,
                        MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                        entries,
                    )?;
                    *attrs = flat_attrs_heap_field_write_object(
                        metadata,
                        attrs,
                        &write.source,
                        write.replacement,
                    )
                    .map_err(|error| direct_heap_field_write_object_error(write, error))?;
                }
            }
        }

        Ok(())
    }

    /// Returns the staged flat-list spine for `ptr`, cloning the live payload
    /// on first touch (the flat analog of the record staging buffer).
    fn staged_flat_list_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<(NonNull<HeapObject>, NixList)>,
        ptr: NonNull<HeapObject>,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut NixList, EvalHeapError> {
        if let Some(index) = staged.iter().position(|(existing, _)| *existing == ptr) {
            return Ok(&mut staged[index].1);
        }

        let base = self.flat_list_payload(ptr)?.clone();
        staged.push((ptr, base));
        let Some((_, list)) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(list)
    }

    /// Commits staged flat-list spines through the flat store's exclusive
    /// writeback door.
    ///
    /// # Panics
    ///
    /// Panics if a staged address no longer resolves as a flat list, which
    /// staging validated under the same exclusive borrow — the flat analog of
    /// the record commit's index panic on a broken commit invariant.
    fn commit_collector_poll_minor_gc_staged_flat_list_writes(
        &mut self,
        staged: Vec<(NonNull<HeapObject>, NixList)>,
    ) {
        for (ptr, list) in staged {
            if let Err(error) = self.flat_list_commit_writeback(ptr, list) {
                unreachable!("staged flat-list writeback failed to commit: {error}");
            }
        }
    }

    /// Returns the staged flat-attrs entry storage for `ptr`, cloning the
    /// live payload's entries on first touch (the flat analog of the record
    /// staging buffer; the payload metadata is immutable and never staged).
    fn staged_flat_attrs_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<(NonNull<HeapObject>, FlatAttrs)>,
        ptr: NonNull<HeapObject>,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut FlatAttrs, EvalHeapError> {
        if let Some(index) = staged.iter().position(|(existing, _)| *existing == ptr) {
            return Ok(&mut staged[index].1);
        }

        let base = self.flat_attrs_payload(ptr)?.attrs.clone();
        staged.push((ptr, base));
        let Some((_, attrs)) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(attrs)
    }

    /// Commits staged flat-attrs entry storage through the flat store's
    /// exclusive writeback door.
    ///
    /// # Panics
    ///
    /// Panics if a staged address no longer resolves as a flat attrset,
    /// which staging validated under the same exclusive borrow — the flat
    /// analog of the record commit's index panic on a broken commit
    /// invariant.
    fn commit_collector_poll_minor_gc_staged_flat_attrs_writes(
        &mut self,
        staged: Vec<(NonNull<HeapObject>, FlatAttrs)>,
    ) {
        for (ptr, attrs) in staged {
            if let Err(error) = self.flat_attrs_commit_writeback(ptr, attrs) {
                unreachable!("staged flat-attrs writeback failed to commit: {error}");
            }
        }
    }

    fn staged_collector_poll_minor_gc_heap_field_write_object_mut<'a>(
        &self,
        staged: &'a mut Vec<(usize, HeapObjectValue)>,
        record_index: usize,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut HeapObjectValue, EvalHeapError> {
        self.staged_collector_poll_minor_gc_heap_field_write_object_mut_with_base(
            staged,
            record_index,
            None,
            table,
            entries,
        )
    }

    fn staged_collector_poll_minor_gc_heap_field_write_object_mut_with_base<'a>(
        &self,
        staged: &'a mut Vec<(usize, HeapObjectValue)>,
        record_index: usize,
        base_object: Option<&HeapObjectValue>,
        table: &'static str,
        entries: usize,
    ) -> Result<&'a mut HeapObjectValue, EvalHeapError> {
        if let Some(index) = staged
            .iter()
            .position(|(existing, _)| *existing == record_index)
        {
            return Ok(&mut staged[index].1);
        }

        staged.push((
            record_index,
            base_object
                .cloned()
                .unwrap_or_else(|| self.records[record_index].object.clone()),
        ));
        let Some((_, object)) = staged.last_mut() else {
            return Err(EvalHeapError::RootScanAllocationFailed { table, entries });
        };
        Ok(object)
    }

    fn commit_collector_poll_minor_gc_staged_heap_field_writes(
        &mut self,
        staged: Vec<(usize, HeapObjectValue)>,
    ) {
        for (record_index, object) in staged {
            let address = self.records[record_index].ptr.as_ptr() as usize;
            let record = &mut self.records[record_index];
            record.object = object;
            record.structural_hash = None;
            self.records.clear_cold_hashes(address);
        }
    }

    fn record_collector_poll_minor_gc_direct_heap_field_write_barriers(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
        remembered_set: &mut RememberedSet,
        card_table: &mut GcCardTable,
    ) -> Result<(), EvalHeapError> {
        if let Some((staged_remembered_set, staged_card_table)) = self
            .stage_collector_poll_minor_gc_direct_heap_field_write_barriers(
                writes,
                remembered_set,
                card_table,
            )?
        {
            *remembered_set = staged_remembered_set;
            *card_table = staged_card_table;
        }
        Ok(())
    }

    fn stage_collector_poll_minor_gc_direct_heap_field_write_barriers(
        &self,
        writes: &[CollectorPollDirectHeapFieldWrite],
        remembered_set: &RememberedSet,
        card_table: &GcCardTable,
    ) -> Result<Option<(RememberedSet, GcCardTable)>, EvalHeapError> {
        if writes.iter().all(|write| write.remembered_edge.is_none()) {
            return Ok(None);
        }

        let mut staged_remembered_set =
            self.clone_remembered_set_for_direct_heap_field_write_barriers(remembered_set)?;
        let mut staged_card_table = card_table
            .try_clone()
            .map_err(EvalHeapError::GenerationalGc)?;
        for write in writes {
            let Some(edge) = write.remembered_edge else {
                continue;
            };
            staged_remembered_set
                .record(edge)
                .map_err(EvalHeapError::GenerationalGc)?;
            staged_card_table
                .mark_source(edge.source())
                .map_err(EvalHeapError::GenerationalGc)?;
        }

        Ok(Some((staged_remembered_set, staged_card_table)))
    }

    fn clone_remembered_set_for_direct_heap_field_write_barriers(
        &self,
        remembered_set: &RememberedSet,
    ) -> Result<RememberedSet, EvalHeapError> {
        let mut staged = RememberedSet::with_epoch(remembered_set.epoch());
        for edge in remembered_set.edges() {
            staged
                .record(*edge)
                .map_err(EvalHeapError::GenerationalGc)?;
        }
        Ok(staged)
    }

    fn validate_direct_heap_field_write_requests(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        allow_young_replacements: bool,
    ) -> Result<(), EvalHeapError> {
        let replacement_request = write.replacement_request();
        let ResolvedValueGeneration::Heap {
            address: replacement,
            generation,
        } = write.replacement()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    value: write.replacement(),
                },
            );
        };
        if replacement_request.destination() != replacement {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteReplacementRequestDestinationMismatch {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    binding_replacement: replacement,
                    request_destination: replacement_request.destination(),
                },
            );
        }
        let expected_generation =
            validate_object_byte_copy_request_destination_generation(replacement_request)?;
        if generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    expected: expected_generation,
                    actual: generation,
                    action: replacement_request.action(),
                },
            );
        }
        if generation != HeapGeneration::Old
            && !(allow_young_replacements && generation == HeapGeneration::Young)
        {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteYoungReplacementUnsupported {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    generation,
                },
            );
        }

        Ok(())
    }

    fn validate_direct_heap_field_writeback_generation(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
        record: &HeapRecord,
    ) -> Result<(), EvalHeapError> {
        let expected = expected_direct_heap_field_write_generation(write.allocation_domain());
        let actual = generation_for_record(record);
        if record.allocation_domain != write.allocation_domain() || actual != expected {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteObjectGenerationMismatch {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    expected,
                    actual,
                },
            );
        }

        Ok(())
    }

    fn validate_direct_heap_field_replacement_generation(
        &self,
        write: &AllocationCollectorPollDirectHeapFieldWrite,
    ) -> Result<(), EvalHeapError> {
        let ResolvedValueGeneration::Heap {
            address: replacement,
            generation: expected,
        } = write.replacement()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    value: write.replacement(),
                },
            );
        };
        let actual = self.generation_for_address(replacement, "heap-field replacement")?;
        if actual != expected {
            return Err(
                EvalHeapError::CollectorPollDirectHeapFieldWriteReplacementGenerationMismatch {
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    replacement,
                    expected,
                    actual,
                },
            );
        }
        Ok(())
    }

    fn object_body_binding_tag(
        &self,
        request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Result<ValueTag, EvalHeapError> {
        let source = self.record_for_minor_gc_survivor(request.source())?;
        Ok(source.object.tag())
    }

    /// Returns the live side-table forwarding value installed for `address`.
    ///
    /// This exposes evaluator-owned forwarding metadata used by the tree-walk
    /// GC-stress bridge. It does not read an ABI object header or prove that
    /// destination object storage has been allocated.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `address` does not belong to this heap.
    pub fn minor_gc_forwarding_value_at(
        &self,
        address: GcHeapAddress,
    ) -> Result<Option<ResolvedValueGeneration>, EvalHeapError> {
        Ok(self
            .record_for_gc_address(address, "forwarding source")?
            .minor_gc_forwarding
            .get())
    }

    fn alloc_minor_gc_destination_record_like(
        &mut self,
        source: GcHeapAddress,
        tag: ValueTag,
    ) -> Result<Value, EvalHeapError> {
        if matches!(tag, ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk) {
            self.alloc_minor_gc_destination_worker_record(source, tag)
        } else {
            Err(
                EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                    source_address: source,
                    tag,
                },
            )
        }
    }

    fn validate_minor_gc_destination_record_reservation(
        &self,
        reservation: AllocationCollectorPollMinorGcDestinationRecordReservation,
    ) -> Result<(), EvalHeapError> {
        let source = self.record_for_minor_gc_survivor(reservation.source())?;
        let Some(destination) = self
            .records
            .record_at_address(reservation.destination().address_bits())
        else {
            return Err(EvalHeapError::UnknownCollectorPollObjectBodyDestination {
                destination: reservation.destination(),
            });
        };

        if source.object.tag() != reservation.tag() || destination.object.tag() != reservation.tag()
        {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                source_address: reservation.source(),
                destination: reservation.destination(),
                reason: "reserved destination record tag does not match source record tag",
            });
        }
        if !heap_record_layout_matches(
            destination.layout,
            source.layout.size_bytes,
            source.layout.align,
        ) {
            return Err(EvalHeapError::CollectorPollObjectBodyWriteLayoutMismatch {
                address: reservation.destination(),
                expected_size: source.layout.size_bytes,
                actual_size: destination.layout.size_bytes,
                expected_align: source.layout.align,
                actual_align: destination.layout.align,
            });
        }

        Ok(())
    }

    /// Returns every installed live side-table forwarding value.
    ///
    /// This exposes evaluator-owned forwarding metadata used by the tree-walk
    /// GC-stress bridge. It snapshots occupied side-table cells in heap-record
    /// order, and does not read ABI object headers, prove destination storage
    /// exists, or validate destination generations.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding value storage cannot be reserved
    /// or a heap record cannot be converted back into a GC address.
    pub fn minor_gc_forwarding_values(
        &self,
    ) -> Result<Vec<AllocationCollectorPollForwardingValue>, EvalHeapError> {
        let forwarding_value_count = self
            .records
            .iter()
            .filter(|record| record.minor_gc_forwarding.get().is_some())
            .count();
        let mut forwarding_values = Vec::new();
        forwarding_values
            .try_reserve_exact(forwarding_value_count)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_FORWARDING_VALUES_TABLE,
                entries: forwarding_value_count,
            })?;

        for record in &self.records {
            let Some(forwarded_value) = record.minor_gc_forwarding.get() else {
                continue;
            };
            forwarding_values.push(AllocationCollectorPollForwardingValue::new(
                gc_address_for_record(record)?,
                forwarded_value,
            ));
        }

        Ok(forwarding_values)
    }

    /// Installs live side-table forwarding values for a minor-GC commit.
    ///
    /// Each supplied slot must be occupied, must name a current young
    /// worker-domain source object, and that object's live forwarding cell must
    /// still be empty. All slots are validated before any heap record is
    /// mutated, so validation failures leave every forwarding cell unchanged.
    /// This is an evaluator side-table bridge for GC-stress execution; it does
    /// not write ABI object headers, copy object bytes, rewrite roots or fields,
    /// publish remembered sets, clear card-table storage, or manage semispaces.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a slot is empty, duplicated, references an
    /// unknown or non-young source object, or if the source object's forwarding
    /// cell is already occupied.
    pub fn install_collector_poll_minor_gc_forwarding_slots(
        &mut self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<AllocationCollectorPollForwardingInstallReport, EvalHeapError> {
        let staged = self.stage_collector_poll_minor_gc_forwarding_slots(slots)?;
        Ok(self.commit_collector_poll_minor_gc_staged_forwarding_slots(staged))
    }

    /// Validates live evaluator heap forwarding slots without installing them.
    ///
    /// This performs the same checks as
    /// [`Self::install_collector_poll_minor_gc_forwarding_slots`] while leaving
    /// every source object's forwarding cell unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a slot is empty, duplicated, references an
    /// unknown or non-young source object, or if the source object's forwarding
    /// cell is already occupied.
    pub fn validate_collector_poll_minor_gc_forwarding_slots(
        &self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<AllocationCollectorPollForwardingInstallReport, EvalHeapError> {
        let staged = self.stage_collector_poll_minor_gc_forwarding_slots(slots)?;
        Ok(staged.report())
    }

    /// Stages live evaluator heap forwarding slots without installing them.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::install_collector_poll_minor_gc_forwarding_slots`].
    pub(crate) fn stage_collector_poll_minor_gc_forwarding_slots(
        &self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<AllocationCollectorPollForwardingInstallStage, EvalHeapError> {
        let planned = self.collector_poll_minor_gc_forwarding_slot_plan(slots)?;
        Ok(AllocationCollectorPollForwardingInstallStage { planned })
    }

    /// Commits a prevalidated evaluator heap forwarding slot stage.
    pub(crate) fn commit_collector_poll_minor_gc_staged_forwarding_slots(
        &mut self,
        staged: AllocationCollectorPollForwardingInstallStage,
    ) -> AllocationCollectorPollForwardingInstallReport {
        let report = staged.report();
        for (record_index, _, forwarded) in staged.planned {
            self.records[record_index]
                .minor_gc_forwarding
                .set(Some(forwarded));
        }
        report
    }

    fn collector_poll_minor_gc_forwarding_slot_plan(
        &self,
        slots: &[MinorGcForwardingSlot],
    ) -> Result<Vec<(usize, GcHeapAddress, ResolvedValueGeneration)>, EvalHeapError> {
        let mut planned = Vec::new();
        planned.try_reserve_exact(slots.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries: slots.len(),
            }
        })?;

        for (index, slot) in slots.iter().copied().enumerate() {
            let Some(forwarded) = slot.forwarded_value() else {
                return Err(EvalHeapError::CollectorPollForwardingSlotEmpty {
                    index,
                    address: slot.source(),
                });
            };
            if planned.iter().any(
                |(_, source, _): &(usize, GcHeapAddress, ResolvedValueGeneration)| {
                    *source == slot.source()
                },
            ) {
                return Err(EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
                    index,
                    address: slot.source(),
                });
            }

            let record_index = self.record_index_for_minor_gc_survivor(slot.source())?;
            if let Some(actual) = self.records[record_index].minor_gc_forwarding.get() {
                return Err(EvalHeapError::GenerationalGc(
                    GenerationalGcError::MinorGcForwardingPointerSlotOccupied {
                        index,
                        address: slot.source(),
                        actual,
                    },
                ));
            }
            planned.push((record_index, slot.source(), forwarded));
        }

        Ok(planned)
    }

    /// Derives a reference buffer for heap-field-backed commit slots.
    ///
    /// This is a live side-table binding precursor for remembered-source fields,
    /// dirty old fields, and copied nursery fields. It validates that each saved
    /// field index still points at the same [`HeapEdgeSource`] label before
    /// reading the current value. Copied tree-walk/JIT root slots are rejected
    /// because [`EvalHeap`] does not own their mutable storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if any reference slot is root-backed,
    /// if a saved field object no longer belongs to the heap, if a saved field
    /// index or label is stale, if current field scanning fails, or if the
    /// reference buffer cannot reserve storage.
    pub fn collector_poll_minor_gc_heap_field_reference_buffer(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let reference_slots = commit_plan.reference_slots();
        let mut references = Vec::new();
        references
            .try_reserve_exact(reference_slots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_REFERENCE_BUFFER_TABLE,
                entries: reference_slots.len(),
            })?;
        for (index, slot) in reference_slots.iter().enumerate() {
            references.push(self.current_heap_field_reference_value(index, slot.source())?);
        }
        Ok(references)
    }

    /// Derives a complete commit reference buffer in copied slot order.
    ///
    /// `root_values` must contain one current root value for every copied root
    /// reference slot in [`AllocationCollectorPollMinorGcCommitPlan::reference_slots`]
    /// order, including roots that will not be rewritten by the lower-level
    /// reference-rewrite plan. Heap-field-backed slots are read and revalidated
    /// from the current typed heap side table. The returned buffer is caller-owned
    /// and suitable for the reference slice passed to
    /// [`AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if the caller supplies too few or too
    /// many root values, if a supplied root source or value no longer matches the
    /// copied reference slot, if a heap-field slot is stale, or if the reference
    /// buffer cannot reserve storage.
    pub fn collector_poll_minor_gc_reference_buffer(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
        root_values: &[AllocationCollectorPollRootReferenceValue],
    ) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let reference_slots = commit_plan.reference_slots();
        let expected_roots = reference_slots.iter().filter(|slot| slot.is_root()).count();
        if root_values.len() != expected_roots {
            return Err(
                EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
                    expected: expected_roots,
                    actual: root_values.len(),
                },
            );
        }

        let mut references = Vec::new();
        references
            .try_reserve_exact(reference_slots.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_REFERENCE_BUFFER_TABLE,
                entries: reference_slots.len(),
            })?;

        let mut root_index = 0usize;
        for (index, slot) in reference_slots.iter().enumerate() {
            let value = match slot.source() {
                AllocationCollectorPollReferenceSource::Root { source } => {
                    let Some(root_value) = root_values.get(root_index) else {
                        return Err(
                            EvalHeapError::CollectorPollRootReferenceValueLengthMismatch {
                                expected: expected_roots,
                                actual: root_values.len(),
                            },
                        );
                    };
                    root_index =
                        root_index
                            .checked_add(1)
                            .ok_or(EvalHeapError::RootScanLengthOverflow {
                                table: MINOR_GC_REFERENCE_BUFFER_TABLE,
                            })?;
                    if root_value.source() != source {
                        return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                            index,
                            expected: source.clone(),
                            actual: root_value.source().clone(),
                        });
                    }
                    root_value.value()
                }
                _ => self.current_heap_field_reference_value(index, slot.source())?,
            };
            let expected = slot.value();
            if value != expected {
                return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                    index,
                    expected,
                    actual: value,
                });
            }
            references.push(value);
        }

        Ok(references)
    }

    /// Derives writeback metadata for heap-field-backed minor-GC rewrites.
    ///
    /// The returned plan contains only remembered-source, dirty old-field, and
    /// nursery-field slots that the lower-level commit plan will rewrite. Root
    /// slots are skipped because their mutable storage is owned by the active
    /// tree-walk/JIT safepoint machinery, not by [`EvalHeap`]. Every heap-field
    /// slot is re-read from the current typed side table before it is admitted
    /// so stale field labels or changed field values fail before a future
    /// mutating writeback.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if writeback storage cannot be
    /// reserved, if a saved field object no longer belongs to the heap, if a saved
    /// field index or label is stale, if a copied slot no longer matches its
    /// lower-level rewrite, or if the current field value no longer matches the
    /// copied poll slot value.
    pub fn collector_poll_minor_gc_heap_field_writeback_plan(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<AllocationCollectorPollHeapFieldWritebackPlan, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let rewrites = commit_plan.commit_plan().reference_rewrites().rewrites();
        let reference_slots = commit_plan.reference_slots();
        let mut writebacks = Vec::new();
        writebacks.try_reserve_exact(rewrites.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries: rewrites.len(),
            }
        })?;

        for rewrite in rewrites {
            let slot_index = rewrite.slot();
            let Some(slot) = reference_slots.get(slot_index) else {
                let expected =
                    slot_index
                        .checked_add(1)
                        .ok_or(EvalHeapError::RootScanLengthOverflow {
                            table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                        })?;
                return Err(
                    EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                        expected,
                        actual: reference_slots.len(),
                    },
                );
            };
            let Some((validation_object, writeback_object, field_index, source)) =
                heap_field_writeback_source(
                    slot.source(),
                    commit_plan.commit_plan().object_copies(),
                )?
            else {
                continue;
            };
            let expected = validate_reference_slot_matches_rewrite(slot_index, slot, *rewrite)?;
            let actual = self.current_heap_field_reference_value_at(
                slot_index,
                validation_object,
                field_index,
                source,
            )?;
            if actual != expected {
                return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
                    index: slot_index,
                    expected,
                    actual,
                });
            }
            writebacks.push(AllocationCollectorPollHeapFieldWriteback::new(
                slot_index,
                validation_object,
                writeback_object,
                field_index,
                source.clone(),
                expected,
                rewrite.replacement(),
            ));
        }

        Ok(AllocationCollectorPollHeapFieldWritebackPlan::new(
            writebacks,
        ))
    }

    /// Reads current heap-field values for a derived writeback plan.
    ///
    /// The returned slots preserve the plan's writeback order and copied field
    /// labels, but their values come from the current typed heap side table. This
    /// lets higher-level safepoint bridges validate caller-owned heap-field
    /// buffers immediately before applying reference writebacks.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if slot storage cannot be reserved, if a saved
    /// field object no longer belongs to the heap, if a saved field index or
    /// label is stale, or if the current field value cannot be classified.
    pub fn collector_poll_minor_gc_heap_field_writeback_slots(
        &self,
        plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    ) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
        let writebacks = plan.writebacks();
        let mut slots = Vec::new();
        slots.try_reserve_exact(writebacks.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE,
                entries: writebacks.len(),
            }
        })?;

        for writeback in writebacks {
            let value = self.current_heap_field_reference_value_at(
                writeback.slot(),
                writeback.validation_object(),
                writeback.field_index(),
                writeback.source(),
            )?;
            slots.push(AllocationCollectorPollHeapFieldWritebackSlot::new(
                writeback.validation_object(),
                writeback.writeback_object(),
                writeback.field_index(),
                writeback.source().clone(),
                value,
            ));
        }

        Ok(slots)
    }

    pub(crate) fn collector_poll_minor_gc_live_heap_field_write_inputs(
        &self,
        object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
        plan: &AllocationCollectorPollHeapFieldWritebackPlan,
    ) -> Result<
        (
            Vec<AllocationCollectorPollCopiedHeapFieldWrite>,
            Vec<AllocationCollectorPollDirectHeapFieldWrite>,
        ),
        EvalHeapError,
    > {
        let writebacks = plan.writebacks();
        let mut copied_writes = Vec::new();
        let mut direct_writes = Vec::new();
        copied_writes
            .try_reserve_exact(writebacks.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_COPIED_HEAP_FIELD_WRITES_TABLE,
                entries: writebacks.len(),
            })?;
        direct_writes
            .try_reserve_exact(writebacks.len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_DIRECT_HEAP_FIELD_WRITES_TABLE,
                entries: writebacks.len(),
            })?;

        for writeback in writebacks {
            let allocation_domain = self.allocation_domain_for_address(
                writeback.validation_object(),
                "heap-field writeback validation object",
            )?;
            let replacement_request = object_copy_request_for_reference_writeback(
                object_body_plan,
                writeback.slot(),
                writeback.expected(),
                writeback.replacement(),
            )?;
            if writeback.validation_object() == writeback.writeback_object() {
                direct_writes.push(AllocationCollectorPollDirectHeapFieldWrite::new(
                    allocation_domain,
                    writeback.writeback_object(),
                    writeback.field_index(),
                    writeback.source().clone(),
                    writeback.replacement(),
                    replacement_request,
                ));
            } else {
                let writeback_object_request = object_copy_request_for_reference_writeback_address(
                    object_body_plan,
                    writeback.slot(),
                    writeback.validation_object(),
                    writeback.writeback_object(),
                )?;
                copied_writes.push(AllocationCollectorPollCopiedHeapFieldWrite::new(
                    allocation_domain,
                    writeback.validation_object(),
                    writeback.writeback_object(),
                    writeback.field_index(),
                    writeback.source().clone(),
                    writeback.replacement(),
                    replacement_request,
                    writeback_object_request,
                ));
            }
        }

        validate_collector_poll_minor_gc_reference_writeback_direct_destination_aliases(
            object_body_plan,
            &direct_writes,
        )?;

        Ok((copied_writes, direct_writes))
    }

    /// Derives all root-backed and heap-field-backed reference writebacks.
    ///
    /// This composes [`AllocationCollectorPollMinorGcCommitPlan::root_writeback_plan`]
    /// with [`Self::collector_poll_minor_gc_heap_field_writeback_plan`]. Root
    /// writebacks remain metadata for externally owned tree-walk/JIT slots, while
    /// heap-field writebacks are revalidated against current typed heap fields.
    /// The helper still does not mutate live roots or heap objects.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the heap record count or allocation-safepoint
    /// state changed after commit planning, if root writeback metadata cannot be
    /// built, or if heap-field writeback validation fails.
    pub fn collector_poll_minor_gc_reference_writeback_plan(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<AllocationCollectorPollReferenceWritebackPlan, EvalHeapError> {
        self.validate_collector_poll_commit_allocation_state(commit_plan)?;
        let root_writebacks = commit_plan.root_writeback_plan()?;
        let heap_field_writebacks =
            self.collector_poll_minor_gc_heap_field_writeback_plan(commit_plan)?;
        Ok(AllocationCollectorPollReferenceWritebackPlan::new(
            root_writebacks,
            heap_field_writebacks,
        ))
    }

    fn push_interned_table_roots<'a>(
        &self,
        roots: &mut EvalRootSet,
        table: InternedRootTable,
        values: impl Iterator<Item = (&'a HotXxh3Hash, usize, &'a Value)>,
    ) -> Result<(), EvalRootSetError> {
        let mut entries = Vec::new();
        for (hash, bucket_index, value) in values {
            let requested = entries
                .len()
                .checked_add(1)
                .ok_or(EvalRootSetError::LengthOverflow)?;
            entries
                .try_reserve_exact(1)
                .map_err(|_| EvalRootSetError::AllocationFailed { roots: requested })?;
            entries.push((*hash, bucket_index, *value));
        }
        entries.sort_by_key(|(hash, bucket_index, _value)| (*hash, *bucket_index));
        for (index, (_hash, _bucket_index, value)) in entries.into_iter().enumerate() {
            roots.try_push_interned(table, index, value)?;
        }
        Ok(())
    }

    pub(super) fn scan_record_edges(
        &self,
        record: &HeapRecord,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        match &record.object {
            HeapObjectValue::String(_) => {}
            HeapObjectValue::List(list) => {
                for (index, value) in list.iter().copied().enumerate() {
                    push_heap_edge(&mut edges, HeapEdgeSource::ListElement { index }, value)?;
                }
            }
            HeapObjectValue::Lambda(lambda) => {
                push_capture_edges(
                    &mut edges,
                    CapturedRootOwner::Lambda,
                    lambda.env(),
                    lambda.with_scope_env(),
                    lambda.scoped_global_env(),
                )?;
            }
            HeapObjectValue::Primop(primop) => {
                for (index, arg) in primop.args().iter().enumerate() {
                    push_heap_edge(
                        &mut edges,
                        HeapEdgeSource::PrimopArgument { index },
                        arg.value(),
                    )?;
                }
            }
            HeapObjectValue::Thunk(thunk) => match thunk.cell().state()? {
                ThunkState::Suspended | ThunkState::Blackhole => {
                    push_thunk_kind_edges(&mut edges, thunk.kind())?;
                    push_parallel_thunk_payload_edge(&mut edges, thunk)?;
                }
                ThunkState::Forced => {
                    if let Some(value) = thunk.cell().cached_value()? {
                        push_heap_edge(&mut edges, HeapEdgeSource::ThunkCachedResult, value)?;
                    }
                    push_parallel_thunk_payload_edge(&mut edges, thunk)?;
                }
            },
            // Retired slots are unreachable through resolution (their index
            // entries were removed at retirement); a scan can only reach one
            // through a stale root, which must fail loudly.
            HeapObjectValue::Retired { tag } => {
                return Err(EvalHeapError::UnknownPointer {
                    tag: *tag,
                    address: record.ptr.as_ptr() as usize,
                });
            }
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a flat list's element spine.
    ///
    /// The flat analog of the [`HeapObjectValue::List`] arm of
    /// [`EvalHeap::scan_record_edges`]: one `ListElement`-labelled edge per
    /// scannable element, in element order, so every consumer (sweep seeding,
    /// pop validation, poll snapshots, staleness comparison) observes the
    /// identical edge stream a record-backed list produced.
    pub(super) fn scan_flat_list_edges(
        &self,
        list: &NixList,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        for (index, value) in list.iter().copied().enumerate() {
            push_heap_edge(&mut edges, HeapEdgeSource::ListElement { index }, value)?;
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a flat attrset's entry values.
    ///
    /// The flat analog of the [`HeapObjectValue::Attrs`] arm of
    /// [`EvalHeap::scan_record_edges`]: one `AttrBinding`-labelled edge per
    /// scannable entry, in symbol order with the payload's shape id, so
    /// every consumer (sweep seeding, pop validation, poll snapshots,
    /// staleness comparison) observes the identical edge stream a
    /// record-backed attrset produced.
    pub(super) fn scan_flat_attrs_edges(
        &self,
        payload: &FlatAttrsPayload,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        for (slot, entry) in payload.attrs.entries_by_symbol().iter().enumerate() {
            push_heap_edge(
                &mut edges,
                HeapEdgeSource::AttrBinding {
                    shape: payload.metadata.shape(),
                    slot,
                    key: entry.key,
                },
                entry.value,
            )?;
        }
        Ok(edges)
    }

    /// Synthesizes precise edges for a flat worker closure (doc 30 FV-3).
    ///
    /// The flat analog of the [`HeapObjectValue::Lambda`],
    /// [`HeapObjectValue::Primop`], and [`HeapObjectValue::Thunk`] arms of
    /// [`EvalHeap::scan_record_edges`], so every consumer (sweep marking, pop
    /// validation) observes the identical edge stream a record-backed
    /// closure produced: capture edges for lambdas, `PrimopArgument` edges
    /// for builtins, and state-dependent thunk edges (kind captures while
    /// suspended or blackholed, the cached result once forced, plus the
    /// parallel payload edge in both states).
    ///
    /// # Errors
    ///
    /// A retired payload fails as [`EvalHeapError::UnknownPointer`] — a scan
    /// can only reach one through a stale root, which must fail loudly —
    /// and a released thunk's deferred work fails as
    /// [`EvalHeapError::ReleasedThunkWork`] exactly as the record arm did.
    pub(super) fn scan_flat_closure_edges(
        &self,
        ptr: NonNull<HeapObject>,
        payload: &FlatClosurePayload,
    ) -> Result<Vec<HeapEdge>, EvalHeapError> {
        let mut edges = Vec::new();
        match payload {
            FlatClosurePayload::Lambda(lambda) => {
                push_capture_edges(
                    &mut edges,
                    CapturedRootOwner::Lambda,
                    lambda.env(),
                    lambda.with_scope_env(),
                    lambda.scoped_global_env(),
                )?;
            }
            FlatClosurePayload::Primop(primop) => {
                for (index, arg) in primop.args().iter().enumerate() {
                    push_heap_edge(
                        &mut edges,
                        HeapEdgeSource::PrimopArgument { index },
                        arg.value(),
                    )?;
                }
            }
            FlatClosurePayload::Thunk(thunk) => match thunk.cell().state()? {
                ThunkState::Suspended | ThunkState::Blackhole => {
                    push_thunk_kind_edges(&mut edges, thunk.kind())?;
                    push_parallel_thunk_payload_edge(&mut edges, thunk)?;
                }
                ThunkState::Forced => {
                    if let Some(value) = thunk.cell().cached_value()? {
                        push_heap_edge(&mut edges, HeapEdgeSource::ThunkCachedResult, value)?;
                    }
                    push_parallel_thunk_payload_edge(&mut edges, thunk)?;
                }
            },
            FlatClosurePayload::Retired(tag) => {
                return Err(EvalHeapError::UnknownPointer {
                    tag: *tag,
                    address: ptr.as_ptr() as usize,
                });
            }
        }
        let (kind, owner) = match payload.tag() {
            ValueTag::Lambda => (FlatObjectKind::Lambda, CapturedRootOwner::Lambda),
            ValueTag::Thunk => (FlatObjectKind::Thunk, CapturedRootOwner::Thunk),
            _ => return Ok(edges),
        };
        if let Some(values) = self
            .flat_closures
            .value_tail(ptr, kind)
            .map_err(|error| self.closure_resolution_error(payload.tag(), ptr, error))?
        {
            for (index, value) in values.iter().copied().enumerate() {
                push_heap_edge(
                    &mut edges,
                    HeapEdgeSource::CapturedFlatEnv { owner, index },
                    value,
                )?;
            }
        }
        Ok(edges)
    }

    fn validate_collector_poll_scan_is_current(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<(), EvalHeapError> {
        for root in poll_scan.scan().roots() {
            self.validate_scannable_value(root.value())?;
        }

        for object in poll_scan.scan().objects() {
            let (tag, ptr) = heap_ptr(object.value())?;
            if self.shared.is_none() && matches!(tag, ValueTag::String | ValueTag::Path) {
                // Flat strings/paths are immutable, edge-free leaves; a scan
                // that recorded them with no edges is always current.
                self.flat_verify(tag, ptr)?;
                if !object.edges().is_empty() {
                    return Err(EvalHeapError::CollectorPollScanStaleObject {
                        address: gc_address_for_value(object.value())?,
                    });
                }
                continue;
            }
            if self.shared.is_none() && tag == ValueTag::List {
                // Flat lists carry edges; re-synthesize them and compare, the
                // exact staleness check a record-backed list received.
                let current_edges = self.scan_flat_list_edges(self.flat_list_payload(ptr)?)?;
                if current_edges != object.edges() {
                    return Err(EvalHeapError::CollectorPollScanStaleObject {
                        address: gc_address_for_value(object.value())?,
                    });
                }
                continue;
            }
            if self.shared.is_none() && tag == ValueTag::Attrs {
                // Flat attrsets carry edges; same staleness re-synthesis.
                let current_edges = self.scan_flat_attrs_edges(self.flat_attrs_payload(ptr)?)?;
                if current_edges != object.edges() {
                    return Err(EvalHeapError::CollectorPollScanStaleObject {
                        address: gc_address_for_value(object.value())?,
                    });
                }
                continue;
            }
            let record = self.record_for_scannable_value(object.value())?;
            let current_edges = self.scan_record_edges(record)?;
            if current_edges != object.edges() {
                return Err(EvalHeapError::CollectorPollScanStaleObject {
                    address: gc_address_for_value(object.value())?,
                });
            }
        }
        Ok(())
    }

    /// Returns the count of scannable typed objects (records plus flat).
    ///
    /// Collector-poll snapshots capture this count and staleness validation
    /// re-compares it, so any typed allocation — record-backed or flat —
    /// invalidates an outstanding snapshot exactly as string records did
    /// before FV-1.
    fn scannable_object_count(&self) -> usize {
        self.records
            .len()
            .saturating_add(self.flat.len())
            .saturating_add(self.flat_lists.len())
            .saturating_add(self.flat_attrs.len())
            .saturating_add(self.flat_closures.len())
    }

    /// Validates a scan root value against either heap domain.
    fn validate_scannable_value(&self, value: Value) -> Result<(), EvalHeapError> {
        let (tag, ptr) = heap_ptr(value)?;
        if self.shared.is_none()
            && matches!(
                tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            )
        {
            return self.flat_verify(tag, ptr);
        }
        self.record_for_scannable_value(value).map(|_| ())
    }

    fn validate_collector_poll_snapshot_allocation_state(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<(), EvalHeapError> {
        if poll_scan.heap_records() != self.scannable_object_count() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if poll_scan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        Ok(())
    }

    fn validate_remembered_set_snapshot(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
    ) -> Result<(), EvalHeapError> {
        for edge in remembered_set.edges() {
            let source_generation = self.generation_for_address(edge.source(), "source")?;
            let target_generation = self.generation_for_address(edge.target(), "target")?;
            if !matches!(
                source_generation,
                HeapGeneration::Old | HeapGeneration::Permanent
            ) || target_generation != HeapGeneration::Young
            {
                return Err(EvalHeapError::InvalidCollectorPollRememberedEdge {
                    source_address: edge.source(),
                    source_generation,
                    target_address: edge.target(),
                    target_generation,
                });
            }
        }
        Ok(())
    }

    fn validate_current_permanent_edges_are_remembered(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
    ) -> Result<(), EvalHeapError> {
        for record in &self.records {
            if generation_for_record(record) != HeapGeneration::Permanent {
                continue;
            }
            let source = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;

            for edge in edges {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if !remembered_set.edges().contains(&remembered_edge) {
                    return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                        source_address: source,
                        target_address: target,
                    });
                }
            }
        }
        // Flat lists and attrsets are permanent edge carriers (doc 30
        // FV-1/FV-2): their permanent-to-young edges must be remembered
        // exactly as record-backed permanent lists' and attrsets' edges were.
        for entry in self.flat_lists.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_list_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if !remembered_set.edges().contains(&remembered_edge) {
                    return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                        source_address: source,
                        target_address: target,
                    });
                }
            }
        }
        for entry in self.flat_attrs.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_attrs_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if !remembered_set.edges().contains(&remembered_edge) {
                    return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                        source_address: source,
                        target_address: target,
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_current_permanent_edges_are_remembered_or_dirty_survivors(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: GcCardTableSnapshot<'_>,
        plan: &MinorGcPlan,
    ) -> Result<(), EvalHeapError> {
        for record in &self.records {
            if generation_for_record(record) != HeapGeneration::Permanent {
                continue;
            }
            let source = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;

            for edge in edges {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if remembered_set.edges().contains(&remembered_edge) {
                    continue;
                }
                if card_table.covers_source(source)
                    && plan
                        .survivors()
                        .iter()
                        .any(|survivor| survivor.address() == target)
                {
                    continue;
                }
                return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                    source_address: source,
                    target_address: target,
                });
            }
        }
        // Flat lists and attrsets: same permanent-to-young coverage
        // requirement, with the same dirty-card survivor escape hatch.
        for entry in self.flat_lists.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_list_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if remembered_set.edges().contains(&remembered_edge) {
                    continue;
                }
                if card_table.covers_source(source)
                    && plan
                        .survivors()
                        .iter()
                        .any(|survivor| survivor.address() == target)
                {
                    continue;
                }
                return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                    source_address: source,
                    target_address: target,
                });
            }
        }
        for entry in self.flat_attrs.iter() {
            let source = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            for edge in self.scan_flat_attrs_edges(entry.object().payload())? {
                let target = self.resolved_generation_for_value(edge.value())?;
                let ResolvedValueGeneration::Heap {
                    address: target,
                    generation: HeapGeneration::Young,
                } = target
                else {
                    continue;
                };
                let remembered_edge = RememberedEdge::new(source, target);
                if remembered_set.edges().contains(&remembered_edge) {
                    continue;
                }
                if card_table.covers_source(source)
                    && plan
                        .survivors()
                        .iter()
                        .any(|survivor| survivor.address() == target)
                {
                    continue;
                }
                return Err(EvalHeapError::MissingCollectorPollRememberedEdge {
                    source_address: source,
                    target_address: target,
                });
            }
        }
        Ok(())
    }

    fn validate_card_table_snapshot(
        &self,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: GcCardTableSnapshot<'_>,
    ) -> Result<(), EvalHeapError> {
        for edge in remembered_set.edges() {
            if !card_table.covers_source(edge.source()) {
                return Err(EvalHeapError::MissingCollectorPollDirtyCard {
                    source_address: edge.source(),
                    target_address: edge.target(),
                    card_index: card_table.card_index_for_source(edge.source()),
                });
            }
        }
        Ok(())
    }

    fn minor_gc_roots_for_poll_scan(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(poll_scan.scan().roots().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_ROOTS_TABLE,
                entries: poll_scan.scan().roots().len(),
            })?;
        for root in poll_scan.scan().roots() {
            roots.push(self.resolved_generation_for_value(root.value())?);
        }
        Ok(roots)
    }

    fn current_nursery_objects(&self) -> Result<Vec<NurseryObjectAge>, EvalHeapError> {
        let mut nursery_objects = Vec::new();
        for record in &self.records {
            if generation_for_record(record) == HeapGeneration::Young {
                let entries = nursery_objects.len().checked_add(1).ok_or(
                    EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_NURSERY_OBJECTS_TABLE,
                    },
                )?;
                nursery_objects.try_reserve_exact(1).map_err(|_| {
                    EvalHeapError::RootScanAllocationFailed {
                        table: MINOR_GC_NURSERY_OBJECTS_TABLE,
                        entries,
                    }
                })?;
                nursery_objects.push(NurseryObjectAge::new(gc_address_for_record(record)?, 0));
            }
        }
        Ok(nursery_objects)
    }

    fn current_nursery_fields(
        &self,
    ) -> Result<Vec<AllocationCollectorPollNurseryFields>, EvalHeapError> {
        let mut nursery_fields = Vec::new();
        for record in &self.records {
            if generation_for_record(record) != HeapGeneration::Young {
                continue;
            }
            let address = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;
            let mut fields = Vec::new();
            fields.try_reserve_exact(edges.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_NURSERY_FIELD_VALUES_TABLE,
                    entries: edges.len(),
                }
            })?;
            for edge in edges {
                fields.push(AllocationCollectorPollNurseryField::new(
                    edge.source().clone(),
                    self.resolved_generation_for_value(edge.value())?,
                ));
            }

            let entries = nursery_fields.len().checked_add(1).ok_or(
                EvalHeapError::RootScanLengthOverflow {
                    table: MINOR_GC_NURSERY_FIELDS_TABLE,
                },
            )?;
            nursery_fields.try_reserve_exact(1).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_NURSERY_FIELDS_TABLE,
                    entries,
                }
            })?;
            nursery_fields.push(AllocationCollectorPollNurseryFields::new(address, fields)?);
        }
        Ok(nursery_fields)
    }

    fn current_old_fields(&self) -> Result<Vec<AllocationCollectorPollOldFields>, EvalHeapError> {
        let mut old_fields = Vec::new();
        for record in &self.records {
            let generation = generation_for_record(record);
            if !matches!(generation, HeapGeneration::Old | HeapGeneration::Permanent) {
                continue;
            }
            let address = gc_address_for_record(record)?;
            let edges = self.scan_record_edges(record)?;
            let mut fields = Vec::new();
            fields.try_reserve_exact(edges.len()).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_OLD_FIELD_VALUES_TABLE,
                    entries: edges.len(),
                }
            })?;
            for edge in edges {
                fields.push(AllocationCollectorPollOldField::new(
                    edge.source().clone(),
                    self.resolved_generation_for_value(edge.value())?,
                ));
            }

            let entries =
                old_fields
                    .len()
                    .checked_add(1)
                    .ok_or(EvalHeapError::RootScanLengthOverflow {
                        table: MINOR_GC_OLD_FIELDS_TABLE,
                    })?;
            old_fields.try_reserve_exact(1).map_err(|_| {
                EvalHeapError::RootScanAllocationFailed {
                    table: MINOR_GC_OLD_FIELDS_TABLE,
                    entries,
                }
            })?;
            old_fields.push(AllocationCollectorPollOldFields::new(
                address, generation, fields,
            )?);
        }
        // Flat lists and attrsets are permanent edge carriers and contribute
        // old-field snapshots exactly as their record-backed forms did.
        for entry in self.flat_lists.iter() {
            let address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            let edges = self.scan_flat_list_edges(entry.object().payload())?;
            self.push_current_old_fields_entry(&mut old_fields, address, edges)?;
        }
        for entry in self.flat_attrs.iter() {
            let address = GcHeapAddress::new(entry.ptr().as_ptr() as usize)
                .map_err(EvalHeapError::GenerationalGc)?;
            let edges = self.scan_flat_attrs_edges(entry.object().payload())?;
            self.push_current_old_fields_entry(&mut old_fields, address, edges)?;
        }
        Ok(old_fields)
    }

    /// Appends one permanent flat object's old-field snapshot.
    ///
    /// Shared tail of the flat-list and flat-attrs arms of
    /// [`EvalHeap::current_old_fields`]; flat objects are permanent by
    /// construction.
    fn push_current_old_fields_entry(
        &self,
        old_fields: &mut Vec<AllocationCollectorPollOldFields>,
        address: GcHeapAddress,
        edges: Vec<HeapEdge>,
    ) -> Result<(), EvalHeapError> {
        let mut fields = Vec::new();
        fields.try_reserve_exact(edges.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OLD_FIELD_VALUES_TABLE,
                entries: edges.len(),
            }
        })?;
        for edge in edges {
            fields.push(AllocationCollectorPollOldField::new(
                edge.source().clone(),
                self.resolved_generation_for_value(edge.value())?,
            ));
        }

        let entries =
            old_fields
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: MINOR_GC_OLD_FIELDS_TABLE,
                })?;
        old_fields.try_reserve_exact(1).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_OLD_FIELDS_TABLE,
                entries,
            }
        })?;
        old_fields.push(AllocationCollectorPollOldFields::new(
            address,
            HeapGeneration::Permanent,
            fields,
        )?);
        Ok(())
    }

    fn nursery_layouts_for_minor_gc_plan(
        &self,
        plan: &MinorGcPlan,
    ) -> Result<Vec<NurseryObjectLayout>, EvalHeapError> {
        let mut nursery_layouts = Vec::new();
        nursery_layouts
            .try_reserve_exact(plan.survivors().len())
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: MINOR_GC_NURSERY_LAYOUTS_TABLE,
                entries: plan.survivors().len(),
            })?;
        for survivor in plan.survivors() {
            let record = self.record_for_minor_gc_survivor(survivor.address())?;
            nursery_layouts.push(NurseryObjectLayout::new(
                survivor.address(),
                record.layout.size_bytes,
                record.layout.align,
            ));
        }
        Ok(nursery_layouts)
    }

    fn minor_gc_reference_slots_for_plan(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        card_table: Option<GcCardTableSnapshot<'_>>,
        plan: &MinorGcPlan,
        nursery_fields: &[AllocationCollectorPollNurseryFields],
        old_fields: &[AllocationCollectorPollOldFields],
    ) -> Result<Vec<AllocationCollectorPollReferenceSlot>, EvalHeapError> {
        let mut reference_slots = Vec::new();
        for root in poll_scan.scan().roots() {
            push_reference_slot(
                &mut reference_slots,
                AllocationCollectorPollReferenceSource::Root {
                    source: root.source().clone(),
                },
                self.resolved_generation_for_value(root.value())?,
                Some(root.value().tag()),
            )?;
        }

        for edge in remembered_set.edges() {
            self.push_remembered_edge_reference_slots(&mut reference_slots, *edge)?;
        }

        if let Some(card_table) = card_table {
            push_dirty_old_field_reference_slots(
                &mut reference_slots,
                card_table,
                remembered_set,
                plan,
                old_fields,
            )?;
        }

        for survivor in plan.survivors() {
            let fields = nursery_fields_for_survivor(nursery_fields, survivor.address())?;
            for (field_index, field) in fields.fields().iter().enumerate() {
                push_reference_slot(
                    &mut reference_slots,
                    AllocationCollectorPollReferenceSource::NurseryField {
                        object: survivor.address(),
                        field_index,
                        source: field.source().clone(),
                    },
                    field.value(),
                    None,
                )?;
            }
        }

        Ok(reference_slots)
    }

    fn push_remembered_edge_reference_slots(
        &self,
        reference_slots: &mut Vec<AllocationCollectorPollReferenceSlot>,
        edge: RememberedEdge,
    ) -> Result<(), EvalHeapError> {
        let source_edges = match self.flat_edges_at_gc_address(edge.source())? {
            Some(edges) => edges,
            None => {
                let source_record = self.record_for_gc_address(edge.source(), "source")?;
                self.scan_record_edges(source_record)?
            }
        };
        let mut matched = false;

        for (field_index, source_edge) in source_edges.iter().enumerate() {
            let ResolvedValueGeneration::Heap {
                address,
                generation: HeapGeneration::Young,
            } = self.resolved_generation_for_value(source_edge.value())?
            else {
                continue;
            };
            if address != edge.target() {
                continue;
            }

            matched = true;
            push_reference_slot(
                reference_slots,
                AllocationCollectorPollReferenceSource::RememberedEdge {
                    edge,
                    field_index,
                    source: source_edge.source().clone(),
                },
                ResolvedValueGeneration::Heap {
                    address,
                    generation: HeapGeneration::Young,
                },
                None,
            )?;
        }

        if matched {
            Ok(())
        } else {
            Err(EvalHeapError::StaleCollectorPollRememberedEdge {
                source_address: edge.source(),
                target_address: edge.target(),
            })
        }
    }

    fn current_heap_field_reference_value(
        &self,
        index: usize,
        source: &AllocationCollectorPollReferenceSource,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        match source {
            AllocationCollectorPollReferenceSource::Root { source } => {
                Err(EvalHeapError::CollectorPollReferenceSlotNotHeapBacked {
                    index,
                    root_source: source.clone(),
                })
            }
            AllocationCollectorPollReferenceSource::RememberedEdge {
                edge,
                field_index,
                source,
            } => self.current_heap_field_reference_value_at(
                index,
                edge.source(),
                *field_index,
                source,
            ),
            AllocationCollectorPollReferenceSource::DirtyOldField {
                object,
                field_index,
                source,
            } => self.current_heap_field_reference_value_at(index, *object, *field_index, source),
            AllocationCollectorPollReferenceSource::NurseryField {
                object,
                field_index,
                source,
            } => self.current_heap_field_reference_value_at(index, *object, *field_index, source),
        }
    }

    fn current_heap_field_reference_value_at(
        &self,
        index: usize,
        object: GcHeapAddress,
        field_index: usize,
        expected_source: &HeapEdgeSource,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        let edges = match self.flat_edges_at_gc_address(object)? {
            Some(edges) => edges,
            None => {
                let record = self.record_for_reference_slot_object(object)?;
                self.scan_record_edges(record)?
            }
        };
        let Some(edge) = edges.get(field_index) else {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index,
                expected: expected_source.clone(),
                actual: None,
            });
        };
        if edge.source() != expected_source {
            return Err(EvalHeapError::CollectorPollReferenceSlotSourceMismatch {
                index,
                expected: expected_source.clone(),
                actual: Some(edge.source().clone()),
            });
        }
        self.resolved_generation_for_value(edge.value())
    }

    fn record_for_scannable_value(&self, value: Value) -> Result<&HeapRecord, EvalHeapError> {
        let (tag, ptr) = heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            Ok(record)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    fn resolved_generation_for_value(
        &self,
        value: Value,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        let (tag, ptr) = heap_ptr(value)?;
        if self.shared.is_none()
            && matches!(
                tag,
                ValueTag::String | ValueTag::Path | ValueTag::List | ValueTag::Attrs
            )
        {
            self.flat_verify(tag, ptr)?;
            return Ok(ResolvedValueGeneration::Heap {
                address: GcHeapAddress::new(ptr.as_ptr() as usize)
                    .map_err(EvalHeapError::GenerationalGc)?,
                generation: HeapGeneration::Permanent,
            });
        }
        let record = self.record_for_scannable_value(value)?;
        Ok(ResolvedValueGeneration::Heap {
            address: gc_address_for_record(record)?,
            generation: generation_for_record(record),
        })
    }

    fn resolved_generation_for_thunk_resolve_value(
        &self,
        value: Value,
    ) -> Result<ResolvedValueGeneration, EvalHeapError> {
        if !is_scannable_eval_heap_value(value) {
            return Ok(ResolvedValueGeneration::Inline);
        }
        self.resolved_generation_for_value(value)
    }

    fn generation_for_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<HeapGeneration, EvalHeapError> {
        // Flat strings/paths/lists (doc 30 FV-1) are permanent by
        // construction and have no record.
        if self.flat_tag_at_gc_address(address).is_some() {
            return Ok(HeapGeneration::Permanent);
        }
        let record = self.record_for_gc_address(address, role)?;
        Ok(generation_for_record(record))
    }

    pub(crate) fn allocation_domain_for_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<HeapAllocationDomain, EvalHeapError> {
        if self.flat_tag_at_gc_address(address).is_some() {
            return Ok(HeapAllocationDomain::PermanentShared);
        }
        let record = self.record_for_gc_address(address, role)?;
        Ok(record.allocation_domain)
    }

    /// Returns the flat-object tag at a GC address, if a flat store owns it.
    fn flat_tag_at_gc_address(&self, address: GcHeapAddress) -> Option<ValueTag> {
        let ptr = NonNull::new(address.address_bits() as *mut HeapObject)?;
        self.flat_kind_tag(ptr)
    }

    /// Synthesizes precise edges for the flat object at a GC address, if a
    /// flat edge-carrying store (lists or attrsets) owns it.
    fn flat_edges_at_gc_address(
        &self,
        address: GcHeapAddress,
    ) -> Result<Option<Vec<HeapEdge>>, EvalHeapError> {
        let Some(ptr) = NonNull::new(address.address_bits() as *mut HeapObject) else {
            return Ok(None);
        };
        if let Ok(list) = self.flat_list_payload(ptr) {
            return Ok(Some(self.scan_flat_list_edges(list)?));
        }
        if let Ok(payload) = self.flat_attrs_payload(ptr) {
            return Ok(Some(self.scan_flat_attrs_edges(payload)?));
        }
        Ok(None)
    }

    fn record_for_gc_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.records
            .record_at_address(address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollRememberedEdgeAddress { role, address })
    }

    fn record_for_minor_gc_survivor(
        &self,
        address: GcHeapAddress,
    ) -> Result<&HeapRecord, EvalHeapError> {
        let record = &self.records[self.record_index_for_minor_gc_survivor(address)?];
        Ok(record)
    }

    fn record_index_for_minor_gc_survivor(
        &self,
        address: GcHeapAddress,
    ) -> Result<usize, EvalHeapError> {
        let record_index = self
            .records
            .index_of_address(address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollSurvivorAddress { address })?;
        let record = &self.records[record_index];
        if generation_for_record(record) != HeapGeneration::Young {
            return Err(EvalHeapError::GenerationalGc(
                GenerationalGcError::StaleNurseryObjectLayout { address },
            ));
        }
        Ok(record_index)
    }

    fn record_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<&HeapRecord, EvalHeapError> {
        let index = self.record_index_for_reference_slot_object(address)?;
        Ok(&self.records[index])
    }

    fn record_index_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<usize, EvalHeapError> {
        self.records
            .index_of_address(address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollReferenceSlotAddress { address })
    }

    fn validate_collector_poll_plan_allocation_state(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
    ) -> Result<(), EvalHeapError> {
        if plan.heap_records() != self.scannable_object_count() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if plan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        Ok(())
    }

    fn validate_collector_poll_commit_allocation_state(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<(), EvalHeapError> {
        if commit_plan.heap_records() != self.scannable_object_count() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        if commit_plan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.scannable_object_count(),
            });
        }
        Ok(())
    }
}

fn validate_destination_reservation_snapshot_matches_plan(
    plan: &AllocationCollectorPollMinorGcPlan,
    reservations: &AllocationCollectorPollMinorGcDestinationRecordReservations,
) -> Result<(), EvalHeapError> {
    if reservations.heap_records() != plan.heap_records() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation heap record count differs from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.worker_region_owner() != plan.worker_region_owner() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation worker region owner differs from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.worker_region_epoch() != plan.worker_region_epoch() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation worker region epoch differs from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.allocation_safepoints() != plan.allocation_safepoints() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation worker allocation safepoints differ from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    if reservations.permanent_allocation_safepoints() != plan.permanent_allocation_safepoints() {
        return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
            reason: "destination reservation permanent allocation safepoints differ from minor-GC plan",
            expected_records: plan.heap_records(),
            actual_records: reservations.heap_records(),
        });
    }
    Ok(())
}

fn nursery_field_views(
    nursery_fields: &[AllocationCollectorPollNurseryFields],
) -> Result<Vec<NurseryObjectFields<'_>>, EvalHeapError> {
    let mut views = Vec::new();
    views.try_reserve_exact(nursery_fields.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_NURSERY_FIELDS_TABLE,
            entries: nursery_fields.len(),
        }
    })?;
    for object in nursery_fields {
        views.push(NurseryObjectFields::new(
            object.address(),
            object.field_values(),
        ));
    }
    Ok(views)
}

fn old_field_views(
    old_fields: &[AllocationCollectorPollOldFields],
) -> Result<Vec<MinorGcOldObjectFields<'_>>, GenerationalGcError> {
    let mut views = Vec::new();
    views.try_reserve_exact(old_fields.len()).map_err(|_| {
        GenerationalGcError::MinorGcOldFieldRescanAllocationFailed {
            rescans: old_fields.len(),
        }
    })?;
    for object in old_fields {
        views.push(MinorGcOldObjectFields::new(
            object.address(),
            object.generation(),
            object.field_values(),
        ));
    }
    Ok(views)
}

fn remembered_set_with_dirty_old_field_edges(
    remembered_set: RememberedSetSnapshot<'_>,
    card_table: GcCardTableSnapshot<'_>,
    old_fields: &[AllocationCollectorPollOldFields],
) -> Result<RememberedSet, GenerationalGcError> {
    let mut frontier = remembered_set_from_snapshot(remembered_set)?;
    for object in old_fields {
        if !card_table.covers_source(object.address()) {
            continue;
        }
        for field in object.fields() {
            let ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } = field.value()
            else {
                continue;
            };
            frontier.record(RememberedEdge::new(object.address(), target))?;
        }
    }
    Ok(frontier)
}

fn push_dirty_old_field_reference_slots(
    reference_slots: &mut Vec<AllocationCollectorPollReferenceSlot>,
    card_table: GcCardTableSnapshot<'_>,
    remembered_set: RememberedSetSnapshot<'_>,
    plan: &MinorGcPlan,
    old_fields: &[AllocationCollectorPollOldFields],
) -> Result<(), EvalHeapError> {
    for object in old_fields {
        if !card_table.covers_source(object.address()) {
            continue;
        }
        for (field_index, field) in object.fields().iter().enumerate() {
            let ResolvedValueGeneration::Heap {
                address: target,
                generation: HeapGeneration::Young,
            } = field.value()
            else {
                continue;
            };
            if remembered_set
                .edges()
                .contains(&RememberedEdge::new(object.address(), target))
            {
                continue;
            }
            if !plan
                .survivors()
                .iter()
                .any(|survivor| survivor.address() == target)
            {
                continue;
            }
            push_reference_slot(
                reference_slots,
                AllocationCollectorPollReferenceSource::DirtyOldField {
                    object: object.address(),
                    field_index,
                    source: field.source().clone(),
                },
                field.value(),
                None,
            )?;
        }
    }
    Ok(())
}

fn nursery_fields_for_survivor(
    nursery_fields: &[AllocationCollectorPollNurseryFields],
    address: GcHeapAddress,
) -> Result<&AllocationCollectorPollNurseryFields, EvalHeapError> {
    nursery_fields
        .iter()
        .find(|fields| fields.address() == address)
        .ok_or(EvalHeapError::GenerationalGc(
            GenerationalGcError::MissingNurseryObjectFields { address },
        ))
}

fn remembered_set_from_snapshot(
    snapshot: RememberedSetSnapshot<'_>,
) -> Result<RememberedSet, GenerationalGcError> {
    let mut remembered_set = RememberedSet::with_epoch(snapshot.epoch());
    for edge in snapshot.edges() {
        remembered_set.record(*edge)?;
    }
    Ok(remembered_set)
}

fn owned_card_table_from_snapshot(
    snapshot: GcCardTableSnapshot<'_>,
) -> Result<GcCardTable, GenerationalGcError> {
    let mut card_table = GcCardTable::new(snapshot.card_size_bytes())?;
    for card in snapshot.dirty_cards() {
        card_table.mark_source(card.source())?;
    }
    Ok(card_table)
}

fn heap_field_writeback_source<'a>(
    source: &'a AllocationCollectorPollReferenceSource,
    object_copies: &MinorGcObjectCopyPlan,
) -> Result<Option<(GcHeapAddress, GcHeapAddress, usize, &'a HeapEdgeSource)>, EvalHeapError> {
    match source {
        AllocationCollectorPollReferenceSource::Root { .. } => Ok(None),
        AllocationCollectorPollReferenceSource::RememberedEdge {
            edge,
            field_index,
            source,
        } => Ok(Some((edge.source(), edge.source(), *field_index, source))),
        AllocationCollectorPollReferenceSource::DirtyOldField {
            object,
            field_index,
            source,
        } => Ok(Some((*object, *object, *field_index, source))),
        AllocationCollectorPollReferenceSource::NurseryField {
            object,
            field_index,
            source,
        } => Ok(Some((
            *object,
            minor_gc_writeback_object_for_nursery_field(object_copies, *object)?,
            *field_index,
            source,
        ))),
    }
}

fn validate_reference_slot_matches_rewrite(
    index: usize,
    slot: &AllocationCollectorPollReferenceSlot,
    rewrite: MinorGcReferenceRewrite,
) -> Result<ResolvedValueGeneration, EvalHeapError> {
    let expected = slot.value();
    let rewrite_source = ResolvedValueGeneration::Heap {
        address: rewrite.source(),
        generation: HeapGeneration::Young,
    };
    if expected != rewrite_source {
        return Err(EvalHeapError::CollectorPollCommitReferenceSlotMismatch {
            index,
            expected,
            actual: rewrite_source,
        });
    }
    Ok(expected)
}

fn value_for_resolved_generation(
    tag: ValueTag,
    value: ResolvedValueGeneration,
) -> Result<Value, EvalHeapError> {
    let ResolvedValueGeneration::Heap { address, .. } = value else {
        return Err(EvalHeapError::CollectorPollRootWritebackNonHeapValue { tag, value });
    };
    let ptr = NonNull::new(address.address_bits() as *mut HeapObject)
        .ok_or(EvalHeapError::Value(ValueError::NullHeapPointer { tag }))?;
    Value::heap(tag, ptr).map_err(EvalHeapError::Value)
}

fn minor_gc_writeback_object_for_nursery_field(
    object_copies: &MinorGcObjectCopyPlan,
    object: GcHeapAddress,
) -> Result<GcHeapAddress, EvalHeapError> {
    object_copies
        .copies()
        .iter()
        .find(|copy| copy.source() == object)
        .map(|copy| copy.destination())
        .ok_or(EvalHeapError::GenerationalGc(
            GenerationalGcError::MissingMinorGcRelocationDestination { address: object },
        ))
}

fn push_reference_slot(
    slots: &mut Vec<AllocationCollectorPollReferenceSlot>,
    source: AllocationCollectorPollReferenceSource,
    value: ResolvedValueGeneration,
    value_tag: Option<ValueTag>,
) -> Result<(), EvalHeapError> {
    let entries = slots
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: MINOR_GC_REFERENCE_SLOTS_TABLE,
        })?;
    slots
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: MINOR_GC_REFERENCE_SLOTS_TABLE,
            entries,
        })?;
    slots.push(AllocationCollectorPollReferenceSlot::new(
        source, value, value_tag,
    ));
    Ok(())
}

fn gc_address_for_value(value: Value) -> Result<GcHeapAddress, EvalHeapError> {
    let (_tag, ptr) = heap_ptr(value)?;
    GcHeapAddress::new(ptr.as_ptr() as usize).map_err(EvalHeapError::GenerationalGc)
}

fn gc_address_for_record(record: &HeapRecord) -> Result<GcHeapAddress, EvalHeapError> {
    GcHeapAddress::new(record.ptr.as_ptr() as usize).map_err(EvalHeapError::GenerationalGc)
}

const fn generation_for_record(record: &HeapRecord) -> HeapGeneration {
    record.generation
}

const fn expected_direct_heap_field_write_generation(
    allocation_domain: HeapAllocationDomain,
) -> HeapGeneration {
    match allocation_domain {
        HeapAllocationDomain::Worker => HeapGeneration::Old,
        HeapAllocationDomain::PermanentShared => HeapGeneration::Permanent,
    }
}

fn heap_object_value_raw_eq(left: &HeapObjectValue, right: &HeapObjectValue) -> bool {
    match (left, right) {
        (HeapObjectValue::String(left), HeapObjectValue::String(right)) => left == right,
        (HeapObjectValue::List(left), HeapObjectValue::List(right)) => left.raw_eq(right),
        (HeapObjectValue::Lambda(left), HeapObjectValue::Lambda(right)) => left.raw_eq(right),
        (HeapObjectValue::Primop(left), HeapObjectValue::Primop(right)) => left.raw_eq(right),
        (HeapObjectValue::Thunk(left), HeapObjectValue::Thunk(right)) => left.raw_eq(right),
        _ => false,
    }
}

fn copied_heap_field_write_identity_matches(
    left: &AllocationCollectorPollCopiedHeapFieldWrite,
    right: &AllocationCollectorPollCopiedHeapFieldWrite,
) -> bool {
    left.allocation_domain() == right.allocation_domain()
        && left.validation_object() == right.validation_object()
        && left.writeback_object() == right.writeback_object()
        && left.field_index() == right.field_index()
        && left.source() == right.source()
}

fn direct_heap_field_write_identity_matches(
    left: &AllocationCollectorPollDirectHeapFieldWrite,
    right: &AllocationCollectorPollDirectHeapFieldWrite,
) -> bool {
    left.allocation_domain() == right.allocation_domain()
        && left.writeback_object() == right.writeback_object()
        && left.field_index() == right.field_index()
        && left.source() == right.source()
}

fn validate_copied_heap_field_write_object_source(
    object: &HeapObjectValue,
    write: &AllocationCollectorPollCopiedHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if validate_captured_environment_source(object, write.source())
        .map_err(EvalHeapError::Environment)?
    {
        return Ok(());
    }
    match (object, write.source()) {
        (HeapObjectValue::List(_), HeapEdgeSource::ListElement { .. }) => Ok(()),
        (HeapObjectValue::Primop(primop), HeapEdgeSource::PrimopArgument { index })
            if *index < primop.args().len() =>
        {
            Ok(())
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.with_scope_env().scopes().len() => Ok(()),
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.scoped_global_env().scopes().len() => Ok(()),
        (HeapObjectValue::Thunk(thunk), source)
            if validate_forced_thunk_cached_result_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_parallel_thunk_payload_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_suspended_thunk_field_write_source(thunk, source)? =>
        {
            Ok(())
        }
        _ => Err(
            EvalHeapError::CollectorPollCopiedHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object(),
                field_index: write.field_index(),
                field_source: write.source().clone(),
            },
        ),
    }
}

/// Source-shape validation for a flat-list direct writeback target.
///
/// The flat analog of the `(List, ListElement)` arm of
/// [`validate_direct_heap_field_write_object_source`]: a flat list only
/// carries `ListElement` fields.
fn validate_flat_list_direct_heap_field_write_source(
    write: &AllocationCollectorPollDirectHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if matches!(write.source(), HeapEdgeSource::ListElement { .. }) {
        return Ok(());
    }
    Err(
        EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            field_source: write.source().clone(),
        },
    )
}

/// Rewrites one element of a staged flat-list spine.
///
/// The flat analog of [`record_owned_heap_field_write_object`]'s
/// `(List, ListElement)` arm: clone-and-replace over the staged spine, so
/// nothing observable mutates until the staged commit.
fn flat_list_heap_field_write_object(
    list: &NixList,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<NixList, RecordOwnedHeapFieldWriteObjectError> {
    let HeapEdgeSource::ListElement { index } = source else {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    };
    let mut elements = list.clone().into_vec();
    let Some(slot) = elements.get_mut(*index) else {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    };
    *slot = replacement;
    Ok(NixList::new(elements))
}

/// Source-shape validation for a flat-attrs direct writeback target.
///
/// The flat analog of the `(Attrs, AttrBinding)` arm of
/// [`validate_direct_heap_field_write_object_source`]: a flat attrset only
/// carries `AttrBinding` fields, and the write's shape must match the
/// payload's recorded shape id.
fn validate_flat_attrs_direct_heap_field_write_source(
    payload: &FlatAttrsPayload,
    write: &AllocationCollectorPollDirectHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if let HeapEdgeSource::AttrBinding { shape, .. } = write.source()
        && payload.metadata.shape() == *shape
    {
        return Ok(());
    }
    Err(
        EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            field_source: write.source().clone(),
        },
    )
}

/// Rewrites one entry value of staged flat-attrs entry storage.
///
/// The flat analog of [`record_owned_heap_field_write_object`]'s
/// `(Attrs, AttrBinding)` arm: shape-guarded clone-and-replace over the
/// staged entries, so nothing observable mutates until the staged commit.
fn flat_attrs_heap_field_write_object(
    metadata: EvalHeapAttrsMetadata,
    attrs: &FlatAttrs,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<FlatAttrs, RecordOwnedHeapFieldWriteObjectError> {
    let HeapEdgeSource::AttrBinding { shape, slot, key } = source else {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    };
    if metadata.shape() != *shape {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    }
    attrs
        .with_symbol_slot_value(*slot, *key, replacement)
        .map_err(RecordOwnedHeapFieldWriteObjectError::Attr)
}

fn validate_direct_heap_field_write_object_source(
    object: &HeapObjectValue,
    write: &AllocationCollectorPollDirectHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if validate_captured_environment_source(object, write.source())
        .map_err(EvalHeapError::Environment)?
    {
        return Ok(());
    }
    match (object, write.source()) {
        (HeapObjectValue::List(_), HeapEdgeSource::ListElement { .. }) => Ok(()),
        (HeapObjectValue::Primop(primop), HeapEdgeSource::PrimopArgument { index })
            if *index < primop.args().len() =>
        {
            Ok(())
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.with_scope_env().scopes().len() => Ok(()),
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.scoped_global_env().scopes().len() => Ok(()),
        (HeapObjectValue::Thunk(thunk), source)
            if validate_forced_thunk_cached_result_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_parallel_thunk_payload_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_suspended_thunk_field_write_source(thunk, source)? =>
        {
            Ok(())
        }
        _ => Err(
            EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object(),
                field_index: write.field_index(),
                field_source: write.source().clone(),
            },
        ),
    }
}

fn copied_heap_field_write_object_error(
    write: &CollectorPollCopiedHeapFieldWrite,
    error: RecordOwnedHeapFieldWriteObjectError,
) -> EvalHeapError {
    match error {
        RecordOwnedHeapFieldWriteObjectError::UnsupportedSource => {
            EvalHeapError::CollectorPollCopiedHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object,
                field_index: write.field_index,
                field_source: write.source.clone(),
            }
        }
        RecordOwnedHeapFieldWriteObjectError::Attr(source) => EvalHeapError::Attr(source),
        RecordOwnedHeapFieldWriteObjectError::Environment(source) => {
            EvalHeapError::Environment(source)
        }
        RecordOwnedHeapFieldWriteObjectError::Thunk(source) => EvalHeapError::Thunk(source),
        RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload(source) => {
            EvalHeapError::ParallelThunkPayload(source)
        }
    }
}

fn direct_heap_field_write_object_error(
    write: &CollectorPollDirectHeapFieldWrite,
    error: RecordOwnedHeapFieldWriteObjectError,
) -> EvalHeapError {
    match error {
        RecordOwnedHeapFieldWriteObjectError::UnsupportedSource => {
            EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object,
                field_index: write.field_index,
                field_source: write.source.clone(),
            }
        }
        RecordOwnedHeapFieldWriteObjectError::Attr(source) => EvalHeapError::Attr(source),
        RecordOwnedHeapFieldWriteObjectError::Environment(source) => {
            EvalHeapError::Environment(source)
        }
        RecordOwnedHeapFieldWriteObjectError::Thunk(source) => EvalHeapError::Thunk(source),
        RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload(source) => {
            EvalHeapError::ParallelThunkPayload(source)
        }
    }
}

fn stage_record_owned_heap_field_write(
    object: &mut HeapObjectValue,
    source: &HeapEdgeSource,
    replacement: Value,
    environment_writebacks: &mut EnvironmentWritebackStage,
) -> Result<(), RecordOwnedHeapFieldWriteObjectError> {
    if environment_writebacks
        .stage(object, source, replacement)
        .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?
    {
        return Ok(());
    }
    *object = record_owned_heap_field_write_object(object, source, replacement)?;
    Ok(())
}

fn record_owned_heap_field_write_object(
    object: &HeapObjectValue,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<HeapObjectValue, RecordOwnedHeapFieldWriteObjectError> {
    match (object, source) {
        (HeapObjectValue::List(list), HeapEdgeSource::ListElement { index }) => {
            let mut elements = list.clone().into_vec();
            let Some(slot) = elements.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *slot = replacement;
            Ok(HeapObjectValue::List(NixList::new(elements)))
        }
        (HeapObjectValue::Primop(primop), HeapEdgeSource::PrimopArgument { index }) => {
            let mut args = primop.args().to_vec();
            let Some(arg) = args.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *arg = EvalPrimOpArg::new_in_module(arg.module(), arg.id(), arg.span(), replacement);
            Ok(HeapObjectValue::Primop(EvalPrimOp {
                builtin: primop.builtin(),
                symbol: primop.symbol(),
                args,
            }))
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) => {
            let mut scopes = lambda.with_scope_env().scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = EvalWithScope::new(scope.module(), scope.scope(), replacement);
            let with_env = EvalWithEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            Ok(HeapObjectValue::Lambda(EvalLambda::with_captures(
                lambda.module(),
                lambda.pattern(),
                lambda.body(),
                lambda.frame(),
                lambda.env().clone(),
                with_env,
                lambda.scoped_global_env().clone(),
            )))
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) => {
            let mut scopes = lambda.scoped_global_env().scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = replacement;
            let scoped_globals = EvalScopedGlobalEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            Ok(HeapObjectValue::Lambda(EvalLambda::with_captures(
                lambda.module(),
                lambda.pattern(),
                lambda.body(),
                lambda.frame(),
                lambda.env().clone(),
                lambda.with_scope_env().clone(),
                scoped_globals,
            )))
        }
        (HeapObjectValue::Thunk(thunk), HeapEdgeSource::ThunkCachedResult) => {
            if thunk
                .cell()
                .cached_value()
                .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?
                .is_none()
            {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            }
            let parallel_cell = clone_parallel_thunk_cell_for_heap_field_write(thunk)?;
            if parallel_cell.is_none() {
                return Ok(HeapObjectValue::Thunk(
                    EvalThunk::with_forced_cached_result_from(thunk, replacement),
                ));
            }
            Ok(HeapObjectValue::Thunk(EvalThunk {
                kind: thunk.kind().clone(),
                cell: Arc::new(ThunkCell::forced(replacement)),
                force_storage_mode: thunk.force_storage_mode(),
                parallel_cell,
            }))
        }
        (HeapObjectValue::Thunk(thunk), HeapEdgeSource::ThunkParallelPayloadValue) => {
            let Some(parallel_cell) = thunk.parallel_payload_cell() else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            if parallel_cell
                .forced_terminal_value()
                .map_err(RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload)?
                .is_none()
            {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            }
            let parallel_cell = parallel_cell
                .relocated_forced_value(replacement)
                .map_err(RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload)?;
            Ok(HeapObjectValue::Thunk(EvalThunk {
                kind: thunk.kind().clone(),
                cell: Arc::new(
                    clone_serial_thunk_cell_for_heap_field_write(thunk.cell())
                        .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?,
                ),
                force_storage_mode: thunk.force_storage_mode(),
                parallel_cell: Some(Arc::new(parallel_cell)),
            }))
        }
        (HeapObjectValue::Thunk(thunk), source) => {
            rewrite_suspended_thunk_field(thunk, source, replacement)
        }
        _ => Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource),
    }
}

fn validate_suspended_thunk_field_write_source(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, EvalHeapError> {
    thunk_supports_suspended_field_write(thunk, source).map_err(EvalHeapError::Thunk)
}

fn validate_forced_thunk_cached_result_write_source(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, EvalHeapError> {
    if source != &HeapEdgeSource::ThunkCachedResult {
        return Ok(false);
    }
    Ok(thunk
        .cell()
        .cached_value()
        .map_err(EvalHeapError::Thunk)?
        .is_some())
}

fn validate_parallel_thunk_payload_write_source(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, EvalHeapError> {
    if source != &HeapEdgeSource::ThunkParallelPayloadValue {
        return Ok(false);
    }
    Ok(thunk
        .parallel_payload_cell()
        .map(|cell| cell.forced_terminal_value())
        .transpose()?
        .flatten()
        .is_some())
}

fn clone_serial_thunk_cell_for_heap_field_write(cell: &ThunkCell) -> Result<ThunkCell, ForceError> {
    match cell.state()? {
        ThunkState::Suspended => Ok(ThunkCell::new()),
        ThunkState::Blackhole => Err(ForceError::UnexpectedState {
            expected: ThunkState::Suspended,
            actual: ThunkState::Blackhole,
        }),
        ThunkState::Forced => Ok(ThunkCell::forced(
            cell.cached_value()?.ok_or(ForceError::MissingForcedValue)?,
        )),
    }
}

fn clone_parallel_thunk_cell_for_heap_field_write(
    thunk: &EvalThunk,
) -> Result<Option<Arc<TreeWalkParallelThunkCell>>, RecordOwnedHeapFieldWriteObjectError> {
    thunk
        .parallel_payload_cell()
        .map(|cell| {
            cell.clone_for_relocation()
                .map(Arc::new)
                .map_err(RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload)
        })
        .transpose()
}

fn rebuild_thunk_for_heap_field_write(
    thunk: &EvalThunk,
    kind: EvalThunkKind,
) -> Result<HeapObjectValue, RecordOwnedHeapFieldWriteObjectError> {
    Ok(HeapObjectValue::Thunk(EvalThunk {
        kind,
        cell: Arc::new(
            clone_serial_thunk_cell_for_heap_field_write(thunk.cell())
                .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?,
        ),
        force_storage_mode: thunk.force_storage_mode(),
        parallel_cell: clone_parallel_thunk_cell_for_heap_field_write(thunk)?,
    }))
}

fn thunk_supports_suspended_field_write(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, ForceError> {
    if thunk.cell().state()? != ThunkState::Suspended {
        return Ok(false);
    }

    Ok(matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Node { with_env, .. },
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) if *index < with_env.scopes().len()
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Node { scoped_globals, .. },
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) if *index < scoped_globals.scopes().len()
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Apply { .. },
            HeapEdgeSource::ThunkApplyFunction | HeapEdgeSource::ThunkApplyArgument,
        )
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Apply2 { .. },
            HeapEdgeSource::ThunkApply2Function
                | HeapEdgeSource::ThunkApply2FirstArgument
                | HeapEdgeSource::ThunkApply2SecondArgument,
        )
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Select { .. },
            HeapEdgeSource::ThunkSelectReceiver
        )
    ))
}

fn rewrite_suspended_thunk_field(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<HeapObjectValue, RecordOwnedHeapFieldWriteObjectError> {
    if thunk
        .cell()
        .state()
        .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?
        != ThunkState::Suspended
    {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    }

    match (thunk.kind(), source) {
        (
            EvalThunkKind::Node {
                body,
                env,
                with_env,
                scoped_globals,
            },
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) => {
            let mut scopes = with_env.scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = EvalWithScope::new(scope.module(), scope.scope(), replacement);
            let with_env = EvalWithEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            rebuild_thunk_for_heap_field_write(
                thunk,
                EvalThunkKind::Node {
                    body: *body,
                    env: env.clone(),
                    with_env,
                    scoped_globals: scoped_globals.clone(),
                },
            )
        }
        (
            EvalThunkKind::Node {
                body,
                env,
                with_env,
                scoped_globals,
            },
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) => {
            let mut scopes = scoped_globals.scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = replacement;
            let scoped_globals = EvalScopedGlobalEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            rebuild_thunk_for_heap_field_write(
                thunk,
                EvalThunkKind::Node {
                    body: *body,
                    env: env.clone(),
                    with_env: with_env.clone(),
                    scoped_globals,
                },
            )
        }
        (
            EvalThunkKind::Apply {
                function,
                function_span,
                argument,
                argument_value,
                ..
            },
            HeapEdgeSource::ThunkApplyFunction,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply {
                function: *function,
                function_span: *function_span,
                function_value: replacement,
                argument: *argument,
                argument_value: *argument_value,
            },
        ),
        (
            EvalThunkKind::Apply {
                function,
                function_span,
                function_value,
                argument,
                ..
            },
            HeapEdgeSource::ThunkApplyArgument,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply {
                function: *function,
                function_span: *function_span,
                function_value: *function_value,
                argument: *argument,
                argument_value: replacement,
            },
        ),
        (
            EvalThunkKind::Apply2 {
                function,
                function_span,
                first_argument,
                first_argument_span,
                first_argument_value,
                second_argument,
                second_argument_span,
                second_argument_value,
                ..
            },
            HeapEdgeSource::ThunkApply2Function,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply2 {
                function: *function,
                function_span: *function_span,
                function_value: replacement,
                first_argument: *first_argument,
                first_argument_span: *first_argument_span,
                first_argument_value: *first_argument_value,
                second_argument: *second_argument,
                second_argument_span: *second_argument_span,
                second_argument_value: *second_argument_value,
            },
        ),
        (
            EvalThunkKind::Apply2 {
                function,
                function_span,
                function_value,
                first_argument,
                first_argument_span,
                second_argument,
                second_argument_span,
                second_argument_value,
                ..
            },
            HeapEdgeSource::ThunkApply2FirstArgument,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply2 {
                function: *function,
                function_span: *function_span,
                function_value: *function_value,
                first_argument: *first_argument,
                first_argument_span: *first_argument_span,
                first_argument_value: replacement,
                second_argument: *second_argument,
                second_argument_span: *second_argument_span,
                second_argument_value: *second_argument_value,
            },
        ),
        (
            EvalThunkKind::Apply2 {
                function,
                function_span,
                function_value,
                first_argument,
                first_argument_span,
                first_argument_value,
                second_argument,
                second_argument_span,
                ..
            },
            HeapEdgeSource::ThunkApply2SecondArgument,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply2 {
                function: *function,
                function_span: *function_span,
                function_value: *function_value,
                first_argument: *first_argument,
                first_argument_span: *first_argument_span,
                first_argument_value: *first_argument_value,
                second_argument: *second_argument,
                second_argument_span: *second_argument_span,
                second_argument_value: replacement,
            },
        ),
        (EvalThunkKind::Select { select, path, .. }, HeapEdgeSource::ThunkSelectReceiver) => {
            rebuild_thunk_for_heap_field_write(
                thunk,
                EvalThunkKind::Select {
                    select: *select,
                    receiver: replacement,
                    path: *path,
                },
            )
        }
        _ => Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource),
    }
}

fn push_parallel_thunk_payload_edge(
    edges: &mut Vec<HeapEdge>,
    thunk: &EvalThunk,
) -> Result<(), EvalHeapError> {
    if let Some(value) = thunk
        .parallel_payload_cell()
        .map(|cell| cell.forced_terminal_value())
        .transpose()?
        .flatten()
    {
        push_heap_edge(edges, HeapEdgeSource::ThunkParallelPayloadValue, value)?;
    }
    Ok(())
}

fn push_thunk_kind_edges(
    edges: &mut Vec<HeapEdge>,
    kind: &EvalThunkKind,
) -> Result<(), EvalHeapError> {
    match kind {
        EvalThunkKind::Node {
            env,
            with_env,
            scoped_globals,
            ..
        } => push_capture_edges(
            edges,
            CapturedRootOwner::Thunk,
            env,
            with_env,
            scoped_globals,
        ),
        EvalThunkKind::Apply {
            function_value,
            argument_value,
            ..
        } => {
            push_heap_edge(edges, HeapEdgeSource::ThunkApplyFunction, *function_value)?;
            push_heap_edge(edges, HeapEdgeSource::ThunkApplyArgument, *argument_value)
        }
        EvalThunkKind::Apply2 {
            function_value,
            first_argument_value,
            second_argument_value,
            ..
        } => {
            push_heap_edge(edges, HeapEdgeSource::ThunkApply2Function, *function_value)?;
            push_heap_edge(
                edges,
                HeapEdgeSource::ThunkApply2FirstArgument,
                *first_argument_value,
            )?;
            push_heap_edge(
                edges,
                HeapEdgeSource::ThunkApply2SecondArgument,
                *second_argument_value,
            )
        }
        EvalThunkKind::Select { receiver, .. } => {
            push_heap_edge(edges, HeapEdgeSource::ThunkSelectReceiver, *receiver)
        }
        EvalThunkKind::BuiltinAttr { .. } => Ok(()),
        // Only forced thunks are shed, and forced thunks scan their cached
        // result instead of their kind, so a released kind can never reach a
        // suspended/blackhole kind scan. Fail loudly if it somehow does.
        EvalThunkKind::Released => Err(EvalHeapError::ReleasedThunkWork { address: 0 }),
    }
}

fn push_capture_edges(
    edges: &mut Vec<HeapEdge>,
    owner: CapturedRootOwner,
    env: &EvalEnv,
    with_env: &EvalWithEnv,
    scoped_globals: &EvalScopedGlobalEnv,
) -> Result<(), EvalHeapError> {
    for (frame_index, frame) in env.frames().iter().enumerate() {
        let slots = frame.slot_values()?;
        for (slot, value) in slots.into_iter().enumerate() {
            push_heap_edge(
                edges,
                HeapEdgeSource::CapturedEnv {
                    owner,
                    frame: frame_index,
                    slot,
                },
                value,
            )?;
        }
    }
    if let Some(flat) = env.flat_base() {
        push_heap_edge(
            edges,
            HeapEdgeSource::CapturedFlatEnvOwner { owner },
            flat.inline_owner(),
        )?;
    }

    for (index, scope) in with_env.scopes().iter().enumerate() {
        push_heap_edge(
            edges,
            HeapEdgeSource::CapturedWithScope { owner, index },
            scope.value(),
        )?;
    }

    for (index, value) in scoped_globals.scopes().iter().copied().enumerate() {
        push_heap_edge(
            edges,
            HeapEdgeSource::CapturedScopedGlobal { owner, index },
            value,
        )?;
    }

    Ok(())
}
