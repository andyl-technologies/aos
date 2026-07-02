//! Precise root and field scanning for the tree-walk evaluator heap.
//!
//! The moving collector needs exact `Value` roots, not a conservative stack
//! scan. This module records explicit mutator roots and scans typed heap records
//! through their evaluator-side layouts: lists expose element slots, attrsets
//! expose shape-qualified bindings, closures expose captured environments,
//! primops expose captured lazy arguments, and thunks expose either suspended
//! work captures or their forced result depending on the thunk state.
//!
//! This is a tree-walk graph-reporting substrate. It intentionally returns
//! copied [`Value`] handles, not mutable relocation slots. The production
//! evaluator can build safepoint root sets for its explicit tree-walk state, but
//! arbitrary Rust locals still need explicit safepoint registration before they
//! are collector-visible.

use std::collections::{HashSet, VecDeque};
use std::ptr::NonNull;

use super::*;
use crate::eval::thunk::{ForceError, ThunkResolveBarrier, ThunkState};
use crate::heap::{
    GcCardTable, GcCardTableSnapshot, GcHeapAddress, GenerationalGcError, GenerationalGcTier,
    HeapGeneration, MinorGcCommitBuffers, MinorGcCommitPlan, MinorGcCommitReport,
    MinorGcDestinationAllocationPlan, MinorGcDestinationBases, MinorGcDestinationPlacementPlan,
    MinorGcForwardingPointerPlan, MinorGcForwardingSlot, MinorGcObjectByteCopyBuffer,
    MinorGcObjectCopy, MinorGcObjectCopyPlan, MinorGcPlan, MinorGcPromotionPolicy,
    MinorGcReferenceRewrite, MinorGcReferenceRewritePlan, MinorGcRelocationDestination,
    MinorGcRelocationDestinationPlan, MinorGcRelocationPlan, MinorGcRememberedSetRefreshPlan,
    MinorGcSurvivorAction, NurseryObjectAge, NurseryObjectFields, NurseryObjectLayout,
    RememberedEdge, RememberedSet, RememberedSetEpoch, RememberedSetSnapshot,
    ResolvedValueGeneration, ThunkResolveWrite, ThunkResolveWriteBarrier,
    record_thunk_resolve_write_barrier, record_thunk_resolve_write_barrier_with_card_table,
};
use crate::runtime::alloc::{AllocationCollectorPoll, AllocationSafepointState};
use thiserror::Error;

const ROOTS_TABLE: &str = "roots";
const WORKLIST_TABLE: &str = "worklist";
const VISITED_TABLE: &str = "visited";
const OBJECTS_TABLE: &str = "objects";
const EDGES_TABLE: &str = "edges";
const MINOR_GC_ROOTS_TABLE: &str = "minor-GC roots";
const MINOR_GC_NURSERY_OBJECTS_TABLE: &str = "minor-GC nursery objects";
const MINOR_GC_NURSERY_FIELDS_TABLE: &str = "minor-GC nursery fields";
const MINOR_GC_NURSERY_FIELD_VALUES_TABLE: &str = "minor-GC nursery field values";
const MINOR_GC_NURSERY_LAYOUTS_TABLE: &str = "minor-GC nursery layouts";
const MINOR_GC_REFERENCE_SLOTS_TABLE: &str = "minor-GC reference slots";
const MINOR_GC_OBJECT_BYTE_COPY_REQUESTS_TABLE: &str = "minor-GC object byte-copy requests";
const MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE: &str = "minor-GC forwarding slot buffer";
const MINOR_GC_REFERENCE_BUFFER_TABLE: &str = "minor-GC reference buffer";
const MINOR_GC_HEAP_FIELD_WRITEBACKS_TABLE: &str = "minor-GC heap field writebacks";
const MINOR_GC_ROOT_WRITEBACKS_TABLE: &str = "minor-GC root writebacks";

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
}

/// A precise object field edge.
#[derive(Clone, Debug)]
pub struct HeapEdge {
    source: HeapEdgeSource,
    value: Value,
}

impl HeapEdge {
    fn new(source: HeapEdgeSource, value: Value) -> Self {
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

    /// Returns the explicit roots that seeded this scan.
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
}

impl AllocationCollectorPollReferenceSlot {
    fn new(source: AllocationCollectorPollReferenceSource, value: ResolvedValueGeneration) -> Self {
        Self { source, value }
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
    roots: Vec<ResolvedValueGeneration>,
    nursery_objects: Vec<NurseryObjectAge>,
    nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
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
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
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
            roots,
            nursery_objects,
            nursery_fields,
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
            roots,
            nursery_objects,
            nursery_fields,
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

    /// Builds ordered minor-GC commit metadata for this poll plan.
    ///
    /// The returned value keeps this plan's copied reference-slot labels next to
    /// the validated lower-level commit plan and the allocation-state snapshot
    /// used by later heap-backed buffer derivation. It still does not own mutable
    /// evaluator roots, object fields, object bytes, forwarding slots, or
    /// remembered-set storage. The destination wrapper must preserve this poll
    /// plan's survivor count, source order, and copy/promote actions.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if destination placements or relocation
    /// destinations do not match this poll plan, if any subplan cannot reserve
    /// storage or detects byte-size overflow, if the remembered-set refresh
    /// cannot be built, or if the subplans are not mutually consistent.
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
        let commit_plan = MinorGcCommitPlan::from_parts(
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
        )?;
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

    /// Returns the materialized relocation-destination plan.
    pub const fn relocation_destinations(&self) -> &MinorGcRelocationDestinationPlan {
        &self.relocation_destinations
    }

    /// Returns materialized relocation destinations in survivor-frontier order.
    pub fn destinations(&self) -> &[MinorGcRelocationDestination] {
        self.relocation_destinations.destinations()
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
    if record.layout.size_bytes != copy.size_bytes() || record.layout.align != copy.align() {
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
    /// or if a copied root slot no longer matches its lower-level rewrite source.
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
                rewrite.replacement(),
            ));
        }

        Ok(AllocationCollectorPollRootWritebackPlan::new(writebacks))
    }

    /// Applies this allocation-poll commit plan to caller-owned buffers.
    ///
    /// The allocation-poll layer first checks that the caller supplied the same
    /// reference values captured with the copied poll reference labels. It then
    /// delegates byte-copy buffers, forwarding slots, reference values, and
    /// remembered-set state to the lower-level validated commit plan. This
    /// remains a caller-buffer bridge and does not bind those buffers to live
    /// evaluator roots, heap-object fields, object headers, or semispace
    /// storage.
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
    /// headers, or semispace storage.
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
        if buffers.references.len() != self.reference_slots.len() {
            return Err(
                EvalHeapError::CollectorPollCommitReferenceSlotLengthMismatch {
                    expected: self.reference_slots.len(),
                    actual: buffers.references.len(),
                },
            );
        }
        for (index, (slot, actual)) in self
            .reference_slots
            .iter()
            .zip(buffers.references.iter().copied())
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

        self.commit_plan
            .apply_to_buffers_with_report(MinorGcCommitBuffers::new(
                buffers.object_byte_copies,
                buffers.forwarding_slots,
                buffers.references,
                buffers.remembered_set,
            ))
            .map_err(EvalHeapError::from)
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
}

/// One root-backed reference that must be rewritten after minor GC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollRootWriteback {
    slot: usize,
    source: EvalRootSource,
    expected: ResolvedValueGeneration,
    replacement: ResolvedValueGeneration,
}

impl AllocationCollectorPollRootWriteback {
    fn new(
        slot: usize,
        source: EvalRootSource,
        expected: ResolvedValueGeneration,
        replacement: ResolvedValueGeneration,
    ) -> Self {
        Self {
            slot,
            source,
            expected,
            replacement,
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

    /// Returns the relocated value that must replace [`Self::expected`].
    pub const fn replacement(&self) -> ResolvedValueGeneration {
        self.replacement
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
/// Remembered-source fields are validated and rewritten in the same
/// old/permanent object. Nursery fields are validated against the current
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
    /// This matches [`Self::validation_object`] for remembered-source fields and
    /// names the relocated object for copied nursery fields.
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

/// Caller-owned buffers for applying an allocation-poll minor-GC commit plan.
pub struct AllocationCollectorPollMinorGcCommitBuffers<'a, 'bytes> {
    object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
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
            self.records.len(),
            self.region_owner,
            self.worker_region_epoch,
            self.allocation_safepoints(),
            self.permanent_allocation_safepoints(),
        ))
    }

    /// Converts a collector-poll heap graph snapshot into a minor-GC plan.
    ///
    /// Worker-domain records are treated as current young-generation objects.
    /// Permanent shared records are treated as permanent objects and therefore
    /// enter the plan only through remembered permanent-to-young edges. The
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
    /// edge references an unknown object or is not permanent-to-young, if a
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

    /// Converts a collector-poll heap graph snapshot into a card-table-checked
    /// minor-GC plan.
    ///
    /// This performs the same planning work as [`Self::plan_collector_poll_minor_gc`]
    /// and additionally verifies that every remembered edge's source object is
    /// covered by the supplied dirty-card snapshot. The check is conservative at
    /// card granularity: a dirty card may cover more than one source object.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::plan_collector_poll_minor_gc`]. Also returns
    /// [`EvalHeapError::MissingCollectorPollDirtyCard`] when a remembered edge
    /// is not covered by the dirty-card snapshot.
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
        self.validate_current_permanent_edges_are_remembered(remembered_set)?;

        let roots = self.minor_gc_roots_for_poll_scan(poll_scan)?;
        let nursery_objects = self.current_nursery_objects()?;
        let nursery_fields = self.current_nursery_fields()?;
        let nursery_field_views = nursery_field_views(&nursery_fields)?;
        let plan = MinorGcPlan::from_roots_remembered_and_fields(
            roots.iter().copied(),
            remembered_set,
            collection_epoch,
            &nursery_objects,
            &nursery_field_views,
            promotion_policy,
        )?;
        let reference_slots = self.minor_gc_reference_slots_for_plan(
            poll_scan,
            remembered_set,
            &plan,
            &nursery_fields,
        )?;

        Ok(AllocationCollectorPollMinorGcPlan::new(
            poll_scan.poll(),
            poll_scan.heap_records(),
            poll_scan.worker_region_owner(),
            poll_scan.worker_region_epoch(),
            poll_scan.allocation_safepoints(),
            poll_scan.permanent_allocation_safepoints(),
            remembered_set_from_snapshot(remembered_set)?,
            roots,
            nursery_objects,
            nursery_fields,
            reference_slots,
            plan,
        ))
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

    /// Derives a reference buffer for heap-field-backed commit slots.
    ///
    /// This is a live side-table binding precursor for remembered-source fields
    /// and copied nursery fields. It validates that each saved field index still
    /// points at the same [`HeapEdgeSource`] label before reading the current
    /// value. Copied tree-walk/JIT root slots are rejected because [`EvalHeap`]
    /// does not own their mutable storage.
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
    /// The returned plan contains only remembered-source and nursery-field slots
    /// that the lower-level commit plan will rewrite. Root slots are skipped
    /// because their mutable storage is owned by the active tree-walk/JIT
    /// safepoint machinery, not by [`EvalHeap`]. Every heap-field slot is
    /// re-read from the current typed side table before it is admitted so stale
    /// field labels or changed field values fail before a future mutating writeback.
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
            HeapObjectValue::String(_) | HeapObjectValue::Path(_) => {}
            HeapObjectValue::List(list) => {
                for (index, value) in list.iter().copied().enumerate() {
                    push_heap_edge(&mut edges, HeapEdgeSource::ListElement { index }, value)?;
                }
            }
            HeapObjectValue::Attrs { shape, attrs } => {
                for (slot, entry) in attrs.entries_by_symbol().iter().enumerate() {
                    push_heap_edge(
                        &mut edges,
                        HeapEdgeSource::AttrBinding {
                            shape: *shape,
                            slot,
                            key: entry.key,
                        },
                        entry.value,
                    )?;
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
                }
                ThunkState::Forced => {
                    if let Some(value) = thunk.cell().cached_value()? {
                        push_heap_edge(&mut edges, HeapEdgeSource::ThunkCachedResult, value)?;
                    }
                }
            },
        }
        Ok(edges)
    }

    fn validate_collector_poll_scan_is_current(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<(), EvalHeapError> {
        for root in poll_scan.scan().roots() {
            self.record_for_scannable_value(root.value())?;
        }

        for object in poll_scan.scan().objects() {
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

    fn validate_collector_poll_snapshot_allocation_state(
        &self,
        poll_scan: &AllocationCollectorPollScan,
    ) -> Result<(), EvalHeapError> {
        if poll_scan.heap_records() != self.records.len() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if poll_scan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if poll_scan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if poll_scan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if poll_scan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed",
                expected_records: poll_scan.heap_records(),
                actual_records: self.records.len(),
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
            if source_generation != HeapGeneration::Permanent
                || target_generation != HeapGeneration::Young
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
        plan: &MinorGcPlan,
        nursery_fields: &[AllocationCollectorPollNurseryFields],
    ) -> Result<Vec<AllocationCollectorPollReferenceSlot>, EvalHeapError> {
        let mut reference_slots = Vec::new();
        for root in poll_scan.scan().roots() {
            push_reference_slot(
                &mut reference_slots,
                AllocationCollectorPollReferenceSource::Root {
                    source: root.source().clone(),
                },
                self.resolved_generation_for_value(root.value())?,
            )?;
        }

        for edge in remembered_set.edges() {
            self.push_remembered_edge_reference_slots(&mut reference_slots, *edge)?;
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
        let source_record = self.record_for_gc_address(edge.source(), "source")?;
        let source_edges = self.scan_record_edges(source_record)?;
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
        let record = self.record_for_reference_slot_object(object)?;
        let edges = self.scan_record_edges(record)?;
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
        let record = self.record_for_gc_address(address, role)?;
        Ok(generation_for_record(record))
    }

    fn record_for_gc_address(
        &self,
        address: GcHeapAddress,
        role: &'static str,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollRememberedEdgeAddress { role, address })
    }

    fn record_for_minor_gc_survivor(
        &self,
        address: GcHeapAddress,
    ) -> Result<&HeapRecord, EvalHeapError> {
        let record = self
            .records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollSurvivorAddress { address })?;
        if generation_for_record(record) != HeapGeneration::Young {
            return Err(EvalHeapError::GenerationalGc(
                GenerationalGcError::StaleNurseryObjectLayout { address },
            ));
        }
        Ok(record)
    }

    fn record_for_reference_slot_object(
        &self,
        address: GcHeapAddress,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address.address_bits())
            .ok_or(EvalHeapError::UnknownCollectorPollReferenceSlotAddress { address })
    }

    fn validate_collector_poll_plan_allocation_state(
        &self,
        plan: &AllocationCollectorPollMinorGcPlan,
    ) -> Result<(), EvalHeapError> {
        if plan.heap_records() != self.records.len() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if plan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if plan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if plan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if plan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed since minor-GC planning",
                expected_records: plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        Ok(())
    }

    fn validate_collector_poll_commit_allocation_state(
        &self,
        commit_plan: &AllocationCollectorPollMinorGcCommitPlan<'_>,
    ) -> Result<(), EvalHeapError> {
        if commit_plan.heap_records() != self.records.len() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "heap record count changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if commit_plan.worker_region_owner() != self.region_owner {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region owner changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if commit_plan.worker_region_epoch() != self.worker_region_epoch {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker region epoch changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if commit_plan.allocation_safepoints() != self.allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "worker allocation safepoints changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        if commit_plan.permanent_allocation_safepoints() != self.permanent_allocation_safepoints() {
            return Err(EvalHeapError::CollectorPollScanStaleHeapSnapshot {
                reason: "permanent allocation safepoints changed since minor-GC commit planning",
                expected_records: commit_plan.heap_records(),
                actual_records: self.records.len(),
            });
        }
        Ok(())
    }
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
    slots.push(AllocationCollectorPollReferenceSlot::new(source, value));
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
    match record.allocation_domain {
        HeapAllocationDomain::Worker => HeapGeneration::Young,
        HeapAllocationDomain::PermanentShared => HeapGeneration::Permanent,
    }
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

fn push_heap_edge(
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

fn push_worklist(worklist: &mut VecDeque<Value>, value: Value) -> Result<(), EvalHeapError> {
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

fn push_visited(visited: &mut HashSet<usize>, address: usize) -> Result<bool, EvalHeapError> {
    if visited.contains(&address) {
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
    Ok(visited.insert(address))
}

fn push_object_scan(
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

const fn is_scannable_eval_heap_value(value: Value) -> bool {
    matches!(
        value.tag(),
        ValueTag::String
            | ValueTag::Path
            | ValueTag::List
            | ValueTag::Attrs
            | ValueTag::Lambda
            | ValueTag::Primop
            | ValueTag::Thunk
    )
}

fn heap_ptr(value: Value) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
    let tag = value.tag();
    let ptr = value.as_heap_ptr().map_err(EvalHeapError::Value)?;
    Ok((tag, ptr))
}
