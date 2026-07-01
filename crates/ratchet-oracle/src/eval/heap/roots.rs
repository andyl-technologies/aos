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
use crate::eval::thunk::ThunkState;
use crate::heap::{
    GcHeapAddress, HeapGeneration, MinorGcPlan, MinorGcPromotionPolicy, NurseryObjectAge,
    NurseryObjectFields, RememberedEdge, RememberedSetEpoch, RememberedSetSnapshot,
    ResolvedValueGeneration,
};
use crate::runtime::alloc::AllocationCollectorPoll;
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
    allocation_safepoints: AllocationSafepointState,
    permanent_allocation_safepoints: AllocationSafepointState,
}

impl AllocationCollectorPollScan {
    fn new(
        poll: AllocationCollectorPoll,
        scan: PreciseHeapScan,
        heap_records: usize,
        allocation_safepoints: AllocationSafepointState,
        permanent_allocation_safepoints: AllocationSafepointState,
    ) -> Self {
        Self {
            poll,
            scan,
            heap_records,
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
    fields: Vec<ResolvedValueGeneration>,
}

impl AllocationCollectorPollNurseryFields {
    fn new(address: GcHeapAddress, fields: Vec<ResolvedValueGeneration>) -> Self {
        Self { address, fields }
    }

    /// Returns the young object whose fields were scanned.
    pub const fn address(&self) -> GcHeapAddress {
        self.address
    }

    /// Returns the object's precise outgoing field metadata.
    pub fn fields(&self) -> &[ResolvedValueGeneration] {
        &self.fields
    }
}

/// A collector-poll snapshot converted into minor-GC planner inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcPlan {
    poll: AllocationCollectorPoll,
    roots: Vec<ResolvedValueGeneration>,
    nursery_objects: Vec<NurseryObjectAge>,
    nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
    plan: MinorGcPlan,
}

impl AllocationCollectorPollMinorGcPlan {
    fn new(
        poll: AllocationCollectorPoll,
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
        plan: MinorGcPlan,
    ) -> Self {
        Self {
            poll,
            roots,
            nursery_objects,
            nursery_fields,
            plan,
        }
    }

    /// Returns the allocation safepoint collector-poll request.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
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

    /// Returns the planned young-generation survivor frontier.
    pub const fn plan(&self) -> &MinorGcPlan {
        &self.plan
    }
}

impl EvalHeap {
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
    /// visible permanent-to-young edge is missing from the remembered set, or if
    /// the minor-GC planner rejects the generated roots, age metadata, or field
    /// metadata.
    pub fn plan_collector_poll_minor_gc(
        &self,
        poll_scan: &AllocationCollectorPollScan,
        remembered_set: RememberedSetSnapshot<'_>,
        collection_epoch: RememberedSetEpoch,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<AllocationCollectorPollMinorGcPlan, EvalHeapError> {
        self.validate_collector_poll_snapshot_allocation_state(poll_scan)?;
        self.validate_collector_poll_scan_is_current(poll_scan)?;
        self.validate_remembered_set_snapshot(remembered_set)?;
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

        Ok(AllocationCollectorPollMinorGcPlan::new(
            poll_scan.poll(),
            roots,
            nursery_objects,
            nursery_fields,
            plan,
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

    fn scan_record_edges(&self, record: &HeapRecord) -> Result<Vec<HeapEdge>, EvalHeapError> {
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
                fields.push(self.resolved_generation_for_value(edge.value())?);
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
            nursery_fields.push(AllocationCollectorPollNurseryFields::new(address, fields));
        }
        Ok(nursery_fields)
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
        views.push(NurseryObjectFields::new(object.address(), object.fields()));
    }
    Ok(views)
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
