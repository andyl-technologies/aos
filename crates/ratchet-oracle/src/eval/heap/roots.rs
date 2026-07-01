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
    GcHeapAddress, GenerationalGcError, HeapGeneration, MinorGcCommitBuffers, MinorGcCommitPlan,
    MinorGcDestinationAllocationPlan, MinorGcDestinationBases, MinorGcDestinationPlacementPlan,
    MinorGcForwardingPointerPlan, MinorGcForwardingSlot, MinorGcObjectByteCopyBuffer,
    MinorGcObjectCopyPlan, MinorGcPlan, MinorGcPromotionPolicy, MinorGcReferenceRewritePlan,
    MinorGcRelocationDestination, MinorGcRelocationDestinationPlan, MinorGcRelocationPlan,
    MinorGcRememberedSetRefreshPlan, NurseryObjectAge, NurseryObjectFields, NurseryObjectLayout,
    RememberedEdge, RememberedSet, RememberedSetEpoch, RememberedSetSnapshot,
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
const MINOR_GC_REFERENCE_SLOTS_TABLE: &str = "minor-GC reference slots";

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

    /// Returns the reference value copied from the slot.
    pub const fn value(&self) -> ResolvedValueGeneration {
        self.value
    }
}

/// A collector-poll snapshot converted into minor-GC planner inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcPlan {
    poll: AllocationCollectorPoll,
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
        remembered_set: RememberedSet,
        roots: Vec<ResolvedValueGeneration>,
        nursery_objects: Vec<NurseryObjectAge>,
        nursery_fields: Vec<AllocationCollectorPollNurseryFields>,
        reference_slots: Vec<AllocationCollectorPollReferenceSlot>,
        plan: MinorGcPlan,
    ) -> Self {
        Self {
            poll,
            remembered_set,
            roots,
            nursery_objects,
            nursery_fields,
            reference_slots,
            plan,
        }
    }

    /// Returns the allocation safepoint collector-poll request.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
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
    /// the validated lower-level commit plan. It still does not own mutable
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

/// Commit metadata for an allocation-poll minor-GC plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationCollectorPollMinorGcCommitPlan<'a> {
    reference_slots: &'a [AllocationCollectorPollReferenceSlot],
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
            .apply_to_buffers(MinorGcCommitBuffers::new(
                buffers.object_byte_copies,
                buffers.forwarding_slots,
                buffers.references,
                buffers.remembered_set,
            ))
            .map_err(EvalHeapError::from)
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
        let reference_slots = self.minor_gc_reference_slots_for_plan(
            poll_scan,
            remembered_set,
            &plan,
            &nursery_fields,
        )?;

        Ok(AllocationCollectorPollMinorGcPlan::new(
            poll_scan.poll(),
            remembered_set_from_snapshot(remembered_set)?,
            roots,
            nursery_objects,
            nursery_fields,
            reference_slots,
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
            push_reference_slot(
                &mut reference_slots,
                AllocationCollectorPollReferenceSource::RememberedEdge { edge: *edge },
                ResolvedValueGeneration::Heap {
                    address: edge.target(),
                    generation: HeapGeneration::Young,
                },
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
                )?;
            }
        }

        Ok(reference_slots)
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
