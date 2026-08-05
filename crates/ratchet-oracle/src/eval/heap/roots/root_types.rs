//! Root-set and heap-edge types: the thunk-resolve barrier adapter,
//! evaluator roots and the interned root set, heap edges, and precise scans.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

/// A write-barrier adapter for publishing a forced thunk result.
///
/// This adapter records edges from the source thunk captured at construction
/// time. Callers must pass it only to the [`crate::eval::thunk::ForceGuard`]
/// that owns the same source thunk; the guard API does not re-check that
/// pairing before publication.
#[derive(Debug)]
pub struct EvalHeapThunkResolveBarrier<'a> {
    pub(super) heap: &'a EvalHeap,
    pub(super) tier: GenerationalGcTier,
    pub(super) source: GcHeapAddress,
    pub(super) source_generation: HeapGeneration,
    pub(super) remembered_set: &'a mut RememberedSet,
    pub(super) card_table: Option<&'a mut GcCardTable>,
    pub(super) last_action: Option<ThunkResolveWriteBarrier>,
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
    pub(super) const fn new(source: EvalRootSource, value: Value) -> Self {
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
    /// A value retained by the packed-STG machine's value stack.
    StgValue {
        /// The stack depth, with zero nearest the active continuation.
        depth: usize,
    },
    /// A lazy argument retained by the packed-STG machine.
    StgArgument {
        /// The stack depth, with zero nearest the active continuation.
        depth: usize,
    },
    /// An edge retained by ordinary Node work detached from a blackholed cell.
    DetachedNodeThunkWork {
        /// Active detached-Node lease depth, nearest force first.
        depth: usize,
        /// Edge index in the canonical suspended-thunk edge stream.
        edge: usize,
    },
    /// An edge retained by typed thunk work detached from a blackholed head.
    DetachedTypedThunkWork {
        /// Active typed-work lease depth, with zero nearest the active force.
        depth: usize,
        /// Edge index in the canonical suspended-thunk edge stream.
        edge: usize,
    },
    /// A blackholed typed head whose work is expanded by sibling lease roots.
    DetachedTypedThunkHead {
        /// Active typed-work lease depth, with zero nearest the active force.
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

    /// Records a packed-STG value-stack slot when it contains a heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if root storage cannot grow.
    pub(in crate::eval) fn try_push_stg_value(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::StgValue { depth }, value)
    }

    /// Records a packed-STG lazy-argument slot when it contains a heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if root storage cannot grow.
    pub(in crate::eval) fn try_push_stg_argument(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::StgArgument { depth }, value)
    }

    /// Records one heap edge retained by detached typed thunk work.
    ///
    /// Returns `true` when the value was recorded, and `false` for an inline
    /// value that does not require tracing.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if root storage cannot grow.
    pub(in crate::eval) fn try_push_detached_typed_thunk_work(
        &mut self,
        depth: usize,
        edge: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(
            EvalRootSource::DetachedTypedThunkWork { depth, edge },
            value,
        )
    }

    /// Records one heap edge retained by detached ordinary Node work.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if root storage cannot grow.
    pub(in crate::eval) fn try_push_detached_node_thunk_work(
        &mut self,
        depth: usize,
        edge: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::DetachedNodeThunkWork { depth, edge }, value)
    }

    /// Records the permanent typed head owned by one detached-work lease.
    ///
    /// The precise scanners recognize this evaluator-only source as evidence
    /// that the matching lease roots externally expand the head's work.
    ///
    /// # Errors
    ///
    /// Returns [`EvalRootSetError`] if root storage cannot grow.
    pub(in crate::eval) fn try_push_detached_typed_thunk_head(
        &mut self,
        depth: usize,
        value: Value,
    ) -> Result<bool, EvalRootSetError> {
        self.try_push_heap_root(EvalRootSource::DetachedTypedThunkHead { depth }, value)
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

    pub(super) fn try_push_heap_root(
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
    // Pre-split audience was the heap module; widened path-explicitly
    // after the §2 relocation (root_scan.rs constructs edges directly).
    pub(in crate::eval::heap) fn new(source: HeapEdgeSource, value: Value) -> Self {
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
    pub(super) fn new(value: Value, edges: Vec<HeapEdge>) -> Self {
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
    pub(super) roots: Vec<EvalRoot>,
    pub(super) objects: Vec<HeapObjectScan>,
}

impl PreciseHeapScan {
    pub(super) fn with_root_capacity(roots: usize) -> Result<Self, EvalHeapError> {
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
