//! Safepoint root-set construction for the tree-walk evaluator.
//!
//! Allocation safepoints need a precise set of live heap values before a moving
//! collector can run. This module exposes the tree-walk evaluator state that is
//! already explicit in Rust data structures: active lexical frames, dynamic
//! `with` scopes, scoped-import globals, active force continuations,
//! first-class primop arguments, and permanent hash-cons roots.

use std::{collections::BTreeMap, path::PathBuf};

use thiserror::Error;

use crate::eval::heap::EvalRootSource;

use super::*;

const TREE_WALK_SAFEPOINT_ROOT_WRITEBACK_SLOTS_TABLE: &str =
    "tree-walk safepoint root writeback slots";

/// A tree-walk safepoint root-set construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkSafepointRootError {
    /// Active environment state could not be snapshotted.
    #[error("failed to snapshot tree-walk environment roots: {0}")]
    Environment(#[from] EvalEnvError),
    /// Root-set storage could not be extended.
    #[error("failed to build tree-walk safepoint root set: {0}")]
    RootSet(#[from] super::super::heap::EvalRootSetError),
    /// Active primop root bookkeeping was internally inconsistent.
    #[error("active primop root frame [{start}, {start} + {len}) exceeds {roots} registered roots")]
    ActivePrimopRootFrameOutOfBounds {
        /// The recorded start offset in the active primop root stack.
        start: usize,
        /// The recorded frame length.
        len: usize,
        /// The number of active primop roots currently registered.
        roots: usize,
    },
}

/// A tree-walk safepoint heap-scan failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkSafepointScanError {
    /// Root-set construction failed before the heap scan began.
    #[error("failed to build tree-walk safepoint roots: {0}")]
    Roots(#[from] TreeWalkSafepointRootError),
    /// The supplied allocation poll is no longer current for its allocator tier.
    #[error(
        "allocation collector poll {poll:?} is stale for its allocator tier; current poll is {current:?}"
    )]
    StaleCollectorPoll {
        /// The stale collector poll supplied by the caller.
        poll: AllocationCollectorPoll,
        /// The current collector poll for the same allocation tier, if any.
        current: Option<AllocationCollectorPoll>,
    },
    /// The precise heap scanner rejected the constructed root graph.
    #[error("failed to scan tree-walk safepoint roots: {0}")]
    Heap(#[from] EvalHeapError),
}

/// A tree-walk safepoint root-writeback failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkSafepointRootWritebackError {
    /// Building the current collector-poll root graph failed.
    #[error("failed to scan tree-walk safepoint roots before writeback: {0}")]
    Scan(#[from] TreeWalkSafepointScanError),
    /// Root-slot writeback validation failed.
    #[error("failed to apply tree-walk safepoint root writebacks: {0}")]
    Heap(#[from] EvalHeapError),
    /// Reading or writing a lexical frame root failed.
    #[error("failed to access tree-walk environment root: {0}")]
    Environment(#[from] EvalEnvError),
    /// A planned root source has no mutable tree-walk root storage in this
    /// precursor.
    #[error("tree-walk safepoint root writeback source {root_source:?} is unsupported")]
    UnsupportedSource {
        /// The unsupported root source.
        root_source: EvalRootSource,
    },
    /// A planned mutable root source is not currently live in the tree-walk
    /// evaluator state supplied by the caller.
    #[error("tree-walk safepoint root writeback source {root_source:?} is not live")]
    SourceUnavailable {
        /// The unavailable root source.
        root_source: EvalRootSource,
    },
    /// A root-only safepoint writeback helper encountered heap-field
    /// writebacks that require a broader live reference writer.
    #[error(
        "tree-walk safepoint root-only writeback plan contains {heap_field_writebacks} heap-field writebacks"
    )]
    UnsupportedHeapFieldWritebacks {
        /// The number of heap-field writebacks that were not applied.
        heap_field_writebacks: usize,
    },
}

/// A tree-walk safepoint minor-GC root-writeback summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcRootWritebackReport {
    poll: AllocationCollectorPoll,
    scanned_roots: usize,
    scanned_objects: usize,
    survivors: usize,
    reference_slots: usize,
    root_writebacks: usize,
    heap_field_writebacks: usize,
    applied_root_writebacks: usize,
}

impl TreeWalkSafepointMinorGcRootWritebackReport {
    fn new(
        poll: AllocationCollectorPoll,
        scanned_roots: usize,
        scanned_objects: usize,
        survivors: usize,
        reference_slots: usize,
        root_writebacks: usize,
        heap_field_writebacks: usize,
        applied_root_writebacks: usize,
    ) -> Self {
        Self {
            poll,
            scanned_roots,
            scanned_objects,
            survivors,
            reference_slots,
            root_writebacks,
            heap_field_writebacks,
            applied_root_writebacks,
        }
    }

    /// Returns the collector poll used to derive this writeback.
    pub const fn poll(self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the number of explicit roots in the safepoint scan.
    pub const fn scanned_roots(self) -> usize {
        self.scanned_roots
    }

    /// Returns the number of heap objects reached by the safepoint scan.
    pub const fn scanned_objects(self) -> usize {
        self.scanned_objects
    }

    /// Returns the number of young survivors in the minor-GC plan.
    pub const fn survivors(self) -> usize {
        self.survivors
    }

    /// Returns the number of reference slots in the commit plan.
    pub const fn reference_slots(self) -> usize {
        self.reference_slots
    }

    /// Returns the number of root writebacks derived from the commit plan.
    pub const fn root_writebacks(self) -> usize {
        self.root_writebacks
    }

    /// Returns the number of heap-field writebacks derived from the commit plan.
    pub const fn heap_field_writebacks(self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the number of live tree-walk root slots rewritten.
    pub const fn applied_root_writebacks(self) -> usize {
        self.applied_root_writebacks
    }
}

/// A tree-walk safepoint minor-GC reference-writeback plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcReferenceWritebackPlan {
    poll: AllocationCollectorPoll,
    scanned_roots: usize,
    scanned_objects: usize,
    survivors: usize,
    reference_slots: usize,
    writebacks: AllocationCollectorPollReferenceWritebackPlan,
}

impl TreeWalkSafepointMinorGcReferenceWritebackPlan {
    fn new(
        poll: AllocationCollectorPoll,
        scanned_roots: usize,
        scanned_objects: usize,
        survivors: usize,
        reference_slots: usize,
        writebacks: AllocationCollectorPollReferenceWritebackPlan,
    ) -> Self {
        Self {
            poll,
            scanned_roots,
            scanned_objects,
            survivors,
            reference_slots,
            writebacks,
        }
    }

    /// Returns the collector poll used to derive this plan.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the number of explicit roots in the safepoint scan.
    pub const fn scanned_roots(&self) -> usize {
        self.scanned_roots
    }

    /// Returns the number of heap objects reached by the safepoint scan.
    pub const fn scanned_objects(&self) -> usize {
        self.scanned_objects
    }

    /// Returns the number of young survivors in the minor-GC plan.
    pub const fn survivors(&self) -> usize {
        self.survivors
    }

    /// Returns the number of reference slots in the commit plan.
    pub const fn reference_slots(&self) -> usize {
        self.reference_slots
    }

    /// Returns the complete root and heap-field writeback plan.
    pub const fn writebacks(&self) -> &AllocationCollectorPollReferenceWritebackPlan {
        &self.writebacks
    }

    /// Returns the number of root writebacks in the plan.
    pub fn root_writebacks(&self) -> usize {
        self.writebacks.root_writebacks().len()
    }

    /// Returns the number of heap-field writebacks in the plan.
    pub fn heap_field_writebacks(&self) -> usize {
        self.writebacks.heap_field_writebacks().len()
    }
}

/// Caller-owned buffers after applying safepoint reference writebacks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcReferenceWritebackBufferApplication {
    poll: AllocationCollectorPoll,
    scanned_roots: usize,
    scanned_objects: usize,
    survivors: usize,
    reference_slots: usize,
    root_writebacks: usize,
    heap_field_writebacks: usize,
    report: AllocationCollectorPollReferenceWritebackReport,
    root_value_writeback_slots: Vec<AllocationCollectorPollRootValueWritebackSlot>,
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
}

impl TreeWalkSafepointMinorGcReferenceWritebackBufferApplication {
    fn new(
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        report: AllocationCollectorPollReferenceWritebackReport,
        root_value_writeback_slots: Vec<AllocationCollectorPollRootValueWritebackSlot>,
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    ) -> Self {
        Self {
            poll: plan.poll(),
            scanned_roots: plan.scanned_roots(),
            scanned_objects: plan.scanned_objects(),
            survivors: plan.survivors(),
            reference_slots: plan.reference_slots(),
            root_writebacks: plan.root_writebacks(),
            heap_field_writebacks: plan.heap_field_writebacks(),
            report,
            root_value_writeback_slots,
            heap_field_writeback_slots,
        }
    }

    /// Returns the collector poll used to derive the writebacks.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.poll
    }

    /// Returns the number of explicit roots in the safepoint scan.
    pub const fn scanned_roots(&self) -> usize {
        self.scanned_roots
    }

    /// Returns the number of heap objects reached by the safepoint scan.
    pub const fn scanned_objects(&self) -> usize {
        self.scanned_objects
    }

    /// Returns the number of young survivors in the minor-GC plan.
    pub const fn survivors(&self) -> usize {
        self.survivors
    }

    /// Returns the number of reference slots in the commit plan.
    pub const fn reference_slots(&self) -> usize {
        self.reference_slots
    }

    /// Returns the number of planned root writebacks.
    pub const fn root_writebacks(&self) -> usize {
        self.root_writebacks
    }

    /// Returns the number of planned heap-field writebacks.
    pub const fn heap_field_writebacks(&self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the caller-owned buffer writeback report.
    pub const fn report(&self) -> AllocationCollectorPollReferenceWritebackReport {
        self.report
    }

    /// Returns the number of caller-owned typed root slots rewritten.
    pub const fn applied_root_writebacks(&self) -> usize {
        self.report.root_writebacks()
    }

    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn applied_heap_field_writebacks(&self) -> usize {
        self.report.heap_field_writebacks()
    }

    /// Returns the total number of caller-owned reference slots rewritten.
    pub const fn applied_writebacks(&self) -> usize {
        self.report.writebacks()
    }

    /// Returns typed root slots after applying planned replacements.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        &self.root_value_writeback_slots
    }

    /// Returns heap-field buffer slots materialized from live fields after
    /// applying planned replacements.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
    }
}

impl TreeWalk {
    /// Builds the explicit heap roots live at the current tree-walk safepoint.
    ///
    /// The returned set includes active lexical frame slots, active `with`
    /// scopes, active scoped-import globals, active force continuations,
    /// first-class primop arguments, and permanent interned/hash-cons table
    /// entries. It deliberately does not infer roots from arbitrary Rust locals;
    /// evaluator code that keeps a heap value live across an allocation
    /// safepoint must register that value in one of these explicit structures.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootError`] if an active environment frame
    /// cannot be snapshotted, if a root-set length overflows, or if storage for
    /// another root cannot be reserved.
    pub fn safepoint_root_set(&self) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        let mut roots = EvalRootSet::new();

        for (frame_index, frame) in self.env.iter().enumerate() {
            let slots = frame.slot_values()?;
            for (slot_index, value) in slots.into_iter().enumerate() {
                roots.try_push_tree_walk_frame(frame_index, slot_index, value)?;
            }
        }

        for (depth, scope) in self.with_scopes.iter().enumerate() {
            roots.try_push_with_scope(depth, scope.value())?;
        }

        for (depth, value) in self.scoped_globals.iter().copied().enumerate() {
            roots.try_push_scoped_global(depth, value)?;
        }

        for (depth, suspended) in self.suspended_env_roots.iter().rev().enumerate() {
            for (frame_index, frame) in suspended.env.iter().enumerate() {
                let slots = frame.slot_values()?;
                for (slot_index, value) in slots.into_iter().enumerate() {
                    roots.try_push_suspended_tree_walk_frame(
                        depth,
                        frame_index,
                        slot_index,
                        value,
                    )?;
                }
            }
            for (scope_depth, scope) in suspended.with_scopes.iter().enumerate() {
                roots.try_push_suspended_with_scope(depth, scope_depth, scope.value())?;
            }
            for (scope_depth, value) in suspended.scoped_globals.iter().copied().enumerate() {
                roots.try_push_suspended_scoped_global(depth, scope_depth, value)?;
            }
        }

        for (depth, value) in self.active_force_roots.iter().rev().copied().enumerate() {
            roots.try_push_force_continuation(depth, value)?;
        }

        for (call_depth, frame) in self.active_primop_arg_frames.iter().rev().enumerate() {
            let end = frame.start.checked_add(frame.len).ok_or(
                TreeWalkSafepointRootError::ActivePrimopRootFrameOutOfBounds {
                    start: frame.start,
                    len: frame.len,
                    roots: self.active_primop_arg_roots.len(),
                },
            )?;
            let args = self.active_primop_arg_roots.get(frame.start..end).ok_or(
                TreeWalkSafepointRootError::ActivePrimopRootFrameOutOfBounds {
                    start: frame.start,
                    len: frame.len,
                    roots: self.active_primop_arg_roots.len(),
                },
            )?;
            for (index, arg) in args.iter().enumerate() {
                roots.try_push_tree_walk_primop_argument(call_depth, index, arg.value())?;
            }
        }

        let mut import_index = 0usize;
        for entry in self.import_cache.values() {
            let ImportCacheEntry::Ready { value, .. } = entry else {
                continue;
            };
            roots.try_push_import_cache(import_index, *value)?;
            import_index = import_index
                .checked_add(1)
                .ok_or(super::super::heap::EvalRootSetError::LengthOverflow)?;
        }

        roots.try_extend(&self.heap.interned_root_set()?)?;
        Ok(roots)
    }

    /// Builds the explicit safepoint roots with caller-owned value-stack slots.
    ///
    /// Scannable heap values yielded by `value_stack` are recorded as
    /// [`EvalRootSource::ValueStack`]
    /// roots in iteration order. Inline values are skipped as non-roots, but
    /// slot indexes still reflect the original iterator position. This gives
    /// allocation-safepoint callers an explicit place to publish transient Rust
    /// locals or allocation return values before a precise collector-poll scan,
    /// without relying on conservative stack discovery.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootError`] if the base tree-walk root set
    /// cannot be built or if recording an additional value-stack root fails.
    pub fn safepoint_root_set_with_value_stack(
        &self,
        value_stack: impl IntoIterator<Item = Value>,
    ) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        let mut roots = self.safepoint_root_set()?;
        for (slot, value) in value_stack.into_iter().enumerate() {
            roots.try_push_value_stack(slot, value)?;
        }
        Ok(roots)
    }

    /// Scans the precise heap graph reachable at the current tree-walk
    /// safepoint.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointScanError`] if root construction fails or if
    /// the precise heap scanner rejects one of the constructed roots or edges.
    pub fn safepoint_heap_scan(&self) -> Result<PreciseHeapScan, TreeWalkSafepointScanError> {
        let roots = self.safepoint_root_set()?;
        Ok(self.heap.scan_precise_roots(&roots)?)
    }

    /// Scans the precise heap graph for a supplied allocation collector poll.
    ///
    /// The caller supplies the exact poll observed at the allocation safepoint
    /// and any transient value-stack roots that are live but not yet stored in
    /// the evaluator's explicit environment, force-continuation, primop, import,
    /// or intern tables. This method first rejects `poll` unless it is still
    /// the current collector poll for its allocator tier. It then validates and
    /// scans the same explicit roots used by [`Self::safepoint_heap_scan`],
    /// pairs the scan with `poll`, and does not invoke a collector or mutate
    /// heap state.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointScanError`] if `poll` is stale for its
    /// allocator tier, if root-set construction fails, or if the heap rejects
    /// the precise collector-poll scan.
    pub fn safepoint_collector_poll_scan(
        &self,
        poll: AllocationCollectorPoll,
        value_stack: impl IntoIterator<Item = Value>,
    ) -> Result<AllocationCollectorPollScan, TreeWalkSafepointScanError> {
        self.validate_current_collector_poll(poll)?;
        let roots = self.safepoint_root_set_with_value_stack(value_stack)?;
        Ok(self.heap.scan_collector_poll_roots(poll, &roots)?)
    }

    /// Applies typed root writebacks to explicit tree-walk safepoint roots.
    ///
    /// The supplied `value_stack` represents caller-owned transient slots in the
    /// same order passed to [`Self::safepoint_collector_poll_scan`]. This method
    /// reads every planned root source into a temporary typed slot buffer,
    /// validates that buffer with the existing root-writeback plan, and only
    /// then writes relocated values back to the matching tree-walk root storage.
    ///
    /// This precursor supports mutable tree-walk roots: value-stack slots,
    /// active and suspended lexical frames, active and suspended dynamic
    /// `with` scopes, active and suspended scoped-import globals, active force
    /// continuations, active first-class primop arguments, and ready import-cache
    /// entries. It deliberately does not mutate interned roots, detached
    /// primop-argument metadata, or JIT stack-map slots.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if a planned root source
    /// is unsupported, is not currently live, cannot be read or written, if the
    /// temporary slot buffer cannot be reserved, or if the root writeback plan
    /// rejects the current root values. Validation happens before any real
    /// tree-walk root storage is changed.
    pub fn apply_root_value_writebacks_to_safepoint_roots(
        &mut self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<AllocationCollectorPollRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let mut slots = self.safepoint_root_value_writeback_slots(plan, value_stack)?;
        let report = plan.apply_to_value_slots(&mut slots)?;
        for slot in &slots {
            self.write_safepoint_root_writeback_value(slot.source(), slot.value(), value_stack)?;
        }
        Ok(report)
    }

    /// Derives and applies root writebacks from a current minor-GC poll.
    ///
    /// This is a narrow live-root bridge for tree-walk allocation safepoints. It
    /// scans the current explicit tree-walk roots plus the supplied transient
    /// `value_stack`, builds a card-table-aware minor-GC plan from the
    /// evaluator's live remembered-set and card-table state, materializes
    /// relocation destinations from `bases`, derives the commit reference
    /// writebacks, and applies only the root-backed partition through
    /// [`Self::apply_root_value_writebacks_to_safepoint_roots`].
    ///
    /// Plans with heap-field writebacks are rejected before any root mutation,
    /// because applying only roots would publish a partial live collection. This
    /// helper still does not allocate destination records, copy object bodies,
    /// update heap fields, install forwarding headers, clear card-table state,
    /// publish a remembered-set refresh, reserve semispace storage, consume JIT
    /// stack maps, or dispatch Tier B automatically from allocation sites.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, if relocation or
    /// commit metadata cannot be derived, if the commit contains heap-field
    /// writebacks, or if live root validation rejects the current root storage.
    pub fn apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
    ) -> Result<TreeWalkSafepointMinorGcRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let reference_plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        let root_writebacks = reference_plan.root_writebacks();
        let heap_field_writebacks = reference_plan.heap_field_writebacks();
        if heap_field_writebacks != 0 {
            return Err(
                TreeWalkSafepointRootWritebackError::UnsupportedHeapFieldWritebacks {
                    heap_field_writebacks,
                },
            );
        }

        let applied = self.apply_root_value_writebacks_to_safepoint_roots(
            reference_plan.writebacks().root_writebacks(),
            value_stack,
        )?;
        Ok(TreeWalkSafepointMinorGcRootWritebackReport::new(
            reference_plan.poll(),
            reference_plan.scanned_roots(),
            reference_plan.scanned_objects(),
            reference_plan.survivors(),
            reference_plan.reference_slots(),
            root_writebacks,
            heap_field_writebacks,
            applied.writebacks(),
        ))
    }

    /// Derives complete reference writebacks from a current minor-GC poll.
    ///
    /// This helper runs the current tree-walk safepoint scan, card-table-aware
    /// minor-GC planning, destination materialization, commit-plan derivation,
    /// and reference-writeback extraction without mutating roots, heap fields,
    /// object bytes, forwarding headers, remembered sets, or card tables. It is
    /// the shared planning bridge for root-only and future full live-reference
    /// safepoint applicators.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, or if relocation,
    /// commit, or reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        let scan = self.safepoint_collector_poll_scan(poll, value_stack.iter().copied())?;
        let scanned_roots = scan.scan().roots().len();
        let scanned_objects = scan.scan().objects().len();
        let remembered_set = self.thunk_resolve_remembered_set.snapshot();
        let card_table = self.thunk_resolve_card_table.snapshot();
        let collection_epoch = self.thunk_resolve_remembered_set.epoch();
        let minor_gc = self.heap.plan_collector_poll_minor_gc_with_card_table(
            &scan,
            remembered_set,
            card_table,
            collection_epoch,
            promotion_policy,
        )?;
        let survivors = minor_gc.plan().survivors().len();
        let reference_slots = minor_gc.reference_slots().len();
        let destinations = self
            .heap
            .plan_collector_poll_minor_gc_relocation_destinations(&minor_gc, bases)?;
        let commit_plan = minor_gc
            .commit_plan(&destinations)
            .map_err(EvalHeapError::from)?;
        let writebacks = self
            .heap
            .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
        Ok(TreeWalkSafepointMinorGcReferenceWritebackPlan::new(
            poll,
            scanned_roots,
            scanned_objects,
            survivors,
            reference_slots,
            writebacks,
        ))
    }

    /// Applies complete reference writebacks to caller-owned safepoint buffers.
    ///
    /// This validates a previously derived current-poll reference plan against
    /// the explicit tree-walk roots visible through `value_stack`, reads
    /// caller-owned typed root slots and live heap-field slots, and applies the
    /// planned replacements into those buffers. It does not write the mutated
    /// buffers back to evaluator roots or heap records.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if caller-owned buffer
    /// storage cannot be reserved, or if the plan rejects the current root or
    /// live heap-field slots.
    pub fn apply_reference_writebacks_to_safepoint_buffers(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        self.validate_current_collector_poll(plan.poll())?;
        let mut root_value_writeback_slots = self.safepoint_root_value_writeback_slots(
            plan.writebacks().root_writebacks(),
            value_stack,
        )?;
        let mut heap_field_writeback_slots = self
            .heap
            .collector_poll_minor_gc_heap_field_writeback_slots(
                plan.writebacks().heap_field_writebacks(),
            )?;
        let report = plan.writebacks().apply_to_value_and_heap_field_slots(
            &mut root_value_writeback_slots,
            &mut heap_field_writeback_slots,
        )?;

        Ok(
            TreeWalkSafepointMinorGcReferenceWritebackBufferApplication::new(
                plan,
                report,
                root_value_writeback_slots,
                heap_field_writeback_slots,
            ),
        )
    }

    /// Derives and applies complete reference writebacks to owned buffers.
    ///
    /// This is the full-partition buffer counterpart to
    /// [`Self::apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots`].
    /// It derives the current root+heap-field reference writeback plan and
    /// applies both partitions to caller-owned buffers only. The evaluator's
    /// roots, heap records, object bodies, forwarding headers, remembered set,
    /// card table, and semispace storage are not mutated.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// the derived writebacks cannot be represented as caller-owned buffers, or
    /// if buffer validation rejects the derived current root or heap-field
    /// slots.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.apply_reference_writebacks_to_safepoint_buffers(&plan, value_stack)
    }

    fn safepoint_root_value_writeback_slots(
        &self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &[Value],
    ) -> Result<
        Vec<AllocationCollectorPollRootValueWritebackSlot>,
        TreeWalkSafepointRootWritebackError,
    > {
        let writebacks = plan.writebacks();
        let mut slots = Vec::new();
        slots.try_reserve_exact(writebacks.len()).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: TREE_WALK_SAFEPOINT_ROOT_WRITEBACK_SLOTS_TABLE,
                entries: writebacks.len(),
            }
        })?;

        for writeback in writebacks {
            let source = writeback.source().clone();
            let value = self.read_safepoint_root_writeback_value(&source, value_stack)?;
            slots.push(AllocationCollectorPollRootValueWritebackSlot::new(
                source, value,
            ));
        }

        Ok(slots)
    }

    fn read_safepoint_root_writeback_value(
        &self,
        source: &EvalRootSource,
        value_stack: &[Value],
    ) -> Result<Value, TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => value_stack
                .get(*slot)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::TreeWalkFrame { frame, slot } => self
                .env
                .get(*frame)
                .ok_or_else(|| root_writeback_source_unavailable(source))?
                .get(root_writeback_frame_slot(source, *slot)?)
                .map_err(TreeWalkSafepointRootWritebackError::Environment),
            EvalRootSource::SuspendedTreeWalkFrame { depth, frame, slot } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .env
                    .get(*frame)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?
                    .get(root_writeback_frame_slot(source, *slot)?)
                    .map_err(TreeWalkSafepointRootWritebackError::Environment)
            }
            EvalRootSource::WithScope { depth } => self
                .with_scopes
                .get(*depth)
                .map(EvalWithScope::value)
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedWithScope { depth, scope_depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .with_scopes
                    .get(*scope_depth)
                    .map(EvalWithScope::value)
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ScopedGlobal { depth } => self
                .scoped_globals
                .get(*depth)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::SuspendedScopedGlobal { depth, scope_depth } => {
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_root_index(
                        self.suspended_env_roots.len(),
                        *depth,
                        source,
                    )?)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .scoped_globals
                    .get(*scope_depth)
                    .copied()
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ForceContinuation { depth } => self
                .active_force_roots
                .get(reverse_root_index(
                    self.active_force_roots.len(),
                    *depth,
                    source,
                )?)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index } => {
                let root_index = active_primop_arg_root_index(self, *call_depth, *index, source)?;
                self.active_primop_arg_roots
                    .get(root_index)
                    .map(EvalPrimOpArg::value)
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ImportCache { index } => {
                read_import_cache_root(&self.import_cache, *index, source)
            }
            EvalRootSource::PrimopArgument { .. }
            | EvalRootSource::Interned { .. }
            | EvalRootSource::StackMap { .. } => Err(root_writeback_source_unsupported(source)),
        }
    }

    fn write_safepoint_root_writeback_value(
        &mut self,
        source: &EvalRootSource,
        value: Value,
        value_stack: &mut [Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => {
                let target = value_stack
                    .get_mut(*slot)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::TreeWalkFrame { frame, slot } => self
                .env
                .get(*frame)
                .ok_or_else(|| root_writeback_source_unavailable(source))?
                .set(root_writeback_frame_slot(source, *slot)?, value)
                .map_err(TreeWalkSafepointRootWritebackError::Environment),
            EvalRootSource::SuspendedTreeWalkFrame { depth, frame, slot } => {
                let suspended_index =
                    suspended_root_index(self.suspended_env_roots.len(), *depth, source)?;
                let suspended = self
                    .suspended_env_roots
                    .get(suspended_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                suspended
                    .env
                    .get(*frame)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?
                    .set(root_writeback_frame_slot(source, *slot)?, value)
                    .map_err(TreeWalkSafepointRootWritebackError::Environment)
            }
            EvalRootSource::WithScope { depth } => {
                let scope = self
                    .with_scopes
                    .get_mut(*depth)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *scope = EvalWithScope::new(scope.module(), scope.scope(), value);
                Ok(())
            }
            EvalRootSource::SuspendedWithScope { depth, scope_depth } => {
                let suspended_index =
                    suspended_root_index(self.suspended_env_roots.len(), *depth, source)?;
                let scope = self
                    .suspended_env_roots
                    .get_mut(suspended_index)
                    .and_then(|suspended| suspended.with_scopes.get_mut(*scope_depth))
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *scope = EvalWithScope::new(scope.module(), scope.scope(), value);
                Ok(())
            }
            EvalRootSource::ScopedGlobal { depth } => {
                let target = self
                    .scoped_globals
                    .get_mut(*depth)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::SuspendedScopedGlobal { depth, scope_depth } => {
                let suspended_index =
                    suspended_root_index(self.suspended_env_roots.len(), *depth, source)?;
                let target = self
                    .suspended_env_roots
                    .get_mut(suspended_index)
                    .and_then(|suspended| suspended.scoped_globals.get_mut(*scope_depth))
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::ForceContinuation { depth } => {
                let root_index = reverse_root_index(self.active_force_roots.len(), *depth, source)?;
                let target = self
                    .active_force_roots
                    .get_mut(root_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index } => {
                let root_index = active_primop_arg_root_index(self, *call_depth, *index, source)?;
                let arg = self
                    .active_primop_arg_roots
                    .get_mut(root_index)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *arg = EvalPrimOpArg::new_in_module(arg.module(), arg.id(), arg.span(), value);
                Ok(())
            }
            EvalRootSource::ImportCache { index } => {
                write_import_cache_root(&mut self.import_cache, *index, value, source)
            }
            EvalRootSource::PrimopArgument { .. }
            | EvalRootSource::Interned { .. }
            | EvalRootSource::StackMap { .. } => Err(root_writeback_source_unsupported(source)),
        }
    }

    pub(in crate::eval::tree_walk) fn gc_stress_boundary_scans(
        &self,
        value: Value,
    ) -> Result<EvalGcStressBoundaryScans, TreeWalkSafepointScanError> {
        let worker = match self.current_collector_poll_for_tier(RuntimeAllocatorTier::TierAOneShot)
        {
            Some(poll) => Some(self.safepoint_collector_poll_scan(poll, [value])?),
            None => None,
        };
        let permanent_shared =
            match self.current_collector_poll_for_tier(RuntimeAllocatorTier::PermanentShared) {
                Some(poll) => Some(self.safepoint_collector_poll_scan(poll, [value])?),
                None => None,
            };
        Ok(EvalGcStressBoundaryScans::new(worker, permanent_shared))
    }

    fn validate_current_collector_poll(
        &self,
        poll: AllocationCollectorPoll,
    ) -> Result<(), TreeWalkSafepointScanError> {
        let current = self.current_collector_poll_for_tier(poll.tier());
        if current == Some(poll) {
            return Ok(());
        }
        Err(TreeWalkSafepointScanError::StaleCollectorPoll { poll, current })
    }

    fn current_collector_poll_for_tier(
        &self,
        tier: RuntimeAllocatorTier,
    ) -> Option<AllocationCollectorPoll> {
        match tier {
            RuntimeAllocatorTier::TierAOneShot => self
                .heap
                .allocation_safepoints()
                .last_safepoint_collector_poll(),
            RuntimeAllocatorTier::PermanentShared => self
                .heap
                .permanent_allocation_safepoints()
                .last_safepoint_collector_poll(),
        }
    }

    pub(in crate::eval::tree_walk) fn push_active_force_root(
        &mut self,
        id: IrId,
        span: Span,
        value: Value,
    ) -> Result<(), TreeWalkError> {
        let roots = self
            .active_force_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_force_roots.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots },
                span,
            )
        })?;
        self.active_force_roots.push(value);
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn reserve_suspended_env_root_frame(
        &mut self,
        id: IrId,
        span: Span,
    ) -> Result<(), TreeWalkError> {
        let roots = self
            .suspended_env_roots
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.suspended_env_roots.try_reserve_exact(1).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots },
                span,
            )
        })?;
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn push_suspended_env_roots(
        &mut self,
        env: Vec<Rc<EvalFrame>>,
        with_scopes: Vec<EvalWithScope>,
        scoped_globals: Vec<Value>,
    ) {
        self.suspended_env_roots
            .push(SuspendedTreeWalkEnv::new(env, with_scopes, scoped_globals));
    }

    pub(in crate::eval::tree_walk) fn pop_suspended_env_roots(
        &mut self,
    ) -> Option<SuspendedTreeWalkEnv> {
        self.suspended_env_roots.pop()
    }

    pub(in crate::eval::tree_walk) fn pop_active_force_root(&mut self, value: Value) {
        let popped = self.active_force_roots.pop();
        debug_assert!(
            popped.is_some_and(|popped| popped.raw_eq(value)),
            "active force root stack is unbalanced"
        );
    }

    pub(in crate::eval::tree_walk) fn push_active_primop_arg_roots(
        &mut self,
        id: IrId,
        span: Span,
        args: &[EvalPrimOpArg],
    ) -> Result<(), TreeWalkError> {
        let arg_roots = self
            .active_primop_arg_roots
            .len()
            .checked_add(args.len())
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        let frames = self
            .active_primop_arg_frames
            .len()
            .checked_add(1)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.active_primop_arg_roots
            .try_reserve_exact(args.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                        id,
                        roots: arg_roots,
                    },
                    span,
                )
            })?;
        self.active_primop_arg_frames
            .try_reserve_exact(1)
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed { id, roots: frames },
                    span,
                )
            })?;

        let start = self.active_primop_arg_roots.len();
        self.active_primop_arg_roots.extend_from_slice(args);
        self.active_primop_arg_frames.push(ActivePrimopArgFrame {
            start,
            len: args.len(),
        });
        Ok(())
    }

    pub(in crate::eval::tree_walk) fn pop_active_primop_arg_roots(&mut self) {
        let Some(frame) = self.active_primop_arg_frames.pop() else {
            debug_assert!(false, "active primop root stack is unbalanced");
            return;
        };
        debug_assert_eq!(
            self.active_primop_arg_roots.len(),
            frame.start.saturating_add(frame.len),
            "active primop root frame length is unbalanced"
        );
        self.active_primop_arg_roots.truncate(frame.start);
    }
}

fn root_writeback_source_unavailable(
    source: &EvalRootSource,
) -> TreeWalkSafepointRootWritebackError {
    TreeWalkSafepointRootWritebackError::SourceUnavailable {
        root_source: source.clone(),
    }
}

fn root_writeback_source_unsupported(
    source: &EvalRootSource,
) -> TreeWalkSafepointRootWritebackError {
    TreeWalkSafepointRootWritebackError::UnsupportedSource {
        root_source: source.clone(),
    }
}

fn root_writeback_frame_slot(
    source: &EvalRootSource,
    slot: usize,
) -> Result<u32, TreeWalkSafepointRootWritebackError> {
    u32::try_from(slot).map_err(|_| root_writeback_source_unavailable(source))
}

fn reverse_root_index(
    len: usize,
    depth: usize,
    source: &EvalRootSource,
) -> Result<usize, TreeWalkSafepointRootWritebackError> {
    if depth >= len {
        return Err(root_writeback_source_unavailable(source));
    }
    Ok(len - 1 - depth)
}

fn suspended_root_index(
    len: usize,
    depth: usize,
    source: &EvalRootSource,
) -> Result<usize, TreeWalkSafepointRootWritebackError> {
    reverse_root_index(len, depth, source)
}

fn active_primop_arg_root_index(
    eval: &TreeWalk,
    call_depth: usize,
    index: usize,
    source: &EvalRootSource,
) -> Result<usize, TreeWalkSafepointRootWritebackError> {
    let frame_index = reverse_root_index(eval.active_primop_arg_frames.len(), call_depth, source)?;
    let frame = eval
        .active_primop_arg_frames
        .get(frame_index)
        .ok_or_else(|| root_writeback_source_unavailable(source))?;
    if index >= frame.len {
        return Err(root_writeback_source_unavailable(source));
    }
    let root_index = frame
        .start
        .checked_add(index)
        .ok_or_else(|| root_writeback_source_unavailable(source))?;
    if root_index >= eval.active_primop_arg_roots.len() {
        return Err(root_writeback_source_unavailable(source));
    }
    Ok(root_index)
}

fn read_import_cache_root(
    import_cache: &BTreeMap<PathBuf, ImportCacheEntry>,
    index: usize,
    source: &EvalRootSource,
) -> Result<Value, TreeWalkSafepointRootWritebackError> {
    let mut ready_index = 0usize;
    for entry in import_cache.values() {
        let ImportCacheEntry::Ready { value, .. } = entry else {
            continue;
        };
        if ready_index == index {
            return Ok(*value);
        }
        ready_index = ready_index.saturating_add(1);
    }
    Err(root_writeback_source_unavailable(source))
}

fn write_import_cache_root(
    import_cache: &mut BTreeMap<PathBuf, ImportCacheEntry>,
    index: usize,
    next: Value,
    source: &EvalRootSource,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    let mut ready_index = 0usize;
    for entry in import_cache.values_mut() {
        let ImportCacheEntry::Ready { value, .. } = entry else {
            continue;
        };
        if ready_index == index {
            *value = next;
            return Ok(());
        }
        ready_index = ready_index.saturating_add(1);
    }
    Err(root_writeback_source_unavailable(source))
}
