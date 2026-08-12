//! Error, report, plan, and application types for safepoint root writebacks.

use super::*;

/// A tree-walk safepoint root-set construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TreeWalkSafepointRootError {
    /// A flat capture owner could not be reconstructed from its signed handle.
    #[error("failed to resolve tree-walk flat-capture owner: {0}")]
    Heap(#[from] EvalHeapError),
    /// Active environment state could not be snapshotted.
    #[error("failed to snapshot tree-walk environment roots: {0}")]
    Environment(#[from] EvalEnvError),
    /// Root-set storage could not be extended.
    #[error("failed to build tree-walk safepoint root set: {0}")]
    RootSet(#[from] crate::eval::heap::EvalRootSetError),
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
    /// The requested allocator tier has no current collector poll.
    #[error("allocator tier {tier:?} has no current collector poll")]
    NoCurrentCollectorPoll {
        /// The allocator tier inspected for a current collector poll.
        tier: RuntimeAllocatorTier,
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
    /// Two roots claimed the same mutable evaluator slot.
    #[cfg(feature = "collection_poll_probe")]
    #[error("tree-walk safepoint root source {root_source:?} was enumerated more than once")]
    DuplicateSource {
        /// The duplicated root source.
        root_source: EvalRootSource,
    },
    /// A root changed between enumeration and readback.
    #[cfg(feature = "collection_poll_probe")]
    #[error(
        "tree-walk safepoint root source {root_source:?} changed between enumeration and readback"
    )]
    SnapshotMismatch {
        /// The root source whose current value differs from the snapshot.
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
    /// Live heap-field validation disagreed with the prevalidated buffer
    /// writeback count.
    #[error(
        "tree-walk live heap-field validation covered {live_heap_field_writebacks} field writebacks, but buffer validation rewrote {buffer_heap_field_writebacks}"
    )]
    LiveHeapFieldWritebackCountMismatch {
        /// The heap-field writes covered by live heap-field validation.
        live_heap_field_writebacks: usize,
        /// The heap-field slots rewritten by caller-owned buffer validation.
        buffer_heap_field_writebacks: usize,
    },
    /// The live remembered-set epoch no longer matches the source state
    /// consumed by a planned safepoint writeback.
    #[error(
        "tree-walk safepoint source remembered-set epoch {actual} does not match planned epoch {expected}"
    )]
    SourceRememberedSetEpochMismatch {
        /// The remembered-set epoch captured by the plan.
        expected: RememberedSetEpoch,
        /// The current remembered-set epoch.
        actual: RememberedSetEpoch,
    },
    /// The live remembered-set edge count no longer matches the source state
    /// consumed by a planned safepoint writeback.
    #[error(
        "tree-walk safepoint source remembered-set edge count {actual} does not match planned count {expected}"
    )]
    SourceRememberedSetLengthMismatch {
        /// The edge count captured by the plan.
        expected: usize,
        /// The current edge count.
        actual: usize,
    },
    /// One live remembered-set edge no longer matches the source state
    /// consumed by a planned safepoint writeback.
    #[error(
        "tree-walk safepoint source remembered-set edge mismatch at index {index}: expected {expected:?}, got {actual:?}"
    )]
    SourceRememberedSetEdgeMismatch {
        /// The mismatched remembered-set edge index.
        index: usize,
        /// The edge captured by the plan.
        expected: RememberedEdge,
        /// The current edge.
        actual: RememberedEdge,
    },
    /// The live card-table size no longer matches the source state consumed by
    /// a planned safepoint writeback.
    #[error("tree-walk safepoint source card size {actual} does not match planned size {expected}")]
    SourceCardTableCardSizeMismatch {
        /// The card size captured by the plan.
        expected: usize,
        /// The current card size.
        actual: usize,
    },
    /// The live dirty-card count no longer matches the source state consumed by
    /// a planned safepoint writeback.
    #[error(
        "tree-walk safepoint source dirty-card count {actual} does not match planned count {expected}"
    )]
    SourceCardTableLengthMismatch {
        /// The dirty-card count captured by the plan.
        expected: usize,
        /// The current dirty-card count.
        actual: usize,
    },
    /// One live dirty-card marker no longer matches the source state consumed
    /// by a planned safepoint writeback.
    #[error(
        "tree-walk safepoint source dirty-card mismatch at index {index}: expected {expected:?}, got {actual:?}"
    )]
    SourceCardTableDirtyCardMismatch {
        /// The mismatched dirty-card index.
        index: usize,
        /// The dirty-card marker captured by the plan.
        expected: GcDirtyCard,
        /// The current dirty-card marker.
        actual: GcDirtyCard,
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
    pub(super) fn new(
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
    source_remembered_set: RememberedSet,
    source_card_table: GcCardTable,
    remembered_set_refreshes: usize,
    next_remembered_set: RememberedSet,
    placement_plan: MinorGcDestinationPlacementPlan,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    object_body_plan: AllocationCollectorPollObjectByteCopyPlan,
    writebacks: AllocationCollectorPollReferenceWritebackPlan,
}

impl TreeWalkSafepointMinorGcReferenceWritebackPlan {
    pub(super) fn new(
        poll: AllocationCollectorPoll,
        scanned_roots: usize,
        scanned_objects: usize,
        survivors: usize,
        reference_slots: usize,
        source_remembered_set: RememberedSet,
        source_card_table: GcCardTable,
        remembered_set_refreshes: usize,
        next_remembered_set: RememberedSet,
        placement_plan: MinorGcDestinationPlacementPlan,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        object_body_plan: AllocationCollectorPollObjectByteCopyPlan,
        writebacks: AllocationCollectorPollReferenceWritebackPlan,
    ) -> Self {
        Self {
            poll,
            scanned_roots,
            scanned_objects,
            survivors,
            reference_slots,
            source_remembered_set,
            source_card_table,
            remembered_set_refreshes,
            next_remembered_set,
            placement_plan,
            forwarding_slots,
            object_body_plan,
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

    /// Returns the remembered set consumed by this plan.
    pub const fn source_remembered_set(&self) -> &RememberedSet {
        &self.source_remembered_set
    }

    /// Returns the number of remembered edges consumed by this plan.
    pub fn source_remembered_set_edges(&self) -> usize {
        self.source_remembered_set.len()
    }

    /// Returns the card table consumed by this plan.
    pub const fn source_card_table(&self) -> &GcCardTable {
        &self.source_card_table
    }

    /// Returns the number of dirty cards consumed by this plan.
    pub fn source_dirty_cards(&self) -> usize {
        self.source_card_table.len()
    }

    /// Returns the number of remembered-set refresh decisions in the commit plan.
    pub const fn remembered_set_refreshes(&self) -> usize {
        self.remembered_set_refreshes
    }

    /// Returns the rebuilt remembered set that a later commit would publish.
    ///
    /// This is retained planning metadata only; accessing it does not publish
    /// the set into evaluator state.
    pub const fn next_remembered_set(&self) -> &RememberedSet {
        &self.next_remembered_set
    }

    /// Returns the number of remembered edges in the rebuilt next-epoch set.
    pub fn next_remembered_set_edges(&self) -> usize {
        self.next_remembered_set.len()
    }

    /// Returns the destination placement metadata paired with relocation planning.
    pub const fn placement_plan(&self) -> &MinorGcDestinationPlacementPlan {
        &self.placement_plan
    }

    /// Returns the number of destination placements in the plan.
    pub fn destination_placements(&self) -> usize {
        self.placement_plan.len()
    }

    /// Returns reserved bytes needed for the next nursery destination space.
    pub const fn nursery_reserved_bytes(&self) -> usize {
        self.placement_plan.nursery_reserved_bytes()
    }

    /// Returns reserved bytes needed for old-generation destination space.
    pub const fn old_reserved_bytes(&self) -> usize {
        self.placement_plan.old_reserved_bytes()
    }

    /// Returns total reserved destination bytes, including alignment padding.
    pub const fn total_reserved_bytes(&self) -> usize {
        self.placement_plan.total_reserved_bytes()
    }

    /// Returns the filled forwarding slots for relocated source objects.
    pub fn forwarding_slots(&self) -> &[MinorGcForwardingSlot] {
        &self.forwarding_slots
    }

    /// Returns the number of forwarding pointers in the plan.
    pub fn forwarding_pointers(&self) -> usize {
        self.forwarding_slots.len()
    }

    /// Returns the object-copy plan for relocated destination records.
    pub const fn object_body_plan(&self) -> &AllocationCollectorPollObjectByteCopyPlan {
        &self.object_body_plan
    }

    /// Returns the number of relocated object bodies in the plan.
    pub fn object_bodies(&self) -> usize {
        self.object_body_plan.requests().len()
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
    pub(super) fn new(
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

    /// Returns heap-field buffer slots, originally materialized from live
    /// fields, after applying planned replacements.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
    }
}

/// Applied tree-walk roots plus caller-owned heap-field writeback buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication {
    buffers: TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
}

impl TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication {
    pub(super) fn new(
        buffers: TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
    ) -> Self {
        Self { buffers }
    }

    /// Returns the validated buffer application used before writing roots.
    pub const fn buffers(&self) -> &TreeWalkSafepointMinorGcReferenceWritebackBufferApplication {
        &self.buffers
    }

    /// Returns the collector poll used to derive the writebacks.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.buffers.poll()
    }

    /// Returns the number of explicit roots in the safepoint scan.
    pub const fn scanned_roots(&self) -> usize {
        self.buffers.scanned_roots()
    }

    /// Returns the number of heap objects reached by the safepoint scan.
    pub const fn scanned_objects(&self) -> usize {
        self.buffers.scanned_objects()
    }

    /// Returns the number of young survivors in the minor-GC plan.
    pub const fn survivors(&self) -> usize {
        self.buffers.survivors()
    }

    /// Returns the number of reference slots in the commit plan.
    pub const fn reference_slots(&self) -> usize {
        self.buffers.reference_slots()
    }

    /// Returns the number of planned root writebacks.
    pub const fn root_writebacks(&self) -> usize {
        self.buffers.root_writebacks()
    }

    /// Returns the number of planned heap-field writebacks.
    pub const fn heap_field_writebacks(&self) -> usize {
        self.buffers.heap_field_writebacks()
    }

    /// Returns the caller-owned buffer writeback report.
    pub const fn report(&self) -> AllocationCollectorPollReferenceWritebackReport {
        self.buffers.report()
    }

    /// Returns the number of live tree-walk root slots rewritten.
    pub const fn applied_root_writebacks(&self) -> usize {
        self.buffers.applied_root_writebacks()
    }

    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn applied_heap_field_writebacks(&self) -> usize {
        self.buffers.applied_heap_field_writebacks()
    }

    /// Returns the total number of reference slots rewritten.
    pub const fn applied_writebacks(&self) -> usize {
        self.buffers.applied_writebacks()
    }

    /// Returns root slots used to update live tree-walk root storage.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        self.buffers.root_value_writeback_slots()
    }

    /// Returns heap-field buffer slots, originally materialized from live
    /// fields, after applying planned replacements.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        self.buffers.heap_field_writeback_slots()
    }
}

/// Applied tree-walk roots and live heap-field writes for existing destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcLiveReferenceWritebackApplication {
    root_storage: TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    live_heap_field_writebacks: usize,
    remembered_set_published_edges: usize,
    card_table_clear_report: GcCardTableClearReport,
}

impl TreeWalkSafepointMinorGcLiveReferenceWritebackApplication {
    pub(super) fn new(
        root_storage: TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        live_heap_field_writebacks: usize,
        remembered_set_published_edges: usize,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            root_storage,
            object_body_and_generation_write_report,
            live_heap_field_writebacks,
            remembered_set_published_edges,
            card_table_clear_report,
        }
    }

    /// Returns the root-storage application used for live root writes.
    pub const fn root_storage(
        &self,
    ) -> &TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication {
        &self.root_storage
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        &self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(&self) -> usize {
        self.object_body_and_generation_write_report
            .body_write_report()
            .objects()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(&self) -> usize {
        self.object_body_and_generation_write_report
            .generation_write_report()
            .objects()
    }

    /// Returns how many live heap fields were rewritten.
    pub const fn live_heap_field_writebacks(&self) -> usize {
        self.live_heap_field_writebacks
    }

    /// Returns the number of remembered edges published for the next epoch.
    pub const fn remembered_set_published_edges(&self) -> usize {
        self.remembered_set_published_edges
    }

    /// Returns the report for the live card-table clear.
    pub const fn card_table_clear_report(&self) -> GcCardTableClearReport {
        self.card_table_clear_report
    }

    /// Returns how many dirty-card markers were cleared from live state.
    pub const fn card_table_dirty_cards_cleared(&self) -> usize {
        self.card_table_clear_report.dirty_cards()
    }

    /// Returns the collector poll used to derive the writebacks.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.root_storage.poll()
    }

    /// Returns the number of explicit roots in the safepoint scan.
    pub const fn scanned_roots(&self) -> usize {
        self.root_storage.scanned_roots()
    }

    /// Returns the number of heap objects reached by the safepoint scan.
    pub const fn scanned_objects(&self) -> usize {
        self.root_storage.scanned_objects()
    }

    /// Returns the number of young survivors in the minor-GC plan.
    pub const fn survivors(&self) -> usize {
        self.root_storage.survivors()
    }

    /// Returns the number of reference slots in the commit plan.
    pub const fn reference_slots(&self) -> usize {
        self.root_storage.reference_slots()
    }

    /// Returns the number of planned root writebacks.
    pub const fn root_writebacks(&self) -> usize {
        self.root_storage.root_writebacks()
    }

    /// Returns the number of planned heap-field writebacks.
    pub const fn heap_field_writebacks(&self) -> usize {
        self.root_storage.heap_field_writebacks()
    }

    /// Returns the number of live tree-walk root slots rewritten.
    pub const fn applied_root_writebacks(&self) -> usize {
        self.root_storage.applied_root_writebacks()
    }

    /// Returns the total number of live root and heap-field references rewritten.
    pub const fn applied_live_writebacks(&self) -> usize {
        self.applied_root_writebacks()
            .saturating_add(self.live_heap_field_writebacks)
    }

    /// Returns root slots used to update live tree-walk root storage.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        self.root_storage.root_value_writeback_slots()
    }

    /// Returns heap-field buffer slots used to prevalidate live heap-field writes.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        self.root_storage.heap_field_writeback_slots()
    }
}

/// Applied forwarding slots plus tree-walk roots and live heap-field writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication {
    reference_application: TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
    forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
}

impl TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication {
    pub(super) fn new(
        reference_application: TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
    ) -> Self {
        Self {
            reference_application,
            forwarding_install_report,
        }
    }

    /// Returns the live-reference application committed with forwarding install.
    pub const fn reference_application(
        &self,
    ) -> &TreeWalkSafepointMinorGcLiveReferenceWritebackApplication {
        &self.reference_application
    }

    /// Returns the live forwarding installation report.
    pub const fn forwarding_install_report(
        &self,
    ) -> AllocationCollectorPollForwardingInstallReport {
        self.forwarding_install_report
    }

    /// Returns how many forwarding cells were installed.
    pub const fn forwarding_pointers_installed(&self) -> usize {
        self.forwarding_install_report.forwarding_pointers()
    }

    /// Returns the collector poll used to derive the writebacks.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.reference_application.poll()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(&self) -> usize {
        self.reference_application.object_bodies_written()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(&self) -> usize {
        self.reference_application.object_generations_written()
    }

    /// Returns the number of live tree-walk root slots rewritten.
    pub const fn applied_root_writebacks(&self) -> usize {
        self.reference_application.applied_root_writebacks()
    }

    /// Returns how many live heap fields were rewritten.
    pub const fn live_heap_field_writebacks(&self) -> usize {
        self.reference_application.live_heap_field_writebacks()
    }

    /// Returns the total number of live root and heap-field references rewritten.
    pub const fn applied_live_writebacks(&self) -> usize {
        self.reference_application.applied_live_writebacks()
    }

    /// Returns root slots used to update live tree-walk root storage.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        self.reference_application.root_value_writeback_slots()
    }

    /// Returns heap-field slots used to prevalidate live heap-field writes.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        self.reference_application.heap_field_writeback_slots()
    }
}

/// Preflighted tree-walk roots and live heap-field writes for existing destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight {
    pub(crate) buffers: TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
    pub(crate) object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    pub(crate) live_heap_field_writebacks: usize,
}

impl TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight {
    pub(super) fn new(
        buffers: TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        live_heap_field_writebacks: usize,
    ) -> Self {
        Self {
            buffers,
            object_body_and_generation_write_report,
            live_heap_field_writebacks,
        }
    }

    /// Returns the validated buffer application used for root and field checks.
    pub const fn buffers(&self) -> &TreeWalkSafepointMinorGcReferenceWritebackBufferApplication {
        &self.buffers
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        &self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns how many destination object-body writes were preflighted.
    pub const fn object_bodies_preflighted(&self) -> usize {
        self.object_body_and_generation_write_report
            .body_write_report()
            .objects()
    }

    /// Returns how many destination object-generation writes were preflighted.
    pub const fn object_generations_preflighted(&self) -> usize {
        self.object_body_and_generation_write_report
            .generation_write_report()
            .objects()
    }

    /// Returns how many live heap fields were validated.
    pub const fn live_heap_field_writebacks(&self) -> usize {
        self.live_heap_field_writebacks
    }

    /// Returns the collector poll used to derive the writebacks.
    pub const fn poll(&self) -> AllocationCollectorPoll {
        self.buffers.poll()
    }

    /// Returns the number of explicit roots in the safepoint scan.
    pub const fn scanned_roots(&self) -> usize {
        self.buffers.scanned_roots()
    }

    /// Returns the number of heap objects reached by the safepoint scan.
    pub const fn scanned_objects(&self) -> usize {
        self.buffers.scanned_objects()
    }

    /// Returns the number of young survivors in the minor-GC plan.
    pub const fn survivors(&self) -> usize {
        self.buffers.survivors()
    }

    /// Returns the number of reference slots in the commit plan.
    pub const fn reference_slots(&self) -> usize {
        self.buffers.reference_slots()
    }

    /// Returns the number of planned root writebacks.
    pub const fn root_writebacks(&self) -> usize {
        self.buffers.root_writebacks()
    }

    /// Returns the number of planned heap-field writebacks.
    pub const fn heap_field_writebacks(&self) -> usize {
        self.buffers.heap_field_writebacks()
    }

    /// Returns the number of live tree-walk root slots validated.
    pub const fn validated_root_writebacks(&self) -> usize {
        self.buffers.applied_root_writebacks()
    }

    /// Returns the total number of live root and heap-field references validated.
    pub const fn validated_live_writebacks(&self) -> usize {
        self.validated_root_writebacks()
            .saturating_add(self.live_heap_field_writebacks)
    }

    /// Returns root slots used to validate live tree-walk root storage.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        self.buffers.root_value_writeback_slots()
    }

    /// Returns heap-field buffer slots used to validate live heap-field writes.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        self.buffers.heap_field_writeback_slots()
    }
}
