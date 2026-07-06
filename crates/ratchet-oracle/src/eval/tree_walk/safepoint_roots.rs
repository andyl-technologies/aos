//! Safepoint root-set construction for the tree-walk evaluator.
//!
//! Allocation safepoints need a precise set of live heap values before a moving
//! collector can run. This module exposes the tree-walk evaluator state that is
//! already explicit in Rust data structures: active lexical frames, dynamic
//! `with` scopes, scoped-import globals, active force continuations,
//! first-class primop arguments, and permanent hash-cons roots.

use std::{
    collections::BTreeMap,
    ops::Range,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
};

use thiserror::Error;

use crate::heap::MinorGcForwardingSlot;

use crate::eval::heap::{
    AllocationCollectorPollForwardingInstallReport,
    AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    AllocationCollectorPollObjectByteCopyPlan, EvalRootSource,
};

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
    fn new(
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
    fn new(buffers: TreeWalkSafepointMinorGcReferenceWritebackBufferApplication) -> Self {
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
    fn new(
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
    fn new(
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
    buffers: TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    live_heap_field_writebacks: usize,
}

impl TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight {
    fn new(
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

impl TreeWalk {
    /// Runs `body` with caller-owned values published to allocation safepoints.
    ///
    /// The supplied slots are appended to the tree-walk transient value stack
    /// before `body` runs. GC-stress allocation safepoints scan that stack as
    /// [`EvalRootSource::ValueStack`] storage and write relocated values back
    /// into it. This helper copies the final stored values back to `roots` and
    /// restores the previous stack depth whether `body` succeeds or returns an
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkError`] if transient-root storage cannot be reserved or
    /// if `body` returns an error.
    ///
    /// # Panics
    ///
    /// Panics if `body` panics. The transient root stack is restored before the
    /// panic resumes.
    pub fn with_transient_value_stack_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        roots: &mut [Value],
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        self.with_indexed_transient_value_stack_roots(id, span, roots, |eval, _| body(eval))
    }

    /// Runs `body` with access to the active transient-root stack slots.
    ///
    /// The passed range indexes into `self` while `body` runs, allowing callers
    /// that recurse across allocation safepoints to read roots after writeback.
    pub(in crate::eval::tree_walk) fn with_indexed_transient_value_stack_roots<T>(
        &mut self,
        id: IrId,
        span: Span,
        roots: &mut [Value],
        body: impl FnOnce(&mut Self, Range<usize>) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let start = self.transient_value_stack_roots.len();
        let end = start.checked_add(roots.len()).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::ListAllocationFailed {
                    id,
                    len: roots.len(),
                },
                span,
            )
        })?;
        self.transient_value_stack_roots
            .try_reserve_exact(roots.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::ListAllocationFailed { id, len: end },
                    span,
                )
            })?;
        self.transient_value_stack_roots.extend_from_slice(roots);

        let result = match catch_unwind(AssertUnwindSafe(|| body(self, start..end))) {
            Ok(result) => result,
            Err(payload) => {
                self.transient_value_stack_roots.truncate(start);
                resume_unwind(payload);
            }
        };
        if let Some(updated_roots) = self.transient_value_stack_roots.get(start..end) {
            for (root, updated) in roots.iter_mut().zip(updated_roots.iter().copied()) {
                *root = updated;
            }
        }
        self.transient_value_stack_roots.truncate(start);
        result
    }

    /// Returns the current value stored in one transient-root stack slot.
    pub(in crate::eval::tree_walk) fn current_transient_value_stack_root(
        &self,
        slot: usize,
    ) -> Option<Value> {
        self.transient_value_stack_roots.get(slot).copied()
    }

    /// Replaces the current value stored in one transient-root stack slot.
    pub(in crate::eval::tree_walk) fn set_current_transient_value_stack_root(
        &mut self,
        slot: usize,
        value: Value,
    ) -> bool {
        let Some(root) = self.transient_value_stack_roots.get_mut(slot) else {
            return false;
        };
        *root = value;
        true
    }

    /// Returns transient value-stack roots registered for allocation safepoints.
    #[cfg(test)]
    pub(in crate::eval::tree_walk) fn transient_value_stack_roots(&self) -> &[Value] {
        &self.transient_value_stack_roots
    }

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
        self.safepoint_root_set_with_value_stack_and_primop_arguments(value_stack, [])
    }

    /// Builds explicit safepoint roots with caller-owned value and primop slots.
    ///
    /// Scannable heap values yielded by `value_stack` are recorded as
    /// [`EvalRootSource::ValueStack`] roots. Scannable heap values yielded by
    /// `primop_arguments` are recorded as [`EvalRootSource::PrimopArgument`]
    /// roots. Inline values are skipped as non-roots, but slot indexes still
    /// reflect the original iterator position for both buffers.
    ///
    /// This gives allocation-safepoint callers explicit storage for transient
    /// Rust locals and spilled primop arguments without relying on conservative
    /// stack discovery.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootError`] if the base tree-walk root set
    /// cannot be built or if recording an additional caller-owned root fails.
    pub fn safepoint_root_set_with_value_stack_and_primop_arguments(
        &self,
        value_stack: impl IntoIterator<Item = Value>,
        primop_arguments: impl IntoIterator<Item = Value>,
    ) -> Result<EvalRootSet, TreeWalkSafepointRootError> {
        let mut roots = self.safepoint_root_set()?;
        for (slot, value) in value_stack.into_iter().enumerate() {
            roots.try_push_value_stack(slot, value)?;
        }
        for (index, value) in primop_arguments.into_iter().enumerate() {
            roots.try_push_primop_argument(index, value)?;
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
        self.safepoint_collector_poll_scan_with_primop_arguments(poll, value_stack, [])
    }

    /// Scans the precise heap graph for a poll with spilled primop roots.
    ///
    /// The caller supplies the exact poll observed at the allocation safepoint,
    /// transient value-stack roots, and caller-owned primop argument roots that
    /// are live but not yet stored in evaluator-owned root storage.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointScanError`] if `poll` is stale for its
    /// allocator tier, if root-set construction fails, or if the heap rejects
    /// the precise collector-poll scan.
    pub fn safepoint_collector_poll_scan_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        value_stack: impl IntoIterator<Item = Value>,
        primop_arguments: impl IntoIterator<Item = Value>,
    ) -> Result<AllocationCollectorPollScan, TreeWalkSafepointScanError> {
        self.validate_current_collector_poll(poll)?;
        self.safepoint_collector_poll_scan_with_primop_arguments_for_validated_poll(
            poll,
            value_stack,
            primop_arguments,
        )
    }

    fn safepoint_collector_poll_scan_with_primop_arguments_for_validated_poll(
        &self,
        poll: AllocationCollectorPoll,
        value_stack: impl IntoIterator<Item = Value>,
        primop_arguments: impl IntoIterator<Item = Value>,
    ) -> Result<AllocationCollectorPollScan, TreeWalkSafepointScanError> {
        let roots = self.safepoint_root_set_with_value_stack_and_primop_arguments(
            value_stack,
            primop_arguments,
        )?;
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
    /// entries. It deliberately does not mutate interned roots,
    /// caller-owned [`EvalRootSource::PrimopArgument`] slots, or JIT stack-map
    /// slots; use
    /// [`Self::apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments`]
    /// when generic primop argument roots are present.
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
        let mut primop_arguments: [Value; 0] = [];
        self.apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies typed root writebacks with caller-owned primop argument slots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_root_value_writebacks_to_safepoint_roots`]. It supports the
    /// same evaluator-owned root storage plus generic
    /// [`EvalRootSource::PrimopArgument`] roots backed by `primop_arguments`.
    /// Interned roots and JIT stack-map slots remain unsupported here.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if a planned root source
    /// is unsupported, is not currently live in either caller-owned buffer or
    /// evaluator storage, cannot be read or written, if the temporary slot
    /// buffer cannot be reserved, or if the root writeback plan rejects the
    /// current root values. Validation happens before any root storage is
    /// changed.
    pub fn apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
        &mut self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<AllocationCollectorPollRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let mut slots =
            self.safepoint_root_value_writeback_slots(plan, value_stack, primop_arguments)?;
        let report = plan.apply_to_value_slots(&mut slots)?;
        self.validate_safepoint_root_writeback_targets(&slots, value_stack, primop_arguments)?;
        for slot in &slots {
            self.write_safepoint_root_writeback_value(
                slot.source(),
                slot.value(),
                value_stack,
                primop_arguments,
            )?;
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

    /// Derives and applies root writebacks with caller-owned primop slots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots`].
    /// It includes generic [`EvalRootSource::PrimopArgument`] roots from
    /// `primop_arguments` in the current safepoint scan and rewrites them only
    /// after the complete root-only partition validates.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, if relocation or
    /// commit metadata cannot be derived, if the commit contains heap-field
    /// writebacks, or if live root validation rejects the current root storage.
    pub fn apply_collector_poll_minor_gc_root_writebacks_to_safepoint_roots_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<TreeWalkSafepointMinorGcRootWritebackReport, TreeWalkSafepointRootWritebackError>
    {
        let reference_plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
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

        let applied = self.apply_root_value_writebacks_to_safepoint_roots_with_primop_arguments(
            reference_plan.writebacks().root_writebacks(),
            value_stack,
            primop_arguments,
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
    /// the shared planning bridge for root-only, existing-destination, and
    /// future broader live-reference safepoint applicators.
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
        self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            bases,
            value_stack,
            &[],
        )
    }

    /// Derives complete reference writebacks from a poll with spilled primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::collector_poll_minor_gc_reference_writeback_plan_for_safepoint`].
    /// It includes generic [`EvalRootSource::PrimopArgument`] entries from
    /// `primop_arguments` in the precise safepoint scan and later root
    /// writeback partition.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale, if safepoint scanning or minor-GC planning fails, or if relocation,
    /// commit, or reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        let scan = self.safepoint_collector_poll_scan_with_primop_arguments(
            poll,
            value_stack.iter().copied(),
            primop_arguments.iter().copied(),
        )?;
        let scanned_roots = scan.scan().roots().len();
        let scanned_objects = scan.scan().objects().len();
        let source_remembered_set = self
            .thunk_resolve_remembered_set
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let source_card_table = self
            .thunk_resolve_card_table
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let collection_epoch = source_remembered_set.epoch();
        let minor_gc = self.heap.plan_collector_poll_minor_gc_with_card_table(
            &scan,
            source_remembered_set.snapshot(),
            source_card_table.snapshot(),
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
        let remembered_set_refreshes = commit_plan.commit_plan().remembered_set_refresh().len();
        let next_remembered_set = commit_plan
            .commit_plan()
            .next_remembered_set()
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let mut forwarding_slots = commit_plan.forwarding_slot_buffer()?;
        commit_plan
            .commit_plan()
            .forwarding_pointers()
            .install_into_slots(&mut forwarding_slots)
            .map_err(EvalHeapError::from)?;
        let object_body_plan = self
            .heap
            .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
        let writebacks = self
            .heap
            .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
        let placement_plan = destinations.into_placement_plan();
        Ok(TreeWalkSafepointMinorGcReferenceWritebackPlan::new(
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
        ))
    }

    /// Derives reference writebacks using reserved destination records.
    ///
    /// This validates `poll`, reserves placeholder destination records for the
    /// current young worker heap records, scans the post-reservation safepoint
    /// roots, and maps the minor-GC survivor frontier onto those reservations.
    /// The returned plan is suitable for the existing live-reference preflight
    /// and applicator paths, which still validate and bind object
    /// body/generation writes before any root or field publication.
    ///
    /// If reserving destination records also produces a collector poll for the
    /// same allocator tier, the plan records that post-reservation poll.
    /// Otherwise, it records the already-validated poll that triggered
    /// reservation. Permanent-shared polls remain current while worker
    /// destination records are reserved.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if `poll` is stale before
    /// reservation, if reservation or scanning fails, if minor-GC planning
    /// fails, or if reserved relocation, commit, object-copy, or
    /// reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            &[],
        )
    }

    /// Derives reserved-destination writebacks with spilled primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint`].
    /// It includes generic [`EvalRootSource::PrimopArgument`] entries from
    /// `primop_arguments` in the post-reservation safepoint scan.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if `poll` is stale before
    /// reservation, if reservation or scanning fails, if minor-GC planning
    /// fails, or if reserved relocation, commit, object-copy, or
    /// reference-writeback metadata cannot be derived.
    pub fn collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<TreeWalkSafepointMinorGcReferenceWritebackPlan, TreeWalkSafepointRootWritebackError>
    {
        self.validate_current_collector_poll(poll)?;
        let poll_tier = poll.tier();
        let reservations = self
            .heap
            .reserve_current_young_minor_gc_destination_records()?;
        let scan_poll = self
            .current_collector_poll_for_tier(poll_tier)
            .unwrap_or(poll);
        let scan = self.safepoint_collector_poll_scan_with_primop_arguments_for_validated_poll(
            scan_poll,
            value_stack.iter().copied(),
            primop_arguments.iter().copied(),
        )?;
        let scanned_roots = scan.scan().roots().len();
        let scanned_objects = scan.scan().objects().len();
        let source_remembered_set = self
            .thunk_resolve_remembered_set
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let source_card_table = self
            .thunk_resolve_card_table
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let collection_epoch = source_remembered_set.epoch();
        let minor_gc = self.heap.plan_collector_poll_minor_gc_with_card_table(
            &scan,
            source_remembered_set.snapshot(),
            source_card_table.snapshot(),
            collection_epoch,
            promotion_policy,
        )?;
        let survivors = minor_gc.plan().survivors().len();
        let reference_slots = minor_gc.reference_slots().len();
        let destinations = self
            .heap
            .plan_collector_poll_minor_gc_reserved_relocation_destinations(
                &minor_gc,
                &reservations,
            )?;
        let commit_plan = minor_gc
            .commit_plan(&destinations)
            .map_err(EvalHeapError::from)?;
        let remembered_set_refreshes = commit_plan.commit_plan().remembered_set_refresh().len();
        let next_remembered_set = commit_plan
            .commit_plan()
            .next_remembered_set()
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let mut forwarding_slots = commit_plan.forwarding_slot_buffer()?;
        commit_plan
            .commit_plan()
            .forwarding_pointers()
            .install_into_slots(&mut forwarding_slots)
            .map_err(EvalHeapError::from)?;
        let object_body_plan = self
            .heap
            .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
        let writebacks = self
            .heap
            .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
        let placement_plan = destinations.into_placement_plan();
        Ok(TreeWalkSafepointMinorGcReferenceWritebackPlan::new(
            scan_poll,
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
        self.apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            plan,
            value_stack,
            &[],
        )
    }

    /// Applies complete reference writebacks to buffers with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_buffers`]. It validates
    /// generic [`EvalRootSource::PrimopArgument`] roots against
    /// `primop_arguments` while leaving all mutated roots and heap fields in
    /// caller-owned buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if caller-owned buffer
    /// storage cannot be reserved, or if the plan rejects the current root or
    /// live heap-field slots.
    pub fn apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        self.apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments_and_poll_validation(
            plan,
            value_stack,
            primop_arguments,
            true,
        )
    }

    fn apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments_and_poll_validation(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
        validate_poll: bool,
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        if validate_poll {
            self.validate_current_collector_poll(plan.poll())?;
        }
        let mut root_value_writeback_slots = self.safepoint_root_value_writeback_slots(
            plan.writebacks().root_writebacks(),
            value_stack,
            primop_arguments,
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

    /// Derives and applies reference writebacks to buffers with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers`].
    /// It includes `primop_arguments` in the current-poll root scan and applies
    /// resulting generic primop-argument root writebacks into that same buffer.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// the derived writebacks cannot be represented as caller-owned buffers, or
    /// if buffer validation rejects the derived current root or heap-field
    /// slots.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackBufferApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
            )?;
        self.apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Applies complete reference writebacks to tree-walk roots and field buffers.
    ///
    /// This is a mixed live-root/buffer bridge for tree-walk allocation
    /// safepoints. It first validates and applies the complete root+heap-field
    /// partition to caller-owned typed root slots and live heap-field slots.
    /// Only after both partitions validate does it write the relocated root
    /// values back to supported tree-walk root storage. Heap-field rewrites stay
    /// in caller-owned buffers; this helper does not mutate evaluator object
    /// fields or bind destination storage.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if
    /// caller-owned buffer storage cannot be reserved, or if the plan rejects
    /// the current root or live heap-field slots. Heap-field and root-target
    /// validation happen before any tree-walk root is rewritten.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies complete reference writebacks to roots, primop slots, and field buffers.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers`].
    /// Generic primop argument root writebacks are applied to
    /// `primop_arguments`; evaluator-owned roots are written to their existing
    /// tree-walk storage, and heap-field rewrites stay in caller-owned buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if
    /// caller-owned buffer storage cannot be reserved, or if the plan rejects
    /// the current root or live heap-field slots. Heap-field and root-target
    /// validation happen before any tree-walk root is rewritten.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let application = self
            .apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments(
                plan,
                value_stack,
                primop_arguments,
            )?;
        self.validate_safepoint_root_writeback_targets(
            application.root_value_writeback_slots(),
            value_stack,
            primop_arguments,
        )?;
        for slot in application.root_value_writeback_slots() {
            self.write_safepoint_root_writeback_value(
                slot.source(),
                slot.value(),
                value_stack,
                primop_arguments,
            )?;
        }

        Ok(TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication::new(application))
    }

    /// Derives reference writebacks and applies root storage plus field buffers.
    ///
    /// This derives the complete current root+heap-field reference writeback
    /// partition, prevalidates both partitions, writes supported tree-walk root
    /// storage, and leaves heap-field rewrites in caller-owned buffers.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// buffers cannot be represented, if current root or heap-field validation
    /// fails, or if supported tree-walk root storage cannot be written.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers(
            &plan,
            value_stack,
        )
    }

    /// Derives reference writebacks for roots, primop slots, and field buffers.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// buffers cannot be represented, if current root or heap-field validation
    /// fails, or if supported root storage cannot be written.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
            )?;
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_field_buffers_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Validates complete reference writebacks for roots and live heap fields.
    ///
    /// This is the read-only companion to
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It validates the complete root+heap-field partition against
    /// caller-owned typed root slots and live heap-field slots, validates that
    /// the live remembered set and card table still match the source state
    /// consumed by the plan, then stages the existing-destination object
    /// body/generation writes, live heap-field writes, and
    /// remembered/card-table barriers without committing any of those staged
    /// changes to the evaluator.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if current root or
    /// heap-field validation fails, if the live remembered set or card table no
    /// longer matches the plan's source state, if object-copy request metadata
    /// is inconsistent, if a destination heap record is missing or rejects
    /// paired body/generation staging, if a supported live heap-field write
    /// cannot be staged, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            plan,
            value_stack,
            &[],
        )
    }

    /// Validates reference writebacks for roots, primop slots, and heap fields.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    /// It validates generic primop argument root writebacks against
    /// `primop_arguments` before staging live heap-field writes.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read, if current root or
    /// heap-field validation fails, if the live remembered set or card table no
    /// longer matches the plan's source state, if object-copy request metadata
    /// is inconsistent, if a destination heap record is missing or rejects
    /// paired body/generation staging, if a supported live heap-field write
    /// cannot be staged, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
            plan,
            value_stack,
            primop_arguments,
            true,
        )
    }

    fn validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
        validate_poll: bool,
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let application = self
            .apply_reference_writebacks_to_safepoint_buffers_with_primop_arguments_and_poll_validation(
                plan,
                value_stack,
                primop_arguments,
                validate_poll,
            )?;
        self.validate_safepoint_reference_writeback_source_gc_state(plan)?;
        let (copied_writes, direct_writes) = self
            .heap
            .collector_poll_minor_gc_live_heap_field_write_inputs(
                plan.object_body_plan(),
                plan.writebacks().heap_field_writebacks(),
            )?;
        let (object_body_and_generation_write_report, copied_report, direct_report) = self
            .heap
            .validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
                plan.object_body_plan(),
                &copied_writes,
                &direct_writes,
                &self.thunk_resolve_remembered_set,
                &self.thunk_resolve_card_table,
            )?;
        let live_heap_field_writebacks = copied_report
            .fields()
            .saturating_add(direct_report.fields());
        validate_live_heap_field_writeback_count(
            live_heap_field_writebacks,
            application.applied_heap_field_writebacks(),
        )?;

        Ok(
            TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight::new(
                application,
                object_body_and_generation_write_report,
                live_heap_field_writebacks,
            ),
        )
    }

    /// Derives and validates complete live reference writebacks from a poll.
    ///
    /// This derives the complete current root+heap-field reference writeback
    /// partition and object-copy plan, then runs the read-only existing
    /// destination live reference preflight in
    /// [`Self::validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation staging, if live
    /// heap-field barrier staging fails, or if live-field staging disagrees with
    /// the prevalidated buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
            &plan,
            value_stack,
        )
    }

    /// Derives and validates live reference writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation staging, if live
    /// heap-field barrier staging fails, or if live-field staging disagrees with
    /// the prevalidated buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
            )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Reserves destinations and validates live reference writebacks.
    ///
    /// This is the reserved-destination counterpart to
    /// [`Self::validate_collector_poll_minor_gc_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    /// It validates the supplied poll, reserves placeholder destination records
    /// for current young worker records, derives the live reference plan from
    /// those reservations, then runs the existing read-only live-reference
    /// preflight. The preflight does not publish roots, heap fields,
    /// object-body writes, remembered-set state, or card-table state, but the
    /// destination reservation itself does allocate scratch heap records.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation staging, if live heap-field barrier
    /// staging fails, or if live-field staging disagrees with the prevalidated
    /// buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            value_stack,
        )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
            &plan,
            value_stack,
            &[],
            false,
        )
    }

    /// Reserves destinations and validates live writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation staging, if live heap-field barrier
    /// staging fails, or if live-field staging disagrees with the prevalidated
    /// buffer writeback count.
    pub fn validate_collector_poll_minor_gc_reserved_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )?;
        self.validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
            &plan,
            value_stack,
            primop_arguments,
            false,
        )
    }

    /// Applies complete reference writebacks to roots and live heap fields.
    ///
    /// This is a narrow existing-destination live-reference bridge for
    /// tree-walk allocation safepoints. It first runs the read-only
    /// existing-destination live-reference preflight, validating the complete
    /// root+heap-field partition, the plan's source remembered-set/card-table
    /// state, paired object body/generation staging, live heap-field writes,
    /// and remembered/card-table barrier staging. It also validates that
    /// supported root writeback targets can be written and clones the planned
    /// next remembered set before committing heap state. It then binds the
    /// plan's paired object body/generation writes to already-existing
    /// destination records, applies supported record-owned heap-field writes,
    /// writes the prevalidated root slots back to supported tree-walk root
    /// storage, publishes the planned next remembered set, and clears the live
    /// card table.
    ///
    /// This still requires destination heap records to pre-exist and does not
    /// allocate semispace storage, install forwarding headers, consume JIT
    /// stack maps, or dispatch Tier B from allocation sites. The remembered-set
    /// and card-table publication is limited to this existing-destination
    /// tree-walk bridge.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if the live remembered set or card
    /// table no longer matches the plan's source state, if object-copy request
    /// metadata is inconsistent, if a destination heap record is missing or
    /// rejects paired body/generation writes, if a supported live heap-field
    /// write cannot be staged, if the next remembered set cannot be cloned
    /// before mutation, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies complete reference writebacks to roots, primop slots, and heap fields.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It rewrites generic primop argument roots through `primop_arguments`
    /// after the same full root/heap-field preflight used by the value-stack
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if the live remembered set or card
    /// table no longer matches the plan's source state, if object-copy request
    /// metadata is inconsistent, if a destination heap record is missing or
    /// rejects paired body/generation writes, if a supported live heap-field
    /// write cannot be staged, if the next remembered set cannot be cloned
    /// before mutation, or if live-field staging disagrees with the
    /// prevalidated buffer writeback count.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let (application, _) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
                plan,
                value_stack,
                primop_arguments,
                None,
                true,
            )?;
        Ok(application)
    }

    /// Installs forwarding slots and applies live reference writebacks.
    ///
    /// This is the side-table-forwarding companion to
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It runs the same full root/heap-field preflight, validates the plan's
    /// filled forwarding slots and heap publication work without mutating them,
    /// writes supported roots before forwarding cells are installed, and then
    /// commits the staged forwarding, destination body/generation, heap-field,
    /// remembered-set, and card-table state without further fallible staging.
    ///
    /// This remains side-table forwarding only: it does not write real ABI
    /// object headers, reserve semispace storage, consume JIT stack maps, or
    /// dispatch Tier B from allocation sites.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if live forwarding-slot validation
    /// fails, if paired body/generation writes fail, or if live root or
    /// heap-field mutation fails.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            plan,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Installs forwarding slots and applies writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the plan's poll is no
    /// longer current, if root storage cannot be read or written, if current
    /// root or heap-field validation fails, if live forwarding-slot validation
    /// fails, if paired body/generation writes fail, or if live root or
    /// heap-field mutation fails.
    pub fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let (reference_application, forwarding_install_report) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
                plan,
                value_stack,
                primop_arguments,
                Some(plan.forwarding_slots()),
                true,
            )?;
        Ok(
            TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication::new(
                reference_application,
                forwarding_install_report,
            ),
        )
    }

    fn apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
        &mut self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
        forwarding_slots: Option<&[MinorGcForwardingSlot]>,
        validate_poll: bool,
    ) -> Result<
        (
            TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
            AllocationCollectorPollForwardingInstallReport,
        ),
        TreeWalkSafepointRootWritebackError,
    > {
        let preflight = self
            .validate_reference_writebacks_for_safepoint_root_storage_and_heap_fields_with_primop_arguments_and_poll_validation(
                plan,
                value_stack,
                primop_arguments,
                validate_poll,
            )?;
        let TreeWalkSafepointMinorGcLiveReferenceWritebackPreflight {
            buffers: application,
            live_heap_field_writebacks: preflight_live_heap_field_writebacks,
            ..
        } = preflight;
        self.validate_safepoint_root_writeback_targets(
            application.root_value_writeback_slots(),
            value_stack,
            primop_arguments,
        )?;
        let forwarding_install_stage = match forwarding_slots {
            Some(forwarding_slots) => Some(
                self.heap
                    .stage_collector_poll_minor_gc_forwarding_slots(forwarding_slots)?,
            ),
            None => None,
        };
        let next_remembered_set = plan
            .next_remembered_set()
            .try_clone()
            .map_err(EvalHeapError::from)?;
        let remembered_set_published_edges = next_remembered_set.len();
        let (copied_writes, direct_writes) = self
            .heap
            .collector_poll_minor_gc_live_heap_field_write_inputs(
                plan.object_body_plan(),
                plan.writebacks().heap_field_writebacks(),
            )?;
        let planned_live_heap_field_writebacks =
            copied_writes.len().saturating_add(direct_writes.len());
        validate_live_heap_field_writeback_count(
            planned_live_heap_field_writebacks,
            application.applied_heap_field_writebacks(),
        )?;
        let staged_live_heap_field_writes = self
            .heap
            .stage_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
                plan.object_body_plan(),
                &copied_writes,
                &direct_writes,
                &self.thunk_resolve_remembered_set,
                &self.thunk_resolve_card_table,
            )?;
        let live_heap_field_writebacks = staged_live_heap_field_writes.live_heap_field_writebacks();
        debug_assert_eq!(
            live_heap_field_writebacks,
            preflight_live_heap_field_writebacks
        );
        debug_assert_eq!(
            live_heap_field_writebacks,
            planned_live_heap_field_writebacks
        );
        let (
            forwarding_install_report,
            object_body_and_generation_write_report,
            copied_report,
            direct_report,
        ) = if let Some(forwarding_install_stage) = forwarding_install_stage {
            // Root writes are the final fallible operation in the forwarding
            // path. Do them before installing side-table forwarding cells so a
            // rejected target cannot poison a retry with an occupied forwarding
            // slot.
            for slot in application.root_value_writeback_slots() {
                self.write_safepoint_root_writeback_value(
                    slot.source(),
                    slot.value(),
                    value_stack,
                    primop_arguments,
                )?;
            }
            let forwarding_install_report = self
                .heap
                .commit_collector_poll_minor_gc_staged_forwarding_slots(forwarding_install_stage);
            let (object_body_and_generation_write_report, copied_report, direct_report) = self
                .heap
                .commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
                    staged_live_heap_field_writes,
                    &mut self.thunk_resolve_remembered_set,
                    &mut self.thunk_resolve_card_table,
                );
            (
                forwarding_install_report,
                object_body_and_generation_write_report,
                copied_report,
                direct_report,
            )
        } else {
            let (object_body_and_generation_write_report, copied_report, direct_report) = self
                .heap
                .commit_collector_poll_minor_gc_staged_live_heap_field_writes_with_card_table(
                    staged_live_heap_field_writes,
                    &mut self.thunk_resolve_remembered_set,
                    &mut self.thunk_resolve_card_table,
                );
            for slot in application.root_value_writeback_slots() {
                self.write_safepoint_root_writeback_value(
                    slot.source(),
                    slot.value(),
                    value_stack,
                    primop_arguments,
                )?;
            }
            (
                AllocationCollectorPollForwardingInstallReport::default(),
                object_body_and_generation_write_report,
                copied_report,
                direct_report,
            )
        };
        debug_assert_eq!(
            live_heap_field_writebacks,
            copied_report
                .fields()
                .saturating_add(direct_report.fields())
        );
        self.thunk_resolve_remembered_set = next_remembered_set;
        let card_table_clear_report = self.thunk_resolve_card_table.clear_dirty_cards();

        Ok((
            TreeWalkSafepointMinorGcLiveReferenceWritebackApplication::new(
                TreeWalkSafepointMinorGcReferenceWritebackRootStorageApplication::new(application),
                object_body_and_generation_write_report,
                live_heap_field_writebacks,
                remembered_set_published_edges,
                card_table_clear_report,
            ),
            forwarding_install_report,
        ))
    }

    /// Derives and applies complete live reference writebacks from a current poll.
    ///
    /// This derives the complete current root+heap-field reference writeback
    /// partition and object-copy plan, then applies the existing-destination live
    /// reference bridge in
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation writes, or if live
    /// root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            bases,
            value_stack,
        )?;
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
            &plan,
            value_stack,
        )
    }

    /// Derives and applies live reference writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if planning fails, if
    /// current root or heap-field validation fails, if existing destination
    /// records are missing or reject paired body/generation writes, or if live
    /// root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self
            .collector_poll_minor_gc_reference_writeback_plan_for_safepoint_with_primop_arguments(
                poll,
                promotion_policy,
                bases,
                value_stack,
                primop_arguments,
            )?;
        self.apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
            &plan,
            value_stack,
            primop_arguments,
        )
    }

    /// Reserves destinations and applies complete live reference writebacks.
    ///
    /// This is the reserved-destination counterpart to
    /// [`Self::apply_collector_poll_minor_gc_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It validates the current poll, reserves placeholder destination records
    /// for current young worker records, derives the survivor relocation plan
    /// from those reservations, then reuses the existing live-reference
    /// applicator to bind object bodies/generations, rewrite supported
    /// tree-walk roots and live heap fields, publish the rebuilt remembered
    /// set, and clear the card table.
    ///
    /// This still does not reserve semispace pages, install forwarding headers,
    /// consume JIT stack maps, mutate interned roots, or dispatch Tier B from
    /// allocation sites automatically.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation writes, or if live root or
    /// heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint(
            poll,
            promotion_policy,
            value_stack,
        )?;
        let mut primop_arguments: [Value; 0] = [];
        let (application, _) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
                &plan,
                value_stack,
                &mut primop_arguments,
                None,
                false,
            )?;
        Ok(application)
    }

    /// Reserves destinations and applies live writebacks with primop arguments.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if reserved destination
    /// records reject paired body/generation writes, or if live root or
    /// heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )?;
        let (application, _) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
            &plan,
            value_stack,
            primop_arguments,
                None,
                false,
            )?;
        Ok(application)
    }

    /// Reserves destinations, installs forwarding slots, and applies writebacks.
    ///
    /// This is the side-table-forwarding counterpart to
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields`].
    /// It derives the reserved-destination plan from the supplied poll and then
    /// applies the plan through
    /// [`Self::apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// This remains side-table forwarding only: it does not write real ABI
    /// object headers, reserve semispace storage, consume JIT stack maps, or
    /// dispatch Tier B from allocation sites.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if forwarding-slot
    /// validation fails, if reserved destination records reject paired
    /// body/generation writes, or if live root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Reserves destinations and applies forwarding writebacks with primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if the supplied poll is
    /// stale before reservation, if destination reservation or planning fails,
    /// if current root or heap-field validation fails, if forwarding-slot
    /// validation fails, if reserved destination records reject paired
    /// body/generation writes, or if live root or heap-field mutation fails.
    pub fn apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
        &mut self,
        poll: AllocationCollectorPoll,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let plan = self.collector_poll_minor_gc_reserved_reference_writeback_plan_for_safepoint_with_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )?;
        let (reference_application, forwarding_install_report) = self
            .apply_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_optional_forwarding_slots(
            &plan,
            value_stack,
            primop_arguments,
                Some(plan.forwarding_slots()),
                false,
            )?;
        Ok(
            TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication::new(
                reference_application,
                forwarding_install_report,
            ),
        )
    }

    /// Applies the current tier poll through the reserved forwarding bridge.
    ///
    /// This is the current-poll convenience form of
    /// [`Self::apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    /// It reads the latest collector poll for `tier` immediately before
    /// reservation, so callers do not have to preserve an
    /// [`AllocationCollectorPoll`] handle across intervening code.
    ///
    /// This remains an explicit tree-walk bridge outside the current tree-walk
    /// allocation precursors: it does not run for arbitrary allocation sites,
    /// write real ABI object headers, reserve semispace storage, consume JIT
    /// stack maps, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if no current poll exists
    /// for `tier`, if destination reservation or planning fails, if current root
    /// or heap-field validation fails, if forwarding-slot validation fails, if
    /// reserved destination records reject paired body/generation writes, or if
    /// live root or heap-field mutation fails.
    pub fn apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots(
        &mut self,
        tier: RuntimeAllocatorTier,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let mut primop_arguments: [Value; 0] = [];
        self.apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            tier,
            promotion_policy,
            value_stack,
            &mut primop_arguments,
        )
    }

    /// Applies current-poll reserved forwarding writebacks with primop roots.
    ///
    /// This is the caller-buffer-aware form of
    /// [`Self::apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`TreeWalkSafepointRootWritebackError`] if no current poll exists
    /// for `tier`, if destination reservation or planning fails, if current root
    /// or heap-field validation fails, if forwarding-slot validation fails, if
    /// reserved destination records reject paired body/generation writes, or if
    /// live root or heap-field mutation fails.
    pub fn apply_current_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
        &mut self,
        tier: RuntimeAllocatorTier,
        promotion_policy: MinorGcPromotionPolicy,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<
        TreeWalkSafepointMinorGcForwardingLiveReferenceWritebackApplication,
        TreeWalkSafepointRootWritebackError,
    > {
        let poll = self
            .current_collector_poll_for_tier(tier)
            .ok_or(TreeWalkSafepointScanError::NoCurrentCollectorPoll { tier })?;
        self.apply_collector_poll_minor_gc_reserved_reference_writebacks_to_safepoint_root_storage_and_heap_fields_with_forwarding_slots_and_primop_arguments(
            poll,
            promotion_policy,
            value_stack,
            primop_arguments,
        )
    }

    fn safepoint_root_value_writeback_slots(
        &self,
        plan: &AllocationCollectorPollRootWritebackPlan,
        value_stack: &[Value],
        primop_arguments: &[Value],
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
            let value =
                self.read_safepoint_root_writeback_value(&source, value_stack, primop_arguments)?;
            slots.push(AllocationCollectorPollRootValueWritebackSlot::new(
                source, value,
            ));
        }

        Ok(slots)
    }

    fn validate_safepoint_root_writeback_targets(
        &self,
        slots: &[AllocationCollectorPollRootValueWritebackSlot],
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        for slot in slots {
            self.validate_safepoint_root_writeback_target(
                slot.source(),
                value_stack,
                primop_arguments,
            )?;
        }
        Ok(())
    }

    fn validate_safepoint_reference_writeback_source_gc_state(
        &self,
        plan: &TreeWalkSafepointMinorGcReferenceWritebackPlan,
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        validate_safepoint_source_remembered_set(
            plan.source_remembered_set(),
            &self.thunk_resolve_remembered_set,
        )?;
        validate_safepoint_source_card_table(
            plan.source_card_table(),
            &self.thunk_resolve_card_table,
        )
    }

    fn read_safepoint_root_writeback_value(
        &self,
        source: &EvalRootSource,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<Value, TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => value_stack
                .get(*slot)
                .copied()
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::PrimopArgument { index } => primop_arguments
                .get(*index)
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
            EvalRootSource::Interned { .. } | EvalRootSource::StackMap { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
        }
    }

    fn validate_safepoint_root_writeback_target(
        &self,
        source: &EvalRootSource,
        value_stack: &[Value],
        primop_arguments: &[Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => value_stack
                .get(*slot)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::PrimopArgument { index } => primop_arguments
                .get(*index)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::TreeWalkFrame { frame, slot } => self
                .env
                .get(*frame)
                .ok_or_else(|| root_writeback_source_unavailable(source))?
                .validate_set(root_writeback_frame_slot(source, *slot)?)
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
                    .validate_set(root_writeback_frame_slot(source, *slot)?)
                    .map_err(TreeWalkSafepointRootWritebackError::Environment)
            }
            EvalRootSource::WithScope { depth } => self
                .with_scopes
                .get(*depth)
                .map(|_| ())
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
                    .map(|_| ())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ScopedGlobal { depth } => self
                .scoped_globals
                .get(*depth)
                .map(|_| ())
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
                    .map(|_| ())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ForceContinuation { depth } => self
                .active_force_roots
                .get(reverse_root_index(
                    self.active_force_roots.len(),
                    *depth,
                    source,
                )?)
                .map(|_| ())
                .ok_or_else(|| root_writeback_source_unavailable(source)),
            EvalRootSource::TreeWalkPrimopArgument { call_depth, index } => {
                let root_index = active_primop_arg_root_index(self, *call_depth, *index, source)?;
                self.active_primop_arg_roots
                    .get(root_index)
                    .map(|_| ())
                    .ok_or_else(|| root_writeback_source_unavailable(source))
            }
            EvalRootSource::ImportCache { index } => {
                read_import_cache_root(&self.import_cache, *index, source).map(|_| ())
            }
            EvalRootSource::Interned { .. } | EvalRootSource::StackMap { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
        }
    }

    fn write_safepoint_root_writeback_value(
        &mut self,
        source: &EvalRootSource,
        value: Value,
        value_stack: &mut [Value],
        primop_arguments: &mut [Value],
    ) -> Result<(), TreeWalkSafepointRootWritebackError> {
        match source {
            EvalRootSource::ValueStack { slot } => {
                let target = value_stack
                    .get_mut(*slot)
                    .ok_or_else(|| root_writeback_source_unavailable(source))?;
                *target = value;
                Ok(())
            }
            EvalRootSource::PrimopArgument { index } => {
                let target = primop_arguments
                    .get_mut(*index)
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
            EvalRootSource::Interned { .. } | EvalRootSource::StackMap { .. } => {
                Err(root_writeback_source_unsupported(source))
            }
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
        // Amortized (doubling) reservation, not `try_reserve_exact`: this stack is
        // pushed once per thunk force and pop-reused, so exact growth would
        // reallocate on every push while the stack deepens. Values and the
        // allocation-failure error are unchanged.
        self.active_force_roots.try_reserve(1).map_err(|_| {
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
        // Amortized reservation: this frame stack is reserved once per thunk-body
        // force, so exact growth would reallocate on every deepening push.
        self.suspended_env_roots.try_reserve(1).map_err(|_| {
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
            .try_reserve(args.len())
            .map_err(|_| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackAllocationFailed {
                        id,
                        roots: arg_roots,
                    },
                    span,
                )
            })?;
        self.active_primop_arg_frames.try_reserve(1).map_err(|_| {
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

fn validate_live_heap_field_writeback_count(
    live_heap_field_writebacks: usize,
    buffer_heap_field_writebacks: usize,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    if live_heap_field_writebacks != buffer_heap_field_writebacks {
        return Err(
            TreeWalkSafepointRootWritebackError::LiveHeapFieldWritebackCountMismatch {
                live_heap_field_writebacks,
                buffer_heap_field_writebacks,
            },
        );
    }

    Ok(())
}

fn validate_safepoint_source_remembered_set(
    expected: &RememberedSet,
    actual: &RememberedSet,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    if expected.epoch() != actual.epoch() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceRememberedSetEpochMismatch {
                expected: expected.epoch(),
                actual: actual.epoch(),
            },
        );
    }
    if expected.len() != actual.len() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceRememberedSetLengthMismatch {
                expected: expected.len(),
                actual: actual.len(),
            },
        );
    }
    for (index, (expected, actual)) in expected.edges().iter().zip(actual.edges()).enumerate() {
        if expected != actual {
            return Err(
                TreeWalkSafepointRootWritebackError::SourceRememberedSetEdgeMismatch {
                    index,
                    expected: *expected,
                    actual: *actual,
                },
            );
        }
    }
    Ok(())
}

fn validate_safepoint_source_card_table(
    expected: &GcCardTable,
    actual: &GcCardTable,
) -> Result<(), TreeWalkSafepointRootWritebackError> {
    if expected.card_size_bytes() != actual.card_size_bytes() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceCardTableCardSizeMismatch {
                expected: expected.card_size_bytes(),
                actual: actual.card_size_bytes(),
            },
        );
    }
    if expected.len() != actual.len() {
        return Err(
            TreeWalkSafepointRootWritebackError::SourceCardTableLengthMismatch {
                expected: expected.len(),
                actual: actual.len(),
            },
        );
    }
    for (index, (expected, actual)) in expected
        .dirty_cards()
        .iter()
        .zip(actual.dirty_cards())
        .enumerate()
    {
        if expected != actual {
            return Err(
                TreeWalkSafepointRootWritebackError::SourceCardTableDirtyCardMismatch {
                    index,
                    expected: *expected,
                    actual: *actual,
                },
            );
        }
    }
    Ok(())
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
