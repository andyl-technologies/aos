//! Typed heap-object registry for the tree-walk evaluator.
//!
//! Runtime [`Value`] words carry opaque [`HeapObject`] pointers. This registry
//! owns the typed Rust-side objects behind those pointers for the safe tree-walk
//! oracle: the bump arena provides stable opaque handles, while a side table
//! maps those handles back to checked [`NixString`], path [`NixString`],
//! [`NixList`], [`FlatAttrs`], [`EvalLambda`], [`EvalPrimOp`], and
//! [`EvalThunk`] values.

use std::cell::Cell;
use std::ptr::NonNull;
use std::rc::Rc;

use thiserror::Error;

use super::env::{EvalEnv, EvalEnvError, EvalScopedGlobalEnv, EvalWithEnv};
use super::module::{EvalModuleId, EvalNodeRef};
use super::thunk::{ForceError, ThunkCell};
use crate::attrs::FlatAttrs;
use crate::cache::{HotXxh3Hash, ValueHash};
use crate::compile::{FrameId, IrAttrPathId, IrId};
use crate::hashcons::{HashConsError, HashConsReservation, HashConsSlot, HashConsTable};
use crate::heap::arena::{ArenaAllocation, ArenaError, ArenaRegionPopReport, ArenaStats};
use crate::heap::{
    GcHeapAddress, GenerationalGcError, HeapGeneration, HeapMemoryBudget, MinorGcSurvivorAction,
    RememberedSetEpoch, ResolvedValueGeneration,
};
use crate::list::NixList;
use crate::runtime::alloc::{
    AllocationSafepointState, GcStressPolicy, PermanentSharedAllocator, RuntimeAllocator,
    RuntimeAllocatorRegionMark, RuntimeAllocatorTier,
};
use crate::runtime::builtins::Builtin;
use crate::string::NixString;
use crate::syntax::{Span, Symbol};
use crate::value::{HeapObject, Value, ValueError, ValueTag};

mod arena;
mod lambda;
mod primop;
mod roots;
mod thunk;

pub use arena::{
    EvalHeapCheapMemoryAdviceReport, EvalHeapCheapMemoryBudgetPlan,
    EvalHeapColdHashConsedAdviceReport, EvalHeapMemoryAdviceReport, EvalHeapMemoryBudgetAction,
    EvalHeapMemoryBudgetDecision, EvalHeapResidentMemoryMode, EvalHeapResidentMemorySource,
};
pub use roots::{
    AllocationCollectorPollForwardingInstallReport, AllocationCollectorPollForwardingValue,
    AllocationCollectorPollHeapFieldWriteback, AllocationCollectorPollHeapFieldWritebackPlan,
    AllocationCollectorPollHeapFieldWritebackReport, AllocationCollectorPollHeapFieldWritebackSlot,
    AllocationCollectorPollMinorGcCommitBuffers, AllocationCollectorPollMinorGcCommitPlan,
    AllocationCollectorPollMinorGcPlan, AllocationCollectorPollMinorGcRelocationDestinations,
    AllocationCollectorPollNurseryField, AllocationCollectorPollNurseryFields,
    AllocationCollectorPollObjectByteCopyPlan, AllocationCollectorPollObjectByteCopyRequest,
    AllocationCollectorPollReferenceSlot, AllocationCollectorPollReferenceSource,
    AllocationCollectorPollReferenceWritebackPlan, AllocationCollectorPollReferenceWritebackReport,
    AllocationCollectorPollRootReferenceValue, AllocationCollectorPollRootValueWritebackSlot,
    AllocationCollectorPollRootWriteback, AllocationCollectorPollRootWritebackPlan,
    AllocationCollectorPollRootWritebackReport, AllocationCollectorPollRootWritebackSlot,
    AllocationCollectorPollScan, CapturedRootOwner, EvalHeapThunkResolveBarrier, EvalRoot,
    EvalRootSet, EvalRootSetError, EvalRootSource, HeapEdge, HeapEdgeSource, HeapObjectScan,
    InternedRootTable, PreciseHeapScan, StackMapSlot,
};

const PRIMOP_TYPE_TAG: u32 = 0x7072_696d;
const PRIMOP_HANDLE_BYTES: usize = std::mem::size_of::<u64>() * 4;
const PRIMOP_HANDLE_ALIGN: usize = std::mem::align_of::<u64>();

/// The suspended work stored in a tree-walk thunk heap record.
#[derive(Debug)]
pub(crate) enum EvalThunkKind {
    /// Evaluates a lowered IR body under captured lexical and dynamic scopes.
    Node {
        /// The lowered body to evaluate when forced.
        body: EvalNodeRef,
        /// Captured lexical frames.
        env: EvalEnv,
        /// Captured dynamic `with` scopes.
        with_env: EvalWithEnv,
        /// Captured scoped-import global scopes.
        scoped_globals: EvalScopedGlobalEnv,
    },
    /// Applies a forced function value to a lazy argument value.
    Apply {
        /// The IR node that produced the function.
        function: EvalNodeRef,
        /// The source span associated with the function.
        function_span: Span,
        /// The forced function value.
        function_value: Value,
        /// The IR node that produced the argument.
        argument: EvalNodeRef,
        /// The lazy argument value.
        argument_value: Value,
    },
    /// Applies a forced function value to two lazy argument values.
    Apply2 {
        /// The IR node that produced the function.
        function: EvalNodeRef,
        /// The source span associated with the function.
        function_span: Span,
        /// The function value, forced only when this thunk is forced.
        function_value: Value,
        /// The IR node associated with the first argument.
        first_argument: EvalNodeRef,
        /// The source span associated with the first argument.
        first_argument_span: Span,
        /// The first lazy argument value.
        first_argument_value: Value,
        /// The IR node associated with the second argument.
        second_argument: EvalNodeRef,
        /// The source span associated with the second argument.
        second_argument_span: Span,
        /// The second lazy argument value.
        second_argument_value: Value,
    },
    /// Selects an attribute path from an already allocated lazy receiver.
    Select {
        /// The IR select node that defines the path and diagnostic span.
        select: EvalNodeRef,
        /// The shared lazy receiver value.
        receiver: Value,
        /// The lowered attribute path to select.
        path: IrAttrPathId,
    },
    /// Evaluates a builtin attribute value when a reified `builtins` entry is forced.
    BuiltinAttr {
        /// The selected builtin attribute symbol.
        symbol: Symbol,
        /// The selected builtin declaration.
        builtin: Builtin,
    },
}

/// A suspended tree-walk thunk heap record.
///
/// The record stores deferred tree-walk work and a serial state/result cell.
#[derive(Debug)]
pub struct EvalThunk {
    kind: EvalThunkKind,
    cell: ThunkCell,
}

/// A user lambda closure heap record.
///
/// The record stores the lowered parameter pattern and body, the resolver frame
/// used for the call's argument slots, and the lexical and dynamic `with`
/// environments captured when the lambda was constructed.
#[derive(Debug)]
pub struct EvalLambda {
    module: EvalModuleId,
    pattern: IrId,
    body: IrId,
    frame: FrameId,
    env: EvalEnv,
    with_env: EvalWithEnv,
    scoped_globals: EvalScopedGlobalEnv,
}

/// One lazy argument captured by the tree-walk `PrimopApp` equivalent.
#[derive(Clone, Copy, Debug)]
pub struct EvalPrimOpArg {
    module: EvalModuleId,
    id: IrId,
    span: Span,
    value: Value,
}

/// A builtin function or partially applied builtin heap record.
///
/// This is the tree-walk oracle's representation of the RFC `PrimopApp`
/// wrapper. Evaluator-selected records carry the selected registry declaration,
/// `symbol` preserves the source symbol used for diagnostics, and `args`
/// stores the already supplied lazy arguments. A record with fewer captured
/// arguments than the builtin's declared arity is a WHNF function value; the
/// evaluator calls the builtin only after saturation.
#[derive(Debug)]
pub struct EvalPrimOp {
    builtin: Option<Builtin>,
    symbol: Symbol,
    args: Vec<EvalPrimOpArg>,
}

/// Owns typed heap values allocated by one tree-walk evaluation.
#[derive(Debug)]
pub struct EvalHeap {
    allocator: RuntimeAllocator,
    permanent_allocator: PermanentSharedAllocator,
    region_owner: u64,
    worker_allocator_epoch: u64,
    worker_region_epoch: u64,
    next_worker_region_mark: u64,
    worker_region_mark_stack: Vec<u64>,
    access_epoch: Cell<u64>,
    memory_budget: Option<HeapMemoryBudget>,
    resident_memory_mode: EvalHeapResidentMemoryMode,
    memory_budget_poll_count: u64,
    last_memory_budget_action: Option<EvalHeapMemoryBudgetAction>,
    records: Vec<HeapRecord>,
    string_cons: HashConsTable<HotXxh3Hash, Value>,
    path_cons: HashConsTable<HotXxh3Hash, Value>,
    list_cons: HashConsTable<HotXxh3Hash, Value>,
    attrs_cons: HashConsTable<HotXxh3Hash, Value>,
}

impl Default for EvalHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct HeapRecord {
    ptr: NonNull<HeapObject>,
    layout: HeapRecordLayout,
    structural_hash: Option<HotXxh3Hash>,
    allocation_domain: HeapAllocationDomain,
    minor_gc_forwarding: Cell<Option<ResolvedValueGeneration>>,
    last_touch_epoch: Cell<u64>,
    value_hash: Cell<Option<ValueHash>>,
    captured_value_hash: Cell<Option<ValueHash>>,
    object: HeapObjectValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeapRecordLayout {
    size_bytes: usize,
    align: usize,
}

impl HeapRecordLayout {
    const fn from_allocation(allocation: ArenaAllocation) -> Self {
        Self {
            size_bytes: allocation.requested_size,
            align: allocation.align,
        }
    }
}

/// The allocation domain that owns a typed evaluator heap record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapAllocationDomain {
    /// A per-worker allocator owns the record for the current evaluation.
    Worker,
    /// Permanent shared storage owns a hash-consed reusable value record.
    PermanentShared,
}

/// The result of writing a canonical value hash onto a heap record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeapValueHashCacheUpdate {
    /// The record had no cached hash and now stores the supplied hash.
    Inserted,
    /// The record already stored the same hash.
    AlreadyPresent,
}

/// Worker-domain allocator reset accounting for an evaluator heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapWorkerResetReport {
    dropped_worker_stats: ArenaStats,
    worker_stats_after: ArenaStats,
    permanent_stats: ArenaStats,
}

impl EvalHeapWorkerResetReport {
    const fn new(
        dropped_worker_stats: ArenaStats,
        worker_stats_after: ArenaStats,
        permanent_stats: ArenaStats,
    ) -> Self {
        Self {
            dropped_worker_stats,
            worker_stats_after,
            permanent_stats,
        }
    }

    /// Returns the worker-domain arena accounting before the reset.
    pub const fn dropped_worker_stats(self) -> ArenaStats {
        self.dropped_worker_stats
    }

    /// Returns worker-domain arena accounting after the reset.
    pub const fn worker_stats_after(self) -> ArenaStats {
        self.worker_stats_after
    }

    /// Returns permanent-shared arena accounting observed during the reset.
    pub const fn permanent_stats(self) -> ArenaStats {
        self.permanent_stats
    }
}

/// Worker-domain heap position captured for lexical region reclamation.
///
/// A marker is valid only for the [`EvalHeap`] that produced it and only while
/// allocations above the marker remain the innermost worker region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapWorkerRegionMark {
    allocator: RuntimeAllocatorRegionMark,
    owner: u64,
    allocator_epoch: u64,
    mark_id: u64,
    records: usize,
}

impl EvalHeapWorkerRegionMark {
    const fn new(
        allocator: RuntimeAllocatorRegionMark,
        owner: u64,
        allocator_epoch: u64,
        mark_id: u64,
        records: usize,
    ) -> Self {
        Self {
            allocator,
            owner,
            allocator_epoch,
            mark_id,
            records,
        }
    }

    /// Returns the typed heap record count captured at the marker.
    pub const fn records(self) -> usize {
        self.records
    }
}

/// Accounting returned after reclaiming one worker lexical region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapWorkerRegionPopReport {
    arena: ArenaRegionPopReport,
    reclaimed_records: usize,
    records_after: usize,
}

impl EvalHeapWorkerRegionPopReport {
    const fn new(
        arena: ArenaRegionPopReport,
        reclaimed_records: usize,
        records_after: usize,
    ) -> Self {
        Self {
            arena,
            reclaimed_records,
            records_after,
        }
    }

    /// Returns the lower-level arena reclamation report.
    pub const fn arena_report(self) -> ArenaRegionPopReport {
        self.arena
    }

    /// Returns the number of typed worker records removed from the side table.
    pub const fn reclaimed_records(self) -> usize {
        self.reclaimed_records
    }

    /// Returns the typed heap record count after reclamation.
    pub const fn records_after(self) -> usize {
        self.records_after
    }
}

/// A cold permanent hash-consed value selected for future CA-store spill work.
#[derive(Clone, Copy, Debug)]
pub struct EvalHeapColdHashConsedValue {
    value: Value,
    size_bytes: usize,
    idle_epochs: u64,
}

impl EvalHeapColdHashConsedValue {
    const fn new(value: Value, size_bytes: usize, idle_epochs: u64) -> Self {
        Self {
            value,
            size_bytes,
            idle_epochs,
        }
    }

    /// Returns the heap value selected by the cold hash-cons policy.
    pub const fn value(self) -> Value {
        self.value
    }

    /// Returns the requested allocation size for this heap record.
    pub const fn size_bytes(self) -> usize {
        self.size_bytes
    }

    /// Returns the number of access epochs elapsed since this record was touched.
    pub const fn idle_epochs(self) -> u64 {
        self.idle_epochs
    }
}

#[derive(Debug)]
enum HeapObjectValue {
    String(NixString),
    Path(NixString),
    List(NixList),
    Attrs { shape: u32, attrs: FlatAttrs },
    Lambda(Rc<EvalLambda>),
    Primop(Rc<EvalPrimOp>),
    Thunk(Rc<EvalThunk>),
}

impl HeapObjectValue {
    const fn tag(&self) -> ValueTag {
        match self {
            Self::String(_) => ValueTag::String,
            Self::Path(_) => ValueTag::Path,
            Self::List(_) => ValueTag::List,
            Self::Attrs { .. } => ValueTag::Attrs,
            Self::Lambda(_) => ValueTag::Lambda,
            Self::Primop(_) => ValueTag::Primop,
            Self::Thunk(_) => ValueTag::Thunk,
        }
    }
}

/// A typed evaluator-heap operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalHeapError {
    /// The runtime allocator could not allocate an opaque handle.
    #[error("evaluator heap allocation error: {0}")]
    Arena(#[from] ArenaError),
    /// The heap side table length overflowed.
    #[error("evaluator heap record length overflow")]
    RecordLengthOverflow,
    /// The heap side table could not reserve space for another object.
    #[error("evaluator heap failed to reserve {records} object records")]
    RecordAllocationFailed {
        /// The requested record capacity.
        records: usize,
    },
    /// The evaluator heap cons table length overflowed.
    #[error("evaluator heap cons table length overflow")]
    ConsTableLengthOverflow,
    /// The evaluator heap cons table could not reserve space for another entry.
    #[error("evaluator heap failed to reserve {entries} cons-table entries")]
    ConsTableAllocationFailed {
        /// The requested cons-table entry count.
        entries: usize,
    },
    /// A runtime value failed a checked heap-value operation.
    #[error("heap value operation failed: {0}")]
    Value(#[from] ValueError),
    /// A heap pointer did not belong to this evaluator heap.
    #[error("unknown heap pointer for {tag:?}: 0x{address:x}")]
    UnknownPointer {
        /// The expected runtime value tag.
        tag: ValueTag,
        /// The unrecognized pointer address.
        address: usize,
    },
    /// A heap pointer belonged to this heap but referenced another typed object.
    #[error("heap record type mismatch at 0x{address:x}: expected {expected:?}, got {actual:?}")]
    RecordTypeMismatch {
        /// The expected runtime value tag.
        expected: ValueTag,
        /// The actual typed record tag.
        actual: ValueTag,
        /// The pointer address shared by the runtime value and heap record.
        address: usize,
    },
    /// A heap record already carries a different canonical value hash.
    #[error("heap value hash mismatch: existing {existing:?}, attempted {attempted:?}")]
    ValueHashMismatch {
        /// The hash already cached on the heap record.
        existing: ValueHash,
        /// The hash the caller attempted to cache.
        attempted: ValueHash,
    },
    /// The worker allocator cannot be reset while worker records remain live.
    #[error(
        "worker allocator reset rejected while {records} worker-domain heap records remain live"
    )]
    WorkerResetLiveRecords {
        /// The number of worker-domain records still registered in the heap.
        records: usize,
    },
    /// A worker-region marker referred to more records than the heap currently
    /// contains.
    #[error(
        "worker region pop marker is stale: {reason}; marker record count was {marker_records}, current record count is {current_records}"
    )]
    WorkerRegionPopStaleMark {
        /// The stale marker condition that failed.
        reason: &'static str,
        /// The typed heap record count captured by the marker.
        marker_records: usize,
        /// The current typed heap record count.
        current_records: usize,
    },
    /// The worker-region mark stack length overflowed.
    #[error("worker region mark stack length overflow")]
    WorkerRegionMarkLengthOverflow,
    /// The worker-region mark stack could not reserve another marker.
    #[error("evaluator heap failed to reserve {marks} worker region marks")]
    WorkerRegionMarkAllocationFailed {
        /// The requested mark capacity.
        marks: usize,
    },
    /// The worker-region mark id space was exhausted.
    #[error("worker region mark id space exhausted")]
    WorkerRegionMarkIdExhausted,
    /// A worker-region pop would reclaim non-worker records.
    #[error("worker region pop rejected while {records} non-worker records exist above the marker")]
    WorkerRegionPopNonWorkerRecords {
        /// The number of non-worker records allocated above the marker.
        records: usize,
    },
    /// A retained heap record still references an object above the region
    /// marker.
    #[error(
        "worker region pop rejected because retained object 0x{source_address:x} field {edge_source:?} points at reclaimed object 0x{target_address:x}",
        source_address = source_address.address_bits(),
        target_address = target_address.address_bits()
    )]
    WorkerRegionPopRetainedEdge {
        /// The retained source object containing the edge.
        source_address: GcHeapAddress,
        /// The precise source label on the retained object.
        edge_source: HeapEdgeSource,
        /// The worker object above the marker that would be reclaimed.
        target_address: GcHeapAddress,
    },
    /// A thunk-resolution write barrier was requested for a non-thunk source.
    #[error("thunk resolve write barrier source must be a thunk, found {actual:?}")]
    ThunkResolveBarrierSourceNotThunk {
        /// The runtime tag supplied as the source object.
        actual: ValueTag,
    },
    /// Lexical environment access failed during precise root scanning.
    #[error("heap root scan environment error: {0}")]
    Environment(#[from] EvalEnvError),
    /// Thunk state access failed during precise root scanning.
    #[error("heap root scan thunk error: {0}")]
    Thunk(#[from] ForceError),
    /// Precise root scanning overflowed a side table length.
    #[error("heap root scan {table} length overflow")]
    RootScanLengthOverflow {
        /// The scanner side table being grown.
        table: &'static str,
    },
    /// Precise root scanning could not reserve side table storage.
    #[error("heap root scan failed to reserve {entries} {table} entries")]
    RootScanAllocationFailed {
        /// The scanner side table being grown.
        table: &'static str,
        /// The requested side table capacity.
        entries: usize,
    },
    /// A collector-poll heap graph snapshot no longer matches the current heap
    /// record.
    #[error("collector-poll heap graph is stale for 0x{address:x}", address = address.address_bits())]
    CollectorPollScanStaleObject {
        /// The object whose current outgoing edges differ from the snapshot.
        address: GcHeapAddress,
    },
    /// A collector-poll heap graph snapshot no longer matches the current heap
    /// allocation state.
    #[error(
        "collector-poll heap graph snapshot is stale: {reason}; record count was {expected_records}, now {actual_records}"
    )]
    CollectorPollScanStaleHeapSnapshot {
        /// The stale snapshot condition that failed.
        reason: &'static str,
        /// The typed heap record count captured by the scan.
        expected_records: usize,
        /// The current typed heap record count.
        actual_records: usize,
    },
    /// A remembered-set edge referenced an address outside this evaluator heap.
    #[error("collector-poll remembered-set {role} address does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollRememberedEdgeAddress {
        /// Whether the unknown address was the edge source or target.
        role: &'static str,
        /// The unrecognized remembered-set address.
        address: GcHeapAddress,
    },
    /// A remembered-set edge did not describe a permanent-to-young edge in the
    /// current oracle heap.
    #[error(
        "collector-poll remembered-set edge is not permanent-to-young: 0x{source:x} ({source_generation:?}) -> 0x{target:x} ({target_generation:?})",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    InvalidCollectorPollRememberedEdge {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The current generation of the source record.
        source_generation: HeapGeneration,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
        /// The current generation of the target record.
        target_generation: HeapGeneration,
    },
    /// A visible permanent-to-young edge was absent from the supplied
    /// remembered-set snapshot.
    #[error(
        "collector-poll minor-GC plan is missing remembered permanent-to-young edge: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    MissingCollectorPollRememberedEdge {
        /// The permanent source object containing the young reference.
        source_address: GcHeapAddress,
        /// The young target object that must be remembered.
        target_address: GcHeapAddress,
    },
    /// A remembered-set edge's source card was absent from the supplied
    /// card-table snapshot.
    #[error(
        "collector-poll remembered-set edge source card {card_index} is not dirty: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    MissingCollectorPollDirtyCard {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
        /// The source card index expected in the dirty-card snapshot.
        card_index: usize,
    },
    /// A remembered-set edge no longer matches any concrete source field.
    #[error(
        "collector-poll remembered-set edge has no current source field: 0x{source:x} -> 0x{target:x}",
        source = source_address.address_bits(),
        target = target_address.address_bits()
    )]
    StaleCollectorPollRememberedEdge {
        /// The remembered edge source address.
        source_address: GcHeapAddress,
        /// The remembered edge target address.
        target_address: GcHeapAddress,
    },
    /// A planned minor-GC survivor no longer belongs to this evaluator heap.
    #[error("collector-poll minor-GC survivor address does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollSurvivorAddress {
        /// The unrecognized survivor address.
        address: GcHeapAddress,
    },
    /// A collector-poll commit application did not receive one reference value
    /// per copied reference-slot label.
    #[error(
        "collector-poll minor-GC commit reference buffer length {actual} does not match copied slot count {expected}"
    )]
    CollectorPollCommitReferenceSlotLengthMismatch {
        /// The copied allocation-poll reference-slot count.
        expected: usize,
        /// The caller-supplied reference buffer length.
        actual: usize,
    },
    /// A collector-poll commit application found a reference value that no
    /// longer matches the copied reference-slot label.
    #[error(
        "collector-poll minor-GC commit reference slot {index} expected {expected:?}, found {actual:?}"
    )]
    CollectorPollCommitReferenceSlotMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The reference value captured with the poll plan.
        expected: ResolvedValueGeneration,
        /// The caller-supplied reference value.
        actual: ResolvedValueGeneration,
    },
    /// Boundary live remembered-set publication saw an unexpected source epoch.
    #[error(
        "boundary minor-GC live remembered-set source epoch {actual} does not match outcome epoch {expected}"
    )]
    BoundaryMinorGcLiveRememberedSetSourceEpochMismatch {
        /// The epoch held by the outcome-owned remembered set.
        expected: RememberedSetEpoch,
        /// The source epoch consumed by the boundary commit application.
        actual: RememberedSetEpoch,
    },
    /// Boundary live remembered-set publication saw an unexpected next epoch.
    #[error(
        "boundary minor-GC live remembered-set next epoch {actual} does not match expected next epoch {expected}"
    )]
    BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
        /// The epoch expected for merged live remembered-set publication.
        expected: RememberedSetEpoch,
        /// The next epoch published by the boundary commit application.
        actual: RememberedSetEpoch,
    },
    /// Boundary sibling dry-runs disagreed about an overlapping relocation.
    #[error(
        "boundary minor-GC live remembered-set merge relocation mismatch for source {source_address:?}: expected {expected:?}, found {actual:?}"
    )]
    BoundaryMinorGcLiveRememberedSetRelocationMismatch {
        /// The from-space survivor address present in both sibling applications.
        source_address: GcHeapAddress,
        /// The first relocation value recorded for the source.
        expected: ResolvedValueGeneration,
        /// The sibling relocation value recorded for the source.
        actual: ResolvedValueGeneration,
    },
    /// Boundary sibling dry-runs mapped different sources to one destination.
    #[error(
        "boundary minor-GC live remembered-set merge destination collision for {destination:?}: source {source_address:?} conflicts with {existing_source_address:?}"
    )]
    BoundaryMinorGcLiveRememberedSetDestinationCollision {
        /// The from-space survivor address currently being validated.
        source_address: GcHeapAddress,
        /// The earlier from-space survivor address that uses the same destination.
        existing_source_address: GcHeapAddress,
        /// The duplicate relocation value.
        destination: ResolvedValueGeneration,
    },
    /// Boundary sibling dry-runs mapped a survivor into from-space.
    #[error(
        "boundary minor-GC live remembered-set merge destination {destination:?} collides with live source {source_address:?}"
    )]
    BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
        /// The from-space survivor address also used as a destination.
        source_address: GcHeapAddress,
        /// The relocation value whose address collides with the source set.
        destination: ResolvedValueGeneration,
    },
    /// Boundary live destination-byte snapshots have already been installed.
    #[error(
        "boundary minor-GC live destination storage already contains {existing} object snapshots"
    )]
    BoundaryMinorGcLiveDestinationStorageAlreadyInstalled {
        /// The number of previously installed destination object snapshots.
        existing: usize,
    },
    /// Boundary live object-generation metadata has already been installed.
    #[error("boundary minor-GC live object generations already contain {existing} object records")]
    BoundaryMinorGcLiveObjectGenerationsAlreadyInstalled {
        /// The number of previously installed object-generation records.
        existing: usize,
    },
    /// Boundary live reference-writeback metadata has already been installed.
    #[error(
        "boundary minor-GC live reference writebacks already contain {existing} rewritten slots"
    )]
    BoundaryMinorGcLiveReferenceWritebacksAlreadyInstalled {
        /// The number of previously installed reference-writeback slots.
        existing: usize,
    },
    /// Boundary sibling dry-runs disagreed about one destination byte snapshot.
    #[error(
        "boundary minor-GC live destination storage object mismatch for source 0x{source_address:x}: expected {expected:?}, found {actual:?}",
        source_address = source_address.address_bits()
    )]
    BoundaryMinorGcLiveDestinationStorageObjectMismatch {
        /// The from-space survivor address present in both sibling applications.
        source_address: GcHeapAddress,
        /// The first byte-copy request recorded for the source.
        expected: AllocationCollectorPollObjectByteCopyRequest,
        /// The sibling byte-copy request recorded for the source.
        actual: AllocationCollectorPollObjectByteCopyRequest,
    },
    /// Boundary sibling dry-runs mapped different sources to one byte snapshot.
    #[error(
        "boundary minor-GC live destination storage destination collision for 0x{destination_address:x}: source 0x{source_address:x} conflicts with 0x{existing_source_address:x}",
        destination_address = destination_address.address_bits(),
        source_address = source_address.address_bits(),
        existing_source_address = existing_source_address.address_bits()
    )]
    BoundaryMinorGcLiveDestinationStorageDestinationCollision {
        /// The from-space survivor address currently being validated.
        source_address: GcHeapAddress,
        /// The earlier from-space survivor address that uses the same destination.
        existing_source_address: GcHeapAddress,
        /// The duplicate destination object address.
        destination_address: GcHeapAddress,
    },
    /// A live root writeback points at no installed destination-byte snapshot.
    #[error(
        "boundary minor-GC root writeback for {root_source:?} points at missing destination 0x{destination:x}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackDestinationMissing {
        /// The copied root source whose replacement needs destination bytes.
        root_source: EvalRootSource,
        /// The replacement destination address without an installed snapshot.
        destination: GcHeapAddress,
    },
    /// A live root writeback's typed replacement disagrees with its destination metadata.
    #[error(
        "boundary minor-GC root writeback for {root_source:?} expected destination 0x{expected_destination:x}, found typed {actual_tag:?}/0x{actual_payload:016x}",
        expected_destination = expected_destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackDestinationMismatch {
        /// The copied root source whose replacement metadata disagreed.
        root_source: EvalRootSource,
        /// The destination address carried by the generation-style root slot.
        expected_destination: GcHeapAddress,
        /// The tag carried by the typed root slot.
        actual_tag: ValueTag,
        /// The raw typed-slot payload bits.
        actual_payload: u64,
    },
    /// A live root writeback's generation disagrees with its destination action.
    #[error(
        "boundary minor-GC root writeback for {root_source:?} destination 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcRootWritebackGenerationMismatch {
        /// The copied root source whose destination generation disagreed.
        root_source: EvalRootSource,
        /// The replacement destination address.
        destination: GcHeapAddress,
        /// The generation implied by the destination action.
        expected: HeapGeneration,
        /// The generation carried by the generation-style root slot.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A destination byte-copy request disagrees with its own survivor action.
    #[error(
        "boundary minor-GC destination request for 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcDestinationActionGenerationMismatch {
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
        /// The generation implied by the survivor action.
        expected: HeapGeneration,
        /// The generation carried by the destination request.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A destination byte-copy snapshot does not match its request length.
    #[error(
        "boundary minor-GC destination snapshot for 0x{destination:x} has {actual} bytes, expected {expected}",
        destination = destination.address_bits()
    )]
    BoundaryMinorGcDestinationPayloadSizeMismatch {
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
        /// The byte length requested by the object-copy metadata.
        expected: usize,
        /// The installed byte-snapshot length.
        actual: usize,
    },
    /// A forwarding value points at no installed destination-byte snapshot.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} points at missing destination payload",
        source = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingDestinationMissing {
        /// The from-space source whose forwarding value lacks destination bytes.
        source_address: GcHeapAddress,
    },
    /// A destination-byte snapshot has no matching forwarding value.
    #[error(
        "boundary minor-GC destination payload for source 0x{source:x} -> 0x{destination:x} has no forwarding value",
        source = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcDestinationForwardingMissing {
        /// The from-space source object.
        source_address: GcHeapAddress,
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
    },
    /// A forwarding value is not heap-backed destination metadata.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} is not heap destination metadata: {actual:?}",
        source = source_address.address_bits()
    )]
    BoundaryMinorGcForwardingDestinationNonHeap {
        /// The from-space source whose forwarding metadata is invalid.
        source_address: GcHeapAddress,
        /// The non-heap forwarding metadata.
        actual: ResolvedValueGeneration,
    },
    /// A forwarding value disagrees with its destination-byte snapshot.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} expected destination 0x{expected:x}, found 0x{actual:x}",
        source = source_address.address_bits(),
        expected = expected.address_bits(),
        actual = actual.address_bits()
    )]
    BoundaryMinorGcForwardingDestinationMismatch {
        /// The from-space source whose forwarding destination disagreed.
        source_address: GcHeapAddress,
        /// The destination address installed with copied bytes.
        expected: GcHeapAddress,
        /// The destination address carried by forwarding metadata.
        actual: GcHeapAddress,
    },
    /// A forwarding value's generation disagrees with its destination action.
    #[error(
        "boundary minor-GC forwarding source 0x{source:x} destination 0x{destination:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        source = source_address.address_bits(),
        destination = destination.address_bits()
    )]
    BoundaryMinorGcForwardingGenerationMismatch {
        /// The from-space source whose forwarding generation disagreed.
        source_address: GcHeapAddress,
        /// The copied or promoted destination address.
        destination: GcHeapAddress,
        /// The generation implied by the destination action.
        expected: HeapGeneration,
        /// The generation carried by forwarding metadata.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A heap-field writeback replacement is not heap-backed metadata.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{writeback_object:x}[{field_index}] {field_source:?} replacement is not heap metadata: {value:?}",
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
        /// The heap object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The non-heap replacement metadata.
        value: ResolvedValueGeneration,
    },
    /// A heap-field writeback replacement points at no destination-byte snapshot.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{writeback_object:x}[{field_index}] {field_source:?} points at missing replacement destination 0x{replacement:x}",
        writeback_object = writeback_object.address_bits(),
        replacement = replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackReplacementMissing {
        /// The heap object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address without an installed snapshot.
        replacement: GcHeapAddress,
    },
    /// A heap-field writeback replacement generation disagrees with its copy action.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{writeback_object:x}[{field_index}] {field_source:?} replacement 0x{replacement:x} has generation {actual:?}, expected {expected:?} from action {action:?}",
        writeback_object = writeback_object.address_bits(),
        replacement = replacement.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
        /// The heap object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The replacement destination address.
        replacement: GcHeapAddress,
        /// The generation implied by the replacement copy action.
        expected: HeapGeneration,
        /// The generation carried by the replacement metadata.
        actual: HeapGeneration,
        /// The object-copy action that implied the expected generation.
        action: MinorGcSurvivorAction,
    },
    /// A copied nursery-field writeback object has no destination-byte snapshot.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{validation_object:x}[{field_index}] {field_source:?} targets missing writeback object 0x{writeback_object:x}",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackObjectMissing {
        /// The from-space object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The relocated object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
    },
    /// A copied nursery-field writeback object snapshot belongs to another source.
    #[error(
        "boundary minor-GC heap-field writeback for 0x{validation_object:x}[{field_index}] {field_source:?} targets destination 0x{writeback_object:x} from source 0x{actual_source:x}",
        validation_object = validation_object.address_bits(),
        writeback_object = writeback_object.address_bits(),
        actual_source = actual_source.address_bits()
    )]
    BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
        /// The from-space object used to validate the copied field label.
        validation_object: GcHeapAddress,
        /// The relocated object whose copied field slot would be rewritten.
        writeback_object: GcHeapAddress,
        /// The field index in precise scanner order.
        field_index: usize,
        /// The copied field source label.
        field_source: HeapEdgeSource,
        /// The source address recorded by the installed destination snapshot.
        actual_source: GcHeapAddress,
    },
    /// A live forwarding installation received an empty forwarding slot.
    #[error(
        "collector-poll minor-GC forwarding slot for 0x{address:x} at index {index} has no forwarded value",
        address = address.address_bits()
    )]
    CollectorPollForwardingSlotEmpty {
        /// The supplied forwarding slot index.
        index: usize,
        /// The source object whose forwarding slot was empty.
        address: GcHeapAddress,
    },
    /// A live forwarding installation received a duplicated source slot.
    #[error(
        "collector-poll minor-GC forwarding slot for 0x{address:x} appears more than once at index {index}",
        address = address.address_bits()
    )]
    CollectorPollForwardingSlotDuplicateSource {
        /// The supplied forwarding slot index.
        index: usize,
        /// The duplicated source object.
        address: GcHeapAddress,
    },
    /// A caller-supplied root value list did not contain one value per copied
    /// root reference slot.
    #[error(
        "collector-poll minor-GC root reference value count {actual} does not match copied root slot count {expected}"
    )]
    CollectorPollRootReferenceValueLengthMismatch {
        /// The copied allocation-poll root-slot count.
        expected: usize,
        /// The caller-supplied root value count.
        actual: usize,
    },
    /// A caller-supplied or installed root value names a different root source.
    #[error(
        "collector-poll minor-GC root reference source {index} mismatch: expected {expected:?}, found {actual:?}"
    )]
    CollectorPollRootReferenceSourceMismatch {
        /// The copied allocation-poll reference slot or root-writeback pair index.
        index: usize,
        /// The copied root source captured by the poll plan.
        expected: EvalRootSource,
        /// The caller-supplied root source.
        actual: EvalRootSource,
    },
    /// A root writeback application did not receive one caller-owned slot per
    /// derived root writeback.
    #[error(
        "collector-poll minor-GC root writeback slot count {actual} does not match root writeback count {expected}"
    )]
    CollectorPollRootWritebackSlotLengthMismatch {
        /// The derived root writeback count.
        expected: usize,
        /// The caller-supplied root writeback slot count.
        actual: usize,
    },
    /// A root-backed writeback was derived from a copied slot without the
    /// heap-value tag needed to reconstruct a typed replacement value later.
    #[error(
        "collector-poll minor-GC root writeback slot {index} for {root_source:?} is missing its copied value tag"
    )]
    CollectorPollRootWritebackMissingValueTag {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The copied root source missing tag metadata.
        root_source: EvalRootSource,
    },
    /// A tagged root-writeback value could not be reconstructed from
    /// heap-backed address metadata.
    #[error(
        "collector-poll minor-GC root writeback value with tag {tag:?} is not heap-backed metadata: {value:?}"
    )]
    CollectorPollRootWritebackNonHeapValue {
        /// The copied heap tag associated with the root writeback.
        tag: ValueTag,
        /// The generation metadata that should have carried a heap address.
        value: ResolvedValueGeneration,
    },
    /// A caller-owned root `Value` slot no longer contains the expected raw
    /// evaluator value.
    #[error(
        "collector-poll minor-GC root value writeback slot {index} value mismatch: expected {expected_tag:?}/0x{expected_payload:016x}, found {actual_tag:?}/0x{actual_payload:016x}"
    )]
    CollectorPollRootValueWritebackSlotMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The tag expected in the caller-owned slot.
        expected_tag: ValueTag,
        /// The payload expected in the caller-owned slot.
        expected_payload: u64,
        /// The actual tag supplied by the caller-owned slot.
        actual_tag: ValueTag,
        /// The actual payload supplied by the caller-owned slot.
        actual_payload: u64,
    },
    /// A live reference buffer cannot be derived for copied root-only slots yet.
    #[error(
        "collector-poll minor-GC reference slot {index} is not heap-field-backed: {root_source:?}"
    )]
    CollectorPollReferenceSlotNotHeapBacked {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The copied root source that still needs external mutable storage.
        root_source: EvalRootSource,
    },
    /// A heap-field-backed reference slot no longer points at the same field.
    #[error(
        "collector-poll minor-GC reference slot {index} source mismatch: expected {expected:?}, found {actual:?}"
    )]
    CollectorPollReferenceSlotSourceMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The precise field source captured by the poll plan.
        expected: HeapEdgeSource,
        /// The current field source at the saved index, if any.
        actual: Option<HeapEdgeSource>,
    },
    /// A heap-field writeback application did not receive one caller-owned slot
    /// per derived heap-field writeback.
    #[error(
        "collector-poll minor-GC heap-field writeback slot count {actual} does not match heap-field writeback count {expected}"
    )]
    CollectorPollHeapFieldWritebackSlotLengthMismatch {
        /// The derived heap-field writeback count.
        expected: usize,
        /// The caller-supplied heap-field writeback slot count.
        actual: usize,
    },
    /// A caller-owned heap-field writeback slot names different objects than the
    /// copied writeback plan.
    #[error(
        "collector-poll minor-GC heap-field writeback slot {index} object mismatch: expected validation 0x{expected_validation_object:x} / writeback 0x{expected_writeback_object:x}, found validation 0x{actual_validation_object:x} / writeback 0x{actual_writeback_object:x}",
        expected_validation_object = expected_validation_object.address_bits(),
        expected_writeback_object = expected_writeback_object.address_bits(),
        actual_validation_object = actual_validation_object.address_bits(),
        actual_writeback_object = actual_writeback_object.address_bits()
    )]
    CollectorPollHeapFieldWritebackSlotObjectMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The heap object used to validate the copied field label.
        expected_validation_object: GcHeapAddress,
        /// The caller-supplied validation object.
        actual_validation_object: GcHeapAddress,
        /// The heap object whose field must be rewritten.
        expected_writeback_object: GcHeapAddress,
        /// The caller-supplied writeback object.
        actual_writeback_object: GcHeapAddress,
    },
    /// A caller-owned heap-field writeback slot names a different field than
    /// the copied writeback plan.
    #[error(
        "collector-poll minor-GC heap-field writeback slot {index} field mismatch: expected field {expected_field_index} {expected_source:?}, found field {actual_field_index} {actual_source:?}"
    )]
    CollectorPollHeapFieldWritebackSlotFieldMismatch {
        /// The copied allocation-poll reference-slot index.
        index: usize,
        /// The precise field index captured by the writeback plan.
        expected_field_index: usize,
        /// The caller-supplied field index.
        actual_field_index: usize,
        /// The precise field source captured by the writeback plan.
        expected_source: HeapEdgeSource,
        /// The caller-supplied field source.
        actual_source: HeapEdgeSource,
    },
    /// A heap-field-backed reference slot object no longer belongs to this heap.
    #[error("collector-poll minor-GC reference slot object does not belong to this heap: 0x{address:x}", address = address.address_bits())]
    UnknownCollectorPollReferenceSlotAddress {
        /// The unrecognized reference-slot object address.
        address: GcHeapAddress,
    },
    /// A planned object byte-copy source no longer has the copied layout.
    #[error(
        "collector-poll minor-GC object byte-copy layout mismatch for 0x{address:x}: expected {expected_size} bytes/{expected_align}-byte alignment, found {actual_size} bytes/{actual_align}-byte alignment",
        address = address.address_bits()
    )]
    CollectorPollObjectByteCopyLayoutMismatch {
        /// The copied source object address.
        address: GcHeapAddress,
        /// The planned copy size in bytes.
        expected_size: usize,
        /// The current source-record size in bytes.
        actual_size: usize,
        /// The planned copy alignment in bytes.
        expected_align: usize,
        /// The current source-record alignment in bytes.
        actual_align: usize,
    },
    /// The generational minor-GC planner rejected the oracle snapshot.
    #[error("collector-poll minor-GC planning error: {0}")]
    GenerationalGc(#[from] GenerationalGcError),
}

impl EvalHeapError {
    fn unknown(tag: ValueTag, ptr: NonNull<HeapObject>) -> Self {
        Self::UnknownPointer {
            tag,
            address: ptr.as_ptr() as usize,
        }
    }

    fn record_type_mismatch(
        expected: ValueTag,
        actual: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Self {
        Self::RecordTypeMismatch {
            expected,
            actual,
            address: ptr.as_ptr() as usize,
        }
    }
}

impl From<HashConsError> for EvalHeapError {
    fn from(error: HashConsError) -> Self {
        match error {
            HashConsError::BucketLengthOverflow => Self::ConsTableLengthOverflow,
            HashConsError::TableAllocationFailed { entries }
            | HashConsError::BucketAllocationFailed { entries } => {
                Self::ConsTableAllocationFailed { entries }
            }
        }
    }
}

#[cfg(test)]
mod tests;
