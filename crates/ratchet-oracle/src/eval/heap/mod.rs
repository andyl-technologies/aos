//! Typed heap-object registry for the tree-walk evaluator.
//!
//! Runtime [`Value`] words carry opaque [`HeapObject`] pointers. This registry
//! owns the typed Rust-side objects behind those pointers for the safe tree-walk
//! oracle: the bump arena provides stable opaque handles, while a side table
//! maps those handles back to checked [`NixList`], [`FlatAttrs`] plus
//! representation/shape metadata, [`EvalLambda`], [`EvalPrimOp`], and
//! [`EvalThunk`] values.
//!
//! Strings, paths, lists, and attrsets live *flat* behind the value address
//! (header plus payload in a flat object store) and never enter the
//! record table — in serial mode with string bytes inlined after the payload
//! (FV-1b), and in shared mode as per-shard published flat slots. Lists and
//! attrsets carry heap edges, so their serial flat stores participate in the
//! B1 sweep's permanent-edge seeding, worker-region-pop retained-edge
//! validation, collector-poll edge snapshots/writebacks, and edge scans; see
//! `flat_values` for the seam. After FV-2 the record table's remaining
//! population is the worker-domain closure kinds (thunks, lambdas, partially
//! applied builtins), which move in stage FV-3.

use std::cell::Cell;
use std::ptr::NonNull;
use std::sync::Arc;

use thiserror::Error;

use super::env::{EvalEnv, EvalEnvError, EvalFlatCaptureBuffer, EvalScopedGlobalEnv, EvalWithEnv};
use super::module::{EvalModuleId, EvalNodeRef};
use super::thunk::{ForceError, ThunkCell};
use super::thunk_payload::{ParallelThunkPayloadError, TreeWalkParallelThunkCell};
use super::thunk_registry::ParallelForceCycleRegistry;
use super::tree_walk::TreeWalkError;
use crate::attrs::{AttrError, FlatAttrs, repr::AttrSetReprKind, shape::ShapeId};
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
use crate::runtime::builtins::{Builtin, BuiltinKind};
use crate::string::NixString;
use crate::syntax::{Span, Symbol};
use crate::value::{HeapObject, Value, ValueError, ValueTag};
mod alloc_counters;
mod arena;
#[cfg(feature = "candidate_c_value")]
mod census;
#[cfg(feature = "candidate_c_value")]
mod closure_code_ref;
#[cfg(feature = "candidate_c_value")]
#[allow(dead_code)] // Production heap routing is the next packed-publication slice.
mod collection_view;
#[cfg(feature = "candidate_c_value")]
#[allow(unused_imports)] // Used by the next packed resolver integration slice.
pub(crate) use collection_view::{EvalAttrsView, EvalListView};
#[cfg(feature = "active_packed_thunk_probe")]
mod active_packed_thunks;
#[cfg(feature = "demand_region_shadow_probe")]
mod demand_region;
mod deref_counters;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe",
    feature = "active_packed_thunk_probe"
))]
#[allow(dead_code)] // Consumed by the next packed-rotation publication hook.
mod direct_root_rewrite;
mod environment_writeback;
mod errors;
#[cfg(feature = "candidate_c_value")]
#[allow(dead_code)] // Installed by the next selective-evacuation publication slice.
mod evacuation_forwarding;
mod flat_values;
mod gc;
mod lambda;
#[cfg(feature = "mesh_projection_probe")]
mod mesh_projection;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Destination machinery awaits whole-heap publication wiring.
mod packed_collection_lane;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Destination machinery awaits whole-heap publication wiring.
mod packed_frame_lane;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Owner admission is consumed by the production publication slice.
mod packed_generation;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Consumed by the tree-walk packed publication hook.
mod packed_publication;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Prepared stage is consumed by the packed publication transaction.
mod packed_retained_heap_healing;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Prepared transaction is consumed by the publication hook.
mod packed_rotation_prepare;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Destination machinery awaits whole-heap publication wiring.
mod packed_scalar_lane;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Consumed by the packed publication transaction.
mod packed_source_retirement;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Destination machinery awaits whole-heap publication wiring.
mod packed_string_lane;
#[cfg(any(
    feature = "active_packed_thunk_probe",
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Destination machinery awaits whole-heap publication wiring.
mod packed_thunk_lane;
#[cfg(feature = "active_packed_thunk_probe")]
pub(in crate::eval) use active_packed_thunks::{ActivePackedApplyWork, ActivePackedThunkForce};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Construction scratch is dropped at packed publication.
mod packed_translation;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(dead_code)] // Prepared replacement is consumed by the publication hook.
mod packed_weak_indexes;
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(unused_imports)] // Consumed by the packed publication transaction.
pub(in crate::eval) use packed_weak_indexes::{PackedWeakIndexError, PreparedPackedWeakIndexes};
#[cfg(feature = "peak_ordinal_probe")]
mod peak_ordinal;
mod primop;
mod record_table;
#[allow(dead_code)] // Production string consumers are migrated incrementally.
mod string_view;
#[allow(unused_imports)] // Used by packed-aware evaluator read paths.
pub(crate) use string_view::{EvalStringContextView, EvalStringView};
mod root_scan;
mod roots;
mod shared_arena;
mod shared_backend;
#[cfg(feature = "candidate_c_value")]
mod snapshot;
mod structural_writeback;
#[cfg(feature = "candidate_c_value")]
mod terminal_composite_retirement;
mod thunk;
#[cfg(any(feature = "candidate_c_value", feature = "lifetime_cohort_probe"))]
mod weak_hash_cons_purge;
pub(crate) use alloc_counters::EvalHeapAllocationCounters;
#[cfg(feature = "candidate_c_value")]
pub(crate) use census::ImportEpochCensusFence;
#[cfg(feature = "lifetime_cohort_probe")]
pub(crate) use census::{
    LifetimeCohortCandidate, LifetimeCohortCandidateKind, LifetimeCohortCandidateObservation,
    LifetimeCohortCensus, LifetimeCohortMass,
};
#[cfg(feature = "demand_region_shadow_probe")]
pub(crate) use demand_region::{DemandRegionAllocationCensus, DemandRegionAllocationFence};
pub(crate) use deref_counters::{EvalHeapDerefCounters, EvalHeapDerefCountersSnapshot};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(unused_imports)] // Consumed by the next packed-rotation publication hook.
pub(in crate::eval) use direct_root_rewrite::{
    DirectRootBinding, DirectRootObservation, DirectRootRewrite, DirectRootRewriteError,
    DirectRootRewritePlan, DirectRootRewriteReport,
};
#[cfg(feature = "candidate_c_value")]
use evacuation_forwarding::EvacuationForwardingDirectory;
#[cfg(feature = "candidate_c_value")]
use flat_values::EvacuatedGeneration;
use flat_values::FlatColdHashStore;
pub(crate) use flat_values::attrs::FlatAttrsPayload;
pub(in crate::eval) use flat_values::closures::FlatCapturePublication;
pub use flat_values::closures::WorkerClosurePlacement;
pub(crate) use flat_values::closures::{FlatClosurePayload, serial_flat_closure_store};
#[cfg(feature = "candidate_c_value")]
pub(in crate::eval) use flat_values::permanent_publication::PermanentRetirementReport;
pub(in crate::eval) use flat_values::thunk_heads::TypedThunkWorkHandle;
use flat_values::thunk_heads::{StableThunkHead, TypedThunkWorkPool};
pub(in crate::eval) use flat_values::thunk_heads::{TypedThunkForceClaim, TypedThunkForceParts};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(unused_imports)] // Consumed by the tree-walk packed publication hook.
pub(in crate::eval) use packed_publication::{
    PackedPublicationCommit, PackedPublicationError, PackedPublicationRetirementReport,
    PackedSourceAliasAuditFailure, PreparedPackedPublication, PublishedPackedPublication,
    ZeroAliasPackedPublication,
};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
#[allow(unused_imports)] // Consumed by the packed publication transaction.
pub(in crate::eval) use packed_retained_heap_healing::{
    PackedRetainedHeapHealingError, PackedRetainedHeapHealingStage,
};
#[cfg(any(
    feature = "compact_destination_probe",
    feature = "evacuation_plan_probe"
))]
pub(in crate::eval) use packed_rotation_prepare::PackedRotationAdmissionInput;
#[cfg(feature = "peak_ordinal_probe")]
pub(crate) use peak_ordinal::{PeakAllocationSample, PeakOrdinalProbe};
#[cfg(feature = "lifetime_cohort_probe")]
pub(crate) use weak_hash_cons_purge::{WeakHashConsPurgeReport, WeakHashConsTablePurgeReport};

use crate::heap::flat::{
    FlatKindSet, FlatObjectKind, FlatObjectStore, FlatStorePopReport, FlatStoreRegionMark,
    HeaderlessFlatLane, SharedFlatStoreArena,
};
#[cfg(feature = "candidate_c_value")]
pub(crate) use closure_code_ref::{LambdaCodeFingerprints, LambdaCodeResolver};
pub use errors::EvalHeapError;
pub use gc::{EvalGcMode, EvalHeapSweepReport};
use record_table::HeapRecordTable;
use shared_backend::SharedHeapBackend;
#[cfg(feature = "candidate_c_value")]
pub use snapshot::EvalHeapSnapshotError;
#[cfg(feature = "candidate_c_value")]
#[allow(unused_imports)] // Consumed by the tree-walk heap-snapshot tests.
pub(crate) use snapshot::{CapturedFrameTable, RestoredFrameTable};

pub use shared_arena::{SharedHeapArena, SharedHeapError, SharedHeapShard};

pub use arena::{
    EvalHeapCheapMemoryAdviceReport, EvalHeapCheapMemoryBudgetPlan,
    EvalHeapColdHashConsedAdviceReport, EvalHeapMemoryAdviceReport, EvalHeapMemoryBudgetAction,
    EvalHeapMemoryBudgetDecision, EvalHeapResidentMemoryMode, EvalHeapResidentMemorySource,
    EvalHeapTierBAdmissionPlan, EvalHeapTierBAdmissionRecord, EvalHeapTierBAdmissionReport,
};
pub(crate) use roots::{
    AllocationCollectorPollCopiedHeapFieldWrite, AllocationCollectorPollDirectHeapFieldWrite,
};
pub use roots::{
    AllocationCollectorPollForwardingInstallReport, AllocationCollectorPollForwardingValue,
    AllocationCollectorPollHeapFieldWriteback, AllocationCollectorPollHeapFieldWritebackPlan,
    AllocationCollectorPollHeapFieldWritebackReport, AllocationCollectorPollHeapFieldWritebackSlot,
    AllocationCollectorPollMinorGcCommitBuffers, AllocationCollectorPollMinorGcCommitPlan,
    AllocationCollectorPollMinorGcOwnedCommitBuffers, AllocationCollectorPollMinorGcPlan,
    AllocationCollectorPollMinorGcRelocationDestinations, AllocationCollectorPollNurseryField,
    AllocationCollectorPollNurseryFields,
    AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    AllocationCollectorPollObjectBodyWriteReport, AllocationCollectorPollObjectByteCopyPlan,
    AllocationCollectorPollObjectByteCopyRequest, AllocationCollectorPollObjectGenerationWrite,
    AllocationCollectorPollObjectGenerationWritePlan,
    AllocationCollectorPollObjectGenerationWriteReport, AllocationCollectorPollReferenceSlot,
    AllocationCollectorPollReferenceSource, AllocationCollectorPollReferenceWritebackPlan,
    AllocationCollectorPollReferenceWritebackReport, AllocationCollectorPollRootReferenceValue,
    AllocationCollectorPollRootValueWritebackSlot, AllocationCollectorPollRootWriteback,
    AllocationCollectorPollRootWritebackPlan, AllocationCollectorPollRootWritebackReport,
    AllocationCollectorPollRootWritebackSlot, AllocationCollectorPollScan, CapturedRootOwner,
    EvalHeapThunkResolveBarrier, EvalRoot, EvalRootSet, EvalRootSetError, EvalRootSource, HeapEdge,
    HeapEdgeSource, HeapObjectScan, InternedRootTable, PreciseHeapScan, StackMapSlot,
};

const PRIMOP_TYPE_TAG: u32 = 0x7072_696d;
const PRIMOP_HANDLE_BYTES: usize = std::mem::size_of::<u64>() * 4;
const PRIMOP_HANDLE_ALIGN: usize = std::mem::align_of::<u64>();

/// The suspended work stored in a tree-walk thunk heap record.
#[derive(Clone, Debug)]
pub(crate) enum EvalThunkKind {
    /// Evaluates a lowered IR body under captured lexical and dynamic scopes.
    Node {
        /// The lowered body to evaluate when forced.
        body: EvalNodeRef,
        /// Captured lexical frames.
        env: EvalEnv,
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
    /// Applies a `genList` generator whose body is `elemAt receiver (index + 1)`.
    ///
    /// The payload intentionally matches [`Self::Apply`] exactly. The marker
    /// admits a guarded force-time fast path without widening the common thunk
    /// record or changing its roots; unsupported evaluator modes execute it as
    /// an ordinary application.
    GenListElemAtAddOne {
        /// The IR node that produced the generator.
        function: EvalNodeRef,
        /// The source span associated with the generator.
        function_span: Span,
        /// The forced generator lambda.
        function_value: Value,
        /// The IR node associated with the generated index.
        argument: EvalNodeRef,
        /// The generated lazy index value.
        argument_value: Value,
    },
    /// Applies a forced function value to two lazy argument values.
    Apply2(Box<EvalApply2Thunk>),
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
        /// Stable handle for the selected builtin declaration.
        builtin: BuiltinKind,
    },
    /// The deferred work and captured environments were released after forcing.
    ///
    /// The Tier-B `AOS_NIX_GC=sweep` mode sheds a thunk's captures once its
    /// WHNF result is published (the tree-walk analogue of GHC/C++ Nix's
    /// destructive thunk update): the record keeps its address and its
    /// [`ThunkCell`] `Forced` result, but the closure graph is dropped so the
    /// captured environments can be reclaimed mid-evaluation. Reading the
    /// deferred work of a released thunk is an evaluator bug and every reader
    /// must fail loudly rather than guess.
    Released,
}

/// Rare two-argument application payload kept out of the uniform thunk enum.
#[derive(Clone, Debug)]
pub(crate) struct EvalApply2Thunk {
    pub(crate) function: EvalNodeRef,
    pub(crate) function_span: Span,
    pub(crate) function_value: Value,
    pub(crate) first_argument: EvalNodeRef,
    pub(crate) first_argument_span: Span,
    pub(crate) first_argument_value: Value,
    pub(crate) second_argument: EvalNodeRef,
    pub(crate) second_argument_span: Span,
    pub(crate) second_argument_value: Value,
}

/// Non-lexical environments captured only when a closure has dynamic scopes.
///
/// The AOS module-system workload captures millions of closures while both
/// stacks are empty. Keeping the two persistent-head handles out of line makes
/// common thunk and lambda records smaller without adding an allocation there.
#[derive(Clone, Debug)]
pub(crate) struct EvalClosureDynamicEnv {
    pub(crate) with_env: EvalWithEnv,
    pub(crate) scoped_globals: EvalScopedGlobalEnv,
}

impl EvalClosureDynamicEnv {
    /// Builds an optional dynamic capture, omitting two empty stack handles.
    fn new(with_env: EvalWithEnv, scoped_globals: EvalScopedGlobalEnv) -> Option<Self> {
        if with_env.scopes().is_empty() && scoped_globals.scopes().is_empty() {
            None
        } else {
            Some(Self {
                with_env,
                scoped_globals,
            })
        }
    }

    /// Builds an optional boxed dynamic capture for a closure without another sidecar.
    fn boxed(with_env: EvalWithEnv, scoped_globals: EvalScopedGlobalEnv) -> Option<Box<Self>> {
        Self::new(with_env, scoped_globals).map(Box::new)
    }
}

/// A suspended tree-walk thunk heap record.
///
/// The record stores deferred tree-walk work and force-state storage.
#[derive(Clone, Debug)]
pub struct EvalThunk {
    kind: EvalThunkKind,
    /// Inline serial force state for the common unshared path.
    cell: ThunkCell,
    /// Storage used only by rare captures or non-default forcing modes.
    ///
    /// The serial full-toplevel path allocates millions of thunks and never
    /// populates this pointer unless a source node captures a dynamic scope.
    /// Dynamic scopes, single-entry state, and parallel state stay out of line
    /// so the common record remains compact.
    storage_extension: Option<Box<EvalThunkStorageExtension>>,
}

/// Shape-sized suspended work for the dominant ordinary Node thunk.
///
/// Typed stable heads keep this payload in a dedicated reusable pool instead
/// of reserving one full [`EvalThunk`] enum slot. The compatibility expansion
/// is initialized only when a metadata reader requires `&EvalThunk`; forcing
/// consumes this record directly and drops both representations after update.
#[derive(Debug)]
pub(in crate::eval::heap) struct TypedNodeThunkWork {
    body: EvalNodeRef,
    env: EvalEnv,
    expanded: std::sync::OnceLock<Box<EvalThunk>>,
}

/// Force-storage state absent from the common serial thunk.
#[derive(Clone, Debug)]
struct EvalThunkStorageExtension {
    /// Shared serial identity used only by detached record clones.
    shared_cell: Option<Arc<ThunkCell>>,
    /// Rare non-empty dynamic scopes captured by a source node thunk.
    dynamic_env: Option<EvalClosureDynamicEnv>,
    mode: EvalThunkStorageExtensionMode,
}

/// Non-common forcing mode carried in an out-of-line extension.
#[derive(Clone, Debug)]
enum EvalThunkStorageExtensionMode {
    /// Serial forcing with only a promoted shared-cell identity.
    Serial,
    /// The thunk is proven frame-local and used once.
    SingleEntry,
    /// The thunk participates in the evaluator-native parallel force protocol.
    Parallel(Arc<TreeWalkParallelThunkCell>),
}

/// The force-storage cells currently attached to an [`EvalThunk`].
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvalThunkForceStorageMode {
    /// The thunk only has the serial tree-walk [`ThunkCell`].
    Serial,
    /// The thunk is proven frame-local and used once, so forcing evaluates the
    /// body directly without publishing a cached serial or parallel result.
    SingleEntry,
    /// The thunk has the serial cell plus an evaluator-native parallel payload cell.
    SerialWithParallelPayload,
}

/// A user lambda closure heap record.
///
/// The record stores the lowered parameter pattern and body, the resolver frame
/// used for the call's argument slots, and the lexical and dynamic `with`
/// environments captured when the lambda was constructed.
#[derive(Clone, Debug)]
pub struct EvalLambda {
    module: EvalModuleId,
    pattern: IrId,
    body: IrId,
    frame: FrameId,
    env: EvalEnv,
    /// Rare non-empty dynamic scopes, kept out of the common lambda body.
    dynamic_env: Option<Box<EvalClosureDynamicEnv>>,
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
#[derive(Clone, Debug)]
pub struct EvalPrimOp {
    /// Stable handle for the selected registry declaration.
    builtin: Option<BuiltinKind>,
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
    /// Whether per-resolve last-touch epoch stamping is active (RFC-0007 §P1
    /// ledger lever 5). The stamped epochs are read only by the cheap
    /// memory-advice cold-value policy, which runs only when
    /// `heap_cheap_memory_advice_min_idle_epochs` is set; so the stamp is gated
    /// on that same option and the default hot resolve path takes no epoch write.
    epoch_tracking_enabled: bool,
    memory_budget: Option<HeapMemoryBudget>,
    resident_memory_mode: EvalHeapResidentMemoryMode,
    memory_budget_poll_count: u64,
    last_memory_budget_action: Option<EvalHeapMemoryBudgetAction>,
    records: HeapRecordTable,
    string_cons: HashConsTable<HotXxh3Hash, Value>,
    path_cons: HashConsTable<HotXxh3Hash, Value>,
    list_cons: HashConsTable<HotXxh3Hash, Value>,
    attrs_cons: HashConsTable<HotXxh3Hash, Value>,
    attrs_hash_cons_enabled: bool,
    alloc_counters: EvalHeapAllocationCounters,
    #[cfg(feature = "peak_ordinal_probe")]
    peak_ordinal_probe: PeakOrdinalProbe,
    /// Dereference-chain volume counters (RFC-0007 doc 30 FV-0).
    deref_counters: EvalHeapDerefCounters,
    /// Default-off nonmoving shadow for execution-176 dead candidates.
    #[cfg(feature = "lifetime_cohort_probe")]
    lifetime_quarantine: Option<lifetime_quarantine::LifetimeQuarantine>,
    /// Flat string/path objects (RFC-0007 doc 30 FV-1, serial mode).
    ///
    /// Owns its own arena; payload drop glue runs in the store's `Drop`
    /// before that arena unmaps. See `flat_values` for the integration seam.
    flat: FlatObjectStore<NixString>,
    /// Flat list objects (doc 30 FV-1, serial mode).
    ///
    /// Lists are permanent-domain like strings but their element spines carry
    /// heap **edges**, so this store participates in the B1 sweep's
    /// permanent-edge seeding, worker-region-pop retained-edge validation,
    /// collector-poll edge snapshots/writebacks, and edge scans. See
    /// `flat_values::lists` for the integration seam.
    flat_lists: FlatObjectStore<NixList>,
    /// Flat attribute-set objects (doc 30 FV-2, serial mode).
    /// Attrsets are permanent-domain hash-consed values like lists, carry
    /// heap **edges** in their entry values, and additionally carry shape
    /// metadata in the payload (see [`FlatAttrsPayload`] for the placement
    /// decision). The store participates in the same four GC couplings as
    /// the flat list store; see `flat_values::attrs` for the seam.
    flat_attrs: FlatObjectStore<FlatAttrsPayload>,
    /// Permanent stable identities for the default-off typed-thunk experiment.
    ///
    /// Unlike `flat_closures`, this store occupies the non-rewindable low lane:
    /// a published thunk value must never name an address that a lexical region
    /// pop can recycle.
    typed_thunk_heads: HeaderlessFlatLane<StableThunkHead>,
    /// Reusable, generational suspended-work slots for typed thunk heads.
    typed_thunk_work: TypedThunkWorkPool<EvalThunk>,
    /// Shape-sized reusable work slots for ordinary serial Node thunks.
    typed_node_thunk_work: TypedThunkWorkPool<TypedNodeThunkWork>,
    /// Whether plain serial no-tail thunk allocations may use typed heads.
    typed_apply_thunk_heads_enabled: bool,
    /// Fixed-capacity serial packed Apply/GenList execution experiment.
    #[cfg(feature = "active_packed_thunk_probe")]
    active_packed_thunks: active_packed_thunks::ActivePackedThunkStore,
    /// The shared permanent-domain flat arena (doc 30 FV-4, serial mode).
    ///
    /// One Candidate-C reservation hosts the string/path, list, and attrset
    /// stores' objects (each store keeps its own registry and disjoint kind
    /// set). Used-prefix statistics are read once through this handle; the
    /// virtual 4 GiB range is not charged as resident/mapped bytes. Explicit
    /// test geometry and unsupported mappings retain the chunked fallback.
    /// Worker closures grow downward, so pops never cross permanent allocations.
    flat_arena: SharedFlatStoreArena,
    compressed_scalars: crate::value::compressed::CandidateCScalarStore,
    /// Flat worker-domain closure objects (doc 30 FV-3, serial mode).
    ///
    /// Thunks, lambdas, and partially applied builtins — the mutable,
    /// claim-carrying, region-popped worker kinds — live flat behind their
    /// value addresses as arena-owned payloads. Thunk force-state cells use
    /// side-owned `Arc`s so claims survive evaluator re-entry, while one store
    /// hosts all three kinds under a single worker-region mark. Production
    /// shares `flat_arena`'s high lane; chunked fallback stays independently
    /// owned. The store participates in region pops and the B1 sweep; see
    /// `flat_values::closures` for the reclamation contract.
    flat_closures: FlatObjectStore<FlatClosurePayload>,
    /// Running total of flat closures retired by the Tier-B sweep.
    ///
    /// The flat half of the region-pop interlock: pops rewind the flat
    /// closure arena and may reuse addresses, which is only sound while no
    /// retirement has pinned an address as permanently unknown. Mirrors
    /// `HeapRecordTable::retired_total` and is never reset.
    flat_closures_retired: u64,
    /// Where newly allocated worker closures are placed (doc 30 FV-3).
    ///
    /// `Flat` in production; `Record` under an installed GC-stress policy so
    /// the Tier-B B2 relocation proving ground keeps operating on
    /// record-table objects. See `flat_values::closures`.
    worker_closure_placement: WorkerClosurePlacement,
    /// Sparse cutoff-cache hash side map for flat objects.
    flat_cold_hashes: FlatColdHashStore,
    /// Flat object addresses (lists or attrsets) whose header hash word went
    /// stale after a collector-poll heap-field writeback rewrote a field in
    /// place (the flat analog of a record's `structural_hash = None` at
    /// commit); hash-cons admission must skip these addresses for dedup.
    /// Addresses are unique across the flat stores, so one set serves both.
    flat_stale_hashes: std::collections::HashSet<
        usize,
        std::hash::BuildHasherDefault<record_table::AddressHasher>,
    >,
    /// Parallel-mode shared-arena backend. `None` in serial mode, where every
    /// allocation and resolution path keeps its unchanged serial behavior
    /// behind one branch-predictable check of this option.
    shared: Option<SharedHeapBackend>,
    /// Cached Candidate-C reservation identity for the trusted serial resolve
    /// path.
    ///
    /// Context-free [`Value`] accessors must consult the process-global
    /// reservation registry. The evaluator already owns the reservation, so
    /// its serial hot path can validate the encoded domain and reconstruct a
    /// pointer with one checked `base + index` operation instead.
    #[cfg(feature = "candidate_c_value")]
    serial_reservation: Option<SerialReservationResolver>,
    /// Cached identity for the compact serial generation, when evacuation has
    /// installed one alongside the allocation/nursery reservation.
    ///
    /// This is metadata only: the generation owner must keep the corresponding
    /// reservation mapped for as long as this resolver is present.
    #[cfg(feature = "candidate_c_value")]
    evacuated_serial_reservation: Option<SerialReservationResolver>,
    /// Owner of the installed compact aggregate generation.
    ///
    /// The owner and [`Self::evacuated_serial_reservation`] are published
    /// together by the explicit installation boundary. Ordinary construction
    /// and object movement leave both absent.
    #[cfg(feature = "candidate_c_value")]
    evacuated_generation: Option<EvacuatedGeneration>,
    /// Owner of the installed registry-free packed generation.
    ///
    /// Its logical Candidate-C domain has no native reservation base. Typed
    /// heap access must recognize the domain and resolve a direct lane
    /// coordinate before attempting ordinary pointer reconstruction.
    #[cfg(any(
        feature = "compact_destination_probe",
        feature = "evacuation_plan_probe"
    ))]
    packed_generation: Option<packed_generation::PackedGeneration>,
    /// Temporary nursery-offset aliases for evacuated plain closures.
    ///
    /// This directory is installed atomically with
    /// [`Self::evacuated_generation`] and its resolver. It currently
    /// participates only in the safe evaluator's primop/lambda get, raw-pointer
    /// get, and clone paths. GC, JIT, FFI, and context-free `Value` access do
    /// not canonicalize these aliases yet, so no production batch publishes
    /// the directory.
    #[cfg(feature = "candidate_c_value")]
    evacuated_closure_forwarding: Option<EvacuationForwardingDirectory>,
}

/// Heap-owned Candidate-C reservation metadata used by serial hot paths.
#[cfg(feature = "candidate_c_value")]
#[derive(Clone, Copy, Debug)]
struct SerialReservationResolver {
    domain: crate::heap::ArenaDomainId,
    base: usize,
    capacity: usize,
}

/// One of the two allocation-free serial Candidate-C resolution targets.
#[cfg(feature = "candidate_c_value")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SerialHeapGeneration {
    /// The reservation receiving new serial allocations.
    Nursery,
    /// The compact reservation containing evacuated survivors.
    Evacuated,
}

/// A serial heap address together with the generation that owns its stores.
#[cfg(feature = "candidate_c_value")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SerialHeapLocation {
    ptr: NonNull<HeapObject>,
    generation: SerialHeapGeneration,
}

#[cfg(not(feature = "lifetime_cohort_probe"))]
impl EvalHeap {
    /// Ignores raw-identity observations when the quarantine probe is disabled.
    #[inline]
    pub(in crate::eval) fn observe_value_identity(&self, _value: Value) {}
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
    generation: HeapGeneration,
    minor_gc_forwarding: Cell<Option<ResolvedValueGeneration>>,
    last_touch_epoch: Cell<u64>,
    object: HeapObjectValue,
}

impl HeapRecord {
    /// Returns `true` when the record was reclaimed by the Tier-B sweep.
    ///
    /// Retired slots are unreachable through address resolution (their index
    /// entries are removed at retirement) but remain in the record table until
    /// the slot is recycled; whole-table iterations must skip them.
    const fn is_retired(&self) -> bool {
        matches!(self.object, HeapObjectValue::Retired { .. })
    }
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

const fn initial_generation_for_allocation_domain(domain: HeapAllocationDomain) -> HeapGeneration {
    match domain {
        HeapAllocationDomain::Worker => HeapGeneration::Young,
        HeapAllocationDomain::PermanentShared => HeapGeneration::Permanent,
    }
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
    flat_closures: FlatStoreRegionMark,
}

impl EvalHeapWorkerRegionMark {
    const fn new(
        allocator: RuntimeAllocatorRegionMark,
        owner: u64,
        allocator_epoch: u64,
        mark_id: u64,
        records: usize,
        flat_closures: FlatStoreRegionMark,
    ) -> Self {
        Self {
            allocator,
            owner,
            allocator_epoch,
            mark_id,
            records,
            flat_closures,
        }
    }

    /// Returns the typed heap record count captured at the marker.
    pub const fn records(self) -> usize {
        self.records
    }

    /// Returns the flat worker-closure count captured at the marker.
    pub const fn flat_closures(self) -> usize {
        self.flat_closures.entries()
    }

    /// Returns the typed worker-object count captured at the marker.
    ///
    /// Counts record-table records and flat worker closures together
    /// (doc 30 FV-3), matching the stale-mark diagnostics.
    pub const fn typed_objects(self) -> usize {
        self.records + self.flat_closures.entries()
    }
}

/// Accounting returned after reclaiming one worker lexical region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapWorkerRegionPopReport {
    arena: ArenaRegionPopReport,
    flat_closures: FlatStorePopReport,
    reclaimed_records: usize,
    records_after: usize,
}

impl EvalHeapWorkerRegionPopReport {
    const fn new(
        arena: ArenaRegionPopReport,
        flat_closures: FlatStorePopReport,
        reclaimed_records: usize,
        records_after: usize,
    ) -> Self {
        Self {
            arena,
            flat_closures,
            reclaimed_records,
            records_after,
        }
    }

    /// Returns the whole worker domain's arena reclamation accounting.
    ///
    /// Merges the worker allocator's rewind with the flat closure store's
    /// (doc 30 FV-3), so before/after stats line up with
    /// [`EvalHeap::arena_stats`].
    pub const fn arena_report(self) -> ArenaRegionPopReport {
        self.arena
    }

    /// Returns the flat closure store's reclamation report (doc 30 FV-3).
    pub const fn flat_closures_report(self) -> FlatStorePopReport {
        self.flat_closures
    }

    /// Returns the number of typed worker objects reclaimed by the pop.
    ///
    /// Counts record-table records and flat worker closures together, so the
    /// figure reads the same across worker-closure placements.
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

/// Metadata attached to a heap-owned attribute set.
///
/// The active tree-walk heap still stores [`FlatAttrs`] as the value payload.
/// This metadata records the lowered IR shape id, the projected hidden-class
/// shape id when active shape projection succeeded, and the representation
/// selected by the current policy so later shape/PIC/HAMT bridges can query
/// runtime attrset state without changing the flat consumer API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvalHeapAttrsMetadata {
    shape: u32,
    projected_shape: Option<ShapeId>,
    repr: AttrSetReprKind,
}

impl EvalHeapAttrsMetadata {
    /// Creates metadata for a heap-owned attrset.
    pub const fn new(shape: u32, repr: AttrSetReprKind) -> Self {
        Self {
            shape,
            projected_shape: None,
            repr,
        }
    }

    /// Creates metadata with a process-local projected hidden-class shape id.
    pub const fn with_projected_shape(
        shape: u32,
        repr: AttrSetReprKind,
        projected_shape: ShapeId,
    ) -> Self {
        Self {
            shape,
            projected_shape: Some(projected_shape),
            repr,
        }
    }

    /// Returns the lowered shape id stored with the attrset.
    pub const fn shape(self) -> u32 {
        self.shape
    }

    /// Returns the process-local hidden-class shape id projected for the attrset.
    pub const fn projected_shape(self) -> Option<ShapeId> {
        self.projected_shape
    }

    /// Returns this metadata with the process-local projected shape cleared
    /// (RFC-0007 doc 31 §1 step-4 cross-evaluator restore: shape ids are
    /// per-evaluator, so a foreign image's projections reset to unshaped and
    /// selects fall back to the flat path).
    #[cfg(feature = "candidate_c_value")]
    pub(crate) const fn without_projected_shape(self) -> Self {
        Self {
            shape: self.shape,
            projected_shape: None,
            repr: self.repr,
        }
    }

    /// Returns the projected backing representation for the attrset.
    pub const fn repr(self) -> AttrSetReprKind {
        self.repr
    }
}

#[derive(Clone, Debug)]
enum HeapObjectValue {
    /// Retained for the Tier-B B2 relocation proving ground's record
    /// fixtures; production strings are flat (doc 30 FV-1). The `Path` and
    /// `Attrs` variants FV-1/FV-2 left as never-constructed placeholders
    /// were retired by FV-3.
    String(NixString),
    List(NixList),
    Lambda(EvalLambda),
    Primop(EvalPrimOp),
    Thunk(EvalThunk),
    /// The record was reclaimed by the Tier-B non-moving sweep.
    ///
    /// A retired slot keeps its position in the record table (the slot is
    /// recycled through the table's free list) but its payload has been
    /// dropped and its address index entry removed, so no `Value` resolution
    /// can reach it: a stale handle fails loudly as
    /// [`EvalHeapError::UnknownPointer`] instead of resolving to a zombie
    /// payload. `tag` preserves the retired record's original type for
    /// diagnostics.
    Retired {
        /// The [`ValueTag`] the record carried before retirement.
        tag: ValueTag,
    },
}

impl HeapObjectValue {
    const fn tag(&self) -> ValueTag {
        match self {
            Self::String(_) => ValueTag::String,
            Self::List(_) => ValueTag::List,
            Self::Lambda(_) => ValueTag::Lambda,
            Self::Primop(_) => ValueTag::Primop,
            Self::Thunk(_) => ValueTag::Thunk,
            Self::Retired { tag } => *tag,
        }
    }
}

#[cfg(test)]
mod tests;
